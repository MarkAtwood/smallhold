use std::sync::LazyLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fieldwork::circuit_breaker::CircuitBreaker;
use sqlx::SqlitePool;

use crate::api::millis_to_iso;
use crate::config::Config;
use crate::federation::FederationClient;
use crate::id::generate_id;
use crate::posting::render_content;
use crate::server::fw_pool;

#[derive(sqlx::FromRow)]
struct DeliveryRow {
    id: i64,
    target_inbox: String,
    sender_persona_id: String,
    activity_json: String,
    attempts: i32,
    private_key_pem: String,
    username: String,
}

impl std::fmt::Debug for DeliveryRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeliveryRow")
            .field("id", &self.id)
            .field("target_inbox", &self.target_inbox)
            .field("sender_persona_id", &self.sender_persona_id)
            .field("activity_json", &self.activity_json)
            .field("attempts", &self.attempts)
            .field("private_key_pem", &"[REDACTED]")
            .field("username", &self.username)
            .finish()
    }
}

static CIRCUIT_BREAKER: LazyLock<CircuitBreaker> = LazyLock::new(CircuitBreaker::new);

fn now_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

// -- Public API --

/// Enqueue a single activity delivery.
pub async fn enqueue_delivery(
    pool: &SqlitePool,
    target_inbox: &str,
    sender_persona_id: &str,
    activity_json: &serde_json::Value,
) -> anyhow::Result<()> {
    let json = serde_json::to_string(activity_json)?;
    let now = now_secs();
    fieldwork::delivery_db::enqueue(
        &fw_pool(pool),
        target_inbox,
        sender_persona_id,
        &json,
        now,
    )
    .await?;
    Ok(())
}

/// Fan-out an activity to every subscribed relay's inbox.
pub async fn enqueue_to_relays(
    pool: &SqlitePool,
    sender_persona_id: &str,
    activity: &serde_json::Value,
) -> anyhow::Result<()> {
    let relays = fieldwork::relay::get_accepted(&fw_pool(pool)).await?;

    for relay in relays {
        enqueue_delivery(pool, &relay.inbox_url, sender_persona_id, activity).await?;
    }

    Ok(())
}

/// Fan-out an activity to every follower's inbox (deduped by shared inbox).
pub async fn enqueue_to_followers(
    pool: &SqlitePool,
    sender_persona_id: &str,
    activity: &serde_json::Value,
) -> anyhow::Result<()> {
    let inboxes: Vec<(String,)> = sqlx::query_as(
        "SELECT DISTINCT COALESCE(ra.shared_inbox_url, ra.inbox_url) as inbox \
         FROM followers f \
         JOIN remote_accounts ra ON f.remote_account_id = ra.id \
         WHERE f.persona_id = ?",
    )
    .bind(sender_persona_id)
    .fetch_all(pool)
    .await?;

    for (inbox,) in inboxes {
        enqueue_delivery(pool, &inbox, sender_persona_id, activity).await?;
    }

    Ok(())
}

/// Long-running background task: poll `delivery_queue` and deliver activities.
pub async fn run_delivery_worker(pool: SqlitePool, config: Config) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(config.federation.delivery_timeout_secs))
        .user_agent(&config.federation.user_agent)
        .redirect(reqwest::redirect::Policy::none())
        .use_rustls_tls()
        .build()
        .expect("failed to build delivery HTTP client");

    let mut interval = tokio::time::interval(Duration::from_secs(5));
    loop {
        interval.tick().await;
        if let Err(e) = process_batch(&pool, &client, &config).await {
            tracing::error!("delivery worker error: {e}");
        }
    }
}

// -- Internals --

async fn process_batch(
    pool: &SqlitePool,
    client: &reqwest::Client,
    config: &Config,
) -> anyhow::Result<()> {
    let now = now_secs();

    let rows: Vec<DeliveryRow> = sqlx::query_as(
        "SELECT d.id, d.target_inbox, d.sender_persona_id, d.activity_json, d.attempts, \
                a.private_key_pem, a.username \
         FROM delivery_queue d \
         JOIN personas a ON d.sender_persona_id = a.id \
         WHERE d.delivered_at IS NULL AND d.dead_at IS NULL AND d.next_attempt_at <= ? \
         ORDER BY d.next_attempt_at \
         LIMIT ?",
    )
    .bind(now)
    .bind(config.federation.delivery_concurrency as i64)
    .fetch_all(pool)
    .await?;

    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(
        config.federation.delivery_concurrency,
    ));
    let mut handles = Vec::new();

    for row in rows {
        // Skip rows whose target domain has an open circuit breaker.
        if let Ok(url) = row.target_inbox.parse::<url::Url>() {
            if let Some(domain) = url.host_str() {
                if CIRCUIT_BREAKER.is_open(domain, now) {
                    continue;
                }
            }
        }

        let permit = match semaphore.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => break, // Semaphore closed; stop processing
        };
        let pool = pool.clone();
        let client = client.clone();
        let domain = config.server.domain.clone();

        handles.push(tokio::spawn(async move {
            let result = deliver_one(&client, &pool, &row, &domain).await;
            drop(permit);
            result
        }));
    }

    for handle in handles {
        if let Err(e) = handle.await {
            tracing::error!("delivery task panicked: {e}");
        }
    }

    // Process due scheduled posts
    if let Err(e) = process_scheduled_posts(pool, config).await {
        tracing::error!("scheduled posts error: {e}");
    }

    Ok(())
}

async fn deliver_one(
    client: &reqwest::Client,
    pool: &SqlitePool,
    row: &DeliveryRow,
    domain: &str,
) -> anyhow::Result<()> {
    let target_url: url::Url = row.target_inbox.parse()?;

    if let Err(e) = crate::federation::validate_outbound_url(&target_url) {
        mark_dead(pool, row.id, &e.to_string()).await?;
        return Ok(());
    }

    let key_id = format!("https://{domain}/users/{}#main-key", row.username);
    let body = row.activity_json.as_bytes();

    let mut headers =
        FederationClient::sign_post_headers(&row.private_key_pem, &key_id, &target_url, body)?;

    let target_domain = target_url.host_str().unwrap_or("unknown").to_owned();

    // FEP-8fcf: Include Collection-Synchronization header with follower digest
    // for the target domain so the remote server can detect follower drift.
    if let Some(digest) =
        crate::federation::compute_follower_sync_digest(pool, &row.sender_persona_id, &target_domain)
            .await
    {
        let sync_val =
            crate::federation::format_collection_sync_header(domain, &row.username, &digest);
        if let Ok(hv) = sync_val.parse() {
            headers.insert("Collection-Synchronization", hv);
        }
    }

    let result = client
        .post(target_url.as_str())
        .headers(headers)
        .header("Content-Type", "application/activity+json")
        .body(body.to_vec())
        .send()
        .await;

    let now_ms = chrono::Utc::now().timestamp_millis(); // millis for circuit breaker

    match result {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() {
                mark_delivered(pool, row.id).await?;
                CIRCUIT_BREAKER.record_success(&target_domain);
            } else if status == 410 {
                // Gone — this specific remote actor is deleted; no point retrying.
                // Don't trigger circuit breaker: 410 is resource-specific, not domain-wide.
                mark_dead(pool, row.id, "410 Gone").await?;
            } else if status.is_client_error() {
                // Client errors (4xx) are unlikely to succeed on retry.
                // Give one extra attempt in case of a transient proxy error,
                // then mark dead.
                if row.attempts >= 1 {
                    mark_dead(pool, row.id, &format!("HTTP {status}")).await?;
                } else {
                    schedule_retry(pool, row.id, row.attempts, &format!("HTTP {status}")).await?;
                }
                CIRCUIT_BREAKER.record_failure(&target_domain, now_ms);
            } else {
                // 5xx / other — retry with backoff.
                schedule_retry(pool, row.id, row.attempts, &format!("HTTP {status}")).await?;
                CIRCUIT_BREAKER.record_failure(&target_domain, now_ms);
            }
        }
        Err(e) => {
            schedule_retry(pool, row.id, row.attempts, &e.to_string()).await?;
            CIRCUIT_BREAKER.record_failure(&target_domain, now_ms);
        }
    }

    Ok(())
}

async fn mark_delivered(pool: &SqlitePool, id: i64) -> anyhow::Result<()> {
    fieldwork::delivery_db::mark_delivered(&fw_pool(pool), id, now_secs()).await?;
    Ok(())
}

async fn mark_dead(pool: &SqlitePool, id: i64, reason: &str) -> anyhow::Result<()> {
    fieldwork::delivery_db::mark_dead(&fw_pool(pool), id, reason, now_secs()).await?;
    Ok(())
}

async fn schedule_retry(
    pool: &SqlitePool,
    id: i64,
    _attempts: i32,
    error: &str,
) -> anyhow::Result<()> {
    fieldwork::delivery_db::schedule_retry(&fw_pool(pool), id, error, now_secs()).await?;
    Ok(())
}

// -- Scheduled posts --

/// Check for and create any scheduled posts that are now due.
async fn process_scheduled_posts(pool: &SqlitePool, config: &Config) -> anyhow::Result<()> {
    let now_ms = chrono::Utc::now().timestamp_millis();
    let domain = &config.server.domain;

    let due_posts: Vec<(i64, String, String)> = sqlx::query_as(
        "SELECT id, persona_id, params_json FROM scheduled_statuses \
         WHERE scheduled_at <= ? ORDER BY scheduled_at LIMIT 10",
    )
    .bind(now_ms)
    .fetch_all(pool)
    .await?;

    for (sched_id, account_id, params_json) in due_posts {
        if let Err(e) = create_scheduled_post(pool, domain, &account_id, &params_json, now_ms).await
        {
            tracing::error!("Failed to create scheduled post {sched_id}: {e}");
            // Delete the row anyway to avoid infinite retry of a broken scheduled post
        }

        sqlx::query("DELETE FROM scheduled_statuses WHERE id = ?")
            .bind(sched_id)
            .execute(pool)
            .await?;
    }

    Ok(())
}

/// Create a post from stored scheduled params. Simplified version of the
/// create_status handler — inserts the post row, renders content, inserts
/// tags/mentions, and enqueues delivery to followers.
async fn create_scheduled_post(
    pool: &SqlitePool,
    domain: &str,
    account_id: &str,
    params_json: &str,
    now_ms: i64,
) -> anyhow::Result<()> {
    let params: serde_json::Value = serde_json::from_str(params_json)?;

    let text = params.get("status").and_then(|v| v.as_str()).unwrap_or("");
    let visibility = params
        .get("visibility")
        .and_then(|v| v.as_str())
        .unwrap_or("public");
    let sensitive = params
        .get("sensitive")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let spoiler_text = params
        .get("spoiler_text")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let language = params.get("language").and_then(|v| v.as_str());

    let account: (String,) = sqlx::query_as("SELECT username FROM personas WHERE id = ?")
        .bind(account_id)
        .fetch_one(pool)
        .await?;
    let username = &account.0;

    let rendered = render_content(text, domain);
    let post_id = generate_id();
    let ap_id = format!("https://{domain}/users/{username}/statuses/{post_id}");
    // FEP-f228: scheduled posts are always originals (no in_reply_to), so they get their own context.
    let context_url = format!("{ap_id}/context");

    sqlx::query(
        "INSERT INTO posts (id, user_id, persona_id, ap_id, context_url, content, content_html, \
         spoiler_text, visibility, sensitive, language, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(post_id)
    .bind(crate::db::DEFAULT_USER_ID)
    .bind(account_id)
    .bind(&ap_id)
    .bind(&context_url)
    .bind(text)
    .bind(&rendered.html)
    .bind(spoiler_text)
    .bind(visibility)
    .bind(sensitive)
    .bind(language)
    .bind(now_ms)
    .execute(pool)
    .await?;

    // Attach media
    let media_ids: Vec<i64> = params
        .get("media_ids")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| {
                    v.as_str()
                        .and_then(|s| s.parse().ok())
                        .or_else(|| v.as_i64())
                })
                .collect()
        })
        .unwrap_or_default();
    for mid in &media_ids {
        sqlx::query(
            "UPDATE media SET post_id = ? WHERE id = ? AND persona_id = ? AND post_id IS NULL",
        )
        .bind(post_id)
        .bind(mid)
        .bind(account_id)
        .execute(pool)
        .await?;
    }

    // Insert tags
    for tag in &rendered.tags {
        sqlx::query("INSERT OR IGNORE INTO post_tags (post_id, tag) VALUES (?, ?)")
            .bind(post_id)
            .bind(tag)
            .execute(pool)
            .await?;
    }

    // Insert mentions
    for m in &rendered.mentions {
        match &m.domain {
            None => {
                let local: Option<(i64,)> =
                    sqlx::query_as("SELECT id FROM personas WHERE username = ?")
                        .bind(&m.username)
                        .fetch_optional(pool)
                        .await?;
                if let Some((aid,)) = local {
                    sqlx::query(
                        "INSERT OR IGNORE INTO mentions (post_id, mentioned_persona_id) \
                         VALUES (?, ?)",
                    )
                    .bind(post_id)
                    .bind(aid)
                    .execute(pool)
                    .await?;
                }
            }
            Some(mention_domain) => {
                let remote: Option<(i64,)> = sqlx::query_as(
                    "SELECT id FROM remote_accounts WHERE username = ? AND domain = ?",
                )
                .bind(&m.username)
                .bind(mention_domain)
                .fetch_optional(pool)
                .await?;
                if let Some((rid,)) = remote {
                    sqlx::query(
                        "INSERT OR IGNORE INTO mentions (post_id, mentioned_remote_id) \
                         VALUES (?, ?)",
                    )
                    .bind(post_id)
                    .bind(rid)
                    .execute(pool)
                    .await?;
                }
            }
        }
    }

    // Update last_status_at
    sqlx::query("UPDATE personas SET last_status_at = ? WHERE id = ?")
        .bind(now_ms)
        .bind(account_id)
        .execute(pool)
        .await?;

    // Query media attachments for the AP Note
    #[allow(clippy::type_complexity)]
    let ap_media: Vec<(
        String,
        String,
        Option<i32>,
        Option<i32>,
        Option<String>,
        String,
    )> = sqlx::query_as(
        "SELECT file_path, mime_type, width, height, blurhash, description \
             FROM media WHERE post_id = ? ORDER BY id",
    )
    .bind(post_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let ap_attachments: Vec<serde_json::Value> = ap_media
        .iter()
        .map(
            |(file_path, mime_type, width, height, blurhash, description)| {
                let mut doc = serde_json::json!({
                    "type": "Document",
                    "mediaType": mime_type,
                    "url": format!("https://{domain}/media/{file_path}"),
                    "name": description,
                });
                if let Some(bh) = blurhash {
                    doc["blurhash"] = serde_json::json!(bh);
                }
                if let Some(w) = width {
                    doc["width"] = serde_json::json!(w);
                }
                if let Some(h) = height {
                    doc["height"] = serde_json::json!(h);
                }
                doc
            },
        )
        .collect();

    // Enqueue federation Create{Note}
    let actor = format!("https://{domain}/users/{username}");
    let note_id = format!("{actor}/statuses/{post_id}");
    let followers_url = format!("{actor}/followers");
    let published = millis_to_iso(now_ms);
    let public = "https://www.w3.org/ns/activitystreams#Public";

    let (to, cc) = match visibility {
        "public" => (
            vec![serde_json::json!(public)],
            vec![serde_json::json!(&followers_url)],
        ),
        "unlisted" => (
            vec![serde_json::json!(&followers_url)],
            vec![serde_json::json!(public)],
        ),
        "private" => (vec![serde_json::json!(&followers_url)], vec![]),
        _ => (
            vec![serde_json::json!(public)],
            vec![serde_json::json!(&followers_url)],
        ),
    };

    let activity = serde_json::json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": format!("{note_id}/activity"),
        "type": "Create",
        "actor": &actor,
        "published": &published,
        "to": &to,
        "cc": &cc,
        "object": {
            "id": &note_id,
            "type": "Note",
            "attributedTo": &actor,
            "context": &context_url,
            "content": &rendered.html,
            "url": format!("https://{domain}/@{username}/{post_id}"),
            "to": &to,
            "cc": &cc,
            "published": &published,
            "sensitive": sensitive,
            "summary": if spoiler_text.is_empty() { None } else { Some(spoiler_text) },
            "attachment": &ap_attachments,
        }
    });

    if let Err(e) = enqueue_to_followers(pool, account_id, &activity).await {
        tracing::error!("Failed to enqueue scheduled Create activity: {e}");
    }

    // Also fan out to relays for public posts
    if visibility == "public" {
        if let Err(e) = enqueue_to_relays(pool, account_id, &activity).await {
            tracing::debug!("Failed to enqueue to relays: {e}");
        }
    }

    // ponytail: search index lives in AppState which the delivery worker doesn't
    // have access to. Scheduled posts won't appear in search until the next
    // `smallhold search reindex` or a full reindex is triggered. Upgrade path:
    // pass Arc<AppState> to the delivery worker instead of bare pool+config.

    // Emit streaming event so connected clients see the post immediately
    crate::streaming::publish(crate::streaming::StreamEvent {
        event_type: "update".to_string(),
        payload: activity["object"].to_string(),
        channel: format!("user:{account_id}"),
    });

    tracing::info!("Created scheduled post {post_id} for @{username}");
    Ok(())
}
