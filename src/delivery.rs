use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use sqlx::SqlitePool;

use crate::config::Config;
use crate::federation::FederationClient;
use crate::id::generate_id;

#[derive(sqlx::FromRow)]
struct DeliveryRow {
    id: i64,
    target_inbox: String,
    #[allow(dead_code)]
    sender_account_id: i64,
    activity_json: String,
    attempts: i32,
    private_key_pem: String,
    username: String,
}

const MAX_ATTEMPTS: i32 = 6;

/// Exponential backoff schedule in milliseconds.
fn retry_delay_ms(attempt: i32) -> i64 {
    match attempt {
        0 => 60_000,       // 1 minute
        1 => 300_000,      // 5 minutes
        2 => 1_800_000,    // 30 minutes
        3 => 7_200_000,    // 2 hours
        4 => 28_800_000,   // 8 hours
        _ => 86_400_000,   // 24 hours
    }
}

// -- Circuit breaker (per-domain) --

struct CircuitState {
    consecutive_failures: u32,
    /// Unix timestamp (ms) until which the circuit is open; `None` = closed.
    open_until: Option<i64>,
}

const CIRCUIT_THRESHOLD: u32 = 10;
const CIRCUIT_OPEN_MS: i64 = 3_600_000; // 1 hour

static CIRCUIT_BREAKER: LazyLock<Mutex<HashMap<String, CircuitState>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Returns `true` if deliveries to `domain` are currently paused.
fn circuit_is_open(domain: &str, now_ms: i64) -> bool {
    let map = CIRCUIT_BREAKER.lock().unwrap();
    match map.get(domain) {
        Some(state) => matches!(state.open_until, Some(until) if now_ms < until),
        None => false,
    }
}

fn circuit_record_success(domain: &str) {
    let mut map = CIRCUIT_BREAKER.lock().unwrap();
    map.remove(domain);
}

fn circuit_record_failure(domain: &str, now_ms: i64) {
    let mut map = CIRCUIT_BREAKER.lock().unwrap();
    let state = map.entry(domain.to_owned()).or_insert(CircuitState {
        consecutive_failures: 0,
        open_until: None,
    });
    state.consecutive_failures += 1;
    if state.consecutive_failures >= CIRCUIT_THRESHOLD {
        state.open_until = Some(now_ms + CIRCUIT_OPEN_MS);
    }
}

// -- Public API --

/// Enqueue a single activity delivery.
pub async fn enqueue_delivery(
    pool: &SqlitePool,
    target_inbox: &str,
    sender_account_id: i64,
    activity_json: &serde_json::Value,
) -> anyhow::Result<()> {
    let id = generate_id();
    let now = chrono::Utc::now().timestamp_millis();
    let json = serde_json::to_string(activity_json)?;

    sqlx::query(
        "INSERT INTO delivery_queue \
         (id, target_inbox, sender_account_id, activity_json, attempts, next_attempt_at, created_at) \
         VALUES (?, ?, ?, ?, 0, ?, ?)",
    )
    .bind(id)
    .bind(target_inbox)
    .bind(sender_account_id)
    .bind(&json)
    .bind(now)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(())
}

/// Fan-out an activity to every follower's inbox (deduped by shared inbox).
pub async fn enqueue_to_followers(
    pool: &SqlitePool,
    sender_account_id: i64,
    activity: &serde_json::Value,
) -> anyhow::Result<()> {
    let inboxes: Vec<(String,)> = sqlx::query_as(
        "SELECT DISTINCT COALESCE(ra.shared_inbox_url, ra.inbox_url) as inbox \
         FROM followers f \
         JOIN remote_accounts ra ON f.remote_account_id = ra.id \
         WHERE f.local_account_id = ?",
    )
    .bind(sender_account_id)
    .fetch_all(pool)
    .await?;

    for (inbox,) in inboxes {
        enqueue_delivery(pool, &inbox, sender_account_id, activity).await?;
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
    let now = chrono::Utc::now().timestamp_millis();

    let rows: Vec<DeliveryRow> = sqlx::query_as(
        "SELECT d.id, d.target_inbox, d.sender_account_id, d.activity_json, d.attempts, \
                a.private_key_pem, a.username \
         FROM delivery_queue d \
         JOIN accounts a ON d.sender_account_id = a.id \
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
                if circuit_is_open(domain, now) {
                    continue;
                }
            }
        }

        let permit = semaphore.clone().acquire_owned().await.unwrap();
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

    let headers = FederationClient::sign_post_headers(&row.private_key_pem, &key_id, &target_url, body)?;

    let target_domain = target_url
        .host_str()
        .unwrap_or("unknown")
        .to_owned();

    let result = client
        .post(target_url.as_str())
        .headers(headers)
        .header("Content-Type", "application/activity+json")
        .body(body.to_vec())
        .send()
        .await;

    let now_ms = chrono::Utc::now().timestamp_millis();

    match result {
        Ok(resp) => {
            let status = resp.status();
            if status.is_success() || status == 202 {
                mark_delivered(pool, row.id).await?;
                circuit_record_success(&target_domain);
            } else if status == 410 {
                // Gone — remote actor deleted; no point retrying.
                mark_dead(pool, row.id, "410 Gone").await?;
                circuit_record_failure(&target_domain, now_ms);
            } else if status.is_client_error() {
                // Client errors (4xx) are unlikely to succeed on retry.
                // Give one extra attempt in case of a transient proxy error,
                // then mark dead.
                if row.attempts >= 1 {
                    mark_dead(pool, row.id, &format!("HTTP {status}")).await?;
                } else {
                    schedule_retry(pool, row.id, row.attempts, &format!("HTTP {status}")).await?;
                }
                circuit_record_failure(&target_domain, now_ms);
            } else {
                // 5xx / other — retry with backoff.
                schedule_retry(pool, row.id, row.attempts, &format!("HTTP {status}")).await?;
                circuit_record_failure(&target_domain, now_ms);
            }
        }
        Err(e) => {
            schedule_retry(pool, row.id, row.attempts, &e.to_string()).await?;
            circuit_record_failure(&target_domain, now_ms);
        }
    }

    Ok(())
}

async fn mark_delivered(pool: &SqlitePool, id: i64) -> anyhow::Result<()> {
    let now = chrono::Utc::now().timestamp_millis();
    sqlx::query("UPDATE delivery_queue SET delivered_at = ? WHERE id = ?")
        .bind(now)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

async fn mark_dead(pool: &SqlitePool, id: i64, reason: &str) -> anyhow::Result<()> {
    let now = chrono::Utc::now().timestamp_millis();
    sqlx::query("UPDATE delivery_queue SET dead_at = ?, last_error = ? WHERE id = ?")
        .bind(now)
        .bind(reason)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

async fn schedule_retry(
    pool: &SqlitePool,
    id: i64,
    attempts: i32,
    error: &str,
) -> anyhow::Result<()> {
    let next_attempt = attempts + 1;
    if next_attempt >= MAX_ATTEMPTS {
        return mark_dead(pool, id, error).await;
    }

    let now = chrono::Utc::now().timestamp_millis();
    let next_at = now + retry_delay_ms(attempts);

    sqlx::query(
        "UPDATE delivery_queue \
         SET attempts = ?, next_attempt_at = ?, last_error = ? \
         WHERE id = ?",
    )
    .bind(next_attempt)
    .bind(next_at)
    .bind(error)
    .bind(id)
    .execute(pool)
    .await?;

    Ok(())
}
