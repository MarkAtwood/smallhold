use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use axum::Router;
use base64::Engine;
use serde_json::Value;
use sqlx::SqlitePool;
use std::sync::Arc;

use crate::delivery;
use crate::error::AppError;
use crate::federation::{upsert_remote_account, FederationClient, RemoteActorData};
use crate::id::generate_id;
use crate::server::AppState;
use crate::streaming::{publish, StreamEvent};

// Length caps for inbound string fields.
const MAX_CONTENT_LEN: usize = 100_000;
const MAX_SPOILER_LEN: usize = 500;
const MAX_URI_LEN: usize = 2048;
const MAX_LANGUAGE_LEN: usize = 10;

/// Pre-check JSON nesting depth without fully parsing.
fn check_json_depth(bytes: &[u8], max_depth: usize) -> bool {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escape = false;
    for &b in bytes {
        if escape {
            escape = false;
            continue;
        }
        if b == b'\\' && in_string {
            escape = true;
            continue;
        }
        if b == b'"' {
            in_string = !in_string;
            continue;
        }
        if in_string {
            continue;
        }
        match b {
            b'{' | b'[' => {
                depth += 1;
                if depth > max_depth {
                    return false;
                }
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
    }
    true
}

/// Subset of remote_accounts needed for inbox processing.
#[derive(Debug)]
struct RemoteAccountRow {
    id: i64,
    actor_uri: String,
    public_key_pem: String,
    inbox_url: String,
    shared_inbox_url: Option<String>,
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/inbox", post(shared_inbox))
        .route("/users/{username}/inbox", post(user_inbox))
}

/// POST /inbox — shared inbox, dispatches to all relevant local actors.
async fn shared_inbox(
    State(state): State<Arc<AppState>>,
    request: axum::extract::Request,
) -> Result<impl IntoResponse, AppError> {
    let (parts, body) = request.into_parts();
    let path = parts.uri.path().to_string();
    let headers = parts.headers;
    let body = axum::body::to_bytes(body, 10 * 1024 * 1024)
        .await
        .map_err(|_| AppError::bad_request("request body too large"))?;
    process_inbox(&state, &headers, &body, &path).await?;
    Ok(StatusCode::ACCEPTED)
}

/// POST /users/{username}/inbox — per-actor inbox.
async fn user_inbox(
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
    request: axum::extract::Request,
) -> Result<impl IntoResponse, AppError> {
    // Verify the target account exists.
    let exists: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM accounts WHERE username = ?")
        .bind(&username)
        .fetch_one(&state.pool)
        .await?;
    if exists.0 == 0 {
        return Err(AppError::not_found("Account not found"));
    }

    let (parts, body) = request.into_parts();
    let path = parts.uri.path().to_string();
    let headers = parts.headers;
    let body = axum::body::to_bytes(body, 10 * 1024 * 1024)
        .await
        .map_err(|_| AppError::bad_request("request body too large"))?;
    process_inbox(&state, &headers, &body, &path).await?;
    Ok(StatusCode::ACCEPTED)
}

/// Core inbox processing: parse, verify signature, dispatch by activity type.
async fn process_inbox(
    state: &AppState,
    headers: &HeaderMap,
    body: &[u8],
    request_path: &str,
) -> Result<(), AppError> {
    if !check_json_depth(body, 50) {
        return Err(AppError::bad_request("JSON nesting too deep"));
    }
    let activity: Value =
        serde_json::from_slice(body).map_err(|_| AppError::bad_request("invalid JSON"))?;

    let actor_uri = activity["actor"]
        .as_str()
        .ok_or_else(|| AppError::bad_request("missing actor"))?;

    if actor_uri.len() > MAX_URI_LEN {
        return Err(AppError::bad_request("actor URI too long"));
    }

    let remote_account =
        verify_and_fetch_actor(state, headers, body, actor_uri, request_path).await?;

    let activity_type = activity["type"].as_str().unwrap_or("");
    tracing::info!(
        activity_type = activity_type,
        actor = actor_uri,
        "processing inbound activity"
    );
    tracing::trace!(body = %String::from_utf8_lossy(body), "full activity body");

    match activity_type {
        "Follow" => handle_follow(state, &activity, &remote_account).await,
        "Undo" => handle_undo(state, &activity, &remote_account).await,
        "Create" => handle_create(state, &activity, &remote_account).await,
        "Update" => handle_update(state, &activity, &remote_account).await,
        "Delete" => handle_delete(state, &activity, &remote_account).await,
        "Like" => handle_like(state, &activity, &remote_account).await,
        "Announce" => handle_announce(state, &activity, &remote_account).await,
        "Block" => handle_block(state, &activity, &remote_account).await,
        "Move" => handle_move(state, &activity, &remote_account).await,
        "Accept" => handle_accept(state, &activity, &remote_account).await,
        "Reject" => handle_reject(state, &activity, &remote_account).await,
        _ => {
            tracing::debug!("ignoring unknown activity type: {activity_type}");
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP Signature verification
// ---------------------------------------------------------------------------

/// Parsed components of a draft-cavage HTTP Signature header.
#[derive(Debug)]
struct SignatureParams {
    key_id: String,
    headers_list: Vec<String>,
    signature_bytes: Vec<u8>,
}

/// Parse the `Signature` header value into its components.
fn parse_signature_header(header_val: &str) -> Result<SignatureParams, AppError> {
    let mut key_id = None;
    let mut headers_list = None;
    let mut signature_b64 = None;

    // Format: keyId="...",algorithm="...",headers="...",signature="..."
    // Values may contain commas inside quotes, so we parse key="value" pairs.
    let mut remaining = header_val.trim();
    while !remaining.is_empty() {
        remaining = remaining.trim_start_matches(|c: char| c == ',' || c.is_whitespace());
        if remaining.is_empty() {
            break;
        }
        let eq_pos = remaining
            .find('=')
            .ok_or_else(|| AppError::bad_request("malformed Signature header"))?;
        let param_name = remaining[..eq_pos].trim();
        remaining = &remaining[eq_pos + 1..];

        // Value is quoted
        if !remaining.starts_with('"') {
            return Err(AppError::bad_request(
                "malformed Signature header: unquoted value",
            ));
        }
        remaining = &remaining[1..]; // skip opening quote
        let close_quote = remaining
            .find('"')
            .ok_or_else(|| AppError::bad_request("malformed Signature header: unclosed quote"))?;
        let value = &remaining[..close_quote];
        remaining = &remaining[close_quote + 1..];

        match param_name {
            "keyId" => key_id = Some(value.to_string()),
            "headers" => {
                headers_list = Some(
                    value
                        .split_whitespace()
                        .map(String::from)
                        .collect::<Vec<_>>(),
                );
            }
            "signature" => {
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(value)
                    .map_err(|_| AppError::bad_request("invalid base64 in Signature"))?;
                signature_b64 = Some(decoded);
            }
            _ => { /* ignore algorithm, etc. */ }
        }
    }

    let key_id = key_id.ok_or_else(|| AppError::bad_request("Signature header missing keyId"))?;
    let headers_list =
        headers_list.ok_or_else(|| AppError::bad_request("Signature header missing headers"))?;
    let signature_bytes =
        signature_b64.ok_or_else(|| AppError::bad_request("Signature header missing signature"))?;

    if key_id.len() > MAX_URI_LEN {
        return Err(AppError::bad_request("keyId too long"));
    }

    Ok(SignatureParams {
        key_id,
        headers_list,
        signature_bytes,
    })
}

/// Reconstruct the signed string from the listed headers.
fn build_signed_string(
    headers_list: &[String],
    http_headers: &HeaderMap,
    body: &[u8],
    request_path: &str,
) -> Result<String, AppError> {
    let mut parts = Vec::with_capacity(headers_list.len());

    for header_name in headers_list {
        let value = match header_name.as_str() {
            "(request-target)" => format!("post {request_path}"),
            "digest" => {
                // Recompute the digest from the body and use that.
                // If a Digest header is present, we verify it matches.
                use sha2::Digest;
                let computed_hash = sha2::Sha256::digest(body);
                let computed_b64 = base64::engine::general_purpose::STANDARD.encode(computed_hash);
                let computed_digest = format!("SHA-256={computed_b64}");

                if let Some(header_val) = http_headers.get("digest") {
                    let sent_digest = header_val
                        .to_str()
                        .map_err(|_| AppError::bad_request("invalid Digest header encoding"))?;
                    if sent_digest != computed_digest {
                        return Err(AppError::unauthorized("Digest mismatch"));
                    }
                }

                computed_digest
            }
            other => {
                let hv = http_headers.get(other).ok_or_else(|| {
                    AppError::bad_request(format!("Signature references missing header: {other}"))
                })?;
                hv.to_str()
                    .map_err(|_| AppError::bad_request(format!("non-ASCII header value: {other}")))?
                    .to_string()
            }
        };
        parts.push(format!("{header_name}: {value}"));
    }

    Ok(parts.join("\n"))
}

/// Verify an RSA-SHA256 signature against a public key PEM.
fn verify_rsa_sha256(
    public_key_pem: &str,
    signed_string: &[u8],
    signature_bytes: &[u8],
) -> Result<(), AppError> {
    use rsa::pkcs8::DecodePublicKey;
    use rsa::signature::Verifier;
    use rsa::RsaPublicKey;
    use sha2::Sha256;

    let public_key = RsaPublicKey::from_public_key_pem(public_key_pem)
        .map_err(|_| AppError::unauthorized("invalid remote public key"))?;
    let verifying_key = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(public_key);
    let signature = rsa::pkcs1v15::Signature::try_from(signature_bytes)
        .map_err(|_| AppError::unauthorized("invalid signature format"))?;

    verifying_key
        .verify(signed_string, &signature)
        .map_err(|_| AppError::unauthorized("signature verification failed"))
}

/// Look up a remote account by key_id in our database.
async fn lookup_by_key_id(
    pool: &SqlitePool,
    key_id: &str,
) -> Result<Option<RemoteAccountRow>, AppError> {
    let row: Option<(i64, String, String, String, Option<String>)> = sqlx::query_as(
        "SELECT id, actor_uri, public_key_pem, inbox_url, shared_inbox_url
         FROM remote_accounts WHERE public_key_id = ? LIMIT 1",
    )
    .bind(key_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(
        |(id, actor_uri, public_key_pem, inbox_url, shared_inbox_url)| RemoteAccountRow {
            id,
            actor_uri,
            public_key_pem,
            inbox_url,
            shared_inbox_url,
        },
    ))
}

/// Get a local account's private key and key_id for signing outbound fetches.
/// Uses the first local account found.
async fn get_signing_credentials(state: &AppState) -> Result<(String, String), AppError> {
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT username, private_key_pem FROM accounts LIMIT 1")
            .fetch_optional(&state.pool)
            .await?;

    let (username, private_key_pem) =
        row.ok_or_else(|| AppError::internal("no local accounts configured"))?;

    let domain = &state.config.server.domain;
    let key_id = format!("https://{domain}/users/{username}#main-key");
    Ok((private_key_pem, key_id))
}

/// Fetch a remote actor, upsert into our database, and return the account row.
async fn fetch_and_upsert_actor(
    state: &AppState,
    actor_uri: &str,
) -> Result<RemoteAccountRow, AppError> {
    let (signing_key_pem, signing_key_id) = get_signing_credentials(state).await?;

    let fed_client = FederationClient::new(&state.config)
        .map_err(|e| AppError::internal(format!("federation client: {e}")))?;

    let actor_data: RemoteActorData = fed_client
        .fetch_actor(actor_uri, &signing_key_pem, &signing_key_id)
        .await
        .map_err(|e| {
            tracing::warn!(actor_uri, error = %e, "failed to fetch remote actor");
            AppError::unauthorized(format!("failed to fetch actor: {e}"))
        })?;

    let id = upsert_remote_account(&state.pool, &actor_data)
        .await
        .map_err(|e| AppError::internal(format!("upsert remote account: {e}")))?;

    Ok(RemoteAccountRow {
        id,
        actor_uri: actor_data.actor_uri,
        public_key_pem: actor_data.public_key_pem,
        inbox_url: actor_data.inbox_url,
        shared_inbox_url: actor_data.shared_inbox_url,
    })
}

/// Verify the HTTP signature on an inbox delivery and return the remote account.
///
/// Strategy: look up the key_id in remote_accounts first; if not found, fetch the
/// actor. If verification fails with a cached key, re-fetch (key rotation).
async fn verify_and_fetch_actor(
    state: &AppState,
    headers: &HeaderMap,
    body: &[u8],
    actor_uri: &str,
    request_path: &str,
) -> Result<RemoteAccountRow, AppError> {
    // Check Date header freshness (±5 minutes)
    let date_val = headers
        .get("date")
        .ok_or_else(|| AppError::unauthorized("Missing Date header"))?;
    if let Ok(date_str) = date_val.to_str() {
        if let Ok(parsed) = chrono::DateTime::parse_from_rfc2822(date_str) {
            let now = chrono::Utc::now();
            let diff = (now - parsed.with_timezone(&chrono::Utc))
                .num_seconds()
                .abs();
            if diff > 300 {
                return Err(AppError::unauthorized(
                    "Date header too old or too far in future",
                ));
            }
        }
    }

    let sig_header_val = headers
        .get("signature")
        .ok_or_else(|| AppError::unauthorized("missing Signature header"))?
        .to_str()
        .map_err(|_| AppError::bad_request("non-ASCII Signature header"))?;

    let sig_params = parse_signature_header(sig_header_val)?;

    if !sig_params.headers_list.iter().any(|h| h == "digest") {
        return Err(AppError::unauthorized(
            "Signature must include digest header",
        ));
    }

    if !sig_params.headers_list.iter().any(|h| h == "date") {
        return Err(AppError::unauthorized("Signature must include date header"));
    }

    // The keyId typically looks like "https://remote.example/users/alice#main-key".
    // The actor URI should be the keyId minus the fragment.
    let key_actor_uri = sig_params
        .key_id
        .split('#')
        .next()
        .unwrap_or(&sig_params.key_id);

    // Verify the key belongs to the claimed actor (anti-spoofing).
    if key_actor_uri != actor_uri {
        return Err(AppError::unauthorized(
            "Signature keyId does not match activity actor",
        ));
    }

    let signed_string = build_signed_string(&sig_params.headers_list, headers, body, request_path)?;

    // Try cached key first.
    if let Some(cached) = lookup_by_key_id(&state.pool, &sig_params.key_id).await? {
        if verify_rsa_sha256(
            &cached.public_key_pem,
            signed_string.as_bytes(),
            &sig_params.signature_bytes,
        )
        .is_ok()
        {
            return Ok(cached);
        }
        // Verification failed with cached key — try re-fetching (key rotation).
        tracing::info!(
            actor = actor_uri,
            "signature failed with cached key, re-fetching"
        );
    }

    // Fetch (or re-fetch) the actor.
    let account = fetch_and_upsert_actor(state, actor_uri).await?;

    verify_rsa_sha256(
        &account.public_key_pem,
        signed_string.as_bytes(),
        &sig_params.signature_bytes,
    )?;

    Ok(account)
}

// ---------------------------------------------------------------------------
// Helper: truncate a string to a max byte length at a char boundary.
// ---------------------------------------------------------------------------

fn truncate_str(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Extract a URI string from a Value that may be a string or {"id": "..."}.
fn object_id(val: &Value) -> Option<&str> {
    val.as_str().or_else(|| val["id"].as_str())
}

/// Collect all URIs from the `to` and `cc` fields of an activity.
fn collect_recipients(activity: &Value) -> Vec<&str> {
    let mut uris = Vec::new();
    for field in &["to", "cc"] {
        match &activity[*field] {
            Value::String(s) => uris.push(s.as_str()),
            Value::Array(arr) => {
                for item in arr {
                    if let Some(s) = item.as_str() {
                        uris.push(s);
                    }
                }
            }
            _ => {}
        }
    }
    uris
}

/// Resolve a local account URI (https://domain/users/username) to an account ID.
async fn resolve_local_account(
    pool: &SqlitePool,
    domain: &str,
    uri: &str,
) -> Result<Option<(i64, String, bool)>, AppError> {
    let prefix = format!("https://{domain}/users/");
    let username = match uri.strip_prefix(&prefix) {
        Some(u) => u,
        None => return Ok(None),
    };

    let row: Option<(i64, String, bool)> =
        sqlx::query_as("SELECT id, username, is_locked FROM accounts WHERE username = ? LIMIT 1")
            .bind(username)
            .fetch_optional(pool)
            .await?;

    Ok(row)
}

/// Enqueue an activity for delivery to a remote inbox.
async fn enqueue_activity(
    pool: &SqlitePool,
    target_inbox: &str,
    sender_account_id: i64,
    activity: &Value,
) -> Result<(), AppError> {
    delivery::enqueue_delivery(pool, target_inbox, sender_account_id, activity)
        .await
        .map_err(|e| AppError::internal(format!("enqueue delivery: {e}")))
}

// ---------------------------------------------------------------------------
// Activity handlers
// ---------------------------------------------------------------------------

/// Handle a Follow activity.
///
/// If the target local account is not locked, auto-accept: insert into `followers`
/// and send back an Accept. If locked, insert into `follow_requests`.
async fn handle_follow(
    state: &AppState,
    activity: &Value,
    remote: &RemoteAccountRow,
) -> Result<(), AppError> {
    let object_uri = object_id(&activity["object"])
        .ok_or_else(|| AppError::bad_request("Follow missing object"))?;

    if object_uri.len() > MAX_URI_LEN {
        return Err(AppError::bad_request("Follow object URI too long"));
    }

    let domain = &state.config.server.domain;
    let (account_id, username, is_locked) = resolve_local_account(&state.pool, domain, object_uri)
        .await?
        .ok_or_else(|| AppError::not_found("Follow target not found"))?;

    let now = chrono::Utc::now().timestamp();

    if is_locked {
        // Insert into follow_requests.
        let ap_id = activity["id"].as_str().unwrap_or("").to_string();
        if ap_id.is_empty() {
            return Err(AppError::bad_request("Follow activity missing id"));
        }
        let req_id = generate_id();

        sqlx::query(
            "INSERT OR IGNORE INTO follow_requests (id, requester_remote_id, target_account_id, ap_id, created_at)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(req_id)
        .bind(remote.id)
        .bind(account_id)
        .bind(&ap_id)
        .bind(now)
        .execute(&state.pool)
        .await?;

        tracing::info!(
            follower = %remote.actor_uri,
            target = username,
            "follow request queued (account is locked)"
        );
    } else {
        // Auto-accept: insert into followers.
        sqlx::query(
            "INSERT OR IGNORE INTO followers (local_account_id, remote_account_id, accepted_at)
             VALUES (?, ?, ?)",
        )
        .bind(account_id)
        .bind(remote.id)
        .bind(now)
        .execute(&state.pool)
        .await?;

        // Create a notification.
        let notif_id = generate_id();
        sqlx::query(
            "INSERT INTO notifications (id, account_id, kind, from_remote_account_id, created_at)
             VALUES (?, ?, 'follow', ?, ?)",
        )
        .bind(notif_id)
        .bind(account_id)
        .bind(remote.id)
        .bind(now)
        .execute(&state.pool)
        .await?;

        // Fire-and-forget push notification
        let pool = state.pool.clone();
        let actor = remote.actor_uri.clone();
        let push_domain = domain.clone();
        tokio::spawn(async move {
            crate::push::send_push_notification(
                &pool,
                account_id,
                "follow",
                "New follower",
                &actor,
                None,
                &push_domain,
            )
            .await;
        });

        // Send Accept back.
        let accept_id = generate_id();
        let accept_activity = serde_json::json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": format!("https://{domain}/activities/accept-{accept_id}"),
            "type": "Accept",
            "actor": format!("https://{domain}/users/{username}"),
            "object": activity
        });

        let target_inbox = remote
            .shared_inbox_url
            .as_deref()
            .unwrap_or(&remote.inbox_url);

        enqueue_activity(&state.pool, target_inbox, account_id, &accept_activity).await?;

        tracing::info!(
            follower = %remote.actor_uri,
            target = username,
            "follow accepted"
        );
    }

    Ok(())
}

/// Handle an Undo activity. Dispatches by the inner object type.
async fn handle_undo(
    state: &AppState,
    activity: &Value,
    remote: &RemoteAccountRow,
) -> Result<(), AppError> {
    let inner = &activity["object"];
    let inner_type = inner["type"].as_str().unwrap_or("");

    match inner_type {
        "Follow" => handle_undo_follow(state, inner, remote).await,
        "Like" => handle_undo_like(state, inner, remote).await,
        "Announce" => handle_undo_announce(state, inner, remote).await,
        _ => {
            tracing::debug!("ignoring Undo of unknown type: {inner_type}");
            Ok(())
        }
    }
}

/// Undo Follow: remove the remote account from our followers table.
async fn handle_undo_follow(
    state: &AppState,
    inner: &Value,
    remote: &RemoteAccountRow,
) -> Result<(), AppError> {
    let object_uri = object_id(&inner["object"])
        .ok_or_else(|| AppError::bad_request("Undo Follow missing object"))?;

    let domain = &state.config.server.domain;
    if let Some((account_id, _, _)) = resolve_local_account(&state.pool, domain, object_uri).await?
    {
        sqlx::query("DELETE FROM followers WHERE local_account_id = ? AND remote_account_id = ?")
            .bind(account_id)
            .bind(remote.id)
            .execute(&state.pool)
            .await?;

        // Also remove any pending follow request.
        sqlx::query(
            "DELETE FROM follow_requests WHERE requester_remote_id = ? AND target_account_id = ?",
        )
        .bind(remote.id)
        .bind(account_id)
        .execute(&state.pool)
        .await?;

        tracing::info!(
            follower = %remote.actor_uri,
            target_account_id = account_id,
            "unfollowed"
        );
    }

    Ok(())
}

/// Undo Like: remove the like notification.
async fn handle_undo_like(
    state: &AppState,
    inner: &Value,
    remote: &RemoteAccountRow,
) -> Result<(), AppError> {
    // The inner object's `object` field is the URI of the liked post.
    let liked_uri = object_id(&inner["object"]).unwrap_or("");
    if !liked_uri.is_empty() {
        // Find local post by ap_id, then delete the favourite notification.
        let post_row: Option<(i64, i64)> =
            sqlx::query_as("SELECT id, account_id FROM posts WHERE ap_id = ? LIMIT 1")
                .bind(liked_uri)
                .fetch_optional(&state.pool)
                .await?;

        if let Some((post_id, account_id)) = post_row {
            sqlx::query(
                "DELETE FROM notifications
                 WHERE account_id = ? AND kind = 'favourite' AND from_remote_account_id = ? AND post_id = ?",
            )
            .bind(account_id)
            .bind(remote.id)
            .bind(post_id)
            .execute(&state.pool)
            .await?;
        }
    }

    Ok(())
}

/// Undo Announce: remove the reblog notification.
async fn handle_undo_announce(
    state: &AppState,
    inner: &Value,
    remote: &RemoteAccountRow,
) -> Result<(), AppError> {
    let boosted_uri = object_id(&inner["object"]).unwrap_or("");
    if !boosted_uri.is_empty() {
        let post_row: Option<(i64, i64)> =
            sqlx::query_as("SELECT id, account_id FROM posts WHERE ap_id = ? LIMIT 1")
                .bind(boosted_uri)
                .fetch_optional(&state.pool)
                .await?;

        if let Some((post_id, account_id)) = post_row {
            sqlx::query(
                "DELETE FROM notifications
                 WHERE account_id = ? AND kind = 'reblog' AND from_remote_account_id = ? AND post_id = ?",
            )
            .bind(account_id)
            .bind(remote.id)
            .bind(post_id)
            .execute(&state.pool)
            .await?;
        }
    }

    Ok(())
}

/// Handle a Create activity. Expected inner object is a Note.
async fn handle_create(
    state: &AppState,
    activity: &Value,
    remote: &RemoteAccountRow,
) -> Result<(), AppError> {
    let object = &activity["object"];
    let object_type = object["type"].as_str().unwrap_or("");

    if object_type != "Note" {
        tracing::debug!("ignoring Create of non-Note type: {object_type}");
        return Ok(());
    }

    let ap_uri = object["id"]
        .as_str()
        .ok_or_else(|| AppError::bad_request("Create Note missing id"))?;
    if ap_uri.len() > MAX_URI_LEN {
        return Err(AppError::bad_request("Note id too long"));
    }

    let raw_content = object["content"].as_str().unwrap_or("");
    let content_html = ammonia::clean(truncate_str(raw_content, MAX_CONTENT_LEN));

    let spoiler_text = object["summary"]
        .as_str()
        .map(|s| truncate_str(s, MAX_SPOILER_LEN).to_string())
        .unwrap_or_default();

    let sensitive = object["sensitive"].as_bool().unwrap_or(false);

    let language = object["contentMap"]
        .as_object()
        .and_then(|m| m.keys().next())
        .map(|k| truncate_str(k, MAX_LANGUAGE_LEN).to_string());

    let in_reply_to_uri = object["inReplyTo"]
        .as_str()
        .filter(|s| s.len() <= MAX_URI_LEN)
        .map(String::from);

    // Determine visibility from addressing.
    let visibility = determine_visibility(activity, object);

    let now = chrono::Utc::now().timestamp();
    let published = object["published"]
        .as_str()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.timestamp())
        .unwrap_or(now);

    let post_id = generate_id();

    sqlx::query(
        "INSERT OR IGNORE INTO remote_posts
         (id, ap_uri, remote_account_id, in_reply_to_uri, content_html, spoiler_text, visibility, sensitive, language, created_at, fetched_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(post_id)
    .bind(ap_uri)
    .bind(remote.id)
    .bind(&in_reply_to_uri)
    .bind(&content_html)
    .bind(&spoiler_text)
    .bind(&visibility)
    .bind(sensitive)
    .bind(&language)
    .bind(published)
    .bind(now)
    .execute(&state.pool)
    .await?;

    // Publish to public streaming timeline
    if visibility == "public" || visibility == "unlisted" {
        publish(StreamEvent {
            event_type: "update".into(),
            payload: post_id.to_string(),
            channel: "public".into(),
        });
    }

    // Process mentions in the tag array.
    let domain = &state.config.server.domain;
    if let Some(tags) = object["tag"].as_array() {
        for tag in tags {
            if tag["type"].as_str() != Some("Mention") {
                continue;
            }
            let href = match tag["href"].as_str() {
                Some(h) => h,
                None => continue,
            };

            if let Some((local_account_id, _, _)) =
                resolve_local_account(&state.pool, domain, href).await?
            {
                sqlx::query(
                    "INSERT OR IGNORE INTO mentions (remote_post_id, mentioned_account_id)
                     VALUES (?, ?)",
                )
                .bind(post_id)
                .bind(local_account_id)
                .execute(&state.pool)
                .await?;

                // Create a mention notification.
                let notif_id = generate_id();
                sqlx::query(
                    "INSERT INTO notifications (id, account_id, kind, from_remote_account_id, remote_post_id, created_at)
                     VALUES (?, ?, 'mention', ?, ?, ?)",
                )
                .bind(notif_id)
                .bind(local_account_id)
                .bind(remote.id)
                .bind(post_id)
                .bind(now)
                .execute(&state.pool)
                .await?;

                publish(StreamEvent {
                    event_type: "notification".into(),
                    payload: notif_id.to_string(),
                    channel: format!("user:{}", local_account_id),
                });

                // Fire-and-forget push notification
                let pool = state.pool.clone();
                let actor = remote.actor_uri.clone();
                let push_domain = domain.clone();
                tokio::spawn(async move {
                    crate::push::send_push_notification(
                        &pool,
                        local_account_id,
                        "mention",
                        "New mention",
                        &actor,
                        None,
                        &push_domain,
                    )
                    .await;
                });
            }
        }
    }

    // FEP-e232: Log any Object Link (quote) tags from the inbound Note.
    if let Some(tags) = object["tag"].as_array() {
        for tag in tags {
            if tag["type"].as_str() == Some("Link") {
                let media_type = tag["mediaType"].as_str().unwrap_or("");
                if media_type.contains("application/ld+json")
                    || media_type.contains("application/activity+json")
                {
                    let href = tag["href"].as_str().unwrap_or("");
                    if !href.is_empty() {
                        tracing::debug!(quote_uri = href, "inbound post quotes another post");
                    }
                }
            }
        }
    }

    // Handle direct messages: if visibility is "direct", create mention notifications
    // for local recipients in to/cc that weren't already handled via tags.
    if visibility == "direct" {
        let recipients = collect_recipients(activity);
        for uri in recipients {
            if let Some((local_account_id, _, _)) =
                resolve_local_account(&state.pool, domain, uri).await?
            {
                // Insert mention (ignore if already exists from tag processing).
                sqlx::query(
                    "INSERT OR IGNORE INTO mentions (remote_post_id, mentioned_account_id)
                     VALUES (?, ?)",
                )
                .bind(post_id)
                .bind(local_account_id)
                .execute(&state.pool)
                .await?;

                // Check if notification already exists for this account+post before inserting.
                let exists: (i64,) = sqlx::query_as(
                    "SELECT COUNT(*) FROM notifications
                     WHERE account_id = ? AND kind = 'mention' AND remote_post_id = ?",
                )
                .bind(local_account_id)
                .bind(post_id)
                .fetch_one(&state.pool)
                .await?;

                if exists.0 == 0 {
                    let notif_id = generate_id();
                    sqlx::query(
                        "INSERT INTO notifications (id, account_id, kind, from_remote_account_id, remote_post_id, created_at)
                         VALUES (?, ?, 'mention', ?, ?, ?)",
                    )
                    .bind(notif_id)
                    .bind(local_account_id)
                    .bind(remote.id)
                    .bind(post_id)
                    .bind(now)
                    .execute(&state.pool)
                    .await?;

                    publish(StreamEvent {
                        event_type: "notification".into(),
                        payload: notif_id.to_string(),
                        channel: format!("user:{}", local_account_id),
                    });

                    // Fire-and-forget push notification
                    let pool = state.pool.clone();
                    let actor = remote.actor_uri.clone();
                    let push_domain = domain.clone();
                    tokio::spawn(async move {
                        crate::push::send_push_notification(
                            &pool,
                            local_account_id,
                            "mention",
                            "New mention",
                            &actor,
                            None,
                            &push_domain,
                        )
                        .await;
                    });
                }
            }
        }
    }

    Ok(())
}

/// Determine visibility from addressing fields (Mastodon convention).
fn determine_visibility(activity: &Value, object: &Value) -> String {
    let recipients = collect_recipients(activity);
    let obj_recipients = collect_recipients(object);
    let all: Vec<&str> = recipients.into_iter().chain(obj_recipients).collect();

    let has_public = all
        .iter()
        .any(|u| *u == "https://www.w3.org/ns/activitystreams#Public" || *u == "as:Public");

    if has_public {
        // Check if public is in `to` (public) or only in `cc` (unlisted).
        let to_vals = collect_to_only(activity, object);
        let public_in_to = to_vals
            .iter()
            .any(|u| *u == "https://www.w3.org/ns/activitystreams#Public" || *u == "as:Public");
        if public_in_to {
            "public".to_string()
        } else {
            "unlisted".to_string()
        }
    } else {
        // Check if followers collection is addressed (private) or no collection (direct).
        let has_followers = all.iter().any(|u| u.ends_with("/followers"));
        if has_followers {
            "private".to_string()
        } else {
            "direct".to_string()
        }
    }
}

/// Collect only `to` field URIs from activity and object.
fn collect_to_only<'a>(activity: &'a Value, object: &'a Value) -> Vec<&'a str> {
    let mut uris = Vec::new();
    for val in [&activity["to"], &object["to"]] {
        match val {
            Value::String(s) => uris.push(s.as_str()),
            Value::Array(arr) => {
                for item in arr {
                    if let Some(s) = item.as_str() {
                        uris.push(s);
                    }
                }
            }
            _ => {}
        }
    }
    uris
}

/// Handle an Update activity.
///
/// If the object is a Note, update the remote_posts row.
/// If the object is an actor (Person, Service, etc.), re-fetch and update remote_accounts.
async fn handle_update(
    state: &AppState,
    activity: &Value,
    remote: &RemoteAccountRow,
) -> Result<(), AppError> {
    let object = &activity["object"];
    let object_type = object["type"].as_str().unwrap_or("");

    match object_type {
        "Note" => {
            let ap_uri = object["id"]
                .as_str()
                .ok_or_else(|| AppError::bad_request("Update Note missing id"))?;
            if ap_uri.len() > MAX_URI_LEN {
                return Err(AppError::bad_request("Note id too long"));
            }

            let raw_content = object["content"].as_str().unwrap_or("");
            let content_html = ammonia::clean(truncate_str(raw_content, MAX_CONTENT_LEN));

            let spoiler_text = object["summary"]
                .as_str()
                .map(|s| truncate_str(s, MAX_SPOILER_LEN).to_string())
                .unwrap_or_default();

            let sensitive = object["sensitive"].as_bool().unwrap_or(false);

            let now = chrono::Utc::now().timestamp();

            // Only update if the post belongs to this remote account (anti-spoofing).
            let result = sqlx::query(
                "UPDATE remote_posts SET content_html = ?, spoiler_text = ?, sensitive = ?, fetched_at = ?
                 WHERE ap_uri = ? AND remote_account_id = ?",
            )
            .bind(&content_html)
            .bind(&spoiler_text)
            .bind(sensitive)
            .bind(now)
            .bind(ap_uri)
            .bind(remote.id)
            .execute(&state.pool)
            .await?;

            if result.rows_affected() == 0 {
                tracing::debug!(
                    ap_uri,
                    actor = %remote.actor_uri,
                    "Update Note: post not found or not owned by actor"
                );
            }
        }
        "Person" | "Service" | "Application" | "Group" | "Organization" => {
            // Re-fetch the actor document and upsert.
            let actor_id = object_id(object).unwrap_or(&remote.actor_uri);
            if actor_id != remote.actor_uri {
                tracing::debug!(
                    expected = %remote.actor_uri,
                    got = actor_id,
                    "Update actor: id does not match sender, ignoring"
                );
                return Ok(());
            }
            let _ = fetch_and_upsert_actor(state, &remote.actor_uri).await;
        }
        _ => {
            tracing::debug!("ignoring Update of unknown type: {object_type}");
        }
    }

    Ok(())
}

/// Handle a Delete activity.
///
/// Object can be a URI string, {"id": "..."}, or a Tombstone.
/// If deleting a post, remove from remote_posts. If deleting an actor, remove all data.
async fn handle_delete(
    state: &AppState,
    activity: &Value,
    remote: &RemoteAccountRow,
) -> Result<(), AppError> {
    let deleted_uri = object_id(&activity["object"]).unwrap_or("");
    if deleted_uri.is_empty() || deleted_uri.len() > MAX_URI_LEN {
        return Ok(()); // Silently ignore
    }

    // If the deleted URI matches the actor URI, this is an account self-deletion.
    if deleted_uri == remote.actor_uri {
        tracing::info!(actor = %remote.actor_uri, "remote actor self-deleted");

        // Remove all their data in order: notifications, mentions, remote_posts,
        // followers, follow_requests, then the account itself.
        sqlx::query("DELETE FROM notifications WHERE from_remote_account_id = ?")
            .bind(remote.id)
            .execute(&state.pool)
            .await?;

        sqlx::query(
            "DELETE FROM mentions WHERE remote_post_id IN
             (SELECT id FROM remote_posts WHERE remote_account_id = ?)",
        )
        .bind(remote.id)
        .execute(&state.pool)
        .await?;

        sqlx::query("DELETE FROM remote_posts WHERE remote_account_id = ?")
            .bind(remote.id)
            .execute(&state.pool)
            .await?;

        sqlx::query("DELETE FROM followers WHERE remote_account_id = ?")
            .bind(remote.id)
            .execute(&state.pool)
            .await?;

        sqlx::query("DELETE FROM follow_requests WHERE requester_remote_id = ?")
            .bind(remote.id)
            .execute(&state.pool)
            .await?;

        sqlx::query("DELETE FROM follows WHERE followee_remote_id = ?")
            .bind(remote.id)
            .execute(&state.pool)
            .await?;

        sqlx::query("DELETE FROM remote_accounts WHERE id = ?")
            .bind(remote.id)
            .execute(&state.pool)
            .await?;

        return Ok(());
    }

    // Otherwise, try to delete a post — only if owned by this actor.
    let result = sqlx::query("DELETE FROM remote_posts WHERE ap_uri = ? AND remote_account_id = ?")
        .bind(deleted_uri)
        .bind(remote.id)
        .execute(&state.pool)
        .await?;

    if result.rows_affected() > 0 {
        tracing::info!(
            ap_uri = deleted_uri,
            actor = %remote.actor_uri,
            "remote post deleted"
        );
        // Clean up mentions referencing the deleted post.
        sqlx::query(
            "DELETE FROM mentions WHERE remote_post_id NOT IN (SELECT id FROM remote_posts)",
        )
        .execute(&state.pool)
        .await?;
    }

    Ok(())
}

/// Handle a Like activity. Create a notification for the local post owner.
async fn handle_like(
    state: &AppState,
    activity: &Value,
    remote: &RemoteAccountRow,
) -> Result<(), AppError> {
    let liked_uri = object_id(&activity["object"]).unwrap_or("");
    if liked_uri.is_empty() || liked_uri.len() > MAX_URI_LEN {
        return Ok(());
    }

    // Look up the local post.
    let post_row: Option<(i64, i64)> =
        sqlx::query_as("SELECT id, account_id FROM posts WHERE ap_id = ? LIMIT 1")
            .bind(liked_uri)
            .fetch_optional(&state.pool)
            .await?;

    if let Some((post_id, account_id)) = post_row {
        let now = chrono::Utc::now().timestamp();
        let notif_id = generate_id();

        sqlx::query(
            "INSERT INTO notifications (id, account_id, kind, from_remote_account_id, post_id, created_at)
             VALUES (?, ?, 'favourite', ?, ?, ?)",
        )
        .bind(notif_id)
        .bind(account_id)
        .bind(remote.id)
        .bind(post_id)
        .bind(now)
        .execute(&state.pool)
        .await?;

        // Fire-and-forget push notification
        let pool = state.pool.clone();
        let actor = remote.actor_uri.clone();
        let push_domain = state.config.server.domain.clone();
        tokio::spawn(async move {
            crate::push::send_push_notification(
                &pool,
                account_id,
                "favourite",
                "New favourite",
                &actor,
                None,
                &push_domain,
            )
            .await;
        });

        tracing::info!(
            actor = %remote.actor_uri,
            post_id,
            "post liked"
        );
    }

    Ok(())
}

/// Handle an Announce (boost) activity. The object is a URI to a post.
async fn handle_announce(
    state: &AppState,
    activity: &Value,
    remote: &RemoteAccountRow,
) -> Result<(), AppError> {
    let boosted_uri = object_id(&activity["object"]).unwrap_or("");
    if boosted_uri.is_empty() || boosted_uri.len() > MAX_URI_LEN {
        return Ok(());
    }

    // Look up the local post being boosted.
    let post_row: Option<(i64, i64)> =
        sqlx::query_as("SELECT id, account_id FROM posts WHERE ap_id = ? LIMIT 1")
            .bind(boosted_uri)
            .fetch_optional(&state.pool)
            .await?;

    if let Some((post_id, account_id)) = post_row {
        let now = chrono::Utc::now().timestamp();
        let notif_id = generate_id();

        sqlx::query(
            "INSERT INTO notifications (id, account_id, kind, from_remote_account_id, post_id, created_at)
             VALUES (?, ?, 'reblog', ?, ?, ?)",
        )
        .bind(notif_id)
        .bind(account_id)
        .bind(remote.id)
        .bind(post_id)
        .bind(now)
        .execute(&state.pool)
        .await?;

        // Fire-and-forget push notification
        let pool = state.pool.clone();
        let actor = remote.actor_uri.clone();
        let push_domain = state.config.server.domain.clone();
        tokio::spawn(async move {
            crate::push::send_push_notification(
                &pool,
                account_id,
                "reblog",
                "New boost",
                &actor,
                None,
                &push_domain,
            )
            .await;
        });

        tracing::info!(
            actor = %remote.actor_uri,
            post_id,
            "post boosted"
        );
    }

    Ok(())
}

/// Handle a Block activity.
///
/// Remove the blocking actor from our followers table, and remove any follow
/// we have on them from the follows table.
async fn handle_block(
    state: &AppState,
    _activity: &Value,
    remote: &RemoteAccountRow,
) -> Result<(), AppError> {
    // Remove them as a follower of any local account.
    sqlx::query("DELETE FROM followers WHERE remote_account_id = ?")
        .bind(remote.id)
        .execute(&state.pool)
        .await?;

    // Remove any follow we have on them.
    sqlx::query("DELETE FROM follows WHERE followee_remote_id = ?")
        .bind(remote.id)
        .execute(&state.pool)
        .await?;

    // Remove pending follow requests from them.
    sqlx::query("DELETE FROM follow_requests WHERE requester_remote_id = ?")
        .bind(remote.id)
        .execute(&state.pool)
        .await?;

    tracing::info!(actor = %remote.actor_uri, "blocked by remote actor");

    Ok(())
}

/// Handle a Move activity.
///
/// Verify that the old actor's `alsoKnownAs` includes the new actor URI,
/// then migrate follows from the old actor to the new one.
async fn handle_move(
    state: &AppState,
    activity: &Value,
    remote: &RemoteAccountRow,
) -> Result<(), AppError> {
    let target_uri = object_id(&activity["target"])
        .or_else(|| activity["object"].as_str())
        .ok_or_else(|| AppError::bad_request("Move missing target"))?;

    if target_uri.len() > MAX_URI_LEN {
        return Err(AppError::bad_request("Move target URI too long"));
    }

    // Fetch the old actor to verify alsoKnownAs.
    let old_actor = fetch_and_upsert_actor(state, &remote.actor_uri).await?;
    let _ = old_actor; // We just need the fetch to succeed; verification uses the raw document.

    // Fetch the old actor document to check alsoKnownAs.
    let (signing_key_pem, signing_key_id) = get_signing_credentials(state).await?;
    // We need to fetch the NEW actor and check if the OLD actor lists the NEW actor
    // in alsoKnownAs. Fetch old actor's raw document.
    let old_actor_url: url::Url = remote
        .actor_uri
        .parse()
        .map_err(|_| AppError::bad_request("invalid actor URI"))?;
    let get_headers =
        FederationClient::sign_get_headers(&signing_key_pem, &signing_key_id, &old_actor_url)
            .map_err(|e| AppError::internal(format!("sign headers: {e}")))?;

    // ponytail: re-fetch the raw actor document to check alsoKnownAs.
    // This duplicates the fetch_actor call somewhat but we need the raw JSON.
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(
            state.config.federation.fetch_timeout_secs,
        ))
        .build()
        .map_err(|e| AppError::internal(format!("http client: {e}")))?;

    let resp = client
        .get(old_actor_url.as_str())
        .headers(get_headers)
        .header(
            "Accept",
            "application/activity+json, application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\"",
        )
        .send()
        .await
        .map_err(|e| AppError::internal(format!("fetch old actor: {e}")))?;

    if !resp.status().is_success() {
        return Err(AppError::internal(
            "failed to fetch old actor for Move verification",
        ));
    }

    let old_doc: Value = resp
        .json()
        .await
        .map_err(|e| AppError::internal(format!("parse old actor: {e}")))?;

    // Verify alsoKnownAs includes target_uri.
    let also_known = old_doc["alsoKnownAs"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .any(|s| s == target_uri)
        })
        .unwrap_or(false);

    if !also_known {
        tracing::warn!(
            old_actor = %remote.actor_uri,
            new_actor = target_uri,
            "Move rejected: alsoKnownAs does not include target"
        );
        return Err(AppError::unauthorized(
            "Move: old actor alsoKnownAs does not include new actor",
        ));
    }

    // Fetch and upsert the new actor.
    let new_account = fetch_and_upsert_actor(state, target_uri).await?;

    // Migrate follows: for each local account following the old remote account,
    // create a follow on the new account and enqueue a Follow activity.
    let local_followers: Vec<(i64, String, String)> = sqlx::query_as(
        "SELECT a.id, a.username, a.private_key_pem
         FROM follows f
         JOIN accounts a ON a.id = f.follower_id
         WHERE f.followee_remote_id = ?",
    )
    .bind(remote.id)
    .fetch_all(&state.pool)
    .await?;

    let domain = &state.config.server.domain;
    let now = chrono::Utc::now().timestamp();

    for (local_id, local_username, _) in &local_followers {
        // Insert new follow.
        sqlx::query(
            "INSERT OR IGNORE INTO follows (follower_id, followee_remote_id, created_at)
             VALUES (?, ?, ?)",
        )
        .bind(local_id)
        .bind(new_account.id)
        .bind(now)
        .execute(&state.pool)
        .await?;

        // Enqueue a Follow activity to the new actor.
        let follow_id = generate_id();
        let follow_activity = serde_json::json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": format!("https://{domain}/activities/follow-{follow_id}"),
            "type": "Follow",
            "actor": format!("https://{domain}/users/{local_username}"),
            "object": target_uri
        });

        let target_inbox = new_account
            .shared_inbox_url
            .as_deref()
            .unwrap_or(&new_account.inbox_url);

        enqueue_activity(&state.pool, target_inbox, *local_id, &follow_activity).await?;
    }

    // Remove old follows.
    sqlx::query("DELETE FROM follows WHERE followee_remote_id = ?")
        .bind(remote.id)
        .execute(&state.pool)
        .await?;

    tracing::info!(
        old_actor = %remote.actor_uri,
        new_actor = target_uri,
        migrated_follows = local_followers.len(),
        "actor move processed"
    );

    Ok(())
}

/// Handle an Accept activity (our outbound Follow was accepted).
async fn handle_accept(
    state: &AppState,
    activity: &Value,
    remote: &RemoteAccountRow,
) -> Result<(), AppError> {
    let inner = &activity["object"];
    let inner_type = inner["type"].as_str().unwrap_or("");

    if inner_type != "Follow" {
        tracing::debug!("ignoring Accept of non-Follow type: {inner_type}");
        return Ok(());
    }

    // The inner Follow's actor should be a local account, and the object should be the remote actor.
    let follow_actor_uri = inner["actor"].as_str().unwrap_or("");
    let domain = &state.config.server.domain;

    let local_account = resolve_local_account(&state.pool, domain, follow_actor_uri).await?;
    let (local_id, _, _) = match local_account {
        Some(a) => a,
        None => {
            tracing::debug!(
                follow_actor = follow_actor_uri,
                "Accept: follow actor is not a local account"
            );
            return Ok(());
        }
    };

    // Verify the follow target matches the actor sending the Accept.
    let follow_object = object_id(&inner["object"]).unwrap_or("");
    if follow_object != remote.actor_uri {
        tracing::debug!(
            expected = %remote.actor_uri,
            got = follow_object,
            "Accept: follow target does not match accepting actor"
        );
        return Ok(());
    }

    // The follow already exists in the follows table (inserted when we sent the Follow).
    // This is a confirmation. If it's somehow not there, we can insert it.
    let now = chrono::Utc::now().timestamp();
    sqlx::query(
        "INSERT OR IGNORE INTO follows (follower_id, followee_remote_id, created_at)
         VALUES (?, ?, ?)",
    )
    .bind(local_id)
    .bind(remote.id)
    .bind(now)
    .execute(&state.pool)
    .await?;

    // Check if this Accept is from a relay we subscribed to.
    let relay_updated = sqlx::query("UPDATE relays SET state = 'accepted' WHERE actor_uri = ?")
        .bind(&remote.actor_uri)
        .execute(&state.pool)
        .await?;

    if relay_updated.rows_affected() > 0 {
        tracing::info!(
            relay = %remote.actor_uri,
            "relay subscription accepted"
        );
    }

    tracing::info!(
        local_account_id = local_id,
        remote_actor = %remote.actor_uri,
        "follow accepted by remote"
    );

    Ok(())
}

/// Handle a Reject activity (our outbound Follow was rejected).
async fn handle_reject(
    state: &AppState,
    activity: &Value,
    remote: &RemoteAccountRow,
) -> Result<(), AppError> {
    let inner = &activity["object"];
    let inner_type = inner["type"].as_str().unwrap_or("");

    if inner_type != "Follow" {
        tracing::debug!("ignoring Reject of non-Follow type: {inner_type}");
        return Ok(());
    }

    let follow_actor_uri = inner["actor"].as_str().unwrap_or("");
    let domain = &state.config.server.domain;

    let local_account = resolve_local_account(&state.pool, domain, follow_actor_uri).await?;
    let (local_id, _, _) = match local_account {
        Some(a) => a,
        None => {
            tracing::debug!(
                follow_actor = follow_actor_uri,
                "Reject: follow actor is not a local account"
            );
            return Ok(());
        }
    };

    // Remove the pending follow.
    sqlx::query("DELETE FROM follows WHERE follower_id = ? AND followee_remote_id = ?")
        .bind(local_id)
        .bind(remote.id)
        .execute(&state.pool)
        .await?;

    // Check if this Reject is from a relay we subscribed to.
    let relay_updated = sqlx::query("UPDATE relays SET state = 'rejected' WHERE actor_uri = ?")
        .bind(&remote.actor_uri)
        .execute(&state.pool)
        .await?;

    if relay_updated.rows_affected() > 0 {
        tracing::info!(
            relay = %remote.actor_uri,
            "relay subscription rejected"
        );
    }

    tracing::info!(
        local_account_id = local_id,
        remote_actor = %remote.actor_uri,
        "follow rejected by remote"
    );

    Ok(())
}
