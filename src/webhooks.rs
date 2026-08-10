use crate::api::{hex_encode, millis_to_iso, AuthenticatedAccount};
use crate::error::AppError;
use crate::id::generate_id;
use crate::server::AppState;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

use crate::sqlx;
use sqlx::SqlitePool;

fn sq(pool: &fieldwork_db::db::Pool) -> &SqlitePool {
    match pool {
        fieldwork_db::db::Pool::Sqlite(p) => p,
    }
}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

pub struct WebhookRow {
    pub id: i64,
    pub url: String,
    pub events: String,
    pub secret: String,
    pub enabled: bool,
    pub created_at: i64,
}

fn webhook_to_json(row: &WebhookRow) -> Value {
    let events: Vec<&str> = row.events.split(',').map(|s| s.trim()).collect();
    json!({
        "id": row.id.to_string(),
        "url": row.url,
        "events": events,
        "enabled": row.enabled,
        "created_at": millis_to_iso(row.created_at),
    })
}

// ---------------------------------------------------------------------------
// DB helpers
// ---------------------------------------------------------------------------

pub async fn list_webhooks(pool: &fieldwork_db::db::Pool) -> Result<Vec<WebhookRow>, sqlx::Error> {
    let rows: Vec<(i64, String, String, String, bool, i64)> = sqlx::query_as(
        "SELECT id, url, events, secret, enabled != 0, created_at FROM webhooks ORDER BY id",
    )
    .fetch_all(sq(pool))
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, url, events, secret, enabled, created_at)| WebhookRow {
            id,
            url,
            events,
            secret,
            enabled,
            created_at,
        })
        .collect())
}

pub async fn get_webhook(
    pool: &fieldwork_db::db::Pool,
    id: i64,
) -> Result<Option<WebhookRow>, sqlx::Error> {
    let row: Option<(i64, String, String, String, bool, i64)> = sqlx::query_as(
        "SELECT id, url, events, secret, enabled != 0, created_at FROM webhooks WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(sq(pool))
    .await?;
    Ok(row.map(|(id, url, events, secret, enabled, created_at)| WebhookRow {
        id,
        url,
        events,
        secret,
        enabled,
        created_at,
    }))
}

pub async fn create_webhook(
    pool: &fieldwork_db::db::Pool,
    id: i64,
    url: &str,
    events: &str,
    secret: &str,
    created_at: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO webhooks (id, url, events, secret, enabled, created_at) VALUES (?, ?, ?, ?, 1, ?)",
    )
    .bind(id)
    .bind(url)
    .bind(events)
    .bind(secret)
    .bind(created_at)
    .execute(sq(pool))
    .await?;
    Ok(())
}

pub async fn update_webhook(
    pool: &fieldwork_db::db::Pool,
    id: i64,
    url: &str,
    events: &str,
    secret: &str,
    enabled: bool,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE webhooks SET url = ?, events = ?, secret = ?, enabled = ? WHERE id = ?",
    )
    .bind(url)
    .bind(events)
    .bind(secret)
    .bind(enabled)
    .bind(id)
    .execute(sq(pool))
    .await?;
    Ok(result.rows_affected())
}

pub async fn delete_webhook(
    pool: &fieldwork_db::db::Pool,
    id: i64,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query("DELETE FROM webhooks WHERE id = ?")
        .bind(id)
        .execute(sq(pool))
        .await?;
    Ok(result.rows_affected())
}

pub async fn set_webhook_enabled(
    pool: &fieldwork_db::db::Pool,
    id: i64,
    enabled: bool,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query("UPDATE webhooks SET enabled = ? WHERE id = ?")
        .bind(enabled)
        .bind(id)
        .execute(sq(pool))
        .await?;
    Ok(result.rows_affected())
}

pub async fn webhooks_for_event(
    pool: &fieldwork_db::db::Pool,
    event: &str,
) -> Result<Vec<WebhookRow>, sqlx::Error> {
    let pattern = format!("%{event}%");
    let rows: Vec<(i64, String, String, String, bool, i64)> = sqlx::query_as(
        "SELECT id, url, events, secret, enabled != 0, created_at FROM webhooks WHERE events LIKE ? AND enabled = 1",
    )
    .bind(&pattern)
    .fetch_all(sq(pool))
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, url, events, secret, enabled, created_at)| WebhookRow {
            id,
            url,
            events,
            secret,
            enabled,
            created_at,
        })
        .collect())
}

// ---------------------------------------------------------------------------
// Webhook log DB helpers
// ---------------------------------------------------------------------------

pub struct WebhookLogRow {
    pub id: i64,
    pub webhook_id: i64,
    pub event: String,
    pub status_code: Option<i64>,
    pub attempts: i64,
    pub next_retry: Option<i64>,
    pub payload: String,
    pub created_at: i64,
    pub url: String,
}

async fn insert_webhook_log(
    pool: &fieldwork_db::db::Pool,
    webhook_id: i64,
    event: &str,
    status_code: Option<i64>,
    attempts: i64,
    next_retry: Option<i64>,
    payload: &str,
    created_at: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO webhook_log (webhook_id, event, status_code, attempts, next_retry, payload, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(webhook_id)
    .bind(event)
    .bind(status_code)
    .bind(attempts)
    .bind(next_retry)
    .bind(payload)
    .bind(created_at)
    .execute(sq(pool))
    .await?;
    Ok(())
}

pub async fn list_webhook_log(
    pool: &fieldwork_db::db::Pool,
    limit: i64,
) -> Result<Vec<WebhookLogRow>, sqlx::Error> {
    let rows: Vec<(i64, i64, String, Option<i64>, i64, Option<i64>, String, i64)> = sqlx::query_as(
        "SELECT wl.id, wl.webhook_id, wl.event, wl.status_code, wl.attempts, wl.next_retry, wl.payload, wl.created_at FROM webhook_log wl ORDER BY wl.created_at DESC LIMIT ?",
    )
    .bind(limit)
    .fetch_all(sq(pool))
    .await?;

    let mut result = Vec::with_capacity(rows.len());
    for (id, webhook_id, event, status_code, attempts, next_retry, payload, created_at) in rows {
        let url_row: Option<(String,)> =
            sqlx::query_as("SELECT url FROM webhooks WHERE id = ?")
                .bind(webhook_id)
                .fetch_optional(sq(pool))
                .await?;
        let url = url_row.map(|(u,)| u).unwrap_or_else(|| "(deleted)".into());
        result.push(WebhookLogRow {
            id,
            webhook_id,
            event,
            status_code,
            attempts,
            next_retry,
            payload,
            created_at,
            url,
        });
    }
    Ok(result)
}

pub async fn list_webhook_log_by_id(
    pool: &fieldwork_db::db::Pool,
    webhook_id: i64,
    limit: i64,
) -> Result<Vec<WebhookLogRow>, sqlx::Error> {
    let url_row: Option<(String,)> =
        sqlx::query_as("SELECT url FROM webhooks WHERE id = ?")
            .bind(webhook_id)
            .fetch_optional(sq(pool))
            .await?;
    let url = url_row.map(|(u,)| u).unwrap_or_else(|| "(deleted)".into());

    let rows: Vec<(i64, i64, String, Option<i64>, i64, Option<i64>, String, i64)> = sqlx::query_as(
        "SELECT id, webhook_id, event, status_code, attempts, next_retry, payload, created_at FROM webhook_log WHERE webhook_id = ? ORDER BY created_at DESC LIMIT ?",
    )
    .bind(webhook_id)
    .bind(limit)
    .fetch_all(sq(pool))
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, webhook_id, event, status_code, attempts, next_retry, payload, created_at)| {
            WebhookLogRow {
                id,
                webhook_id,
                event,
                status_code,
                attempts,
                next_retry,
                payload,
                created_at,
                url: url.clone(),
            }
        })
        .collect())
}

// ---------------------------------------------------------------------------
// HMAC-SHA256
// ---------------------------------------------------------------------------

fn hmac_sha256(secret: &str, body: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(body.as_bytes());
    hex_encode(&mac.finalize().into_bytes())
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

pub fn dispatch_webhook_event(
    pool: fieldwork_db::db::Pool,
    event: &str,
    payload: serde_json::Value,
) {
    let event = event.to_string();
    tokio::spawn(async move {
        let hooks = webhooks_for_event(&pool, &event).await.unwrap_or_default();
        let now = crate::api::now_millis();

        for hook in hooks {
            if let Ok(parsed) = url::Url::parse(&hook.url) {
                if crate::federation::validate_outbound_url(&parsed).is_err() {
                    tracing::warn!("webhook {} blocked by SSRF check", hook.url);
                    continue;
                }
            }

            let body = serde_json::to_string(&payload).unwrap_or_default();
            let signature = hmac_sha256(&hook.secret, &body);

            let client = match reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none())
                .build()
            {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("webhook client build failed: {e}");
                    continue;
                }
            };

            let resp = client
                .post(&hook.url)
                .header("Content-Type", "application/json")
                .header("X-Webhook-Signature", format!("sha256={signature}"))
                .body(body.clone())
                .send()
                .await;

            match resp {
                Ok(r) => {
                    let code = r.status().as_u16() as i64;
                    tracing::info!("webhook {} -> {}", hook.url, r.status());
                    if r.status().is_success() {
                        let _ = insert_webhook_log(
                            &pool, hook.id, &event, Some(code), 1, None, &body, now,
                        )
                        .await;
                    } else {
                        let _ = insert_webhook_log(
                            &pool, hook.id, &event, Some(code), 1,
                            Some(now + 60_000), &body, now,
                        )
                        .await;
                    }
                }
                Err(e) => {
                    tracing::warn!("webhook {} failed: {e}", hook.url);
                    let _ = insert_webhook_log(
                        &pool, hook.id, &event, None, 1,
                        Some(now + 60_000), &body, now,
                    )
                    .await;
                }
            }
        }

        process_webhook_retries(&pool).await;
    });
}

async fn process_webhook_retries(pool: &fieldwork_db::db::Pool) {
    let now = crate::api::now_millis();
    let rows: Vec<(i64, i64, String, i64, String)> = match sqlx::query_as(
        "SELECT wl.id, wl.webhook_id, wl.event, wl.attempts, wl.payload FROM webhook_log wl WHERE wl.next_retry IS NOT NULL AND wl.next_retry <= ? AND wl.attempts < 3",
    )
    .bind(now)
    .fetch_all(sq(pool))
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("webhook retry query failed: {e}");
            return;
        }
    };

    for (log_id, webhook_id, _event, attempts, payload) in rows {
        let hook = match get_webhook(pool, webhook_id).await {
            Ok(Some(h)) if h.enabled => h,
            _ => {
                // Webhook deleted or disabled — give up
                let _ = sqlx::query("UPDATE webhook_log SET next_retry = NULL WHERE id = ?")
                    .bind(log_id)
                    .execute(sq(pool))
                    .await;
                continue;
            }
        };

        let signature = hmac_sha256(&hook.secret, &payload);
        let client = match reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
        {
            Ok(c) => c,
            Err(_) => continue,
        };

        let resp = client
            .post(&hook.url)
            .header("Content-Type", "application/json")
            .header("X-Webhook-Signature", format!("sha256={signature}"))
            .body(payload)
            .send()
            .await;

        let new_attempts = attempts + 1;
        match resp {
            Ok(r) if r.status().is_success() => {
                let code = r.status().as_u16() as i64;
                let _ = sqlx::query(
                    "UPDATE webhook_log SET status_code = ?, attempts = ?, next_retry = NULL WHERE id = ?",
                )
                .bind(code)
                .bind(new_attempts)
                .bind(log_id)
                .execute(sq(pool))
                .await;
            }
            Ok(r) => {
                let code = r.status().as_u16() as i64;
                let next = if new_attempts >= 3 {
                    None // give up
                } else if new_attempts == 2 {
                    Some(now + 5 * 60_000) // +5min
                } else {
                    Some(now + 15 * 60_000) // +15min
                };
                let _ = sqlx::query(
                    "UPDATE webhook_log SET status_code = ?, attempts = ?, next_retry = ? WHERE id = ?",
                )
                .bind(code)
                .bind(new_attempts)
                .bind(next)
                .bind(log_id)
                .execute(sq(pool))
                .await;
            }
            Err(_) => {
                let next = if new_attempts >= 3 {
                    None
                } else if new_attempts == 2 {
                    Some(now + 5 * 60_000)
                } else {
                    Some(now + 15 * 60_000)
                };
                let _ = sqlx::query(
                    "UPDATE webhook_log SET attempts = ?, next_retry = ? WHERE id = ?",
                )
                .bind(new_attempts)
                .bind(next)
                .bind(log_id)
                .execute(sq(pool))
                .await;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// API routes
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct CreateWebhookRequest {
    url: String,
    events: Vec<String>,
    #[serde(default)]
    secret: Option<String>,
}

#[derive(Deserialize)]
struct UpdateWebhookRequest {
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    events: Option<Vec<String>>,
    #[serde(default)]
    secret: Option<String>,
    #[serde(default)]
    enabled: Option<bool>,
}

async fn api_list_webhooks(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
) -> Result<Json<Value>, AppError> {
    auth.require_scope("admin:read")?;
    let hooks = list_webhooks(&state.pool).await.map_err(AppError::from)?;
    let items: Vec<Value> = hooks.iter().map(webhook_to_json).collect();
    Ok(Json(json!(items)))
}

async fn api_create_webhook(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Json(body): Json<CreateWebhookRequest>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    auth.require_scope("admin:write")?;

    // SSRF validate URL on creation
    let parsed = url::Url::parse(&body.url)
        .map_err(|_| AppError::unprocessable("Invalid webhook URL"))?;
    crate::federation::validate_outbound_url(&parsed)
        .map_err(|e| AppError::unprocessable(format!("URL blocked: {e}")))?;

    let id = generate_id();
    let events = body.events.join(",");
    let secret = body.secret.unwrap_or_else(|| {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        hex_encode(&bytes)
    });
    let now = crate::api::now_millis();

    create_webhook(&state.pool, id, &body.url, &events, &secret, now)
        .await
        .map_err(AppError::from)?;

    let row = WebhookRow {
        id,
        url: body.url,
        events,
        secret,
        enabled: true,
        created_at: now,
    };
    Ok((StatusCode::OK, Json(webhook_to_json(&row))))
}

async fn api_get_webhook(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    auth.require_scope("admin:read")?;
    let wh_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("Webhook not found"))?;
    let hook = get_webhook(&state.pool, wh_id)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("Webhook not found"))?;
    Ok(Json(webhook_to_json(&hook)))
}

async fn api_update_webhook(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(id): Path<String>,
    Json(body): Json<UpdateWebhookRequest>,
) -> Result<Json<Value>, AppError> {
    auth.require_scope("admin:write")?;
    let wh_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("Webhook not found"))?;

    let existing = get_webhook(&state.pool, wh_id)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("Webhook not found"))?;

    let url = body.url.as_deref().unwrap_or(&existing.url);
    let events = body
        .events
        .as_ref()
        .map(|e| e.join(","))
        .unwrap_or(existing.events.clone());
    let secret = body.secret.as_deref().unwrap_or(&existing.secret);
    let enabled = body.enabled.unwrap_or(existing.enabled);

    // SSRF validate if URL changed
    if body.url.is_some() {
        let parsed = url::Url::parse(url)
            .map_err(|_| AppError::unprocessable("Invalid webhook URL"))?;
        crate::federation::validate_outbound_url(&parsed)
            .map_err(|e| AppError::unprocessable(format!("URL blocked: {e}")))?;
    }

    update_webhook(&state.pool, wh_id, url, &events, secret, enabled)
        .await
        .map_err(AppError::from)?;

    let updated = WebhookRow {
        id: wh_id,
        url: url.to_string(),
        events,
        secret: secret.to_string(),
        enabled,
        created_at: existing.created_at,
    };
    Ok(Json(webhook_to_json(&updated)))
}

async fn api_delete_webhook(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    auth.require_scope("admin:write")?;
    let wh_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("Webhook not found"))?;
    let rows = delete_webhook(&state.pool, wh_id)
        .await
        .map_err(AppError::from)?;
    if rows == 0 {
        return Err(AppError::not_found("Webhook not found"));
    }
    Ok(StatusCode::OK)
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/api/v1/admin/webhooks",
            get(api_list_webhooks).post(api_create_webhook),
        )
        .route(
            "/api/v1/admin/webhooks/{id}",
            get(api_get_webhook)
                .put(api_update_webhook)
                .delete(api_delete_webhook),
        )
}

// ---------------------------------------------------------------------------
// CLI handlers
// ---------------------------------------------------------------------------

pub async fn cmd_webhook_list(pool: &fieldwork_db::db::Pool) -> anyhow::Result<()> {
    let hooks = list_webhooks(pool).await?;
    if hooks.is_empty() {
        eprintln!("No webhooks registered.");
    } else {
        for h in &hooks {
            let status = if h.enabled { "enabled" } else { "disabled" };
            let masked_secret = if h.secret.len() >= 4 {
                format!("****{}", &h.secret[h.secret.len() - 4..])
            } else {
                "****".to_string()
            };
            eprintln!(
                "  {} — {} [{}] ({}) secret: {}",
                h.id, h.url, h.events, status, masked_secret
            );
        }
    }
    Ok(())
}

pub async fn cmd_webhook_add(
    pool: &fieldwork_db::db::Pool,
    url: &str,
    events: &str,
) -> anyhow::Result<()> {
    // SSRF validate
    let parsed = url::Url::parse(url)?;
    crate::federation::validate_outbound_url(&parsed)?;

    let id = generate_id();
    let mut secret_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut secret_bytes);
    let secret = hex_encode(&secret_bytes);
    let now = crate::api::now_millis();

    create_webhook(pool, id, url, events, &secret, now).await?;
    eprintln!("Created webhook {id}:");
    eprintln!("  URL: {url}");
    eprintln!("  Events: {events}");
    eprintln!("  Secret: {secret}");
    Ok(())
}

pub async fn cmd_webhook_remove(pool: &fieldwork_db::db::Pool, id_str: &str) -> anyhow::Result<()> {
    let id: i64 = id_str.parse()?;
    let rows = delete_webhook(pool, id).await?;
    if rows == 0 {
        eprintln!("Webhook not found.");
    } else {
        eprintln!("Webhook {id} removed.");
    }
    Ok(())
}

pub async fn cmd_webhook_test(pool: &fieldwork_db::db::Pool, id_str: &str) -> anyhow::Result<()> {
    let id: i64 = id_str.parse()?;
    let hook = get_webhook(pool, id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Webhook not found"))?;

    let payload = json!({
        "event": "webhook.test",
        "object": { "id": "0", "content": "This is a test webhook delivery." }
    });
    let body = serde_json::to_string(&payload)?;
    let signature = hmac_sha256(&hook.secret, &body);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let resp = client
        .post(&hook.url)
        .header("Content-Type", "application/json")
        .header("X-Webhook-Signature", format!("sha256={signature}"))
        .body(body)
        .send()
        .await?;

    eprintln!("Test delivery to {} -> {}", hook.url, resp.status());
    Ok(())
}

pub async fn cmd_webhook_enable(pool: &fieldwork_db::db::Pool, id_str: &str) -> anyhow::Result<()> {
    let id: i64 = id_str.parse()?;
    let rows = set_webhook_enabled(pool, id, true).await?;
    if rows == 0 {
        eprintln!("Webhook not found.");
    } else {
        eprintln!("Webhook {id} enabled.");
    }
    Ok(())
}

pub async fn cmd_webhook_disable(pool: &fieldwork_db::db::Pool, id_str: &str) -> anyhow::Result<()> {
    let id: i64 = id_str.parse()?;
    let rows = set_webhook_enabled(pool, id, false).await?;
    if rows == 0 {
        eprintln!("Webhook not found.");
    } else {
        eprintln!("Webhook {id} disabled.");
    }
    Ok(())
}

pub async fn cmd_webhook_log(pool: &fieldwork_db::db::Pool, id: Option<&str>) -> anyhow::Result<()> {
    let entries = if let Some(id_str) = id {
        let wh_id: i64 = id_str.parse()?;
        list_webhook_log_by_id(pool, wh_id, 50).await?
    } else {
        list_webhook_log(pool, 50).await?
    };

    if entries.is_empty() {
        eprintln!("No webhook log entries.");
    } else {
        for e in &entries {
            let ts = millis_to_iso(e.created_at);
            let code = e
                .status_code
                .map(|c| c.to_string())
                .unwrap_or_else(|| "ERR".into());
            let attempts = if e.attempts == 1 {
                "1 attempt".to_string()
            } else {
                format!("{} attempts", e.attempts)
            };
            eprintln!("  {}  {}  {}  {}  ({})", ts, e.event, e.url, code, attempts);
        }
    }
    Ok(())
}
