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
                .body(body)
                .send()
                .await;

            match resp {
                Ok(r) => tracing::info!("webhook {} -> {}", hook.url, r.status()),
                Err(e) => tracing::warn!("webhook {} failed: {e}", hook.url),
            }
        }
    });
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
            eprintln!("  {} — {} [{}] ({})", h.id, h.url, h.events, status);
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
