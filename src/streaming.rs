use crate::api::{hex_encode, AuthenticatedAccount};
use crate::error::AppError;
use crate::server::AppState;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, LazyLock};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt as TokioStreamExt;

// ---------------------------------------------------------------------------
// Broadcast infrastructure
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct StreamEvent {
    pub event_type: String,
    pub payload: String,
    pub channel: String,
}

static STREAM_TX: LazyLock<broadcast::Sender<StreamEvent>> = LazyLock::new(|| {
    let (tx, _) = broadcast::channel(1024);
    tx
});

/// Publish an event to all connected streaming clients.
pub fn publish(event: StreamEvent) {
    let _ = STREAM_TX.send(event);
}

// ---------------------------------------------------------------------------
// Auth helper — supports both Bearer header and query param
// ---------------------------------------------------------------------------

async fn authenticate(
    pool: &SqlitePool,
    headers: &HeaderMap,
    params: &HashMap<String, String>,
) -> Result<AuthenticatedAccount, AppError> {
    let token = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string())
        .or_else(|| params.get("access_token").cloned())
        .ok_or_else(|| AppError::unauthorized("Missing access token"))?;

    let token_hash = hex_encode(&Sha256::digest(token.as_bytes()));

    let row: Option<(i64, String, String)> = sqlx::query_as(
        "SELECT t.account_id, a.username, t.scopes \
         FROM oauth_tokens t JOIN accounts a ON t.account_id = a.id \
         WHERE t.token_hash = ? AND t.revoked_at IS NULL",
    )
    .bind(&token_hash)
    .fetch_optional(pool)
    .await
    .map_err(AppError::from)?;

    let (account_id, username, scopes) =
        row.ok_or_else(|| AppError::unauthorized("Invalid or revoked token"))?;

    Ok(AuthenticatedAccount {
        account_id,
        username,
        scopes,
        token_hash,
    })
}

// ---------------------------------------------------------------------------
// Channel resolution
// ---------------------------------------------------------------------------

/// Map a requested stream name to the internal channel key used for filtering.
/// Channels that are per-user get the account ID appended.
fn resolve_channel(
    stream: &str,
    account: &AuthenticatedAccount,
    params: &HashMap<String, String>,
) -> Result<String, AppError> {
    match stream {
        "user" | "user:notification" => Ok(format!("user:{}", account.account_id)),
        "direct" => Ok(format!("direct:{}", account.account_id)),
        "public" => Ok("public".to_string()),
        "public:local" => Ok("public:local".to_string()),
        "public:media" => Ok("public:media".to_string()),
        "public:local:media" => Ok("public:local:media".to_string()),
        "hashtag" => {
            let tag = params
                .get("tag")
                .ok_or_else(|| AppError::bad_request("Missing tag parameter"))?;
            Ok(format!("hashtag:{}", tag.to_lowercase()))
        }
        "hashtag:local" => {
            let tag = params
                .get("tag")
                .ok_or_else(|| AppError::bad_request("Missing tag parameter"))?;
            Ok(format!("hashtag:local:{}", tag.to_lowercase()))
        }
        "list" => {
            let list_id = params
                .get("list")
                .ok_or_else(|| AppError::bad_request("Missing list parameter"))?;
            Ok(format!("list:{}:{}", account.account_id, list_id))
        }
        _ => Err(AppError::bad_request(format!("Unknown stream: {stream}"))),
    }
}

// ---------------------------------------------------------------------------
// SSE endpoint: GET /api/v1/streaming/{channel}
// ---------------------------------------------------------------------------

async fn streaming_sse_handler(
    State(state): State<Arc<AppState>>,
    Path(channel): Path<String>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>>, AppError> {
    let account = authenticate(&state.pool, &headers, &params).await?;
    let resolved = resolve_channel(&channel, &account, &params)?;

    let rx = STREAM_TX.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(move |msg| match msg {
        Ok(ev) if ev.channel == resolved => {
            let event = Event::default().event(&ev.event_type).data(&ev.payload);
            Some(Ok(event))
        }
        _ => None,
    });

    Ok(Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(std::time::Duration::from_secs(15))
            .text("thump"),
    ))
}

// ---------------------------------------------------------------------------
// WebSocket endpoint: GET /api/v1/streaming
// ---------------------------------------------------------------------------

async fn streaming_ws(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<impl IntoResponse, AppError> {
    let account = authenticate(&state.pool, &headers, &params).await?;
    let pool = state.pool.clone();

    Ok(ws.on_upgrade(move |socket| handle_ws(socket, account, pool, params)))
}

#[derive(Deserialize)]
struct WsCommand {
    #[serde(rename = "type")]
    cmd_type: String,
    stream: Option<String>,
    tag: Option<String>,
    list: Option<String>,
}

async fn handle_ws(
    socket: WebSocket,
    account: AuthenticatedAccount,
    _pool: SqlitePool,
    initial_params: HashMap<String, String>,
) {
    let (mut ws_tx, mut ws_rx) = futures::StreamExt::split(socket);
    // ponytail: no per-connection subscription cap; connection limits delegated
    // to reverse proxy (Caddy max_conns, nginx limit_conn_zone).
    let mut subscriptions: Vec<String> = Vec::new();

    // If `stream` was provided as a query param, auto-subscribe
    if let Some(stream) = initial_params.get("stream") {
        if let Ok(ch) = resolve_channel(stream, &account, &initial_params) {
            subscriptions.push(ch);
        }
    }

    let mut broadcast_rx = STREAM_TX.subscribe();

    // ponytail: single-task select loop; upgrade to spawn_paired if backpressure matters
    loop {
        tokio::select! {
            msg = futures::StreamExt::next(&mut ws_rx) => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        if let Ok(cmd) = serde_json::from_str::<WsCommand>(&text) {
                            let mut params = HashMap::new();
                            if let Some(ref tag) = cmd.tag {
                                params.insert("tag".to_string(), tag.clone());
                            }
                            if let Some(ref list) = cmd.list {
                                params.insert("list".to_string(), list.clone());
                            }
                            if let Some(ref stream) = cmd.stream {
                                match cmd.cmd_type.as_str() {
                                    "subscribe" => {
                                        if let Ok(ch) = resolve_channel(stream, &account, &params) {
                                            if !subscriptions.contains(&ch) {
                                                subscriptions.push(ch);
                                            }
                                        }
                                    }
                                    "unsubscribe" => {
                                        if let Ok(ch) = resolve_channel(stream, &account, &params) {
                                            subscriptions.retain(|s| s != &ch);
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
            ev = broadcast_rx.recv() => {
                match ev {
                    Ok(event) if subscriptions.iter().any(|s| s == &event.channel) => {
                        let frame = serde_json::json!({
                            "event": event.event_type,
                            "payload": event.payload,
                            "stream": [&event.channel],
                        });
                        let text = frame.to_string();
                        if futures::SinkExt::send(&mut ws_tx, Message::Text(text.into())).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("streaming ws lagged, skipped {n} events");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                    _ => {}
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

async fn streaming_health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/streaming", get(streaming_ws))
        .route("/api/v1/streaming/{channel}", get(streaming_sse_handler))
        .route("/api/v1/streaming/health", get(streaming_health))
}
