//! Pixelfed-compatible API endpoints for smallhold.
//!
//! Full implementation: collection CRUD (authenticated) and discover
//! endpoints (public).

use crate::api::{fetch_account_row, AuthenticatedAccount};
use crate::error::AppError;
use crate::id::generate_id;
use crate::posting::{fw_to_local_post, load_status};
use crate::server::AppState;
use axum::extract::{Path, Query, State};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Query / request types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct DiscoverQuery {
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default = "default_range")]
    range: String,
}

#[derive(Deserialize)]
struct AccountsQuery {
    #[serde(default = "default_limit")]
    limit: i64,
}

#[derive(Deserialize)]
struct CreateCollectionRequest {
    title: String,
    #[serde(default)]
    description: String,
    #[serde(default = "default_visibility")]
    visibility: String,
}

#[derive(Deserialize)]
struct AddItemRequest {
    #[serde(deserialize_with = "deserialize_string_or_int")]
    media_id: String,
    #[serde(default)]
    position: i32,
}

/// Accept both `"12345"` (string) and `12345` (integer) for ID fields.
/// Pixelfed clients may send either form.
fn deserialize_string_or_int<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    let v: Value = Deserialize::deserialize(d)?;
    match v {
        Value::String(s) => Ok(s),
        Value::Number(n) => Ok(n.to_string()),
        _ => Err(serde::de::Error::custom("expected string or integer")),
    }
}

fn default_limit() -> i64 {
    20
}

fn default_range() -> String {
    "daily".into()
}

fn default_visibility() -> String {
    "public".into()
}

fn range_to_since(range: &str) -> i64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let duration = match range {
        "weekly" => 7 * 24 * 3600,
        "monthly" => 30 * 24 * 3600,
        _ => 24 * 3600,
    };
    now - duration
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

// ---------------------------------------------------------------------------
// Collection helpers
// ---------------------------------------------------------------------------

fn album_to_json(
    album: &fieldwork_db::albums_db::AlbumRow,
    item_count: usize,
) -> Value {
    json!({
        "id": album.id.to_string(),
        "title": album.title,
        "description": album.description,
        "visibility": album.visibility,
        "thumb": null,
        "post_count": item_count,
        "created_at": chrono::DateTime::from_timestamp(album.created_at, 0)
            .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()),
        "updated_at": album.updated_at.and_then(|t|
            chrono::DateTime::from_timestamp(t, 0)
                .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        ),
    })
}

// ---------------------------------------------------------------------------
// GET /api/pixelfed/v1/accounts/{id}/collections
// ---------------------------------------------------------------------------

async fn list_collections(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let persona_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("Account not found"))?;

    let albums = fieldwork_db::albums_db::list_albums(&state.pool, persona_id)
        .await
        .map_err(AppError::from)?;

    let mut results = Vec::with_capacity(albums.len());
    for album in &albums {
        let items = fieldwork_db::albums_db::album_items(&state.pool, album.id)
            .await
            .unwrap_or_default();
        results.push(album_to_json(album, items.len()));
    }

    Ok(Json(Value::Array(results)))
}

// ---------------------------------------------------------------------------
// POST /api/pixelfed/v1/collections
// ---------------------------------------------------------------------------

async fn create_collection(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Json(body): Json<CreateCollectionRequest>,
) -> Result<Json<Value>, AppError> {
    auth.require_scope("write")?;

    let album = fieldwork_db::albums_db::AlbumRow {
        id: generate_id(),
        user_id: crate::db::DEFAULT_USER_ID,
        persona_id: auth.account_id,
        title: body.title,
        description: body.description,
        visibility: body.visibility,
        cover_media_id: None,
        created_at: now_secs(),
        updated_at: None,
    };

    fieldwork_db::albums_db::create_album(&state.pool, &album)
        .await
        .map_err(AppError::from)?;

    Ok(Json(album_to_json(&album, 0)))
}

// ---------------------------------------------------------------------------
// GET /api/pixelfed/v1/collections/{id}
// ---------------------------------------------------------------------------

async fn get_collection(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let album_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("Collection not found"))?;

    let album = fieldwork_db::albums_db::get_album(&state.pool, album_id)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("Collection not found"))?;

    let media_ids = fieldwork_db::albums_db::album_items(&state.pool, album_id)
        .await
        .map_err(AppError::from)?;

    let domain = &state.config.server.domain;
    let mut items = Vec::with_capacity(media_ids.len());
    for mid in &media_ids {
        if let Ok(Some(m)) = fieldwork_db::media_db::get_media(&state.pool, *mid).await {
            items.push(json!({
                "id": m.id.to_string(),
                "type": m.mime_type,
                "url": format!("https://{domain}/media/{}", m.file_path),
            }));
        }
    }

    let mut result = album_to_json(&album, media_ids.len());
    result["items"] = Value::Array(items);

    Ok(Json(result))
}

// ---------------------------------------------------------------------------
// POST /api/pixelfed/v1/collections/{id}/items
// ---------------------------------------------------------------------------

async fn add_collection_item(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(id): Path<String>,
    Json(body): Json<AddItemRequest>,
) -> Result<Json<Value>, AppError> {
    auth.require_scope("write")?;

    let album_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("Collection not found"))?;

    let album = fieldwork_db::albums_db::get_album(&state.pool, album_id)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("Collection not found"))?;

    if album.persona_id != auth.account_id {
        return Err(AppError::forbidden("Not your collection"));
    }

    let media_id: i64 = body
        .media_id
        .parse()
        .map_err(|_| AppError::bad_request("Invalid media_id"))?;

    fieldwork_db::albums_db::add_to_album(&state.pool, album_id, media_id, body.position)
        .await
        .map_err(AppError::from)?;

    Ok(Json(json!({})))
}

// ---------------------------------------------------------------------------
// DELETE /api/pixelfed/v1/collections/{id}/items/{media_id}
// ---------------------------------------------------------------------------

async fn remove_collection_item(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path((id, media_id)): Path<(String, String)>,
) -> Result<Json<Value>, AppError> {
    auth.require_scope("write")?;

    let album_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("Collection not found"))?;

    let album = fieldwork_db::albums_db::get_album(&state.pool, album_id)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("Collection not found"))?;

    if album.persona_id != auth.account_id {
        return Err(AppError::forbidden("Not your collection"));
    }

    let mid: i64 = media_id
        .parse()
        .map_err(|_| AppError::bad_request("Invalid media_id"))?;

    fieldwork_db::albums_db::remove_from_album(&state.pool, album_id, mid)
        .await
        .map_err(AppError::from)?;

    Ok(Json(json!({})))
}

// ---------------------------------------------------------------------------
// GET /api/pixelfed/v1/discover/posts
// ---------------------------------------------------------------------------

async fn discover_posts(
    State(state): State<Arc<AppState>>,
    Query(query): Query<DiscoverQuery>,
) -> Result<Json<Value>, AppError> {
    let limit = query.limit.clamp(1, 40);
    let since = range_to_since(&query.range);

    let post_ids = fieldwork_db::trending_db::trending_posts(&state.pool, limit, since)
        .await
        .map_err(AppError::from)?;

    let domain = &state.config.server.domain;
    let mut statuses = Vec::with_capacity(post_ids.len());
    for post_id in post_ids {
        let fw_post = match fieldwork_db::posts_db::get_post(&state.pool, post_id).await {
            Ok(Some(p)) if p.visibility == "public" => p,
            _ => continue,
        };
        let local_post = fw_to_local_post(&fw_post);
        match load_status(&state.pool, &local_post, domain, None).await {
            Ok(status) => statuses.push(status),
            Err(_) => continue,
        }
    }

    Ok(Json(Value::Array(statuses)))
}

// ---------------------------------------------------------------------------
// GET /api/pixelfed/v1/discover/hashtags
// ---------------------------------------------------------------------------

async fn discover_hashtags(
    State(state): State<Arc<AppState>>,
    Query(query): Query<DiscoverQuery>,
) -> Result<Json<Value>, AppError> {
    let limit = query.limit.clamp(1, 40);
    let since = range_to_since(&query.range);

    let tags = fieldwork_db::trending_db::trending_tags(&state.pool, limit, since)
        .await
        .map_err(AppError::from)?;

    let domain = &state.config.server.domain;
    let day_str = (since as u64).to_string();
    let results: Vec<Value> = tags
        .into_iter()
        .map(|(name, count)| {
            json!({
                "name": name,
                "url": format!("https://{domain}/tags/{name}"),
                "history": [
                    { "day": day_str, "uses": count.to_string(), "accounts": count.to_string() }
                ]
            })
        })
        .collect();

    Ok(Json(Value::Array(results)))
}

// ---------------------------------------------------------------------------
// GET /api/pixelfed/v1/discover/accounts
// ---------------------------------------------------------------------------

async fn discover_accounts(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AccountsQuery>,
) -> Result<Json<Value>, AppError> {
    let limit = query.limit.clamp(1, 40);
    let domain = &state.config.server.domain;

    let personas = fieldwork_db::persona_db::list_personas(&state.pool)
        .await
        .map_err(AppError::from)?;

    let mut persona_counts: Vec<(i64, i64)> = Vec::with_capacity(personas.len());
    for p in &personas {
        let count = fieldwork_db::followers_db::follower_count(&state.pool, p.id)
            .await
            .unwrap_or(0);
        persona_counts.push((p.id, count));
    }
    persona_counts.sort_by(|a, b| b.1.cmp(&a.1));
    persona_counts.truncate(limit as usize);

    let mut results = Vec::with_capacity(persona_counts.len());
    for (pid, _) in &persona_counts {
        match fetch_account_row(&state.pool, *pid).await {
            Ok(row) => {
                let (f, fo, s) = crate::api::fetch_account_counts(&state.pool, *pid).await;
                results.push(crate::api::account_to_json_with_counts(&row, domain, f, fo, s));
            }
            Err(_) => continue,
        }
    }

    Ok(Json(Value::Array(results)))
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        // Collections
        .route(
            "/api/pixelfed/v1/accounts/{id}/collections",
            get(list_collections),
        )
        .route("/api/pixelfed/v1/collections", post(create_collection))
        .route("/api/pixelfed/v1/collections/{id}", get(get_collection))
        .route(
            "/api/pixelfed/v1/collections/{id}/items",
            post(add_collection_item),
        )
        .route(
            "/api/pixelfed/v1/collections/{id}/items/{media_id}",
            delete(remove_collection_item),
        )
        // Discover
        .route("/api/pixelfed/v1/discover/posts", get(discover_posts))
        .route(
            "/api/pixelfed/v1/discover/hashtags",
            get(discover_hashtags),
        )
        .route(
            "/api/pixelfed/v1/discover/accounts",
            get(discover_accounts),
        )
}
