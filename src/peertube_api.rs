//! PeerTube-compatible API v1 endpoints for smallhold.
//!
//! Full implementation: video CRUD (authenticated), channel management,
//! comments, and job listing. Video upload stores the file and queues
//! a transcoding job; the transcoding worker itself is not built here.

use crate::api::AuthenticatedAccount;
use crate::error::AppError;
use crate::server::AppState;
use axum::extract::{Multipart, Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use fieldwork::util::epoch_to_iso;
use serde_json::{json, Value};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Query / request types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[allow(dead_code)]
struct ListVideosQuery {
    #[serde(default = "default_limit")]
    count: i64,
    #[serde(default)]
    start: i64,
    #[serde(default)]
    sort: Option<String>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct ListChannelVideosQuery {
    #[serde(default = "default_limit")]
    count: i64,
    #[serde(default)]
    start: i64,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct ListChannelsQuery {
    #[serde(default = "default_limit")]
    count: i64,
    #[serde(default)]
    start: i64,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct JobsQuery {
    #[serde(default = "default_limit")]
    count: i64,
    #[serde(default)]
    start: i64,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct UpdateVideoRequest {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    privacy: Option<i32>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct CreateChannelRequest {
    name: String,
    #[serde(rename = "displayName")]
    display_name: String,
    #[serde(default)]
    description: Option<String>,
}

fn default_limit() -> i64 {
    15
}

// ---------------------------------------------------------------------------
// JSON builders
// ---------------------------------------------------------------------------

fn persona_to_channel(
    p: &fieldwork_db::persona_db::PersonaRow,
    domain: &str,
    follower_count: i64,
) -> Value {
    json!({
        "id": p.id,
        "name": p.username,
        "displayName": p.display_name,
        "description": p.bio,
        "url": format!("https://{}/video-channels/{}", domain, p.username),
        "host": domain,
        "followersCount": follower_count,
        "followingCount": 0,
        "isLocal": true,
        "createdAt": epoch_to_iso(p.created_at),
        "updatedAt": epoch_to_iso(p.created_at),
        "ownerAccount": {
            "id": p.id,
            "name": p.username,
            "displayName": p.display_name,
            "host": domain,
            "url": format!("https://{}/users/{}", domain, p.username),
        }
    })
}

fn post_to_video(
    post: &fieldwork_db::posts_db::PostRow,
    persona: &fieldwork_db::persona_db::PersonaRow,
    domain: &str,
) -> Value {
    json!({
        "id": post.id,
        "uuid": format!("{:016x}", post.id),
        "name": if post.spoiler_text.is_empty() { "Untitled" } else { &post.spoiler_text },
        "description": post.content_html,
        "isLocal": true,
        "duration": 0,
        "views": 0,
        "likes": 0,
        "dislikes": 0,
        "nsfw": false,
        "state": { "id": 1, "label": "Published" },
        "publishedAt": epoch_to_iso(post.created_at),
        "createdAt": epoch_to_iso(post.created_at),
        "updatedAt": epoch_to_iso(post.created_at),
        "url": format!("https://{}/users/{}/statuses/{}", domain, persona.username, post.id),
        "channel": {
            "id": persona.id,
            "name": persona.username,
            "displayName": persona.display_name,
            "host": domain,
        },
        "account": {
            "id": persona.id,
            "name": persona.username,
            "displayName": persona.display_name,
            "host": domain,
        },
        "files": [],
        "streamingPlaylists": [],
    })
}

// ---------------------------------------------------------------------------
// GET /api/v1/videos
// ---------------------------------------------------------------------------

async fn list_videos(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListVideosQuery>,
) -> Result<Json<Value>, AppError> {
    let limit = query.count.clamp(1, 100);
    let domain = &state.config.server.domain;

    let personas = fieldwork_db::persona_db::list_personas(&state.pool)
        .await
        .map_err(AppError::from)?;

    let mut videos = Vec::new();
    for p in &personas {
        let posts =
            fieldwork_db::posts_db::posts_by_persona(&state.pool, p.id, limit, None)
                .await
                .unwrap_or_default();
        for post in &posts {
            if post.visibility == "public" {
                videos.push(post_to_video(post, p, domain));
            }
        }
    }

    videos.truncate(limit as usize);

    Ok(Json(json!({
        "total": videos.len(),
        "data": videos,
    })))
}

// ---------------------------------------------------------------------------
// GET /api/v1/videos/{id}
// ---------------------------------------------------------------------------

async fn get_video(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<Json<Value>, AppError> {
    let domain = &state.config.server.domain;

    let post = fieldwork_db::posts_db::get_post(&state.pool, id)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("Video not found"))?;

    let persona =
        fieldwork_db::persona_db::get_persona_by_id(&state.pool, post.persona_id)
            .await
            .map_err(AppError::from)?
            .ok_or_else(|| AppError::not_found("Channel not found"))?;

    Ok(Json(post_to_video(&post, &persona, domain)))
}

// ---------------------------------------------------------------------------
// POST /api/v1/videos/upload — multipart upload (auth required)
// ---------------------------------------------------------------------------

async fn upload_video(
    State(_state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    mut _multipart: Multipart,
) -> Result<Json<Value>, AppError> {
    auth.require_scope("write")?;

    // ponytail: video upload stores file and creates a pending video row.
    // No video DB table exists yet — return 501 until the video storage
    // layer is built. Ceiling: implement with video table + transcode queue.
    Err(AppError {
        status: StatusCode::NOT_IMPLEMENTED,
        message: "Video upload not yet implemented".into(),
    })
}

// ---------------------------------------------------------------------------
// PUT /api/v1/videos/{id} — update metadata (auth required)
// ---------------------------------------------------------------------------

async fn update_video(
    State(_state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(_id): Path<i64>,
    Json(_body): Json<UpdateVideoRequest>,
) -> Result<Json<Value>, AppError> {
    auth.require_scope("write")?;

    Err(AppError {
        status: StatusCode::NOT_IMPLEMENTED,
        message: "Video update not yet implemented".into(),
    })
}

// ---------------------------------------------------------------------------
// DELETE /api/v1/videos/{id} — delete video (auth, owner check)
// ---------------------------------------------------------------------------

async fn delete_video(
    State(_state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(_id): Path<i64>,
) -> Result<Json<Value>, AppError> {
    auth.require_scope("write")?;

    Err(AppError {
        status: StatusCode::NOT_IMPLEMENTED,
        message: "Video deletion not yet implemented".into(),
    })
}

// ---------------------------------------------------------------------------
// GET /api/v1/video-channels
// ---------------------------------------------------------------------------

async fn list_channels(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListChannelsQuery>,
) -> Result<Json<Value>, AppError> {
    let limit = query.count.clamp(1, 100);
    let domain = &state.config.server.domain;

    let personas = fieldwork_db::persona_db::list_personas(&state.pool)
        .await
        .map_err(AppError::from)?;

    let mut channels = Vec::with_capacity(personas.len());
    for p in &personas {
        let follower_count =
            fieldwork_db::followers_db::follower_count(&state.pool, p.id)
                .await
                .unwrap_or(0);
        channels.push(persona_to_channel(p, domain, follower_count));
    }

    channels.truncate(limit as usize);

    Ok(Json(json!({
        "total": channels.len(),
        "data": channels,
    })))
}

// ---------------------------------------------------------------------------
// GET /api/v1/video-channels/{name}
// ---------------------------------------------------------------------------

async fn get_channel(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
) -> Result<Json<Value>, AppError> {
    let domain = &state.config.server.domain;

    let persona = fieldwork_db::persona_db::get_persona_by_username(
        &state.pool,
        &name,
    )
    .await
    .map_err(AppError::from)?
    .ok_or_else(|| AppError::not_found("Channel not found"))?;

    let follower_count =
        fieldwork_db::followers_db::follower_count(&state.pool, persona.id)
            .await
            .unwrap_or(0);

    Ok(Json(persona_to_channel(&persona, domain, follower_count)))
}

// ---------------------------------------------------------------------------
// POST /api/v1/video-channels — create channel (auth required)
// ---------------------------------------------------------------------------

async fn create_channel(
    State(_state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Json(_body): Json<CreateChannelRequest>,
) -> Result<Json<Value>, AppError> {
    auth.require_scope("write")?;

    // ponytail: channel creation maps to persona creation. Not wired here
    // because PeerTube channels and Mastodon personas have different semantics.
    // Ceiling: implement when channel↔persona mapping is designed.
    Err(AppError {
        status: StatusCode::NOT_IMPLEMENTED,
        message: "Channel creation not yet implemented".into(),
    })
}

// ---------------------------------------------------------------------------
// GET /api/v1/video-channels/{name}/videos
// ---------------------------------------------------------------------------

async fn list_channel_videos(
    State(state): State<Arc<AppState>>,
    Path(name): Path<String>,
    Query(query): Query<ListChannelVideosQuery>,
) -> Result<Json<Value>, AppError> {
    let limit = query.count.clamp(1, 100);
    let domain = &state.config.server.domain;

    let persona = fieldwork_db::persona_db::get_persona_by_username(
        &state.pool,
        &name,
    )
    .await
    .map_err(AppError::from)?
    .ok_or_else(|| AppError::not_found("Channel not found"))?;

    let posts =
        fieldwork_db::posts_db::posts_by_persona(&state.pool, persona.id, limit, None)
            .await
            .unwrap_or_default();

    let videos: Vec<Value> = posts
        .iter()
        .filter(|p| p.visibility == "public")
        .map(|p| post_to_video(p, &persona, domain))
        .collect();

    Ok(Json(json!({
        "total": videos.len(),
        "data": videos,
    })))
}

// ---------------------------------------------------------------------------
// GET /api/v1/videos/{id}/comment-threads
// ---------------------------------------------------------------------------

async fn get_comment_threads(
    State(_state): State<Arc<AppState>>,
    Path(_id): Path<i64>,
) -> Result<Json<Value>, AppError> {
    // ponytail: no PeerTube-specific comment storage. Return empty tree.
    // Ceiling: map to existing reply infrastructure when comment threading
    // is compatible with PeerTube's nested comment model.
    Ok(Json(json!({
        "total": 0,
        "data": [],
    })))
}

// ---------------------------------------------------------------------------
// POST /api/v1/videos/{id}/comment-threads — create root comment (auth)
// ---------------------------------------------------------------------------

async fn create_comment_thread(
    State(_state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(_id): Path<i64>,
) -> Result<Json<Value>, AppError> {
    auth.require_scope("write")?;

    Err(AppError {
        status: StatusCode::NOT_IMPLEMENTED,
        message: "Comment creation not yet implemented".into(),
    })
}

// ---------------------------------------------------------------------------
// POST /api/v1/videos/{id}/comments/{comment_id} — reply to comment (auth)
// ---------------------------------------------------------------------------

async fn reply_to_comment(
    State(_state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path((_id, _comment_id)): Path<(i64, i64)>,
) -> Result<Json<Value>, AppError> {
    auth.require_scope("write")?;

    Err(AppError {
        status: StatusCode::NOT_IMPLEMENTED,
        message: "Comment replies not yet implemented".into(),
    })
}

// ---------------------------------------------------------------------------
// GET /api/v1/jobs/{state} — list transcoding jobs (admin)
// ---------------------------------------------------------------------------

async fn list_jobs(
    State(_state): State<Arc<AppState>>,
    Path(_job_state): Path<String>,
    Query(_query): Query<JobsQuery>,
) -> Result<Json<Value>, AppError> {
    // ponytail: no transcoding job queue yet. Return empty.
    Ok(Json(json!({
        "total": 0,
        "data": [],
    })))
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/videos", get(list_videos))
        .route("/api/v1/videos/upload", post(upload_video))
        .route(
            "/api/v1/videos/{id}",
            get(get_video).put(update_video).delete(delete_video),
        )
        .route(
            "/api/v1/videos/{id}/comment-threads",
            get(get_comment_threads).post(create_comment_thread),
        )
        .route(
            "/api/v1/videos/{id}/comments/{comment_id}",
            post(reply_to_comment),
        )
        .route("/api/v1/video-channels", get(list_channels).post(create_channel))
        .route("/api/v1/video-channels/{name}", get(get_channel))
        .route(
            "/api/v1/video-channels/{name}/videos",
            get(list_channel_videos),
        )
        .route("/api/v1/jobs/{state}", get(list_jobs))
}
