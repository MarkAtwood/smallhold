//! Funkwhale-compatible API endpoints for smallhold.

use crate::api::AuthenticatedAccount;
use crate::error::AppError;
use crate::server::AppState;
use axum::extract::{Path, Query, State};
use axum::routing::get;
use axum::{Json, Router};
use fieldwork::funkwhale_api::*;
use std::sync::Arc;

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn track_row_to_response(t: &fieldwork_db::audio_db::TrackRow) -> TrackResponse {
    TrackResponse {
        id: t.id,
        title: t.title.clone(),
        artist: t.artist.clone(),
        album: t.album.clone(),
        track_number: t.track_number,
        duration: t.duration,
        file_size: t.file_size,
        mime_type: t.mime_type.clone(),
        description: t.description.clone(),
        visibility: t.visibility.clone(),
        created_at: t.created_at,
        listen_url: Some(format!("/api/v1/listen/{}", t.id)),
    }
}

fn channel_row_to_response(c: &fieldwork_db::audio_db::AudioChannelRow) -> ChannelResponse {
    ChannelResponse {
        persona_id: c.persona_id,
        description: c.description.clone(),
        category: c.category.clone(),
        language: c.language.clone(),
        rss_enabled: c.rss_enabled,
        itunes_category: c.itunes_category.clone(),
        created_at: c.created_at,
    }
}

// ---------------------------------------------------------------------------
// GET /api/v1/tracks
// ---------------------------------------------------------------------------

async fn list_tracks(
    State(state): State<Arc<AppState>>,
    Query(params): Query<PaginationParams>,
) -> Json<PaginatedResponse<TrackResponse>> {
    let (limit, offset) = params.to_limit_offset();
    let tracks = fieldwork_db::audio_db::list_public_tracks(&state.pool, limit, offset)
        .await
        .unwrap_or_default();
    let results: Vec<_> = tracks.iter().map(track_row_to_response).collect();
    Json(PaginatedResponse {
        count: results.len(),
        results,
    })
}

// ---------------------------------------------------------------------------
// GET /api/v1/tracks/{id}
// ---------------------------------------------------------------------------

async fn get_track(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<Json<TrackResponse>, AppError> {
    let track = fieldwork_db::audio_db::get_track(&state.pool, id)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("Track not found"))?;
    Ok(Json(track_row_to_response(&track)))
}

// ---------------------------------------------------------------------------
// GET /api/v1/albums
// ---------------------------------------------------------------------------

async fn list_albums(
    State(state): State<Arc<AppState>>,
    Query(params): Query<PaginationParams>,
) -> Json<PaginatedResponse<AlbumResponse>> {
    let (limit, offset) = params.to_limit_offset();
    let albums = fieldwork_db::audio_db::list_albums(&state.pool, limit, offset)
        .await
        .unwrap_or_default();
    let results: Vec<_> = albums
        .iter()
        .map(|(album, artist, count)| AlbumResponse {
            album: album.clone(),
            artist: artist.clone(),
            track_count: *count,
        })
        .collect();
    Json(PaginatedResponse {
        count: results.len(),
        results,
    })
}

// ---------------------------------------------------------------------------
// GET /api/v1/channels
// ---------------------------------------------------------------------------

async fn list_channels(
    State(state): State<Arc<AppState>>,
    Query(params): Query<PaginationParams>,
) -> Json<PaginatedResponse<ChannelResponse>> {
    let (limit, offset) = params.to_limit_offset();
    let channels = fieldwork_db::audio_db::list_all_audio_channels(&state.pool, limit, offset)
        .await
        .unwrap_or_default();
    let results: Vec<_> = channels.iter().map(channel_row_to_response).collect();
    Json(PaginatedResponse {
        count: results.len(),
        results,
    })
}

// ---------------------------------------------------------------------------
// GET /api/v1/playlists
// ---------------------------------------------------------------------------

async fn list_playlists(
    State(state): State<Arc<AppState>>,
    Query(params): Query<PaginationParams>,
) -> Json<PaginatedResponse<PlaylistResponse>> {
    let (limit, offset) = params.to_limit_offset();
    let playlists = fieldwork_db::audio_db::list_audio_playlists(&state.pool, limit, offset)
        .await
        .unwrap_or_default();
    let results: Vec<_> = playlists
        .iter()
        .map(|(id, user_id, title, desc, vis, created_at)| PlaylistResponse {
            id: *id,
            user_id: *user_id,
            title: title.clone(),
            description: desc.clone(),
            visibility: vis.clone(),
            created_at: *created_at,
        })
        .collect();
    Json(PaginatedResponse {
        count: results.len(),
        results,
    })
}

// ---------------------------------------------------------------------------
// POST /api/v1/playlists
// ---------------------------------------------------------------------------

async fn create_playlist(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Json(body): Json<CreatePlaylistRequest>,
) -> Result<Json<PlaylistResponse>, AppError> {
    auth.require_scope("write")?;
    let now = now_secs();
    let id = fieldwork::id::generate_id();
    fieldwork_db::audio_db::create_audio_playlist(
        &state.pool,
        id,
        crate::db::DEFAULT_USER_ID,
        &body.title,
        &body.description,
        &body.visibility,
        now,
    )
    .await
    .map_err(AppError::from)?;
    Ok(Json(PlaylistResponse {
        id,
        user_id: crate::db::DEFAULT_USER_ID,
        title: body.title,
        description: body.description,
        visibility: body.visibility,
        created_at: now,
    }))
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(TRACKS_PATH, get(list_tracks))
        .route(TRACK_PATH, get(get_track))
        .route(ALBUMS_PATH, get(list_albums))
        .route(CHANNELS_PATH, get(list_channels))
        .route(PLAYLISTS_PATH, get(list_playlists).post(create_playlist))
}
