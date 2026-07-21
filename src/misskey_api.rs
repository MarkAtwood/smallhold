//! Misskey-compatible API endpoints for smallhold.
//!
//! Full implementation: note CRUD, timeline, emoji reactions, and user profile.
//! Auth is via `i` field in the POST JSON body (token), mapped to the same
//! oauth_tokens table used by the Mastodon-compatible API.

use crate::api::{hex_encode, AuthenticatedAccount};
use crate::error::AppError;
use crate::id::generate_id;
use crate::server::AppState;
use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct AuthOnlyRequest {
    i: String,
}

#[derive(Deserialize)]
struct NoteShowRequest {
    i: Option<String>,
    #[serde(rename = "noteId")]
    note_id: String,
}

#[derive(Deserialize)]
struct TimelineRequest {
    i: Option<String>,
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(rename = "untilId")]
    until_id: Option<String>,
}

#[derive(Deserialize)]
struct AuthTimelineRequest {
    i: String,
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(rename = "untilId")]
    until_id: Option<String>,
}

#[derive(Deserialize)]
struct NoteCreateRequest {
    i: String,
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    visibility: Option<String>,
    #[serde(default)]
    cw: Option<String>,
    #[serde(rename = "replyId")]
    #[serde(default)]
    reply_id: Option<String>,
}

#[derive(Deserialize)]
struct ReactionCreateRequest {
    i: String,
    #[serde(rename = "noteId")]
    note_id: String,
    reaction: String,
}

#[derive(Deserialize)]
struct ReactionDeleteRequest {
    i: String,
    #[serde(rename = "noteId")]
    note_id: String,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct UserShowRequest {
    i: Option<String>,
    #[serde(rename = "userId")]
    user_id: Option<String>,
    username: Option<String>,
}

fn default_limit() -> i64 {
    20
}

fn simple_html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

// ---------------------------------------------------------------------------
// Auth helper
// ---------------------------------------------------------------------------

async fn misskey_auth(
    pool: &fieldwork_db::db::Pool,
    token: &str,
) -> Result<AuthenticatedAccount, AppError> {
    let token_hash = hex_encode(&Sha256::digest(token.as_bytes()));

    let row = fieldwork_db::oauth_db::verify_token(pool, &token_hash)
        .await
        .map_err(AppError::from)?;

    let (account_id, username, scopes) =
        row.ok_or_else(|| AppError::unauthorized("Invalid or revoked token"))?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let _ = fieldwork_db::oauth_db::touch_token(pool, &token_hash, now).await;

    Ok(AuthenticatedAccount {
        account_id,
        username,
        scopes,
        token_hash,
    })
}

// ---------------------------------------------------------------------------
// JSON builders
// ---------------------------------------------------------------------------

fn epoch_to_misskey_date(epoch: i64) -> String {
    chrono::DateTime::from_timestamp(epoch, 0)
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
        .unwrap_or_default()
}

fn post_to_note(
    post: &fieldwork_db::posts_db::PostRow,
    persona: &fieldwork_db::persona_db::PersonaRow,
    domain: &str,
    reactions: &[(String, i64)],
    my_reaction: Option<&str>,
) -> Value {
    let reactions_map: serde_json::Map<String, Value> = reactions
        .iter()
        .map(|(emoji, count)| (emoji.clone(), json!(count)))
        .collect();

    json!({
        "id": post.id.to_string(),
        "createdAt": epoch_to_misskey_date(post.created_at),
        "text": post.content,
        "cw": if post.spoiler_text.is_empty() { None } else { Some(&post.spoiler_text) },
        "visibility": misskey_visibility(&post.visibility),
        "uri": format!("https://{domain}/users/{}/statuses/{}", persona.username, post.id),
        "url": format!("https://{domain}/users/{}/statuses/{}", persona.username, post.id),
        "user": persona_to_misskey_user(persona, domain),
        "reactions": Value::Object(reactions_map),
        "myReaction": my_reaction,
        "replyId": post.in_reply_to_id.map(|id| id.to_string()),
        "renoteId": post.boost_of_id.map(|id| id.to_string()),
    })
}

fn persona_to_misskey_user(
    p: &fieldwork_db::persona_db::PersonaRow,
    domain: &str,
) -> Value {
    json!({
        "id": p.id.to_string(),
        "username": p.username,
        "name": p.display_name,
        "host": null,
        "description": p.bio,
        "isBot": p.bot,
        "isLocked": p.is_locked,
        "url": format!("https://{domain}/@{}", p.username),
        "avatarUrl": null,
        "bannerUrl": null,
    })
}

fn misskey_visibility(mastodon_vis: &str) -> &str {
    match mastodon_vis {
        "public" => "public",
        "unlisted" => "home",
        "private" => "followers",
        "direct" => "specified",
        _ => "public",
    }
}

fn mastodon_visibility(misskey_vis: &str) -> &str {
    match misskey_vis {
        "public" => "public",
        "home" => "unlisted",
        "followers" => "private",
        "specified" => "direct",
        _ => "public",
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

async fn note_with_reactions(
    pool: &fieldwork_db::db::Pool,
    post: &fieldwork_db::posts_db::PostRow,
    persona: &fieldwork_db::persona_db::PersonaRow,
    domain: &str,
    viewer_persona_id: Option<i64>,
) -> Result<Value, AppError> {
    let reactions = fieldwork_db::reactions_db::reactions_for_post(pool, post.id)
        .await
        .unwrap_or_default();

    let my_reaction = if let Some(pid) = viewer_persona_id {
        let my = fieldwork_db::reactions_db::user_reactions(pool, pid, post.id)
            .await
            .unwrap_or_default();
        my.into_iter().next()
    } else {
        None
    };

    Ok(post_to_note(
        post,
        persona,
        domain,
        &reactions,
        my_reaction.as_deref(),
    ))
}

// ---------------------------------------------------------------------------
// POST /api/notes/show
// ---------------------------------------------------------------------------

async fn notes_show(
    State(state): State<Arc<AppState>>,
    Json(body): Json<NoteShowRequest>,
) -> Result<Json<Value>, AppError> {
    let note_id: i64 = body.note_id.parse()
        .map_err(|_| AppError::bad_request("Invalid noteId"))?;

    let viewer = if let Some(token) = &body.i {
        Some(misskey_auth(&state.pool, token).await?)
    } else {
        None
    };

    let post = fieldwork_db::posts_db::get_post(&state.pool, note_id)
        .await?
        .ok_or_else(|| AppError::not_found("Note not found"))?;

    if post.deleted_at.is_some() {
        return Err(AppError::not_found("Note not found"));
    }

    let persona = fieldwork_db::persona_db::get_persona_by_id(&state.pool, post.persona_id)
        .await?
        .ok_or_else(|| AppError::not_found("User not found"))?;

    let domain = &state.config.server.domain;
    let note = note_with_reactions(
        &state.pool,
        &post,
        &persona,
        domain,
        viewer.as_ref().map(|v| v.account_id),
    )
    .await?;

    Ok(Json(note))
}

// ---------------------------------------------------------------------------
// POST /api/notes/create
// ---------------------------------------------------------------------------

async fn notes_create(
    State(state): State<Arc<AppState>>,
    Json(body): Json<NoteCreateRequest>,
) -> Result<Json<Value>, AppError> {
    let auth = misskey_auth(&state.pool, &body.i).await?;
    auth.require_scope("write")?;

    let text = body.text.unwrap_or_default();
    if text.is_empty() {
        return Err(AppError::bad_request("Text is required"));
    }

    let domain = &state.config.server.domain;
    let id = generate_id();
    let now = now_secs();
    let visibility = body.visibility.as_deref().map(mastodon_visibility).unwrap_or("public");
    let spoiler = body.cw.unwrap_or_default();
    let content_html = format!("<p>{}</p>", simple_html_escape(&text));
    let ap_id = format!("https://{domain}/users/{}/statuses/{id}", auth.username);

    let in_reply_to_id = if let Some(ref rid) = body.reply_id {
        Some(rid.parse::<i64>().map_err(|_| AppError::bad_request("Invalid replyId"))?)
    } else {
        None
    };

    fieldwork_db::posts_db::create_post(
        &state.pool,
        &fieldwork_db::posts_db::PostRow {
            id,
            user_id: crate::db::DEFAULT_USER_ID,
            persona_id: auth.account_id,
            ap_id,
            in_reply_to_id,
            in_reply_to_uri: None,
            boost_of_id: None,
            boost_of_uri: None,
            content: text.clone(),
            content_html,
            spoiler_text: spoiler,
            visibility: visibility.to_string(),
            sensitive: false,
            language: None,
            context_url: None,
            created_at: now,
            edited_at: None,
            deleted_at: None,
            deleted_reason: None,
        },
    )
    .await?;

    let post = fieldwork_db::posts_db::get_post(&state.pool, id)
        .await?
        .ok_or_else(|| AppError::internal("Post not found after creation"))?;
    let persona = fieldwork_db::persona_db::get_persona_by_id(&state.pool, auth.account_id)
        .await?
        .ok_or_else(|| AppError::internal("Persona not found"))?;

    let note = post_to_note(&post, &persona, domain, &[], None);
    Ok(Json(json!({ "createdNote": note })))
}

// ---------------------------------------------------------------------------
// POST /api/notes/timeline
// ---------------------------------------------------------------------------

async fn notes_timeline(
    State(state): State<Arc<AppState>>,
    Json(body): Json<AuthTimelineRequest>,
) -> Result<Json<Value>, AppError> {
    let auth = misskey_auth(&state.pool, &body.i).await?;
    let limit = body.limit.clamp(1, 40);
    let max_id = body.until_id.as_deref().and_then(|s| s.parse::<i64>().ok());
    let domain = &state.config.server.domain;

    let posts = fieldwork_db::timeline_db::home_timeline(
        &state.pool, auth.account_id, limit, max_id,
    )
    .await?;

    let mut notes = Vec::with_capacity(posts.len());
    for post in &posts {
        if post.deleted_at.is_some() {
            continue;
        }
        let persona = match fieldwork_db::persona_db::get_persona_by_id(&state.pool, post.persona_id).await {
            Ok(Some(p)) => p,
            _ => continue,
        };
        match note_with_reactions(&state.pool, post, &persona, domain, Some(auth.account_id)).await {
            Ok(n) => notes.push(n),
            Err(_) => continue,
        }
    }

    Ok(Json(json!(notes)))
}

// ---------------------------------------------------------------------------
// POST /api/notes/local-timeline
// ---------------------------------------------------------------------------

async fn notes_local_timeline(
    State(state): State<Arc<AppState>>,
    Json(body): Json<TimelineRequest>,
) -> Result<Json<Value>, AppError> {
    let viewer = if let Some(token) = &body.i {
        Some(misskey_auth(&state.pool, token).await?)
    } else {
        None
    };

    let limit = body.limit.clamp(1, 40);
    let max_id = body.until_id.as_deref().and_then(|s| s.parse::<i64>().ok());
    let domain = &state.config.server.domain;

    let posts = fieldwork_db::timeline_db::public_timeline(&state.pool, limit, max_id).await?;

    let mut notes = Vec::with_capacity(posts.len());
    for post in &posts {
        if post.deleted_at.is_some() {
            continue;
        }
        let persona = match fieldwork_db::persona_db::get_persona_by_id(&state.pool, post.persona_id).await {
            Ok(Some(p)) => p,
            _ => continue,
        };
        match note_with_reactions(
            &state.pool, post, &persona, domain,
            viewer.as_ref().map(|v| v.account_id),
        ).await {
            Ok(n) => notes.push(n),
            Err(_) => continue,
        }
    }

    Ok(Json(json!(notes)))
}

// ---------------------------------------------------------------------------
// POST /api/notes/reactions/create
// ---------------------------------------------------------------------------

async fn reactions_create(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ReactionCreateRequest>,
) -> Result<Json<Value>, AppError> {
    let auth = misskey_auth(&state.pool, &body.i).await?;
    auth.require_scope("write")?;

    let note_id: i64 = body.note_id.parse()
        .map_err(|_| AppError::bad_request("Invalid noteId"))?;

    // Verify post exists
    let _post = fieldwork_db::posts_db::get_post(&state.pool, note_id)
        .await?
        .ok_or_else(|| AppError::not_found("Note not found"))?;

    let id = generate_id();
    let now = now_secs();

    fieldwork_db::reactions_db::add_reaction(
        &state.pool, id, crate::db::DEFAULT_USER_ID, auth.account_id,
        Some(note_id), None, &body.reaction, now,
    )
    .await?;

    Ok(Json(json!({})))
}

// ---------------------------------------------------------------------------
// POST /api/notes/reactions/delete
// ---------------------------------------------------------------------------

async fn reactions_delete(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ReactionDeleteRequest>,
) -> Result<Json<Value>, AppError> {
    let auth = misskey_auth(&state.pool, &body.i).await?;
    auth.require_scope("write")?;

    let note_id: i64 = body.note_id.parse()
        .map_err(|_| AppError::bad_request("Invalid noteId"))?;

    // Delete all reactions this persona has on this note
    let my_reactions = fieldwork_db::reactions_db::user_reactions(
        &state.pool, auth.account_id, note_id,
    )
    .await
    .unwrap_or_default();

    for emoji in &my_reactions {
        fieldwork_db::reactions_db::remove_reaction(
            &state.pool, auth.account_id, Some(note_id), None, emoji,
        )
        .await?;
    }

    Ok(Json(json!({})))
}

// ---------------------------------------------------------------------------
// POST /api/users/show
// ---------------------------------------------------------------------------

async fn users_show(
    State(state): State<Arc<AppState>>,
    Json(body): Json<UserShowRequest>,
) -> Result<Json<Value>, AppError> {
    let domain = &state.config.server.domain;

    let persona = if let Some(uid) = &body.user_id {
        let id: i64 = uid.parse().map_err(|_| AppError::bad_request("Invalid userId"))?;
        fieldwork_db::persona_db::get_persona_by_id(&state.pool, id).await?
    } else if let Some(username) = &body.username {
        fieldwork_db::persona_db::get_persona_by_username(&state.pool, username).await?
    } else {
        return Err(AppError::bad_request("userId or username required"));
    };

    let persona = persona.ok_or_else(|| AppError::not_found("User not found"))?;
    Ok(Json(persona_to_misskey_user(&persona, domain)))
}

// ---------------------------------------------------------------------------
// POST /api/i
// ---------------------------------------------------------------------------

async fn api_i(
    State(state): State<Arc<AppState>>,
    Json(body): Json<AuthOnlyRequest>,
) -> Result<Json<Value>, AppError> {
    let auth = misskey_auth(&state.pool, &body.i).await?;
    let domain = &state.config.server.domain;

    let persona = fieldwork_db::persona_db::get_persona_by_id(&state.pool, auth.account_id)
        .await?
        .ok_or_else(|| AppError::not_found("User not found"))?;

    Ok(Json(persona_to_misskey_user(&persona, domain)))
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/notes/create", post(notes_create))
        .route("/api/notes/show", post(notes_show))
        .route("/api/notes/timeline", post(notes_timeline))
        .route("/api/notes/local-timeline", post(notes_local_timeline))
        .route("/api/notes/reactions/create", post(reactions_create))
        .route("/api/notes/reactions/delete", post(reactions_delete))
        .route("/api/users/show", post(users_show))
        .route("/api/i", post(api_i))
}
