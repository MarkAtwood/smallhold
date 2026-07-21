//! Lemmy-compatible API v3 endpoints for smallhold.
//!
//! Full implementation: community CRUD, post/comment creation, voting,
//! and subscription management. Auth uses the same Bearer token as the
//! Mastodon API.

use crate::api::AuthenticatedAccount;
use crate::error::AppError;
use crate::server::AppState;
use axum::extract::{Query, State};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use fieldwork::util::{epoch_to_iso, now_iso};
use serde::Deserialize;
use serde_json::json;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Query / request types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct ListCommunitiesQuery {
    #[serde(default = "default_limit")]
    limit: i64,
}

#[derive(Deserialize)]
struct GetCommunityQuery {
    #[serde(default)]
    id: Option<i64>,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Deserialize)]
struct CreateCommunityRequest {
    name: String,
    title: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    nsfw: bool,
}

#[derive(Deserialize)]
struct FollowCommunityRequest {
    community_id: i64,
    follow: bool,
}

#[derive(Deserialize)]
struct ListPostsQuery {
    #[serde(default)]
    community_id: Option<i64>,
    #[serde(default)]
    community_name: Option<String>,
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default)]
    page: Option<i64>,
    #[serde(default)]
    sort: Option<String>,
}

#[derive(Deserialize)]
struct GetPostQuery {
    id: i64,
}

#[derive(Deserialize)]
struct CreatePostRequest {
    name: String,
    community_id: i64,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    url: Option<String>,
}

#[derive(Deserialize)]
struct PostLikeRequest {
    post_id: i64,
    score: i32,
}

#[derive(Deserialize)]
struct ListCommentsQuery {
    #[serde(default)]
    post_id: Option<i64>,
    #[serde(default)]
    sort: Option<String>,
}

#[derive(Deserialize)]
struct CreateCommentRequest {
    content: String,
    post_id: i64,
    #[serde(default)]
    parent_id: Option<i64>,
}

#[derive(Deserialize)]
struct CommentLikeRequest {
    comment_id: i64,
    score: i32,
}

fn default_limit() -> i64 {
    20
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

// ---------------------------------------------------------------------------
// JSON builders
// ---------------------------------------------------------------------------

fn community_to_json(
    c: &fieldwork_db::communities_db::CommunityRow,
    persona: &fieldwork_db::persona_db::PersonaRow,
    member_count: i64,
    domain: &str,
) -> serde_json::Value {
    json!({
        "community": {
            "id": persona.id,
            "name": persona.username,
            "title": c.title,
            "description": c.description,
            "removed": false,
            "published": epoch_to_iso(c.created_at),
            "deleted": false,
            "nsfw": c.nsfw,
            "actor_id": format!("https://{}/users/{}", domain, persona.username),
            "local": true,
            "icon": null,
            "banner": null,
            "hidden": false,
            "posting_restricted_to_mods": c.posting_restricted,
            "instance_id": 1,
        },
        "subscribed": "NotSubscribed",
        "blocked": false,
        "counts": {
            "id": persona.id,
            "community_id": persona.id,
            "subscribers": member_count,
            "posts": 0,
            "comments": 0,
            "published": epoch_to_iso(c.created_at),
            "users_active_day": 0,
            "users_active_week": 0,
            "users_active_month": 0,
            "users_active_half_year": 0,
        },
    })
}

fn post_to_json(
    p: &fieldwork_db::communities_db::CommunityPostRow,
    author: &fieldwork_db::persona_db::PersonaRow,
    community_persona: &fieldwork_db::persona_db::PersonaRow,
    score: i64,
    domain: &str,
) -> serde_json::Value {
    let upvotes = score.max(0);
    let downvotes = (-score).max(0);
    json!({
        "post": {
            "id": p.id,
            "name": p.title,
            "body": p.body,
            "creator_id": p.author_persona_id,
            "community_id": p.community_id,
            "removed": p.removed,
            "locked": p.locked,
            "published": epoch_to_iso(p.created_at),
            "updated": p.updated_at.map(epoch_to_iso),
            "deleted": false,
            "nsfw": false,
            "ap_id": p.ap_id,
            "local": true,
            "url": p.url,
            "featured_community": p.pinned,
            "featured_local": false,
        },
        "creator": {
            "id": author.id,
            "name": author.username,
            "display_name": author.display_name,
            "actor_id": format!("https://{}/users/{}", domain, author.username),
            "local": true,
            "deleted": false,
            "bot_account": false,
        },
        "community": {
            "id": community_persona.id,
            "name": community_persona.username,
            "title": community_persona.display_name,
            "actor_id": format!("https://{}/users/{}", domain, community_persona.username),
            "local": true,
        },
        "counts": {
            "id": p.id,
            "post_id": p.id,
            "comments": 0,
            "score": score,
            "upvotes": upvotes,
            "downvotes": downvotes,
            "published": epoch_to_iso(p.created_at),
        },
        "subscribed": "NotSubscribed",
        "saved": false,
        "read": false,
        "creator_blocked": false,
        "unread_comments": 0,
    })
}

fn comment_to_json(
    c: &fieldwork_db::communities_db::CommentRow,
    author: &fieldwork_db::persona_db::PersonaRow,
    score: i64,
    domain: &str,
) -> serde_json::Value {
    let upvotes = score.max(0);
    let downvotes = (-score).max(0);
    let path = match c.parent_comment_id {
        Some(pid) => format!("0.{}.{}", pid, c.id),
        None => format!("0.{}", c.id),
    };
    json!({
        "comment": {
            "id": c.id,
            "creator_id": c.author_persona_id,
            "post_id": c.post_id,
            "content": c.content,
            "removed": c.removed,
            "published": epoch_to_iso(c.created_at),
            "updated": c.updated_at.map(epoch_to_iso),
            "deleted": false,
            "ap_id": c.ap_id,
            "local": true,
            "path": path,
            "distinguished": false,
        },
        "creator": {
            "id": author.id,
            "name": author.username,
            "display_name": author.display_name,
            "actor_id": format!("https://{}/users/{}", domain, author.username),
            "local": true,
            "deleted": false,
            "bot_account": false,
        },
        "post": {
            "id": c.post_id,
        },
        "counts": {
            "id": c.id,
            "comment_id": c.id,
            "score": score,
            "upvotes": upvotes,
            "downvotes": downvotes,
            "child_count": 0,
        },
        "subscribed": "NotSubscribed",
        "saved": false,
        "creator_blocked": false,
    })
}

// ---------------------------------------------------------------------------
// GET /api/v3/site
// ---------------------------------------------------------------------------

async fn get_site(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let domain = &state.config.server.domain;
    let personas = fieldwork_db::persona_db::list_personas(&state.pool)
        .await
        .unwrap_or_default();
    let user_count = personas.len() as i64;

    let mut post_count = 0i64;
    for p in &personas {
        post_count += fieldwork_db::posts_db::posts_count(&state.pool, p.id)
            .await
            .unwrap_or(0);
    }

    let community_count = fieldwork_db::communities_db::list_communities(&state.pool, 1000)
        .await
        .map(|v| v.len() as i64)
        .unwrap_or(0);

    Json(json!({
        "site_view": {
            "site": {
                "id": 1,
                "name": format!("Smallhold ({})", domain),
                "description": "Single-user fediverse server",
                "published": now_iso(),
                "updated": null,
                "actor_id": format!("https://{}", domain),
                "instance_id": 1,
            },
            "local_site": {
                "id": 1,
                "site_id": 1,
                "enable_downvotes": true,
                "enable_nsfw": true,
                "community_creation_admin_only": false,
                "require_email_verification": false,
                "registration_mode": "Closed",
                "published": now_iso(),
            },
            "local_site_rate_limit": {
                "id": 1,
                "local_site_id": 1,
            },
            "counts": {
                "id": 1,
                "site_id": 1,
                "users": user_count,
                "posts": post_count,
                "comments": 0,
                "communities": community_count,
                "users_active_day": 0,
                "users_active_week": 0,
                "users_active_month": 0,
                "users_active_half_year": 0,
            },
        },
        "admins": [],
        "version": "0.1.0",
        "all_languages": [],
        "discussion_languages": [],
        "taglines": [],
    }))
}

// ---------------------------------------------------------------------------
// GET /api/v3/community/list
// ---------------------------------------------------------------------------

async fn list_communities(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListCommunitiesQuery>,
) -> impl IntoResponse {
    let limit = query.limit.clamp(1, 50);
    let domain = &state.config.server.domain;

    let communities = fieldwork_db::communities_db::list_communities(&state.pool, limit)
        .await
        .unwrap_or_default();

    let mut views = Vec::with_capacity(communities.len());
    for c in &communities {
        let persona = match fieldwork_db::persona_db::get_persona_by_id(
            &state.pool,
            c.persona_id,
        )
        .await
        {
            Ok(Some(p)) => p,
            _ => continue,
        };
        let members = fieldwork_db::communities_db::member_count(&state.pool, c.persona_id)
            .await
            .unwrap_or(0);
        views.push(community_to_json(c, &persona, members, domain));
    }

    Json(json!({ "communities": views }))
}

// ---------------------------------------------------------------------------
// GET /api/v3/community
// ---------------------------------------------------------------------------

async fn get_community(
    State(state): State<Arc<AppState>>,
    Query(query): Query<GetCommunityQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let domain = &state.config.server.domain;
    let persona_id = if let Some(id) = query.id {
        id
    } else if let Some(ref name) = query.name {
        fieldwork_db::persona_db::get_persona_by_username(&state.pool, name)
            .await
            .map_err(AppError::from)?
            .ok_or_else(|| AppError::not_found("Community not found"))?
            .id
    } else {
        return Err(AppError::bad_request("id or name required"));
    };

    let c = fieldwork_db::communities_db::get_community(&state.pool, persona_id)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("Community not found"))?;

    let persona = fieldwork_db::persona_db::get_persona_by_id(&state.pool, persona_id)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("Community not found"))?;

    let members = fieldwork_db::communities_db::member_count(&state.pool, persona_id)
        .await
        .unwrap_or(0);

    Ok(Json(json!({
        "community_view": community_to_json(&c, &persona, members, domain),
    })))
}

// ---------------------------------------------------------------------------
// POST /api/v3/community
// ---------------------------------------------------------------------------

async fn create_community(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Json(body): Json<CreateCommunityRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_scope("write")?;

    let domain = &state.config.server.domain;
    let now = now_secs();
    let persona_id = fieldwork::id::generate_id();

    // Create a persona to back the community Group actor
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
    use rsa::RsaPrivateKey;

    let private_key = RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048)
        .map_err(|e| AppError::bad_request(format!("key generation failed: {e}")))?;
    let private_key_pem = private_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| AppError::bad_request(format!("key encode failed: {e}")))?;
    let public_key_pem = private_key
        .to_public_key()
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| AppError::bad_request(format!("key encode failed: {e}")))?;

    crate::db_extras::create_persona(
        &state.pool,
        persona_id,
        crate::db::DEFAULT_USER_ID,
        &body.name,
        &body.title,
        private_key_pem.as_str(),
        &public_key_pem,
        false,
        false,
        now,
    )
    .await
    .map_err(AppError::from)?;

    let community = fieldwork_db::communities_db::CommunityRow {
        persona_id,
        title: body.title.clone(),
        sidebar_html: String::new(),
        description: body.description.unwrap_or_default(),
        nsfw: body.nsfw,
        posting_restricted: false,
        created_at: now,
    };

    fieldwork_db::communities_db::create_community(&state.pool, &community)
        .await
        .map_err(AppError::from)?;

    // Auto-join the creator as admin
    fieldwork_db::communities_db::join_community(
        &state.pool,
        persona_id,
        crate::db::DEFAULT_USER_ID,
        auth.account_id,
        now,
    )
    .await
    .map_err(AppError::from)?;
    fieldwork_db::communities_db::set_role(&state.pool, persona_id, auth.account_id, "admin")
        .await
        .map_err(AppError::from)?;

    let persona = fieldwork_db::persona_db::get_persona_by_id(&state.pool, persona_id)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("Community not found"))?;

    Ok(Json(json!({
        "community_view": community_to_json(&community, &persona, 1, domain),
    })))
}

// ---------------------------------------------------------------------------
// POST /api/v3/community/follow
// ---------------------------------------------------------------------------

async fn follow_community(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Json(body): Json<FollowCommunityRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_scope("write")?;

    let domain = &state.config.server.domain;
    let now = now_secs();

    if body.follow {
        fieldwork_db::communities_db::join_community(
            &state.pool,
            body.community_id,
            crate::db::DEFAULT_USER_ID,
            auth.account_id,
            now,
        )
        .await
        .map_err(AppError::from)?;
    } else {
        fieldwork_db::communities_db::leave_community(
            &state.pool,
            body.community_id,
            auth.account_id,
        )
        .await
        .map_err(AppError::from)?;
    }

    let c = fieldwork_db::communities_db::get_community(&state.pool, body.community_id)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("Community not found"))?;

    let persona =
        fieldwork_db::persona_db::get_persona_by_id(&state.pool, body.community_id)
            .await
            .map_err(AppError::from)?
            .ok_or_else(|| AppError::not_found("Community not found"))?;

    let members = fieldwork_db::communities_db::member_count(&state.pool, body.community_id)
        .await
        .unwrap_or(0);

    Ok(Json(json!({
        "community_view": community_to_json(&c, &persona, members, domain),
    })))
}

// ---------------------------------------------------------------------------
// GET /api/v3/post/list
// ---------------------------------------------------------------------------

async fn list_posts(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListPostsQuery>,
) -> impl IntoResponse {
    let limit = query.limit.clamp(1, 50);
    let page = query.page.unwrap_or(1).max(1);
    let offset = (page - 1) * limit;
    let sort = query.sort.as_deref().unwrap_or("new");
    let domain = &state.config.server.domain;

    let community_id = if let Some(id) = query.community_id {
        Some(id)
    } else if let Some(ref name) = query.community_name {
        fieldwork_db::persona_db::get_persona_by_username(&state.pool, name)
            .await
            .ok()
            .flatten()
            .map(|p| p.id)
    } else {
        None
    };

    let community_id = match community_id {
        Some(id) => id,
        None => return Json(json!({ "posts": [] })).into_response(),
    };

    let posts = fieldwork_db::communities_db::list_posts(
        &state.pool,
        community_id,
        sort,
        limit,
        offset,
    )
    .await
    .unwrap_or_default();

    let community_persona =
        match fieldwork_db::persona_db::get_persona_by_id(&state.pool, community_id).await {
            Ok(Some(p)) => p,
            _ => return Json(json!({ "posts": [] })).into_response(),
        };

    let mut views = Vec::with_capacity(posts.len());
    for p in &posts {
        let author = match fieldwork_db::persona_db::get_persona_by_id(
            &state.pool,
            p.author_persona_id,
        )
        .await
        {
            Ok(Some(a)) => a,
            _ => continue,
        };
        let score = fieldwork_db::communities_db::post_score(&state.pool, p.id)
            .await
            .unwrap_or(0);
        views.push(post_to_json(p, &author, &community_persona, score, domain));
    }

    Json(json!({ "posts": views })).into_response()
}

// ---------------------------------------------------------------------------
// GET /api/v3/post
// ---------------------------------------------------------------------------

async fn get_post(
    State(state): State<Arc<AppState>>,
    Query(query): Query<GetPostQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let domain = &state.config.server.domain;

    let p = fieldwork_db::communities_db::get_post(&state.pool, query.id)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("Post not found"))?;

    let author = fieldwork_db::persona_db::get_persona_by_id(&state.pool, p.author_persona_id)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("Author not found"))?;

    let community_persona =
        fieldwork_db::persona_db::get_persona_by_id(&state.pool, p.community_id)
            .await
            .map_err(AppError::from)?
            .ok_or_else(|| AppError::not_found("Community not found"))?;

    let score = fieldwork_db::communities_db::post_score(&state.pool, p.id)
        .await
        .unwrap_or(0);

    let comments = fieldwork_db::communities_db::get_comments(&state.pool, query.id, "new")
        .await
        .unwrap_or_default();

    let mut comment_views = Vec::with_capacity(comments.len());
    for c in &comments {
        let c_author = match fieldwork_db::persona_db::get_persona_by_id(
            &state.pool,
            c.author_persona_id,
        )
        .await
        {
            Ok(Some(a)) => a,
            _ => continue,
        };
        let c_score = fieldwork_db::communities_db::comment_score(&state.pool, c.id)
            .await
            .unwrap_or(0);
        comment_views.push(comment_to_json(c, &c_author, c_score, domain));
    }

    Ok(Json(json!({
        "post_view": post_to_json(&p, &author, &community_persona, score, domain),
        "comments": comment_views,
    })))
}

// ---------------------------------------------------------------------------
// POST /api/v3/post
// ---------------------------------------------------------------------------

async fn create_post(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Json(body): Json<CreatePostRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_scope("write")?;

    let domain = &state.config.server.domain;
    let now = now_secs();
    let id = fieldwork::id::generate_id();
    let ap_id = format!("https://{}/post/{}", domain, id);

    let post_row = fieldwork_db::communities_db::CommunityPostRow {
        id,
        community_id: body.community_id,
        author_persona_id: auth.account_id,
        author_user_id: crate::db::DEFAULT_USER_ID,
        title: body.name,
        body: body.body.clone(),
        body_html: body.body.map(|b| format!("<p>{}</p>", ammonia::clean(&b))),
        url: body.url,
        ap_id,
        locked: false,
        pinned: false,
        removed: false,
        created_at: now,
        updated_at: None,
    };

    fieldwork_db::communities_db::create_post(&state.pool, &post_row)
        .await
        .map_err(AppError::from)?;

    // Auto-upvote by creator
    let _ = fieldwork_db::communities_db::vote_post(
        &state.pool,
        crate::db::DEFAULT_USER_ID,
        auth.account_id,
        id,
        1,
        now,
    )
    .await;

    let author =
        fieldwork_db::persona_db::get_persona_by_id(&state.pool, auth.account_id)
            .await
            .map_err(AppError::from)?
            .ok_or_else(|| AppError::not_found("Account not found"))?;

    let community_persona =
        fieldwork_db::persona_db::get_persona_by_id(&state.pool, body.community_id)
            .await
            .map_err(AppError::from)?
            .ok_or_else(|| AppError::not_found("Community not found"))?;

    Ok(Json(json!({
        "post_view": post_to_json(&post_row, &author, &community_persona, 1, domain),
    })))
}

// ---------------------------------------------------------------------------
// POST /api/v3/post/like
// ---------------------------------------------------------------------------

async fn like_post(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Json(body): Json<PostLikeRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_scope("write")?;

    let domain = &state.config.server.domain;
    let now = now_secs();
    let score = body.score.clamp(-1, 1);

    fieldwork_db::communities_db::vote_post(
        &state.pool,
        crate::db::DEFAULT_USER_ID,
        auth.account_id,
        body.post_id,
        score,
        now,
    )
    .await
    .map_err(AppError::from)?;

    let p = fieldwork_db::communities_db::get_post(&state.pool, body.post_id)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("Post not found"))?;

    let author =
        fieldwork_db::persona_db::get_persona_by_id(&state.pool, p.author_persona_id)
            .await
            .map_err(AppError::from)?
            .ok_or_else(|| AppError::not_found("Author not found"))?;

    let community_persona =
        fieldwork_db::persona_db::get_persona_by_id(&state.pool, p.community_id)
            .await
            .map_err(AppError::from)?
            .ok_or_else(|| AppError::not_found("Community not found"))?;

    let total_score = fieldwork_db::communities_db::post_score(&state.pool, body.post_id)
        .await
        .unwrap_or(0);

    Ok(Json(json!({
        "post_view": post_to_json(&p, &author, &community_persona, total_score, domain),
    })))
}

// ---------------------------------------------------------------------------
// GET /api/v3/comment/list
// ---------------------------------------------------------------------------

async fn list_comments(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListCommentsQuery>,
) -> impl IntoResponse {
    let sort = query.sort.as_deref().unwrap_or("new");
    let domain = &state.config.server.domain;

    let comments = if let Some(post_id) = query.post_id {
        fieldwork_db::communities_db::get_comments(&state.pool, post_id, sort)
            .await
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    let mut views = Vec::with_capacity(comments.len());
    for c in &comments {
        let author = match fieldwork_db::persona_db::get_persona_by_id(
            &state.pool,
            c.author_persona_id,
        )
        .await
        {
            Ok(Some(a)) => a,
            _ => continue,
        };
        let score = fieldwork_db::communities_db::comment_score(&state.pool, c.id)
            .await
            .unwrap_or(0);
        views.push(comment_to_json(c, &author, score, domain));
    }

    Json(json!({ "comments": views }))
}

// ---------------------------------------------------------------------------
// POST /api/v3/comment
// ---------------------------------------------------------------------------

async fn create_comment(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Json(body): Json<CreateCommentRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_scope("write")?;

    let domain = &state.config.server.domain;
    let now = now_secs();
    let id = fieldwork::id::generate_id();
    let ap_id = format!("https://{}/comment/{}", domain, id);

    let comment = fieldwork_db::communities_db::CommentRow {
        id,
        post_id: body.post_id,
        parent_comment_id: body.parent_id,
        author_persona_id: auth.account_id,
        author_user_id: crate::db::DEFAULT_USER_ID,
        content: body.content.clone(),
        content_html: format!("<p>{}</p>", ammonia::clean(&body.content)),
        ap_id,
        removed: false,
        created_at: now,
        updated_at: None,
    };

    fieldwork_db::communities_db::create_comment(&state.pool, &comment)
        .await
        .map_err(AppError::from)?;

    // Auto-upvote by creator
    let _ = fieldwork_db::communities_db::vote_comment(
        &state.pool,
        crate::db::DEFAULT_USER_ID,
        auth.account_id,
        id,
        1,
        now,
    )
    .await;

    let author =
        fieldwork_db::persona_db::get_persona_by_id(&state.pool, auth.account_id)
            .await
            .map_err(AppError::from)?
            .ok_or_else(|| AppError::not_found("Account not found"))?;

    Ok(Json(json!({
        "comment_view": comment_to_json(&comment, &author, 1, domain),
    })))
}

// ---------------------------------------------------------------------------
// POST /api/v3/comment/like
// ---------------------------------------------------------------------------

async fn like_comment(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Json(body): Json<CommentLikeRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_scope("write")?;

    let domain = &state.config.server.domain;
    let now = now_secs();
    let score = body.score.clamp(-1, 1);

    fieldwork_db::communities_db::vote_comment(
        &state.pool,
        crate::db::DEFAULT_USER_ID,
        auth.account_id,
        body.comment_id,
        score,
        now,
    )
    .await
    .map_err(AppError::from)?;

    let c = fieldwork_db::communities_db::get_comment(&state.pool, body.comment_id)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("Comment not found"))?;

    let author =
        fieldwork_db::persona_db::get_persona_by_id(&state.pool, c.author_persona_id)
            .await
            .map_err(AppError::from)?
            .ok_or_else(|| AppError::not_found("Author not found"))?;

    let total_score = fieldwork_db::communities_db::comment_score(&state.pool, body.comment_id)
        .await
        .unwrap_or(0);

    Ok(Json(json!({
        "comment_view": comment_to_json(&c, &author, total_score, domain),
    })))
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v3/site", get(get_site))
        .route("/api/v3/community/list", get(list_communities))
        .route(
            "/api/v3/community",
            get(get_community).post(create_community),
        )
        .route("/api/v3/community/follow", post(follow_community))
        .route("/api/v3/post/list", get(list_posts))
        .route("/api/v3/post", get(get_post).post(create_post))
        .route("/api/v3/post/like", post(like_post))
        .route("/api/v3/comment/list", get(list_comments))
        .route("/api/v3/comment", post(create_comment))
        .route("/api/v3/comment/like", post(like_comment))
}
