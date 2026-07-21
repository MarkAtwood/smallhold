//! WriteFreely-compatible API endpoints for smallhold.

use crate::api::AuthenticatedAccount;
use crate::error::AppError;
use crate::server::AppState;
use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use fieldwork::util::{now_secs, render_markdown_simple, slugify};
use fieldwork::writefreely_api::*;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// POST /api/posts — create post
// ---------------------------------------------------------------------------

async fn create_post(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Json(body): Json<CreatePostRequest>,
) -> Result<Json<WfResponse<PostResponse>>, AppError> {
    auth.require_scope("write")?;
    let now = now_secs();
    let id = fieldwork::id::generate_id();
    let domain = &state.config.server.domain;

    let (user_id, persona_id) = (crate::db::DEFAULT_USER_ID, auth.account_id);
    let edit_token: Option<String> = None;

    let title = body.title.unwrap_or_default();
    let slug = body.slug.or_else(|| {
        let s = slugify(&title);
        if s.is_empty() { None } else { Some(s) }
    });

    let body_html = render_markdown_simple(&body.body);

    let article = fieldwork_db::articles_db::ArticleRow {
        id,
        user_id,
        persona_id,
        collection_alias: None,
        slug,
        title,
        body: body.body,
        body_html,
        font: body.font.unwrap_or_else(|| "norm".into()),
        language: body.lang,
        rtl: body.rtl.unwrap_or(false),
        pinned: false,
        pin_position: None,
        draft: false,
        ap_id: format!("https://{}/articles/{}", domain, id),
        edit_token,
        views: 0,
        created_at: now,
        updated_at: None,
    };

    fieldwork_db::articles_db::create_article(&state.pool, &article)
        .await
        .map_err(AppError::from)?;

    Ok(Json(WfResponse {
        code: 201,
        data: article.to_api_response(true),
    }))
}

// ---------------------------------------------------------------------------
// GET /api/posts/{id}
// ---------------------------------------------------------------------------

async fn get_post(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<Json<WfResponse<PostResponse>>, AppError> {
    let article = fieldwork_db::articles_db::get_article(&state.pool, id)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("Post not found"))?;

    fieldwork_db::articles_db::increment_views(&state.pool, id).await.ok();

    Ok(Json(WfResponse {
        code: 200,
        data: article.to_api_response(false),
    }))
}

// ---------------------------------------------------------------------------
// POST /api/posts/{id} — update post
// ---------------------------------------------------------------------------

async fn update_post(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Json(body): Json<UpdatePostRequest>,
) -> Result<Json<WfResponse<PostResponse>>, AppError> {
    let article = fieldwork_db::articles_db::get_article(&state.pool, id)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("Post not found"))?;

    // Auth: either edit token or logged-in owner
    if let Some(ref token) = body.token {
        if article.edit_token.as_deref() != Some(token) {
            return Err(AppError::unauthorized("Invalid edit token"));
        }
    }

    let body_html = body.body.as_deref().map(render_markdown_simple);
    let now = now_secs();

    fieldwork_db::articles_db::update_article(
        &state.pool,
        id,
        body.body.as_deref(),
        body_html.as_deref(),
        body.title.as_deref(),
        body.font.as_deref(),
        body.lang.as_deref(),
        body.rtl,
        now,
    )
    .await
    .map_err(AppError::from)?;

    let updated = fieldwork_db::articles_db::get_article(&state.pool, id)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("Post not found"))?;

    Ok(Json(WfResponse {
        code: 200,
        data: updated.to_api_response(false),
    }))
}

// ---------------------------------------------------------------------------
// DELETE /api/posts/{id}
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct DeleteQuery {
    #[serde(default)]
    token: Option<String>,
}

async fn delete_post(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Query(query): Query<DeleteQuery>,
) -> Result<axum::http::StatusCode, AppError> {
    let article = fieldwork_db::articles_db::get_article(&state.pool, id)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("Post not found"))?;

    if let Some(ref et) = article.edit_token {
        if query.token.as_deref() != Some(et) {
            return Err(AppError::unauthorized("Invalid edit token"));
        }
    }

    fieldwork_db::articles_db::delete_article(&state.pool, id)
        .await
        .map_err(AppError::from)?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// POST /api/collections — create collection
// ---------------------------------------------------------------------------

async fn create_collection(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Json(body): Json<CreateCollectionRequest>,
) -> Result<Json<WfResponse<CollectionResponse>>, AppError> {
    auth.require_scope("write")?;
    let now = now_secs();
    let col = fieldwork_db::articles_db::CollectionRow {
        alias: body.alias,
        user_id: crate::db::DEFAULT_USER_ID,
        persona_id: auth.account_id,
        title: body.title.unwrap_or_default(),
        description: String::new(),
        style_sheet: String::new(),
        visibility: "public".into(),
        created_at: now,
    };
    fieldwork_db::articles_db::create_collection(&state.pool, &col)
        .await
        .map_err(AppError::from)?;
    Ok(Json(WfResponse {
        code: 201,
        data: col.to_api_response(),
    }))
}

// ---------------------------------------------------------------------------
// GET /api/collections/{alias}
// ---------------------------------------------------------------------------

async fn get_collection(
    State(state): State<Arc<AppState>>,
    Path(alias): Path<String>,
) -> Result<Json<WfResponse<CollectionResponse>>, AppError> {
    let col = fieldwork_db::articles_db::get_collection(&state.pool, &alias)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("Collection not found"))?;
    Ok(Json(WfResponse {
        code: 200,
        data: col.to_api_response(),
    }))
}

// ---------------------------------------------------------------------------
// POST /api/collections/{alias} — update collection
// ---------------------------------------------------------------------------

async fn update_collection(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(alias): Path<String>,
    Json(body): Json<UpdateCollectionRequest>,
) -> Result<Json<WfResponse<CollectionResponse>>, AppError> {
    auth.require_scope("write")?;
    fieldwork_db::articles_db::update_collection(
        &state.pool,
        &alias,
        body.title.as_deref(),
        body.description.as_deref(),
        body.style_sheet.as_deref(),
        body.visibility.as_deref(),
    )
    .await
    .map_err(AppError::from)?;
    let col = fieldwork_db::articles_db::get_collection(&state.pool, &alias)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("Collection not found"))?;
    Ok(Json(WfResponse {
        code: 200,
        data: col.to_api_response(),
    }))
}

// ---------------------------------------------------------------------------
// DELETE /api/collections/{alias}
// ---------------------------------------------------------------------------

async fn delete_collection(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(alias): Path<String>,
) -> Result<axum::http::StatusCode, AppError> {
    auth.require_scope("write")?;
    fieldwork_db::articles_db::delete_collection(&state.pool, &alias)
        .await
        .map_err(AppError::from)?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// GET /api/collections/{alias}/posts
// ---------------------------------------------------------------------------

async fn collection_posts(
    State(state): State<Arc<AppState>>,
    Path(alias): Path<String>,
    Query(query): Query<CollectionPostsQuery>,
) -> Result<Json<WfResponse<Vec<PostResponse>>>, AppError> {
    let page = query.page.max(1);
    let per_page = 20i64;
    let offset = ((page - 1) as i64) * per_page;
    let articles = fieldwork_db::articles_db::list_collection_articles(
        &state.pool, &alias, per_page, offset,
    )
    .await
    .map_err(AppError::from)?;
    let posts: Vec<_> = articles.iter().map(|a| a.to_api_response(false)).collect();
    Ok(Json(WfResponse { code: 200, data: posts }))
}

// ---------------------------------------------------------------------------
// POST /api/collections/{alias}/posts — create post in collection
// ---------------------------------------------------------------------------

async fn create_collection_post(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(alias): Path<String>,
    Json(body): Json<CreatePostRequest>,
) -> Result<Json<WfResponse<PostResponse>>, AppError> {
    auth.require_scope("write")?;
    let now = now_secs();
    let id = fieldwork::id::generate_id();
    let domain = &state.config.server.domain;

    let title = body.title.unwrap_or_default();
    let slug = body.slug.or_else(|| {
        let s = slugify(&title);
        if s.is_empty() { None } else { Some(s) }
    });

    let body_html = render_markdown_simple(&body.body);

    let article = fieldwork_db::articles_db::ArticleRow {
        id,
        user_id: crate::db::DEFAULT_USER_ID,
        persona_id: auth.account_id,
        collection_alias: Some(alias),
        slug,
        title,
        body: body.body,
        body_html,
        font: body.font.unwrap_or_else(|| "norm".into()),
        language: body.lang,
        rtl: body.rtl.unwrap_or(false),
        pinned: false,
        pin_position: None,
        draft: false,
        ap_id: format!("https://{}/articles/{}", domain, id),
        edit_token: None,
        views: 0,
        created_at: now,
        updated_at: None,
    };

    fieldwork_db::articles_db::create_article(&state.pool, &article)
        .await
        .map_err(AppError::from)?;

    Ok(Json(WfResponse {
        code: 201,
        data: article.to_api_response(false),
    }))
}

// ---------------------------------------------------------------------------
// GET /api/collections/{alias}/posts/{slug}
// ---------------------------------------------------------------------------

async fn get_collection_post(
    State(state): State<Arc<AppState>>,
    Path((alias, slug)): Path<(String, String)>,
) -> Result<Json<WfResponse<PostResponse>>, AppError> {
    let article = fieldwork_db::articles_db::get_article_by_slug(&state.pool, &alias, &slug)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("Post not found"))?;

    fieldwork_db::articles_db::increment_views(&state.pool, article.id).await.ok();

    Ok(Json(WfResponse {
        code: 200,
        data: article.to_api_response(false),
    }))
}

// ---------------------------------------------------------------------------
// GET /api/me
// ---------------------------------------------------------------------------

async fn me(auth: AuthenticatedAccount) -> Json<WfResponse<UserResponse>> {
    Json(WfResponse {
        code: 200,
        data: UserResponse {
            username: auth.username,
        },
    })
}

// ---------------------------------------------------------------------------
// GET /api/me/posts
// ---------------------------------------------------------------------------

async fn me_posts(
    State(state): State<Arc<AppState>>,
    _auth: AuthenticatedAccount,
) -> Json<WfResponse<Vec<PostResponse>>> {
    let articles = fieldwork_db::articles_db::list_user_articles(
        &state.pool, crate::db::DEFAULT_USER_ID, 50, 0,
    )
    .await
    .unwrap_or_default();
    let posts: Vec<_> = articles.iter().map(|a| a.to_api_response(false)).collect();
    Json(WfResponse { code: 200, data: posts })
}

// ---------------------------------------------------------------------------
// GET /api/me/collections
// ---------------------------------------------------------------------------

async fn me_collections(
    State(state): State<Arc<AppState>>,
    _auth: AuthenticatedAccount,
) -> Json<WfResponse<Vec<CollectionResponse>>> {
    let cols = fieldwork_db::articles_db::list_user_collections(
        &state.pool, crate::db::DEFAULT_USER_ID,
    )
    .await
    .unwrap_or_default();
    let data: Vec<_> = cols.iter().map(|c| c.to_api_response()).collect();
    Json(WfResponse { code: 200, data })
}

// ---------------------------------------------------------------------------
// POST /api/markdown
// ---------------------------------------------------------------------------

async fn render_md(
    Json(body): Json<MarkdownRequest>,
) -> Json<WfResponse<MarkdownResponse>> {
    let html = render_markdown_simple(&body.raw_body);
    Json(WfResponse {
        code: 200,
        data: MarkdownResponse { body: html },
    })
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(POSTS_PATH, post(create_post))
        .route(POST_PATH, get(get_post).post(update_post).delete(delete_post))
        .route(COLLECTIONS_PATH, post(create_collection))
        .route(
            COLLECTION_PATH,
            get(get_collection).post(update_collection).delete(delete_collection),
        )
        .route(
            COLLECTION_POSTS_PATH,
            get(collection_posts).post(create_collection_post),
        )
        .route(COLLECTION_POST_PATH, get(get_collection_post))
        .route(ME_PATH, get(me))
        .route(ME_POSTS_PATH, get(me_posts))
        .route(ME_COLLECTIONS_PATH, get(me_collections))
        .route(MARKDOWN_PATH, post(render_md))
}
