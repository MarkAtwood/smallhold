//! WriteFreely-compatible API endpoints for smallhold.

use crate::api::AuthenticatedAccount;
use crate::error::AppError;
use crate::server::AppState;
use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use fieldwork::writefreely_api::*;
use std::sync::Arc;

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn epoch_to_iso(epoch: i64) -> String {
    chrono::DateTime::from_timestamp(epoch, 0)
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_default()
}

fn article_to_post_response(
    a: &fieldwork_db::articles_db::ArticleRow,
    include_token: bool,
) -> PostResponse {
    let collection = a.collection_alias.as_ref().map(|alias| CollectionRef {
        alias: alias.clone(),
        title: String::new(),
    });
    PostResponse {
        id: a.id.to_string(),
        slug: a.slug.clone(),
        token: if include_token { a.edit_token.clone() } else { None },
        title: a.title.clone(),
        body: a.body.clone(),
        font: Some(a.font.clone()),
        lang: a.language.clone(),
        rtl: if a.rtl { Some(true) } else { None },
        created: epoch_to_iso(a.created_at),
        updated: a.updated_at.map(epoch_to_iso),
        views: a.views,
        collection,
    }
}

fn collection_to_response(c: &fieldwork_db::articles_db::CollectionRow) -> CollectionResponse {
    CollectionResponse {
        alias: c.alias.clone(),
        title: c.title.clone(),
        description: c.description.clone(),
        style_sheet: if c.style_sheet.is_empty() { None } else { Some(c.style_sheet.clone()) },
        public: c.visibility == "public",
    }
}

fn render_markdown(md: &str) -> String {
    // ponytail: basic markdown→HTML. pulldown-cmark would be better but
    // ammonia::clean is already a dep. Paragraph wrapping is good enough.
    let cleaned = ammonia::clean(md);
    format!("<p>{}</p>", cleaned.replace("\n\n", "</p><p>").replace('\n', "<br>"))
}

fn slugify(title: &str) -> String {
    title
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

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

    let body_html = render_markdown(&body.body);

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
        data: article_to_post_response(&article, true),
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
        data: article_to_post_response(&article, false),
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

    let body_html = body.body.as_deref().map(render_markdown);
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
        data: article_to_post_response(&updated, false),
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
        data: collection_to_response(&col),
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
        data: collection_to_response(&col),
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
        data: collection_to_response(&col),
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
    let posts: Vec<_> = articles.iter().map(|a| article_to_post_response(a, false)).collect();
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

    let body_html = render_markdown(&body.body);

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
        data: article_to_post_response(&article, false),
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
        data: article_to_post_response(&article, false),
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
    let posts: Vec<_> = articles.iter().map(|a| article_to_post_response(a, false)).collect();
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
    let data: Vec<_> = cols.iter().map(collection_to_response).collect();
    Json(WfResponse { code: 200, data })
}

// ---------------------------------------------------------------------------
// POST /api/markdown
// ---------------------------------------------------------------------------

async fn render_md(
    Json(body): Json<MarkdownRequest>,
) -> Json<WfResponse<MarkdownResponse>> {
    let html = render_markdown(&body.raw_body);
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
