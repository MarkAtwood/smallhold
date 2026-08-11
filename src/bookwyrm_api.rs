//! Bookwyrm-compatible API endpoints for smallhold.

use crate::api::AuthenticatedAccount;
use crate::error::AppError;
use crate::server::AppState;
use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use fieldwork::bookwyrm_api::*;
use fieldwork::util::now_secs;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// GET /api/v1/books — search books
// ---------------------------------------------------------------------------

async fn search_books(
    State(state): State<Arc<AppState>>,
    Query(params): Query<BookSearchParams>,
) -> Json<Vec<BookResponse>> {
    let limit = params.limit.clamp(1, 100);
    let books = if params.q.is_empty() {
        fieldwork_db::catalog_db::search_media(&state.pool, "", Some("book"), limit)
            .await
            .unwrap_or_default()
    } else {
        fieldwork_db::catalog_db::search_media(&state.pool, &params.q, Some("book"), limit)
            .await
            .unwrap_or_default()
    };
    Json(books.iter().map(|b| b.into()).collect())
}

// ---------------------------------------------------------------------------
// GET /api/v1/books/{id}
// ---------------------------------------------------------------------------

async fn get_book(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<Json<BookResponse>, AppError> {
    let book = fieldwork_db::catalog_db::get_media(&state.pool, id)
        .await
        .map_err(AppError::from)?
        .ok_or_else(|| AppError::not_found("Book not found"))?;
    Ok(Json(BookResponse::from(&book)))
}

// ---------------------------------------------------------------------------
// POST /api/v1/books — add book
// ---------------------------------------------------------------------------

async fn create_book(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Json(body): Json<CreateBookRequest>,
) -> Result<Json<BookResponse>, AppError> {
    auth.require_scope("write")?;
    let now = now_secs();
    let id = fieldwork::id::generate_id();
    let item = fieldwork_db::catalog_db::MediaItem {
        id,
        media_type: "book".into(),
        format: None,
        title: body.title,
        creator: body.author,
        description: body.description,
        cover_url: body.cover_url,
        language: body.language,
        pages: body.pages,
        runtime_min: None,
        issue: None,
        season: None,
        episode: None,
        tracks: None,
        publisher: None,
        label: None,
        published_year: body.published_year,
        release_date: None,
        source: None,
        created_at: now,
    };
    fieldwork_db::catalog_db::create_media(&state.pool, &item)
        .await
        .map_err(AppError::from)?;
    if let Some(ref isbn) = body.isbn {
        fieldwork_db::catalog_db::add_identifier(&state.pool, id, "isbn", isbn)
            .await
            .ok();
    }
    if let Some(ref isbn13) = body.isbn13 {
        fieldwork_db::catalog_db::add_identifier(&state.pool, id, "isbn13", isbn13)
            .await
            .ok();
    }
    if let Some(ref ol_id) = body.openlibrary_id {
        fieldwork_db::catalog_db::add_identifier(&state.pool, id, "openlibrary", ol_id)
            .await
            .ok();
    }
    Ok(Json(BookResponse::from(&item)))
}

// ---------------------------------------------------------------------------
// GET /api/v1/shelves — shelf summary
// ---------------------------------------------------------------------------

async fn shelves_summary(State(state): State<Arc<AppState>>) -> Json<ShelfSummaryResponse> {
    let (to_read, reading, read) =
        fieldwork_db::catalog_db::shelf_stats(&state.pool, crate::db::DEFAULT_USER_ID)
            .await
            .unwrap_or((0, 0, 0));
    Json(ShelfSummaryResponse {
        to_read,
        reading,
        read,
    })
}

// ---------------------------------------------------------------------------
// GET /api/v1/shelves/{status}
// ---------------------------------------------------------------------------

async fn shelf_by_status(
    State(state): State<Arc<AppState>>,
    Path(status): Path<String>,
) -> Json<Vec<ShelfBookResponse>> {
    let books =
        fieldwork_db::catalog_db::user_shelf(&state.pool, crate::db::DEFAULT_USER_ID, &status, 100)
            .await
            .unwrap_or_default();
    Json(
        books
            .iter()
            .map(
                |(book_id, title, author, cover_url, rating)| ShelfBookResponse {
                    book_id: *book_id,
                    title: title.clone(),
                    author: author.clone(),
                    cover_url: cover_url.clone(),
                    rating: *rating,
                },
            )
            .collect(),
    )
}

// ---------------------------------------------------------------------------
// POST /api/v1/shelves — set reading status
// ---------------------------------------------------------------------------

async fn set_status(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Json(body): Json<SetReadingStatusRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_scope("write")?;
    let now = now_secs();
    fieldwork_db::catalog_db::set_shelf_status(
        &state.pool,
        crate::db::DEFAULT_USER_ID,
        body.book_id,
        &body.status,
        now,
    )
    .await
    .map_err(AppError::from)?;
    Ok(Json(
        serde_json::json!({ "status": body.status, "book_id": body.book_id }),
    ))
}

// ---------------------------------------------------------------------------
// POST /api/v1/books/{id}/rate
// ---------------------------------------------------------------------------

async fn rate_book(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(id): Path<i64>,
    Json(body): Json<RateBookRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    auth.require_scope("write")?;
    let rating = body.rating.clamp(1, 5);
    let now = now_secs();
    fieldwork_db::catalog_db::rate_media(&state.pool, crate::db::DEFAULT_USER_ID, id, rating, now)
        .await
        .map_err(AppError::from)?;
    Ok(Json(serde_json::json!({ "book_id": id, "rating": rating })))
}

// ---------------------------------------------------------------------------
// GET /api/v1/books/{id}/reviews
// ---------------------------------------------------------------------------

async fn book_reviews(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Json<Vec<ReviewResponse>> {
    let reviews = fieldwork_db::catalog_db::reviews_for_media(&state.pool, id, 50)
        .await
        .unwrap_or_default();
    Json(reviews.iter().map(|r| r.into()).collect())
}

// ---------------------------------------------------------------------------
// POST /api/v1/books/{id}/reviews — write review
// ---------------------------------------------------------------------------

async fn create_review(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(book_id): Path<i64>,
    Json(body): Json<CreateReviewRequest>,
) -> Result<Json<ReviewResponse>, AppError> {
    auth.require_scope("write")?;
    let now = now_secs();
    let id = fieldwork::id::generate_id();
    let domain = &state.config.server.domain;
    let review = fieldwork_db::catalog_db::MediaReview {
        id,
        user_id: crate::db::DEFAULT_USER_ID,
        persona_id: auth.account_id,
        media_id: book_id,
        content: body.content.clone(),
        content_html: format!("<p>{}</p>", ammonia::clean(&body.content)),
        rating: body.rating,
        spoiler: body.spoiler,
        ap_id: format!("https://{}/reviews/{}", domain, id),
        created_at: now,
    };
    fieldwork_db::catalog_db::create_review(&state.pool, &review)
        .await
        .map_err(AppError::from)?;
    Ok(Json(ReviewResponse::from(&review)))
}

// ---------------------------------------------------------------------------
// GET /api/v1/users/{id}/reading
// ---------------------------------------------------------------------------

async fn user_reading(
    State(state): State<Arc<AppState>>,
    Path(_id): Path<i64>,
) -> Json<UserReadingResponse> {
    let user_id = crate::db::DEFAULT_USER_ID;
    let (to_read, reading, read) = fieldwork_db::catalog_db::shelf_stats(&state.pool, user_id)
        .await
        .unwrap_or((0, 0, 0));
    let reviews = fieldwork_db::catalog_db::reviews_by_user(&state.pool, user_id, 10)
        .await
        .unwrap_or_default();
    Json(UserReadingResponse {
        shelves: ShelfSummaryResponse {
            to_read,
            reading,
            read,
        },
        recent_reviews: reviews.iter().map(|r| r.into()).collect(),
    })
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(BOOKS_PATH, get(search_books).post(create_book))
        .route(BOOK_PATH, get(get_book))
        .route(SHELVES_PATH, get(shelves_summary).post(set_status))
        .route(SHELF_STATUS_PATH, get(shelf_by_status))
        .route(BOOK_RATE_PATH, post(rate_book))
        .route(BOOK_REVIEWS_PATH, get(book_reviews).post(create_review))
        .route(USER_READING_PATH, get(user_reading))
}
