use crate::config::Config;
use axum::{routing::get, Json, Router};
use sqlx::SqlitePool;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};

pub struct AppState {
    pub config: Config,
    pub pool: SqlitePool,
    pub search: Option<std::sync::Arc<crate::search::SearchIndex>>,
}

pub fn create_router(state: Arc<AppState>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any)
        .expose_headers(Any);

    Router::new()
        .merge(crate::discovery::routes())
        .merge(crate::activitypub::routes())
        .merge(crate::api::routes())
        .merge(crate::inbox::routes())
        .merge(crate::interactions::routes())
        .merge(crate::media::routes())
        .merge(crate::feeds::routes())
        .merge(crate::posting::routes())
        .merge(crate::streaming::routes())
        .merge(crate::push::routes())
        .merge(crate::webauthn::routes())
        .route("/health", get(health))
        .layer(axum::middleware::from_fn(security_headers))
        .layer(cors)
        .with_state(state)
}

async fn security_headers(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let path = request.uri().path().to_string();
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert("X-Content-Type-Options", "nosniff".parse().unwrap());
    headers.insert("X-Frame-Options", "DENY".parse().unwrap());
    headers.insert("Referrer-Policy", "same-origin".parse().unwrap());

    // Cache-Control by path category
    if path.starts_with("/api/")
        || path.starts_with("/oauth")
        || path.starts_with("/inbox")
        || path == "/health"
    {
        // API, auth, inbox, health: never cache
        headers.insert("Cache-Control", "no-store".parse().unwrap());
    } else if path.starts_with("/.well-known/") || path.starts_with("/nodeinfo") {
        // Discovery: short cache, revalidate
        headers.insert(
            "Cache-Control",
            "public, max-age=300, must-revalidate".parse().unwrap(),
        );
    } else if path.starts_with("/users/") && path.contains("/feed.") {
        // RSS/Atom feeds: short cache
        headers.insert("Cache-Control", "public, max-age=300".parse().unwrap());
    } else if path.starts_with("/users/") {
        // Actor docs, outbox, collections: short cache
        headers.insert(
            "Cache-Control",
            "public, max-age=60, must-revalidate".parse().unwrap(),
        );
    } else if path.starts_with("/@") {
        // Profile and post pages: short cache
        headers.insert("Cache-Control", "public, max-age=60".parse().unwrap());
    }
    // Media files are served by the reverse proxy, not this handler.
    // The Caddyfile/nginx config sets immutable headers for /media/*.

    response
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}
