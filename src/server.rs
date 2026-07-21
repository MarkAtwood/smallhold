use crate::config::Config;
use axum::{routing::get, Json, Router};
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};

pub struct AppState {
    pub config: Config,
    pub pool: fieldwork_db::db::Pool,
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
        .merge(crate::pixelfed_api::routes())
        .merge(crate::lemmy_api::routes())
        .route("/health", get(health))
        .layer(cors)
        .with_state(state)
}

// ponytail: security headers (X-Frame-Options, X-Content-Type-Options,
// Referrer-Policy, CSP, Cache-Control, HSTS) delegated to reverse proxy
// (Caddy/nginx). See docs/deployment.md for required proxy config.

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}
