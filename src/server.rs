use crate::config::Config;
use axum::{routing::get, Json, Router};
use sqlx::SqlitePool;
use std::sync::Arc;

pub struct AppState {
    pub config: Config,
    pub pool: SqlitePool,
}

pub fn create_router(state: Arc<AppState>) -> Router {
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
        .route("/health", get(health))
        .with_state(state)
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}
