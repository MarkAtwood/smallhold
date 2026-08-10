use crate::config::Config;
use axum::response::Response;
use axum::{middleware, routing::get, Json, Router};
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};

pub struct AppState {
    pub config: Config,
    pub pool: fieldwork_db::db::Pool,
    pub search: Option<std::sync::Arc<crate::search::SearchIndex>>,
    pub federation_client: crate::federation::FederationClient,
}

async fn security_headers(
    request: axum::http::Request<axum::body::Body>,
    next: middleware::Next,
) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert("x-content-type-options", "nosniff".parse().unwrap());
    headers.insert("x-frame-options", "DENY".parse().unwrap());
    headers.insert(
        "referrer-policy",
        "strict-origin-when-cross-origin".parse().unwrap(),
    );
    response
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
        .merge(crate::peertube_api::routes())
        .merge(crate::misskey_api::routes())
        .merge(crate::funkwhale_api::routes())
        .merge(crate::bookwyrm_api::routes())
        .merge(crate::writefreely_api::routes())
        .route("/health", get(health))
        .layer(middleware::from_fn(security_headers))
        .layer(cors)
        .with_state(state)
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}
