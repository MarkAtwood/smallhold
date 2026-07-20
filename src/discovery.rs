use axum::extract::{Query, State};
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;

use crate::error::AppError;
use crate::server::AppState;

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/.well-known/webfinger", get(webfinger))
        .route("/.well-known/nodeinfo", get(nodeinfo_links))
        .route("/nodeinfo/2.0", get(nodeinfo))
        .route("/.well-known/host-meta", get(host_meta))
}

// --- WebFinger (RFC 7033) ---

#[derive(Serialize)]
struct JrdResponse {
    subject: String,
    aliases: Vec<String>,
    links: Vec<JrdLink>,
}

#[derive(Serialize)]
struct JrdLink {
    rel: String,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    link_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    href: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    template: Option<String>,
}

async fn webfinger(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response, AppError> {
    let resource = params
        .get("resource")
        .ok_or_else(|| AppError::bad_request("missing resource parameter"))?;

    // RFC 7033 Section 4.5: server MUST accept any URI scheme.
    // For non-acct: schemes, return 404 (resource not found), not 400.
    let acct = match resource.strip_prefix("acct:") {
        Some(a) => a,
        None => return Err(AppError::not_found("resource not found")),
    };

    let (username, domain) = acct
        .split_once('@')
        .ok_or_else(|| AppError::bad_request("invalid acct: URI"))?;

    if domain != state.config.server.domain {
        return Err(AppError::not_found("unknown domain"));
    }

    let exists: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM accounts WHERE username = ?")
        .bind(username)
        .fetch_one(&state.pool)
        .await?;

    if exists.0 == 0 {
        return Err(AppError::not_found("unknown user"));
    }

    let domain = &state.config.server.domain;
    let resp = JrdResponse {
        subject: resource.clone(),
        aliases: vec![
            format!("https://{domain}/users/{username}"),
            format!("https://{domain}/@{username}"),
        ],
        links: vec![
            JrdLink {
                rel: "http://webfinger.net/rel/profile-page".into(),
                link_type: Some("text/html".into()),
                href: Some(format!("https://{domain}/@{username}")),
                template: None,
            },
            JrdLink {
                rel: "self".into(),
                link_type: Some("application/activity+json".into()),
                href: Some(format!("https://{domain}/users/{username}")),
                template: None,
            },
            JrdLink {
                rel: "http://ostatus.org/schema/1.0/subscribe".into(),
                link_type: None,
                href: None,
                template: Some(format!(
                    "https://{domain}/authorize_interaction?uri={{uri}}"
                )),
            },
        ],
    };

    let body = serde_json::to_string(&resp).map_err(|e| AppError::internal(e.to_string()))?;

    Ok(Response::builder()
        .header("Content-Type", "application/jrd+json; charset=utf-8")
        .body(body.into())
        .unwrap())
}

// --- NodeInfo ---

async fn nodeinfo_links(State(state): State<Arc<AppState>>) -> Response {
    let domain = &state.config.server.domain;
    let body = serde_json::json!({
        "links": [{
            "rel": "http://nodeinfo.diaspora.software/ns/schema/2.0",
            "href": format!("https://{domain}/nodeinfo/2.0")
        }]
    });

    Response::builder()
        .header("Content-Type", "application/json")
        .body(serde_json::to_string(&body).unwrap().into())
        .unwrap()
}

async fn nodeinfo(State(state): State<Arc<AppState>>) -> Result<Response, AppError> {
    let (local_posts,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM posts")
        .fetch_one(&state.pool)
        .await?;

    let (user_count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM accounts")
        .fetch_one(&state.pool)
        .await?;

    let body = serde_json::json!({
        "version": "2.0",
        "software": {
            "name": "smallhold",
            "version": "0.1.0"
        },
        "protocols": ["activitypub"],
        "usage": {
            "users": { "total": user_count },
            "localPosts": local_posts
        },
        "openRegistrations": false
    });

    let json = serde_json::to_string(&body).map_err(|e| AppError::internal(e.to_string()))?;

    Ok(Response::builder()
        .header(
            "Content-Type",
            "application/json; profile=\"http://nodeinfo.diaspora.software/ns/schema/2.0\"",
        )
        .body(json.into())
        .unwrap())
}

// --- host-meta (RFC 6415) ---

async fn host_meta(State(state): State<Arc<AppState>>) -> Response {
    let domain = xml_escape(&state.config.server.domain);
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <XRD xmlns=\"http://docs.oasis-open.org/ns/xri/xrd-1.0\">\n  \
           <Link rel=\"lrdd\" \
                  type=\"application/xrd+xml\" \
                  template=\"https://{domain}/.well-known/webfinger?resource={{uri}}\"/>\n\
         </XRD>"
    );

    Response::builder()
        .header("Content-Type", "application/xrd+xml; charset=utf-8")
        .body(xml.into())
        .unwrap()
}
