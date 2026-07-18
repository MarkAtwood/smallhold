use crate::error::AppError;
use crate::server::AppState;
use axum::extract::{Path, State};
use axum::http::header::{ACCEPT, CONTENT_TYPE, LOCATION};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use serde_json::{json, Value};
use std::sync::Arc;

/// Content-Type for ActivityPub JSON responses.
const AP_CONTENT_TYPE: &str = "application/activity+json; charset=utf-8";

/// Returns true if the Accept header indicates the client wants an ActivityPub document.
fn wants_activitypub(headers: &HeaderMap) -> bool {
    headers
        .get_all(ACCEPT)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .any(|accept| {
            accept.contains("application/activity+json")
                || accept.contains("application/ld+json")
                || accept.contains("application/json")
        })
}

/// Builds the standard ActivityPub JSON-LD @context array (matches Mastodon).
fn ap_context() -> Value {
    json!([
        "https://www.w3.org/ns/activitystreams",
        "https://w3id.org/security/v1",
        {
            "manuallyApprovesFollowers": "as:manuallyApprovesFollowers",
            "toot": "http://joinmastodon.org/ns#",
            "featured": {"@id": "toot:featured", "@type": "@id"},
            "featuredTags": {"@id": "toot:featuredTags", "@type": "@id"},
            "alsoKnownAs": {"@id": "as:alsoKnownAs", "@type": "@id"},
            "movedTo": {"@id": "as:movedTo", "@type": "@id"},
            "schema": "http://schema.org#",
            "PropertyValue": "schema:PropertyValue",
            "value": "schema:value",
            "discoverable": "toot:discoverable",
            "suspended": "toot:suspended",
            "memorial": "toot:memorial",
            "Hashtag": "as:Hashtag",
            "Emoji": "toot:Emoji",
            "blurhash": "toot:blurhash",
            "focalPoint": {"@container": "@list", "@id": "toot:focalPoint"}
        }
    ])
}

/// Returns an ActivityPub JSON response with the correct content type.
fn ap_response(body: Value) -> Response {
    (
        StatusCode::OK,
        [(CONTENT_TYPE, AP_CONTENT_TYPE)],
        body.to_string(),
    )
        .into_response()
}

/// Row from the accounts table needed for actor documents and profile pages.
#[derive(sqlx::FromRow)]
struct AccountRow {
    username: String,
    display_name: String,
    bio_html: String,
    public_key_pem: String,
    is_locked: bool,
    discoverable: bool,
    bot: bool,
    fields_json: String,
    created_at: i64,
}

/// Looks up a local account by username, returning 404 if not found.
async fn fetch_account(
    pool: &sqlx::SqlitePool,
    username: &str,
) -> Result<AccountRow, AppError> {
    let row: AccountRow = sqlx::query_as(
        "SELECT username, display_name, bio_html, public_key_pem,
                is_locked, discoverable, bot, fields_json, created_at
         FROM accounts WHERE username = ? LIMIT 1",
    )
    .bind(username)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| AppError::not_found("Account not found"))?;

    Ok(row)
}

/// GET /users/{username}
///
/// Content-negotiated: returns the AP actor document for AP clients, or redirects
/// to the profile page for browsers.
async fn actor(
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    if !wants_activitypub(&headers) {
        let location = format!("/@{username}");
        return Ok((StatusCode::SEE_OTHER, [(LOCATION, location)]).into_response());
    }

    let account = fetch_account(&state.pool, &username).await?;
    let domain = &state.config.server.domain;
    let actor_uri = format!("https://{domain}/users/{username}");

    let published = chrono::DateTime::from_timestamp_millis(account.created_at)
        .unwrap_or_default()
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    let actor_type = if account.bot { "Service" } else { "Person" };

    // Parse profile fields from fields_json into AP attachment array.
    let attachment: Vec<Value> = serde_json::from_str::<Vec<Value>>(&account.fields_json)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|field| {
            let name = field.get("name")?.as_str()?;
            let value = field.get("value")?.as_str()?;
            Some(json!({
                "type": "PropertyValue",
                "name": name,
                "value": value
            }))
        })
        .collect();

    let doc = json!({
        "@context": ap_context(),
        "id": actor_uri,
        "type": actor_type,
        "following": format!("{actor_uri}/following"),
        "followers": format!("{actor_uri}/followers"),
        "inbox": format!("{actor_uri}/inbox"),
        "outbox": format!("{actor_uri}/outbox"),
        "featured": format!("{actor_uri}/collections/featured"),
        "featuredTags": format!("{actor_uri}/collections/tags"),
        "preferredUsername": account.username,
        "name": account.display_name,
        "summary": account.bio_html,
        "url": format!("https://{domain}/@{username}"),
        "manuallyApprovesFollowers": account.is_locked,
        "discoverable": account.discoverable,
        "published": published,
        "endpoints": {
            "sharedInbox": format!("https://{domain}/inbox")
        },
        "publicKey": {
            "id": format!("{actor_uri}#main-key"),
            "owner": actor_uri,
            "publicKeyPem": account.public_key_pem
        },
        "icon": null,
        "image": null,
        "attachment": attachment,
        "tag": []
    });

    Ok(ap_response(doc))
}

/// GET /@{username} — minimal server-rendered HTML profile page.
async fn profile_page(
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
) -> Result<Html<String>, AppError> {
    let account = fetch_account(&state.pool, &username).await?;
    let domain = &state.config.server.domain;

    // Escape display_name for safe HTML embedding. bio_html is already sanitized
    // by the ingest pipeline (ammonia) so it is safe to embed directly.
    let display_name_escaped = ammonia::clean(&account.display_name);

    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>@{username}@{domain}</title>
  <link rel="alternate" type="application/activity+json" href="https://{domain}/users/{username}">
</head>
<body>
  <h1>{display_name}</h1>
  <p>@{username}@{domain}</p>
  <div>{bio_html}</div>
</body>
</html>"#,
        username = username,
        domain = domain,
        display_name = display_name_escaped,
        bio_html = account.bio_html,
    );

    Ok(Html(html))
}

/// GET /users/{username}/outbox — empty OrderedCollection stub.
async fn outbox(
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
) -> Result<Response, AppError> {
    // Verify the account exists before returning a collection.
    let _ = fetch_account(&state.pool, &username).await?;
    let domain = &state.config.server.domain;

    Ok(ap_response(json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": format!("https://{domain}/users/{username}/outbox"),
        "type": "OrderedCollection",
        "totalItems": 0,
        "orderedItems": []
    })))
}

/// GET /users/{username}/followers — OrderedCollection with follower count.
async fn followers_collection(
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
) -> Result<Response, AppError> {
    let account_row: Option<(i64,)> = sqlx::query_as(
        "SELECT id FROM accounts WHERE username = ? LIMIT 1",
    )
    .bind(&username)
    .fetch_optional(&state.pool)
    .await?;

    let (account_id,) =
        account_row.ok_or_else(|| AppError::not_found("Account not found"))?;

    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM followers WHERE local_account_id = ?",
    )
    .bind(account_id)
    .fetch_one(&state.pool)
    .await?;

    let domain = &state.config.server.domain;
    Ok(ap_response(json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": format!("https://{domain}/users/{username}/followers"),
        "type": "OrderedCollection",
        "totalItems": count
    })))
}

/// GET /users/{username}/following — OrderedCollection with following count.
async fn following_collection(
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
) -> Result<Response, AppError> {
    let account_row: Option<(i64,)> = sqlx::query_as(
        "SELECT id FROM accounts WHERE username = ? LIMIT 1",
    )
    .bind(&username)
    .fetch_optional(&state.pool)
    .await?;

    let (account_id,) =
        account_row.ok_or_else(|| AppError::not_found("Account not found"))?;

    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM follows WHERE follower_id = ?",
    )
    .bind(account_id)
    .fetch_one(&state.pool)
    .await?;

    let domain = &state.config.server.domain;
    Ok(ap_response(json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": format!("https://{domain}/users/{username}/following"),
        "type": "OrderedCollection",
        "totalItems": count
    })))
}

/// GET /users/{username}/collections/featured — empty OrderedCollection stub.
async fn featured(
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
) -> Result<Response, AppError> {
    let _ = fetch_account(&state.pool, &username).await?;
    let domain = &state.config.server.domain;

    Ok(ap_response(json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": format!("https://{domain}/users/{username}/collections/featured"),
        "type": "OrderedCollection",
        "totalItems": 0,
        "orderedItems": []
    })))
}

/// GET /users/{username}/collections/tags — empty OrderedCollection stub.
async fn featured_tags(
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
) -> Result<Response, AppError> {
    let _ = fetch_account(&state.pool, &username).await?;
    let domain = &state.config.server.domain;

    Ok(ap_response(json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": format!("https://{domain}/users/{username}/collections/tags"),
        "type": "OrderedCollection",
        "totalItems": 0,
        "orderedItems": []
    })))
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/users/{username}", get(actor))
        .route("/@{username}", get(profile_page))
        .route("/users/{username}/outbox", get(outbox))
        .route("/users/{username}/followers", get(followers_collection))
        .route("/users/{username}/following", get(following_collection))
        .route("/users/{username}/collections/featured", get(featured))
        .route("/users/{username}/collections/tags", get(featured_tags))
}
