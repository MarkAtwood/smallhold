use crate::error::AppError;
use crate::server::AppState;
use axum::extract::{Path, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use std::sync::Arc;

#[derive(sqlx::FromRow)]
struct FeedPost {
    id: i64,
    content_html: String,
    created_at: i64,
}

/// Look up account_id by username, returning 404 if not found.
async fn resolve_account_id(
    pool: &sqlx::SqlitePool,
    username: &str,
) -> Result<i64, AppError> {
    let row: Option<(i64,)> =
        sqlx::query_as("SELECT id FROM accounts WHERE username = ? LIMIT 1")
            .bind(username)
            .fetch_optional(pool)
            .await?;
    row.map(|r| r.0)
        .ok_or_else(|| AppError::not_found("Account not found"))
}

/// Fetch last 20 public posts for an account.
async fn fetch_public_posts(
    pool: &sqlx::SqlitePool,
    account_id: i64,
) -> Result<Vec<FeedPost>, AppError> {
    let posts: Vec<FeedPost> = sqlx::query_as(
        "SELECT id, content_html, created_at \
         FROM posts \
         WHERE account_id = ? AND visibility = 'public' AND boost_of_id IS NULL \
         ORDER BY created_at DESC \
         LIMIT 20",
    )
    .bind(account_id)
    .fetch_all(pool)
    .await?;
    Ok(posts)
}

fn millis_to_rfc2822(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms)
        .unwrap_or_default()
        .to_rfc2822()
}

fn millis_to_rfc3339(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms)
        .unwrap_or_default()
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Escape text for safe inclusion in XML.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// GET /users/{username}/feed.rss
async fn rss_feed(
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
) -> Result<Response, AppError> {
    let domain = &state.config.server.domain;
    let account_id = resolve_account_id(&state.pool, &username).await?;
    let posts = fetch_public_posts(&state.pool, account_id).await?;

    let escaped_username = xml_escape(&username);
    let escaped_domain = xml_escape(domain);

    let mut items = String::new();
    for p in &posts {
        items.push_str(&format!(
            "    <item>\n\
             \x20     <title>Post by @{escaped_username}</title>\n\
             \x20     <link>https://{escaped_domain}/@{escaped_username}/{id}</link>\n\
             \x20     <guid isPermaLink=\"true\">https://{escaped_domain}/@{escaped_username}/{id}</guid>\n\
             \x20     <pubDate>{date}</pubDate>\n\
             \x20     <description>{content}</description>\n\
             \x20   </item>\n",
            id = p.id,
            date = xml_escape(&millis_to_rfc2822(p.created_at)),
            content = xml_escape(&p.content_html),
        ));
    }

    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <rss version=\"2.0\" xmlns:atom=\"http://www.w3.org/2005/Atom\">\n\
         <channel>\n\
         \x20 <title>@{escaped_username}@{escaped_domain}</title>\n\
         \x20 <link>https://{escaped_domain}/@{escaped_username}</link>\n\
         \x20 <description>Posts by @{escaped_username}</description>\n\
         \x20 <atom:link href=\"https://{escaped_domain}/users/{escaped_username}/feed.rss\" rel=\"self\" type=\"application/rss+xml\"/>\n\
         {items}\
         </channel>\n\
         </rss>\n",
    );

    Ok((
        StatusCode::OK,
        [(CONTENT_TYPE, "application/rss+xml; charset=utf-8")],
        xml,
    )
        .into_response())
}

/// GET /users/{username}/feed.atom
async fn atom_feed(
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
) -> Result<Response, AppError> {
    let domain = &state.config.server.domain;
    let account_id = resolve_account_id(&state.pool, &username).await?;
    let posts = fetch_public_posts(&state.pool, account_id).await?;

    let escaped_username = xml_escape(&username);
    let escaped_domain = xml_escape(domain);

    let updated = posts
        .first()
        .map(|p| millis_to_rfc3339(p.created_at))
        .unwrap_or_else(|| millis_to_rfc3339(0));

    let mut entries = String::new();
    for p in &posts {
        let ts = millis_to_rfc3339(p.created_at);
        entries.push_str(&format!(
            "  <entry>\n\
             \x20   <title>Post by @{escaped_username}</title>\n\
             \x20   <link href=\"https://{escaped_domain}/@{escaped_username}/{id}\"/>\n\
             \x20   <id>https://{escaped_domain}/users/{escaped_username}/statuses/{id}</id>\n\
             \x20   <published>{ts}</published>\n\
             \x20   <updated>{ts}</updated>\n\
             \x20   <content type=\"html\">{content}</content>\n\
             \x20   <author><name>@{escaped_username}@{escaped_domain}</name></author>\n\
             \x20 </entry>\n",
            id = p.id,
            content = xml_escape(&p.content_html),
        ));
    }

    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <feed xmlns=\"http://www.w3.org/2005/Atom\">\n\
         \x20 <title>@{escaped_username}@{escaped_domain}</title>\n\
         \x20 <link href=\"https://{escaped_domain}/@{escaped_username}\" rel=\"alternate\"/>\n\
         \x20 <link href=\"https://{escaped_domain}/users/{escaped_username}/feed.atom\" rel=\"self\"/>\n\
         \x20 <id>https://{escaped_domain}/users/{escaped_username}</id>\n\
         \x20 <updated>{updated}</updated>\n\
         {entries}\
         </feed>\n",
    );

    Ok((
        StatusCode::OK,
        [(CONTENT_TYPE, "application/atom+xml; charset=utf-8")],
        xml,
    )
        .into_response())
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/users/{username}/feed.rss", get(rss_feed))
        .route("/users/{username}/feed.atom", get(atom_feed))
}
