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

const PAGE_CSS: &str = r#"
:root{--text:#1d1d1f;--muted:#6e6e73;--bg:#fff;--card:#f5f5f7;--border:#d2d2d7;--link:#0066cc}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',sans-serif;
 color:var(--text);background:var(--bg);line-height:1.6}
main{max-width:640px;margin:0 auto;padding:2rem 1.5rem}
h1{font-size:1.75rem;font-weight:600;margin-bottom:.15rem}
h2{font-size:1.1rem;font-weight:600;color:var(--muted);text-transform:uppercase;
 letter-spacing:.05em;margin:1.5rem 0 .75rem}
.handle{color:var(--muted);font-size:.95rem;margin-bottom:1rem}
.bio{margin-bottom:1rem}
.bio p{margin-bottom:.5rem}
table{width:100%;border-collapse:collapse;margin-bottom:1rem}
th,td{padding:.6rem .8rem;text-align:left;border-bottom:1px solid var(--border)}
th{background:var(--card);color:var(--muted);font-size:.8rem;font-weight:600;
 text-transform:uppercase;letter-spacing:.04em;width:30%}
td{font-size:.95rem}
.meta{color:var(--muted);font-size:.85rem;margin-bottom:1.5rem}
hr{border:none;border-top:1px solid var(--border);margin:1.5rem 0}
article{padding:1rem 0;border-bottom:1px solid var(--border)}
article .content{margin-bottom:.5rem}
article .content p{margin-bottom:.5rem}
article time{color:var(--muted);font-size:.8rem}
ul{list-style:none}
li{padding:.75rem 0;border-bottom:1px solid var(--border)}
li a{text-decoration:none;color:var(--text);display:block}
li a:hover{color:var(--link)}
li span{color:var(--muted);font-size:.9rem;margin-left:.5rem}
a{color:var(--link);text-decoration:none}
a:hover{text-decoration:underline}
footer.site{margin-top:2rem;color:var(--muted);font-size:.8rem}
.mention{color:var(--link)}
.hashtag{color:var(--link)}
@media(prefers-color-scheme:dark){
 :root{--text:#f5f5f7;--muted:#98989d;--bg:#1d1d1f;--card:#2c2c2e;--border:#3a3a3c;--link:#2997ff}
}
"#;

/// Load theme token overrides and custom CSS. Theme tokens come first so custom CSS can override.
fn load_extra_css(config: &crate::config::Config) -> String {
    let mut css = crate::theme::load_theme_css(config);
    let custom_path = &config.branding.custom_css_path;
    if !custom_path.is_empty() {
        match std::fs::read_to_string(custom_path) {
            Ok(custom) => css.push_str(&custom),
            Err(e) => tracing::warn!(path = custom_path, "failed to load custom CSS: {e}"),
        }
    }
    css
}

/// GET / — root page listing personas.
async fn index_page(
    State(state): State<Arc<AppState>>,
) -> Result<Html<String>, AppError> {
    let domain = &state.config.server.domain;
    let site_title = ammonia::clean(&state.config.branding.site_title);
    let site_desc = if state.config.branding.site_description.is_empty() {
        format!("ActivityPub server on {domain}")
    } else {
        ammonia::clean(&state.config.branding.site_description)
    };
    let custom_css = load_extra_css(&state.config);

    let accounts: Vec<(String, String)> = sqlx::query_as(
        "SELECT username, display_name FROM accounts ORDER BY created_at",
    )
    .fetch_all(&state.pool)
    .await?;

    let mut personas_html = String::new();
    for (username, display_name) in &accounts {
        let dn = ammonia::clean(display_name);
        personas_html.push_str(&format!(
            r#"<li><a href="/@{username}"><strong>{dn}</strong> <span>@{username}@{domain}</span></a></li>"#,
        ));
    }

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{domain} — {site_title}</title>
<style>{PAGE_CSS}</style>
<style>{custom_css}</style>
</head>
<body>
<main>
<h1>{site_title}</h1>
<p class="handle">{site_desc}</p>
<ul>{personas_html}</ul>
<footer class="site">Powered by smallhold</footer>
</main>
</body>
</html>"#,
    );
    Ok(Html(html))
}

/// GET /@{username} — profile page with posts.
async fn profile_page(
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
) -> Result<Html<String>, AppError> {
    let account = fetch_account(&state.pool, &username).await?;
    let domain = &state.config.server.domain;
    let display_name = ammonia::clean(&account.display_name);
    let custom_css = load_extra_css(&state.config);

    // Counts
    let account_id: Option<(i64,)> = sqlx::query_as(
        "SELECT id FROM accounts WHERE username = ?",
    )
    .bind(&username)
    .fetch_optional(&state.pool)
    .await?;
    let aid = account_id.map(|r| r.0).unwrap_or(0);

    let (post_count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM posts WHERE account_id = ?",
    )
    .bind(aid)
    .fetch_one(&state.pool)
    .await
    .unwrap_or((0,));

    let (follower_count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM followers WHERE local_account_id = ?",
    )
    .bind(aid)
    .fetch_one(&state.pool)
    .await
    .unwrap_or((0,));

    // Profile fields
    let fields: Vec<serde_json::Value> =
        serde_json::from_str(&account.fields_json).unwrap_or_default();
    let mut fields_html = String::new();
    if !fields.is_empty() {
        fields_html.push_str("<table class=\"fields\">");
        for f in &fields {
            let name = ammonia::clean(f["name"].as_str().unwrap_or(""));
            let clean_value = ammonia::clean(f["value"].as_str().unwrap_or(""));
            fields_html.push_str(&format!("<tr><th>{name}</th><td>{clean_value}</td></tr>"));
        }
        fields_html.push_str("</table>");
    }

    // Recent posts
    let posts: Vec<PostRow> = sqlx::query_as(
        "SELECT id, content_html, created_at FROM posts WHERE account_id = ? AND visibility = 'public' ORDER BY created_at DESC LIMIT 20",
    )
    .bind(aid)
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let mut posts_html = String::new();
    for post in &posts {
        let dt = chrono::DateTime::from_timestamp_millis(post.created_at)
            .unwrap_or_default();
        let date = dt.format("%Y-%m-%d").to_string();
        let iso = dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        posts_html.push_str(&format!(
            r#"<article><div class="content">{content}</div><footer><a href="/@{username}/{id}"><time datetime="{iso}">{date}</time></a></footer></article>"#,
            content = post.content_html,
            id = post.id,
        ));
    }

    let joined = chrono::DateTime::from_timestamp_millis(account.created_at)
        .unwrap_or_default()
        .format("%B %Y")
        .to_string();

    let bio_section = if account.bio_html.is_empty() {
        String::new()
    } else {
        format!(r#"<div class="bio">{}</div>"#, account.bio_html)
    };

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>@{username}@{domain} — {display_name}</title>
<meta property="og:title" content="{display_name} (@{username}@{domain})">
<meta property="og:type" content="profile">
<meta property="og:url" content="https://{domain}/@{username}">
<meta property="og:description" content="Profile on {domain}">
<link rel="alternate" type="application/activity+json" href="https://{domain}/users/{username}">
<link rel="alternate" type="application/rss+xml" title="RSS" href="https://{domain}/users/{username}/feed.rss">
<link rel="alternate" type="application/atom+xml" title="Atom" href="https://{domain}/users/{username}/feed.atom">
<style>{PAGE_CSS}</style>
<style>{custom_css}</style>
</head>
<body>
<main>
<h1>{display_name}</h1>
<p class="handle">@{username}@{domain}</p>
{bio_section}
{fields_html}
<p class="meta">{post_count} posts · {follower_count} followers · Joined {joined}</p>
<hr>
<h2>Posts</h2>
{posts_html}
</main>
</body>
</html>"#,
    );
    Ok(Html(html))
}

/// Escape a string for use in HTML attributes (meta content, title, etc.).
fn html_attr_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// GET /@{username}/{post_id} — individual post page.
async fn post_page(
    State(state): State<Arc<AppState>>,
    Path((username, post_id)): Path<(String, String)>,
) -> Result<Html<String>, AppError> {
    let domain = &state.config.server.domain;
    let pid: i64 = post_id
        .parse()
        .map_err(|_| AppError::not_found("Post not found"))?;

    let post: PostRow = sqlx::query_as(
        "SELECT p.id, p.content_html, p.created_at FROM posts p \
         JOIN accounts a ON p.account_id = a.id \
         WHERE p.id = ? AND a.username = ?",
    )
    .bind(pid)
    .bind(&username)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::not_found("Post not found"))?;

    let account = fetch_account(&state.pool, &username).await?;
    let display_name = ammonia::clean(&account.display_name);
    let custom_css = load_extra_css(&state.config);

    let dt = chrono::DateTime::from_timestamp_millis(post.created_at).unwrap_or_default();
    let date = dt.format("%Y-%m-%d %H:%M").to_string();
    let iso = dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    // Strip HTML for OG description
    let plain_text = ammonia::Builder::new()
        .tags(std::collections::HashSet::new())
        .clean(&post.content_html)
        .to_string();
    let og_desc = if plain_text.len() > 200 {
        format!("{}...", &plain_text[..197])
    } else {
        plain_text
    };

    let og_desc_escaped = html_attr_escape(&og_desc);
    let og_desc_title_escaped = html_attr_escape(
        &og_desc.chars().take(50).collect::<String>(),
    );

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{display_name}: "{og_desc_title_escaped}" — @{username}@{domain}</title>
<meta property="og:title" content="{display_name} (@{username}@{domain})">
<meta property="og:type" content="article">
<meta property="og:url" content="https://{domain}/@{username}/{post_id}">
<meta property="og:description" content="{og_desc_escaped}">
<link rel="alternate" type="application/activity+json" href="https://{domain}/users/{username}/statuses/{post_id}">
<style>{PAGE_CSS}</style>
<style>{custom_css}</style>
</head>
<body>
<main>
<article>
<div class="content">{content}</div>
<footer><time datetime="{iso}">{date}</time></footer>
</article>
<hr>
<p><a href="/@{username}">← @{username}@{domain}</a></p>
</main>
</body>
</html>"#,
        content = post.content_html,
    );
    Ok(Html(html))
}

/// Row from the posts table needed for outbox items.
#[derive(sqlx::FromRow)]
struct PostRow {
    id: i64,
    content_html: String,
    created_at: i64,
}

/// GET /users/{username}/outbox — OrderedCollection of public Create{Note} activities.
async fn outbox(
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
) -> Result<Response, AppError> {
    let account_row: Option<(i64,)> =
        sqlx::query_as("SELECT id FROM accounts WHERE username = ? LIMIT 1")
            .bind(&username)
            .fetch_optional(&state.pool)
            .await?;

    let (account_id,) =
        account_row.ok_or_else(|| AppError::not_found("Account not found"))?;

    let domain = &state.config.server.domain;
    let actor_uri = format!("https://{domain}/users/{username}");

    let (total,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM posts WHERE account_id = ? AND visibility = 'public'",
    )
    .bind(account_id)
    .fetch_one(&state.pool)
    .await?;

    let posts: Vec<PostRow> = sqlx::query_as(
        "SELECT id, content_html, created_at \
         FROM posts \
         WHERE account_id = ? AND visibility = 'public' \
         ORDER BY created_at DESC \
         LIMIT 20",
    )
    .bind(account_id)
    .fetch_all(&state.pool)
    .await?;

    let items: Vec<Value> = posts
        .into_iter()
        .map(|p| {
            let published = crate::api::millis_to_iso(p.created_at);
            let status_uri = format!("{actor_uri}/statuses/{}", p.id);
            json!({
                "id": format!("{status_uri}/activity"),
                "type": "Create",
                "actor": &actor_uri,
                "published": &published,
                "object": {
                    "id": &status_uri,
                    "type": "Note",
                    "content": p.content_html,
                    "attributedTo": &actor_uri,
                    "to": ["https://www.w3.org/ns/activitystreams#Public"],
                    "cc": [format!("{actor_uri}/followers")],
                    "published": &published,
                    "url": format!("https://{domain}/@{username}/{}", p.id)
                }
            })
        })
        .collect();

    Ok(ap_response(json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": format!("https://{domain}/users/{username}/outbox"),
        "type": "OrderedCollection",
        "totalItems": total,
        "orderedItems": items
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

/// GET /users/{username}/collections/featured — pinned posts as an OrderedCollection.
async fn featured(
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
) -> Result<Response, AppError> {
    let _ = fetch_account(&state.pool, &username).await?;
    let domain = &state.config.server.domain;

    let account_row: Option<(i64,)> =
        sqlx::query_as("SELECT id FROM accounts WHERE username = ? LIMIT 1")
            .bind(&username)
            .fetch_optional(&state.pool)
            .await?;
    let (account_id,) =
        account_row.ok_or_else(|| AppError::not_found("Account not found"))?;

    let actor_uri = format!("https://{domain}/users/{username}");

    let posts: Vec<PostRow> = sqlx::query_as(
        "SELECT p.id, p.content_html, p.created_at \
         FROM pinned_posts pp JOIN posts p ON pp.post_id = p.id \
         WHERE pp.account_id = ? \
         ORDER BY pp.pinned_at DESC",
    )
    .bind(account_id)
    .fetch_all(&state.pool)
    .await?;

    let items: Vec<Value> = posts
        .iter()
        .map(|p| {
            let published = crate::api::millis_to_iso(p.created_at);
            let status_uri = format!("{actor_uri}/statuses/{}", p.id);
            json!({
                "id": &status_uri,
                "type": "Note",
                "content": p.content_html,
                "attributedTo": &actor_uri,
                "to": ["https://www.w3.org/ns/activitystreams#Public"],
                "cc": [format!("{actor_uri}/followers")],
                "published": &published,
                "url": format!("https://{domain}/@{username}/{}", p.id)
            })
        })
        .collect();

    Ok(ap_response(json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": format!("https://{domain}/users/{username}/collections/featured"),
        "type": "OrderedCollection",
        "totalItems": items.len(),
        "orderedItems": items
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
        .route("/", get(index_page))
        .route("/users/{username}", get(actor))
        .route("/@{username}", get(profile_page))
        .route("/@{username}/{post_id}", get(post_page))
        .route("/users/{username}/outbox", get(outbox))
        .route("/users/{username}/followers", get(followers_collection))
        .route("/users/{username}/following", get(following_collection))
        .route("/users/{username}/collections/featured", get(featured))
        .route("/users/{username}/collections/tags", get(featured_tags))
}
