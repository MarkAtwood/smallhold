use crate::error::AppError;
use crate::server::AppState;
use axum::extract::{Path, Query, State};
use axum::http::header::{ACCEPT, CONTENT_TYPE, LOCATION};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use fieldwork::collections::{build_collection, build_collection_page, paginate_offset};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::{Arc, LazyLock, OnceLock};

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

/// Standard ActivityPub JSON-LD @context array (matches Mastodon), built once.
static AP_CONTEXT: LazyLock<Value> = LazyLock::new(|| {
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
});

fn ap_context() -> Value {
    AP_CONTEXT.clone()
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

/// Row from the personas + users tables needed for actor documents and profile pages.
pub(crate) struct ApAccountRow {
    pub username: String,
    pub display_name: String,
    pub bio_html: String,
    pub public_key_pem: String,
    pub is_locked: bool,
    pub discoverable: bool,
    pub bot: bool,
    pub fields_json: String,
    pub created_at: i64,
    pub did_key: Option<String>,
    pub recovery_pubkey: Option<String>,
}

/// Looks up a local persona by username (with DID data from users table).
async fn fetch_account(pool: &fieldwork_db::db::Pool, username: &str) -> Result<ApAccountRow, AppError> {
    let raw_row = crate::db_extras::fetch_ap_account(pool, username)
        .await?
        .ok_or_else(|| AppError::not_found("Account not found"))?;
    let row: ApAccountRow = crate::sqlx::FromRow::from_row(&raw_row)
        .map_err(|e| AppError::internal(format!("row conversion: {e}")))?;

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

    // Build alsoKnownAs array with profile URL and DID identifiers
    let mut also_known_as: Vec<Value> = Vec::new();
    also_known_as.push(json!(format!("https://{domain}/@{username}")));
    if let Some(ref dk) = account.did_key {
        also_known_as.push(json!(dk));
    }
    let did_web_val = crate::did::did_web(domain, &username);
    also_known_as.push(json!(did_web_val));

    let mut doc = json!({
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
        "alsoKnownAs": also_known_as,
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

    // Add did:key for DID-aware peers
    if let Some(ref dk) = account.did_key {
        doc["did"] = json!(dk);
    }

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
/// Cached in an OnceLock so disk I/O and regex work happen only on first call.
fn load_extra_css(config: &crate::config::Config) -> String {
    static EXTRA_CSS: OnceLock<String> = OnceLock::new();
    EXTRA_CSS
        .get_or_init(|| {
            fieldwork::theme::load_extra_css(
                &config.branding.theme_tokens_path,
                &config.branding.custom_css_path,
            )
        })
        .clone()
}

/// GET / — root page listing personas.
async fn index_page(State(state): State<Arc<AppState>>) -> Result<Html<String>, AppError> {
    let domain = &state.config.server.domain;
    let site_title = ammonia::clean(&state.config.branding.site_title);
    let site_desc = if state.config.branding.site_description.is_empty() {
        format!("ActivityPub server on {domain}")
    } else {
        ammonia::clean(&state.config.branding.site_description)
    };
    let custom_css = load_extra_css(&state.config);

    let accounts: Vec<(String, String)> =
        crate::db_extras::list_personas_display(&state.pool).await?;

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
<footer class="site">Powered by <a href="https://github.com/MarkAtwood/smallhold">smallhold</a></footer>
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
    let username = html_attr_escape(&username);
    let domain = &state.config.server.domain;
    let display_name = ammonia::clean(&account.display_name);
    let dn_escaped = html_attr_escape(&display_name);
    let custom_css = load_extra_css(&state.config);

    // Counts
    let persona = fieldwork_db::persona_db::get_persona_by_username(
        &state.pool, &username,
    ).await?;
    let aid = persona.as_ref().map(|p| p.id).unwrap_or(0);

    let post_count = crate::db_extras::count_posts_for_persona(&state.pool, aid)
        .await
        .unwrap_or(0);

    let follower_count = fieldwork_db::followers_db::follower_count(
        &state.pool, aid,
    ).await.unwrap_or(0);

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
    let post_tuples: Vec<(i64, String, i64)> = crate::db_extras::get_public_feed_posts(&state.pool, aid)
        .await
        .unwrap_or_default();
    let posts: Vec<PostRow> = post_tuples.into_iter().map(|(id, content_html, created_at)| PostRow {
        id, content_html, context_url: None, created_at,
    }).collect();

    let mut posts_html = String::new();
    for post in &posts {
        let dt = chrono::DateTime::from_timestamp_millis(post.created_at).unwrap_or_default();
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
<title>@{username}@{domain} — {dn_escaped}</title>
<meta property="og:title" content="{dn_escaped} (@{username}@{domain})">
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

    let (pid2, ch, ca) = crate::db_extras::get_post_for_page(&state.pool, pid, &username)
        .await?
        .ok_or_else(|| AppError::not_found("Post not found"))?;
    let post = PostRow { id: pid2, content_html: ch, context_url: None, created_at: ca };

    let account = fetch_account(&state.pool, &username).await?;
    let username = html_attr_escape(&username);
    let display_name = ammonia::clean(&account.display_name);
    let dn_escaped = html_attr_escape(&display_name);
    let custom_css = load_extra_css(&state.config);

    let dt = chrono::DateTime::from_timestamp_millis(post.created_at).unwrap_or_default();
    let date = dt.format("%Y-%m-%d %H:%M").to_string();
    let iso = dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    // Strip HTML for OG description
    let plain_text = ammonia::Builder::new()
        .tags(std::collections::HashSet::new())
        .clean(&post.content_html)
        .to_string();
    let og_desc = if plain_text.chars().count() > 200 {
        let truncated: String = plain_text.chars().take(197).collect();
        format!("{truncated}...")
    } else {
        plain_text
    };

    let og_desc_escaped = html_attr_escape(&og_desc);
    let og_desc_title_escaped = html_attr_escape(&og_desc.chars().take(50).collect::<String>());

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{dn_escaped}: "{og_desc_title_escaped}" — @{username}@{domain}</title>
<meta property="og:title" content="{dn_escaped} (@{username}@{domain})">
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

#[derive(Deserialize)]
struct PaginationQuery {
    page: Option<u32>,
}

/// Row from the posts table needed for outbox items.
struct PostRow {
    id: i64,
    content_html: String,
    context_url: Option<String>,
    created_at: i64,
}

/// GET /users/{username}/outbox — OrderedCollection of public Create{Note} activities.
///
/// Without `?page`: returns the top-level collection with `totalItems` and `first` link.
/// With `?page=N`: returns an OrderedCollectionPage with up to 20 items.
async fn outbox(
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
    Query(query): Query<PaginationQuery>,
) -> Result<Response, AppError> {
    let account_id = crate::db_extras::get_persona_id(&state.pool, &username)
        .await?
        .ok_or_else(|| AppError::not_found("Account not found"))?;

    let domain = &state.config.server.domain;
    let outbox_uri = format!("https://{domain}/users/{username}/outbox");
    let total = crate::db_extras::count_public_posts(&state.pool, account_id).await?;

    if query.page.is_none() {
        let col = build_collection(&outbox_uri, total as u64);
        let doc = serde_json::to_value(&col).expect("OrderedCollection serialization is infallible");
        return Ok(ap_response(doc));
    }

    let page = query.page.unwrap_or(1);
    if page == 0 {
        return Err(AppError::bad_request("page must be >= 1"));
    }

    let per_page: u32 = 20;
    let offset = paginate_offset(page, per_page).min(i64::MAX as u64) as i64;
    let actor_uri = format!("https://{domain}/users/{username}");

    let outbox_tuples = crate::db_extras::get_outbox_posts(&state.pool, account_id, i64::from(per_page), offset).await?;
    let posts: Vec<PostRow> = outbox_tuples.into_iter().map(|(id, content_html, context_url, created_at)| PostRow {
        id, content_html, context_url, created_at,
    }).collect();

    let items: Vec<Value> = posts
        .into_iter()
        .map(|p| {
            let published = crate::api::millis_to_iso(p.created_at);
            let status_uri = format!("{actor_uri}/statuses/{}", p.id);
            let mut note = json!({
                "id": &status_uri,
                "type": "Note",
                "content": p.content_html,
                "attributedTo": &actor_uri,
                "to": ["https://www.w3.org/ns/activitystreams#Public"],
                "cc": [format!("{actor_uri}/followers")],
                "published": &published,
                "url": format!("https://{domain}/@{username}/{}", p.id)
            });
            if let Some(ref ctx) = p.context_url {
                note["context"] = json!(ctx);
            }
            json!({
                "id": format!("{status_uri}/activity"),
                "type": "Create",
                "actor": &actor_uri,
                "published": &published,
                "object": note
            })
        })
        .collect();

    let page_doc = build_collection_page(&outbox_uri, page, items, total as u64, per_page);
    let doc = serde_json::to_value(&page_doc).expect("OrderedCollectionPage serialization is infallible");
    Ok(ap_response(doc))
}

/// GET /users/{username}/followers — OrderedCollection with follower count.
async fn followers_collection(
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
) -> Result<Response, AppError> {
    let persona = fieldwork_db::persona_db::get_persona_by_username(
        &state.pool, &username,
    ).await?
    .ok_or_else(|| AppError::not_found("Account not found"))?;

    let count = fieldwork_db::followers_db::follower_count(
        &state.pool, persona.id,
    ).await?;

    let domain = &state.config.server.domain;
    let col = build_collection(&format!("https://{domain}/users/{username}/followers"), count as u64);
    let doc = serde_json::to_value(&col).expect("OrderedCollection serialization is infallible");
    Ok(ap_response(doc))
}

/// GET /users/{username}/following — OrderedCollection with following count.
async fn following_collection(
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
) -> Result<Response, AppError> {
    let persona = fieldwork_db::persona_db::get_persona_by_username(
        &state.pool, &username,
    ).await?
    .ok_or_else(|| AppError::not_found("Account not found"))?;

    let count = fieldwork_db::follows_db::following_count(
        &state.pool, persona.id,
    ).await?;

    let domain = &state.config.server.domain;
    let col = build_collection(&format!("https://{domain}/users/{username}/following"), count as u64);
    let doc = serde_json::to_value(&col).expect("OrderedCollection serialization is infallible");
    Ok(ap_response(doc))
}

/// GET /users/{username}/collections/featured — pinned posts as an OrderedCollection.
async fn featured(
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
) -> Result<Response, AppError> {
    let _ = fetch_account(&state.pool, &username).await?;
    let domain = &state.config.server.domain;

    let account_id = crate::db_extras::get_persona_id(&state.pool, &username)
        .await?
        .ok_or_else(|| AppError::not_found("Account not found"))?;

    let actor_uri = format!("https://{domain}/users/{username}");

    let featured_tuples = crate::db_extras::get_featured_posts(&state.pool, account_id).await?;
    let posts: Vec<PostRow> = featured_tuples.into_iter().map(|(id, content_html, context_url, created_at)| PostRow {
        id, content_html, context_url, created_at,
    }).collect();

    let items: Vec<Value> = posts
        .iter()
        .map(|p| {
            let published = crate::api::millis_to_iso(p.created_at);
            let status_uri = format!("{actor_uri}/statuses/{}", p.id);
            let mut note = json!({
                "id": &status_uri,
                "type": "Note",
                "content": p.content_html,
                "attributedTo": &actor_uri,
                "to": ["https://www.w3.org/ns/activitystreams#Public"],
                "cc": [format!("{actor_uri}/followers")],
                "published": &published,
                "url": format!("https://{domain}/@{username}/{}", p.id)
            });
            if let Some(ref ctx) = p.context_url {
                note["context"] = json!(ctx);
            }
            note
        })
        .collect();

    let featured_uri = format!("https://{domain}/users/{username}/collections/featured");
    let col = build_collection(&featured_uri, items.len() as u64);
    let mut doc = serde_json::to_value(&col).expect("OrderedCollection serialization is infallible");
    doc["orderedItems"] = json!(items);
    Ok(ap_response(doc))
}

/// GET /users/{username}/collections/tags — empty OrderedCollection stub.
async fn featured_tags(
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
) -> Result<Response, AppError> {
    let _ = fetch_account(&state.pool, &username).await?;
    let domain = &state.config.server.domain;

    let col = build_collection(&format!("https://{domain}/users/{username}/collections/tags"), 0);
    let doc = serde_json::to_value(&col).expect("OrderedCollection serialization is infallible");
    Ok(ap_response(doc))
}

/// GET /users/{username}/statuses/{id} — Serve a single post as an ActivityPub Note.
///
/// Required for federation: other servers fetch individual posts by AP ID during
/// inbox processing, conversation backfill, and signature verification.
async fn ap_status(
    State(state): State<Arc<AppState>>,
    Path((username, id_str)): Path<(String, String)>,
    headers: axum::http::HeaderMap,
) -> Result<Response, AppError> {
    let post_id: i64 = id_str.parse().map_err(|_| AppError::not_found("Invalid post ID"))?;
    let domain = &state.config.server.domain;

    // If the client doesn't want AP JSON, redirect to the HTML page
    let accept = headers.get("accept").and_then(|v| v.to_str().ok()).unwrap_or("");
    if !accept.contains("application/activity+json") && !accept.contains("application/ld+json") {
        return Ok(axum::response::Redirect::to(&format!("/@{username}/{post_id}")).into_response());
    }

    // Verify the persona exists and matches
    let persona = fieldwork_db::persona_db::get_persona_by_username(&state.pool, &username)
        .await?
        .ok_or_else(|| AppError::not_found("Account not found"))?;

    // Get the post
    let post = fieldwork_db::posts_db::get_post(&state.pool, post_id)
        .await?
        .ok_or_else(|| AppError::not_found("Post not found"))?;

    // Verify the post belongs to this persona
    if post.persona_id != persona.id {
        return Err(AppError::not_found("Post not found"));
    }

    // Reject deleted posts
    if post.deleted_at.is_some() {
        return Ok(ap_response(json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": format!("https://{domain}/users/{username}/statuses/{post_id}"),
            "type": "Tombstone",
            "formerType": "Note"
        })));
    }

    let actor_uri = format!("https://{domain}/users/{username}");
    let status_uri = format!("{actor_uri}/statuses/{post_id}");
    let published = crate::api::millis_to_iso(post.created_at);

    // Build media attachments with alt text
    let media = fieldwork_db::media_db::attachments_for_post(&state.pool, post_id).await?;
    let attachments: Vec<Value> = media
        .iter()
        .map(|m| {
            let media_url = format!("https://{domain}/media/{}/{}.{}",
                persona.id, m.id,
                m.mime_type.split('/').nth(1).unwrap_or("bin"));
            json!({
                "type": "Document",
                "mediaType": m.mime_type,
                "url": media_url,
                "name": if m.description.is_empty() { Value::Null } else { Value::String(m.description.clone()) },
                "blurhash": m.blurhash,
                "width": m.width,
                "height": m.height
            })
        })
        .collect();

    // Build tags (hashtags + mentions)
    let tags_list = fieldwork_db::post_tags_db::get_tags(&state.pool, post_id).await?;
    let tag_values: Vec<Value> = tags_list
        .iter()
        .map(|tag| json!({
            "type": "Hashtag",
            "href": format!("https://{domain}/tags/{tag}"),
            "name": format!("#{tag}")
        }))
        .collect();

    let mut to = vec![json!("https://www.w3.org/ns/activitystreams#Public")];
    let mut cc = vec![json!(format!("{actor_uri}/followers"))];

    if post.visibility == "direct" {
        to = vec![];
        cc = vec![];
    } else if post.visibility == "followers" {
        to = vec![json!(format!("{actor_uri}/followers"))];
        cc = vec![];
    } else if post.visibility == "unlisted" {
        to = vec![json!(format!("{actor_uri}/followers"))];
        cc = vec![json!("https://www.w3.org/ns/activitystreams#Public")];
    }

    let mut note = json!({
        "@context": [
            "https://www.w3.org/ns/activitystreams",
            "https://w3id.org/security/v1"
        ],
        "id": &status_uri,
        "type": "Note",
        "content": post.content_html,
        "attributedTo": &actor_uri,
        "to": to,
        "cc": cc,
        "published": &published,
        "url": format!("https://{domain}/@{username}/{post_id}"),
        "sensitive": post.sensitive,
        "attachment": attachments,
        "tag": tag_values
    });

    if !post.spoiler_text.is_empty() {
        note["summary"] = json!(post.spoiler_text);
    }
    if let Some(ref reply_uri) = post.in_reply_to_uri {
        note["inReplyTo"] = json!(reply_uri);
    }
    if let Some(ref ctx) = post.context_url {
        note["context"] = json!(ctx);
    }

    Ok(ap_response(note))
}

/// GET /users/{username}/statuses/{id}/context — FEP-f228 conversation context collection.
///
/// Returns an OrderedCollection of all posts in the same conversation, ordered
/// chronologically. Only public/unlisted posts are included; the originating
/// post is identified by its `context_url` column.
async fn ap_context_collection(
    State(state): State<Arc<AppState>>,
    Path((username, id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    // Verify account exists.
    let account_id = crate::db_extras::get_persona_id(&state.pool, &username)
        .await?
        .ok_or_else(|| AppError::not_found("Account not found"))?;

    let post_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("Post not found"))?;

    let domain = &state.config.server.domain;
    let context_url = format!("https://{domain}/users/{username}/statuses/{post_id}/context");

    // If the client does not want AP, redirect to the Mastodon API context endpoint.
    if !wants_activitypub(&headers) {
        let api_url = format!("/api/v1/statuses/{post_id}/context");
        return Ok((StatusCode::SEE_OTHER, [(LOCATION, api_url)]).into_response());
    }

    // Verify the post exists and belongs to this account.
    if !crate::db_extras::post_exists_for_user(&state.pool, post_id, account_id).await? {
        return Err(AppError::not_found("Post not found"));
    }

    // Collect all posts sharing the same context_url, ordered chronologically.
    // Join to accounts so each post uses its actual author, not the URL path username.
    struct ContextPostRow {
        id: i64,
        content_html: String,
        context_url: Option<String>,
        created_at: i64,
        username: String,
    }

    let ctx_tuples = crate::db_extras::get_context_posts(&state.pool, &context_url).await?;
    let posts: Vec<ContextPostRow> = ctx_tuples.into_iter().map(|(id, content_html, context_url, created_at, username)| ContextPostRow {
        id, content_html, context_url, created_at, username,
    }).collect();

    let items: Vec<Value> = posts
        .iter()
        .map(|p| {
            let published = crate::api::millis_to_iso(p.created_at);
            let post_actor_uri = format!("https://{domain}/users/{}", p.username);
            let status_uri = format!("{post_actor_uri}/statuses/{}", p.id);
            let mut note = json!({
                "id": &status_uri,
                "type": "Note",
                "content": &p.content_html,
                "attributedTo": &post_actor_uri,
                "context": &context_url,
                "to": ["https://www.w3.org/ns/activitystreams#Public"],
                "cc": [format!("{post_actor_uri}/followers")],
                "published": &published,
                "url": format!("https://{domain}/@{}/{}", p.username, p.id)
            });
            // Only add context if it differs from the collection URL (shouldn't, but defensive).
            if let Some(ref ctx) = p.context_url {
                note["context"] = json!(ctx);
            }
            note
        })
        .collect();

    Ok(ap_response(json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": &context_url,
        "type": "OrderedCollection",
        "totalItems": items.len(),
        "orderedItems": items
    })))
}

/// GET /users/{username}/did.json — DID document for did:web resolution.
async fn did_document(
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
) -> Result<Response, AppError> {
    let account = fetch_account(&state.pool, &username).await?;
    let domain = &state.config.server.domain;

    // Build alsoKnownAs list
    let mut also_known_as: Vec<String> = Vec::new();
    if let Some(ref dk) = account.did_key {
        also_known_as.push(dk.clone());
    }
    also_known_as.push(format!("https://{domain}/@{username}"));

    // Decode recovery pubkey from hex for the DID document
    let recovery_pub: Option<[u8; 32]> = match &account.recovery_pubkey {
        Some(hex) if !hex.is_empty() => {
            let bytes = crate::api::hex_decode(hex)
                .map_err(|_| AppError::internal("Corrupt recovery_pubkey in database"))?;
            if bytes.len() != 32 {
                return Err(AppError::internal("Invalid recovery_pubkey length"));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Some(arr)
        }
        _ => None,
    };

    let doc = crate::did::did_web_document(
        domain,
        &username,
        &account.public_key_pem,
        recovery_pub.as_ref(),
        &also_known_as,
    );

    Ok((
        StatusCode::OK,
        [(CONTENT_TYPE, "application/did+json")],
        doc.to_string(),
    )
        .into_response())
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
        .route("/users/{username}/did.json", get(did_document))
        .route(
            "/users/{username}/statuses/{id}",
            get(ap_status),
        )
        .route(
            "/users/{username}/statuses/{id}/context",
            get(ap_context_collection),
        )
}
