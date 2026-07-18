use crate::api::{account_to_json, fetch_account_row, hex_encode, millis_to_iso, now_millis,
                  AuthenticatedAccount};
use crate::delivery::enqueue_to_followers;
use crate::error::AppError;
use crate::id::generate_id;
use crate::server::AppState;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Content rendering
// ---------------------------------------------------------------------------

pub struct RenderedContent {
    pub html: String,
    pub mentions: Vec<ParsedMention>,
    pub tags: Vec<String>,
}

pub struct ParsedMention {
    pub username: String,
    pub domain: Option<String>,
}

/// Render user-supplied text into sanitized HTML with parsed mentions and hashtags.
pub fn render_content(input: &str, domain: &str) -> RenderedContent {
    let parser = pulldown_cmark::Parser::new(input);
    let mut raw_html = String::new();
    pulldown_cmark::html::push_html(&mut raw_html, parser);

    let clean_html = ammonia::clean(&raw_html);

    let mentions = parse_mentions(input);
    let tags = parse_hashtags(input);

    // Replace mention patterns in the HTML
    let mut html = clean_html;
    for m in &mentions {
        let full_match = match &m.domain {
            Some(d) => format!("@{}@{}", m.username, d),
            None => format!("@{}", m.username),
        };
        let href = match &m.domain {
            Some(d) => format!("https://{d}/@{}", m.username),
            None => format!("https://{domain}/@{}", m.username),
        };
        let link = format!(
            r#"<a href="{href}" class="u-url mention">@<span>{user}</span></a>"#,
            href = href,
            user = m.username,
        );
        html = html.replace(&full_match, &link);
    }

    // Replace hashtag patterns in the HTML
    for tag in &tags {
        let pattern = format!("#{tag}");
        let link = format!(
            r#"<a href="https://{domain}/tags/{lower}" class="mention hashtag" rel="tag">#<span>{tag}</span></a>"#,
            domain = domain,
            lower = tag.to_lowercase(),
            tag = tag,
        );
        html = html.replace(&pattern, &link);
    }

    let normalized_tags: Vec<String> = tags
        .into_iter()
        .map(|t| {
            t.chars()
                .filter(|c| c.is_alphanumeric())
                .collect::<String>()
                .to_lowercase()
        })
        .filter(|t| !t.is_empty())
        .collect();

    RenderedContent {
        html,
        mentions,
        tags: normalized_tags,
    }
}

/// Find `@user@domain` and `@user` patterns in text.
fn parse_mentions(text: &str) -> Vec<ParsedMention> {
    let mut mentions = Vec::new();
    let mut seen = std::collections::HashSet::new();

    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '@' && (i == 0 || !chars[i - 1].is_alphanumeric()) {
            let start = i + 1;
            let mut end = start;
            while end < chars.len()
                && (chars[end].is_alphanumeric() || chars[end] == '_' || chars[end] == '-')
            {
                end += 1;
            }
            if end > start {
                let username: String = chars[start..end].iter().collect();
                if end < chars.len() && chars[end] == '@' {
                    let domain_start = end + 1;
                    let mut domain_end = domain_start;
                    while domain_end < chars.len()
                        && (chars[domain_end].is_alphanumeric()
                            || chars[domain_end] == '.'
                            || chars[domain_end] == '-')
                    {
                        domain_end += 1;
                    }
                    if domain_end > domain_start {
                        let domain_str: String =
                            chars[domain_start..domain_end].iter().collect();
                        let key = format!(
                            "{}@{}",
                            username.to_lowercase(),
                            domain_str.to_lowercase()
                        );
                        if seen.insert(key) {
                            mentions.push(ParsedMention {
                                username: username.clone(),
                                domain: Some(domain_str),
                            });
                        }
                        i = domain_end;
                        continue;
                    }
                }
                let key = username.to_lowercase();
                if seen.insert(key) {
                    mentions.push(ParsedMention {
                        username,
                        domain: None,
                    });
                }
                i = end;
                continue;
            }
        }
        i += 1;
    }
    mentions
}

/// Find `#word` patterns in text.
fn parse_hashtags(text: &str) -> Vec<String> {
    let mut tags = Vec::new();
    let mut seen = std::collections::HashSet::new();

    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '#' && (i == 0 || !chars[i - 1].is_alphanumeric()) {
            let start = i + 1;
            let mut end = start;
            while end < chars.len() && (chars[end].is_alphanumeric() || chars[end] == '_') {
                end += 1;
            }
            if end > start {
                let tag: String = chars[start..end].iter().collect();
                let lower = tag.to_lowercase();
                if seen.insert(lower) {
                    tags.push(tag);
                }
            }
            i = end;
        } else {
            i += 1;
        }
    }
    tags
}

// ---------------------------------------------------------------------------
// Status serialization
// ---------------------------------------------------------------------------

#[derive(sqlx::FromRow)]
struct PostRow {
    id: i64,
    account_id: i64,
    in_reply_to_id: Option<i64>,
    boost_of_id: Option<i64>,
    #[allow(dead_code)]
    content: String,
    content_html: String,
    spoiler_text: String,
    visibility: String,
    sensitive: bool,
    language: Option<String>,
    created_at: i64,
    edited_at: Option<i64>,
}

const POST_COLUMNS: &str =
    "id, account_id, in_reply_to_id, boost_of_id, content, content_html, \
     spoiler_text, visibility, sensitive, language, created_at, edited_at";

/// Build the Mastodon Status JSON for a local post.
#[allow(clippy::too_many_arguments)]
fn serialize_status(
    post: &PostRow,
    account_json: &Value,
    username: &str,
    domain: &str,
    app_name: &str,
    app_website: Option<&str>,
    media_attachments: &[Value],
    mention_values: &[Value],
    tag_values: &[Value],
    reblog: Option<Value>,
    favourited: bool,
    reblogged: bool,
    muted: bool,
    bookmarked: bool,
    pinned: bool,
) -> Value {
    let id_str = post.id.to_string();
    let created = millis_to_iso(post.created_at);
    let edited = post.edited_at.map(millis_to_iso);
    let uri = format!("https://{domain}/users/{username}/statuses/{id_str}");
    let url = format!("https://{domain}/@{username}/{id_str}");

    let in_reply_to_id = post
        .in_reply_to_id
        .map(|id| Value::String(id.to_string()));
    // ponytail: in_reply_to_account_id requires a join; leave null for now
    let in_reply_to_account_id: Option<Value> = None;

    json!({
        "id": id_str,
        "created_at": created,
        "in_reply_to_id": in_reply_to_id,
        "in_reply_to_account_id": in_reply_to_account_id,
        "sensitive": post.sensitive,
        "spoiler_text": post.spoiler_text,
        "visibility": post.visibility,
        "language": post.language.as_deref().unwrap_or("en"),
        "uri": uri,
        "url": url,
        "replies_count": 0,
        "reblogs_count": 0,
        "favourites_count": 0,
        "favourited": favourited,
        "reblogged": reblogged,
        "muted": muted,
        "bookmarked": bookmarked,
        "pinned": pinned,
        "text": null,
        "content": post.content_html,
        "reblog": reblog,
        "application": {
            "name": app_name,
            "website": app_website
        },
        "account": account_json,
        "media_attachments": media_attachments,
        "mentions": mention_values,
        "tags": tag_values,
        "emojis": [],
        "card": null,
        "poll": null,
        "edited_at": edited
    })
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct CreateStatusRequest {
    status: Option<String>,
    media_ids: Option<Vec<String>>,
    in_reply_to_id: Option<String>,
    sensitive: Option<bool>,
    spoiler_text: Option<String>,
    visibility: Option<String>,
    language: Option<String>,
}

#[derive(Deserialize)]
struct PaginationParams {
    max_id: Option<String>,
    since_id: Option<String>,
    min_id: Option<String>,
    limit: Option<i64>,
}

#[derive(Deserialize)]
struct PublicTimelineParams {
    #[allow(dead_code)]
    local: Option<bool>,
    #[serde(flatten)]
    pagination: PaginationParams,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sha256_hex(data: &[u8]) -> String {
    hex_encode(&Sha256::digest(data))
}

/// Build tag JSON values for the Status response.
fn tag_values_for_post(tags: &[String], domain: &str) -> Vec<Value> {
    tags.iter()
        .map(|tag| {
            json!({
                "name": tag,
                "url": format!("https://{domain}/tags/{tag}")
            })
        })
        .collect()
}

fn media_type_from_mime(mime: &str) -> &str {
    if mime.starts_with("image/") {
        "image"
    } else if mime.starts_with("video/") {
        "video"
    } else if mime.starts_with("audio/") {
        "audio"
    } else {
        "unknown"
    }
}

/// Fetch a post and build a full Status JSON for it.
#[allow(clippy::type_complexity)]
async fn load_status(
    pool: &SqlitePool,
    post: &PostRow,
    domain: &str,
    viewer_account_id: Option<i64>,
) -> Result<Value, AppError> {
    let account = fetch_account_row(pool, post.account_id).await?;
    let account_json = account_to_json(&account, domain);

    // Fetch media attachments
    let media: Vec<(i64, String, String, Option<i32>, Option<i32>, Option<String>, String)> =
        sqlx::query_as(
            "SELECT id, file_path, mime_type, width, height, blurhash, description
             FROM media WHERE post_id = ? ORDER BY id",
        )
        .bind(post.id)
        .fetch_all(pool)
        .await?;

    let media_values: Vec<Value> = media
        .iter()
        .map(
            |(id, file_path, mime_type, width, height, blurhash, description)| {
                json!({
                    "id": id.to_string(),
                    "type": media_type_from_mime(mime_type),
                    "url": format!("https://{domain}/media/{file_path}"),
                    "preview_url": format!("https://{domain}/media/{file_path}"),
                    "remote_url": null,
                    "meta": {
                        "original": {
                            "width": width,
                            "height": height
                        }
                    },
                    "description": description,
                    "blurhash": blurhash
                })
            },
        )
        .collect();

    // Fetch tags
    let tags: Vec<(String,)> =
        sqlx::query_as("SELECT tag FROM post_tags WHERE post_id = ?")
            .bind(post.id)
            .fetch_all(pool)
            .await?;
    let tag_strings: Vec<String> = tags.into_iter().map(|(t,)| t).collect();
    let tag_vals = tag_values_for_post(&tag_strings, domain);

    // Fetch mentions for display
    let mention_rows: Vec<(Option<i64>, Option<i64>)> = sqlx::query_as(
        "SELECT mentioned_account_id, mentioned_remote_id FROM mentions WHERE post_id = ?",
    )
    .bind(post.id)
    .fetch_all(pool)
    .await?;

    let mut mention_vals = Vec::new();
    for (local_id, remote_id) in &mention_rows {
        if let Some(aid) = local_id {
            if let Ok(a) = fetch_account_row(pool, *aid).await {
                mention_vals.push(json!({
                    "id": a.id.to_string(),
                    "username": a.username,
                    "acct": a.username,
                    "url": format!("https://{domain}/@{}", a.username)
                }));
            }
        } else if let Some(rid) = remote_id {
            let remote: Option<(i64, String, String)> = sqlx::query_as(
                "SELECT id, username, domain FROM remote_accounts WHERE id = ?",
            )
            .bind(rid)
            .fetch_optional(pool)
            .await?;
            if let Some((id, username, rdomain)) = remote {
                mention_vals.push(json!({
                    "id": id.to_string(),
                    "username": username,
                    "acct": format!("{username}@{rdomain}"),
                    "url": format!("https://{rdomain}/@{username}")
                }));
            }
        }
    }

    // Check viewer interactions
    let (favourited, reblogged, bookmarked) = if let Some(viewer) = viewer_account_id {
        let fav: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM favourites WHERE account_id = ? AND post_id = ?",
        )
        .bind(viewer)
        .bind(post.id)
        .fetch_one(pool)
        .await?;

        let boost: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM posts WHERE account_id = ? AND boost_of_id = ?",
        )
        .bind(viewer)
        .bind(post.id)
        .fetch_one(pool)
        .await?;

        let bmark: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM bookmarks WHERE account_id = ? AND post_id = ?",
        )
        .bind(viewer)
        .bind(post.id)
        .fetch_one(pool)
        .await?;

        (fav.0 > 0, boost.0 > 0, bmark.0 > 0)
    } else {
        (false, false, false)
    };

    // Handle reblog (boost_of_id)
    let reblog_value = if let Some(boost_id) = post.boost_of_id {
        let boosted: Option<PostRow> = sqlx::query_as::<_, PostRow>(&format!(
            "SELECT {POST_COLUMNS} FROM posts WHERE id = ?"
        ))
        .bind(boost_id)
        .fetch_optional(pool)
        .await?;
        if let Some(bp) = &boosted {
            Some(Box::pin(load_status(pool, bp, domain, viewer_account_id)).await?)
        } else {
            None
        }
    } else {
        None
    };

    Ok(serialize_status(
        post,
        &account_json,
        &account.username,
        domain,
        "Web",
        None,
        &media_values,
        &mention_vals,
        &tag_vals,
        reblog_value,
        favourited,
        reblogged,
        false, // muted
        bookmarked,
        false, // pinned
    ))
}

/// Build a `Link` header with `rel="next"` and `rel="prev"`.
fn pagination_link_header(url_base: &str, items: &[Value]) -> Option<String> {
    if items.is_empty() {
        return None;
    }
    let first_id = items.first()?.get("id")?.as_str()?;
    let last_id = items.last()?.get("id")?.as_str()?;

    let next = format!("<{url_base}?max_id={last_id}>; rel=\"next\"");
    let prev = format!("<{url_base}?min_id={first_id}>; rel=\"prev\"");
    Some(format!("{next}, {prev}"))
}

/// Apply pagination WHERE clauses. Returns (where_clause, bind_values).
fn pagination_clause(params: &PaginationParams) -> (String, Vec<i64>) {
    let mut clauses = Vec::new();
    let mut binds = Vec::new();

    if let Some(ref max_id) = params.max_id {
        if let Ok(v) = max_id.parse::<i64>() {
            clauses.push("id < ?".to_string());
            binds.push(v);
        }
    }
    if let Some(ref since_id) = params.since_id {
        if let Ok(v) = since_id.parse::<i64>() {
            clauses.push("id > ?".to_string());
            binds.push(v);
        }
    }
    if let Some(ref min_id) = params.min_id {
        if let Ok(v) = min_id.parse::<i64>() {
            clauses.push("id > ?".to_string());
            binds.push(v);
        }
    }

    let clause = if clauses.is_empty() {
        String::new()
    } else {
        format!(" AND {}", clauses.join(" AND "))
    };

    (clause, binds)
}

/// Fetch posts with dynamic pagination and return Status JSON values.
async fn fetch_paginated_statuses(
    pool: &SqlitePool,
    base_where: &str,
    base_binds: &[i64],
    params: &PaginationParams,
    domain: &str,
    viewer_account_id: Option<i64>,
    order_asc: bool,
) -> Result<Vec<Value>, AppError> {
    let (page_clause, page_binds) = pagination_clause(params);
    let limit = params.limit.unwrap_or(20).clamp(1, 40);

    let order = if order_asc || params.min_id.is_some() {
        "ASC"
    } else {
        "DESC"
    };

    let sql = format!(
        "SELECT {POST_COLUMNS} FROM posts WHERE {base_where}{page_clause} \
         ORDER BY id {order} LIMIT ?",
    );

    let mut query = sqlx::query_as::<_, PostRow>(&sql);
    for b in base_binds {
        query = query.bind(b);
    }
    for b in &page_binds {
        query = query.bind(b);
    }
    query = query.bind(limit);

    let posts: Vec<PostRow> = query.fetch_all(pool).await?;

    let mut statuses = Vec::with_capacity(posts.len());
    for p in &posts {
        let status = load_status(pool, p, domain, viewer_account_id).await?;
        statuses.push(status);
    }

    if params.min_id.is_some() && !order_asc {
        statuses.reverse();
    }

    Ok(statuses)
}

// ---------------------------------------------------------------------------
// POST /api/v1/statuses
// ---------------------------------------------------------------------------

async fn create_status(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    headers: HeaderMap,
    Json(body): Json<CreateStatusRequest>,
) -> Result<Response, AppError> {
    let domain = &state.config.server.domain;

    // Check idempotency key
    if let Some(idem_key) = headers
        .get("Idempotency-Key")
        .and_then(|v| v.to_str().ok())
    {
        let key_hash = sha256_hex(idem_key.as_bytes());
        let existing: Option<(i64,)> = sqlx::query_as(
            "SELECT post_id FROM idempotency_keys WHERE key_hash = ? AND account_id = ?",
        )
        .bind(&key_hash)
        .bind(auth.account_id)
        .fetch_optional(&state.pool)
        .await?;

        if let Some((post_id,)) = existing {
            let post = sqlx::query_as::<_, PostRow>(&format!(
                "SELECT {POST_COLUMNS} FROM posts WHERE id = ?"
            ))
            .bind(post_id)
            .fetch_optional(&state.pool)
            .await?
            .ok_or_else(|| AppError::not_found("Post not found"))?;

            let status =
                load_status(&state.pool, &post, domain, Some(auth.account_id)).await?;
            return Ok((StatusCode::OK, Json(status)).into_response());
        }
    }

    let text = body.status.as_deref().unwrap_or("").to_string();

    let media_ids: Vec<i64> = body
        .media_ids
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .filter_map(|s| s.parse::<i64>().ok())
        .collect();

    if text.is_empty() && media_ids.is_empty() {
        return Err(AppError::unprocessable(
            "Validation failed: status text or media is required",
        ));
    }

    if text.len() > state.config.limits.max_post_chars {
        return Err(AppError::unprocessable(format!(
            "Validation failed: status text must be at most {} characters",
            state.config.limits.max_post_chars
        )));
    }

    let visibility = body
        .visibility
        .as_deref()
        .unwrap_or(&state.config.defaults.default_visibility)
        .to_string();
    if !matches!(
        visibility.as_str(),
        "public" | "unlisted" | "private" | "direct"
    ) {
        return Err(AppError::unprocessable(
            "Validation failed: visibility must be one of public, unlisted, private, direct",
        ));
    }

    let sensitive = body
        .sensitive
        .unwrap_or(state.config.defaults.default_sensitive);
    let spoiler_text = body.spoiler_text.as_deref().unwrap_or("").to_string();
    let language = body
        .language
        .clone()
        .or_else(|| Some(state.config.defaults.default_language.clone()));

    let in_reply_to_id: Option<i64> = body
        .in_reply_to_id
        .as_ref()
        .and_then(|s| s.parse::<i64>().ok());

    let rendered = render_content(&text, domain);

    let post_id = generate_id();
    let now = now_millis();
    let ap_id = format!(
        "https://{domain}/users/{}/statuses/{post_id}",
        auth.username
    );

    sqlx::query(
        "INSERT INTO posts (id, account_id, ap_id, in_reply_to_id, content, content_html, \
         spoiler_text, visibility, sensitive, language, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(post_id)
    .bind(auth.account_id)
    .bind(&ap_id)
    .bind(in_reply_to_id)
    .bind(&text)
    .bind(&rendered.html)
    .bind(&spoiler_text)
    .bind(&visibility)
    .bind(sensitive)
    .bind(&language)
    .bind(now)
    .execute(&state.pool)
    .await?;

    // Attach media
    for mid in &media_ids {
        sqlx::query(
            "UPDATE media SET post_id = ? WHERE id = ? AND account_id = ? AND post_id IS NULL",
        )
        .bind(post_id)
        .bind(mid)
        .bind(auth.account_id)
        .execute(&state.pool)
        .await?;
    }

    // Insert mentions
    for m in &rendered.mentions {
        match &m.domain {
            None => {
                let local: Option<(i64,)> =
                    sqlx::query_as("SELECT id FROM accounts WHERE username = ?")
                        .bind(&m.username)
                        .fetch_optional(&state.pool)
                        .await?;
                if let Some((aid,)) = local {
                    sqlx::query(
                        "INSERT OR IGNORE INTO mentions (post_id, mentioned_account_id) \
                         VALUES (?, ?)",
                    )
                    .bind(post_id)
                    .bind(aid)
                    .execute(&state.pool)
                    .await?;

                    // Notification for local mention
                    let notif_id = generate_id();
                    sqlx::query(
                        "INSERT INTO notifications \
                         (id, account_id, kind, from_account_id, post_id, created_at) \
                         VALUES (?, ?, 'mention', ?, ?, ?)",
                    )
                    .bind(notif_id)
                    .bind(aid)
                    .bind(auth.account_id)
                    .bind(post_id)
                    .bind(now)
                    .execute(&state.pool)
                    .await?;
                }
            }
            Some(mention_domain) => {
                let remote: Option<(i64,)> = sqlx::query_as(
                    "SELECT id FROM remote_accounts WHERE username = ? AND domain = ?",
                )
                .bind(&m.username)
                .bind(mention_domain)
                .fetch_optional(&state.pool)
                .await?;
                if let Some((rid,)) = remote {
                    sqlx::query(
                        "INSERT OR IGNORE INTO mentions (post_id, mentioned_remote_id) \
                         VALUES (?, ?)",
                    )
                    .bind(post_id)
                    .bind(rid)
                    .execute(&state.pool)
                    .await?;
                }
            }
        }
    }

    // Insert tags
    for tag in &rendered.tags {
        sqlx::query("INSERT OR IGNORE INTO post_tags (post_id, tag) VALUES (?, ?)")
            .bind(post_id)
            .bind(tag)
            .execute(&state.pool)
            .await?;
    }

    // Store idempotency key
    if let Some(idem_key) = headers
        .get("Idempotency-Key")
        .and_then(|v| v.to_str().ok())
    {
        let key_hash = sha256_hex(idem_key.as_bytes());
        sqlx::query(
            "INSERT OR IGNORE INTO idempotency_keys (key_hash, account_id, post_id, created_at) \
             VALUES (?, ?, ?, ?)",
        )
        .bind(&key_hash)
        .bind(auth.account_id)
        .bind(post_id)
        .bind(now)
        .execute(&state.pool)
        .await?;
    }

    // Update last_status_at
    sqlx::query("UPDATE accounts SET last_status_at = ? WHERE id = ?")
        .bind(now)
        .bind(auth.account_id)
        .execute(&state.pool)
        .await?;

    // Build response
    let post = sqlx::query_as::<_, PostRow>(&format!(
        "SELECT {POST_COLUMNS} FROM posts WHERE id = ?"
    ))
    .bind(post_id)
    .fetch_one(&state.pool)
    .await?;

    let status =
        load_status(&state.pool, &post, domain, Some(auth.account_id)).await?;
    Ok((StatusCode::OK, Json(status)).into_response())
}

// ---------------------------------------------------------------------------
// DELETE /api/v1/statuses/:id
// ---------------------------------------------------------------------------

async fn delete_status(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let post_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("Status not found"))?;

    let domain = &state.config.server.domain;

    let post = sqlx::query_as::<_, PostRow>(&format!(
        "SELECT {POST_COLUMNS} FROM posts WHERE id = ?"
    ))
    .bind(post_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::not_found("Status not found"))?;

    if post.account_id != auth.account_id {
        return Err(AppError::forbidden("You do not own this status"));
    }

    // Build response before deletion (Mastodon returns the deleted status)
    let status =
        load_status(&state.pool, &post, domain, Some(auth.account_id)).await?;

    // Enqueue Delete activity for federation
    let ap_id = format!(
        "https://{domain}/users/{}/statuses/{post_id}",
        auth.username
    );
    let delete_activity = json!({
        "@context": "https://www.w3.org/ns/activitystreams",
        "id": format!("{ap_id}#delete"),
        "type": "Delete",
        "actor": format!("https://{domain}/users/{}", auth.username),
        "to": ["https://www.w3.org/ns/activitystreams#Public"],
        "object": {
            "id": ap_id,
            "type": "Tombstone"
        }
    });

    if let Err(e) =
        enqueue_to_followers(&state.pool, auth.account_id, &delete_activity).await
    {
        tracing::error!("Failed to enqueue delete activity: {e}");
    }

    // Delete related rows then the post
    for table in &[
        "DELETE FROM post_tags WHERE post_id = ?",
        "DELETE FROM mentions WHERE post_id = ?",
        "DELETE FROM favourites WHERE post_id = ?",
        "DELETE FROM bookmarks WHERE post_id = ?",
        "DELETE FROM notifications WHERE post_id = ?",
        "DELETE FROM idempotency_keys WHERE post_id = ?",
    ] {
        sqlx::query(table)
            .bind(post_id)
            .execute(&state.pool)
            .await?;
    }
    sqlx::query("UPDATE media SET post_id = NULL WHERE post_id = ?")
        .bind(post_id)
        .execute(&state.pool)
        .await?;
    sqlx::query("DELETE FROM posts WHERE id = ?")
        .bind(post_id)
        .execute(&state.pool)
        .await?;

    Ok((StatusCode::OK, Json(status)).into_response())
}

// ---------------------------------------------------------------------------
// GET /api/v1/statuses/:id
// ---------------------------------------------------------------------------

async fn get_status(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let post_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("Status not found"))?;

    let domain = &state.config.server.domain;

    let post = sqlx::query_as::<_, PostRow>(&format!(
        "SELECT {POST_COLUMNS} FROM posts WHERE id = ?"
    ))
    .bind(post_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::not_found("Status not found"))?;

    let status = load_status(&state.pool, &post, domain, None).await?;
    Ok(Json(status))
}

// ---------------------------------------------------------------------------
// GET /api/v1/statuses/:id/context
// ---------------------------------------------------------------------------

async fn status_context(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let post_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("Status not found"))?;

    let domain = &state.config.server.domain;

    let target = sqlx::query_as::<_, PostRow>(&format!(
        "SELECT {POST_COLUMNS} FROM posts WHERE id = ?"
    ))
    .bind(post_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::not_found("Status not found"))?;

    // Ancestors: walk up the reply chain
    let mut ancestors = Vec::new();
    let mut current_id = target.in_reply_to_id;
    while let Some(parent_id) = current_id {
        let parent = sqlx::query_as::<_, PostRow>(&format!(
            "SELECT {POST_COLUMNS} FROM posts WHERE id = ?"
        ))
        .bind(parent_id)
        .fetch_optional(&state.pool)
        .await?;

        match parent {
            Some(p) => {
                current_id = p.in_reply_to_id;
                let s = load_status(&state.pool, &p, domain, None).await?;
                ancestors.push(s);
            }
            None => break,
        }
    }
    ancestors.reverse();

    // Descendants: recursive CTE
    let descendants_posts: Vec<PostRow> = sqlx::query_as::<_, PostRow>(&format!(
        "WITH RECURSIVE thread(id) AS ( \
            SELECT id FROM posts WHERE in_reply_to_id = ? \
            UNION ALL \
            SELECT p.id FROM posts p JOIN thread t ON p.in_reply_to_id = t.id \
         ) \
         SELECT p.{POST_COLUMNS} FROM thread t JOIN posts p ON t.id = p.id \
         ORDER BY p.id ASC",
        POST_COLUMNS = POST_COLUMNS.replace(", ", ", p.")
    ))
    .bind(post_id)
    .fetch_all(&state.pool)
    .await
    // ponytail: if the CTE alias fails, fall back to the simple form
    .or_else(|_| -> Result<Vec<PostRow>, AppError> { Ok(vec![]) })?;

    let mut descendants = Vec::with_capacity(descendants_posts.len());
    for p in &descendants_posts {
        let s = load_status(&state.pool, p, domain, None).await?;
        descendants.push(s);
    }

    Ok(Json(json!({
        "ancestors": ancestors,
        "descendants": descendants
    })))
}

// ---------------------------------------------------------------------------
// Interactions
// ---------------------------------------------------------------------------

async fn favourite(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let post_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("Status not found"))?;
    let domain = &state.config.server.domain;
    let now = now_millis();

    let post = sqlx::query_as::<_, PostRow>(&format!(
        "SELECT {POST_COLUMNS} FROM posts WHERE id = ?"
    ))
    .bind(post_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::not_found("Status not found"))?;

    sqlx::query(
        "INSERT OR IGNORE INTO favourites (account_id, post_id, created_at) VALUES (?, ?, ?)",
    )
    .bind(auth.account_id)
    .bind(post_id)
    .bind(now)
    .execute(&state.pool)
    .await?;

    if post.account_id != auth.account_id {
        let notif_id = generate_id();
        sqlx::query(
            "INSERT INTO notifications \
             (id, account_id, kind, from_account_id, post_id, created_at) \
             VALUES (?, ?, 'favourite', ?, ?, ?)",
        )
        .bind(notif_id)
        .bind(post.account_id)
        .bind(auth.account_id)
        .bind(post_id)
        .bind(now)
        .execute(&state.pool)
        .await?;
    }

    let status =
        load_status(&state.pool, &post, domain, Some(auth.account_id)).await?;
    Ok(Json(status))
}

async fn unfavourite(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let post_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("Status not found"))?;
    let domain = &state.config.server.domain;

    let post = sqlx::query_as::<_, PostRow>(&format!(
        "SELECT {POST_COLUMNS} FROM posts WHERE id = ?"
    ))
    .bind(post_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::not_found("Status not found"))?;

    sqlx::query("DELETE FROM favourites WHERE account_id = ? AND post_id = ?")
        .bind(auth.account_id)
        .bind(post_id)
        .execute(&state.pool)
        .await?;

    let status =
        load_status(&state.pool, &post, domain, Some(auth.account_id)).await?;
    Ok(Json(status))
}

async fn reblog(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let post_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("Status not found"))?;
    let domain = &state.config.server.domain;
    let now = now_millis();

    let original = sqlx::query_as::<_, PostRow>(&format!(
        "SELECT {POST_COLUMNS} FROM posts WHERE id = ?"
    ))
    .bind(post_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::not_found("Status not found"))?;

    // Check for existing reblog
    let existing: Option<(i64,)> = sqlx::query_as(
        "SELECT id FROM posts WHERE account_id = ? AND boost_of_id = ?",
    )
    .bind(auth.account_id)
    .bind(post_id)
    .fetch_optional(&state.pool)
    .await?;

    let boost_id = if let Some((eid,)) = existing {
        eid
    } else {
        let new_id = generate_id();
        let ap_id = format!(
            "https://{domain}/users/{}/statuses/{new_id}",
            auth.username
        );

        sqlx::query(
            "INSERT INTO posts (id, account_id, ap_id, boost_of_id, content, content_html, \
             visibility, created_at) VALUES (?, ?, ?, ?, '', '', 'public', ?)",
        )
        .bind(new_id)
        .bind(auth.account_id)
        .bind(&ap_id)
        .bind(post_id)
        .bind(now)
        .execute(&state.pool)
        .await?;

        if original.account_id != auth.account_id {
            let notif_id = generate_id();
            sqlx::query(
                "INSERT INTO notifications \
                 (id, account_id, kind, from_account_id, post_id, created_at) \
                 VALUES (?, ?, 'reblog', ?, ?, ?)",
            )
            .bind(notif_id)
            .bind(original.account_id)
            .bind(auth.account_id)
            .bind(post_id)
            .bind(now)
            .execute(&state.pool)
            .await?;
        }

        new_id
    };

    let boost_post = sqlx::query_as::<_, PostRow>(&format!(
        "SELECT {POST_COLUMNS} FROM posts WHERE id = ?"
    ))
    .bind(boost_id)
    .fetch_one(&state.pool)
    .await?;

    let status =
        load_status(&state.pool, &boost_post, domain, Some(auth.account_id)).await?;
    Ok(Json(status))
}

async fn unreblog(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let post_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("Status not found"))?;
    let domain = &state.config.server.domain;

    let boost: Option<(i64,)> = sqlx::query_as(
        "SELECT id FROM posts WHERE account_id = ? AND boost_of_id = ?",
    )
    .bind(auth.account_id)
    .bind(post_id)
    .fetch_optional(&state.pool)
    .await?;

    if let Some((boost_id,)) = boost {
        sqlx::query("DELETE FROM posts WHERE id = ?")
            .bind(boost_id)
            .execute(&state.pool)
            .await?;
    }

    let post = sqlx::query_as::<_, PostRow>(&format!(
        "SELECT {POST_COLUMNS} FROM posts WHERE id = ?"
    ))
    .bind(post_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::not_found("Status not found"))?;

    let status =
        load_status(&state.pool, &post, domain, Some(auth.account_id)).await?;
    Ok(Json(status))
}

async fn bookmark(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let post_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("Status not found"))?;
    let domain = &state.config.server.domain;
    let now = now_millis();

    let post = sqlx::query_as::<_, PostRow>(&format!(
        "SELECT {POST_COLUMNS} FROM posts WHERE id = ?"
    ))
    .bind(post_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::not_found("Status not found"))?;

    sqlx::query(
        "INSERT OR IGNORE INTO bookmarks (account_id, post_id, created_at) VALUES (?, ?, ?)",
    )
    .bind(auth.account_id)
    .bind(post_id)
    .bind(now)
    .execute(&state.pool)
    .await?;

    let status =
        load_status(&state.pool, &post, domain, Some(auth.account_id)).await?;
    Ok(Json(status))
}

async fn unbookmark(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let post_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("Status not found"))?;
    let domain = &state.config.server.domain;

    let post = sqlx::query_as::<_, PostRow>(&format!(
        "SELECT {POST_COLUMNS} FROM posts WHERE id = ?"
    ))
    .bind(post_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::not_found("Status not found"))?;

    sqlx::query("DELETE FROM bookmarks WHERE account_id = ? AND post_id = ?")
        .bind(auth.account_id)
        .bind(post_id)
        .execute(&state.pool)
        .await?;

    let status =
        load_status(&state.pool, &post, domain, Some(auth.account_id)).await?;
    Ok(Json(status))
}

// ---------------------------------------------------------------------------
// Timelines
// ---------------------------------------------------------------------------

async fn timeline_home(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Query(params): Query<PaginationParams>,
) -> Result<Response, AppError> {
    let domain = &state.config.server.domain;

    let base_where = "(account_id = ? OR account_id IN \
        (SELECT followee_id FROM follows WHERE follower_id = ? AND followee_id IS NOT NULL))";
    let base_binds = vec![auth.account_id, auth.account_id];

    let statuses = fetch_paginated_statuses(
        &state.pool,
        base_where,
        &base_binds,
        &params,
        domain,
        Some(auth.account_id),
        false,
    )
    .await?;

    let url_base = format!("https://{domain}/api/v1/timelines/home");
    let mut response = Json(&statuses).into_response();
    if let Some(link) = pagination_link_header(&url_base, &statuses) {
        response
            .headers_mut()
            .insert("Link", link.parse().unwrap());
    }
    Ok(response)
}

async fn timeline_public(
    State(state): State<Arc<AppState>>,
    Query(params): Query<PublicTimelineParams>,
) -> Result<Response, AppError> {
    let domain = &state.config.server.domain;

    let base_where = "visibility = 'public' AND boost_of_id IS NULL";
    let base_binds: Vec<i64> = vec![];

    let statuses = fetch_paginated_statuses(
        &state.pool,
        base_where,
        &base_binds,
        &params.pagination,
        domain,
        None,
        false,
    )
    .await?;

    let url_base = format!("https://{domain}/api/v1/timelines/public");
    let mut response = Json(&statuses).into_response();
    if let Some(link) = pagination_link_header(&url_base, &statuses) {
        response
            .headers_mut()
            .insert("Link", link.parse().unwrap());
    }
    Ok(response)
}

async fn timeline_tag(
    State(state): State<Arc<AppState>>,
    Path(tag): Path<String>,
    Query(params): Query<PaginationParams>,
) -> Result<Response, AppError> {
    let domain = &state.config.server.domain;
    let tag_lower = tag.to_lowercase();

    let base_where =
        "visibility = 'public' AND id IN (SELECT post_id FROM post_tags WHERE tag = ?)";

    let (page_clause, page_binds) = pagination_clause(&params);
    let limit = params.limit.unwrap_or(20).clamp(1, 40);
    let order = if params.min_id.is_some() {
        "ASC"
    } else {
        "DESC"
    };

    let sql = format!(
        "SELECT {POST_COLUMNS} FROM posts WHERE {base_where}{page_clause} \
         ORDER BY id {order} LIMIT ?",
    );

    let mut query = sqlx::query_as::<_, PostRow>(&sql);
    query = query.bind(&tag_lower);
    for b in &page_binds {
        query = query.bind(b);
    }
    query = query.bind(limit);

    let posts: Vec<PostRow> = query.fetch_all(&state.pool).await?;

    let mut statuses = Vec::with_capacity(posts.len());
    for p in &posts {
        let status = load_status(&state.pool, p, domain, None).await?;
        statuses.push(status);
    }

    if params.min_id.is_some() {
        statuses.reverse();
    }

    let url_base = format!("https://{domain}/api/v1/timelines/tag/{tag_lower}");
    let mut response = Json(&statuses).into_response();
    if let Some(link) = pagination_link_header(&url_base, &statuses) {
        response
            .headers_mut()
            .insert("Link", link.parse().unwrap());
    }
    Ok(response)
}

// ---------------------------------------------------------------------------
// Notifications
// ---------------------------------------------------------------------------

#[derive(sqlx::FromRow)]
struct NotificationRow {
    id: i64,
    #[allow(dead_code)]
    account_id: i64,
    kind: String,
    from_account_id: Option<i64>,
    from_remote_account_id: Option<i64>,
    post_id: Option<i64>,
    created_at: i64,
}

async fn serialize_notification(
    pool: &SqlitePool,
    notif: &NotificationRow,
    domain: &str,
    viewer_account_id: i64,
) -> Result<Value, AppError> {
    let from_account = if let Some(aid) = notif.from_account_id {
        let a = fetch_account_row(pool, aid).await?;
        account_to_json(&a, domain)
    } else if let Some(rid) = notif.from_remote_account_id {
        let remote: Option<(i64, String, String, String, String)> = sqlx::query_as(
            "SELECT id, username, domain, display_name, bio_html \
             FROM remote_accounts WHERE id = ?",
        )
        .bind(rid)
        .fetch_optional(pool)
        .await?;
        if let Some((id, username, rdomain, display_name, bio_html)) = remote {
            json!({
                "id": id.to_string(),
                "username": username,
                "acct": format!("{username}@{rdomain}"),
                "display_name": display_name,
                "locked": false,
                "bot": false,
                "discoverable": true,
                "group": false,
                "created_at": "1970-01-01T00:00:00.000Z",
                "note": bio_html,
                "url": format!("https://{rdomain}/@{username}"),
                "uri": format!("https://{rdomain}/users/{username}"),
                "avatar": "",
                "avatar_static": "",
                "header": "",
                "header_static": "",
                "followers_count": 0,
                "following_count": 0,
                "statuses_count": 0,
                "last_status_at": null,
                "noindex": false,
                "emojis": [],
                "roles": [],
                "fields": []
            })
        } else {
            json!(null)
        }
    } else {
        json!(null)
    };

    let status = if let Some(pid) = notif.post_id {
        let post = sqlx::query_as::<_, PostRow>(&format!(
            "SELECT {POST_COLUMNS} FROM posts WHERE id = ?"
        ))
        .bind(pid)
        .fetch_optional(pool)
        .await?;
        if let Some(p) = &post {
            Some(load_status(pool, p, domain, Some(viewer_account_id)).await?)
        } else {
            None
        }
    } else {
        None
    };

    Ok(json!({
        "id": notif.id.to_string(),
        "type": notif.kind,
        "created_at": millis_to_iso(notif.created_at),
        "account": from_account,
        "status": status
    }))
}

async fn get_notifications(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Query(params): Query<PaginationParams>,
) -> Result<Response, AppError> {
    let domain = &state.config.server.domain;
    let (page_clause, page_binds) = pagination_clause(&params);
    let limit = params.limit.unwrap_or(15).clamp(1, 30);

    let order = if params.min_id.is_some() {
        "ASC"
    } else {
        "DESC"
    };

    let sql = format!(
        "SELECT id, account_id, kind, from_account_id, from_remote_account_id, \
         post_id, created_at \
         FROM notifications WHERE account_id = ?{page_clause} \
         ORDER BY id {order} LIMIT ?",
    );

    let mut query = sqlx::query_as::<_, NotificationRow>(&sql);
    query = query.bind(auth.account_id);
    for b in &page_binds {
        query = query.bind(b);
    }
    query = query.bind(limit);

    let notifs: Vec<NotificationRow> = query.fetch_all(&state.pool).await?;

    let mut values = Vec::with_capacity(notifs.len());
    for n in &notifs {
        let v =
            serialize_notification(&state.pool, n, domain, auth.account_id).await?;
        values.push(v);
    }

    if params.min_id.is_some() {
        values.reverse();
    }

    let url_base = format!("https://{domain}/api/v1/notifications");
    let mut response = Json(&values).into_response();
    if let Some(link) = pagination_link_header(&url_base, &values) {
        response
            .headers_mut()
            .insert("Link", link.parse().unwrap());
    }
    Ok(response)
}

async fn get_notification(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let notif_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("Notification not found"))?;

    let domain = &state.config.server.domain;

    let notif = sqlx::query_as::<_, NotificationRow>(
        "SELECT id, account_id, kind, from_account_id, from_remote_account_id, \
         post_id, created_at \
         FROM notifications WHERE id = ? AND account_id = ?",
    )
    .bind(notif_id)
    .bind(auth.account_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::not_found("Notification not found"))?;

    let value =
        serialize_notification(&state.pool, &notif, domain, auth.account_id).await?;
    Ok(Json(value))
}

async fn clear_notifications(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
) -> Result<Json<Value>, AppError> {
    sqlx::query("DELETE FROM notifications WHERE account_id = ?")
        .bind(auth.account_id)
        .execute(&state.pool)
        .await?;

    Ok(Json(json!({})))
}

async fn dismiss_notification(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let notif_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("Notification not found"))?;

    sqlx::query("DELETE FROM notifications WHERE id = ? AND account_id = ?")
        .bind(notif_id)
        .bind(auth.account_id)
        .execute(&state.pool)
        .await?;

    Ok(Json(json!({})))
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        // Posting
        .route("/api/v1/statuses", post(create_status))
        .route(
            "/api/v1/statuses/{id}",
            get(get_status).delete(delete_status),
        )
        .route("/api/v1/statuses/{id}/context", get(status_context))
        // Interactions
        .route("/api/v1/statuses/{id}/favourite", post(favourite))
        .route("/api/v1/statuses/{id}/unfavourite", post(unfavourite))
        .route("/api/v1/statuses/{id}/reblog", post(reblog))
        .route("/api/v1/statuses/{id}/unreblog", post(unreblog))
        .route("/api/v1/statuses/{id}/bookmark", post(bookmark))
        .route("/api/v1/statuses/{id}/unbookmark", post(unbookmark))
        // Timelines
        .route("/api/v1/timelines/home", get(timeline_home))
        .route("/api/v1/timelines/public", get(timeline_public))
        .route("/api/v1/timelines/tag/{tag}", get(timeline_tag))
        // Notifications
        .route("/api/v1/notifications", get(get_notifications))
        .route("/api/v1/notifications/{id}", get(get_notification))
        .route("/api/v1/notifications/clear", post(clear_notifications))
        .route(
            "/api/v1/notifications/{id}/dismiss",
            post(dismiss_notification),
        )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_content_basic_markdown() {
        let result = render_content("Hello **world**", "example.com");
        assert!(result.html.contains("<strong>world</strong>"));
        assert!(result.mentions.is_empty());
        assert!(result.tags.is_empty());
    }

    #[test]
    fn render_content_parses_local_mention() {
        let result = render_content("Hello @alice", "example.com");
        assert_eq!(result.mentions.len(), 1);
        assert_eq!(result.mentions[0].username, "alice");
        assert!(result.mentions[0].domain.is_none());
        assert!(result.html.contains(r#"class="u-url mention"#));
        assert!(result.html.contains("https://example.com/@alice"));
    }

    #[test]
    fn render_content_parses_remote_mention() {
        let result = render_content("Hello @bob@remote.example", "example.com");
        assert_eq!(result.mentions.len(), 1);
        assert_eq!(result.mentions[0].username, "bob");
        assert_eq!(
            result.mentions[0].domain.as_deref(),
            Some("remote.example")
        );
        assert!(result.html.contains("https://remote.example/@bob"));
    }

    #[test]
    fn render_content_parses_hashtags() {
        let result = render_content("Hello #Rust #programming", "example.com");
        assert_eq!(result.tags.len(), 2);
        assert_eq!(result.tags[0], "rust");
        assert_eq!(result.tags[1], "programming");
        assert!(result.html.contains(r#"class="mention hashtag"#));
        assert!(result.html.contains("https://example.com/tags/rust"));
    }

    #[test]
    fn render_content_deduplicates_mentions() {
        let result = render_content("@alice @alice @alice", "example.com");
        assert_eq!(result.mentions.len(), 1);
    }

    #[test]
    fn render_content_deduplicates_tags() {
        let result = render_content("#Rust #rust #RUST", "example.com");
        assert_eq!(result.tags.len(), 1);
    }

    #[test]
    fn render_content_sanitizes_html() {
        let result = render_content("<script>alert('xss')</script>", "example.com");
        assert!(!result.html.contains("<script>"));
    }

    #[test]
    fn parse_mentions_at_start() {
        let mentions = parse_mentions("@user test");
        assert_eq!(mentions.len(), 1);
        assert_eq!(mentions[0].username, "user");
    }

    #[test]
    fn parse_mentions_in_middle() {
        let mentions = parse_mentions("hello @user@domain.com world");
        assert_eq!(mentions.len(), 1);
        assert_eq!(mentions[0].username, "user");
        assert_eq!(mentions[0].domain.as_deref(), Some("domain.com"));
    }

    #[test]
    fn parse_hashtags_basic() {
        let tags = parse_hashtags("hello #world");
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0], "world");
    }

    #[test]
    fn parse_hashtags_ignores_after_alphanum() {
        let tags = parse_hashtags("test");
        assert_eq!(tags.len(), 0);
    }

    #[test]
    fn sha256_hex_known_vector() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let result = sha256_hex(b"");
        assert_eq!(
            result,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn pagination_link_header_empty() {
        assert!(pagination_link_header("https://example.com/api", &[]).is_none());
    }

    #[test]
    fn pagination_link_header_builds_links() {
        let items = vec![
            json!({"id": "100"}),
            json!({"id": "99"}),
            json!({"id": "98"}),
        ];
        let link =
            pagination_link_header("https://example.com/api", &items).unwrap();
        assert!(link.contains("max_id=98"));
        assert!(link.contains("min_id=100"));
        assert!(link.contains(r#"rel="next""#));
        assert!(link.contains(r#"rel="prev""#));
    }

    #[test]
    fn serialize_status_shape() {
        let post = PostRow {
            id: 12345,
            account_id: 1,
            in_reply_to_id: None,
            boost_of_id: None,
            content: "Hello world".into(),
            content_html: "<p>Hello world</p>".into(),
            spoiler_text: String::new(),
            visibility: "public".into(),
            sensitive: false,
            language: Some("en".into()),
            created_at: 1704067200000,
            edited_at: None,
        };
        let account_json = json!({
            "id": "1",
            "username": "writer",
            "acct": "writer",
            "display_name": "Writer",
        });

        let status = serialize_status(
            &post,
            &account_json,
            "writer",
            "example.com",
            "Web",
            None,
            &[],
            &[],
            &[],
            None,
            false,
            false,
            false,
            false,
            false,
        );

        assert_eq!(status["id"], "12345");
        assert!(status["in_reply_to_id"].is_null());
        assert!(status["in_reply_to_account_id"].is_null());
        assert!(status["media_attachments"].is_array());
        assert!(status["mentions"].is_array());
        assert!(status["tags"].is_array());
        assert!(status["emojis"].is_array());
        assert!(status["reblog"].is_null());
        assert_eq!(status["content"], "<p>Hello world</p>");
        assert_eq!(
            status["uri"],
            "https://example.com/users/writer/statuses/12345"
        );
        assert_eq!(status["url"], "https://example.com/@writer/12345");
        assert_eq!(status["application"]["name"], "Web");
        assert!(status["application"]["website"].is_null());
        assert_eq!(status["visibility"], "public");
        assert_eq!(status["sensitive"], false);
        assert_eq!(status["favourited"], false);
        assert_eq!(status["reblogged"], false);
        assert_eq!(status["bookmarked"], false);
        assert!(status["edited_at"].is_null());
    }
}
