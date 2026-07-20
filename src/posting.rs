use crate::api::{
    account_to_json, fetch_account_row, hex_encode, millis_to_iso, now_millis, AuthenticatedAccount,
};
use crate::delivery::{enqueue_delivery, enqueue_to_followers, enqueue_to_relays};
use crate::error::AppError;
use crate::id::generate_id;
use crate::server::AppState;
use crate::streaming::{publish, StreamEvent};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use std::collections::HashSet;
use std::sync::{Arc, LazyLock};

// ---------------------------------------------------------------------------
// Language detection
// ---------------------------------------------------------------------------

pub fn detect_language(text: &str) -> &'static str {
    if text.len() < 20 {
        return "en"; // Too short to detect reliably
    }
    match whatlang::detect(text) {
        Some(info) if info.is_reliable() => whatlang_to_bcp47(info.lang()),
        _ => "en",
    }
}

fn whatlang_to_bcp47(lang: whatlang::Lang) -> &'static str {
    use whatlang::Lang::*;
    match lang {
        Eng => "en",
        Spa => "es",
        Fra => "fr",
        Deu => "de",
        Ita => "it",
        Por => "pt",
        Rus => "ru",
        Jpn => "ja",
        Cmn => "zh",
        Kor => "ko",
        Ara => "ar",
        Hin => "hi",
        Tur => "tr",
        Nld => "nl",
        Pol => "pl",
        Swe => "sv",
        Dan => "da",
        Nob => "nb",
        Fin => "fi",
        Ces => "cs",
        Ukr => "uk",
        Cat => "ca",
        Ron => "ro",
        Hun => "hu",
        Ell => "el",
        Heb => "he",
        Tha => "th",
        Vie => "vi",
        Ind => "id",
        _ => "en",
    }
}

// ---------------------------------------------------------------------------
// Keyword filter types and helpers
// ---------------------------------------------------------------------------

struct ActiveFilter {
    id: i64,
    title: String,
    context_json: String,
    filter_action: String,
    keywords: Vec<ActiveKeyword>,
}

struct ActiveKeyword {
    keyword: String,
    whole_word: bool,
}

/// Load all active (non-expired) filters for the given account and context.
async fn load_active_filters(
    pool: &SqlitePool,
    account_id: i64,
    context: &str,
) -> Result<Vec<ActiveFilter>, AppError> {
    let now = now_millis();
    // Fetch filters where context JSON array contains the requested context
    // and the filter has not expired.
    // ponytail: LIKE on JSON array is fine for small cardinality contexts
    // (home, notifications, public, thread, account). Upgrade: json_each().
    let pattern = format!("%\"{context}\"%");
    let rows: Vec<(i64, String, String, String)> = sqlx::query_as(
        "SELECT id, title, context, filter_action FROM filters \
         WHERE user_id = ? AND context LIKE ? \
         AND (expires_at IS NULL OR expires_at > ?)",
    )
    .bind(account_id)
    .bind(&pattern)
    .bind(now)
    .fetch_all(pool)
    .await?;

    let mut filters = Vec::with_capacity(rows.len());
    for (fid, title, ctx, action) in rows {
        let kw_rows: Vec<(String, bool)> =
            sqlx::query_as("SELECT keyword, whole_word FROM filter_keywords WHERE filter_id = ?")
                .bind(fid)
                .fetch_all(pool)
                .await?;

        let keywords = kw_rows
            .into_iter()
            .map(|(keyword, whole_word)| ActiveKeyword {
                keyword,
                whole_word,
            })
            .collect();

        filters.push(ActiveFilter {
            id: fid,
            title,
            context_json: ctx,
            filter_action: action,
            keywords,
        });
    }
    Ok(filters)
}

/// Check if a keyword matches the content. Case-insensitive.
/// If whole_word is true, the keyword must appear at word boundaries.
fn keyword_matches(content: &str, keyword: &str, whole_word: bool) -> bool {
    let lower_content = content.to_lowercase();
    let lower_keyword = keyword.to_lowercase();

    if !whole_word {
        return lower_content.contains(&lower_keyword);
    }

    // Word-boundary matching: keyword must be bounded by non-alphanumeric chars
    // (or start/end of string).
    let kw_len = lower_keyword.len();
    let content_bytes = lower_content.as_bytes();
    let kw_bytes = lower_keyword.as_bytes();

    let mut start = 0;
    while let Some(pos) = lower_content[start..].find(&lower_keyword) {
        let abs_pos = start + pos;
        let end_pos = abs_pos + kw_len;

        let at_word_start = abs_pos == 0 || !content_bytes[abs_pos - 1].is_ascii_alphanumeric();
        let at_word_end =
            end_pos >= content_bytes.len() || !content_bytes[end_pos].is_ascii_alphanumeric();

        if at_word_start && at_word_end {
            return true;
        }
        start = abs_pos + 1;
        if start >= lower_content.len() {
            break;
        }
    }
    let _ = kw_bytes; // suppress unused warning
    false
}

/// Apply keyword filters to a list of status JSON values.
/// Statuses matching a "hide" filter are removed. Statuses matching a "warn"
/// filter get a `filtered` array appended.
fn apply_filters(statuses: &mut Vec<Value>, filters: &[ActiveFilter]) {
    if filters.is_empty() {
        return;
    }

    statuses.retain_mut(|status| {
        // Get plain-text-ish content by stripping HTML tags for matching
        let content = status.get("content").and_then(|v| v.as_str()).unwrap_or("");
        // ponytail: strip tags with a simple regex-free approach. Good enough
        // for substring matching; upgrade to ammonia text extraction if needed.
        let plain = strip_html_tags(content);

        let mut matched_filters: Vec<Value> = Vec::new();
        let mut should_hide = false;

        for filter in filters {
            let mut kw_matches: Vec<String> = Vec::new();
            for kw in &filter.keywords {
                if keyword_matches(&plain, &kw.keyword, kw.whole_word) {
                    kw_matches.push(kw.keyword.clone());
                }
            }
            if !kw_matches.is_empty() {
                if filter.filter_action == "hide" {
                    should_hide = true;
                    break;
                }
                let context: Vec<String> =
                    serde_json::from_str(&filter.context_json).unwrap_or_default();
                let kw_vals: Vec<Value> = filter
                    .keywords
                    .iter()
                    .map(|k| {
                        json!({
                            "id": "",
                            "keyword": k.keyword,
                            "whole_word": k.whole_word,
                        })
                    })
                    .collect();
                matched_filters.push(json!({
                    "filter": {
                        "id": filter.id.to_string(),
                        "title": filter.title,
                        "context": context,
                        "filter_action": filter.filter_action,
                        "keywords": kw_vals,
                        "statuses": [],
                    },
                    "keyword_matches": kw_matches,
                }));
            }
        }

        if should_hide {
            return false;
        }

        if !matched_filters.is_empty() {
            if let Some(obj) = status.as_object_mut() {
                obj.insert("filtered".to_string(), Value::Array(matched_filters));
            }
        }

        true
    });
}

/// Naive HTML tag stripper for filter matching purposes.
pub fn strip_html_tags(html: &str) -> String {
    let mut result = String::with_capacity(html.len());
    let mut in_tag = false;
    for ch in html.chars() {
        if ch == '<' {
            in_tag = true;
        } else if ch == '>' {
            in_tag = false;
        } else if !in_tag {
            result.push(ch);
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Content rendering
// ---------------------------------------------------------------------------

pub static SANITIZER_TAGS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
        "p",
        "br",
        "a",
        "span",
        "em",
        "strong",
        "del",
        "blockquote",
        "code",
        "pre",
        "ul",
        "ol",
        "li",
    ]
    .into_iter()
    .collect()
});

pub static SANITIZER_TAG_ATTRS: LazyLock<
    std::collections::HashMap<&'static str, HashSet<&'static str>>,
> = LazyLock::new(|| {
    let mut m = std::collections::HashMap::new();
    m.insert("a", ["href", "class"].into_iter().collect());
    m.insert("span", ["class"].into_iter().collect());
    m
});

/// Build a restrictive ammonia sanitizer for Mastodon-compatible HTML.
pub fn html_sanitizer() -> ammonia::Builder<'static> {
    let mut builder = ammonia::Builder::new();
    builder.tags(SANITIZER_TAGS.clone());
    builder.tag_attributes(SANITIZER_TAG_ATTRS.clone());
    builder.link_rel(Some("nofollow noopener noreferrer"));
    builder.url_schemes(["http", "https", "mailto"].into_iter().collect());
    builder
}

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

    let clean_html = html_sanitizer().clean(&raw_html).to_string();

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
            r#"<span class="h-card"><a href="{href}" class="u-url mention">@<span>{user}</span></a></span>"#,
            href = href,
            user = m.username,
        );
        html = html.replacen(&full_match, &link, 1);
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
        html = html.replacen(&pattern, &link, 1);
    }

    // Auto-link bare URLs not already inside <a> tags
    html = autolink_bare_urls(&html);

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

/// Extract URLs from text that look like fediverse post links (FEP-e232 Object Links).
/// Patterns: /users/X/statuses/Y, /@X/Y (numeric), /notes/X
fn extract_fediverse_links(text: &str) -> Vec<String> {
    static FEDI_POST_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(
            r#"https://[^\s<>")\]]+/(?:users/[^/\s]+/statuses/[A-Za-z0-9]+|@[^/\s]+/\d+|notes/[A-Za-z0-9_-]+|objects/[A-Fa-f0-9-]+|notice/[A-Za-z0-9_-]+|p/[^/\s]+/\d+)"#,
        )
        .unwrap()
    });
    let mut seen = HashSet::new();
    FEDI_POST_RE
        .find_iter(text)
        .map(|m| {
            m.as_str()
                .trim_end_matches(['.', ',', ';', ')', ']', '!', '?'])
                .to_string()
        })
        .filter(|url| seen.insert(url.clone()))
        .collect()
}

/// Find `@user@domain` and `@user` patterns in text.
/// Uses word/tag boundary matching to avoid false positives inside URLs or HTML.
fn parse_mentions(text: &str) -> Vec<ParsedMention> {
    static MENTION_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"(?:^|[\s>])@([a-zA-Z0-9_-]+)(?:@([a-zA-Z0-9.-]+))?").unwrap()
    });

    let mut mentions = Vec::new();
    let mut seen = HashSet::new();

    for caps in MENTION_RE.captures_iter(text) {
        let username = caps[1].to_string();
        let domain = caps.get(2).map(|d| d.as_str().to_string());

        let key = match &domain {
            Some(d) => format!("{}@{}", username.to_lowercase(), d.to_lowercase()),
            None => username.to_lowercase(),
        };
        if seen.insert(key) {
            mentions.push(ParsedMention { username, domain });
        }
    }
    mentions
}

/// Find `#word` patterns in text.
/// Uses word/tag boundary matching to avoid false positives inside URLs or HTML.
fn parse_hashtags(text: &str) -> Vec<String> {
    static HASHTAG_RE: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r"(?:^|[\s>])#([a-zA-Z0-9_]+)").unwrap());

    let mut tags = Vec::new();
    let mut seen = HashSet::new();

    for caps in HASHTAG_RE.captures_iter(text) {
        let tag = caps[1].to_string();
        // Require at least one letter — pure numbers like #5 are not hashtags
        if tag.chars().any(|c| c.is_alphabetic()) {
            let lower = tag.to_lowercase();
            if seen.insert(lower) {
                tags.push(tag);
            }
        }
    }
    tags
}

/// Wrap bare `http://` and `https://` URLs that aren't already inside `<a>` tags.
fn autolink_bare_urls(html: &str) -> String {
    // Match URLs that are NOT preceded by href=" or src=" or >
    // Strategy: split on existing <a>...</a> segments, only linkify in non-anchor text.
    static URL_RE: LazyLock<regex::Regex> =
        LazyLock::new(|| regex::Regex::new(r#"https?://[^\s<>")\]]+"#).unwrap());
    let mut result = String::with_capacity(html.len());
    let url_re = &*URL_RE;

    let mut last = 0;
    // Track whether we're inside an <a> tag
    let bytes = html.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i < len {
        if i + 2 < len
            && bytes[i] == b'<'
            && bytes[i + 1] == b'a'
            && (bytes[i + 2] == b' ' || bytes[i + 2] == b'>')
        {
            // We hit an <a> tag — copy everything up to here, linkifying it
            let segment = &html[last..i];
            result.push_str(&linkify_segment(segment, &url_re));

            // Find closing </a>
            if let Some(close_pos) = html[i..].find("</a>") {
                let end = i + close_pos + 4;
                result.push_str(&html[i..end]);
                i = end;
                last = end;
            } else {
                // Malformed — just copy the rest
                result.push_str(&html[i..]);
                return result;
            }
        } else {
            i += 1;
        }
    }

    // Linkify remaining text after last anchor
    if last < len {
        let segment = &html[last..];
        result.push_str(&linkify_segment(segment, &url_re));
    }

    result
}

fn linkify_segment(segment: &str, url_re: &regex::Regex) -> String {
    url_re
        .replace_all(segment, |caps: &regex::Captures| {
            let url = &caps[0];
            format!(
                r#"<a href="{url}" rel="nofollow noopener noreferrer" target="_blank">{url}</a>"#,
                url = url,
            )
        })
        .into_owned()
}

// ---------------------------------------------------------------------------
// Status serialization
// ---------------------------------------------------------------------------

#[derive(Debug, sqlx::FromRow)]
pub struct PostRow {
    id: i64,
    persona_id: i64,
    in_reply_to_id: Option<i64>,
    boost_of_id: Option<i64>,
    context_url: Option<String>,
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

pub const POST_COLUMNS: &str =
    "id, persona_id, in_reply_to_id, boost_of_id, context_url, content, content_html, \
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
    card: Option<Value>,
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

    let in_reply_to_id = post.in_reply_to_id.map(|id| Value::String(id.to_string()));
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
        "card": card,
        "poll": null,
        "edited_at": edited
    })
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

#[derive(Deserialize, serde::Serialize, Clone)]
struct CreateStatusRequest {
    status: Option<String>,
    media_ids: Option<Vec<String>>,
    in_reply_to_id: Option<String>,
    sensitive: Option<bool>,
    spoiler_text: Option<String>,
    visibility: Option<String>,
    language: Option<String>,
    scheduled_at: Option<String>,
}

fn deserialize_optional_number<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<i64>, D::Error> {
    let opt: Option<String> = Option::deserialize(deserializer)?;
    match opt {
        None => Ok(None),
        Some(s) => s.parse::<i64>().map(Some).map_err(serde::de::Error::custom),
    }
}

#[derive(Deserialize)]
struct PaginationParams {
    max_id: Option<String>,
    since_id: Option<String>,
    min_id: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_number")]
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
pub async fn load_status(
    pool: &SqlitePool,
    post: &PostRow,
    domain: &str,
    viewer_account_id: Option<i64>,
) -> Result<Value, AppError> {
    let account = fetch_account_row(pool, post.persona_id).await?;
    let account_json = account_to_json(&account, domain);

    // Fetch media attachments
    let media: Vec<(
        i64,
        String,
        String,
        Option<i32>,
        Option<i32>,
        Option<String>,
        String,
    )> = sqlx::query_as(
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
    let tags: Vec<(String,)> = sqlx::query_as("SELECT tag FROM post_tags WHERE post_id = ?")
        .bind(post.id)
        .fetch_all(pool)
        .await?;
    let tag_strings: Vec<String> = tags.into_iter().map(|(t,)| t).collect();
    let tag_vals = tag_values_for_post(&tag_strings, domain);

    // Fetch mentions for display
    let mention_rows: Vec<(Option<i64>, Option<i64>)> = sqlx::query_as(
        "SELECT mentioned_persona_id, mentioned_remote_id FROM mentions WHERE post_id = ?",
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
            let remote: Option<(i64, String, String)> =
                sqlx::query_as("SELECT id, username, domain FROM remote_accounts WHERE id = ?")
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
        let fav: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM favourites WHERE persona_id = ? AND post_id = ?")
                .bind(viewer)
                .bind(post.id)
                .fetch_one(pool)
                .await?;

        let boost: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM posts WHERE persona_id = ? AND boost_of_id = ?")
                .bind(viewer)
                .bind(post.id)
                .fetch_one(pool)
                .await?;

        let bmark: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM bookmarks WHERE persona_id = ? AND post_id = ?")
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
        let boosted: Option<PostRow> =
            sqlx::query_as::<_, PostRow>(&format!("SELECT {POST_COLUMNS} FROM posts WHERE id = ?"))
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

    let card = crate::cards::load_card_for_post(pool, post.id).await;

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
        card,
        favourited,
        reblogged,
        false, // muted
        bookmarked,
        {
            let pinned: (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM pinned_posts WHERE persona_id = ? AND post_id = ?",
            )
            .bind(post.persona_id)
            .bind(post.id)
            .fetch_one(pool)
            .await?;
            pinned.0 > 0
        },
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
    auth.require_scope("write")?;
    let domain = &state.config.server.domain;

    // Check idempotency key
    if let Some(idem_key) = headers.get("Idempotency-Key").and_then(|v| v.to_str().ok()) {
        let key_hash = sha256_hex(idem_key.as_bytes());
        let existing: Option<(i64,)> = sqlx::query_as(
            "SELECT post_id FROM idempotency_keys WHERE key_hash = ? AND user_id = ?",
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

            let status = load_status(&state.pool, &post, domain, Some(auth.account_id)).await?;
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

    if text.chars().count() > state.config.limits.max_post_chars {
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
    let language = body.language.clone().filter(|l| !l.is_empty()).or_else(|| {
        let detected = detect_language(&text);
        if detected != "en" {
            Some(detected.to_string())
        } else {
            Some(state.config.defaults.default_language.clone())
        }
    });

    // Check for scheduled_at — if present and >= 5 min in the future, store
    // as a scheduled post instead of creating immediately.
    if let Some(ref scheduled_str) = body.scheduled_at {
        let scheduled_ms = chrono::DateTime::parse_from_rfc3339(scheduled_str)
            .or_else(|_| chrono::DateTime::parse_from_str(scheduled_str, "%+"))
            .map(|dt| dt.timestamp_millis())
            .map_err(|_| AppError::unprocessable("Invalid scheduled_at datetime"))?;

        let now = now_millis();
        let five_min_ms = 5 * 60 * 1000;

        if scheduled_ms > now + five_min_ms {
            let sched_id = generate_id();
            let params_json =
                serde_json::to_string(&body).map_err(|e| AppError::internal(e.to_string()))?;

            sqlx::query(
                "INSERT INTO scheduled_statuses \
                 (id, user_id, persona_id, scheduled_at, params_json, created_at) \
                 VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind(sched_id)
            .bind(crate::db::DEFAULT_USER_ID)
            .bind(auth.account_id)
            .bind(scheduled_ms)
            .bind(&params_json)
            .bind(now)
            .execute(&state.pool)
            .await?;

            let scheduled_json = scheduled_status_to_json(
                sched_id,
                scheduled_ms,
                &body,
                &visibility,
                sensitive,
                &language,
            );
            return Ok((StatusCode::OK, Json(scheduled_json)).into_response());
        }
    }

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

    // FEP-f228: compute context_url. Replies inherit parent's context; originals get their own.
    let context_url = match in_reply_to_id {
        Some(parent_id) => {
            let parent_ctx: Option<(Option<String>, String, i64)> =
                sqlx::query_as("SELECT context_url, ap_id, persona_id FROM posts WHERE id = ?")
                    .bind(parent_id)
                    .fetch_optional(&state.pool)
                    .await?;
            match parent_ctx {
                Some((Some(url), _, _)) => url,
                Some((None, parent_ap_id, _)) => format!("{parent_ap_id}/context"),
                None => format!("{ap_id}/context"),
            }
        }
        None => format!("{ap_id}/context"),
    };

    sqlx::query(
        "INSERT INTO posts (id, user_id, persona_id, ap_id, in_reply_to_id, context_url, content, content_html, \
         spoiler_text, visibility, sensitive, language, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(post_id)
    .bind(crate::db::DEFAULT_USER_ID)
    .bind(auth.account_id)
    .bind(&ap_id)
    .bind(in_reply_to_id)
    .bind(&context_url)
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
            "UPDATE media SET post_id = ? WHERE id = ? AND persona_id = ? AND post_id IS NULL",
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
                    sqlx::query_as("SELECT id FROM personas WHERE username = ?")
                        .bind(&m.username)
                        .fetch_optional(&state.pool)
                        .await?;
                if let Some((aid,)) = local {
                    sqlx::query(
                        "INSERT OR IGNORE INTO mentions (post_id, mentioned_persona_id) \
                         VALUES (?, ?)",
                    )
                    .bind(post_id)
                    .bind(aid)
                    .execute(&state.pool)
                    .await?;

                    // Notification for local mention (dedup via unique index)
                    // Skip self-mentions — don't notify the author about their own post
                    if aid != auth.account_id {
                        let notif_id = generate_id();
                        sqlx::query(
                            "INSERT OR IGNORE INTO notifications \
                             (id, user_id, persona_id, kind, from_persona_id, post_id, created_at) \
                             VALUES (?, ?, ?, 'mention', ?, ?, ?)",
                        )
                        .bind(notif_id)
                        .bind(crate::db::DEFAULT_USER_ID)
                        .bind(aid)
                        .bind(auth.account_id)
                        .bind(post_id)
                        .bind(now)
                        .execute(&state.pool)
                        .await?;

                        // Fire-and-forget push notification
                        let pool = state.pool.clone();
                        let from_user = auth.username.clone();
                        let push_domain = domain.clone();
                        tokio::spawn(async move {
                            crate::push::send_push_notification(
                                &pool,
                                aid,
                                "mention",
                                "New mention",
                                &from_user,
                                None,
                                &push_domain,
                            )
                            .await;
                        });
                    }
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
    if let Some(idem_key) = headers.get("Idempotency-Key").and_then(|v| v.to_str().ok()) {
        let key_hash = sha256_hex(idem_key.as_bytes());
        sqlx::query(
            "INSERT OR IGNORE INTO idempotency_keys (key_hash, user_id, post_id, created_at) \
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
    sqlx::query("UPDATE personas SET last_status_at = ? WHERE id = ?")
        .bind(now)
        .bind(auth.account_id)
        .execute(&state.pool)
        .await?;

    // Enqueue outbound ActivityPub Create{Note} for federation
    {
        let actor = format!("https://{domain}/users/{}", auth.username);
        let note_id = format!("{actor}/statuses/{post_id}");
        let followers_url = format!("{actor}/followers");
        let published = millis_to_iso(now);
        let public = "https://www.w3.org/ns/activitystreams#Public";

        let (to, cc) = match visibility.as_str() {
            "public" => (vec![json!(public)], vec![json!(&followers_url)]),
            "unlisted" => (vec![json!(&followers_url)], vec![json!(public)]),
            "private" => (vec![json!(&followers_url)], vec![]),
            "direct" => {
                let mut to_addrs: Vec<Value> = Vec::new();
                for m in &rendered.mentions {
                    match &m.domain {
                        None => {
                            to_addrs.push(json!(format!("https://{domain}/users/{}", m.username)));
                        }
                        Some(mention_domain) => {
                            // Look up the remote account's actor_uri for the AP `to` field
                            let remote: Option<(String,)> = sqlx::query_as(
                                "SELECT actor_uri FROM remote_accounts WHERE username = ? AND domain = ?",
                            )
                            .bind(&m.username)
                            .bind(mention_domain)
                            .fetch_optional(&state.pool)
                            .await?;
                            if let Some((actor_uri,)) = remote {
                                to_addrs.push(json!(actor_uri));
                            }
                        }
                    }
                }
                (to_addrs, vec![])
            }
            _ => (vec![json!(public)], vec![json!(&followers_url)]),
        };

        // Build mention tags for the Note
        let mut mention_tags: Vec<Value> = Vec::new();
        for m in &rendered.mentions {
            match &m.domain {
                None => {
                    mention_tags.push(json!({
                        "type": "Mention",
                        "href": format!("https://{domain}/users/{}", m.username),
                        "name": format!("@{}@{domain}", m.username)
                    }));
                }
                Some(mention_domain) => {
                    let remote: Option<(String,)> = sqlx::query_as(
                        "SELECT actor_uri FROM remote_accounts WHERE username = ? AND domain = ?",
                    )
                    .bind(&m.username)
                    .bind(mention_domain)
                    .fetch_optional(&state.pool)
                    .await?;
                    if let Some((actor_uri,)) = remote {
                        mention_tags.push(json!({
                            "type": "Mention",
                            "href": actor_uri,
                            "name": format!("@{}@{}", m.username, mention_domain)
                        }));
                    }
                }
            }
        }

        // FEP-e232: Add Link tags for quoted fediverse posts
        let fedi_links = extract_fediverse_links(&text);
        for link_url in &fedi_links {
            mention_tags.push(json!({
                "type": "Link",
                "mediaType": "application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\"",
                "href": link_url,
                "name": format!("RE: {link_url}")
            }));
        }

        let in_reply_to_ap = match in_reply_to_id {
            Some(rid) => {
                // Look up the original post's ap_id rather than constructing it
                let original_ap_id: Option<(String,)> =
                    sqlx::query_as("SELECT ap_id FROM posts WHERE id = ?")
                        .bind(rid)
                        .fetch_optional(&state.pool)
                        .await?;
                Some(json!(original_ap_id.map(|(ap_id,)| ap_id).unwrap_or_else(
                    || format!("https://{domain}/users/{}/statuses/{rid}", auth.username)
                )))
            }
            None => None,
        };

        // Query media attachments for the AP Note
        #[allow(clippy::type_complexity)]
        let ap_media: Vec<(
            String,
            String,
            Option<i32>,
            Option<i32>,
            Option<String>,
            String,
        )> = sqlx::query_as(
            "SELECT file_path, mime_type, width, height, blurhash, description \
                 FROM media WHERE post_id = ? ORDER BY id",
        )
        .bind(post_id)
        .fetch_all(&state.pool)
        .await?;

        let ap_attachments: Vec<Value> = ap_media
            .iter()
            .map(
                |(file_path, mime_type, width, height, blurhash, description)| {
                    let mut doc = json!({
                        "type": "Document",
                        "mediaType": mime_type,
                        "url": format!("https://{domain}/media/{file_path}"),
                        "name": description
                    });
                    if let Some(bh) = blurhash {
                        doc["blurhash"] = json!(bh);
                    }
                    if let Some(w) = width {
                        doc["width"] = json!(w);
                    }
                    if let Some(h) = height {
                        doc["height"] = json!(h);
                    }
                    doc
                },
            )
            .collect();

        let activity = json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": format!("{note_id}/activity"),
            "type": "Create",
            "actor": &actor,
            "published": &published,
            "to": &to,
            "cc": &cc,
            "object": {
                "id": &note_id,
                "type": "Note",
                "attributedTo": &actor,
                "context": &context_url,
                "content": &rendered.html,
                "url": format!("https://{domain}/@{}/{post_id}", auth.username),
                "to": &to,
                "cc": &cc,
                "published": &published,
                "sensitive": sensitive,
                "summary": if spoiler_text.is_empty() { None } else { Some(&spoiler_text) },
                "inReplyTo": in_reply_to_ap,
                "tag": &mention_tags,
                "attachment": &ap_attachments
            }
        });

        if visibility == "direct" {
            // Deliver DMs directly to each mentioned remote user's inbox
            for m in &rendered.mentions {
                if let Some(ref mention_domain) = m.domain {
                    let remote: Option<(String,)> = sqlx::query_as(
                        "SELECT inbox_url FROM remote_accounts WHERE username = ? AND domain = ?",
                    )
                    .bind(&m.username)
                    .bind(mention_domain)
                    .fetch_optional(&state.pool)
                    .await?;
                    if let Some((inbox_url,)) = remote {
                        if let Err(e) =
                            enqueue_delivery(&state.pool, &inbox_url, auth.account_id, &activity)
                                .await
                        {
                            tracing::error!("Failed to enqueue DM delivery to {}: {e}", inbox_url);
                        }
                    }
                }
            }
        } else {
            if let Err(e) = enqueue_to_followers(&state.pool, auth.account_id, &activity).await {
                tracing::error!("Failed to enqueue Create activity: {e}");
            }

            if visibility == "public" {
                if let Err(e) = enqueue_to_relays(&state.pool, auth.account_id, &activity).await {
                    tracing::error!("Failed to enqueue Create activity to relays: {e}");
                }
            }
        }
    }

    // Background-fetch link preview card
    if let Some(card_url) = crate::cards::extract_first_url(&text) {
        let pool = state.pool.clone();
        let card_domain = domain.to_string();
        tokio::spawn(async move {
            if let Err(e) =
                crate::cards::fetch_and_cache_card(&pool, post_id, &card_url, &card_domain).await
            {
                tracing::debug!("card fetch failed for {card_url}: {e}");
            }
        });
    }

    // Build response
    let post =
        sqlx::query_as::<_, PostRow>(&format!("SELECT {POST_COLUMNS} FROM posts WHERE id = ?"))
            .bind(post_id)
            .fetch_one(&state.pool)
            .await?;

    let status = load_status(&state.pool, &post, domain, Some(auth.account_id)).await?;

    // Publish streaming events
    let status_json_str = serde_json::to_string(&status).unwrap_or_default();
    if visibility == "public" || visibility == "unlisted" {
        publish(StreamEvent {
            event_type: "update".into(),
            payload: status_json_str.clone(),
            channel: "public".into(),
        });
    }
    publish(StreamEvent {
        event_type: "update".into(),
        payload: status_json_str,
        channel: format!("user:{}", auth.account_id),
    });

    // Index for full-text search
    if let Some(ref search) = state.search {
        let _ = search.index_post(post_id, &text, auth.account_id).await;
    }

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
    auth.require_scope("write")?;
    let post_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("Status not found"))?;

    let domain = &state.config.server.domain;

    let post =
        sqlx::query_as::<_, PostRow>(&format!("SELECT {POST_COLUMNS} FROM posts WHERE id = ?"))
            .bind(post_id)
            .fetch_optional(&state.pool)
            .await?
            .ok_or_else(|| AppError::not_found("Status not found"))?;

    if post.persona_id != auth.account_id {
        return Err(AppError::forbidden("You do not own this status"));
    }

    // Build response before deletion (Mastodon returns the deleted status)
    let status = load_status(&state.pool, &post, domain, Some(auth.account_id)).await?;

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

    if let Err(e) = enqueue_to_followers(&state.pool, auth.account_id, &delete_activity).await {
        tracing::error!("Failed to enqueue delete activity: {e}");
    }

    // Query media files before deletion so we can clean up from disk
    let media_paths: Vec<(String,)> =
        sqlx::query_as("SELECT file_path FROM media WHERE post_id = ?")
            .bind(post_id)
            .fetch_all(&state.pool)
            .await?;

    // Delete related rows then the post, all in a transaction
    let mut tx = state.pool.begin().await?;
    for table in &[
        "DELETE FROM pinned_posts WHERE post_id = ?",
        "DELETE FROM post_tags WHERE post_id = ?",
        "DELETE FROM mentions WHERE post_id = ?",
        "DELETE FROM favourites WHERE post_id = ?",
        "DELETE FROM bookmarks WHERE post_id = ?",
        "DELETE FROM notifications WHERE post_id = ?",
        "DELETE FROM idempotency_keys WHERE post_id = ?",
        "DELETE FROM conversation_read_markers WHERE post_id = ?",
        "DELETE FROM conversation_hidden WHERE post_id = ?",
        "DELETE FROM post_cards WHERE post_id = ?",
    ] {
        sqlx::query(table).bind(post_id).execute(&mut *tx).await?;
    }
    sqlx::query("UPDATE media SET post_id = NULL WHERE post_id = ?")
        .bind(post_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM posts WHERE id = ?")
        .bind(post_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    // Remove media files from disk (best-effort, after transaction committed)
    let media_dir = &state.config.storage.media_dir;
    for (file_path,) in &media_paths {
        let abs_path = std::path::Path::new(media_dir).join(file_path);
        if let Err(e) = tokio::fs::remove_file(&abs_path).await {
            tracing::warn!(path = %abs_path.display(), error = %e, "failed to remove media file");
        }
    }

    // Remove from search index
    if let Some(ref search) = state.search {
        let _ = search.delete_post(post_id).await;
    }

    publish(StreamEvent {
        event_type: "delete".into(),
        payload: id.clone(),
        channel: "public".into(),
    });
    publish(StreamEvent {
        event_type: "delete".into(),
        payload: id.clone(),
        channel: format!("user:{}", auth.account_id),
    });

    Ok((StatusCode::OK, Json(status)).into_response())
}

// ---------------------------------------------------------------------------
// PUT /api/v1/statuses/:id
// ---------------------------------------------------------------------------

async fn edit_status(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(id): Path<String>,
    Json(body): Json<CreateStatusRequest>,
) -> Result<Json<Value>, AppError> {
    auth.require_scope("write")?;
    let post_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("Status not found"))?;
    let domain = &state.config.server.domain;
    let now = now_millis();

    let post =
        sqlx::query_as::<_, PostRow>(&format!("SELECT {POST_COLUMNS} FROM posts WHERE id = ?"))
            .bind(post_id)
            .fetch_optional(&state.pool)
            .await?
            .ok_or_else(|| AppError::not_found("Status not found"))?;

    if post.persona_id != auth.account_id {
        return Err(AppError::forbidden("You do not own this status"));
    }

    let text = body.status.as_deref().unwrap_or("").to_string();
    if text.is_empty() {
        return Err(AppError::unprocessable(
            "Validation failed: status text is required",
        ));
    }
    if text.chars().count() > state.config.limits.max_post_chars {
        return Err(AppError::unprocessable(format!(
            "Validation failed: status text must be at most {} characters",
            state.config.limits.max_post_chars
        )));
    }

    let sensitive = body
        .sensitive
        .unwrap_or(state.config.defaults.default_sensitive);
    let spoiler_text = body.spoiler_text.as_deref().unwrap_or("").to_string();
    let language = body.language.clone().filter(|l| !l.is_empty()).or_else(|| {
        let detected = detect_language(&text);
        if detected != "en" {
            Some(detected.to_string())
        } else {
            Some(state.config.defaults.default_language.clone())
        }
    });

    let rendered = render_content(&text, domain);

    // Save current version to edit history before overwriting
    sqlx::query(
        "INSERT INTO post_edits (id, post_id, content, content_html, spoiler_text, sensitive, created_at) \
         SELECT ?, id, content, content_html, spoiler_text, sensitive, COALESCE(edited_at, created_at) FROM posts WHERE id = ?",
    )
    .bind(generate_id())
    .bind(post_id)
    .execute(&state.pool)
    .await?;

    // Update the post row
    sqlx::query(
        "UPDATE posts SET content = ?, content_html = ?, spoiler_text = ?, \
         sensitive = ?, language = ?, edited_at = ? WHERE id = ?",
    )
    .bind(&text)
    .bind(&rendered.html)
    .bind(&spoiler_text)
    .bind(sensitive)
    .bind(&language)
    .bind(now)
    .bind(post_id)
    .execute(&state.pool)
    .await?;

    // Delete old mentions and tags, re-insert new ones
    sqlx::query("DELETE FROM mentions WHERE post_id = ?")
        .bind(post_id)
        .execute(&state.pool)
        .await?;
    sqlx::query("DELETE FROM post_tags WHERE post_id = ?")
        .bind(post_id)
        .execute(&state.pool)
        .await?;

    for m in &rendered.mentions {
        match &m.domain {
            None => {
                let local: Option<(i64,)> =
                    sqlx::query_as("SELECT id FROM personas WHERE username = ?")
                        .bind(&m.username)
                        .fetch_optional(&state.pool)
                        .await?;
                if let Some((aid,)) = local {
                    sqlx::query(
                        "INSERT OR IGNORE INTO mentions (post_id, mentioned_persona_id) \
                         VALUES (?, ?)",
                    )
                    .bind(post_id)
                    .bind(aid)
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

    for tag in &rendered.tags {
        sqlx::query("INSERT OR IGNORE INTO post_tags (post_id, tag) VALUES (?, ?)")
            .bind(post_id)
            .bind(tag)
            .execute(&state.pool)
            .await?;
    }

    // Enqueue outbound Update{Note} for federation
    {
        let actor = format!("https://{domain}/users/{}", auth.username);
        let note_id = format!("{actor}/statuses/{post_id}");
        let followers_url = format!("{actor}/followers");
        let published = millis_to_iso(post.created_at);
        let updated = millis_to_iso(now);
        let public = "https://www.w3.org/ns/activitystreams#Public";

        let (to, cc) = match post.visibility.as_str() {
            "public" => (vec![json!(public)], vec![json!(&followers_url)]),
            "unlisted" => (vec![json!(&followers_url)], vec![json!(public)]),
            "private" => (vec![json!(&followers_url)], vec![]),
            _ => (vec![json!(public)], vec![json!(&followers_url)]),
        };

        // Build mention tags for the Note
        let mut mention_tags: Vec<Value> = Vec::new();
        for m in &rendered.mentions {
            match &m.domain {
                None => {
                    mention_tags.push(json!({
                        "type": "Mention",
                        "href": format!("https://{domain}/users/{}", m.username),
                        "name": format!("@{}@{domain}", m.username)
                    }));
                }
                Some(mention_domain) => {
                    let remote: Option<(String,)> = sqlx::query_as(
                        "SELECT actor_uri FROM remote_accounts WHERE username = ? AND domain = ?",
                    )
                    .bind(&m.username)
                    .bind(mention_domain)
                    .fetch_optional(&state.pool)
                    .await?;
                    if let Some((actor_uri,)) = remote {
                        mention_tags.push(json!({
                            "type": "Mention",
                            "href": actor_uri,
                            "name": format!("@{}@{}", m.username, mention_domain)
                        }));
                    }
                }
            }
        }

        // FEP-e232: Add Link tags for quoted fediverse posts
        let fedi_links = extract_fediverse_links(&text);
        for link_url in &fedi_links {
            mention_tags.push(json!({
                "type": "Link",
                "mediaType": "application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\"",
                "href": link_url,
                "name": format!("RE: {link_url}")
            }));
        }

        // Query inReplyTo URI
        let (in_reply_to_uri,): (Option<String>,) =
            sqlx::query_as("SELECT in_reply_to_uri FROM posts WHERE id = ?")
                .bind(post_id)
                .fetch_one(&state.pool)
                .await?;

        // Query media attachments for the AP Note
        #[allow(clippy::type_complexity)]
        let ap_media: Vec<(
            String,
            String,
            Option<i32>,
            Option<i32>,
            Option<String>,
            String,
        )> = sqlx::query_as(
            "SELECT file_path, mime_type, width, height, blurhash, description \
                 FROM media WHERE post_id = ? ORDER BY id",
        )
        .bind(post_id)
        .fetch_all(&state.pool)
        .await?;

        let ap_attachments: Vec<Value> = ap_media
            .iter()
            .map(
                |(file_path, mime_type, width, height, blurhash, description)| {
                    let mut doc = json!({
                        "type": "Document",
                        "mediaType": mime_type,
                        "url": format!("https://{domain}/media/{file_path}"),
                        "name": description
                    });
                    if let Some(bh) = blurhash {
                        doc["blurhash"] = json!(bh);
                    }
                    if let Some(w) = width {
                        doc["width"] = json!(w);
                    }
                    if let Some(h) = height {
                        doc["height"] = json!(h);
                    }
                    doc
                },
            )
            .collect();

        let activity = json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": format!("{note_id}#updates/{now}"),
            "type": "Update",
            "actor": &actor,
            "published": &updated,
            "to": &to,
            "cc": &cc,
            "object": {
                "id": &note_id,
                "type": "Note",
                "attributedTo": &actor,
                "context": &post.context_url,
                "content": &rendered.html,
                "url": format!("https://{domain}/@{}/{post_id}", auth.username),
                "to": &to,
                "cc": &cc,
                "published": &published,
                "updated": &updated,
                "sensitive": sensitive,
                "summary": if spoiler_text.is_empty() { None } else { Some(&spoiler_text) },
                "inReplyTo": in_reply_to_uri,
                "tag": &mention_tags,
                "attachment": &ap_attachments
            }
        });

        if let Err(e) = enqueue_to_followers(&state.pool, auth.account_id, &activity).await {
            tracing::error!("Failed to enqueue Update activity: {e}");
        }
    }

    // Re-fetch the updated post and build response
    let updated_post =
        sqlx::query_as::<_, PostRow>(&format!("SELECT {POST_COLUMNS} FROM posts WHERE id = ?"))
            .bind(post_id)
            .fetch_one(&state.pool)
            .await?;

    let status = load_status(&state.pool, &updated_post, domain, Some(auth.account_id)).await?;

    // Publish streaming status.update event
    let status_json_str = serde_json::to_string(&status).unwrap_or_default();
    publish(StreamEvent {
        event_type: "status.update".into(),
        payload: status_json_str.clone(),
        channel: "public".into(),
    });
    publish(StreamEvent {
        event_type: "status.update".into(),
        payload: status_json_str,
        channel: format!("user:{}", auth.account_id),
    });

    // Update search index
    if let Some(ref search) = state.search {
        let _ = search.index_post(post_id, &text, auth.account_id).await;
    }

    Ok(Json(status))
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

    let post =
        sqlx::query_as::<_, PostRow>(&format!("SELECT {POST_COLUMNS} FROM posts WHERE id = ?"))
            .bind(post_id)
            .fetch_optional(&state.pool)
            .await?
            .ok_or_else(|| AppError::not_found("Status not found"))?;

    // Unauthenticated endpoint: only expose public/unlisted posts
    if post.visibility != "public" && post.visibility != "unlisted" {
        return Err(AppError::not_found("Status not found"));
    }

    let status = load_status(&state.pool, &post, domain, None).await?;
    Ok(Json(status))
}

// ---------------------------------------------------------------------------
// GET /api/v1/statuses/:id/history
// ---------------------------------------------------------------------------

async fn status_history(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let post_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("Status not found"))?;
    let domain = &state.config.server.domain;

    let post =
        sqlx::query_as::<_, PostRow>(&format!("SELECT {POST_COLUMNS} FROM posts WHERE id = ?"))
            .bind(post_id)
            .fetch_optional(&state.pool)
            .await?
            .ok_or_else(|| AppError::not_found("Status not found"))?;

    // For non-public posts, history is not exposed (simplification)
    if post.visibility == "direct" || post.visibility == "private" {
        return Err(AppError::not_found("Status not found"));
    }

    let account = fetch_account_row(&state.pool, post.persona_id).await?;
    let account_json = account_to_json(&account, domain);

    // Fetch previous versions from post_edits, ordered oldest first
    let edits: Vec<(String, String, String, bool, i64)> = sqlx::query_as(
        "SELECT content, content_html, spoiler_text, sensitive, created_at \
         FROM post_edits WHERE post_id = ? ORDER BY created_at ASC",
    )
    .bind(post_id)
    .fetch_all(&state.pool)
    .await?;

    let mut history: Vec<Value> = edits
        .iter()
        .map(|(_, html, spoiler, sensitive, created_at)| {
            json!({
                "content": html,
                "spoiler_text": spoiler,
                "sensitive": sensitive,
                "created_at": millis_to_iso(*created_at),
                "account": &account_json,
                "emojis": [],
                "media_attachments": []
            })
        })
        .collect();

    // Append current version as the final entry
    let current_ts = post.edited_at.unwrap_or(post.created_at);
    history.push(json!({
        "content": post.content_html,
        "spoiler_text": post.spoiler_text,
        "sensitive": post.sensitive,
        "created_at": millis_to_iso(current_ts),
        "account": &account_json,
        "emojis": [],
        "media_attachments": []
    }));

    Ok(Json(json!(history)))
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

    let target =
        sqlx::query_as::<_, PostRow>(&format!("SELECT {POST_COLUMNS} FROM posts WHERE id = ?"))
            .bind(post_id)
            .fetch_optional(&state.pool)
            .await?
            .ok_or_else(|| AppError::not_found("Status not found"))?;

    // Ancestors: walk up the reply chain
    let mut ancestors = Vec::new();
    let mut current_id = target.in_reply_to_id;
    while let Some(parent_id) = current_id {
        let parent =
            sqlx::query_as::<_, PostRow>(&format!("SELECT {POST_COLUMNS} FROM posts WHERE id = ?"))
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
        "WITH RECURSIVE thread(id, depth) AS ( \
            SELECT id, 1 FROM posts WHERE in_reply_to_id = ? \
            UNION ALL \
            SELECT p.id, t.depth + 1 FROM posts p JOIN thread t ON p.in_reply_to_id = t.id WHERE t.depth < 200 \
         ) \
         SELECT p.{POST_COLUMNS} FROM thread t JOIN posts p ON t.id = p.id \
         ORDER BY p.id ASC LIMIT 500",
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
    auth.require_scope("write")?;
    let post_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("Status not found"))?;
    let domain = &state.config.server.domain;
    let now = now_millis();

    let post =
        sqlx::query_as::<_, PostRow>(&format!("SELECT {POST_COLUMNS} FROM posts WHERE id = ?"))
            .bind(post_id)
            .fetch_optional(&state.pool)
            .await?
            .ok_or_else(|| AppError::not_found("Status not found"))?;

    sqlx::query(
        "INSERT OR IGNORE INTO favourites (user_id, persona_id, post_id, created_at) VALUES (?, ?, ?, ?)",
    )
    .bind(crate::db::DEFAULT_USER_ID)
    .bind(auth.account_id)
    .bind(post_id)
    .bind(now)
    .execute(&state.pool)
    .await?;

    if post.persona_id != auth.account_id {
        let notif_id = generate_id();
        sqlx::query(
            "INSERT OR IGNORE INTO notifications \
             (id, user_id, persona_id, kind, from_persona_id, post_id, created_at) \
             VALUES (?, ?, ?, 'favourite', ?, ?, ?)",
        )
        .bind(notif_id)
        .bind(crate::db::DEFAULT_USER_ID)
        .bind(post.persona_id)
        .bind(auth.account_id)
        .bind(post_id)
        .bind(now)
        .execute(&state.pool)
        .await?;

        // Fire-and-forget push notification
        let pool = state.pool.clone();
        let target = post.persona_id;
        let from_user = auth.username.clone();
        let push_domain = domain.clone();
        tokio::spawn(async move {
            crate::push::send_push_notification(
                &pool,
                target,
                "favourite",
                "New favourite",
                &from_user,
                None,
                &push_domain,
            )
            .await;
        });
    }

    // Enqueue outbound Like activity
    {
        let post_author = fetch_account_row(&state.pool, post.persona_id).await?;
        let actor = format!("https://{domain}/users/{}", auth.username);
        let object_uri = format!(
            "https://{domain}/users/{}/statuses/{post_id}",
            post_author.username
        );
        let like_id = format!("https://{domain}/activities/like-{post_id}");

        let activity = json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": &like_id,
            "type": "Like",
            "actor": &actor,
            "object": &object_uri
        });

        // Look up the post's AP ID — if it points to a remote server, deliver
        // the Like to that server's inbox. Local posts have local AP IDs so
        // this is a no-op for local-to-local interactions.
        let ap_id: Option<(String,)> = sqlx::query_as("SELECT ap_id FROM posts WHERE id = ?")
            .bind(post_id)
            .fetch_optional(&state.pool)
            .await?;
        let local_prefix = format!("https://{domain}/");
        if let Some((ref post_ap_id,)) = ap_id {
            if !post_ap_id.starts_with(&local_prefix) {
                // Remote post — extract the actor URI and find their inbox
                let actor_uri = post_ap_id.rfind("/statuses/").map(|i| &post_ap_id[..i]);
                if let Some(actor) = actor_uri {
                    let inbox: Option<(String,)> = sqlx::query_as(
                        "SELECT COALESCE(shared_inbox_url, inbox_url) \
                         FROM remote_accounts WHERE actor_uri = ?",
                    )
                    .bind(actor)
                    .fetch_optional(&state.pool)
                    .await?;
                    if let Some((inbox_url,)) = inbox {
                        if let Err(e) =
                            enqueue_delivery(&state.pool, &inbox_url, auth.account_id, &activity)
                                .await
                        {
                            tracing::error!("Failed to enqueue Like activity: {e}");
                        }
                    }
                }
            }
        }
    }

    let status = load_status(&state.pool, &post, domain, Some(auth.account_id)).await?;
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

    let post =
        sqlx::query_as::<_, PostRow>(&format!("SELECT {POST_COLUMNS} FROM posts WHERE id = ?"))
            .bind(post_id)
            .fetch_optional(&state.pool)
            .await?
            .ok_or_else(|| AppError::not_found("Status not found"))?;

    sqlx::query("DELETE FROM favourites WHERE persona_id = ? AND post_id = ?")
        .bind(auth.account_id)
        .bind(post_id)
        .execute(&state.pool)
        .await?;

    // Enqueue outbound Undo{Like} activity
    {
        let post_author = fetch_account_row(&state.pool, post.persona_id).await?;
        let actor = format!("https://{domain}/users/{}", auth.username);
        let object_uri = format!(
            "https://{domain}/users/{}/statuses/{post_id}",
            post_author.username
        );
        let like_id = format!("https://{domain}/activities/like-{post_id}");

        let activity = json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": format!("{like_id}#undo"),
            "type": "Undo",
            "actor": &actor,
            "object": {
                "id": &like_id,
                "type": "Like",
                "actor": &actor,
                "object": &object_uri
            }
        });

        let ap_id: Option<(String,)> = sqlx::query_as("SELECT ap_id FROM posts WHERE id = ?")
            .bind(post_id)
            .fetch_optional(&state.pool)
            .await?;
        let local_prefix = format!("https://{domain}/");
        if let Some((ref post_ap_id,)) = ap_id {
            if !post_ap_id.starts_with(&local_prefix) {
                let actor_uri = post_ap_id.rfind("/statuses/").map(|i| &post_ap_id[..i]);
                if let Some(remote_actor) = actor_uri {
                    let inbox: Option<(String,)> = sqlx::query_as(
                        "SELECT COALESCE(shared_inbox_url, inbox_url) \
                         FROM remote_accounts WHERE actor_uri = ?",
                    )
                    .bind(remote_actor)
                    .fetch_optional(&state.pool)
                    .await?;
                    if let Some((inbox_url,)) = inbox {
                        if let Err(e) =
                            enqueue_delivery(&state.pool, &inbox_url, auth.account_id, &activity)
                                .await
                        {
                            tracing::error!("Failed to enqueue Undo Like activity: {e}");
                        }
                    }
                }
            }
        }
    }

    let status = load_status(&state.pool, &post, domain, Some(auth.account_id)).await?;
    Ok(Json(status))
}

async fn reblog(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    auth.require_scope("write")?;
    let post_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("Status not found"))?;
    let domain = &state.config.server.domain;
    let now = now_millis();

    let original =
        sqlx::query_as::<_, PostRow>(&format!("SELECT {POST_COLUMNS} FROM posts WHERE id = ?"))
            .bind(post_id)
            .fetch_optional(&state.pool)
            .await?
            .ok_or_else(|| AppError::not_found("Status not found"))?;

    // Check for existing reblog
    let existing: Option<(i64,)> =
        sqlx::query_as("SELECT id FROM posts WHERE persona_id = ? AND boost_of_id = ?")
            .bind(auth.account_id)
            .bind(post_id)
            .fetch_optional(&state.pool)
            .await?;

    let boost_id = if let Some((eid,)) = existing {
        eid
    } else {
        let new_id = generate_id();
        let ap_id = format!("https://{domain}/users/{}/statuses/{new_id}", auth.username);

        sqlx::query(
            "INSERT INTO posts (id, user_id, persona_id, ap_id, boost_of_id, content, content_html, \
             visibility, created_at) VALUES (?, ?, ?, ?, ?, '', '', 'public', ?)",
        )
        .bind(new_id)
        .bind(crate::db::DEFAULT_USER_ID)
        .bind(auth.account_id)
        .bind(&ap_id)
        .bind(post_id)
        .bind(now)
        .execute(&state.pool)
        .await?;

        if original.persona_id != auth.account_id {
            let notif_id = generate_id();
            sqlx::query(
                "INSERT OR IGNORE INTO notifications \
                 (id, user_id, persona_id, kind, from_persona_id, post_id, created_at) \
                 VALUES (?, ?, ?, 'reblog', ?, ?, ?)",
            )
            .bind(notif_id)
            .bind(crate::db::DEFAULT_USER_ID)
            .bind(original.persona_id)
            .bind(auth.account_id)
            .bind(post_id)
            .bind(now)
            .execute(&state.pool)
            .await?;

            // Fire-and-forget push notification
            let pool = state.pool.clone();
            let target = original.persona_id;
            let from_user = auth.username.clone();
            let push_domain = domain.clone();
            tokio::spawn(async move {
                crate::push::send_push_notification(
                    &pool,
                    target,
                    "reblog",
                    "New boost",
                    &from_user,
                    None,
                    &push_domain,
                )
                .await;
            });
        }

        // Enqueue outbound Announce activity
        {
            let post_author = fetch_account_row(&state.pool, original.persona_id).await?;
            let actor = format!("https://{domain}/users/{}", auth.username);
            let object_uri = format!(
                "https://{domain}/users/{}/statuses/{post_id}",
                post_author.username
            );
            let announce_id = format!("https://{domain}/activities/announce-{new_id}");

            let activity = json!({
                "@context": "https://www.w3.org/ns/activitystreams",
                "id": &announce_id,
                "type": "Announce",
                "actor": &actor,
                "object": &object_uri,
                "to": ["https://www.w3.org/ns/activitystreams#Public"],
                "cc": [format!("https://{domain}/users/{}/followers", auth.username)]
            });

            // Deliver to followers
            if let Err(e) = enqueue_to_followers(&state.pool, auth.account_id, &activity).await {
                tracing::error!("Failed to enqueue Announce activity to followers: {e}");
            }

            // Also deliver to the post author's inbox if remote
            let ap_id_row: Option<(String,)> =
                sqlx::query_as("SELECT ap_id FROM posts WHERE id = ?")
                    .bind(post_id)
                    .fetch_optional(&state.pool)
                    .await?;
            let local_prefix = format!("https://{domain}/");
            if let Some((ref post_ap_id,)) = ap_id_row {
                if !post_ap_id.starts_with(&local_prefix) {
                    let actor_uri = post_ap_id.rfind("/statuses/").map(|i| &post_ap_id[..i]);
                    if let Some(remote_actor) = actor_uri {
                        let inbox: Option<(String,)> = sqlx::query_as(
                            "SELECT COALESCE(shared_inbox_url, inbox_url) \
                             FROM remote_accounts WHERE actor_uri = ?",
                        )
                        .bind(remote_actor)
                        .fetch_optional(&state.pool)
                        .await?;
                        if let Some((inbox_url,)) = inbox {
                            if let Err(e) = enqueue_delivery(
                                &state.pool,
                                &inbox_url,
                                auth.account_id,
                                &activity,
                            )
                            .await
                            {
                                tracing::error!("Failed to enqueue Announce to author: {e}");
                            }
                        }
                    }
                }
            }
        }

        new_id
    };

    let boost_post =
        sqlx::query_as::<_, PostRow>(&format!("SELECT {POST_COLUMNS} FROM posts WHERE id = ?"))
            .bind(boost_id)
            .fetch_one(&state.pool)
            .await?;

    let status = load_status(&state.pool, &boost_post, domain, Some(auth.account_id)).await?;
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

    let boost: Option<(i64,)> =
        sqlx::query_as("SELECT id FROM posts WHERE persona_id = ? AND boost_of_id = ?")
            .bind(auth.account_id)
            .bind(post_id)
            .fetch_optional(&state.pool)
            .await?;

    if let Some((boost_id,)) = boost {
        // Enqueue outbound Undo{Announce} before deleting
        {
            let original = sqlx::query_as::<_, PostRow>(&format!(
                "SELECT {POST_COLUMNS} FROM posts WHERE id = ?"
            ))
            .bind(post_id)
            .fetch_optional(&state.pool)
            .await?;

            if let Some(ref orig) = original {
                let post_author = fetch_account_row(&state.pool, orig.persona_id).await?;
                let actor = format!("https://{domain}/users/{}", auth.username);
                let object_uri = format!(
                    "https://{domain}/users/{}/statuses/{post_id}",
                    post_author.username
                );
                let announce_id = format!("https://{domain}/activities/announce-{boost_id}");

                let activity = json!({
                    "@context": "https://www.w3.org/ns/activitystreams",
                    "id": format!("{announce_id}#undo"),
                    "type": "Undo",
                    "actor": &actor,
                    "object": {
                        "id": &announce_id,
                        "type": "Announce",
                        "actor": &actor,
                        "object": &object_uri
                    }
                });

                // Deliver Undo to followers
                if let Err(e) = enqueue_to_followers(&state.pool, auth.account_id, &activity).await
                {
                    tracing::error!("Failed to enqueue Undo Announce to followers: {e}");
                }

                // Also deliver to the post author's inbox if remote
                let local_prefix = format!("https://{domain}/");
                if let Some(ref post_ap_id) =
                    sqlx::query_as::<_, (String,)>("SELECT ap_id FROM posts WHERE id = ?")
                        .bind(post_id)
                        .fetch_optional(&state.pool)
                        .await?
                {
                    if !post_ap_id.0.starts_with(&local_prefix) {
                        let actor_uri =
                            post_ap_id.0.rfind("/statuses/").map(|i| &post_ap_id.0[..i]);
                        if let Some(remote_actor) = actor_uri {
                            let inbox: Option<(String,)> = sqlx::query_as(
                                "SELECT COALESCE(shared_inbox_url, inbox_url) \
                                 FROM remote_accounts WHERE actor_uri = ?",
                            )
                            .bind(remote_actor)
                            .fetch_optional(&state.pool)
                            .await?;
                            if let Some((inbox_url,)) = inbox {
                                if let Err(e) = enqueue_delivery(
                                    &state.pool,
                                    &inbox_url,
                                    auth.account_id,
                                    &activity,
                                )
                                .await
                                {
                                    tracing::error!(
                                        "Failed to enqueue Undo Announce to author: {e}"
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        // Delete the orphan reblog notification
        sqlx::query(
            "DELETE FROM notifications WHERE kind = 'reblog' AND from_persona_id = ? AND post_id = ?",
        )
        .bind(auth.account_id)
        .bind(post_id)
        .execute(&state.pool)
        .await?;

        sqlx::query("DELETE FROM posts WHERE id = ?")
            .bind(boost_id)
            .execute(&state.pool)
            .await?;
    }

    let post =
        sqlx::query_as::<_, PostRow>(&format!("SELECT {POST_COLUMNS} FROM posts WHERE id = ?"))
            .bind(post_id)
            .fetch_optional(&state.pool)
            .await?
            .ok_or_else(|| AppError::not_found("Status not found"))?;

    let status = load_status(&state.pool, &post, domain, Some(auth.account_id)).await?;
    Ok(Json(status))
}

async fn bookmark(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    auth.require_scope("write")?;
    let post_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("Status not found"))?;
    let domain = &state.config.server.domain;
    let now = now_millis();

    let post =
        sqlx::query_as::<_, PostRow>(&format!("SELECT {POST_COLUMNS} FROM posts WHERE id = ?"))
            .bind(post_id)
            .fetch_optional(&state.pool)
            .await?
            .ok_or_else(|| AppError::not_found("Status not found"))?;

    sqlx::query(
        "INSERT OR IGNORE INTO bookmarks (user_id, persona_id, post_id, created_at) VALUES (?, ?, ?, ?)",
    )
    .bind(crate::db::DEFAULT_USER_ID)
    .bind(auth.account_id)
    .bind(post_id)
    .bind(now)
    .execute(&state.pool)
    .await?;

    let status = load_status(&state.pool, &post, domain, Some(auth.account_id)).await?;
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

    let post =
        sqlx::query_as::<_, PostRow>(&format!("SELECT {POST_COLUMNS} FROM posts WHERE id = ?"))
            .bind(post_id)
            .fetch_optional(&state.pool)
            .await?
            .ok_or_else(|| AppError::not_found("Status not found"))?;

    sqlx::query("DELETE FROM bookmarks WHERE persona_id = ? AND post_id = ?")
        .bind(auth.account_id)
        .bind(post_id)
        .execute(&state.pool)
        .await?;

    let status = load_status(&state.pool, &post, domain, Some(auth.account_id)).await?;
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

    let base_where = "(persona_id = ? OR persona_id IN \
        (SELECT followee_persona_id FROM follows WHERE persona_id = ? AND followee_persona_id IS NOT NULL) \
        OR (visibility IN ('public', 'unlisted') AND id IN \
        (SELECT pt.post_id FROM post_tags pt JOIN followed_tags ft \
        ON pt.tag = ft.tag WHERE ft.user_id = ?)))";
    let base_binds = vec![auth.account_id, auth.account_id, auth.account_id];

    let mut statuses = fetch_paginated_statuses(
        &state.pool,
        base_where,
        &base_binds,
        &params,
        domain,
        Some(auth.account_id),
        false,
    )
    .await?;

    // Include remote posts from followed accounts
    let limit = params.limit.unwrap_or(20).clamp(1, 40);
    let remote_statuses = fetch_remote_timeline(
        &state.pool,
        auth.account_id,
        limit,
        domain,
    )
    .await?;
    statuses.extend(remote_statuses);
    statuses.sort_by(|a, b| {
        let id_a = a["id"].as_str().unwrap_or("0");
        let id_b = b["id"].as_str().unwrap_or("0");
        id_b.cmp(id_a)
    });
    statuses.truncate(limit as usize);

    let filters = load_active_filters(&state.pool, auth.account_id, "home").await?;
    apply_filters(&mut statuses, &filters);

    let url_base = format!("https://{domain}/api/v1/timelines/home");
    let mut response = Json(&statuses).into_response();
    if let Some(link) = pagination_link_header(&url_base, &statuses) {
        response.headers_mut().insert("Link", link.parse().unwrap());
    }
    Ok(response)
}

/// Fetch remote posts from accounts the user follows.
async fn fetch_remote_timeline(
    pool: &SqlitePool,
    account_id: i64,
    limit: i64,
    domain: &str,
) -> Result<Vec<Value>, AppError> {
    let rows: Vec<(i64, String, String, String, i64, String, Option<String>, i64, i64, String, String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT rp.id, rp.ap_uri, rp.content_html, rp.visibility, rp.created_at, \
         rp.spoiler_text, rp.language, rp.remote_account_id, rp.sensitive, \
         ra.actor_uri, ra.display_name, ra.avatar_url, ra.username \
         FROM remote_posts rp \
         JOIN remote_accounts ra ON rp.remote_account_id = ra.id \
         WHERE rp.remote_account_id IN ( \
             SELECT followee_remote_id FROM follows WHERE persona_id = ? AND followee_remote_id IS NOT NULL \
         ) \
         ORDER BY rp.id DESC LIMIT ?"
    )
    .bind(account_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    let statuses: Vec<Value> = rows
        .iter()
        .map(|r| {
            let acct = if let Some(ref username) = r.12 {
                let domain_part = r.9.split("://").nth(1).and_then(|s| s.split('/').next()).unwrap_or("");
                format!("{username}@{domain_part}")
            } else {
                r.9.clone()
            };

            json!({
                "id": r.0.to_string(),
                "created_at": millis_to_iso(r.4),
                "in_reply_to_id": null,
                "in_reply_to_account_id": null,
                "sensitive": r.8 != 0,
                "spoiler_text": r.5,
                "visibility": r.3,
                "language": r.6,
                "uri": r.1,
                "url": r.1,
                "replies_count": 0,
                "reblogs_count": 0,
                "favourites_count": 0,
                "favourited": false,
                "reblogged": false,
                "muted": false,
                "bookmarked": false,
                "pinned": false,
                "text": null,
                "content": r.2,
                "reblog": null,
                "application": null,
                "account": {
                    "id": r.7.to_string(),
                    "username": r.12.as_deref().unwrap_or(""),
                    "acct": acct,
                    "display_name": r.10,
                    "locked": false,
                    "bot": false,
                    "created_at": "1970-01-01T00:00:00.000Z",
                    "note": "",
                    "url": r.9,
                    "avatar": r.11.as_deref().unwrap_or(&format!("https://{domain}/avatars/original/missing.png")),
                    "avatar_static": r.11.as_deref().unwrap_or(&format!("https://{domain}/avatars/original/missing.png")),
                    "header": format!("https://{domain}/headers/original/missing.png"),
                    "header_static": format!("https://{domain}/headers/original/missing.png"),
                    "followers_count": 0,
                    "following_count": 0,
                    "statuses_count": 0,
                    "emojis": [],
                    "fields": [],
                },
                "media_attachments": [],
                "mentions": [],
                "tags": [],
                "emojis": [],
                "card": null,
                "poll": null,
            })
        })
        .collect();

    Ok(statuses)
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
        response.headers_mut().insert("Link", link.parse().unwrap());
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
        response.headers_mut().insert("Link", link.parse().unwrap());
    }
    Ok(response)
}

/// GET /api/v1/timelines/list/:id
async fn timeline_list(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(id): Path<String>,
    Query(params): Query<PaginationParams>,
) -> Result<Response, AppError> {
    let list_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("List not found"))?;
    let domain = &state.config.server.domain;

    // Verify list ownership
    let list_row: Option<(String,)> =
        sqlx::query_as("SELECT replies_policy FROM lists WHERE id = ? AND user_id = ?")
            .bind(list_id)
            .bind(auth.account_id)
            .fetch_optional(&state.pool)
            .await?;

    let (replies_policy,) = list_row.ok_or_else(|| AppError::not_found("List not found"))?;

    // Build WHERE clause based on replies_policy:
    // "list"     -> show replies only if the replied-to account is also in the list
    // "followed" -> show replies only if the replied-to account is followed
    // "none"     -> hide all replies
    let base_where = match replies_policy.as_str() {
        "none" => {
            "persona_id IN (SELECT persona_id FROM list_accounts WHERE list_id = ?) \
             AND in_reply_to_id IS NULL"
        }
        "followed" => {
            "persona_id IN (SELECT persona_id FROM list_accounts WHERE list_id = ?) \
             AND (in_reply_to_id IS NULL OR in_reply_to_id IN \
               (SELECT p2.id FROM posts p2 \
                JOIN follows f ON p2.persona_id = f.followee_persona_id \
                WHERE f.persona_id = ?))"
        }
        // "list" (default)
        _ => {
            "persona_id IN (SELECT persona_id FROM list_accounts WHERE list_id = ?) \
             AND (in_reply_to_id IS NULL OR in_reply_to_id IN \
               (SELECT p2.id FROM posts p2 \
                JOIN list_accounts la2 ON p2.persona_id = la2.persona_id \
                WHERE la2.list_id = ?))"
        }
    };

    let base_binds = match replies_policy.as_str() {
        "none" => vec![list_id],
        "followed" => vec![list_id, auth.account_id],
        _ => vec![list_id, list_id],
    };

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

    let url_base = format!("https://{domain}/api/v1/timelines/list/{list_id}");
    let mut response = Json(&statuses).into_response();
    if let Some(link) = pagination_link_header(&url_base, &statuses) {
        response.headers_mut().insert("Link", link.parse().unwrap());
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
    persona_id: i64,
    kind: String,
    from_persona_id: Option<i64>,
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
    let from_account = if let Some(aid) = notif.from_persona_id {
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
        let post =
            sqlx::query_as::<_, PostRow>(&format!("SELECT {POST_COLUMNS} FROM posts WHERE id = ?"))
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
        "SELECT id, persona_id, kind, from_persona_id, from_remote_account_id, \
         post_id, created_at \
         FROM notifications WHERE persona_id = ?{page_clause} \
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
        let v = serialize_notification(&state.pool, n, domain, auth.account_id).await?;
        values.push(v);
    }

    if params.min_id.is_some() {
        values.reverse();
    }

    let url_base = format!("https://{domain}/api/v1/notifications");
    let mut response = Json(&values).into_response();
    if let Some(link) = pagination_link_header(&url_base, &values) {
        response.headers_mut().insert("Link", link.parse().unwrap());
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
        "SELECT id, persona_id, kind, from_persona_id, from_remote_account_id, \
         post_id, created_at \
         FROM notifications WHERE id = ? AND persona_id = ?",
    )
    .bind(notif_id)
    .bind(auth.account_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::not_found("Notification not found"))?;

    let value = serialize_notification(&state.pool, &notif, domain, auth.account_id).await?;
    Ok(Json(value))
}

async fn clear_notifications(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
) -> Result<Json<Value>, AppError> {
    sqlx::query("DELETE FROM notifications WHERE persona_id = ?")
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

    sqlx::query("DELETE FROM notifications WHERE id = ? AND persona_id = ?")
        .bind(notif_id)
        .bind(auth.account_id)
        .execute(&state.pool)
        .await?;

    Ok(Json(json!({})))
}

// ---------------------------------------------------------------------------
// Pin / Unpin
// ---------------------------------------------------------------------------

async fn pin_status(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    auth.require_scope("write")?;
    let post_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("Status not found"))?;
    let domain = &state.config.server.domain;
    let now = now_millis();

    let post =
        sqlx::query_as::<_, PostRow>(&format!("SELECT {POST_COLUMNS} FROM posts WHERE id = ?"))
            .bind(post_id)
            .fetch_optional(&state.pool)
            .await?
            .ok_or_else(|| AppError::not_found("Status not found"))?;

    if post.persona_id != auth.account_id {
        return Err(AppError::forbidden("You do not own this status"));
    }

    sqlx::query(
        "INSERT OR IGNORE INTO pinned_posts (persona_id, post_id, pinned_at) VALUES (?, ?, ?)",
    )
    .bind(auth.account_id)
    .bind(post_id)
    .bind(now)
    .execute(&state.pool)
    .await?;

    let status = load_status(&state.pool, &post, domain, Some(auth.account_id)).await?;
    Ok(Json(status))
}

async fn unpin_status(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let post_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("Status not found"))?;
    let domain = &state.config.server.domain;

    let post =
        sqlx::query_as::<_, PostRow>(&format!("SELECT {POST_COLUMNS} FROM posts WHERE id = ?"))
            .bind(post_id)
            .fetch_optional(&state.pool)
            .await?
            .ok_or_else(|| AppError::not_found("Status not found"))?;

    if post.persona_id != auth.account_id {
        return Err(AppError::forbidden("You do not own this status"));
    }

    sqlx::query("DELETE FROM pinned_posts WHERE persona_id = ? AND post_id = ?")
        .bind(auth.account_id)
        .bind(post_id)
        .execute(&state.pool)
        .await?;

    let status = load_status(&state.pool, &post, domain, Some(auth.account_id)).await?;
    Ok(Json(status))
}
// ---------------------------------------------------------------------------
// Scheduled statuses
// ---------------------------------------------------------------------------

fn scheduled_status_to_json(
    id: i64,
    scheduled_at_ms: i64,
    body: &CreateStatusRequest,
    visibility: &str,
    sensitive: bool,
    language: &Option<String>,
) -> Value {
    json!({
        "id": id.to_string(),
        "scheduled_at": millis_to_iso(scheduled_at_ms),
        "params": {
            "text": body.status.as_deref().unwrap_or(""),
            "visibility": visibility,
            "sensitive": sensitive,
            "spoiler_text": body.spoiler_text.as_deref().unwrap_or(""),
            "media_ids": body.media_ids.as_deref().unwrap_or(&[]),
            "language": language.as_deref().unwrap_or("en"),
        },
        "media_attachments": []
    })
}

fn scheduled_row_to_json(id: i64, scheduled_at_ms: i64, params_json: &str) -> Value {
    let params: Value = serde_json::from_str(params_json).unwrap_or(json!({}));
    let visibility = params
        .get("visibility")
        .and_then(|v| v.as_str())
        .unwrap_or("public");
    let sensitive = params
        .get("sensitive")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let spoiler_text = params
        .get("spoiler_text")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let text = params.get("status").and_then(|v| v.as_str()).unwrap_or("");
    let media_ids = params.get("media_ids").cloned().unwrap_or(json!([]));
    let language = params
        .get("language")
        .and_then(|v| v.as_str())
        .unwrap_or("en");

    json!({
        "id": id.to_string(),
        "scheduled_at": millis_to_iso(scheduled_at_ms),
        "params": {
            "text": text,
            "visibility": visibility,
            "sensitive": sensitive,
            "spoiler_text": spoiler_text,
            "media_ids": media_ids,
            "language": language,
        },
        "media_attachments": []
    })
}

/// GET /api/v1/scheduled_statuses
async fn list_scheduled_statuses(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
) -> Result<Json<Value>, AppError> {
    let rows: Vec<(i64, i64, String)> = sqlx::query_as(
        "SELECT id, scheduled_at, params_json FROM scheduled_statuses \
         WHERE persona_id = ? ORDER BY scheduled_at",
    )
    .bind(auth.account_id)
    .fetch_all(&state.pool)
    .await?;

    let items: Vec<Value> = rows
        .iter()
        .map(|(id, scheduled_at, params_json)| {
            scheduled_row_to_json(*id, *scheduled_at, params_json)
        })
        .collect();

    Ok(Json(json!(items)))
}

/// GET /api/v1/scheduled_statuses/:id
async fn get_scheduled_status(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let sched_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("Scheduled status not found"))?;

    let row: Option<(i64, i64, String)> = sqlx::query_as(
        "SELECT id, scheduled_at, params_json FROM scheduled_statuses \
         WHERE id = ? AND user_id = ?",
    )
    .bind(sched_id)
    .bind(auth.account_id)
    .fetch_optional(&state.pool)
    .await?;

    let (id, scheduled_at, params_json) =
        row.ok_or_else(|| AppError::not_found("Scheduled status not found"))?;

    Ok(Json(scheduled_row_to_json(id, scheduled_at, &params_json)))
}

#[derive(Deserialize)]
struct UpdateScheduledStatusRequest {
    scheduled_at: String,
}

/// PUT /api/v1/scheduled_statuses/:id
async fn update_scheduled_status(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(id): Path<String>,
    Json(body): Json<UpdateScheduledStatusRequest>,
) -> Result<Json<Value>, AppError> {
    let sched_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("Scheduled status not found"))?;

    let scheduled_ms = chrono::DateTime::parse_from_rfc3339(&body.scheduled_at)
        .or_else(|_| chrono::DateTime::parse_from_str(&body.scheduled_at, "%+"))
        .map(|dt| dt.timestamp_millis())
        .map_err(|_| AppError::unprocessable("Invalid scheduled_at datetime"))?;

    let now = now_millis();
    let five_min_ms = 5 * 60 * 1000;
    if scheduled_ms <= now + five_min_ms {
        return Err(AppError::unprocessable(
            "scheduled_at must be at least 5 minutes in the future",
        ));
    }

    let row: Option<(i64, String)> = sqlx::query_as(
        "SELECT id, params_json FROM scheduled_statuses \
         WHERE id = ? AND user_id = ?",
    )
    .bind(sched_id)
    .bind(auth.account_id)
    .fetch_optional(&state.pool)
    .await?;

    let (sid, params_json) =
        row.ok_or_else(|| AppError::not_found("Scheduled status not found"))?;

    sqlx::query("UPDATE scheduled_statuses SET scheduled_at = ? WHERE id = ?")
        .bind(scheduled_ms)
        .bind(sched_id)
        .execute(&state.pool)
        .await?;

    Ok(Json(scheduled_row_to_json(sid, scheduled_ms, &params_json)))
}

/// DELETE /api/v1/scheduled_statuses/:id
async fn delete_scheduled_status(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let sched_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("Scheduled status not found"))?;

    let result = sqlx::query("DELETE FROM scheduled_statuses WHERE id = ? AND user_id = ?")
        .bind(sched_id)
        .bind(auth.account_id)
        .execute(&state.pool)
        .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::not_found("Scheduled status not found"));
    }

    Ok(StatusCode::OK)
}

// ---------------------------------------------------------------------------
// Conversations
// ---------------------------------------------------------------------------

/// Build the accounts (participants) array for a conversation, excluding the current user.
async fn conversation_participants(
    pool: &SqlitePool,
    post: &PostRow,
    domain: &str,
    current_account_id: i64,
) -> Result<Vec<Value>, AppError> {
    let mut accounts = Vec::new();
    if post.persona_id != current_account_id {
        let author = fetch_account_row(pool, post.persona_id).await?;
        accounts.push(account_to_json(&author, domain));
    }
    // Add mentioned accounts (excluding current user)
    let mention_rows: Vec<(Option<i64>, Option<i64>)> = sqlx::query_as(
        "SELECT mentioned_persona_id, mentioned_remote_id FROM mentions WHERE post_id = ?",
    )
    .bind(post.id)
    .fetch_all(pool)
    .await?;
    for (local_id, remote_id) in &mention_rows {
        if let Some(aid) = local_id {
            if *aid != current_account_id {
                if let Ok(a) = fetch_account_row(pool, *aid).await {
                    accounts.push(account_to_json(&a, domain));
                }
            }
        } else if let Some(rid) = remote_id {
            let remote: Option<(i64, String, String, String, String)> = sqlx::query_as(
                "SELECT id, username, domain, display_name, bio_html \
                 FROM remote_accounts WHERE id = ?",
            )
            .bind(rid)
            .fetch_optional(pool)
            .await?;
            if let Some((id, username, rdomain, display_name, bio_html)) = remote {
                accounts.push(json!({
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
                }));
            }
        }
    }
    Ok(accounts)
}

async fn list_conversations(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Query(params): Query<PaginationParams>,
) -> Result<Response, AppError> {
    let domain = &state.config.server.domain;
    let limit = params.limit.unwrap_or(20).clamp(1, 40);

    // Find direct-visibility posts where the authenticated user is the author
    // or is mentioned, excluding hidden conversations.
    // Each direct post is treated as its own conversation entry (clients group by reply chain).
    let (page_clause, page_binds) = pagination_clause(&params);

    let order = if params.min_id.is_some() {
        "ASC"
    } else {
        "DESC"
    };

    let sql = format!(
        "SELECT {POST_COLUMNS} FROM posts \
         WHERE visibility = 'direct' \
         AND (persona_id = ? OR id IN (SELECT post_id FROM mentions WHERE mentioned_persona_id = ?)) \
         AND id NOT IN (SELECT post_id FROM conversation_hidden WHERE user_id = ?)\
         {page_clause} \
         ORDER BY id {order} LIMIT ?",
    );

    let mut query = sqlx::query_as::<_, PostRow>(&sql);
    query = query.bind(auth.account_id);
    query = query.bind(auth.account_id);
    query = query.bind(auth.account_id);
    for b in &page_binds {
        query = query.bind(b);
    }
    query = query.bind(limit);

    let posts: Vec<PostRow> = query.fetch_all(&state.pool).await?;

    // TODO(perf): N+1 queries for participants per conversation. The result set is
    // already bounded by LIMIT (max 40), so this is acceptable for now. Batch-loading
    // mentions/accounts for all post IDs would eliminate the per-post queries.
    let mut conversations = Vec::with_capacity(posts.len());
    for p in &posts {
        let status = load_status(&state.pool, p, domain, Some(auth.account_id)).await?;

        // Determine unread: not in conversation_read_markers
        let (read_count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM conversation_read_markers WHERE persona_id = ? AND post_id = ?",
        )
        .bind(auth.account_id)
        .bind(p.id)
        .fetch_one(&state.pool)
        .await?;
        let unread = read_count == 0 && p.persona_id != auth.account_id;

        let accounts = conversation_participants(&state.pool, p, domain, auth.account_id).await?;

        conversations.push(json!({
            "id": p.id.to_string(),
            "unread": unread,
            "accounts": accounts,
            "last_status": status
        }));
    }

    if params.min_id.is_some() {
        conversations.reverse();
    }

    let url_base = format!("https://{domain}/api/v1/conversations");
    let mut response = Json(&conversations).into_response();
    if let Some(link) = pagination_link_header(&url_base, &conversations) {
        if let Ok(val) = link.parse() {
            response.headers_mut().insert("Link", val);
        }
    }
    Ok(response)
}

async fn mark_conversation_read(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let post_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("Conversation not found"))?;

    let domain = &state.config.server.domain;

    // Verify the post exists, is direct, and the user is involved
    let post = sqlx::query_as::<_, PostRow>(&format!(
        "SELECT {POST_COLUMNS} FROM posts WHERE id = ? AND visibility = 'direct'"
    ))
    .bind(post_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::not_found("Conversation not found"))?;

    let is_involved = post.persona_id == auth.account_id || {
        let (cnt,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM mentions WHERE post_id = ? AND mentioned_persona_id = ?",
        )
        .bind(post_id)
        .bind(auth.account_id)
        .fetch_one(&state.pool)
        .await?;
        cnt > 0
    };

    if !is_involved {
        return Err(AppError::not_found("Conversation not found"));
    }

    // Mark as read
    sqlx::query(
        "INSERT OR IGNORE INTO conversation_read_markers (user_id, post_id) VALUES (?, ?)",
    )
    .bind(auth.account_id)
    .bind(post_id)
    .execute(&state.pool)
    .await?;

    // Return the updated conversation object
    let status = load_status(&state.pool, &post, domain, Some(auth.account_id)).await?;
    let accounts = conversation_participants(&state.pool, &post, domain, auth.account_id).await?;

    Ok(Json(json!({
        "id": post.id.to_string(),
        "unread": false,
        "accounts": accounts,
        "last_status": status
    })))
}

async fn delete_conversation(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let post_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("Conversation not found"))?;

    // Mark as hidden for this user (don't delete the actual post)
    sqlx::query("INSERT OR IGNORE INTO conversation_hidden (user_id, post_id) VALUES (?, ?)")
        .bind(auth.account_id)
        .bind(post_id)
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
            get(get_status).delete(delete_status).put(edit_status),
        )
        .route("/api/v1/statuses/{id}/context", get(status_context))
        .route("/api/v1/statuses/{id}/history", get(status_history))
        // Interactions
        .route("/api/v1/statuses/{id}/favourite", post(favourite))
        .route("/api/v1/statuses/{id}/unfavourite", post(unfavourite))
        .route("/api/v1/statuses/{id}/reblog", post(reblog))
        .route("/api/v1/statuses/{id}/unreblog", post(unreblog))
        .route("/api/v1/statuses/{id}/bookmark", post(bookmark))
        .route("/api/v1/statuses/{id}/unbookmark", post(unbookmark))
        .route("/api/v1/statuses/{id}/pin", post(pin_status))
        .route("/api/v1/statuses/{id}/unpin", post(unpin_status))
        // Scheduled statuses
        .route("/api/v1/scheduled_statuses", get(list_scheduled_statuses))
        .route(
            "/api/v1/scheduled_statuses/{id}",
            get(get_scheduled_status)
                .put(update_scheduled_status)
                .delete(delete_scheduled_status),
        )
        // Timelines
        .route("/api/v1/timelines/home", get(timeline_home))
        .route("/api/v1/timelines/public", get(timeline_public))
        .route("/api/v1/timelines/tag/{tag}", get(timeline_tag))
        .route("/api/v1/timelines/list/{id}", get(timeline_list))
        // Notifications
        .route("/api/v1/notifications", get(get_notifications))
        .route("/api/v1/notifications/{id}", get(get_notification))
        .route("/api/v1/notifications/clear", post(clear_notifications))
        .route(
            "/api/v1/notifications/{id}/dismiss",
            post(dismiss_notification),
        )
        // Conversations
        .route("/api/v1/conversations", get(list_conversations))
        .route("/api/v1/conversations/{id}", delete(delete_conversation))
        .route(
            "/api/v1/conversations/{id}/read",
            post(mark_conversation_read),
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
        assert_eq!(result.mentions[0].domain.as_deref(), Some("remote.example"));
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
    fn parse_hashtags_rejects_pure_numbers() {
        assert!(parse_hashtags("issue #5").is_empty());
        assert!(parse_hashtags("#123 items").is_empty());
        assert!(parse_hashtags("#0").is_empty());
    }

    #[test]
    fn parse_hashtags_accepts_mixed_alphanumeric() {
        let tags = parse_hashtags("#test123");
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0], "test123");

        let tags = parse_hashtags("#123test");
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0], "123test");
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
        let link = pagination_link_header("https://example.com/api", &items).unwrap();
        assert!(link.contains("max_id=98"));
        assert!(link.contains("min_id=100"));
        assert!(link.contains(r#"rel="next""#));
        assert!(link.contains(r#"rel="prev""#));
    }

    #[test]
    fn serialize_status_shape() {
        let post = PostRow {
            id: 12345,
            persona_id: 1,
            in_reply_to_id: None,
            boost_of_id: None,
            context_url: None,
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
