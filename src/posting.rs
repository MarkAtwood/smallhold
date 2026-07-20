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
    let fwp = crate::server::fw_pool(pool);
    let all_filters = fieldwork::filters_db::get_filters(&fwp, account_id).await?;

    let mut filters = Vec::new();
    for f in all_filters {
        // Check context match and expiry
        if !f.context.contains(&format!("\"{context}\"")) {
            continue;
        }
        if let Some(exp) = f.expires_at {
            if exp <= now {
                continue;
            }
        }

        let kw_rows = fieldwork::filters_db::get_keywords(&fwp, f.id).await?;
        let keywords = kw_rows
            .into_iter()
            .map(|kw| ActiveKeyword {
                keyword: kw.keyword,
                whole_word: kw.whole_word,
            })
            .collect();

        filters.push(ActiveFilter {
            id: f.id,
            title: f.title,
            context_json: f.context,
            filter_action: f.filter_action,
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

/// Local view of a post row used for API serialization.
/// Populated from `fieldwork::posts_db::PostRow` via `fw_to_local_post`.
#[derive(Debug)]
pub struct PostRow {
    pub id: i64,
    pub persona_id: i64,
    pub ap_id: String,
    pub in_reply_to_id: Option<i64>,
    pub in_reply_to_uri: Option<String>,
    pub boost_of_id: Option<i64>,
    pub context_url: Option<String>,
    pub content: String,
    pub content_html: String,
    pub spoiler_text: String,
    pub visibility: String,
    pub sensitive: bool,
    pub language: Option<String>,
    pub created_at: i64,
    pub edited_at: Option<i64>,
}

/// Convert a fieldwork PostRow to our local PostRow.
pub fn fw_to_local_post(p: &fieldwork::posts_db::PostRow) -> PostRow {
    PostRow {
        id: p.id,
        persona_id: p.persona_id,
        ap_id: p.ap_id.clone(),
        in_reply_to_id: p.in_reply_to_id,
        in_reply_to_uri: p.in_reply_to_uri.clone(),
        boost_of_id: p.boost_of_id,
        context_url: p.context_url.clone(),
        content: p.content.clone(),
        content_html: p.content_html.clone(),
        spoiler_text: p.spoiler_text.clone(),
        visibility: p.visibility.clone(),
        sensitive: p.sensitive,
        language: p.language.clone(),
        created_at: p.created_at,
        edited_at: p.edited_at,
    }
}

/// Fetch a local post by ID using fieldwork, returning our local PostRow.
pub async fn get_local_post(pool: &SqlitePool, id: i64) -> Result<Option<PostRow>, AppError> {
    let fwp = crate::server::fw_pool(pool);
    let fw_post = fieldwork::posts_db::get_post(&fwp, id).await?;
    Ok(fw_post.map(|p| fw_to_local_post(&p)))
}

/// Fetch a local post by AP ID using fieldwork.
pub async fn get_local_post_by_ap_id(pool: &SqlitePool, ap_id: &str) -> Result<Option<PostRow>, AppError> {
    let fwp = crate::server::fw_pool(pool);
    let fw_post = fieldwork::posts_db::get_post_by_ap_id(&fwp, ap_id).await?;
    Ok(fw_post.map(|p| fw_to_local_post(&p)))
}

// REMAINING: POST_COLUMNS and sqlx_row_to_post are needed for dynamic SQL queries
// (paginated timelines, CTEs, conversation queries) that fieldwork doesn't support.
// These use complex WHERE clauses, JOINs, and dynamic pagination that can't be
// expressed through fieldwork's fixed query functions.
pub const POST_COLUMNS: &str =
    "id, persona_id, ap_id, in_reply_to_id, in_reply_to_uri, boost_of_id, context_url, content, content_html, \
     spoiler_text, visibility, sensitive, language, created_at, edited_at";

pub fn sqlx_row_to_post_pub(row: sqlx::sqlite::SqliteRow) -> PostRow {
    sqlx_row_to_post(row)
}

fn sqlx_row_to_post(row: sqlx::sqlite::SqliteRow) -> PostRow {
    use sqlx::Row;
    PostRow {
        id: row.get(0),
        persona_id: row.get(1),
        ap_id: row.get(2),
        in_reply_to_id: row.get(3),
        in_reply_to_uri: row.get(4),
        boost_of_id: row.get(5),
        context_url: row.get(6),
        content: row.get(7),
        content_html: row.get(8),
        spoiler_text: row.get(9),
        visibility: row.get(10),
        sensitive: row.get(11),
        language: row.get(12),
        created_at: row.get(13),
        edited_at: row.get(14),
    }
}

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
    let fwp_media = crate::server::fw_pool(pool);
    let media = fieldwork::media_db::attachments_for_post(&fwp_media, post.id).await?;

    let media_values: Vec<Value> = media
        .iter()
        .map(|m| {
                json!({
                    "id": m.id.to_string(),
                    "type": media_type_from_mime(&m.mime_type),
                    "url": format!("https://{domain}/media/{}", m.file_path),
                    "preview_url": format!("https://{domain}/media/{}", m.file_path),
                    "remote_url": null,
                    "meta": {
                        "original": {
                            "width": m.width,
                            "height": m.height
                        }
                    },
                    "description": m.description,
                    "blurhash": m.blurhash
                })
        })
        .collect();

    // Fetch tags
    let fwp_tags = crate::server::fw_pool(pool);
    let tag_strings = fieldwork::post_tags_db::get_tags(&fwp_tags, post.id).await?;
    let tag_vals = tag_values_for_post(&tag_strings, domain);

    // Fetch mentions for display
    let fwp_mentions = crate::server::fw_pool(pool);
    let fw_mentions = fieldwork::mentions_db::get_mentions(&fwp_mentions, post.id).await?;
    let mention_rows: Vec<(Option<i64>, Option<i64>)> = fw_mentions
        .into_iter()
        .map(|m| (m.mentioned_persona_id, m.mentioned_remote_id))
        .collect();

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
            let remote: Option<(i64, String, String)> = {
                let r = crate::db_extras::get_remote_account_by_id(pool, *rid).await?;
                r.map(|(id, username, domain, _, _)| (id, username, domain))
            };
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
        let fav = fieldwork::interactions_db::is_favourited(
            &crate::server::fw_pool(pool), viewer, post.id,
        ).await?;

        let boost_count = crate::db_extras::count_boosts_by_persona(pool, viewer, post.id).await?;
        let bmark_count = crate::db_extras::count_bookmarks(pool, viewer, post.id).await?;

        (fav, boost_count > 0, bmark_count > 0)
    } else {
        (false, false, false)
    };

    // Handle reblog (boost_of_id)
    let reblog_value = if let Some(boost_id) = post.boost_of_id {
        let boosted: Option<PostRow> =
            get_local_post(pool, boost_id).await?;
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
        crate::db_extras::is_pinned(pool, post.persona_id, post.id).await?,
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
    base_binds: &[String],
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

    let mut all_binds: Vec<String> = base_binds.to_vec();
    for b in &page_binds {
        all_binds.push(b.to_string());
    }
    let rows = crate::db_extras::execute_dynamic_query(pool, &sql, &all_binds, limit).await?;
    let posts: Vec<PostRow> = rows.into_iter().map(sqlx_row_to_post).collect();

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
        let existing = fieldwork::idempotency_db::check_key(
            &crate::server::fw_pool(&state.pool),
            &key_hash,
            auth.account_id,
        )
        .await?;

        if let Some(post_id) = existing {
            let post = get_local_post(&state.pool, post_id).await?
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

            fieldwork::scheduled_db::create_scheduled(
                &crate::server::fw_pool(&state.pool),
                &fieldwork::scheduled_db::ScheduledRow {
                    id: sched_id,
                    user_id: crate::db::DEFAULT_USER_ID,
                    persona_id: auth.account_id,
                    scheduled_at: scheduled_ms,
                    params_json: params_json.clone(),
                    created_at: now,
                },
            ).await?;

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
            let parent_post = get_local_post(&state.pool, parent_id).await?;
            let parent_ctx = parent_post.map(|p| (p.context_url, p.ap_id, p.created_at));
            match parent_ctx {
                Some((Some(url), _, _)) => url,
                Some((None, parent_ap_id, _)) => format!("{parent_ap_id}/context"),
                None => format!("{ap_id}/context"),
            }
        }
        None => format!("{ap_id}/context"),
    };

    fieldwork::posts_db::create_post(
        &crate::server::fw_pool(&state.pool),
        &fieldwork::posts_db::PostRow {
            id: post_id,
            user_id: crate::db::DEFAULT_USER_ID,
            persona_id: auth.account_id,
            ap_id: ap_id.clone(),
            in_reply_to_id,
            in_reply_to_uri: None,
            boost_of_id: None,
            boost_of_uri: None,
            content: text.clone(),
            content_html: rendered.html.clone(),
            spoiler_text: spoiler_text.clone(),
            visibility: visibility.clone(),
            sensitive,
            language: language.clone(),
            context_url: Some(context_url.clone()),
            created_at: now,
            edited_at: None,
            deleted_at: None,
            deleted_reason: None,
        },
    ).await?;

    // Attach media
    // REMAINING: media attach (UPDATE with WHERE post_id IS NULL) — no fieldwork equivalent
    for mid in &media_ids {
        crate::db_extras::attach_media_to_post(&state.pool, post_id, *mid, auth.account_id).await?;
    }

    // Insert mentions
    for m in &rendered.mentions {
        match &m.domain {
            None => {
                let local_persona = fieldwork::persona_db::get_persona_by_username(
                    &crate::server::fw_pool(&state.pool), &m.username,
                ).await?;
                let local: Option<(i64,)> = local_persona.map(|p| (p.id,));
                if let Some((aid,)) = local {
                    fieldwork::mentions_db::add_mention(
                        &crate::server::fw_pool(&state.pool),
                        post_id, None, Some(aid),
                    ).await?;

                    // Notification for local mention (dedup via unique index)
                    // Skip self-mentions — don't notify the author about their own post
                    if aid != auth.account_id {
                        let notif_id = generate_id();
                        fieldwork::notifications_db::create_notification(
                            &crate::server::fw_pool(&state.pool),
                            &fieldwork::notifications_db::NotificationRow {
                                id: notif_id,
                                user_id: crate::db::DEFAULT_USER_ID,
                                persona_id: aid,
                                kind: "mention".to_string(),
                                from_persona_id: Some(auth.account_id),
                                from_remote_account_id: None,
                                post_id: Some(post_id),
                                remote_post_id: None,
                                created_at: now,
                                read_at: None,
                            },
                        ).await?;

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
                let remote_acct = fieldwork::actor_cache::get_by_webfinger(
                    &crate::server::fw_pool(&state.pool), &m.username, mention_domain,
                ).await?;
                let remote: Option<(i64,)> = remote_acct.map(|r| (r.id,));
                if let Some((rid,)) = remote {
                    fieldwork::mentions_db::add_mention(
                        &crate::server::fw_pool(&state.pool),
                        post_id, Some(rid), None,
                    ).await?;
                }
            }
        }
    }

    // Insert tags
    let fwp = crate::server::fw_pool(&state.pool);
    fieldwork::post_tags_db::add_tags(&fwp, post_id, &rendered.tags).await?;

    // Store idempotency key
    if let Some(idem_key) = headers.get("Idempotency-Key").and_then(|v| v.to_str().ok()) {
        let key_hash = sha256_hex(idem_key.as_bytes());
        fieldwork::idempotency_db::store_key(&fwp, &key_hash, auth.account_id, post_id, now).await?;
    }

    crate::db_extras::touch_persona_last_status(&state.pool, auth.account_id, now).await?;

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
                            let remote_uri = crate::db_extras::get_remote_actor_uri_by_webfinger(&state.pool, &m.username, mention_domain).await?;
                            if let Some(actor_uri) = remote_uri {
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
                    let remote_acct = fieldwork::actor_cache::get_by_webfinger(
                        &crate::server::fw_pool(&state.pool), &m.username, mention_domain,
                    ).await?;
                    if let Some(ref ra) = remote_acct {
                        let actor_uri = ra.actor_uri.clone();
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
                let original_ap_id = crate::db_extras::get_post_ap_id(&state.pool, rid).await?;
                Some(json!(original_ap_id.unwrap_or_else(
                    || format!("https://{domain}/users/{}/statuses/{rid}", auth.username)
                )))
            }
            None => None,
        };

        // Query media attachments for the AP Note
        let fwp_apm = crate::server::fw_pool(&state.pool);
        let ap_media_rows = fieldwork::media_db::attachments_for_post(&fwp_apm, post_id).await?;
        let ap_media: Vec<(String, String, Option<i32>, Option<i32>, Option<String>, String)> =
            ap_media_rows.iter().map(|m| (
                m.file_path.clone(), m.mime_type.clone(),
                m.width, m.height, m.blurhash.clone(), m.description.clone(),
            )).collect();

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
                    let remote_acct = fieldwork::actor_cache::get_by_webfinger(
                        &crate::server::fw_pool(&state.pool), &m.username, mention_domain,
                    ).await?;
                    if let Some(ref ra) = remote_acct {
                        let inbox_url = ra.inbox_url.clone();
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
        get_local_post(&state.pool, post_id).await?.ok_or_else(|| AppError::not_found("Post not found"))?;

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
        get_local_post(&state.pool, post_id).await?
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
        {
            let fwp_md = crate::server::fw_pool(&state.pool);
            let media_rows = fieldwork::media_db::attachments_for_post(&fwp_md, post_id).await?;
            media_rows.into_iter().map(|m| (m.file_path,)).collect()
        };

    // Delete related rows then the post, all in a transaction
    let mut tx = state.pool.begin().await?;
    crate::db_extras::delete_post_related(&mut tx, post_id).await?;
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
        get_local_post(&state.pool, post_id).await?
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
    crate::db_extras::save_post_edit_history(&state.pool, generate_id(), post_id).await?;

    // Update the post row
    crate::db_extras::update_post_full(&state.pool, post_id, &text, &rendered.html, &spoiler_text, sensitive, &language, now).await?;

    // Delete old mentions and tags, re-insert new ones
    let fwp_del = crate::server::fw_pool(&state.pool);
    fieldwork::mentions_db::remove_mentions(&fwp_del, post_id).await?;
    fieldwork::post_tags_db::remove_tags(&fwp_del, post_id).await?;

    let fwp_edit = crate::server::fw_pool(&state.pool);
    for m in &rendered.mentions {
        match &m.domain {
            None => {
                let local = fieldwork::persona_db::get_persona_by_username(&fwp_edit, &m.username).await?;
                if let Some(p) = local {
                    fieldwork::mentions_db::add_mention(&fwp_edit, post_id, None, Some(p.id)).await?;
                }
            }
            Some(mention_domain) => {
                let remote = fieldwork::actor_cache::get_by_webfinger(&fwp_edit, &m.username, mention_domain).await?;
                if let Some(r) = remote {
                    fieldwork::mentions_db::add_mention(&fwp_edit, post_id, Some(r.id), None).await?;
                }
            }
        }
    }

    fieldwork::post_tags_db::add_tags(&fwp_edit, post_id, &rendered.tags).await?;

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
                    let remote_acct = fieldwork::actor_cache::get_by_webfinger(
                        &crate::server::fw_pool(&state.pool), &m.username, mention_domain,
                    ).await?;
                    if let Some(ref ra) = remote_acct {
                        let actor_uri = ra.actor_uri.clone();
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
        let reply_post = get_local_post(&state.pool, post_id).await?
            .ok_or_else(|| AppError::not_found("Post not found"))?;
        let in_reply_to_uri = reply_post.in_reply_to_uri;

        // Query media attachments for the AP Note
        let fwp_apm = crate::server::fw_pool(&state.pool);
        let ap_media_rows = fieldwork::media_db::attachments_for_post(&fwp_apm, post_id).await?;
        let ap_media: Vec<(String, String, Option<i32>, Option<i32>, Option<String>, String)> =
            ap_media_rows.iter().map(|m| (
                m.file_path.clone(), m.mime_type.clone(),
                m.width, m.height, m.blurhash.clone(), m.description.clone(),
            )).collect();

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
        get_local_post(&state.pool, post_id).await?.ok_or_else(|| AppError::not_found("Post not found"))?;

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
        get_local_post(&state.pool, post_id).await?
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
        get_local_post(&state.pool, post_id).await?
            .ok_or_else(|| AppError::not_found("Status not found"))?;

    // For non-public posts, history is not exposed (simplification)
    if post.visibility == "direct" || post.visibility == "private" {
        return Err(AppError::not_found("Status not found"));
    }

    let account = fetch_account_row(&state.pool, post.persona_id).await?;
    let account_json = account_to_json(&account, domain);

    // Fetch previous versions from post_edits, ordered oldest first
    let edits: Vec<(String, String, String, bool, i64)> = crate::db_extras::get_post_edits(&state.pool, post_id).await?;

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
        get_local_post(&state.pool, post_id).await?
            .ok_or_else(|| AppError::not_found("Status not found"))?;

    // Ancestors: walk up the reply chain
    let mut ancestors = Vec::new();
    let mut current_id = target.in_reply_to_id;
    while let Some(parent_id) = current_id {
        let parent =
            get_local_post(&state.pool, parent_id).await?;

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

    // REMAINING: recursive CTE for thread descendants — no fieldwork equivalent
    let prefixed_cols = POST_COLUMNS.replace(", ", ", p.");
    let cte_sql = format!(
        "WITH RECURSIVE thread(id, depth) AS ( \
            SELECT id, 1 FROM posts WHERE in_reply_to_id = ? \
            UNION ALL \
            SELECT p.id, t.depth + 1 FROM posts p JOIN thread t ON p.in_reply_to_id = t.id WHERE t.depth < 200 \
         ) \
         SELECT p.{prefixed_cols} FROM thread t JOIN posts p ON t.id = p.id \
         ORDER BY p.id ASC LIMIT 500",
    );
    let descendants_rows = crate::db_extras::execute_raw_query(&state.pool, &cte_sql, &[post_id.to_string()]).await
        // ponytail: if the CTE alias fails, fall back to the simple form
        .unwrap_or_default();
    let descendants_posts: Vec<PostRow> = descendants_rows.into_iter().map(sqlx_row_to_post).collect();

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
        get_local_post(&state.pool, post_id).await?
            .ok_or_else(|| AppError::not_found("Status not found"))?;

    fieldwork::interactions_db::favourite(
        &crate::server::fw_pool(&state.pool),
        crate::db::DEFAULT_USER_ID, auth.account_id, Some(post_id), None, now,
    ).await?;

    if post.persona_id != auth.account_id {
        let notif_id = generate_id();
        fieldwork::notifications_db::create_notification(
            &crate::server::fw_pool(&state.pool),
            &fieldwork::notifications_db::NotificationRow {
                id: notif_id,
                user_id: crate::db::DEFAULT_USER_ID,
                persona_id: post.persona_id,
                kind: "favourite".to_string(),
                from_persona_id: Some(auth.account_id),
                from_remote_account_id: None,
                post_id: Some(post_id),
                remote_post_id: None,
                created_at: now,
                read_at: None,
            },
        ).await?;

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
        let ap_id = get_local_post(&state.pool, post_id).await?.map(|p| (p.ap_id,));
        let local_prefix = format!("https://{domain}/");
        if let Some((ref post_ap_id,)) = ap_id {
            if !post_ap_id.starts_with(&local_prefix) {
                // Remote post — extract the actor URI and find their inbox
                let actor_uri = post_ap_id.rfind("/statuses/").map(|i| &post_ap_id[..i]);
                if let Some(actor) = actor_uri {
                    let ra = fieldwork::actor_cache::get_by_actor_uri(
                        &crate::server::fw_pool(&state.pool), actor,
                    ).await?;
                    let inbox: Option<(String,)> = ra.map(|r| {
                        (r.shared_inbox_url.unwrap_or(r.inbox_url),)
                    });
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
        get_local_post(&state.pool, post_id).await?
            .ok_or_else(|| AppError::not_found("Status not found"))?;

    fieldwork::interactions_db::unfavourite(
        &crate::server::fw_pool(&state.pool), auth.account_id, Some(post_id), None,
    ).await?;

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

        let ap_id = get_local_post(&state.pool, post_id).await?.map(|p| (p.ap_id,));
        let local_prefix = format!("https://{domain}/");
        if let Some((ref post_ap_id,)) = ap_id {
            if !post_ap_id.starts_with(&local_prefix) {
                let actor_uri = post_ap_id.rfind("/statuses/").map(|i| &post_ap_id[..i]);
                if let Some(remote_actor) = actor_uri {
                    let ra = fieldwork::actor_cache::get_by_actor_uri(
                        &crate::server::fw_pool(&state.pool), remote_actor,
                    ).await?;
                    let inbox: Option<(String,)> = ra.map(|r| {
                        (r.shared_inbox_url.unwrap_or(r.inbox_url),)
                    });
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
        get_local_post(&state.pool, post_id).await?
            .ok_or_else(|| AppError::not_found("Status not found"))?;

    // Check for existing reblog
    let existing: Option<(i64,)> = crate::db_extras::find_boost(&state.pool, auth.account_id, post_id)
        .await?.map(|id| (id,));

    let boost_id = if let Some((eid,)) = existing {
        eid
    } else {
        let new_id = generate_id();
        let ap_id = format!("https://{domain}/users/{}/statuses/{new_id}", auth.username);

        fieldwork::posts_db::create_post(
            &crate::server::fw_pool(&state.pool),
            &fieldwork::posts_db::PostRow {
                id: new_id,
                user_id: crate::db::DEFAULT_USER_ID,
                persona_id: auth.account_id,
                ap_id: ap_id.clone(),
                in_reply_to_id: None,
                in_reply_to_uri: None,
                boost_of_id: Some(post_id),
                boost_of_uri: None,
                content: String::new(),
                content_html: String::new(),
                spoiler_text: String::new(),
                visibility: "public".to_string(),
                sensitive: false,
                language: None,
                context_url: None,
                created_at: now,
                edited_at: None,
                deleted_at: None,
                deleted_reason: None,
            },
        ).await?;

        if original.persona_id != auth.account_id {
            let notif_id = generate_id();
            fieldwork::notifications_db::create_notification(
                &crate::server::fw_pool(&state.pool),
                &fieldwork::notifications_db::NotificationRow {
                    id: notif_id,
                    user_id: crate::db::DEFAULT_USER_ID,
                    persona_id: original.persona_id,
                    kind: "reblog".to_string(),
                    from_persona_id: Some(auth.account_id),
                    from_remote_account_id: None,
                    post_id: Some(post_id),
                    remote_post_id: None,
                    created_at: now,
                    read_at: None,
                },
            ).await?;

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
            let ap_id_row: Option<(String,)> = crate::db_extras::get_post_ap_id(&state.pool, post_id)
                .await?.map(|s| (s,));
            let local_prefix = format!("https://{domain}/");
            if let Some((ref post_ap_id,)) = ap_id_row {
                if !post_ap_id.starts_with(&local_prefix) {
                    let actor_uri = post_ap_id.rfind("/statuses/").map(|i| &post_ap_id[..i]);
                    if let Some(remote_actor) = actor_uri {
                        let inbox = crate::db_extras::get_remote_inbox_by_actor(&state.pool, remote_actor).await?;
                        if let Some(inbox_url) = inbox {
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
        get_local_post(&state.pool, boost_id).await?.ok_or_else(|| AppError::not_found("Post not found"))?;

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

    let boost: Option<(i64,)> = crate::db_extras::find_boost(&state.pool, auth.account_id, post_id)
        .await?.map(|id| (id,));

    if let Some((boost_id,)) = boost {
        // Enqueue outbound Undo{Announce} before deleting
        {
            let original = get_local_post(&state.pool, post_id).await?;

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
                let unreblog_post = get_local_post(&state.pool, post_id).await?;
                if let Some(ref post_ap_id) = unreblog_post.map(|p| (p.ap_id,))
                {
                    if !post_ap_id.0.starts_with(&local_prefix) {
                        let actor_uri =
                            post_ap_id.0.rfind("/statuses/").map(|i| &post_ap_id.0[..i]);
                        if let Some(remote_actor) = actor_uri {
                            let inbox = crate::db_extras::get_remote_inbox_by_actor(&state.pool, remote_actor).await?;
                            if let Some(inbox_url) = inbox {
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
        crate::db_extras::delete_reblog_notification(&state.pool, auth.account_id, post_id).await?;
        crate::db_extras::hard_delete_post(&state.pool, boost_id).await?;
    }

    let post =
        get_local_post(&state.pool, post_id).await?
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
        get_local_post(&state.pool, post_id).await?
            .ok_or_else(|| AppError::not_found("Status not found"))?;

    fieldwork::interactions_db::bookmark(
        &crate::server::fw_pool(&state.pool),
        crate::db::DEFAULT_USER_ID, auth.account_id, Some(post_id), None, now,
    ).await?;

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
        get_local_post(&state.pool, post_id).await?
            .ok_or_else(|| AppError::not_found("Status not found"))?;

    fieldwork::interactions_db::unbookmark(
        &crate::server::fw_pool(&state.pool), auth.account_id, Some(post_id), None,
    ).await?;

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
    let base_binds = vec![auth.account_id.to_string(), auth.account_id.to_string(), auth.account_id.to_string()];

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
    let rows = crate::db_extras::fetch_remote_timeline_posts(pool, account_id, limit).await?;

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
    let base_binds: Vec<String> = vec![];

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

    let mut tag_binds = vec![tag_lower.clone()];
    for b in &page_binds {
        tag_binds.push(b.to_string());
    }
    let rows = crate::db_extras::execute_dynamic_query(&state.pool, &sql, &tag_binds, limit).await?;
    let posts: Vec<PostRow> = rows.into_iter().map(sqlx_row_to_post).collect();

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
    let list = fieldwork::lists_db::get_list(
        &crate::server::fw_pool(&state.pool), list_id,
    ).await?
    .ok_or_else(|| AppError::not_found("List not found"))?;

    if list.user_id != auth.account_id {
        return Err(AppError::not_found("List not found"));
    }

    let replies_policy = list.replies_policy;

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
        "none" => vec![list_id.to_string()],
        "followed" => vec![list_id.to_string(), auth.account_id.to_string()],
        _ => vec![list_id.to_string(), list_id.to_string()],
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

// REMAINING: NotificationRow used for dynamic paginated queries — no fieldwork equivalent
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

impl NotificationRow {
    fn from_sqlx_row(row: sqlx::sqlite::SqliteRow) -> Self {
        use sqlx::Row;
        NotificationRow {
            id: row.get(0),
            persona_id: row.get(1),
            kind: row.get(2),
            from_persona_id: row.get(3),
            from_remote_account_id: row.get(4),
            post_id: row.get(5),
            created_at: row.get(6),
        }
    }
}

async fn serialize_notification(
    pool: &SqlitePool,
    notif: &NotificationRow,
    domain: &str,
    viewer_account_id: i64,
) -> Result<Value, AppError> {
    let from_account = if let Some(ref aid) = notif.from_persona_id {
        let a = fetch_account_row(pool, *aid).await?;
        account_to_json(&a, domain)
    } else if let Some(rid) = notif.from_remote_account_id {
        let remote: Option<(i64, String, String, String, String)> = crate::db_extras::get_remote_account_by_id(pool, rid).await?;
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
            get_local_post(pool, pid).await?;
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

    let mut notif_binds = vec![auth.account_id.to_string()];
    for b in &page_binds {
        notif_binds.push(b.to_string());
    }
    let notif_rows = crate::db_extras::execute_dynamic_query(&state.pool, &sql, &notif_binds, limit).await?;
    let notifs: Vec<NotificationRow> = notif_rows.into_iter().map(NotificationRow::from_sqlx_row).collect();

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

    let notif_raw = crate::db_extras::get_notification_row(&state.pool, notif_id, auth.account_id)
        .await?
        .ok_or_else(|| AppError::not_found("Notification not found"))?;
    let notif = NotificationRow::from_sqlx_row(notif_raw);

    let value = serialize_notification(&state.pool, &notif, domain, auth.account_id).await?;
    Ok(Json(value))
}

async fn clear_notifications(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
) -> Result<Json<Value>, AppError> {
    fieldwork::notifications_db::clear_notifications(
        &crate::server::fw_pool(&state.pool), auth.account_id,
    ).await?;

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

    crate::db_extras::dismiss_notification(&state.pool, notif_id, auth.account_id).await?;

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
        get_local_post(&state.pool, post_id).await?
            .ok_or_else(|| AppError::not_found("Status not found"))?;

    if post.persona_id != auth.account_id {
        return Err(AppError::forbidden("You do not own this status"));
    }

    fieldwork::interactions_db::pin_post(
        &crate::server::fw_pool(&state.pool), auth.account_id, post_id, now,
    ).await?;

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
        get_local_post(&state.pool, post_id).await?
            .ok_or_else(|| AppError::not_found("Status not found"))?;

    if post.persona_id != auth.account_id {
        return Err(AppError::forbidden("You do not own this status"));
    }

    fieldwork::interactions_db::unpin_post(
        &crate::server::fw_pool(&state.pool), auth.account_id, post_id,
    ).await?;

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
    let sched_rows = fieldwork::scheduled_db::list_scheduled(
        &crate::server::fw_pool(&state.pool), auth.account_id,
    ).await?;

    let items: Vec<Value> = sched_rows
        .iter()
        .map(|r| {
            scheduled_row_to_json(r.id, r.scheduled_at, &r.params_json)
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

    let sched = fieldwork::scheduled_db::get_scheduled(
        &crate::server::fw_pool(&state.pool), sched_id,
    ).await?
    .ok_or_else(|| AppError::not_found("Scheduled status not found"))?;

    // Verify ownership
    if sched.persona_id != auth.account_id && sched.user_id != auth.account_id {
        return Err(AppError::not_found("Scheduled status not found"));
    }

    Ok(Json(scheduled_row_to_json(sched.id, sched.scheduled_at, &sched.params_json)))
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

    let sched = fieldwork::scheduled_db::get_scheduled(
        &crate::server::fw_pool(&state.pool), sched_id,
    ).await?
    .ok_or_else(|| AppError::not_found("Scheduled status not found"))?;

    if sched.persona_id != auth.account_id && sched.user_id != auth.account_id {
        return Err(AppError::not_found("Scheduled status not found"));
    }

    fieldwork::scheduled_db::update_scheduled(
        &crate::server::fw_pool(&state.pool), sched_id, Some(scheduled_ms), None,
    ).await?;

    Ok(Json(scheduled_row_to_json(sched.id, scheduled_ms, &sched.params_json)))
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

    // Verify existence and ownership before deleting
    let sched = fieldwork::scheduled_db::get_scheduled(
        &crate::server::fw_pool(&state.pool), sched_id,
    ).await?
    .ok_or_else(|| AppError::not_found("Scheduled status not found"))?;

    if sched.persona_id != auth.account_id && sched.user_id != auth.account_id {
        return Err(AppError::not_found("Scheduled status not found"));
    }

    fieldwork::scheduled_db::delete_scheduled(
        &crate::server::fw_pool(&state.pool), sched_id,
    ).await?;

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
    let fwp_cp = crate::server::fw_pool(pool);
    let cp_mentions = fieldwork::mentions_db::get_mentions(&fwp_cp, post.id).await?;
    let mention_rows: Vec<(Option<i64>, Option<i64>)> = cp_mentions
        .into_iter()
        .map(|m| (m.mentioned_persona_id, m.mentioned_remote_id))
        .collect();
    for (local_id, remote_id) in &mention_rows {
        if let Some(aid) = local_id {
            if *aid != current_account_id {
                if let Ok(a) = fetch_account_row(pool, *aid).await {
                    accounts.push(account_to_json(&a, domain));
                }
            }
        } else if let Some(rid) = remote_id {
            let remote: Option<(i64, String, String, String, String)> = crate::db_extras::get_remote_account_by_id(pool, *rid).await?;
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

    let mut conv_binds = vec![
        auth.account_id.to_string(),
        auth.account_id.to_string(),
        auth.account_id.to_string(),
    ];
    for b in &page_binds {
        conv_binds.push(b.to_string());
    }
    let rows = crate::db_extras::execute_dynamic_query(&state.pool, &sql, &conv_binds, limit).await?;
    let posts: Vec<PostRow> = rows.into_iter().map(sqlx_row_to_post).collect();

    // TODO(perf): N+1 queries for participants per conversation. The result set is
    // already bounded by LIMIT (max 40), so this is acceptable for now. Batch-loading
    // mentions/accounts for all post IDs would eliminate the per-post queries.
    let mut conversations = Vec::with_capacity(posts.len());
    for p in &posts {
        let status = load_status(&state.pool, p, domain, Some(auth.account_id)).await?;

        // Determine unread: not in conversation_read_markers
        let is_read = fieldwork::conversations_db::is_read(
            &crate::server::fw_pool(&state.pool), auth.account_id, p.id,
        ).await?;
        let unread = !is_read && p.persona_id != auth.account_id;

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
    let post = get_local_post(&state.pool, post_id).await?
        .ok_or_else(|| AppError::not_found("Conversation not found"))?;
    if post.visibility != "direct" {
        return Err(AppError::not_found("Conversation not found"));
    }

    let is_involved = post.persona_id == auth.account_id || {
        let fwp_m = crate::server::fw_pool(&state.pool);
        let m_rows = fieldwork::mentions_db::get_mentions(&fwp_m, post_id).await?;
        m_rows.iter().any(|m| m.mentioned_persona_id == Some(auth.account_id))
    };

    if !is_involved {
        return Err(AppError::not_found("Conversation not found"));
    }

    // Mark as read
    fieldwork::conversations_db::mark_read(
        &crate::server::fw_pool(&state.pool),
        auth.account_id,
        post_id,
    )
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
    fieldwork::conversations_db::hide(
        &crate::server::fw_pool(&state.pool),
        auth.account_id,
        post_id,
    )
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
            ap_id: "https://example.com/users/writer/statuses/12345".to_string(),
            in_reply_to_id: None,
            in_reply_to_uri: None,
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
