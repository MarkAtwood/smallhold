use anyhow::{bail, Context, Result};
use regex::Regex;
use serde_json::{json, Value};
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::LazyLock;

// ---------------------------------------------------------------------------
// Shared HTTP client for card fetching
// ---------------------------------------------------------------------------

static CARD_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .user_agent("smallhold/0.2 (+https://github.com/smallhold)")
        // SSRF: disable redirects so validate_outbound_url cannot be bypassed
        // via a redirect to an internal IP. Cards behind shorteners (t.co) won't resolve.
        .redirect(reqwest::redirect::Policy::none())
        .use_rustls_tls()
        .build()
        .expect("failed to build card HTTP client")
});

// ---------------------------------------------------------------------------
// CardData
// ---------------------------------------------------------------------------

pub struct CardData {
    pub url: String,
    pub card_type: String,
    pub title: String,
    pub description: String,
    pub image_url: Option<String>,
    pub author_name: String,
    pub author_url: String,
    pub provider_name: String,
    pub provider_url: String,
    pub html: String,
    pub width: i32,
    pub height: i32,
}

// ---------------------------------------------------------------------------
// URL extraction
// ---------------------------------------------------------------------------

static URL_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"https://[^\s<>\]\)]+").unwrap());

/// Extract the first https:// URL from raw post text.
pub fn extract_first_url(text: &str) -> Option<String> {
    URL_RE.find(text).map(|m| {
        let url = m
            .as_str()
            .trim_end_matches(['.', ',', ';', ')', ']', '!', '?']);
        url.to_string()
    })
}

// ---------------------------------------------------------------------------
// OG metadata fetching
// ---------------------------------------------------------------------------

/// Fetch OpenGraph/Twitter Card metadata from a URL.
pub async fn fetch_card(url: &str, own_domain: &str) -> Result<CardData> {
    let parsed = url::Url::parse(url).context("invalid URL")?;

    // Don't fetch cards for our own domain
    if parsed.host_str() == Some(own_domain) {
        bail!("skipping card fetch for own domain");
    }

    // SSRF protection
    crate::federation::validate_outbound_url(&parsed)?;

    let resp = CARD_CLIENT
        .get(url)
        .header("Accept", "text/html")
        .send()
        .await
        .context("HTTP request failed")?;

    if !resp.status().is_success() {
        bail!("HTTP {}", resp.status());
    }

    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !content_type.contains("text/html") {
        bail!("not HTML: {content_type}");
    }

    if let Some(len) = resp.content_length() {
        if len > 1_048_576 {
            bail!("response too large: {len} bytes");
        }
    }

    // ponytail: if Content-Length is absent/lying, the 10s timeout provides a
    // soft cap (~10MB at 1MB/s). The post-download check catches the rest.
    let body = resp.bytes().await.context("failed to read response body")?;
    if body.len() > 1_048_576 {
        bail!("response body exceeds 1MB");
    }

    let html = String::from_utf8_lossy(&body);
    let tags = parse_og_tags(&html);

    let title: String = tags
        .get("og:title")
        .or_else(|| tags.get("twitter:title"))
        .cloned()
        .unwrap_or_else(|| parse_html_title(&html).unwrap_or_default());
    let title: String = decode_html_entities(&title).chars().take(200).collect();

    let description: String = tags
        .get("og:description")
        .or_else(|| tags.get("twitter:description"))
        .cloned()
        .unwrap_or_default();
    let description: String = decode_html_entities(&description)
        .chars()
        .take(512)
        .collect();

    let image_url = tags
        .get("og:image")
        .or_else(|| tags.get("twitter:image"))
        .map(|s| decode_html_entities(s))
        .filter(|s| !s.is_empty())
        .map(|s| {
            // Resolve relative URLs against the page URL
            if s.starts_with("http://") || s.starts_with("https://") {
                s
            } else if let Ok(base) = url::Url::parse(url) {
                base.join(&s).map(|u| u.to_string()).unwrap_or(s)
            } else {
                s
            }
        });

    let og_type = tags.get("og:type").cloned().unwrap_or_default();
    let card_type = if og_type.contains("video") || tags.contains_key("og:video") {
        "video".to_string()
    } else if image_url.is_some() && title.is_empty() {
        "photo".to_string()
    } else {
        "link".to_string()
    };

    let provider_name =
        decode_html_entities(&tags.get("og:site_name").cloned().unwrap_or_default());

    let author_name =
        decode_html_entities(&tags.get("article:author").cloned().unwrap_or_default());
    let width = tags
        .get("og:video:width")
        .or_else(|| tags.get("og:image:width"))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let height = tags
        .get("og:video:height")
        .or_else(|| tags.get("og:image:height"))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    Ok(CardData {
        url: url.to_string(),
        card_type,
        title,
        description,
        image_url,
        author_name,
        author_url: String::new(),
        provider_name,
        provider_url: String::new(),
        html: String::new(), // Never store untrusted HTML; we don't support oEmbed/rich embeds
        width,
        height,
    })
}

// ---------------------------------------------------------------------------
// HTML parsing (regex-based, no full parser needed)
// ---------------------------------------------------------------------------

fn decode_html_entities(s: &str) -> String {
    static ENTITY_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"&#(\d+);|&#x([0-9a-fA-F]+);").unwrap());

    let decoded = s
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&#x27;", "'")
        .replace("&apos;", "'")
        .replace("&nbsp;", " ");

    // Decode numeric entities (&#8217; &#x2019; etc.)
    ENTITY_RE
        .replace_all(&decoded, |caps: &regex::Captures| {
            let code = if let Some(dec) = caps.get(1) {
                dec.as_str().parse::<u32>().ok()
            } else if let Some(hex) = caps.get(2) {
                u32::from_str_radix(hex.as_str(), 16).ok()
            } else {
                None
            };
            code.and_then(char::from_u32)
                .map(|c| c.to_string())
                .unwrap_or_else(|| caps[0].to_string())
        })
        .into_owned()
}

/// Parse OpenGraph and Twitter Card meta tags from HTML.
fn parse_og_tags(html: &str) -> HashMap<String, String> {
    static META_RE: LazyLock<Regex> = LazyLock::new(|| {
        // Match: <meta property="og:X" content="Y"> or <meta name="twitter:X" content="Y">
        // Also handles reversed attribute order: content="Y" property="og:X"
        Regex::new(
            r#"(?i)<meta\s+(?:[^>]*?\s)?(?:(?:property|name)\s*=\s*"((?:og|twitter|article):[^"]+)"[^>]*?\scontent\s*=\s*"([^"]*)"|content\s*=\s*"([^"]*)"[^>]*?(?:property|name)\s*=\s*"((?:og|twitter|article):[^"]+)")"#,
        )
        .unwrap()
    });

    let mut tags = HashMap::new();
    for cap in META_RE.captures_iter(html) {
        let (key, value) = if let (Some(k), Some(v)) = (cap.get(1), cap.get(2)) {
            (k.as_str().to_string(), v.as_str().to_string())
        } else if let (Some(v), Some(k)) = (cap.get(3), cap.get(4)) {
            (k.as_str().to_string(), v.as_str().to_string())
        } else {
            continue;
        };
        // Don't overwrite — first occurrence wins
        tags.entry(key).or_insert(value);
    }
    tags
}

/// Extract <title> content as fallback.
fn parse_html_title(html: &str) -> Option<String> {
    static TITLE_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?i)<title[^>]*>([^<]+)</title>").unwrap());

    TITLE_RE.captures(html).map(|c| c[1].trim().to_string())
}

// ---------------------------------------------------------------------------
// Card JSON serialization (Mastodon format)
// ---------------------------------------------------------------------------

pub fn card_to_json(card: &CardData) -> Value {
    json!({
        "url": card.url,
        "title": card.title,
        "description": card.description,
        "type": card.card_type,
        "author_name": card.author_name,
        "author_url": card.author_url,
        "provider_name": card.provider_name,
        "provider_url": card.provider_url,
        "html": card.html,
        "width": card.width,
        "height": card.height,
        "image": card.image_url,
        "embed_url": "",
        "blurhash": null,
        "published_at": null
    })
}

// ---------------------------------------------------------------------------
// Database: fetch and cache
// ---------------------------------------------------------------------------

/// Fetch card for a URL (or use cache) and link it to a post.
pub async fn fetch_and_cache_card(
    pool: &SqlitePool,
    post_id: i64,
    url: &str,
    own_domain: &str,
) -> Result<()> {
    let now = crate::api::now_millis();

    // Check if already cached and fresh (< 24h)
    let cached: Option<(i64, i64)> =
        sqlx::query_as("SELECT id, fetched_at FROM link_cards WHERE url = ? AND failed = 0")
            .bind(url)
            .fetch_optional(pool)
            .await?;

    if let Some((_, fetched_at)) = cached {
        let age_ms = now - fetched_at;
        if age_ms < 24 * 60 * 60 * 1000 {
            // Fresh cache — just link to post
            sqlx::query("INSERT OR IGNORE INTO post_cards (post_id, card_url) VALUES (?, ?)")
                .bind(post_id)
                .bind(url)
                .execute(pool)
                .await?;
            return Ok(());
        }
    }

    // Check if URL failed recently (< 1h)
    let failed: Option<(i64,)> =
        sqlx::query_as("SELECT fetched_at FROM link_cards WHERE url = ? AND failed = 1")
            .bind(url)
            .fetch_optional(pool)
            .await?;

    if let Some((fetched_at,)) = failed {
        let age_ms = now - fetched_at;
        if age_ms < 60 * 60 * 1000 {
            bail!("URL failed recently, not retrying");
        }
    }

    // Fetch the card
    match fetch_card(url, own_domain).await {
        Ok(card) => {
            sqlx::query(
                "INSERT OR REPLACE INTO link_cards \
                 (url, card_type, title, description, image_url, author_name, author_url, \
                  provider_name, provider_url, html, width, height, fetched_at, failed) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)",
            )
            .bind(&card.url)
            .bind(&card.card_type)
            .bind(&card.title)
            .bind(&card.description)
            .bind(&card.image_url)
            .bind(&card.author_name)
            .bind(&card.author_url)
            .bind(&card.provider_name)
            .bind(&card.provider_url)
            .bind(&card.html)
            .bind(card.width)
            .bind(card.height)
            .bind(now)
            .execute(pool)
            .await?;

            sqlx::query("INSERT OR IGNORE INTO post_cards (post_id, card_url) VALUES (?, ?)")
                .bind(post_id)
                .bind(url)
                .execute(pool)
                .await?;
        }
        Err(_) => {
            // Mark as failed
            sqlx::query(
                "INSERT OR REPLACE INTO link_cards \
                 (url, card_type, title, description, image_url, author_name, author_url, \
                  provider_name, provider_url, html, width, height, fetched_at, failed) \
                 VALUES (?, 'link', '', '', NULL, '', '', '', '', '', 0, 0, ?, 1)",
            )
            .bind(url)
            .bind(now)
            .execute(pool)
            .await?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Load card for status serialization
// ---------------------------------------------------------------------------

/// Load the cached card JSON for a post, or None if no card exists.
// ponytail: batch card loading available via load_cards_for_posts().
// Currently cards loaded per-status in load_status(). Acceptable for
// timeline sizes (max 40 posts). Wire batch loading if this becomes a bottleneck.
#[allow(clippy::type_complexity)]
pub async fn load_card_for_post(pool: &SqlitePool, post_id: i64) -> Option<Value> {
    let row: Option<(
        String,
        String,
        String,
        String,
        Option<String>,
        String,
        String,
        String,
        String,
        String,
        i32,
        i32,
    )> = sqlx::query_as(
        "SELECT lc.url, lc.card_type, lc.title, lc.description, lc.image_url, \
         lc.author_name, lc.author_url, lc.provider_name, lc.provider_url, \
         lc.html, lc.width, lc.height \
         FROM post_cards pc JOIN link_cards lc ON pc.card_url = lc.url \
         WHERE pc.post_id = ? AND lc.failed = 0",
    )
    .bind(post_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();

    row.map(
        |(
            url,
            card_type,
            title,
            description,
            image_url,
            author_name,
            author_url,
            provider_name,
            provider_url,
            html,
            width,
            height,
        )| {
            card_to_json(&CardData {
                url,
                card_type,
                title,
                description,
                image_url,
                author_name,
                author_url,
                provider_name,
                provider_url,
                html,
                width,
                height,
            })
        },
    )
}

/// Batch load cards for multiple posts. Returns a map of post_id -> card JSON.
pub async fn load_cards_for_posts(pool: &SqlitePool, post_ids: &[i64]) -> HashMap<i64, Value> {
    if post_ids.is_empty() {
        return HashMap::new();
    }

    // ponytail: build IN clause with positional params. SQLite max is 999 but
    // timeline pages are <=40 posts, so this is safe.
    let placeholders: String = post_ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
    let query = format!(
        "SELECT pc.post_id, lc.url, lc.card_type, lc.title, lc.description, lc.image_url, \
         lc.author_name, lc.author_url, lc.provider_name, lc.provider_url, \
         lc.html, lc.width, lc.height \
         FROM post_cards pc JOIN link_cards lc ON pc.card_url = lc.url \
         WHERE pc.post_id IN ({placeholders}) AND lc.failed = 0"
    );

    let mut q = sqlx::query_as::<
        _,
        (
            i64,
            String,
            String,
            String,
            String,
            Option<String>,
            String,
            String,
            String,
            String,
            String,
            i32,
            i32,
        ),
    >(&query);

    for id in post_ids {
        q = q.bind(id);
    }

    let rows = match q.fetch_all(pool).await {
        Ok(r) => r,
        Err(_) => return HashMap::new(),
    };

    let mut map = HashMap::new();
    for (
        post_id,
        url,
        card_type,
        title,
        description,
        image_url,
        author_name,
        author_url,
        provider_name,
        provider_url,
        html,
        width,
        height,
    ) in rows
    {
        map.insert(
            post_id,
            card_to_json(&CardData {
                url,
                card_type,
                title,
                description,
                image_url,
                author_name,
                author_url,
                provider_name,
                provider_url,
                html,
                width,
                height,
            }),
        );
    }
    map
}
