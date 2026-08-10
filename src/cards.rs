use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::LazyLock;

pub use fieldwork::cards::{
    card_to_json, classify_card_type, decode_html_entities, extract_first_url, parse_html_title,
    parse_og_tags, CardData,
};

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
    let card_type = classify_card_type(
        &og_type,
        tags.contains_key("og:video"),
        image_url.is_some(),
        !title.is_empty(),
    );

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
// Database: fetch and cache
// ---------------------------------------------------------------------------

/// Fetch card for a URL (or use cache) and link it to a post.
pub async fn fetch_and_cache_card(
    pool: &fieldwork_db::db::Pool,
    post_id: i64,
    url: &str,
    own_domain: &str,
) -> Result<()> {
    let fwp = pool.clone();
    let now = crate::api::now_secs();

    // Check if already cached and fresh (< 24h)
    if let Some(cached) = fieldwork_db::cards_db::get_card_by_url(&fwp, url).await? {
        if !cached.failed && (now - cached.fetched_at) < 24 * 60 * 60 {
            fieldwork_db::cards_db::link_card_to_post(&fwp, post_id, url).await?;
            return Ok(());
        }
    }

    // Check if URL failed recently (< 1h)
    if fieldwork_db::cards_db::is_recent_failure(&fwp, url, 3600).await? {
        bail!("URL failed recently, not retrying");
    }

    // Fetch the card
    match fetch_card(url, own_domain).await {
        Ok(card) => {
            fieldwork_db::cards_db::upsert_card(
                &fwp,
                &fieldwork_db::cards_db::CardRow {
                    id: 0,
                    url: card.url.clone(),
                    card_type: card.card_type,
                    title: card.title,
                    description: card.description,
                    image_url: card.image_url,
                    author_name: card.author_name,
                    author_url: card.author_url,
                    provider_name: card.provider_name,
                    provider_url: card.provider_url,
                    html: card.html,
                    width: card.width,
                    height: card.height,
                    fetched_at: now,
                    failed: false,
                },
            )
            .await?;

            fieldwork_db::cards_db::link_card_to_post(&fwp, post_id, &card.url).await?;
        }
        Err(_) => {
            fieldwork_db::cards_db::upsert_card(
                &fwp,
                &fieldwork_db::cards_db::CardRow {
                    id: 0,
                    url: url.to_string(),
                    card_type: "link".to_string(),
                    title: String::new(),
                    description: String::new(),
                    image_url: None,
                    author_name: String::new(),
                    author_url: String::new(),
                    provider_name: String::new(),
                    provider_url: String::new(),
                    html: String::new(),
                    width: 0,
                    height: 0,
                    fetched_at: now,
                    failed: true,
                },
            )
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
pub async fn load_card_for_post(pool: &fieldwork_db::db::Pool, post_id: i64) -> Option<Value> {
    let cards = fieldwork_db::cards_db::cards_for_post(pool, post_id)
        .await
        .ok()?;

    cards.into_iter().next().map(|c| {
        card_to_json(&CardData {
            url: c.url,
            card_type: c.card_type,
            title: c.title,
            description: c.description,
            image_url: c.image_url,
            author_name: c.author_name,
            author_url: c.author_url,
            provider_name: c.provider_name,
            provider_url: c.provider_url,
            html: c.html,
            width: c.width,
            height: c.height,
        })
    })
}

/// Batch load cards for multiple posts. Returns a map of post_id -> card JSON.
pub async fn load_cards_for_posts(pool: &fieldwork_db::db::Pool, post_ids: &[i64]) -> HashMap<i64, Value> {
    if post_ids.is_empty() {
        return HashMap::new();
    }

    // ponytail: iterates per-post via fieldwork_db::cards_db::cards_for_post.
    // Timeline pages are <=40 posts so N+1 is acceptable. Upgrade to batch
    // query if this becomes a bottleneck.
    let fwp = pool.clone();
    let mut map = HashMap::new();
    for &post_id in post_ids {
        if let Ok(cards) = fieldwork_db::cards_db::cards_for_post(&fwp, post_id).await {
            if let Some(c) = cards.into_iter().next() {
                map.insert(
                    post_id,
                    card_to_json(&CardData {
                        url: c.url,
                        card_type: c.card_type,
                        title: c.title,
                        description: c.description,
                        image_url: c.image_url,
                        author_name: c.author_name,
                        author_url: c.author_url,
                        provider_name: c.provider_name,
                        provider_url: c.provider_url,
                        html: c.html,
                        width: c.width,
                        height: c.height,
                    }),
                );
            }
        }
    }
    map
}
