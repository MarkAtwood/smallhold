use anyhow::{anyhow, bail, Context};
use base64::Engine;
use reqwest::header::HeaderMap;
use serde_json::Value;
use sqlx::SqlitePool;
use std::time::Duration;

use crate::config::Config;
use crate::id::generate_id;

/// Parsed remote actor data, ready for database upsert.
#[derive(Debug)]
pub struct RemoteActorData {
    pub actor_uri: String,
    pub username: String,
    pub domain: String,
    pub display_name: String,
    pub bio_html: String,
    pub avatar_url: Option<String>,
    pub header_url: Option<String>,
    pub public_key_pem: String,
    pub public_key_id: String,
    pub inbox_url: String,
    pub shared_inbox_url: Option<String>,
    pub followers_url: Option<String>,
    pub is_locked: bool,
    pub bot: bool,
}

fn is_private_host(host: &str) -> bool {
    if let Ok(addr) = host.parse::<std::net::IpAddr>() {
        return match addr {
            std::net::IpAddr::V4(ip) => {
                ip.is_loopback()          // 127.0.0.0/8
                || ip.is_private()        // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                || ip.is_link_local()     // 169.254.0.0/16
                || ip.is_broadcast()
                || ip.is_unspecified()
                || ip.octets()[0] == 0    // 0.0.0.0/8
                || (ip.octets()[0] == 100 && (ip.octets()[1] & 0xC0) == 64) // 100.64.0.0/10 (CGNAT)
            }
            std::net::IpAddr::V6(ip) => {
                ip.is_loopback() || ip.is_unspecified()
                || (ip.segments()[0] & 0xFE00) == 0xFC00  // ULA fc00::/7
                || (ip.segments()[0] == 0xFE80) // link-local
                || ip.to_ipv4_mapped().map_or(false, |v4| {
                    v4.is_loopback() || v4.is_private() || v4.is_link_local()
                    || v4.is_broadcast() || v4.is_unspecified()
                    || v4.octets()[0] == 0
                    || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64)
                })
            }
        };
    }
    // Check hostnames
    matches!(host, "localhost" | "localhost.localdomain")
        || host.ends_with(".local")
        || host.ends_with(".internal")
}

// ponytail: DNS rebinding is not mitigated. To fully prevent it, we'd need
// to pin DNS responses or use a custom resolver that validates IPs after
// resolution. The SSRF check on URL parsing catches direct IP literals and
// known hostnames but not DNS rebinding attacks. Acceptable risk for a
// single-operator server.
pub fn validate_outbound_url(url: &url::Url) -> Result<(), anyhow::Error> {
    let host = url.host_str().ok_or_else(|| anyhow!("URL has no host"))?;
    if is_private_host(host) {
        bail!("refusing to connect to private/internal host: {host}");
    }
    if url.scheme() != "https" {
        bail!("refusing non-HTTPS URL: {url}");
    }
    Ok(())
}

/// HTTP client for ActivityPub federation with HTTP Signature support.
pub struct FederationClient {
    client: reqwest::Client,
    domain: String,
    #[allow(dead_code)]
    user_agent: String,
}

impl FederationClient {
    pub fn new(config: &Config) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.federation.fetch_timeout_secs))
            .user_agent(&config.federation.user_agent)
            .redirect(reqwest::redirect::Policy::none())
            .use_rustls_tls()
            .build()
            .context("failed to build HTTP client")?;

        Ok(Self {
            client,
            domain: config.server.domain.clone(),
            user_agent: config.federation.user_agent.clone(),
        })
    }

    /// Borrow the inner reqwest client for custom requests that need the same
    /// timeout / TLS / redirect / user-agent settings.
    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }

    /// Build signed headers for an HTTP GET (draft-cavage-11 HTTP Signatures).
    ///
    /// Signs `(request-target)`, `host`, and `date` with RSA-SHA256.
    pub fn sign_get_headers(
        private_key_pem: &str,
        key_id: &str,
        target_url: &url::Url,
    ) -> anyhow::Result<HeaderMap> {
        let date = chrono::Utc::now()
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string();
        let host = target_url
            .host_str()
            .ok_or_else(|| anyhow!("target URL has no host"))?;
        let path = target_url.path();

        let signed_string = format!("(request-target): get {path}\nhost: {host}\ndate: {date}");

        let sig_b64 = rsa_sha256_sign(private_key_pem, signed_string.as_bytes())?;

        let sig_header = format!(
            r#"keyId="{key_id}",algorithm="rsa-sha256",headers="(request-target) host date",signature="{sig_b64}""#
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            "Date",
            date.parse()
                .map_err(|_| anyhow!("invalid Date header value"))?,
        );
        headers.insert(
            "Signature",
            sig_header
                .parse()
                .map_err(|_| anyhow!("invalid Signature header value"))?,
        );
        Ok(headers)
    }

    /// Build signed headers for an HTTP POST (draft-cavage-11 HTTP Signatures).
    ///
    /// Signs `(request-target)`, `host`, `date`, and `digest` with RSA-SHA256.
    /// The `digest` header contains `SHA-256={base64(sha256(body))}`.
    pub fn sign_post_headers(
        private_key_pem: &str,
        key_id: &str,
        target_url: &url::Url,
        body: &[u8],
    ) -> anyhow::Result<HeaderMap> {
        let date = chrono::Utc::now()
            .format("%a, %d %b %Y %H:%M:%S GMT")
            .to_string();
        let host = target_url
            .host_str()
            .ok_or_else(|| anyhow!("target URL has no host"))?;
        let path = target_url.path();

        let body_digest = {
            use sha2::Digest;
            let hash = sha2::Sha256::digest(body);
            base64::engine::general_purpose::STANDARD.encode(hash)
        };
        let digest_header = format!("SHA-256={body_digest}");

        let signed_string = format!(
            "(request-target): post {path}\nhost: {host}\ndate: {date}\ndigest: {digest_header}"
        );

        let sig_b64 = rsa_sha256_sign(private_key_pem, signed_string.as_bytes())?;

        let sig_header = format!(
            r#"keyId="{key_id}",algorithm="rsa-sha256",headers="(request-target) host date digest",signature="{sig_b64}""#
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            "Date",
            date.parse()
                .map_err(|_| anyhow!("invalid Date header value"))?,
        );
        headers.insert(
            "Digest",
            digest_header
                .parse()
                .map_err(|_| anyhow!("invalid Digest header value"))?,
        );
        headers.insert(
            "Signature",
            sig_header
                .parse()
                .map_err(|_| anyhow!("invalid Signature header value"))?,
        );
        Ok(headers)
    }

    /// Fetch an ActivityPub actor document by URL, with HTTP Signature authentication.
    pub async fn fetch_actor(
        &self,
        actor_uri: &str,
        signing_key_pem: &str,
        signing_key_id: &str,
    ) -> anyhow::Result<RemoteActorData> {
        let url: url::Url = actor_uri
            .parse()
            .with_context(|| format!("invalid actor URI: {actor_uri}"))?;

        validate_outbound_url(&url)?;

        let headers = Self::sign_get_headers(signing_key_pem, signing_key_id, &url)?;

        let resp = self
            .client
            .get(url.as_str())
            .headers(headers)
            .header(
                "Accept",
                "application/activity+json, \
                 application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\"",
            )
            .send()
            .await
            .with_context(|| format!("GET {actor_uri}"))?;

        let status = resp.status();
        if !status.is_success() {
            bail!("fetch actor {actor_uri}: HTTP {status}");
        }

        if let Some(len) = resp.content_length() {
            if len > 1_048_576 {
                bail!("response body exceeds 1MB (Content-Length: {len})");
            }
        }
        let body_bytes = resp
            .bytes()
            .await
            .with_context(|| format!("read actor body from {actor_uri}"))?;
        if body_bytes.len() > 1_048_576 {
            bail!("response body exceeds 1MB limit");
        }
        let doc: Value = serde_json::from_slice(&body_bytes)
            .with_context(|| format!("parse actor JSON from {actor_uri}"))?;

        parse_actor_document(&doc, actor_uri)
    }

    /// Resolve `user@domain` (or `acct:user@domain`) to an actor URI via WebFinger.
    pub async fn resolve_webfinger(&self, acct: &str) -> anyhow::Result<String> {
        let acct = acct.strip_prefix("acct:").unwrap_or(acct);
        let (_user, domain) = acct
            .split_once('@')
            .ok_or_else(|| anyhow!("invalid acct URI, expected user@domain: {acct}"))?;

        let wf_url = format!("https://{domain}/.well-known/webfinger?resource=acct:{acct}");
        let parsed_wf_url: url::Url = wf_url
            .parse()
            .with_context(|| format!("invalid WebFinger URL: {wf_url}"))?;
        validate_outbound_url(&parsed_wf_url)?;

        let resp = self
            .client
            .get(&wf_url)
            .header("Accept", "application/jrd+json, application/json")
            .send()
            .await
            .with_context(|| format!("WebFinger GET {wf_url}"))?;

        let status = resp.status();
        if !status.is_success() {
            bail!("WebFinger {wf_url}: HTTP {status}");
        }

        if let Some(len) = resp.content_length() {
            if len > 1_048_576 {
                bail!("response body exceeds 1MB (Content-Length: {len})");
            }
        }
        let body_bytes = resp
            .bytes()
            .await
            .with_context(|| format!("read WebFinger body from {wf_url}"))?;
        if body_bytes.len() > 1_048_576 {
            bail!("response body exceeds 1MB limit");
        }
        let doc: Value = serde_json::from_slice(&body_bytes)
            .with_context(|| format!("parse WebFinger JSON from {wf_url}"))?;

        let links = doc["links"]
            .as_array()
            .ok_or_else(|| anyhow!("WebFinger response missing links array"))?;

        for link in links {
            let rel = link["rel"].as_str().unwrap_or("");
            let link_type = link["type"].as_str().unwrap_or("");
            if rel == "self"
                && (link_type == "application/activity+json"
                    || link_type.starts_with("application/ld+json"))
            {
                if let Some(href) = link["href"].as_str() {
                    return Ok(href.to_string());
                }
            }
        }

        bail!("WebFinger response for {acct} has no ActivityPub self link")
    }

    /// Accessor for the local domain.
    pub fn domain(&self) -> &str {
        &self.domain
    }
}

/// Truncate a string to at most `max` characters (not bytes).
fn cap_str(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// Parse an ActivityPub actor JSON document into `RemoteActorData`.
fn parse_actor_document(doc: &Value, actor_uri: &str) -> anyhow::Result<RemoteActorData> {
    let id = doc["id"]
        .as_str()
        .ok_or_else(|| anyhow!("actor document missing id"))?;

    // Verify the document's id matches what we requested (prevent spoofing)
    if id != actor_uri {
        bail!("actor document id mismatch: requested {actor_uri}, got {id}");
    }

    let parsed_url: url::Url = id
        .parse()
        .with_context(|| format!("actor id is not a valid URL: {id}"))?;
    let domain = parsed_url
        .host_str()
        .ok_or_else(|| anyhow!("actor id URL has no host"))?
        .to_string();

    let username = cap_str(doc["preferredUsername"].as_str().unwrap_or(""), 100);
    if username.is_empty() {
        bail!("actor document missing preferredUsername");
    }

    let display_name = cap_str(
        &ammonia::clean(
            doc["name"]
                .as_str()
                .filter(|s| !s.is_empty())
                .unwrap_or(&username),
        ),
        200,
    );

    let bio_html = cap_str(
        &ammonia::clean(doc["summary"].as_str().unwrap_or("")),
        10000,
    );

    let avatar_url = doc["icon"]["url"]
        .as_str()
        .or_else(|| doc["icon"].as_str())
        .map(String::from);

    let header_url = doc["image"]["url"]
        .as_str()
        .or_else(|| doc["image"].as_str())
        .map(String::from);

    let inbox_url = doc["inbox"]
        .as_str()
        .ok_or_else(|| anyhow!("actor document missing inbox"))?
        .to_string();

    let shared_inbox_url = doc["endpoints"]["sharedInbox"].as_str().map(String::from);

    let followers_url = doc["followers"].as_str().map(String::from);

    let public_key_id = doc["publicKey"]["id"]
        .as_str()
        .ok_or_else(|| anyhow!("actor document missing publicKey.id"))?
        .to_string();

    let public_key_pem = doc["publicKey"]["publicKeyPem"]
        .as_str()
        .ok_or_else(|| anyhow!("actor document missing publicKey.publicKeyPem"))?
        .to_string();

    let is_locked = doc["manuallyApprovesFollowers"].as_bool().unwrap_or(false);

    // Service and Application types are conventionally bots
    let actor_type = doc["type"].as_str().unwrap_or("Person");
    let bot = matches!(actor_type, "Service" | "Application");

    Ok(RemoteActorData {
        actor_uri: id.to_string(),
        username,
        domain,
        display_name,
        bio_html,
        avatar_url,
        header_url,
        public_key_pem,
        public_key_id,
        inbox_url,
        shared_inbox_url,
        followers_url,
        is_locked,
        bot,
    })
}

/// Insert or update a remote account. Returns the local snowflake ID.
pub async fn upsert_remote_account(
    pool: &SqlitePool,
    data: &RemoteActorData,
) -> anyhow::Result<i64> {
    let now = chrono::Utc::now().timestamp();
    let new_id = generate_id();

    let result = sqlx::query_scalar::<_, i64>(
        "INSERT INTO remote_accounts (
            id, actor_uri, username, domain, display_name, bio_html,
            avatar_url, header_url, public_key_pem, public_key_id,
            inbox_url, shared_inbox_url, followers_url,
            is_locked, bot, last_fetched_at
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6,
            ?7, ?8, ?9, ?10,
            ?11, ?12, ?13,
            ?14, ?15, ?16
        )
        ON CONFLICT(actor_uri) DO UPDATE SET
            username         = excluded.username,
            domain           = excluded.domain,
            display_name     = excluded.display_name,
            bio_html         = excluded.bio_html,
            avatar_url       = excluded.avatar_url,
            header_url       = excluded.header_url,
            public_key_pem   = excluded.public_key_pem,
            public_key_id    = excluded.public_key_id,
            inbox_url        = excluded.inbox_url,
            shared_inbox_url = excluded.shared_inbox_url,
            followers_url    = excluded.followers_url,
            is_locked        = excluded.is_locked,
            bot              = excluded.bot,
            last_fetched_at  = excluded.last_fetched_at,
            fetched_failed_at = NULL,
            fetch_fail_count  = 0
        RETURNING id",
    )
    .bind(new_id)
    .bind(&data.actor_uri)
    .bind(&data.username)
    .bind(&data.domain)
    .bind(&data.display_name)
    .bind(&data.bio_html)
    .bind(&data.avatar_url)
    .bind(&data.header_url)
    .bind(&data.public_key_pem)
    .bind(&data.public_key_id)
    .bind(&data.inbox_url)
    .bind(&data.shared_inbox_url)
    .bind(&data.followers_url)
    .bind(data.is_locked)
    .bind(data.bot)
    .bind(now)
    .fetch_one(pool)
    .await
    .context("upsert remote_accounts")?;

    Ok(result)
}

// ---------------------------------------------------------------------------
// FEP-8fcf: Follower Collection Synchronization
// ---------------------------------------------------------------------------

/// Compute the FEP-8fcf follower sync digest for a local account's followers
/// on a specific remote domain.
///
/// The digest is the XOR of SHA-256 hashes of all follower actor URIs on
/// `target_domain`. Returns `None` if there are no followers on that domain.
pub async fn compute_follower_sync_digest(
    pool: &SqlitePool,
    account_id: i64,
    target_domain: &str,
) -> Option<String> {
    let uris: Vec<(String,)> = sqlx::query_as(
        "SELECT ra.actor_uri FROM followers f \
         JOIN remote_accounts ra ON f.remote_account_id = ra.id \
         WHERE f.local_account_id = ? AND ra.domain = ?",
    )
    .bind(account_id)
    .bind(target_domain)
    .fetch_all(pool)
    .await
    .map_err(|e| {
        tracing::warn!("follower sync digest query failed: {e}");
        e
    })
    .ok()?;

    if uris.is_empty() {
        return None;
    }

    use sha2::Digest;
    let mut xor_hash = [0u8; 32];
    for (uri,) in &uris {
        let hash = sha2::Sha256::digest(uri.as_bytes());
        for (x, h) in xor_hash.iter_mut().zip(hash.iter()) {
            *x ^= h;
        }
    }

    Some(format!(
        "sha-256={}",
        base64::engine::general_purpose::STANDARD.encode(xor_hash)
    ))
}

/// Build the `Collection-Synchronization` header value for FEP-8fcf.
pub fn format_collection_sync_header(domain: &str, username: &str, digest: &str) -> String {
    let followers_url = format!("https://{domain}/users/{username}/followers");
    format!("collectionId=\"{followers_url}\", digest=\"{digest}\", url=\"{followers_url}\"")
}

/// Parse a `Collection-Synchronization` header value into its components.
/// Returns `(collection_id, digest, url)` if all three fields are present.
// ponytail: naive comma split breaks on commas inside quoted values. URLs
// rarely contain commas so this is acceptable. If it ever matters, upgrade
// to a proper quoted-string-aware parser.
pub fn parse_collection_sync_header(header_val: &str) -> Option<(String, String, String)> {
    let mut collection_id = None;
    let mut digest = None;
    let mut url = None;

    for part in header_val.split(',') {
        let part = part.trim();
        if let Some((key, val)) = part.split_once('=') {
            let key = key.trim();
            let val = val.trim().trim_matches('"');
            match key {
                "collectionId" => collection_id = Some(val.to_string()),
                "digest" => digest = Some(val.to_string()),
                "url" => url = Some(val.to_string()),
                _ => {}
            }
        }
    }

    Some((collection_id?, digest?, url?))
}

/// Sign `message` with an RSA private key using PKCS#1 v1.5 + SHA-256.
/// Returns the signature as base64.
// ponytail: PEM re-parsed per sign; cache parsed RsaPrivateKey in AppState
// if delivery throughput exceeds ~100 signs/sec
fn rsa_sha256_sign(private_key_pem: &str, message: &[u8]) -> anyhow::Result<String> {
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::signature::{SignatureEncoding, Signer};
    use rsa::RsaPrivateKey;
    use sha2::Sha256;

    let private_key = RsaPrivateKey::from_pkcs8_pem(private_key_pem)
        .context("failed to decode RSA private key PEM")?;
    let signing_key = rsa::pkcs1v15::SigningKey::<Sha256>::new(private_key);
    let signature = signing_key.sign(message);
    Ok(base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY_PEM: &str = "\
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCu3DRolW21JtBR
hT0FXUSiG8xFn8wNFrHONdg4fXEu4Z4AkzBkGlLC2+dq4FDombo142zUa6nzp/ou
x8aZON9I3g0itN5HeypFypo2pmrha3jfHPwjsvTz9nKEBxxMi1uycFSGukwA+qor
hWIYl2oxUjZzsauPlVDxsvhx9DtBGIuR3fp4TdgeQNR9Gsl5vW69/jp3DBfvcdNn
QxKAf+GgX5ZsRai/wj68o/bWMG9Jgwkdu5POe4zed0614s5WBjIw6gJvGFeYwK9D
gPqVNk7PC9OlJiweuZcaC4B4VwYw2CXZ4pC3ipoJZgX9wTaM7CNzLPLKpXmxJ1db
CHL6JR/lAgMBAAECggEASuMlENtaSlhupFMnQJpir/iuwey/g6WCDdoSmZLju9vF
guKGuYBqjGiIkkWycQORc83MSKc5eJAqvgkyHWH1gqwSvRfwEHYHsy8jX59jK9qO
wCMWOyXD8Y3NGo0/CesvINsp4C9+KHcyFQSBcB28zZWzm1Xur0YYDgODkq4yCFzI
xnza0fc8sKIfkyNbw8xIEjWFiCFNRAXelA4AUJEpp0vyRAgfyYFd9uSO4y7D6L07
aW/rOet2+hYD0RGT/MxNuedFFe0Z/HlIOySBuzr0J5oz+Xyahuv4v2+gFp9vVRXb
LoHK6xuFEaH1TaZM7+GlJQuiP8l32DpBmTmhqpHq2wKBgQDeuxG/A1S2ol9lTg3O
rywehrRrK/0qqBb0f4cP9zDXV1f8UzzsAqgQZMXRy/9eB5GVTiHoXgMICFGLbwyz
CB90l8O2XBM4UmyohWzr9VisXWeCx9Q0GLG8VYbJSybF1Zh2H36cpnlhl73ESlBw
/fn4kQX+VwJI9agOvt4ociB8kwKBgQDI+qDAER82rEE87z3gpRbtGFJ2l2NIPPqO
18ktVLMk7qjCDU0XOJjxcgRfTBMrGf4TBMtzLJZDU03dFDGVer75MS5L2DBOQ8bI
gvDm4feyz5C4D5WnmZ2QHmWJHlESwH0bxnB48xQS3oFl0+VsGpJxma8vohjhWzPk
YYZoiYI0pwKBgGkQEQTrS1CDM0CUGws9sjAMFprfOyKd+4YFie5MCevqNYS+tuQV
NLXW80FNWv49z7yACJqVjhSB6AU/stvYnw3ecOFaeW594udzWLfNGbDktmkIXd7d
LynJpjTZkEaNxMcjgBPgqy0P6OHotB04kGth7VPWMyu7RTT/b8fgXdalAoGBAIuF
+rz75fh1oyCjUgi3c3ALt4ve0yzeMG+j/GS87VURXhTBWShqwTq1FbX2wUPl2o3n
gTom1PZOSbrV/wov2Y5zhxleL0LWKJUg2g7fBq+bC3PMVe+xZEId6A1F/7CN8wyq
OYCt99yVna1ManQfClVVBNqDpNQmFaNR1RaTh9H3AoGBALMLymj9TCR5I3EYLiDs
szYctMao6KIV+Ted2U1xfRGD9110hI4/fVjI+ElnbWIWCNDxBf+Ifuc1L4TP6PEK
gHm6/dE6S2cGKhTJbbhMrOja4ku2L291++q5nS048u1gTwtj/NvIOncdhk4v52s1
zloXrMaFLBPp2UUN/amDTUIJ
-----END PRIVATE KEY-----";

    #[test]
    fn sign_get_headers_produces_valid_header() {
        let url: url::Url = "https://remote.example/users/alice".parse().unwrap();
        let key_id = "https://local.example/users/writer#main-key";

        let headers = FederationClient::sign_get_headers(TEST_KEY_PEM, key_id, &url).unwrap();

        assert!(headers.contains_key("Date"));
        assert!(headers.contains_key("Signature"));

        let sig = headers["Signature"].to_str().unwrap();
        assert!(sig.contains("keyId=\"https://local.example/users/writer#main-key\""));
        assert!(sig.contains("algorithm=\"rsa-sha256\""));
        assert!(sig.contains("headers=\"(request-target) host date\""));
        assert!(sig.contains("signature=\""));
    }

    #[test]
    fn sign_post_headers_includes_digest() {
        let url: url::Url = "https://remote.example/inbox".parse().unwrap();
        let key_id = "https://local.example/users/writer#main-key";
        let body = b"{\"type\":\"Follow\"}";

        let headers =
            FederationClient::sign_post_headers(TEST_KEY_PEM, key_id, &url, body).unwrap();

        assert!(headers.contains_key("Date"));
        assert!(headers.contains_key("Digest"));
        assert!(headers.contains_key("Signature"));

        let digest = headers["Digest"].to_str().unwrap();
        assert!(digest.starts_with("SHA-256="));

        let sig = headers["Signature"].to_str().unwrap();
        assert!(sig.contains("headers=\"(request-target) host date digest\""));
    }

    #[test]
    fn sign_get_signature_verifies() {
        use rsa::pkcs8::DecodePrivateKey;
        use rsa::signature::Verifier;
        use rsa::RsaPrivateKey;
        use sha2::Sha256;

        let url: url::Url = "https://remote.example/users/alice".parse().unwrap();
        let key_id = "https://local.example/users/writer#main-key";

        let headers = FederationClient::sign_get_headers(TEST_KEY_PEM, key_id, &url).unwrap();

        // Extract signature from header
        let sig_header = headers["Signature"].to_str().unwrap();
        let sig_b64 = sig_header
            .split("signature=\"")
            .nth(1)
            .unwrap()
            .trim_end_matches('"');
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(sig_b64)
            .unwrap();

        // Reconstruct signed string
        let date = headers["Date"].to_str().unwrap();
        let signed_string =
            format!("(request-target): get /users/alice\nhost: remote.example\ndate: {date}");

        // Verify with public key derived from the private key
        let private_key = RsaPrivateKey::from_pkcs8_pem(TEST_KEY_PEM).unwrap();
        let public_key = rsa::RsaPublicKey::from(&private_key);
        let verifying_key = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(public_key);
        let signature = rsa::pkcs1v15::Signature::try_from(sig_bytes.as_slice()).unwrap();
        verifying_key
            .verify(signed_string.as_bytes(), &signature)
            .expect("signature verification failed");
    }

    #[test]
    fn parse_actor_document_person() {
        let doc = serde_json::json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": "https://remote.example/users/alice",
            "type": "Person",
            "preferredUsername": "alice",
            "name": "Alice Wonderland",
            "summary": "<p>Down the rabbit hole</p>",
            "inbox": "https://remote.example/users/alice/inbox",
            "followers": "https://remote.example/users/alice/followers",
            "endpoints": {
                "sharedInbox": "https://remote.example/inbox"
            },
            "publicKey": {
                "id": "https://remote.example/users/alice#main-key",
                "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMIIBI...\n-----END PUBLIC KEY-----"
            },
            "icon": {
                "url": "https://remote.example/avatars/alice.png"
            },
            "image": {
                "url": "https://remote.example/headers/alice.jpg"
            },
            "manuallyApprovesFollowers": true
        });

        let data = parse_actor_document(&doc, "https://remote.example/users/alice").unwrap();

        assert_eq!(data.actor_uri, "https://remote.example/users/alice");
        assert_eq!(data.username, "alice");
        assert_eq!(data.domain, "remote.example");
        assert_eq!(data.display_name, "Alice Wonderland");
        assert_eq!(data.bio_html, "<p>Down the rabbit hole</p>");
        assert_eq!(
            data.avatar_url.as_deref(),
            Some("https://remote.example/avatars/alice.png")
        );
        assert_eq!(
            data.header_url.as_deref(),
            Some("https://remote.example/headers/alice.jpg")
        );
        assert_eq!(data.inbox_url, "https://remote.example/users/alice/inbox");
        assert_eq!(
            data.shared_inbox_url.as_deref(),
            Some("https://remote.example/inbox")
        );
        assert!(data.is_locked);
        assert!(!data.bot);
    }

    #[test]
    fn parse_actor_document_service_is_bot() {
        let doc = serde_json::json!({
            "id": "https://remote.example/users/botacct",
            "type": "Service",
            "preferredUsername": "botacct",
            "inbox": "https://remote.example/users/botacct/inbox",
            "publicKey": {
                "id": "https://remote.example/users/botacct#main-key",
                "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----"
            }
        });

        let data = parse_actor_document(&doc, "https://remote.example/users/botacct").unwrap();

        assert!(data.bot);
        // display_name falls back to username when name is absent
        assert_eq!(data.display_name, "botacct");
    }

    #[test]
    fn parse_actor_document_id_mismatch_rejected() {
        let doc = serde_json::json!({
            "id": "https://evil.example/users/alice",
            "type": "Person",
            "preferredUsername": "alice",
            "inbox": "https://evil.example/users/alice/inbox",
            "publicKey": {
                "id": "https://evil.example/users/alice#main-key",
                "publicKeyPem": "key"
            }
        });

        let err = parse_actor_document(&doc, "https://remote.example/users/alice").unwrap_err();
        assert!(
            err.to_string().contains("mismatch"),
            "expected mismatch error, got: {err}"
        );
    }

    #[test]
    fn parse_actor_document_missing_username_rejected() {
        let doc = serde_json::json!({
            "id": "https://remote.example/users/x",
            "type": "Person",
            "inbox": "https://remote.example/users/x/inbox",
            "publicKey": {
                "id": "https://remote.example/users/x#main-key",
                "publicKeyPem": "key"
            }
        });

        let err = parse_actor_document(&doc, "https://remote.example/users/x").unwrap_err();
        assert!(err.to_string().contains("preferredUsername"));
    }

    #[tokio::test]
    async fn upsert_remote_account_insert_and_update() {
        let pool = crate::db::create_pool("sqlite::memory:").await.unwrap();

        let data = RemoteActorData {
            actor_uri: "https://remote.example/users/alice".into(),
            username: "alice".into(),
            domain: "remote.example".into(),
            display_name: "Alice".into(),
            bio_html: "<p>hi</p>".into(),
            avatar_url: None,
            header_url: None,
            public_key_pem: "-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----".into(),
            public_key_id: "https://remote.example/users/alice#main-key".into(),
            inbox_url: "https://remote.example/users/alice/inbox".into(),
            shared_inbox_url: Some("https://remote.example/inbox".into()),
            followers_url: Some("https://remote.example/users/alice/followers".into()),
            is_locked: false,
            bot: false,
        };

        let id1 = upsert_remote_account(&pool, &data).await.unwrap();
        assert!(id1 > 0);

        // Upsert again with changed display_name
        let data2 = RemoteActorData {
            actor_uri: data.actor_uri.clone(),
            username: data.username.clone(),
            domain: data.domain.clone(),
            display_name: "Alice Updated".into(),
            bio_html: data.bio_html.clone(),
            avatar_url: data.avatar_url.clone(),
            header_url: data.header_url.clone(),
            public_key_pem: data.public_key_pem.clone(),
            public_key_id: data.public_key_id.clone(),
            inbox_url: data.inbox_url.clone(),
            shared_inbox_url: data.shared_inbox_url.clone(),
            followers_url: data.followers_url.clone(),
            is_locked: data.is_locked,
            bot: data.bot,
        };

        let id2 = upsert_remote_account(&pool, &data2).await.unwrap();
        // Same row, same ID
        assert_eq!(id1, id2);

        // Verify the update landed
        let (name,): (String,) =
            sqlx::query_as("SELECT display_name FROM remote_accounts WHERE id = ?")
                .bind(id1)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(name, "Alice Updated");
    }

    // -- FEP-8fcf tests --

    #[test]
    fn format_collection_sync_header_roundtrip() {
        let header = format_collection_sync_header("local.example", "alice", "sha-256=AAAA");
        assert_eq!(
            header,
            "collectionId=\"https://local.example/users/alice/followers\", \
             digest=\"sha-256=AAAA\", \
             url=\"https://local.example/users/alice/followers\""
        );

        let (cid, digest, url) = parse_collection_sync_header(&header).unwrap();
        assert_eq!(cid, "https://local.example/users/alice/followers");
        assert_eq!(digest, "sha-256=AAAA");
        assert_eq!(url, "https://local.example/users/alice/followers");
    }

    #[test]
    fn parse_collection_sync_header_missing_field_returns_none() {
        // Missing url field
        assert!(parse_collection_sync_header("collectionId=\"x\", digest=\"y\"").is_none());
        // Empty string
        assert!(parse_collection_sync_header("").is_none());
    }

    #[tokio::test]
    async fn compute_follower_sync_digest_no_followers() {
        let pool = crate::db::create_pool("sqlite::memory:").await.unwrap();

        // Create a local account
        let acct_id = crate::id::generate_id();
        sqlx::query(
            "INSERT INTO accounts (id, username, display_name, private_key_pem, public_key_pem, created_at)
             VALUES (?, 'testuser', 'Test', 'privkey', 'pubkey', 0)",
        )
        .bind(acct_id)
        .execute(&pool)
        .await
        .unwrap();

        // No followers => None
        let result = compute_follower_sync_digest(&pool, acct_id, "remote.example").await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn compute_follower_sync_digest_single_follower() {
        let pool = crate::db::create_pool("sqlite::memory:").await.unwrap();

        // Create a local account
        let acct_id = crate::id::generate_id();
        sqlx::query(
            "INSERT INTO accounts (id, username, display_name, private_key_pem, public_key_pem, created_at)
             VALUES (?, 'testuser', 'Test', 'privkey', 'pubkey', 0)",
        )
        .bind(acct_id)
        .execute(&pool)
        .await
        .unwrap();

        // Create a remote account on remote.example
        let remote_id = crate::id::generate_id();
        let data = RemoteActorData {
            actor_uri: "https://remote.example/users/bob".into(),
            username: "bob".into(),
            domain: "remote.example".into(),
            display_name: "Bob".into(),
            bio_html: "".into(),
            avatar_url: None,
            header_url: None,
            public_key_pem: "-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----".into(),
            public_key_id: format!("https://remote.example/users/bob#main-key-{remote_id}"),
            inbox_url: "https://remote.example/users/bob/inbox".into(),
            shared_inbox_url: None,
            followers_url: None,
            is_locked: false,
            bot: false,
        };
        let rid = upsert_remote_account(&pool, &data).await.unwrap();

        // Add follower
        sqlx::query(
            "INSERT INTO followers (local_account_id, remote_account_id, accepted_at) VALUES (?, ?, 0)",
        )
        .bind(acct_id)
        .bind(rid)
        .execute(&pool)
        .await
        .unwrap();

        let result = compute_follower_sync_digest(&pool, acct_id, "remote.example").await;
        assert!(result.is_some());
        let digest = result.unwrap();
        assert!(digest.starts_with("sha-256="));

        // Verify independently: SHA-256 of a single URI, base64-encoded
        use sha2::Digest;
        let expected_hash = sha2::Sha256::digest(b"https://remote.example/users/bob");
        let expected = format!(
            "sha-256={}",
            base64::engine::general_purpose::STANDARD.encode(expected_hash)
        );
        assert_eq!(digest, expected);
    }

    #[tokio::test]
    async fn compute_follower_sync_digest_xor_is_commutative() {
        let pool = crate::db::create_pool("sqlite::memory:").await.unwrap();

        let acct_id = crate::id::generate_id();
        sqlx::query(
            "INSERT INTO accounts (id, username, display_name, private_key_pem, public_key_pem, created_at)
             VALUES (?, 'testuser', 'Test', 'privkey', 'pubkey', 0)",
        )
        .bind(acct_id)
        .execute(&pool)
        .await
        .unwrap();

        // Create two remote followers on the same domain
        for name in &["carol", "dave"] {
            let data = RemoteActorData {
                actor_uri: format!("https://remote.example/users/{name}"),
                username: name.to_string(),
                domain: "remote.example".into(),
                display_name: name.to_string(),
                bio_html: "".into(),
                avatar_url: None,
                header_url: None,
                public_key_pem: "-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----".into(),
                public_key_id: format!("https://remote.example/users/{name}#main-key"),
                inbox_url: format!("https://remote.example/users/{name}/inbox"),
                shared_inbox_url: None,
                followers_url: None,
                is_locked: false,
                bot: false,
            };
            let rid = upsert_remote_account(&pool, &data).await.unwrap();
            sqlx::query(
                "INSERT INTO followers (local_account_id, remote_account_id, accepted_at) VALUES (?, ?, 0)",
            )
            .bind(acct_id)
            .bind(rid)
            .execute(&pool)
            .await
            .unwrap();
        }

        let digest = compute_follower_sync_digest(&pool, acct_id, "remote.example")
            .await
            .unwrap();

        // Compute expected: XOR of SHA-256("https://remote.example/users/carol")
        // and SHA-256("https://remote.example/users/dave")
        use sha2::Digest;
        let h1 = sha2::Sha256::digest(b"https://remote.example/users/carol");
        let h2 = sha2::Sha256::digest(b"https://remote.example/users/dave");
        let mut xor = [0u8; 32];
        for i in 0..32 {
            xor[i] = h1[i] ^ h2[i];
        }
        let expected = format!(
            "sha-256={}",
            base64::engine::general_purpose::STANDARD.encode(xor)
        );
        assert_eq!(digest, expected);
    }

    #[tokio::test]
    async fn compute_follower_sync_digest_filters_by_domain() {
        let pool = crate::db::create_pool("sqlite::memory:").await.unwrap();

        let acct_id = crate::id::generate_id();
        sqlx::query(
            "INSERT INTO accounts (id, username, display_name, private_key_pem, public_key_pem, created_at)
             VALUES (?, 'testuser', 'Test', 'privkey', 'pubkey', 0)",
        )
        .bind(acct_id)
        .execute(&pool)
        .await
        .unwrap();

        // Follower on remote.example
        let data1 = RemoteActorData {
            actor_uri: "https://remote.example/users/eve".into(),
            username: "eve".into(),
            domain: "remote.example".into(),
            display_name: "Eve".into(),
            bio_html: "".into(),
            avatar_url: None,
            header_url: None,
            public_key_pem: "-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----".into(),
            public_key_id: "https://remote.example/users/eve#main-key".into(),
            inbox_url: "https://remote.example/users/eve/inbox".into(),
            shared_inbox_url: None,
            followers_url: None,
            is_locked: false,
            bot: false,
        };
        let rid1 = upsert_remote_account(&pool, &data1).await.unwrap();

        // Follower on other.example
        let data2 = RemoteActorData {
            actor_uri: "https://other.example/users/frank".into(),
            username: "frank".into(),
            domain: "other.example".into(),
            display_name: "Frank".into(),
            bio_html: "".into(),
            avatar_url: None,
            header_url: None,
            public_key_pem: "-----BEGIN PUBLIC KEY-----\nfake2\n-----END PUBLIC KEY-----".into(),
            public_key_id: "https://other.example/users/frank#main-key".into(),
            inbox_url: "https://other.example/users/frank/inbox".into(),
            shared_inbox_url: None,
            followers_url: None,
            is_locked: false,
            bot: false,
        };
        let rid2 = upsert_remote_account(&pool, &data2).await.unwrap();

        for rid in [rid1, rid2] {
            sqlx::query(
                "INSERT INTO followers (local_account_id, remote_account_id, accepted_at) VALUES (?, ?, 0)",
            )
            .bind(acct_id)
            .bind(rid)
            .execute(&pool)
            .await
            .unwrap();
        }

        // Digest for remote.example should only include eve
        let digest_remote = compute_follower_sync_digest(&pool, acct_id, "remote.example")
            .await
            .unwrap();
        use sha2::Digest;
        let eve_hash = sha2::Sha256::digest(b"https://remote.example/users/eve");
        let expected_remote = format!(
            "sha-256={}",
            base64::engine::general_purpose::STANDARD.encode(eve_hash)
        );
        assert_eq!(digest_remote, expected_remote);

        // Digest for other.example should only include frank
        let digest_other = compute_follower_sync_digest(&pool, acct_id, "other.example")
            .await
            .unwrap();
        let frank_hash = sha2::Sha256::digest(b"https://other.example/users/frank");
        let expected_other = format!(
            "sha-256={}",
            base64::engine::general_purpose::STANDARD.encode(frank_hash)
        );
        assert_eq!(digest_other, expected_other);

        // Different domains produce different digests
        assert_ne!(digest_remote, digest_other);
    }
}
