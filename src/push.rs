use crate::api::AuthenticatedAccount;
use crate::error::AppError;
use crate::id::generate_id;
use crate::server::AppState;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, KeyInit, Nonce};
use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use hkdf::Hkdf;
use p256::ecdh::EphemeralSecret;
use p256::ecdsa::{signature::Signer, SigningKey, VerifyingKey};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use p256::{EncodedPoint, PublicKey};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::Sha256;
use sqlx::SqlitePool;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct AlertsConfig {
    pub mention: bool,
    pub favourite: bool,
    pub reblog: bool,
    pub follow: bool,
    pub poll: bool,
}

#[derive(sqlx::FromRow)]
#[allow(dead_code)]
struct SubscriptionRow {
    id: i64,
    user_id: i64,
    endpoint: String,
    key_p256dh: String,
    key_auth: String,
    alerts_mention: bool,
    alerts_favourite: bool,
    alerts_reblog: bool,
    alerts_follow: bool,
    alerts_poll: bool,
    policy: String,
    created_at: i64,
}

// ---------------------------------------------------------------------------
// VAPID key management
// ---------------------------------------------------------------------------

/// Get or create the server's VAPID keypair. Returns (private_key_pem, public_key_base64url).
pub async fn get_or_create_vapid_key(pool: &SqlitePool) -> anyhow::Result<(String, String)> {
    let existing: Option<(String, String)> =
        sqlx::query_as("SELECT private_key_pem, public_key_base64 FROM vapid_keys WHERE id = 1")
            .fetch_optional(pool)
            .await?;

    if let Some((pem, pub_b64)) = existing {
        return Ok((pem, pub_b64));
    }

    // Generate a new P-256 keypair
    let signing_key = SigningKey::random(&mut rand::thread_rng());
    let verifying_key = VerifyingKey::from(&signing_key);

    let pem = signing_key
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .map_err(|e| anyhow::anyhow!("Failed to encode VAPID key: {e}"))?;

    // Public key in uncompressed SEC1 format, base64url encoded (no padding)
    let pub_bytes = EncodedPoint::from(verifying_key);
    let pub_b64 = URL_SAFE_NO_PAD.encode(pub_bytes.as_bytes());

    sqlx::query("INSERT OR IGNORE INTO vapid_keys (id, private_key_pem, public_key_base64) VALUES (1, ?, ?)")
        .bind(pem.as_str())
        .bind(&pub_b64)
        .execute(pool)
        .await?;

    Ok((pem.to_string(), pub_b64))
}

/// Get just the public key (base64url). Used for instance API responses.
pub async fn get_vapid_public_key(pool: &SqlitePool) -> String {
    match get_or_create_vapid_key(pool).await {
        Ok((_, pub_key)) => pub_key,
        Err(_) => String::new(),
    }
}

// ---------------------------------------------------------------------------
// Subscription CRUD
// ---------------------------------------------------------------------------

pub async fn create_subscription(
    pool: &SqlitePool,
    account_id: i64,
    endpoint: &str,
    p256dh: &str,
    auth: &str,
    alerts: &AlertsConfig,
    policy: &str,
) -> Result<Value, AppError> {
    let id = generate_id();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;

    // Upsert: replace any existing subscription for this account
    sqlx::query("DELETE FROM push_subscriptions WHERE user_id = ?")
        .bind(account_id)
        .execute(pool)
        .await?;

    sqlx::query(
        "INSERT INTO push_subscriptions (id, user_id, endpoint, key_p256dh, key_auth, \
         alerts_mention, alerts_favourite, alerts_reblog, alerts_follow, alerts_poll, policy, created_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id)
    .bind(account_id)
    .bind(endpoint)
    .bind(p256dh)
    .bind(auth)
    .bind(alerts.mention)
    .bind(alerts.favourite)
    .bind(alerts.reblog)
    .bind(alerts.follow)
    .bind(alerts.poll)
    .bind(policy)
    .bind(now)
    .execute(pool)
    .await?;

    let vapid_pub = get_vapid_public_key(pool).await;
    Ok(subscription_to_json(
        id, endpoint, &vapid_pub, alerts, policy,
    ))
}

pub async fn get_subscription(
    pool: &SqlitePool,
    account_id: i64,
) -> Result<Option<Value>, AppError> {
    let row: Option<SubscriptionRow> = sqlx::query_as(
        "SELECT id, user_id, endpoint, key_p256dh, key_auth, \
         alerts_mention, alerts_favourite, alerts_reblog, alerts_follow, alerts_poll, \
         policy, created_at FROM push_subscriptions WHERE user_id = ?",
    )
    .bind(account_id)
    .fetch_optional(pool)
    .await?;

    match row {
        Some(r) => {
            let vapid_pub = get_vapid_public_key(pool).await;
            let alerts = AlertsConfig {
                mention: r.alerts_mention,
                favourite: r.alerts_favourite,
                reblog: r.alerts_reblog,
                follow: r.alerts_follow,
                poll: r.alerts_poll,
            };
            Ok(Some(subscription_to_json(
                r.id,
                &r.endpoint,
                &vapid_pub,
                &alerts,
                &r.policy,
            )))
        }
        None => Ok(None),
    }
}

pub async fn update_subscription(
    pool: &SqlitePool,
    account_id: i64,
    alerts: &AlertsConfig,
    policy: &str,
) -> Result<Value, AppError> {
    sqlx::query(
        "UPDATE push_subscriptions SET alerts_mention = ?, alerts_favourite = ?, \
         alerts_reblog = ?, alerts_follow = ?, alerts_poll = ?, policy = ? \
         WHERE user_id = ?",
    )
    .bind(alerts.mention)
    .bind(alerts.favourite)
    .bind(alerts.reblog)
    .bind(alerts.follow)
    .bind(alerts.poll)
    .bind(policy)
    .bind(account_id)
    .execute(pool)
    .await?;

    get_subscription(pool, account_id)
        .await?
        .ok_or_else(|| AppError::not_found("No push subscription"))
}

pub async fn delete_subscription(pool: &SqlitePool, account_id: i64) -> Result<(), AppError> {
    sqlx::query("DELETE FROM push_subscriptions WHERE user_id = ?")
        .bind(account_id)
        .execute(pool)
        .await?;
    Ok(())
}

fn subscription_to_json(
    id: i64,
    endpoint: &str,
    server_key: &str,
    alerts: &AlertsConfig,
    policy: &str,
) -> Value {
    json!({
        "id": id.to_string(),
        "endpoint": endpoint,
        "server_key": server_key,
        "alerts": {
            "mention": alerts.mention,
            "favourite": alerts.favourite,
            "reblog": alerts.reblog,
            "follow": alerts.follow,
            "poll": alerts.poll,
        },
        "policy": policy,
    })
}

// ---------------------------------------------------------------------------
// Push delivery
// ---------------------------------------------------------------------------

/// Send a push notification to a local account. Fire-and-forget; errors are logged, not propagated.
pub async fn send_push_notification(
    pool: &SqlitePool,
    account_id: i64,
    notification_type: &str,
    title: &str,
    body: &str,
    _icon: Option<&str>,
    domain: &str,
) {
    let result = send_push_inner(pool, account_id, notification_type, title, body, domain).await;
    if let Err(e) = result {
        tracing::debug!(account_id, notification_type, error = %e, "push notification failed");
    }
}

async fn send_push_inner(
    pool: &SqlitePool,
    account_id: i64,
    notification_type: &str,
    title: &str,
    body: &str,
    domain: &str,
) -> anyhow::Result<()> {
    let row: Option<SubscriptionRow> = sqlx::query_as(
        "SELECT id, user_id, endpoint, key_p256dh, key_auth, \
         alerts_mention, alerts_favourite, alerts_reblog, alerts_follow, alerts_poll, \
         policy, created_at FROM push_subscriptions WHERE user_id = ?",
    )
    .bind(account_id)
    .fetch_optional(pool)
    .await?;

    let sub = match row {
        Some(s) => s,
        None => return Ok(()), // No subscription, nothing to do
    };

    // Check if this notification type is enabled
    let enabled = match notification_type {
        "mention" => sub.alerts_mention,
        "favourite" => sub.alerts_favourite,
        "reblog" => sub.alerts_reblog,
        "follow" => sub.alerts_follow,
        "poll" => sub.alerts_poll,
        _ => true,
    };
    if !enabled {
        return Ok(());
    }

    // SSRF check: validate the push endpoint URL before sending
    let endpoint_url: url::Url = sub.endpoint.parse()?;
    if let Err(e) = crate::federation::validate_outbound_url(&endpoint_url) {
        tracing::warn!(account_id, endpoint = %sub.endpoint, error = %e, "push endpoint failed SSRF validation, skipping");
        return Ok(());
    }

    // Build payload
    let payload = serde_json::to_vec(&json!({
        "notification_id": generate_id().to_string(),
        "notification_type": notification_type,
        "title": title,
        "body": body,
    }))?;

    // Get VAPID key
    let (vapid_pem, vapid_pub_b64) = get_or_create_vapid_key(pool).await?;

    // Encrypt payload using RFC 8291 (Web Push Message Encryption)
    let encrypted = encrypt_payload(&sub.key_p256dh, &sub.key_auth, &payload)?;

    // Build VAPID JWT
    let audience = format!(
        "{}://{}",
        endpoint_url.scheme(),
        endpoint_url.host_str().unwrap_or("")
    );
    let jwt = build_vapid_jwt(&vapid_pem, &audience, domain)?;

    // Send HTTP POST
    static PUSH_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("failed to build push HTTP client")
    });
    let response = PUSH_CLIENT
        .post(&sub.endpoint)
        .header("Content-Type", "application/octet-stream")
        .header("Content-Encoding", "aes128gcm")
        .header("TTL", "86400")
        .header("Authorization", format!("vapid t={jwt},k={vapid_pub_b64}"))
        .body(encrypted)
        .send()
        .await?;

    let status = response.status().as_u16();

    // 404 or 410 means the subscription is stale — delete it
    if status == 404 || status == 410 {
        tracing::info!(account_id, "push endpoint gone, removing subscription");
        sqlx::query("DELETE FROM push_subscriptions WHERE user_id = ?")
            .bind(account_id)
            .execute(pool)
            .await?;
    } else if status >= 400 {
        let body_bytes = response.bytes().await.unwrap_or_default();
        let body_text = String::from_utf8_lossy(&body_bytes[..body_bytes.len().min(1024)]);
        tracing::debug!(account_id, status, body = %body_text, "push endpoint returned error");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// RFC 8291 payload encryption (aes128gcm content encoding)
// ---------------------------------------------------------------------------

fn encrypt_payload(
    client_pub_b64: &str,
    client_auth_b64: &str,
    plaintext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    // Decode client public key (base64url)
    let client_pub_bytes = URL_SAFE_NO_PAD
        .decode(client_pub_b64)
        .or_else(|_| STANDARD.decode(client_pub_b64))?;
    let client_pub = PublicKey::from_sec1_bytes(&client_pub_bytes)
        .map_err(|e| anyhow::anyhow!("invalid client public key: {e}"))?;

    // Decode client auth secret (base64url, 16 bytes)
    let auth_secret = URL_SAFE_NO_PAD
        .decode(client_auth_b64)
        .or_else(|_| STANDARD.decode(client_auth_b64))?;

    // Generate ephemeral server keypair for ECDH
    let server_secret = EphemeralSecret::random(&mut rand::thread_rng());
    let server_pub = p256::PublicKey::from(&server_secret);
    let server_pub_bytes = EncodedPoint::from(server_pub);

    // ECDH shared secret
    let shared_secret = server_secret.diffie_hellman(&client_pub);

    // RFC 8291 key derivation
    // IKM for auth_info HKDF
    let ikm = shared_secret.raw_secret_bytes();

    // auth_info = "WebPush: info\0" || client_pub || server_pub
    let mut auth_info = Vec::with_capacity(100);
    auth_info.extend_from_slice(b"WebPush: info\0");
    auth_info.extend_from_slice(&client_pub_bytes);
    auth_info.extend_from_slice(server_pub_bytes.as_bytes());

    // PRK from auth secret
    let hk_auth = Hkdf::<Sha256>::new(Some(&auth_secret), ikm);
    let mut ikm_derived = [0u8; 32];
    hk_auth
        .expand(&auth_info, &mut ikm_derived)
        .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;

    // Generate salt (16 bytes random)
    let mut salt = [0u8; 16];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut salt);

    // Derive content encryption key and nonce
    let hk_content = Hkdf::<Sha256>::new(Some(&salt), &ikm_derived);

    let mut cek = [0u8; 16];
    hk_content
        .expand(b"Content-Encoding: aes128gcm\0", &mut cek)
        .map_err(|_| anyhow::anyhow!("HKDF CEK expand failed"))?;

    let mut nonce_bytes = [0u8; 12];
    hk_content
        .expand(b"Content-Encoding: nonce\0", &mut nonce_bytes)
        .map_err(|_| anyhow::anyhow!("HKDF nonce expand failed"))?;

    // Pad plaintext: add delimiter byte 0x02 (final record)
    let mut padded = Vec::with_capacity(plaintext.len() + 1);
    padded.extend_from_slice(plaintext);
    padded.push(0x02); // delimiter for final record

    // Encrypt with AES-128-GCM
    let cipher =
        Aes128Gcm::new_from_slice(&cek).map_err(|_| anyhow::anyhow!("AES key init failed"))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, padded.as_ref())
        .map_err(|_| anyhow::anyhow!("AES-GCM encryption failed"))?;

    // Build aes128gcm header:
    // salt (16) || record_size (4, big-endian) || keyid_len (1) || keyid (server pub, 65 bytes)
    // Per RFC 8188, record_size is the size of each plaintext record + 17 (16-byte tag + 1-byte padding delimiter)
    let record_size: u32 = (plaintext.len() as u32 + 17).max(4096);

    let mut output = Vec::with_capacity(86 + ciphertext.len());
    output.extend_from_slice(&salt);
    output.extend_from_slice(&record_size.to_be_bytes());
    output.push(server_pub_bytes.as_bytes().len() as u8); // 65 for uncompressed
    output.extend_from_slice(server_pub_bytes.as_bytes());
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

// ---------------------------------------------------------------------------
// VAPID JWT (ES256)
// ---------------------------------------------------------------------------

fn build_vapid_jwt(private_key_pem: &str, audience: &str, domain: &str) -> anyhow::Result<String> {
    let signing_key = SigningKey::from_pkcs8_pem(private_key_pem)
        .map_err(|e| anyhow::anyhow!("Failed to parse VAPID key: {e}"))?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // JWT header: {"typ":"JWT","alg":"ES256"}
    let header = URL_SAFE_NO_PAD.encode(b"{\"typ\":\"JWT\",\"alg\":\"ES256\"}");

    // JWT claims
    let claims = json!({
        "aud": audience,
        "exp": now + 86400,
        "sub": format!("mailto:admin@{}", domain),
    });
    let claims_b64 = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());

    // Sign
    let signing_input = format!("{header}.{claims_b64}");
    let signature: p256::ecdsa::Signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    Ok(format!("{signing_input}.{sig_b64}"))
}

// ---------------------------------------------------------------------------
// API routes
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct PushSubscriptionCreate {
    subscription: Option<SubscriptionKeys>,
    data: Option<PushData>,
}

#[derive(Deserialize)]
struct SubscriptionKeys {
    endpoint: Option<String>,
    keys: Option<KeyPair>,
}

#[derive(Deserialize)]
struct KeyPair {
    p256dh: Option<String>,
    auth: Option<String>,
}

#[derive(Deserialize)]
struct PushData {
    alerts: Option<AlertsInput>,
    policy: Option<String>,
}

#[derive(Deserialize, Default)]
struct AlertsInput {
    mention: Option<bool>,
    favourite: Option<bool>,
    reblog: Option<bool>,
    follow: Option<bool>,
    poll: Option<bool>,
}

fn parse_alerts(input: Option<&AlertsInput>) -> AlertsConfig {
    match input {
        Some(a) => AlertsConfig {
            mention: a.mention.unwrap_or(true),
            favourite: a.favourite.unwrap_or(true),
            reblog: a.reblog.unwrap_or(true),
            follow: a.follow.unwrap_or(true),
            poll: a.poll.unwrap_or(false),
        },
        None => AlertsConfig {
            mention: true,
            favourite: true,
            reblog: true,
            follow: true,
            poll: false,
        },
    }
}

async fn create_push_subscription(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Json(body): Json<PushSubscriptionCreate>,
) -> Result<Json<Value>, AppError> {
    let sub = body
        .subscription
        .ok_or_else(|| AppError::bad_request("Missing subscription"))?;
    let endpoint = sub
        .endpoint
        .ok_or_else(|| AppError::bad_request("Missing endpoint"))?;
    let keys = sub
        .keys
        .ok_or_else(|| AppError::bad_request("Missing keys"))?;
    let p256dh = keys
        .p256dh
        .ok_or_else(|| AppError::bad_request("Missing p256dh key"))?;
    let auth_key = keys
        .auth
        .ok_or_else(|| AppError::bad_request("Missing auth key"))?;

    let alerts = parse_alerts(body.data.as_ref().and_then(|d| d.alerts.as_ref()));
    let policy = body
        .data
        .as_ref()
        .and_then(|d| d.policy.as_deref())
        .unwrap_or("all");

    let result = create_subscription(
        &state.pool,
        auth.account_id,
        &endpoint,
        &p256dh,
        &auth_key,
        &alerts,
        policy,
    )
    .await?;

    Ok(Json(result))
}

async fn get_push_subscription(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
) -> Result<Json<Value>, AppError> {
    let sub = get_subscription(&state.pool, auth.account_id)
        .await?
        .ok_or_else(|| AppError::not_found("No push subscription"))?;
    Ok(Json(sub))
}

async fn update_push_subscription(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Json(body): Json<PushSubscriptionCreate>,
) -> Result<Json<Value>, AppError> {
    let alerts = parse_alerts(body.data.as_ref().and_then(|d| d.alerts.as_ref()));
    let policy = body
        .data
        .as_ref()
        .and_then(|d| d.policy.as_deref())
        .unwrap_or("all");

    let result = update_subscription(&state.pool, auth.account_id, &alerts, policy).await?;
    Ok(Json(result))
}

async fn delete_push_subscription(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
) -> Result<Json<Value>, AppError> {
    delete_subscription(&state.pool, auth.account_id).await?;
    Ok(Json(json!({})))
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route(
        "/api/v1/push/subscription",
        get(get_push_subscription)
            .post(create_push_subscription)
            .put(update_push_subscription)
            .delete(delete_push_subscription),
    )
}
