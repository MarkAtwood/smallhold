use crate::api::{hex_encode, now_millis};
use crate::error::AppError;
use crate::server::AppState;
use axum::extract::State;
use axum::response::Html;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};
use webauthn_rs::prelude::*;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const CHALLENGE_TTL_MS: i64 = 300_000; // 5 minutes
const PASSKEY_TOKEN_TTL_MS: i64 = 120_000; // 2 minutes

// Admin user ID for WebAuthn — singleton admin, fixed UUID
// ponytail: single admin, hardcoded UUID avoids a lookup
static ADMIN_USER_ID: LazyLock<Uuid> =
    LazyLock::new(|| Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap());

// One-time passkey auth tokens: token_hash -> expiry_ms
// ponytail: In-memory store acceptable — tokens have 2-minute TTL and are
// consumed immediately by the authorize form submit. Server restart during
// the narrow window between auth_complete and form submit means the user
// retries (not a security issue, just UX friction).
static PASSKEY_TOKENS: LazyLock<Mutex<HashMap<String, i64>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

// ---------------------------------------------------------------------------
// WebAuthn instance builder
// ---------------------------------------------------------------------------

fn build_webauthn(domain: &str) -> Result<Webauthn, AppError> {
    let origin = Url::parse(&format!("https://{domain}"))
        .map_err(|e| AppError::internal(format!("invalid domain for WebAuthn origin: {e}")))?;

    let builder = WebauthnBuilder::new(domain, &origin)
        .map_err(|e| AppError::internal(format!("WebAuthn builder error: {e}")))?;

    builder
        .rp_name("smallhold")
        .build()
        .map_err(|e| AppError::internal(format!("WebAuthn build error: {e}")))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn random_hex(len: usize) -> String {
    use rand::RngCore;
    let mut bytes = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex_encode(&bytes)
}

async fn has_passkeys(pool: &sqlx::SqlitePool) -> Result<bool, AppError> {
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM webauthn_credentials")
        .fetch_one(pool)
        .await?;
    Ok(count.0 > 0)
}

async fn load_passkeys(pool: &sqlx::SqlitePool) -> Result<Vec<Passkey>, AppError> {
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT credential_json FROM webauthn_credentials ORDER BY id")
            .fetch_all(pool)
            .await?;

    let mut creds = Vec::with_capacity(rows.len());
    for (json_str,) in &rows {
        let pk: Passkey = serde_json::from_str(json_str)
            .map_err(|e| AppError::internal(format!("corrupt credential JSON: {e}")))?;
        creds.push(pk);
    }
    Ok(creds)
}

async fn store_challenge(
    pool: &sqlx::SqlitePool,
    challenge_id: &str,
    state: &impl serde::Serialize,
) -> Result<(), AppError> {
    let state_json = serde_json::to_string(state)
        .map_err(|e| AppError::internal(format!("serialize challenge state: {e}")))?;
    let now = now_millis();

    // Clean up expired challenges while we're here
    let cutoff = now - CHALLENGE_TTL_MS;
    let _ = sqlx::query("DELETE FROM webauthn_challenges WHERE created_at < ?")
        .bind(cutoff)
        .execute(pool)
        .await;

    sqlx::query(
        "INSERT INTO webauthn_challenges (challenge_id, state_json, created_at) VALUES (?, ?, ?)",
    )
    .bind(challenge_id)
    .bind(&state_json)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(())
}

async fn consume_challenge<T: serde::de::DeserializeOwned>(
    pool: &sqlx::SqlitePool,
    challenge_id: &str,
) -> Result<T, AppError> {
    let now = now_millis();
    let cutoff = now - CHALLENGE_TTL_MS;

    let row: Option<(String,)> = sqlx::query_as(
        "DELETE FROM webauthn_challenges WHERE challenge_id = ? AND created_at >= ? RETURNING state_json",
    )
    .bind(challenge_id)
    .bind(cutoff)
    .fetch_optional(pool)
    .await?;

    let (state_json,) = row.ok_or_else(|| AppError::bad_request("Invalid or expired challenge"))?;

    serde_json::from_str(&state_json)
        .map_err(|e| AppError::internal(format!("deserialize challenge state: {e}")))
}

// ---------------------------------------------------------------------------
// POST /admin/webauthn/register/begin
// ---------------------------------------------------------------------------

async fn register_begin(
    State(state): State<Arc<AppState>>,
    body: axum::body::Bytes,
) -> Result<Json<Value>, AppError> {
    // Require admin password auth
    let password = extract_password_from_body(&body)?;
    verify_admin_auth(&state, &password).await?;

    let webauthn = build_webauthn(&state.config.server.domain)?;
    let existing = load_passkeys(&state.pool).await?;

    let exclude: Vec<CredentialID> = existing.iter().map(|pk| pk.cred_id().clone()).collect();

    let (ccr, reg_state) = webauthn
        .start_passkey_registration(*ADMIN_USER_ID, "admin", "Admin", Some(exclude))
        .map_err(|e| AppError::internal(format!("start registration: {e}")))?;

    let challenge_id = random_hex(16);
    store_challenge(&state.pool, &challenge_id, &reg_state).await?;

    let ccr_json = serde_json::to_value(&ccr)
        .map_err(|e| AppError::internal(format!("serialize CCR: {e}")))?;

    Ok(Json(json!({
        "challenge_id": challenge_id,
        "publicKey": ccr_json,
    })))
}

// ---------------------------------------------------------------------------
// POST /admin/webauthn/register/complete
// ---------------------------------------------------------------------------

async fn register_complete(
    State(state): State<Arc<AppState>>,
    Json(body): Json<RegisterCompleteRequest>,
) -> Result<Json<Value>, AppError> {
    let webauthn = build_webauthn(&state.config.server.domain)?;

    let reg_state: PasskeyRegistration = consume_challenge(&state.pool, &body.challenge_id).await?;

    let passkey = webauthn
        .finish_passkey_registration(&body.credential, &reg_state)
        .map_err(|e| AppError::bad_request(format!("registration failed: {e}")))?;

    let credential_json = serde_json::to_string(&passkey)
        .map_err(|e| AppError::internal(format!("serialize passkey: {e}")))?;

    let id = crate::id::generate_id();
    let now = now_millis();

    sqlx::query(
        "INSERT INTO webauthn_credentials (id, credential_json, created_at) VALUES (?, ?, ?)",
    )
    .bind(id)
    .bind(&credential_json)
    .bind(now)
    .execute(&state.pool)
    .await?;

    Ok(Json(json!({
        "status": "ok",
        "credential_id": id.to_string(),
    })))
}

#[derive(serde::Deserialize)]
struct RegisterCompleteRequest {
    challenge_id: String,
    credential: RegisterPublicKeyCredential,
}

// ---------------------------------------------------------------------------
// GET /admin/webauthn/register — Registration page
// ---------------------------------------------------------------------------

async fn register_page(State(state): State<Arc<AppState>>) -> Result<Html<String>, AppError> {
    let has_keys = has_passkeys(&state.pool).await?;
    let note = if has_keys {
        "You already have passkeys registered. Enter your admin password to register another."
    } else {
        "No passkeys registered yet. Enter your admin password to register your first passkey."
    };

    let html = format!(
        r##"<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Register Passkey - smallhold</title>
  <style>
    body {{ font-family: sans-serif; max-width: 480px; margin: 4em auto; padding: 0 1em; }}
    label {{ display: block; margin: 1em 0 0.3em; }}
    input, button {{ width: 100%; padding: 0.5em; box-sizing: border-box; }}
    button {{ margin-top: 1.5em; cursor: pointer; }}
    .status {{ margin-top: 1em; padding: 1em; border-radius: 4px; }}
    .status.ok {{ background: #d4edda; color: #155724; }}
    .status.err {{ background: #f8d7da; color: #721c24; }}
    .status.info {{ background: #cce5ff; color: #004085; }}
  </style>
</head>
<body>
  <h1>Register Passkey</h1>
  <p>{note}</p>
  <label for="password">Admin Password</label>
  <input type="password" id="password" placeholder="Enter admin password">
  <button id="register-btn">Register Passkey</button>
  <div id="status" class="status info" style="display:none;"></div>

  <script>
    const statusEl = document.getElementById('status');
    function showStatus(msg, cls) {{
      statusEl.textContent = msg;
      statusEl.className = 'status ' + cls;
      statusEl.style.display = 'block';
    }}

    document.getElementById('register-btn').addEventListener('click', async () => {{
      const password = document.getElementById('password').value;
      if (!password) {{
        showStatus('Please enter your admin password.', 'err');
        return;
      }}

      showStatus('Starting registration...', 'info');

      try {{
        // Step 1: Begin registration
        const beginResp = await fetch('/admin/webauthn/register/begin', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/x-www-form-urlencoded' }},
          body: 'password=' + encodeURIComponent(password),
        }});
        if (!beginResp.ok) {{
          const err = await beginResp.json();
          showStatus('Error: ' + (err.error || 'Unknown error'), 'err');
          return;
        }}
        const beginData = await beginResp.json();

        // Step 2: Create credential via browser API
        const publicKey = beginData.publicKey;

        // Decode base64url fields
        publicKey.challenge = base64urlToBuffer(publicKey.challenge);
        publicKey.user.id = base64urlToBuffer(publicKey.user.id);
        if (publicKey.excludeCredentials) {{
          publicKey.excludeCredentials = publicKey.excludeCredentials.map(c => ({{
            ...c,
            id: base64urlToBuffer(c.id),
          }}));
        }}

        const credential = await navigator.credentials.create({{ publicKey }});

        // Step 3: Complete registration
        const attestation = {{
          challenge_id: beginData.challenge_id,
          credential: {{
            id: credential.id,
            rawId: bufferToBase64url(credential.rawId),
            type: credential.type,
            response: {{
              attestationObject: bufferToBase64url(credential.response.attestationObject),
              clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
            }},
          }},
        }};

        const completeResp = await fetch('/admin/webauthn/register/complete', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify(attestation),
        }});
        if (!completeResp.ok) {{
          const err = await completeResp.json();
          showStatus('Registration failed: ' + (err.error || 'Unknown error'), 'err');
          return;
        }}

        showStatus('Passkey registered successfully! You can now use it to sign in.', 'ok');
        document.getElementById('password').value = '';

      }} catch (e) {{
        if (e.name === 'NotAllowedError') {{
          showStatus('Registration was cancelled or timed out.', 'err');
        }} else {{
          showStatus('Error: ' + e.message, 'err');
        }}
      }}
    }});

    function base64urlToBuffer(b64url) {{
      const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
      const pad = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4));
      const binary = atob(b64 + pad);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      return bytes.buffer;
    }}

    function bufferToBase64url(buffer) {{
      const bytes = new Uint8Array(buffer);
      let binary = '';
      for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
      return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }}
  </script>
</body>
</html>"##
    );

    Ok(Html(html))
}

// ---------------------------------------------------------------------------
// POST /oauth/authorize/webauthn/begin — Start passkey authentication
// ---------------------------------------------------------------------------

async fn auth_begin(State(state): State<Arc<AppState>>) -> Result<Json<Value>, AppError> {
    let webauthn = build_webauthn(&state.config.server.domain)?;
    let existing = load_passkeys(&state.pool).await?;

    if existing.is_empty() {
        return Err(AppError::bad_request("No passkeys registered"));
    }

    let (rcr, auth_state) = webauthn
        .start_passkey_authentication(&existing)
        .map_err(|e| AppError::internal(format!("start auth: {e}")))?;

    let challenge_id = random_hex(16);
    store_challenge(&state.pool, &challenge_id, &auth_state).await?;

    let rcr_json = serde_json::to_value(&rcr)
        .map_err(|e| AppError::internal(format!("serialize RCR: {e}")))?;

    Ok(Json(json!({
        "challenge_id": challenge_id,
        "publicKey": rcr_json,
    })))
}

// ---------------------------------------------------------------------------
// POST /oauth/authorize/webauthn/complete — Complete passkey authentication
// ---------------------------------------------------------------------------

async fn auth_complete(
    State(state): State<Arc<AppState>>,
    Json(body): Json<AuthCompleteRequest>,
) -> Result<Json<Value>, AppError> {
    let webauthn = build_webauthn(&state.config.server.domain)?;

    let auth_state: PasskeyAuthentication =
        consume_challenge(&state.pool, &body.challenge_id).await?;

    let auth_result = webauthn
        .finish_passkey_authentication(&body.credential, &auth_state)
        .map_err(|e| AppError::forbidden(format!("authentication failed: {e}")))?;

    // Update credential counter in DB to prevent replay attacks
    // webauthn-rs handles counter validation internally, but we should
    // persist the updated credential. Reload and update all credentials.
    let mut passkeys = load_passkeys(&state.pool).await?;
    for pk in &mut passkeys {
        pk.update_credential(&auth_result);
    }
    // Persist updated credentials
    for pk in &passkeys {
        let cred_json = serde_json::to_string(pk)
            .map_err(|e| AppError::internal(format!("serialize passkey: {e}")))?;
        let cred_id_bytes = pk.cred_id().to_vec();
        // Match by credential ID in the JSON. Since credential_json contains the
        // full Passkey struct, we identify by parsing each row.
        // ponytail: O(n) scan is fine for single-digit passkey count
        if let Err(e) = update_credential_bycred_id(&state.pool, &cred_id_bytes, &cred_json).await {
            tracing::warn!("failed to update webauthn credential counter: {e}");
        }
    }

    // Generate a one-time passkey token
    let token = random_hex(32);
    let token_hash = hex_encode(&Sha256::digest(token.as_bytes()));
    let expires = now_millis() + PASSKEY_TOKEN_TTL_MS;

    {
        let mut map = PASSKEY_TOKENS.lock().unwrap();
        // Clean up expired tokens
        let now = now_millis();
        map.retain(|_, exp| *exp > now);
        map.insert(token_hash, expires);
    }

    Ok(Json(json!({
        "status": "ok",
        "passkey_token": token,
    })))
}

async fn update_credential_bycred_id(
    pool: &sqlx::SqlitePool,
    cred_id: &[u8],
    new_json: &str,
) -> Result<(), AppError> {
    // Reload all credentials and find the one matching this cred_id
    let rows: Vec<(i64, String)> =
        sqlx::query_as("SELECT id, credential_json FROM webauthn_credentials ORDER BY id")
            .fetch_all(pool)
            .await?;

    for (id, json_str) in &rows {
        if let Ok(pk) = serde_json::from_str::<Passkey>(json_str) {
            if pk.cred_id().to_vec() == cred_id {
                sqlx::query("UPDATE webauthn_credentials SET credential_json = ? WHERE id = ?")
                    .bind(new_json)
                    .bind(id)
                    .execute(pool)
                    .await?;
                return Ok(());
            }
        }
    }
    Ok(())
}

#[derive(serde::Deserialize)]
struct AuthCompleteRequest {
    challenge_id: String,
    credential: PublicKeyCredential,
}

// ---------------------------------------------------------------------------
// Passkey token verification (called from api.rs authorize_submit)
// ---------------------------------------------------------------------------

/// Verify and consume a one-time passkey token. Returns true if valid.
pub fn verify_passkey_token(token: &str) -> bool {
    let token_hash = hex_encode(&Sha256::digest(token.as_bytes()));
    let now = now_millis();
    let mut map = PASSKEY_TOKENS.lock().unwrap();
    if let Some(expires) = map.remove(&token_hash) {
        expires > now
    } else {
        false
    }
}

/// Check whether any passkeys are registered.
pub async fn passkeys_registered(pool: &sqlx::SqlitePool) -> bool {
    has_passkeys(pool).await.unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Helpers for password verification in registration
// ---------------------------------------------------------------------------

fn extract_password_from_body(body: &[u8]) -> Result<String, AppError> {
    let params: HashMap<String, String> = serde_urlencoded::from_bytes(body)
        .map_err(|e| AppError::bad_request(format!("invalid form data: {e}")))?;
    params
        .get("password")
        .cloned()
        .ok_or_else(|| AppError::bad_request("Missing password"))
}

async fn verify_admin_auth(state: &AppState, password: &str) -> Result<(), AppError> {
    let admin_row: Option<(String,)> =
        sqlx::query_as("SELECT password_hash FROM admin WHERE id = 1")
            .fetch_optional(&state.pool)
            .await?;

    let (password_hash,) =
        admin_row.ok_or_else(|| AppError::forbidden("Admin password not set"))?;

    crate::api::verify_password(password, &password_hash)
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/admin/webauthn/register", get(register_page))
        .route("/admin/webauthn/register/begin", post(register_begin))
        .route("/admin/webauthn/register/complete", post(register_complete))
        .route("/oauth/authorize/webauthn/begin", post(auth_begin))
        .route("/oauth/authorize/webauthn/complete", post(auth_complete))
}
