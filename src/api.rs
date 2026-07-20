use crate::error::AppError;
use crate::id::generate_id;
use crate::server::AppState;
use axum::extract::{FromRequestParts, Path, Query, State};
use axum::http::header::LOCATION;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use base64::Engine;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX_LUT: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX_LUT[(b >> 4) as usize] as char);
        s.push(HEX_LUT[(b & 0x0f) as usize] as char);
    }
    s
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>, AppError> {
    if s.len() % 2 != 0 {
        return Err(AppError::bad_request("Invalid hex string length"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| AppError::bad_request("Invalid hex character"))
        })
        .collect()
}

pub fn now_millis() -> i64 {
    // SystemTime::now() is always after UNIX_EPOCH on any supported platform
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

fn now_secs() -> i64 {
    // SystemTime::now() is always after UNIX_EPOCH on any supported platform
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn random_hex(len: usize) -> String {
    use rand::RngCore;
    let mut bytes = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex_encode(&bytes)
}

fn random_bytes_b64url(len: usize) -> String {
    use rand::RngCore;
    let mut bytes = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes)
}

// ponytail: login rate limiting delegated to reverse proxy (Caddy rate_limit,
// nginx limit_req_zone). In-memory HashMap didn't survive restarts and was
// trivially bypassed by rotating IPs.

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

pub fn millis_to_iso(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms)
        .unwrap_or_default()
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn millis_to_date(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms)
        .unwrap_or_default()
        .format("%Y-%m-%d")
        .to_string()
}

// ---------------------------------------------------------------------------
// Account serialization helper
// ---------------------------------------------------------------------------

pub struct AccountRow {
    pub id: i64,
    pub username: String,
    pub display_name: String,
    pub bio: String,
    pub bio_html: String,
    pub is_locked: bool,
    pub discoverable: bool,
    pub bot: bool,
    pub fields_json: String,
    pub created_at: i64,
    pub last_status_at: Option<i64>,
}

pub struct StatusRow {
    pub id: i64,
    pub persona_id: i64,
    pub ap_id: String,
    pub content_html: String,
    pub spoiler_text: String,
    pub visibility: String,
    pub sensitive: bool,
    pub language: Option<String>,
    pub created_at: i64,
    pub edited_at: Option<i64>,
}

pub fn account_to_json(row: &AccountRow, domain: &str) -> Value {
    account_to_json_with_counts(row, domain, 0, 0, 0)
}

pub fn account_to_json_with_counts(
    row: &AccountRow,
    domain: &str,
    followers_count: i64,
    following_count: i64,
    statuses_count: i64,
) -> Value {
    let fields: Vec<Value> = serde_json::from_str(&row.fields_json).unwrap_or_default();

    json!({
        "id": row.id.to_string(),
        "username": row.username,
        "acct": row.username,
        "display_name": row.display_name,
        "locked": row.is_locked,
        "bot": row.bot,
        "discoverable": row.discoverable,
        "created_at": millis_to_iso(row.created_at),
        "note": row.bio_html,
        "url": format!("https://{domain}/@{}", row.username),
        "uri": format!("https://{domain}/users/{}", row.username),
        "avatar": format!("https://{domain}/avatars/original/missing.png"),
        "avatar_static": format!("https://{domain}/avatars/original/missing.png"),
        "header": format!("https://{domain}/headers/original/missing.png"),
        "header_static": format!("https://{domain}/headers/original/missing.png"),
        "followers_count": followers_count,
        "following_count": following_count,
        "statuses_count": statuses_count,
        "last_status_at": row.last_status_at.map(millis_to_date),
        "emojis": [],
        "fields": fields,
    })
}

pub async fn fetch_account_counts(pool: &fieldwork::db::Pool, account_id: i64) -> (i64, i64, i64) {
    let fwp = pool;
    let followers = fieldwork::followers_db::follower_count(&fwp, account_id)
        .await
        .unwrap_or(0);

    let following = fieldwork::follows_db::following_count(&fwp, account_id)
        .await
        .unwrap_or(0);

    let statuses = fieldwork::posts_db::posts_count(&fwp, account_id)
        .await
        .unwrap_or(0);

    (followers, following, statuses)
}

pub async fn fetch_account_row(pool: &fieldwork::db::Pool, id: i64) -> Result<AccountRow, AppError> {
    let fwp = pool;
    let persona = fieldwork::persona_db::get_persona_by_id(&fwp, id).await?
        .ok_or_else(|| AppError::not_found("Account not found"))?;
    Ok(persona_to_account_row(&persona))
}

fn persona_to_account_row(p: &fieldwork::persona_db::PersonaRow) -> AccountRow {
    AccountRow {
        id: p.id,
        username: p.username.clone(),
        display_name: p.display_name.clone(),
        bio: p.bio.clone(),
        bio_html: p.bio_html.clone(),
        is_locked: p.is_locked,
        discoverable: p.discoverable,
        bot: p.bot,
        fields_json: p.fields_json.clone(),
        created_at: p.created_at,
        last_status_at: p.last_status_at,
    }
}

async fn fetch_account_row_by_username(
    pool: &fieldwork::db::Pool,
    username: &str,
) -> Result<AccountRow, AppError> {
    let fwp = pool;
    let persona = fieldwork::persona_db::get_persona_by_username(&fwp, username).await?
        .ok_or_else(|| AppError::not_found("Account not found"))?;
    Ok(persona_to_account_row(&persona))
}

async fn load_contact_account(pool: &fieldwork::db::Pool, domain: &str) -> Result<Value, AppError> {
    let fwp = pool;
    let personas = fieldwork::persona_db::list_personas(&fwp).await?;
    let row = personas.first().map(persona_to_account_row);
    match row {
        Some(r) => {
            let (f, fo, s) = fetch_account_counts(pool, r.id).await;
            Ok(account_to_json_with_counts(&r, domain, f, fo, s))
        }
        None => Ok(json!(null)),
    }
}

// ---------------------------------------------------------------------------
// Bearer auth extractor
// ---------------------------------------------------------------------------

pub struct AuthenticatedAccount {
    pub account_id: i64,
    pub username: String,
    pub scopes: String,
    pub token_hash: String,
}

impl AuthenticatedAccount {
    /// Check that the token's scopes include the required scope.
    /// A token with "read write" (full access) passes any check.
    pub fn require_scope(&self, scope: &str) -> Result<(), AppError> {
        if self.scopes.split(|c: char| c.is_whitespace() || c == ',').any(|s| s == scope) {
            Ok(())
        } else {
            Err(AppError::forbidden(format!(
                "This action requires the '{scope}' scope"
            )))
        }
    }
}

impl FromRequestParts<Arc<AppState>> for AuthenticatedAccount {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| AppError::unauthorized("Missing Authorization header"))?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or_else(|| AppError::unauthorized("Invalid Authorization header"))?;

        let token_hash = hex_encode(&Sha256::digest(token.as_bytes()));

        // ponytail: SQL equality on SHA-256 hash is acceptable — attacker would
        // need to brute-force the hash, not the token. Constant-time comparison
        // of the hash would require fetching all rows, which is worse.
        let row = fieldwork::oauth_db::verify_token(
            &state.pool, &token_hash,
        )
        .await
        .map_err(AppError::from)?;

        let (account_id, username, scopes) =
            row.ok_or_else(|| AppError::unauthorized("Invalid or revoked token"))?;

        let now = now_millis();
        let _ = fieldwork::oauth_db::touch_token(&state.pool, &token_hash, now).await;

        Ok(AuthenticatedAccount {
            account_id,
            username,
            scopes,
            token_hash,
        })
    }
}

// ---------------------------------------------------------------------------
// OAuth2: POST /api/v1/apps
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct CreateAppRequest {
    client_name: String,
    redirect_uris: String,
    #[serde(default)]
    scopes: Option<String>,
    #[serde(default)]
    website: Option<String>,
}

async fn create_app(
    State(state): State<Arc<AppState>>,
    request: axum::extract::Request,
) -> Result<Json<Value>, AppError> {
    let (parts, req_body) = request.into_parts();
    let content_type = parts
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let bytes = axum::body::to_bytes(req_body, 64 * 1024)
        .await
        .map_err(|_| AppError::bad_request("request body too large"))?;
    let body: CreateAppRequest = if content_type.contains("application/json") {
        serde_json::from_slice(&bytes)
            .map_err(|e| AppError::bad_request(format!("invalid JSON: {e}")))?
    } else {
        serde_urlencoded::from_bytes(&bytes)
            .map_err(|e| AppError::bad_request(format!("invalid form data: {e}")))?
    };
    let id = generate_id();
    let client_id = random_hex(16); // 32 hex chars
    let client_secret = random_hex(32); // 64 hex chars
    let scopes = body.scopes.as_deref().unwrap_or("read");
    let now = now_millis();

    fieldwork::oauth_db::create_app(
        &state.pool,
        &fieldwork::oauth_db::OAuthAppRow {
            id,
            client_id: client_id.clone(),
            client_secret: client_secret.clone(),
            name: body.client_name.clone(),
            website: body.website.clone(),
            redirect_uri: body.redirect_uris.clone(),
            scopes: scopes.to_string(),
            created_at: now,
        },
    ).await?;

    let vapid_key = crate::push::get_vapid_public_key(&state.pool).await;

    Ok(Json(json!({
        "id": id.to_string(),
        "name": body.client_name,
        "website": body.website,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": body.redirect_uris,
        "redirect_uris": [body.redirect_uris],
        "scopes": body.scopes.as_deref().unwrap_or("read").split_whitespace().collect::<Vec<_>>(),
        "vapid_key": vapid_key,
        "client_secret_expires_at": 0,
    })))
}

// ---------------------------------------------------------------------------
// OAuth2: GET /oauth/authorize — login form
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct AuthorizeQuery {
    #[serde(default)]
    response_type: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    redirect_uri: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

async fn authorize_form(
    State(state): State<Arc<AppState>>,
    Query(params): Query<AuthorizeQuery>,
) -> Result<Html<String>, AppError> {
    let fwp = state.pool.clone();
    let personas = fieldwork::persona_db::list_personas(&fwp).await?;
    let accounts: Vec<(i64, String, String)> = personas
        .iter()
        .map(|p| (p.id, p.username.clone(), p.display_name.clone()))
        .collect();

    let response_type = html_escape(params.response_type.as_deref().unwrap_or("code"));
    let client_id = html_escape(params.client_id.as_deref().unwrap_or(""));
    let redirect_uri = html_escape(
        params
            .redirect_uri
            .as_deref()
            .unwrap_or("urn:ietf:wg:oauth:2.0:oob"),
    );
    let scope = html_escape(params.scope.as_deref().unwrap_or("read"));

    let mut options = String::new();
    for (id, username, display_name) in &accounts {
        let escaped_display = html_escape(display_name);
        let escaped_user = html_escape(username);
        options.push_str(&format!(
            "<option value=\"{id}\">{escaped_display} (@{escaped_user})</option>\n"
        ));
    }

    let has_passkeys = crate::webauthn::passkeys_registered(&state.pool).await;

    let passkey_section = if has_passkeys {
        r#"
    <div style="margin: 1.5em 0; padding: 1em 0; border-top: 1px solid #ccc; border-bottom: 1px solid #ccc;">
      <button type="button" id="passkey-btn" style="background: #4a90d9; color: white; border: none; border-radius: 4px; font-size: 1em;">
        Sign in with Passkey
      </button>
      <div id="passkey-status" style="margin-top: 0.5em; font-size: 0.9em; color: #666;"></div>
    </div>
    <p style="text-align: center; color: #999; margin: 0.5em 0;">or use password</p>"#
    } else {
        ""
    };

    let passkey_js = if has_passkeys {
        r##"
  <script>
    document.getElementById('passkey-btn').addEventListener('click', async () => {
      const statusEl = document.getElementById('passkey-status');
      statusEl.textContent = 'Starting passkey authentication...';

      try {
        // Step 1: Get challenge from server
        const beginResp = await fetch('/oauth/authorize/webauthn/begin', {
          method: 'POST',
        });
        if (!beginResp.ok) {
          const err = await beginResp.json();
          statusEl.textContent = 'Error: ' + (err.error || 'Unknown error');
          return;
        }
        const beginData = await beginResp.json();

        // Step 2: Use browser WebAuthn API
        const publicKey = beginData.publicKey;
        publicKey.challenge = base64urlToBuffer(publicKey.challenge);
        if (publicKey.allowCredentials) {
          publicKey.allowCredentials = publicKey.allowCredentials.map(c => ({
            ...c,
            id: base64urlToBuffer(c.id),
          }));
        }

        const assertion = await navigator.credentials.get({ publicKey });

        // Step 3: Send assertion to server
        const authData = {
          challenge_id: beginData.challenge_id,
          credential: {
            id: assertion.id,
            rawId: bufferToBase64url(assertion.rawId),
            type: assertion.type,
            response: {
              authenticatorData: bufferToBase64url(assertion.response.authenticatorData),
              clientDataJSON: bufferToBase64url(assertion.response.clientDataJSON),
              signature: bufferToBase64url(assertion.response.signature),
              userHandle: assertion.response.userHandle ? bufferToBase64url(assertion.response.userHandle) : null,
            },
          },
        };

        const completeResp = await fetch('/oauth/authorize/webauthn/complete', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(authData),
        });
        if (!completeResp.ok) {
          const err = await completeResp.json();
          statusEl.textContent = 'Authentication failed: ' + (err.error || 'Unknown error');
          return;
        }
        const result = await completeResp.json();

        // Step 4: Submit the form with the passkey token
        const form = document.getElementById('authorize-form');
        document.getElementById('password').removeAttribute('required');
        document.getElementById('password').value = '';

        const tokenInput = document.createElement('input');
        tokenInput.type = 'hidden';
        tokenInput.name = 'passkey_token';
        tokenInput.value = result.passkey_token;
        form.appendChild(tokenInput);
        form.submit();

      } catch (e) {
        if (e.name === 'NotAllowedError') {
          statusEl.textContent = 'Authentication was cancelled or timed out.';
        } else {
          statusEl.textContent = 'Error: ' + e.message;
        }
      }
    });

    function base64urlToBuffer(b64url) {
      const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
      const pad = b64.length % 4 === 0 ? '' : '='.repeat(4 - (b64.length % 4));
      const binary = atob(b64 + pad);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      return bytes.buffer;
    }

    function bufferToBase64url(buffer) {
      const bytes = new Uint8Array(buffer);
      let binary = '';
      for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
      return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }
  </script>"##
    } else {
        ""
    };

    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Authorize - smallhold</title>
  <style>
    body {{ font-family: sans-serif; max-width: 400px; margin: 4em auto; padding: 0 1em; }}
    label {{ display: block; margin: 1em 0 0.3em; }}
    input, select, button {{ width: 100%; padding: 0.5em; box-sizing: border-box; }}
    button {{ margin-top: 1.5em; cursor: pointer; }}
  </style>
</head>
<body>
  <h1>Authorize</h1>
  <p>An application is requesting access to your account.</p>
  <form method="post" action="/oauth/authorize" id="authorize-form">
    <input type="hidden" name="response_type" value="{response_type}">
    <input type="hidden" name="client_id" value="{client_id}">
    <input type="hidden" name="redirect_uri" value="{redirect_uri}">
    <input type="hidden" name="scope" value="{scope}">
    {passkey_section}
    <label for="password">Admin Password</label>
    <input type="password" id="password" name="password">
    <label for="account_id">Persona</label>
    <select id="account_id" name="account_id">
      {options}
    </select>
    <button type="submit">Authorize</button>
  </form>
  {passkey_js}
</body>
</html>"#
    );

    Ok(Html(html))
}

// ---------------------------------------------------------------------------
// OAuth2: POST /oauth/authorize — process login
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[allow(dead_code)] // Fields are part of the OAuth protocol shape
struct AuthorizeForm {
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    passkey_token: Option<String>,
    account_id: i64,
    client_id: String,
    redirect_uri: String,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    response_type: Option<String>,
}

async fn authorize_submit(
    State(state): State<Arc<AppState>>,
    axum::Form(form): axum::Form<AuthorizeForm>,
) -> Result<Response, AppError> {
    // Authenticate via passkey token or admin password
    let passkey_ok = form
        .passkey_token
        .as_deref()
        .filter(|t| !t.is_empty())
        .map(crate::webauthn::verify_passkey_token)
        .unwrap_or(false);

    if !passkey_ok {
        let password = form
            .password
            .as_deref()
            .filter(|p| !p.is_empty())
            .ok_or_else(|| AppError::bad_request("Password or passkey required"))?;
        let password_hash = crate::db_extras::get_admin_password_hash(&state.pool)
                .await?
                .ok_or_else(|| AppError::forbidden("Admin password not set"))?;
        verify_password(password, &password_hash)?;
    }

    // Verify account exists
    let fwp_ae = state.pool.clone();
    let account_exists = fieldwork::persona_db::get_persona_by_id(&fwp_ae, form.account_id).await?;
    if account_exists.is_none() {
        return Err(AppError::bad_request("Account not found"));
    }

    // Verify app exists and redirect_uri matches registered URI
    let app_row: Option<(i64, String)> =
        {
            let fwp_oa = state.pool.clone();
            let app = fieldwork::oauth_db::get_app_by_client_id(&fwp_oa, &form.client_id).await?;
            app.map(|a| (a.id, a.redirect_uri))
        };
    let (app_id, registered_uri) =
        app_row.ok_or_else(|| AppError::bad_request("Unknown client_id"))?;

    if form.redirect_uri != registered_uri {
        return Err(AppError::bad_request(
            "redirect_uri does not match registered URI",
        ));
    }

    // Generate authorization code
    let code = random_bytes_b64url(32);
    let code_hash = hex_encode(&Sha256::digest(code.as_bytes()));
    let scope = form.scope.as_deref().unwrap_or("read");
    let now = now_millis();
    let expires_at = now + 600_000; // 10 minutes

    fieldwork::oauth_db::insert_authz_code(&state.pool, &code_hash, app_id, crate::db::DEFAULT_USER_ID, form.account_id, scope, &form.redirect_uri, now, expires_at).await?;

    // For OOB redirect, show the code directly
    if form.redirect_uri == "urn:ietf:wg:oauth:2.0:oob" {
        let html = format!(
            r#"<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Authorization Code</title>
<style>body {{ font-family: sans-serif; max-width: 400px; margin: 4em auto; }} code {{ font-size: 1.2em; word-break: break-all; }}</style>
</head>
<body>
<h1>Authorization Code</h1>
<p>Copy this code and paste it into your application:</p>
<p><code>{code}</code></p>
</body>
</html>"#
        );
        return Ok(Html(html).into_response());
    }

    // Redirect with code
    let separator = if form.redirect_uri.contains('?') {
        '&'
    } else {
        '?'
    };
    let location = format!("{}{separator}code={code}", form.redirect_uri);
    Ok((StatusCode::FOUND, [(LOCATION, location)]).into_response())
}

pub(crate) fn verify_password(password: &str, hash: &str) -> Result<(), AppError> {
    use argon2::{Argon2, PasswordHash, PasswordVerifier};
    let parsed_hash =
        PasswordHash::new(hash).map_err(|_| AppError::internal("Invalid password hash"))?;
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .map_err(|_| AppError::forbidden("Invalid password"))
}

// ---------------------------------------------------------------------------
// OAuth2: POST /oauth/token
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct TokenRequest {
    grant_type: String,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
    #[serde(default)]
    redirect_uri: Option<String>,
}

async fn token(
    State(state): State<Arc<AppState>>,
    axum::Form(form): axum::Form<TokenRequest>,
) -> Result<Json<Value>, AppError> {
    if form.grant_type != "authorization_code" {
        return Err(AppError::bad_request("Unsupported grant_type"));
    }

    let code = form
        .code
        .as_deref()
        .ok_or_else(|| AppError::bad_request("Missing code"))?;

    let code_hash = hex_encode(&Sha256::digest(code.as_bytes()));

    let now = now_millis();

    // Atomically fetch and consume the authorization code (single-use)
    let code_row: Option<(i64, i64, String, String)> = fieldwork::oauth_db::consume_authz_code(&state.pool, &code_hash, now).await?;

    let (app_id, account_id, scopes, stored_redirect) =
        code_row.ok_or_else(|| AppError::bad_request("Invalid or expired authorization code"))?;

    // Verify redirect_uri matches
    if let Some(ref uri) = form.redirect_uri {
        if *uri != stored_redirect {
            return Err(AppError::bad_request("redirect_uri mismatch"));
        }
    }

    // Verify client credentials if provided
    if let Some(ref cid) = form.client_id {
        let app_row: Option<(i64, String)> = crate::db_extras::get_oauth_app_secret(&state.pool, cid).await?;

        let (found_app_id, stored_secret) =
            app_row.ok_or_else(|| AppError::bad_request("Unknown client_id"))?;

        if found_app_id != app_id {
            return Err(AppError::bad_request(
                "client_id does not match authorization code",
            ));
        }

        let cs = form
            .client_secret
            .as_ref()
            .ok_or_else(|| AppError::bad_request("Missing client_secret"))?;
        {
            use subtle::ConstantTimeEq;
            if cs.as_bytes().ct_eq(stored_secret.as_bytes()).unwrap_u8() != 1 {
                return Err(AppError::unauthorized("Invalid client_secret"));
            }
        }
    }

    // Generate access token
    let access_token = random_bytes_b64url(64);
    let token_hash = hex_encode(&Sha256::digest(access_token.as_bytes()));
    let id = generate_id();

    fieldwork::oauth_db::create_token(
        &state.pool,
        id, &token_hash, app_id, crate::db::DEFAULT_USER_ID, account_id, &scopes, now,
    ).await?;

    Ok(Json(json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "scope": scopes,
        "created_at": now_secs(),
    })))
}

// ---------------------------------------------------------------------------
// OAuth2: POST /oauth/revoke
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[allow(dead_code)] // Fields are part of the OAuth protocol shape
struct RevokeRequest {
    token: String,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
}

async fn revoke(
    State(state): State<Arc<AppState>>,
    axum::Form(form): axum::Form<RevokeRequest>,
) -> Result<StatusCode, AppError> {
    let token_hash = hex_encode(&Sha256::digest(form.token.as_bytes()));

    // Look up token ID by hash to use revoke_token API.
    let token_id = crate::db_extras::find_token_id_by_hash(&state.pool, &token_hash).await?;

    if let Some(token_id) = token_id {
        let now = now_millis();
        fieldwork::oauth_db::revoke_token(
            &state.pool, token_id, now,
        ).await?;
    }

    // Always return 200 per RFC 7009, even if token not found
    Ok(StatusCode::OK)
}

// ---------------------------------------------------------------------------
// Instance metadata: GET /api/v1/instance
// ---------------------------------------------------------------------------

async fn instance_v1(State(state): State<Arc<AppState>>) -> Result<Json<Value>, AppError> {
    let domain = &state.config.server.domain;

    let status_count = crate::db_extras::total_post_count(&state.pool).await?;
    let domain_count = crate::db_extras::remote_domain_count(&state.pool).await?;

    // ponytail: one DB query per instance call; VAPID key is immutable, could be cached in AppState
    let vapid_key = crate::push::get_vapid_public_key(&state.pool).await;

    let contact_account = load_contact_account(&state.pool, domain).await?;

    Ok(Json(json!({
        "uri": domain,
        "title": "smallhold",
        "description": "A personal fediverse instance",
        "short_description": "A personal fediverse instance",
        "email": "",
        "version": "4.2.0 (compatible; smallhold 0.1.0)",
        "urls": { "streaming_api": format!("wss://{domain}") },
        "stats": {
            "user_count": 1,
            "status_count": status_count,
            "domain_count": domain_count,
        },
        "thumbnail": null,
        "languages": ["en"],
        "registrations": false,
        "approval_required": false,
        "invites_enabled": false,
        "configuration": {
            "statuses": {
                "max_characters": state.config.limits.max_post_chars,
                "max_media_attachments": state.config.limits.max_attachments,
            },
            "media_attachments": {
                "supported_mime_types": ["image/jpeg", "image/png", "image/gif", "image/webp"],
                "image_size_limit": 41943040,
                "image_matrix_limit": 33177600,
            },
            "polls": { "max_options": 0 },
        },
        "contact_account": contact_account,
        "rules": [],
        "vapid_key": vapid_key,
    })))
}

// ---------------------------------------------------------------------------
// Instance metadata: GET /api/v2/instance
// ---------------------------------------------------------------------------

async fn instance_v2(State(state): State<Arc<AppState>>) -> Result<Json<Value>, AppError> {
    let domain = &state.config.server.domain;

    let status_count = crate::db_extras::total_post_count(&state.pool).await?;

    // ponytail: one DB query per instance call; VAPID key is immutable, could be cached in AppState
    let vapid_key = crate::push::get_vapid_public_key(&state.pool).await;

    let contact_v2: Value = {
        let account = load_contact_account(&state.pool, domain).await?;
        json!({ "email": "", "account": account })
    };

    Ok(Json(json!({
        "domain": domain,
        "title": "smallhold",
        "version": "4.2.0 (compatible; smallhold 0.1.0)",
        "source_url": "https://github.com/smallhold",
        "description": "A personal fediverse instance",
        "usage": {
            "users": { "active_month": 1 },
            "local_posts": status_count,
        },
        "thumbnail": {
            "url": "",
            "blurhash": null,
            "versions": {},
        },
        "languages": ["en"],
        "configuration": {
            "urls": { "streaming": format!("wss://{domain}") },
            "vapid": {
                "public_key": vapid_key,
            },
            "accounts": { "max_featured_tags": 0 },
            "statuses": {
                "max_characters": state.config.limits.max_post_chars,
                "max_media_attachments": state.config.limits.max_attachments,
                "characters_reserved_per_url": 23,
            },
            "media_attachments": {
                "supported_mime_types": ["image/jpeg", "image/png", "image/gif", "image/webp"],
                "image_size_limit": 41943040,
                "image_matrix_limit": 33177600,
                "video_size_limit": 0,
                "video_frame_rate_limit": 0,
                "video_matrix_limit": 0,
            },
            "polls": {
                "max_options": 0,
                "max_characters_per_option": 0,
                "min_expiration": 300,
                "max_expiration": 2629746,
            },
            "translation": { "enabled": false },
        },
        "registrations": {
            "enabled": false,
            "approval_required": false,
            "message": null,
        },
        "contact": contact_v2,
        "rules": [],
    })))
}

// ---------------------------------------------------------------------------
// Account endpoints
// ---------------------------------------------------------------------------

/// GET /api/v1/accounts/verify_credentials
async fn verify_credentials(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
) -> Result<Json<Value>, AppError> {
    let domain = &state.config.server.domain;
    let row = fetch_account_row(&state.pool, auth.account_id).await?;
    let (followers, following, statuses) = fetch_account_counts(&state.pool, auth.account_id).await;
    let mut v = account_to_json_with_counts(&row, domain, followers, following, statuses);
    let fields: Vec<Value> = serde_json::from_str(&row.fields_json).unwrap_or_default();
    v["source"] = json!({
        "privacy": "public",
        "sensitive": false,
        "language": "en",
        "note": row.bio,
        "fields": fields,
        "follow_requests_count": 0
    });
    Ok(Json(v))
}

/// GET /api/v1/accounts/{id}
async fn get_account(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let domain = &state.config.server.domain;
    let id: i64 = id.parse().map_err(|_| AppError::not_found("Account not found"))?;
    let row = fetch_account_row(&state.pool, id).await?;
    let (followers, following, statuses) = fetch_account_counts(&state.pool, id).await;
    Ok(Json(account_to_json_with_counts(
        &row, domain, followers, following, statuses,
    )))
}

/// GET /api/v1/accounts/lookup?acct=username
async fn account_lookup(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, AppError> {
    let acct = params
        .get("acct")
        .ok_or_else(|| AppError::bad_request("Missing acct parameter"))?;

    // Strip @domain suffix if present and it matches our domain
    let username = match acct.split_once('@') {
        Some((user, domain)) if domain == state.config.server.domain => user,
        Some(_) => return Err(AppError::not_found("Remote account lookup not supported")),
        None => acct.as_str(),
    };

    let domain = &state.config.server.domain;
    let row = fetch_account_row_by_username(&state.pool, username).await?;
    let (followers, following, statuses) = fetch_account_counts(&state.pool, row.id).await;
    Ok(Json(account_to_json_with_counts(
        &row, domain, followers, following, statuses,
    )))
}

/// GET /api/v1/accounts/{id}/statuses
async fn account_statuses(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Response, AppError> {
    let account_id: i64 = id.parse().map_err(|_| AppError::not_found("Account not found"))?;

    // Verify account exists
    let _row = fetch_account_row(&state.pool, account_id).await?;

    let limit: i64 = params
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(20)
        .min(40);

    let domain = &state.config.server.domain;

    // Build query with pagination
    let statuses: Vec<StatusRow> = if let Some(max_id) =
        params.get("max_id").and_then(|v| v.parse::<i64>().ok())
    {
        crate::db_extras::account_statuses_max_id(&state.pool, account_id, max_id, limit).await?
    } else if let Some(min_id) = params.get("min_id").and_then(|v| v.parse::<i64>().ok()) {
        crate::db_extras::account_statuses_min_id(&state.pool, account_id, min_id, limit).await?
    } else {
        crate::db_extras::account_statuses_default(&state.pool, account_id, limit).await?
    };

    let account_row = fetch_account_row(&state.pool, account_id).await?;
    let account_json = account_to_json(&account_row, domain);

    let items: Vec<Value> = statuses
        .iter()
        .map(|s| {
            json!({
                "id": s.id.to_string(),
                "created_at": millis_to_iso(s.created_at),
                "in_reply_to_id": null,
                "in_reply_to_account_id": null,
                "sensitive": s.sensitive,
                "spoiler_text": &s.spoiler_text,
                "visibility": &s.visibility,
                "language": &s.language,
                "uri": &s.ap_id,
                "url": &s.ap_id,
                "replies_count": 0,
                "reblogs_count": 0,
                "favourites_count": 0,
                "edited_at": s.edited_at.map(millis_to_iso),
                "content": &s.content_html,
                "reblog": null,
                "application": null,
                "account": account_json.clone(),
                "media_attachments": [],
                "mentions": [],
                "tags": [],
                "emojis": [],
                "card": null,
                "poll": null,
                "favourited": false,
                "reblogged": false,
                "muted": false,
                "bookmarked": false,
                "pinned": false,
                "filtered": [],
            })
        })
        .collect();

    // Build Link header for pagination
    let mut link_parts: Vec<String> = Vec::new();
    if let Some(first) = statuses.first() {
        link_parts.push(format!(
            "<https://{domain}/api/v1/accounts/{account_id}/statuses?min_id={}>; rel=\"prev\"",
            first.id
        ));
    }
    if let Some(last) = statuses.last() {
        link_parts.push(format!(
            "<https://{domain}/api/v1/accounts/{account_id}/statuses?max_id={}>; rel=\"next\"",
            last.id
        ));
    }

    let body = serde_json::to_string(&items).map_err(|e| AppError::internal(e.to_string()))?;

    let mut builder = Response::builder().header("Content-Type", "application/json; charset=utf-8");

    if !link_parts.is_empty() {
        builder = builder.header("Link", link_parts.join(", "));
    }

    Ok(builder.body(body.into()).unwrap())
}

/// GET /api/v1/accounts/relationships?id[]=...
async fn relationships(
    State(_state): State<Arc<AppState>>,
    _auth: AuthenticatedAccount,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, AppError> {
    // Parse id[] parameters. axum's HashMap won't natively handle id[], so we check
    // both "id[]" and "id" keys. For a single-persona server, all relationships
    // are essentially false.
    let mut ids: Vec<String> = Vec::new();

    if let Some(id) = params.get("id[]") {
        ids.push(id.clone());
    }
    if let Some(id) = params.get("id") {
        ids.push(id.clone());
    }

    let results: Vec<Value> = ids
        .into_iter()
        .map(|id| {
            json!({
                "id": id,
                "following": false,
                "showing_reblogs": true,
                "notifying": false,
                "followed_by": false,
                "blocking": false,
                "blocked_by": false,
                "muting": false,
                "muting_notifications": false,
                "requested": false,
                "requested_by": false,
                "domain_blocking": false,
                "endorsed": false,
                "note": "",
            })
        })
        .collect();

    Ok(Json(json!(results)))
}

// ---------------------------------------------------------------------------
// Stub endpoints
// ---------------------------------------------------------------------------

async fn empty_array() -> Json<Value> {
    Json(json!([]))
}

async fn empty_array_authed(
    State(_state): State<Arc<AppState>>,
    _auth: AuthenticatedAccount,
) -> Json<Value> {
    Json(json!([]))
}

async fn preferences() -> Json<Value> {
    Json(json!({
        "posting:default:visibility": "public",
        "posting:default:sensitive": false,
        "posting:default:language": "en",
        "reading:expand:media": "default",
        "reading:expand:spoilers": false,
    }))
}

async fn get_markers() -> Json<Value> {
    Json(json!({}))
}

async fn post_markers() -> Json<Value> {
    Json(json!({}))
}

/// GET /api/v1/apps/verify_credentials
async fn verify_app_credentials(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
) -> Result<Json<Value>, AppError> {
    // Look up the app via the most recently used token for this account.
    // ponytail: single-user server, so most-recent-token heuristic is fine.
    let app_row: Option<(String, Option<String>)> = crate::db_extras::get_app_for_account(&state.pool, auth.account_id).await?;

    let vapid_key = crate::push::get_vapid_public_key(&state.pool).await;

    match app_row {
        Some((name, website)) => Ok(Json(json!({
            "name": name,
            "website": website,
            "vapid_key": vapid_key,
        }))),
        None => Ok(Json(json!({
            "name": "unknown",
            "website": null,
            "vapid_key": vapid_key,
        }))),
    }
}

// ---------------------------------------------------------------------------
// Lists
// ---------------------------------------------------------------------------

fn list_to_json(id: i64, title: &str, replies_policy: &str) -> Value {
    json!({
        "id": id.to_string(),
        "title": title,
        "replies_policy": replies_policy,
        "exclusive": false,
    })
}

/// GET /api/v1/lists
async fn get_lists(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
) -> Result<Json<Value>, AppError> {
    let fwp_l = state.pool.clone();
    let list_rows = fieldwork::lists_db::get_lists(&fwp_l, auth.account_id).await?;
    let rows: Vec<(i64, String, String)> = list_rows.iter().map(|l| (l.id, l.title.clone(), l.replies_policy.clone())).collect();

    let lists: Vec<Value> = rows
        .iter()
        .map(|(id, title, rp)| list_to_json(*id, title, rp))
        .collect();

    Ok(Json(json!(lists)))
}

#[derive(Deserialize)]
struct CreateListRequest {
    title: String,
    #[serde(default = "default_replies_policy")]
    replies_policy: String,
}

fn default_replies_policy() -> String {
    "list".to_string()
}

/// POST /api/v1/lists
async fn create_list(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Json(body): Json<CreateListRequest>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let valid_policies = ["followed", "list", "none"];
    if !valid_policies.contains(&body.replies_policy.as_str()) {
        return Err(AppError::unprocessable("Invalid replies_policy"));
    }

    let id = generate_id();
    let now = now_millis();

    crate::db_extras::create_list(&state.pool, id, auth.account_id, &body.title, &body.replies_policy, now).await?;

    Ok((
        StatusCode::OK,
        Json(list_to_json(id, &body.title, &body.replies_policy)),
    ))
}

/// GET /api/v1/lists/:id
async fn get_list(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let list_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("List not found"))?;

    let list = fieldwork::lists_db::get_list(
        &state.pool, list_id,
    ).await?;
    let row: Option<(i64, String, String)> = list
        .filter(|l| l.user_id == auth.account_id)
        .map(|l| (l.id, l.title, l.replies_policy));

    let (id, title, rp) = row.ok_or_else(|| AppError::not_found("List not found"))?;
    Ok(Json(list_to_json(id, &title, &rp)))
}

#[derive(Deserialize)]
struct UpdateListRequest {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    replies_policy: Option<String>,
}

/// PUT /api/v1/lists/:id
async fn update_list(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(id): Path<String>,
    Json(body): Json<UpdateListRequest>,
) -> Result<Json<Value>, AppError> {
    let list_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("List not found"))?;

    let list = fieldwork::lists_db::get_list(
        &state.pool, list_id,
    ).await?;
    let row: Option<(i64, String, String)> = list
        .filter(|l| l.user_id == auth.account_id)
        .map(|l| (l.id, l.title, l.replies_policy));

    let (_, mut title, mut rp) = row.ok_or_else(|| AppError::not_found("List not found"))?;

    if let Some(ref new_title) = body.title {
        title = new_title.clone();
    }
    if let Some(ref new_rp) = body.replies_policy {
        let valid_policies = ["followed", "list", "none"];
        if !valid_policies.contains(&new_rp.as_str()) {
            return Err(AppError::unprocessable("Invalid replies_policy"));
        }
        rp = new_rp.clone();
    }

    crate::db_extras::update_list(&state.pool, list_id, &title, &rp).await?;

    Ok(Json(list_to_json(list_id, &title, &rp)))
}

/// DELETE /api/v1/lists/:id
async fn delete_list(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let list_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("List not found"))?;

    let del_list = fieldwork::lists_db::get_list(
        &state.pool, list_id,
    ).await?;
    if del_list.as_ref().map(|l| l.user_id) != Some(auth.account_id) {
        return Err(AppError::not_found("List not found"));
    }
    fieldwork::lists_db::delete_list(
        &state.pool, list_id,
    ).await?;

    Ok(StatusCode::OK)
}

/// GET /api/v1/lists/:id/accounts
async fn get_list_accounts(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let list_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("List not found"))?;

    let exists: Option<(i64,)> =
        {
            let fwp_lv = state.pool.clone();
            let l = fieldwork::lists_db::get_list(&fwp_lv, list_id).await?;
            l.filter(|l| l.user_id == auth.account_id).map(|l| (l.id,))
        };

    if exists.is_none() {
        return Err(AppError::not_found("List not found"));
    }

    let domain = &state.config.server.domain;
    let account_rows: Vec<AccountRow> = crate::db_extras::get_list_account_rows(&state.pool, list_id).await?;

    let accounts: Vec<Value> = account_rows
        .iter()
        .map(|row| account_to_json(row, domain))
        .collect();

    Ok(Json(json!(accounts)))
}

#[derive(Deserialize)]
struct ListAccountsRequest {
    account_ids: Vec<String>,
}

/// POST /api/v1/lists/:id/accounts
async fn add_list_accounts(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(id): Path<String>,
    Json(body): Json<ListAccountsRequest>,
) -> Result<StatusCode, AppError> {
    let list_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("List not found"))?;

    let exists: Option<(i64,)> =
        {
            let fwp_lv = state.pool.clone();
            let l = fieldwork::lists_db::get_list(&fwp_lv, list_id).await?;
            l.filter(|l| l.user_id == auth.account_id).map(|l| (l.id,))
        };

    if exists.is_none() {
        return Err(AppError::not_found("List not found"));
    }

    for aid_str in &body.account_ids {
        let aid: i64 = aid_str.parse().map_err(|_| AppError::bad_request("Invalid account ID"))?;
        fieldwork::lists_db::add_to_list(
            &state.pool, list_id, Some(aid), None,
        ).await?;
    }

    Ok(StatusCode::OK)
}

/// DELETE /api/v1/lists/:id/accounts
async fn remove_list_accounts(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(id): Path<String>,
    Json(body): Json<ListAccountsRequest>,
) -> Result<StatusCode, AppError> {
    let list_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("List not found"))?;

    let exists: Option<(i64,)> =
        {
            let fwp_lv = state.pool.clone();
            let l = fieldwork::lists_db::get_list(&fwp_lv, list_id).await?;
            l.filter(|l| l.user_id == auth.account_id).map(|l| (l.id,))
        };

    if exists.is_none() {
        return Err(AppError::not_found("List not found"));
    }

    for aid_str in &body.account_ids {
        let aid: i64 = aid_str.parse().map_err(|_| AppError::bad_request("Invalid account ID"))?;
        fieldwork::lists_db::remove_from_list(
            &state.pool, list_id, Some(aid), None,
        ).await?;
    }

    Ok(StatusCode::OK)
}

// ---------------------------------------------------------------------------
// v2 Filters
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct CreateFilterRequest {
    title: String,
    #[serde(default)]
    context: Vec<String>,
    #[serde(default = "default_filter_action")]
    filter_action: String,
    #[serde(default)]
    expires_in: Option<i64>,
    #[serde(default)]
    keywords_attributes: Vec<KeywordAttribute>,
}

#[derive(Deserialize)]
struct UpdateFilterRequest {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    context: Option<Vec<String>>,
    #[serde(default)]
    filter_action: Option<String>,
    #[serde(default)]
    expires_in: Option<i64>,
    #[serde(default)]
    keywords_attributes: Option<Vec<KeywordAttribute>>,
}

#[derive(Deserialize)]
struct KeywordAttribute {
    keyword: String,
    #[serde(default = "default_true")]
    whole_word: bool,
}

#[derive(Deserialize)]
struct AddKeywordRequest {
    keyword: String,
    #[serde(default = "default_true")]
    whole_word: bool,
}

fn default_filter_action() -> String {
    "warn".to_string()
}

fn default_true() -> bool {
    true
}

/// Build a v2 Filter JSON object with nested keywords.
async fn filter_to_json(pool: &fieldwork::db::Pool, filter_id: i64) -> Result<Value, AppError> {
    let row: (i64, String, String, String, Option<i64>, i64) = crate::db_extras::get_filter_row(pool, filter_id).await?;
    let keywords: Vec<(i64, String, bool)> = crate::db_extras::get_filter_keywords(pool, filter_id).await?;

    let context: Vec<String> = serde_json::from_str(&row.2).unwrap_or_default();
    let keyword_vals: Vec<Value> = keywords
        .iter()
        .map(|(id, kw, ww)| {
            json!({
                "id": id.to_string(),
                "keyword": kw,
                "whole_word": ww,
            })
        })
        .collect();

    Ok(json!({
        "id": row.0.to_string(),
        "title": row.1,
        "context": context,
        "expires_at": row.4.map(millis_to_iso),
        "filter_action": row.3,
        "keywords": keyword_vals,
        "statuses": [],
    }))
}

/// GET /api/v2/filters
async fn list_filters_v2(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
) -> Result<Json<Value>, AppError> {
    let filter_ids: Vec<(i64,)> =
        {
            let fwp_fl = state.pool.clone();
            let filters = fieldwork::filters_db::get_filters(&fwp_fl, auth.account_id).await?;
            filters.into_iter().map(|f| (f.id,)).collect::<Vec<_>>()
        };

    let mut results = Vec::with_capacity(filter_ids.len());
    for (fid,) in &filter_ids {
        results.push(filter_to_json(&state.pool, *fid).await?);
    }
    Ok(Json(json!(results)))
}

/// POST /api/v2/filters
async fn create_filter_v2(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Json(body): Json<CreateFilterRequest>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    let id = generate_id();
    let now = now_millis();
    let context_json =
        serde_json::to_string(&body.context).map_err(|e| AppError::internal(e.to_string()))?;
    let expires_at = body.expires_in.map(|secs| now + secs * 1000);

    crate::db_extras::create_filter(&state.pool, id, auth.account_id, &body.title, &context_json, &body.filter_action, expires_at, now).await?;

    for kw in &body.keywords_attributes {
        let kw_id = generate_id();
        crate::db_extras::insert_filter_keyword(&state.pool, kw_id, id, &kw.keyword, kw.whole_word).await?;
    }

    let result = filter_to_json(&state.pool, id).await?;
    Ok((StatusCode::OK, Json(result)))
}

/// GET /api/v2/filters/:id
async fn get_filter_v2(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let filter_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("Filter not found"))?;

    let exists: Option<(i64,)> =
        {
            let fwp_fc = state.pool.clone();
            let f = fieldwork::filters_db::get_filter(&fwp_fc, filter_id).await?;
            f.filter(|f| f.user_id == auth.account_id).map(|f| (f.id,))
        };
    if exists.is_none() {
        return Err(AppError::not_found("Filter not found"));
    }

    Ok(Json(filter_to_json(&state.pool, filter_id).await?))
}

/// PUT /api/v2/filters/:id
async fn update_filter_v2(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(id): Path<String>,
    Json(body): Json<UpdateFilterRequest>,
) -> Result<Json<Value>, AppError> {
    let filter_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("Filter not found"))?;

    let row: Option<(i64, String, String, String, Option<i64>)> = crate::db_extras::get_filter_for_update(&state.pool, filter_id, auth.account_id).await?;
    let (_fid, cur_title, cur_context, cur_action, cur_expires) =
        row.ok_or_else(|| AppError::not_found("Filter not found"))?;

    let title = body.title.as_deref().unwrap_or(&cur_title);
    let filter_action = body.filter_action.as_deref().unwrap_or(&cur_action);
    let context_json = match &body.context {
        Some(ctx) => serde_json::to_string(ctx).map_err(|e| AppError::internal(e.to_string()))?,
        None => cur_context,
    };
    let now = now_millis();
    let expires_at = match body.expires_in {
        Some(secs) => Some(now + secs * 1000),
        None => cur_expires,
    };

    crate::db_extras::update_filter(&state.pool, filter_id, title, &context_json, filter_action, expires_at).await?;

    if let Some(kw_attrs) = &body.keywords_attributes {
        // Delete all existing keywords before re-adding
        let existing_kws = fieldwork::filters_db::get_keywords(
            &state.pool, filter_id,
        ).await?;
        for kw in &existing_kws {
            fieldwork::filters_db::delete_keyword(
                &state.pool, kw.id,
            ).await?;
        }
        for kw in kw_attrs {
            let kw_id = generate_id();
            crate::db_extras::insert_filter_keyword(&state.pool, kw_id, filter_id, &kw.keyword, kw.whole_word).await?;
        }
    }

    Ok(Json(filter_to_json(&state.pool, filter_id).await?))
}

/// DELETE /api/v2/filters/:id
async fn delete_filter_v2(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let filter_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("Filter not found"))?;

    let del_filter = fieldwork::filters_db::get_filter(
        &state.pool, filter_id,
    ).await?;
    if del_filter.as_ref().map(|f| f.user_id) != Some(auth.account_id) {
        return Err(AppError::not_found("Filter not found"));
    }
    fieldwork::filters_db::delete_filter(
        &state.pool, filter_id,
    ).await?;
    let _rows_affected = if del_filter.is_some() { 1u64 } else { 0u64 };
    Ok(StatusCode::OK)
}

/// GET /api/v2/filters/:id/keywords
async fn list_filter_keywords(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let filter_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("Filter not found"))?;

    let exists: Option<(i64,)> =
        {
            let fwp_fc = state.pool.clone();
            let f = fieldwork::filters_db::get_filter(&fwp_fc, filter_id).await?;
            f.filter(|f| f.user_id == auth.account_id).map(|f| (f.id,))
        };
    if exists.is_none() {
        return Err(AppError::not_found("Filter not found"));
    }

    let keywords: Vec<(i64, String, bool)> = crate::db_extras::get_filter_keywords(&state.pool, filter_id).await?;

    let vals: Vec<Value> = keywords
        .iter()
        .map(|(kid, kw, ww)| {
            json!({
                "id": kid.to_string(),
                "keyword": kw,
                "whole_word": ww,
            })
        })
        .collect();
    Ok(Json(json!(vals)))
}

/// POST /api/v2/filters/:id/keywords
async fn add_filter_keyword(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(id): Path<String>,
    Json(body): Json<AddKeywordRequest>,
) -> Result<Json<Value>, AppError> {
    let filter_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("Filter not found"))?;

    let exists: Option<(i64,)> =
        {
            let fwp_fc = state.pool.clone();
            let f = fieldwork::filters_db::get_filter(&fwp_fc, filter_id).await?;
            f.filter(|f| f.user_id == auth.account_id).map(|f| (f.id,))
        };
    if exists.is_none() {
        return Err(AppError::not_found("Filter not found"));
    }

    let kw_id = generate_id();
    crate::db_extras::insert_filter_keyword(&state.pool, kw_id, filter_id, &body.keyword, body.whole_word).await?;

    Ok(Json(json!({
        "id": kw_id.to_string(),
        "keyword": body.keyword,
        "whole_word": body.whole_word,
    })))
}

/// DELETE /api/v2/filters/keywords/:id
async fn delete_filter_keyword(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let keyword_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("Keyword not found"))?;

    let result = crate::db_extras::delete_filter_keyword_owned(&state.pool, keyword_id, auth.account_id).await?;

    if result == 0 {
        return Err(AppError::not_found("Keyword not found"));
    }
    Ok(StatusCode::OK)
}

/// GET /api/v1/filters — v1 compat: flat list, one entry per keyword
async fn list_filters_v1(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
) -> Result<Json<Value>, AppError> {
    let rows: Vec<(i64, String, String, bool, Option<i64>)> = crate::db_extras::list_filters_v1(&state.pool, auth.account_id).await?;

    let results: Vec<Value> = rows
        .iter()
        .map(|(id, phrase, context_str, whole_word, expires_at)| {
            let context: Vec<String> = serde_json::from_str(context_str).unwrap_or_default();
            json!({
                "id": id.to_string(),
                "phrase": phrase,
                "context": context,
                "whole_word": whole_word,
                "expires_at": expires_at.map(millis_to_iso),
                "irreversible": false,
            })
        })
        .collect();
    Ok(Json(json!(results)))
}

// ---------------------------------------------------------------------------
// OAuth sessions
// ---------------------------------------------------------------------------

/// GET /api/v1/oauth/sessions
async fn list_sessions(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
) -> Result<Json<Value>, AppError> {
    let rows: Vec<(i64, String, String, i64, Option<i64>)> = crate::db_extras::list_sessions(&state.pool, auth.account_id).await?;

    let sessions: Vec<Value> = rows
        .iter()
        .map(|(id, app_name, scopes, created_at, last_used_at)| {
            json!({
                "id": id.to_string(),
                "app_name": app_name,
                "scopes": scopes,
                "created_at": millis_to_iso(*created_at),
                "last_used_at": last_used_at.map(millis_to_iso),
            })
        })
        .collect();

    Ok(Json(json!(sessions)))
}

/// DELETE /api/v1/oauth/sessions/:id
async fn revoke_session(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    let token_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("Session not found"))?;

    let now = now_millis();
    let result = crate::db_extras::revoke_session(&state.pool, token_id, auth.account_id, now).await?;

    if result == 0 {
        return Err(AppError::not_found("Session not found"));
    }

    Ok(StatusCode::OK)
}

/// DELETE /api/v1/oauth/sessions — revoke all sessions except the current one
async fn revoke_all_sessions(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
) -> Result<Json<Value>, AppError> {
    let now = now_millis();
    let result = crate::db_extras::revoke_all_sessions(&state.pool, auth.account_id, &auth.token_hash, now).await?;

    Ok(Json(json!({ "revoked": result })))
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        // OAuth
        .route("/api/v1/apps", post(create_app))
        .route(
            "/oauth/authorize",
            get(authorize_form).post(authorize_submit),
        )
        .route("/oauth/token", post(token))
        .route("/oauth/revoke", post(revoke))
        // OAuth sessions
        .route(
            "/api/v1/oauth/sessions",
            get(list_sessions).delete(revoke_all_sessions),
        )
        .route("/api/v1/oauth/sessions/{id}", delete(revoke_session))
        // Instance
        .route("/api/v1/instance", get(instance_v1))
        .route("/api/v2/instance", get(instance_v2))
        // Accounts
        .route(
            "/api/v1/accounts/verify_credentials",
            get(verify_credentials),
        )
        .route("/api/v1/accounts/lookup", get(account_lookup))
        .route("/api/v1/accounts/relationships", get(relationships))
        .route("/api/v1/accounts/{id}", get(get_account))
        .route("/api/v1/accounts/{id}/statuses", get(account_statuses))
        // Filters
        .route("/api/v1/filters", get(list_filters_v1))
        .route(
            "/api/v2/filters",
            get(list_filters_v2).post(create_filter_v2),
        )
        .route(
            "/api/v2/filters/{id}",
            get(get_filter_v2)
                .put(update_filter_v2)
                .delete(delete_filter_v2),
        )
        .route(
            "/api/v2/filters/{id}/keywords",
            get(list_filter_keywords).post(add_filter_keyword),
        )
        .route(
            "/api/v2/filters/keywords/{id}",
            delete(delete_filter_keyword),
        )
        // Lists
        .route("/api/v1/lists", get(get_lists).post(create_list))
        .route(
            "/api/v1/lists/{id}",
            get(get_list).put(update_list).delete(delete_list),
        )
        .route(
            "/api/v1/lists/{id}/accounts",
            get(get_list_accounts)
                .post(add_list_accounts)
                .delete(remove_list_accounts),
        )
        // Stubs
        .route("/api/v1/custom_emojis", get(empty_array))
        .route("/api/v1/suggestions", get(empty_array))
        .route("/api/v1/trends/tags", get(empty_array))
        .route("/api/v1/trends/statuses", get(empty_array))
        .route("/api/v1/trends/links", get(empty_array))
        .route("/api/v1/announcements", get(empty_array))
        .route("/api/v1/mutes", get(empty_array))
        .route("/api/v1/blocks", get(empty_array))
        .route("/api/v1/domain_blocks", get(empty_array_authed))
        .route("/api/v1/bookmarks", get(empty_array))
        .route("/api/v1/favourites", get(empty_array))
        // conversations moved to posting.rs
        .route("/api/v1/featured_tags", get(empty_array))
        .route("/api/v1/endorsements", get(empty_array))
        .route("/api/v1/instance/rules", get(empty_array))
        .route("/api/v1/instance/peers", get(empty_array))
        .route("/api/v1/instance/activity", get(empty_array))
        .route("/api/v1/preferences", get(preferences))
        .route("/api/v1/markers", get(get_markers).post(post_markers))
        .route(
            "/api/v1/apps/verify_credentials",
            get(verify_app_credentials),
        )
}
