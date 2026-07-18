use crate::error::AppError;
use crate::id::generate_id;
use crate::server::AppState;
use axum::extract::{FromRequestParts, Path, Query, State};
use axum::http::header::LOCATION;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
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
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

fn now_secs() -> i64 {
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

#[derive(sqlx::FromRow)]
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

#[derive(sqlx::FromRow)]
pub struct StatusRow {
    pub id: i64,
    pub account_id: i64,
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

pub async fn fetch_account_counts(pool: &sqlx::SqlitePool, account_id: i64) -> (i64, i64, i64) {
    let (followers,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM followers WHERE local_account_id = ?",
    )
    .bind(account_id)
    .fetch_one(pool)
    .await
    .unwrap_or((0,));

    let (following,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM follows WHERE follower_id = ?",
    )
    .bind(account_id)
    .fetch_one(pool)
    .await
    .unwrap_or((0,));

    let (statuses,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM posts WHERE account_id = ?",
    )
    .bind(account_id)
    .fetch_one(pool)
    .await
    .unwrap_or((0,));

    (followers, following, statuses)
}

pub async fn fetch_account_row(pool: &sqlx::SqlitePool, id: i64) -> Result<AccountRow, AppError> {
    sqlx::query_as::<_, AccountRow>(
        "SELECT id, username, display_name, bio, bio_html, is_locked, discoverable, bot, fields_json, created_at, last_status_at FROM accounts WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| AppError::not_found("Account not found"))
}

async fn fetch_account_row_by_username(
    pool: &sqlx::SqlitePool,
    username: &str,
) -> Result<AccountRow, AppError> {
    sqlx::query_as::<_, AccountRow>(
        "SELECT id, username, display_name, bio, bio_html, is_locked, discoverable, bot, fields_json, created_at, last_status_at FROM accounts WHERE username = ?",
    )
    .bind(username)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| AppError::not_found("Account not found"))
}

// ---------------------------------------------------------------------------
// Bearer auth extractor
// ---------------------------------------------------------------------------

pub struct AuthenticatedAccount {
    pub account_id: i64,
    pub username: String,
    pub scopes: String,
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

        let row: Option<(i64, String, String)> = sqlx::query_as(
            "SELECT t.account_id, a.username, t.scopes FROM oauth_tokens t JOIN accounts a ON t.account_id = a.id WHERE t.token_hash = ? AND t.revoked_at IS NULL",
        )
        .bind(&token_hash)
        .fetch_optional(&state.pool)
        .await
        .map_err(AppError::from)?;

        let (account_id, username, scopes) =
            row.ok_or_else(|| AppError::unauthorized("Invalid or revoked token"))?;

        // Update last_used_at (best-effort, don't fail the request)
        let now = now_millis();
        let _ = sqlx::query("UPDATE oauth_tokens SET last_used_at = ? WHERE token_hash = ?")
            .bind(now)
            .bind(&token_hash)
            .execute(&state.pool)
            .await;

        Ok(AuthenticatedAccount {
            account_id,
            username,
            scopes,
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
    Json(body): Json<CreateAppRequest>,
) -> Result<Json<Value>, AppError> {
    let id = generate_id();
    let client_id = random_hex(16); // 32 hex chars
    let client_secret = random_hex(32); // 64 hex chars
    let scopes = body.scopes.as_deref().unwrap_or("read");
    let now = now_millis();

    sqlx::query(
        "INSERT INTO oauth_apps (id, client_id, client_secret, name, website, redirect_uri, scopes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id)
    .bind(&client_id)
    .bind(&client_secret)
    .bind(&body.client_name)
    .bind(&body.website)
    .bind(&body.redirect_uris)
    .bind(scopes)
    .bind(now)
    .execute(&state.pool)
    .await?;

    Ok(Json(json!({
        "id": id.to_string(),
        "name": body.client_name,
        "website": body.website,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": body.redirect_uris,
        "vapid_key": "",
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
    let accounts: Vec<(i64, String, String)> = sqlx::query_as(
        "SELECT id, username, display_name FROM accounts ORDER BY username",
    )
    .fetch_all(&state.pool)
    .await?;

    let response_type = params.response_type.as_deref().unwrap_or("code");
    let client_id = params.client_id.as_deref().unwrap_or("");
    let redirect_uri = params
        .redirect_uri
        .as_deref()
        .unwrap_or("urn:ietf:wg:oauth:2.0:oob");
    let scope = params.scope.as_deref().unwrap_or("read");

    let mut options = String::new();
    for (id, username, display_name) in &accounts {
        options.push_str(&format!(
            "<option value=\"{id}\">{display_name} (@{username})</option>\n"
        ));
    }

    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Authorize - smallhold</title>
  <style>
    body {{ font-family: sans-serif; max-width: 400px; margin: 4em auto; }}
    label {{ display: block; margin: 1em 0 0.3em; }}
    input, select, button {{ width: 100%; padding: 0.5em; box-sizing: border-box; }}
    button {{ margin-top: 1.5em; cursor: pointer; }}
  </style>
</head>
<body>
  <h1>Authorize</h1>
  <p>An application is requesting access to your account.</p>
  <form method="post" action="/oauth/authorize">
    <input type="hidden" name="response_type" value="{response_type}">
    <input type="hidden" name="client_id" value="{client_id}">
    <input type="hidden" name="redirect_uri" value="{redirect_uri}">
    <input type="hidden" name="scope" value="{scope}">
    <label for="password">Admin Password</label>
    <input type="password" id="password" name="password" required>
    <label for="account_id">Persona</label>
    <select id="account_id" name="account_id">
      {options}
    </select>
    <button type="submit">Authorize</button>
  </form>
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
    password: String,
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
    // Verify admin password
    let admin_row: Option<(String,)> =
        sqlx::query_as("SELECT password_hash FROM admin WHERE id = 1")
            .fetch_optional(&state.pool)
            .await?;

    let (password_hash,) =
        admin_row.ok_or_else(|| AppError::forbidden("Admin password not set"))?;

    verify_password(&form.password, &password_hash)?;

    // Verify account exists
    let account_exists: Option<(i64,)> =
        sqlx::query_as("SELECT id FROM accounts WHERE id = ?")
            .bind(form.account_id)
            .fetch_optional(&state.pool)
            .await?;
    if account_exists.is_none() {
        return Err(AppError::bad_request("Account not found"));
    }

    // Verify app exists
    let app_row: Option<(i64,)> =
        sqlx::query_as("SELECT id FROM oauth_apps WHERE client_id = ?")
            .bind(&form.client_id)
            .fetch_optional(&state.pool)
            .await?;
    let (app_id,) = app_row.ok_or_else(|| AppError::bad_request("Unknown client_id"))?;

    // Generate authorization code
    let code = random_bytes_b64url(32);
    let code_hash = hex_encode(&Sha256::digest(code.as_bytes()));
    let scope = form.scope.as_deref().unwrap_or("read");
    let expires_at = now_millis() + 600_000; // 10 minutes

    sqlx::query(
        "INSERT INTO oauth_authz_codes (code_hash, app_id, account_id, scopes, redirect_uri, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&code_hash)
    .bind(app_id)
    .bind(form.account_id)
    .bind(scope)
    .bind(&form.redirect_uri)
    .bind(expires_at)
    .execute(&state.pool)
    .await?;

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

fn verify_password(password: &str, hash: &str) -> Result<(), AppError> {
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

    // Look up and validate authorization code
    let code_row: Option<(i64, i64, String, String, i64)> = sqlx::query_as(
        "SELECT app_id, account_id, scopes, redirect_uri, expires_at FROM oauth_authz_codes WHERE code_hash = ?",
    )
    .bind(&code_hash)
    .fetch_optional(&state.pool)
    .await?;

    let (app_id, account_id, scopes, stored_redirect, expires_at) =
        code_row.ok_or_else(|| AppError::bad_request("Invalid authorization code"))?;

    let now = now_millis();
    if now > expires_at {
        // Clean up expired code
        let _ = sqlx::query("DELETE FROM oauth_authz_codes WHERE code_hash = ?")
            .bind(&code_hash)
            .execute(&state.pool)
            .await;
        return Err(AppError::bad_request("Authorization code expired"));
    }

    // Verify redirect_uri matches
    if let Some(ref uri) = form.redirect_uri {
        if *uri != stored_redirect {
            return Err(AppError::bad_request("redirect_uri mismatch"));
        }
    }

    // Verify client credentials if provided
    if let Some(ref cid) = form.client_id {
        let app_row: Option<(i64, String)> =
            sqlx::query_as("SELECT id, client_secret FROM oauth_apps WHERE client_id = ?")
                .bind(cid)
                .fetch_optional(&state.pool)
                .await?;

        let (found_app_id, stored_secret) =
            app_row.ok_or_else(|| AppError::bad_request("Unknown client_id"))?;

        if found_app_id != app_id {
            return Err(AppError::bad_request("client_id does not match authorization code"));
        }

        if let Some(ref cs) = form.client_secret {
            if *cs != stored_secret {
                return Err(AppError::unauthorized("Invalid client_secret"));
            }
        }
    }

    // Delete the authorization code (single-use)
    sqlx::query("DELETE FROM oauth_authz_codes WHERE code_hash = ?")
        .bind(&code_hash)
        .execute(&state.pool)
        .await?;

    // Generate access token
    let access_token = random_bytes_b64url(64);
    let token_hash = hex_encode(&Sha256::digest(access_token.as_bytes()));
    let id = generate_id();

    sqlx::query(
        "INSERT INTO oauth_tokens (id, token_hash, app_id, account_id, scopes, created_at) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(id)
    .bind(&token_hash)
    .bind(app_id)
    .bind(account_id)
    .bind(&scopes)
    .bind(now)
    .execute(&state.pool)
    .await?;

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
    let now = now_millis();

    sqlx::query("UPDATE oauth_tokens SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL")
        .bind(now)
        .bind(&token_hash)
        .execute(&state.pool)
        .await?;

    // Always return 200 per RFC 7009, even if token not found
    Ok(StatusCode::OK)
}

// ---------------------------------------------------------------------------
// Instance metadata: GET /api/v1/instance
// ---------------------------------------------------------------------------

async fn instance_v1(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, AppError> {
    let domain = &state.config.server.domain;

    let (status_count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM posts")
        .fetch_one(&state.pool)
        .await?;

    let (domain_count,): (i64,) =
        sqlx::query_as("SELECT COUNT(DISTINCT domain) FROM remote_accounts")
            .fetch_one(&state.pool)
            .await?;

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
        "contact_account": null,
        "rules": [],
    })))
}

// ---------------------------------------------------------------------------
// Instance metadata: GET /api/v2/instance
// ---------------------------------------------------------------------------

async fn instance_v2(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Value>, AppError> {
    let domain = &state.config.server.domain;

    let (status_count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM posts")
        .fetch_one(&state.pool)
        .await?;

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
        "contact": {
            "email": "",
            "account": null,
        },
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
    let (followers, following, statuses) =
        fetch_account_counts(&state.pool, auth.account_id).await;
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
    let id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("Account not found"))?;
    let domain = &state.config.server.domain;
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
    let account_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("Account not found"))?;

    // Verify account exists
    let _row = fetch_account_row(&state.pool, account_id).await?;

    let limit: i64 = params
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(20)
        .min(40);

    let domain = &state.config.server.domain;

    // Build query with pagination
    let statuses: Vec<StatusRow> =
        if let Some(max_id) = params.get("max_id").and_then(|v| v.parse::<i64>().ok()) {
            sqlx::query_as(
                "SELECT id, account_id, ap_id, content_html, spoiler_text, visibility, sensitive, language, created_at, edited_at FROM posts WHERE account_id = ? AND id < ? ORDER BY id DESC LIMIT ?",
            )
            .bind(account_id)
            .bind(max_id)
            .bind(limit)
            .fetch_all(&state.pool)
            .await?
        } else if let Some(min_id) = params.get("min_id").and_then(|v| v.parse::<i64>().ok()) {
            sqlx::query_as(
                "SELECT id, account_id, ap_id, content_html, spoiler_text, visibility, sensitive, language, created_at, edited_at FROM posts WHERE account_id = ? AND id > ? ORDER BY id ASC LIMIT ?",
            )
            .bind(account_id)
            .bind(min_id)
            .bind(limit)
            .fetch_all(&state.pool)
            .await?
        } else {
            sqlx::query_as(
                "SELECT id, account_id, ap_id, content_html, spoiler_text, visibility, sensitive, language, created_at, edited_at FROM posts WHERE account_id = ? ORDER BY id DESC LIMIT ?",
            )
            .bind(account_id)
            .bind(limit)
            .fetch_all(&state.pool)
            .await?
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

    let mut builder = Response::builder()
        .header("Content-Type", "application/json; charset=utf-8");

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

async fn get_tag(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Json<Value> {
    let domain = &state.config.server.domain;
    Json(json!({
        "name": id,
        "url": format!("https://{domain}/tags/{id}"),
        "history": [],
        "following": false
    }))
}

/// GET /api/v1/apps/verify_credentials
async fn verify_app_credentials(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
) -> Result<Json<Value>, AppError> {
    // Look up the app via the most recently used token for this account.
    // ponytail: single-user server, so most-recent-token heuristic is fine.
    let app_row: Option<(String, Option<String>)> = sqlx::query_as(
        "SELECT oa.name, oa.website FROM oauth_tokens ot JOIN oauth_apps oa ON ot.app_id = oa.id WHERE ot.account_id = ? AND ot.revoked_at IS NULL ORDER BY ot.last_used_at DESC LIMIT 1",
    )
    .bind(auth.account_id)
    .fetch_optional(&state.pool)
    .await?;

    match app_row {
        Some((name, website)) => Ok(Json(json!({
            "name": name,
            "website": website,
            "vapid_key": "",
        }))),
        None => Ok(Json(json!({
            "name": "unknown",
            "website": null,
            "vapid_key": "",
        }))),
    }
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
        // Stubs
        .route("/api/v1/custom_emojis", get(empty_array))
        .route("/api/v1/filters", get(empty_array))
        .route("/api/v2/filters", get(empty_array))
        .route("/api/v1/lists", get(empty_array))
        .route("/api/v1/suggestions", get(empty_array))
        .route("/api/v1/trends/tags", get(empty_array))
        .route("/api/v1/trends/statuses", get(empty_array))
        .route("/api/v1/trends/links", get(empty_array))
        .route("/api/v1/announcements", get(empty_array))
        .route("/api/v1/followed_tags", get(empty_array))
        .route("/api/v1/mutes", get(empty_array))
        .route("/api/v1/blocks", get(empty_array))
        .route("/api/v1/domain_blocks", get(empty_array_authed))
        .route("/api/v1/bookmarks", get(empty_array))
        .route("/api/v1/favourites", get(empty_array))
        .route("/api/v1/conversations", get(empty_array))
        .route("/api/v1/featured_tags", get(empty_array))
        .route("/api/v1/endorsements", get(empty_array))
        .route("/api/v1/scheduled_statuses", get(empty_array))
        .route("/api/v1/tags/{id}", get(get_tag))
        .route("/api/v1/tags/{id}/follow", post(get_tag))
        .route("/api/v1/tags/{id}/unfollow", post(get_tag))
        .route("/api/v1/instance/rules", get(empty_array))
        .route("/api/v1/instance/peers", get(empty_array))
        .route("/api/v1/instance/activity", get(empty_array))
        .route("/api/v1/preferences", get(preferences))
        .route(
            "/api/v1/markers",
            get(get_markers).post(post_markers),
        )
        .route(
            "/api/v1/apps/verify_credentials",
            get(verify_app_credentials),
        )
}
