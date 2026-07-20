use crate::api::{
    account_to_json, fetch_account_row, hex_encode, millis_to_iso, now_millis, AccountRow,
    AuthenticatedAccount,
};
use crate::delivery::{enqueue_delivery, enqueue_to_followers};
use crate::error::AppError;
use crate::federation::FederationClient;
use crate::id::generate_id;
use crate::posting::render_content;
use crate::server::AppState;
use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;

// ponytail: blocks and mutes tables are now part of fieldwork's canonical schema,
// created by migrate_full() at startup. No lazy creation needed.

// ---------------------------------------------------------------------------
// Relationship JSON builder
// ---------------------------------------------------------------------------

async fn build_relationship(
    pool: &sqlx::SqlitePool,
    source_account_id: i64,
    target_persona_id: i64,
) -> Result<Value, AppError> {
    // Following (local -> local)
    let (following_count,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM follows WHERE persona_id = ? AND followee_persona_id = ?")
            .bind(source_account_id)
            .bind(target_persona_id)
            .fetch_one(pool)
            .await?;

    // Followed-by (target -> source, local -> local)
    let (followed_by_count,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM follows WHERE persona_id = ? AND followee_persona_id = ?")
            .bind(target_persona_id)
            .bind(source_account_id)
            .fetch_one(pool)
            .await?;

    // Show reblogs
    let show_reblogs_row: Option<(bool,)> = sqlx::query_as(
        "SELECT show_reblogs FROM follows WHERE persona_id = ? AND followee_persona_id = ?",
    )
    .bind(source_account_id)
    .bind(target_persona_id)
    .fetch_optional(pool)
    .await?;
    let showing_reblogs = show_reblogs_row.map(|(v,)| v).unwrap_or(true);

    // Notify
    let notify_row: Option<(bool,)> =
        sqlx::query_as("SELECT notify FROM follows WHERE persona_id = ? AND followee_persona_id = ?")
            .bind(source_account_id)
            .bind(target_persona_id)
            .fetch_optional(pool)
            .await?;
    let notifying = notify_row.map(|(v,)| v).unwrap_or(false);

    // Blocking
    let (blocking_count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM blocks WHERE persona_id = ? AND target_persona_id = ?",
    )
    .bind(source_account_id)
    .bind(target_persona_id)
    .fetch_one(pool)
    .await?;

    // Blocked-by
    let (blocked_by_count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM blocks WHERE persona_id = ? AND target_persona_id = ?",
    )
    .bind(target_persona_id)
    .bind(source_account_id)
    .fetch_one(pool)
    .await?;

    // Muting
    let (muting_count,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM mutes WHERE persona_id = ? AND target_persona_id = ?")
            .bind(source_account_id)
            .bind(target_persona_id)
            .fetch_one(pool)
            .await?;

    // Follow requested (pending)
    // ponytail: follow_requests only tracks inbound from remote; local-to-local
    // follow requests are auto-accepted, so requested is always false here
    let requested = false;

    Ok(json!({
        "id": target_persona_id.to_string(),
        "following": following_count > 0,
        "showing_reblogs": showing_reblogs,
        "notifying": notifying,
        "followed_by": followed_by_count > 0,
        "blocking": blocking_count > 0,
        "blocked_by": blocked_by_count > 0,
        "muting": muting_count > 0,
        "muting_notifications": false,
        "requested": requested,
        "domain_blocking": false,
        "endorsed": false,
        "note": ""
    }))
}

/// Build relationship JSON for a remote account target. The target_id is the
/// remote_accounts.id, but we present the string ID the same way.
async fn build_relationship_remote(
    pool: &sqlx::SqlitePool,
    source_account_id: i64,
    target_remote_id: i64,
) -> Result<Value, AppError> {
    // Following (local -> remote)
    let (following_count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM follows WHERE persona_id = ? AND followee_remote_id = ?",
    )
    .bind(source_account_id)
    .bind(target_remote_id)
    .fetch_one(pool)
    .await?;

    // Followed-by (remote -> local)
    let (followed_by_count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM followers WHERE persona_id = ? AND remote_account_id = ?",
    )
    .bind(source_account_id)
    .bind(target_remote_id)
    .fetch_one(pool)
    .await?;

    // Show reblogs
    let show_reblogs_row: Option<(bool,)> = sqlx::query_as(
        "SELECT show_reblogs FROM follows WHERE persona_id = ? AND followee_remote_id = ?",
    )
    .bind(source_account_id)
    .bind(target_remote_id)
    .fetch_optional(pool)
    .await?;
    let showing_reblogs = show_reblogs_row.map(|(v,)| v).unwrap_or(true);

    // Blocking
    let (blocking_count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM blocks WHERE persona_id = ? AND target_remote_id = ?",
    )
    .bind(source_account_id)
    .bind(target_remote_id)
    .fetch_one(pool)
    .await?;

    // Muting
    let (muting_count,): (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM mutes WHERE persona_id = ? AND target_remote_id = ?")
            .bind(source_account_id)
            .bind(target_remote_id)
            .fetch_one(pool)
            .await?;

    Ok(json!({
        "id": target_remote_id.to_string(),
        "following": following_count > 0,
        "showing_reblogs": showing_reblogs,
        "notifying": false,
        "followed_by": followed_by_count > 0,
        "blocking": blocking_count > 0,
        "blocked_by": false,
        "muting": muting_count > 0,
        "muting_notifications": false,
        "requested": false,
        "domain_blocking": false,
        "endorsed": false,
        "note": ""
    }))
}

// ---------------------------------------------------------------------------
// Helper: determine if target ID is local or remote
// ---------------------------------------------------------------------------

enum TargetAccount {
    Local(i64),
    Remote {
        id: i64,
        actor_uri: String,
        inbox_url: String,
        shared_inbox_url: Option<String>,
    },
}

async fn resolve_target(pool: &sqlx::SqlitePool, id_str: &str) -> Result<TargetAccount, AppError> {
    let id: i64 = id_str
        .parse()
        .map_err(|_| AppError::not_found("Account not found"))?;

    // Check local first
    let local: Option<(i64,)> = sqlx::query_as("SELECT id FROM personas WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    if local.is_some() {
        return Ok(TargetAccount::Local(id));
    }

    // Check remote
    let remote: Option<(i64, String, String, Option<String>)> = sqlx::query_as(
        "SELECT id, actor_uri, inbox_url, shared_inbox_url FROM remote_accounts WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;

    match remote {
        Some((rid, actor_uri, inbox_url, shared_inbox_url)) => Ok(TargetAccount::Remote {
            id: rid,
            actor_uri,
            inbox_url,
            shared_inbox_url,
        }),
        None => Err(AppError::not_found("Account not found")),
    }
}

// ---------------------------------------------------------------------------
// POST /api/v1/accounts/:id/follow
// ---------------------------------------------------------------------------

async fn follow(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    auth.require_scope("write")?;
    let domain = &state.config.server.domain;
    let now = now_millis();

    let target = resolve_target(&state.pool, &id).await?;

    match target {
        TargetAccount::Local(target_id) => {
            if target_id == auth.account_id {
                return Err(AppError::unprocessable("Cannot follow yourself"));
            }
            sqlx::query(
                "INSERT OR IGNORE INTO follows (persona_id, user_id, followee_persona_id, created_at) \
                 VALUES (?, ?, ?, ?)",
            )
            .bind(auth.account_id)
            .bind(crate::db::DEFAULT_USER_ID)
            .bind(target_id)
            .bind(now)
            .execute(&state.pool)
            .await?;

            build_relationship(&state.pool, auth.account_id, target_id)
                .await
                .map(Json)
        }
        TargetAccount::Remote {
            id: remote_id,
            actor_uri,
            inbox_url,
            shared_inbox_url,
        } => {
            // Insert follow locally
            sqlx::query(
                "INSERT OR IGNORE INTO follows (persona_id, user_id, followee_remote_id, created_at) \
                 VALUES (?, ?, ?, ?)",
            )
            .bind(auth.account_id)
            .bind(crate::db::DEFAULT_USER_ID)
            .bind(remote_id)
            .bind(now)
            .execute(&state.pool)
            .await?;

            // Enqueue outbound Follow activity — derive a stable ID from
            // actor+object so Undo{Follow} can reference the same URI.
            let actor_field = format!("https://{domain}/users/{}", auth.username);
            let follow_hash = {
                let mut h = Sha256::new();
                h.update(actor_field.as_bytes());
                h.update(actor_uri.as_bytes());
                hex_encode(&h.finalize())
            };
            let activity = json!({
                "@context": "https://www.w3.org/ns/activitystreams",
                "id": format!("https://{domain}/activities/follow-{follow_hash}"),
                "type": "Follow",
                "actor": &actor_field,
                "object": actor_uri
            });

            let target_inbox = shared_inbox_url.as_deref().unwrap_or(&inbox_url);
            let _ = enqueue_delivery(&state.pool, target_inbox, auth.account_id, &activity).await;

            build_relationship_remote(&state.pool, auth.account_id, remote_id)
                .await
                .map(Json)
        }
    }
}

// ---------------------------------------------------------------------------
// POST /api/v1/accounts/:id/unfollow
// ---------------------------------------------------------------------------

async fn unfollow(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let domain = &state.config.server.domain;

    let target = resolve_target(&state.pool, &id).await?;

    match target {
        TargetAccount::Local(target_id) => {
            sqlx::query("DELETE FROM follows WHERE persona_id = ? AND followee_persona_id = ?")
                .bind(auth.account_id)
                .bind(target_id)
                .execute(&state.pool)
                .await?;

            build_relationship(&state.pool, auth.account_id, target_id)
                .await
                .map(Json)
        }
        TargetAccount::Remote {
            id: remote_id,
            actor_uri,
            inbox_url,
            shared_inbox_url,
        } => {
            sqlx::query("DELETE FROM follows WHERE persona_id = ? AND followee_remote_id = ?")
                .bind(auth.account_id)
                .bind(remote_id)
                .execute(&state.pool)
                .await?;

            // Enqueue Undo{Follow} — derive a stable follow ID from
            // actor+object so the Undo references the same URI.
            let undo_id = generate_id();
            let actor_field = format!("https://{domain}/users/{}", auth.username);
            let follow_hash = {
                let mut h = Sha256::new();
                h.update(actor_field.as_bytes());
                h.update(actor_uri.as_bytes());
                hex_encode(&h.finalize())
            };
            let activity = json!({
                "@context": "https://www.w3.org/ns/activitystreams",
                "id": format!("https://{domain}/activities/undo-{undo_id}"),
                "type": "Undo",
                "actor": &actor_field,
                "object": {
                    "id": format!("https://{domain}/activities/follow-{follow_hash}"),
                    "type": "Follow",
                    "actor": &actor_field,
                    "object": actor_uri
                }
            });

            let target_inbox = shared_inbox_url.as_deref().unwrap_or(&inbox_url);
            let _ = enqueue_delivery(&state.pool, target_inbox, auth.account_id, &activity).await;

            build_relationship_remote(&state.pool, auth.account_id, remote_id)
                .await
                .map(Json)
        }
    }
}

// ---------------------------------------------------------------------------
// GET /api/v1/accounts/:id/followers
// ---------------------------------------------------------------------------

async fn followers_list(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, AppError> {
    let account_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("Account not found"))?;
    let _account = fetch_account_row(&state.pool, account_id).await?;
    let domain = &state.config.server.domain;
    let limit: i64 = params
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(40)
        .min(80);

    // Local followers (other local accounts following this account)
    let local_followers: Vec<AccountRow> = sqlx::query_as(
        "SELECT a.id, a.username, a.display_name, a.bio, a.bio_html, a.is_locked, \
         a.discoverable, a.bot, a.fields_json, a.created_at, a.last_status_at \
         FROM follows f JOIN personas a ON f.persona_id = a.id \
         WHERE f.followee_persona_id = ? ORDER BY f.created_at DESC LIMIT ?",
    )
    .bind(account_id)
    .bind(limit)
    .fetch_all(&state.pool)
    .await?;

    // Remote followers
    let remote_followers: Vec<(i64, String, String, String, String)> = sqlx::query_as(
        "SELECT ra.id, ra.username, ra.domain, ra.display_name, ra.bio_html \
         FROM followers f JOIN remote_accounts ra ON f.remote_account_id = ra.id \
         WHERE f.persona_id = ? ORDER BY f.accepted_at DESC LIMIT ?",
    )
    .bind(account_id)
    .bind(limit)
    .fetch_all(&state.pool)
    .await?;

    let mut accounts: Vec<Value> = local_followers
        .iter()
        .map(|row| account_to_json(row, domain))
        .collect();

    for (rid, username, rdomain, display_name, bio_html) in &remote_followers {
        accounts.push(json!({
            "id": rid.to_string(),
            "username": username,
            "acct": format!("{username}@{rdomain}"),
            "display_name": display_name,
            "locked": false,
            "bot": false,
            "discoverable": true,
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
            "emojis": [],
            "fields": []
        }));
    }

    Ok(Json(json!(accounts)))
}

// ---------------------------------------------------------------------------
// GET /api/v1/accounts/:id/following
// ---------------------------------------------------------------------------

async fn following_list(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, AppError> {
    let account_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("Account not found"))?;
    let _account = fetch_account_row(&state.pool, account_id).await?;
    let domain = &state.config.server.domain;
    let limit: i64 = params
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(40)
        .min(80);

    // Local following
    let local_following: Vec<AccountRow> = sqlx::query_as(
        "SELECT a.id, a.username, a.display_name, a.bio, a.bio_html, a.is_locked, \
         a.discoverable, a.bot, a.fields_json, a.created_at, a.last_status_at \
         FROM follows f JOIN personas a ON f.followee_persona_id = a.id \
         WHERE f.persona_id = ? AND f.followee_persona_id IS NOT NULL \
         ORDER BY f.created_at DESC LIMIT ?",
    )
    .bind(account_id)
    .bind(limit)
    .fetch_all(&state.pool)
    .await?;

    // Remote following
    let remote_following: Vec<(i64, String, String, String, String)> = sqlx::query_as(
        "SELECT ra.id, ra.username, ra.domain, ra.display_name, ra.bio_html \
         FROM follows f JOIN remote_accounts ra ON f.followee_remote_id = ra.id \
         WHERE f.persona_id = ? AND f.followee_remote_id IS NOT NULL \
         ORDER BY f.created_at DESC LIMIT ?",
    )
    .bind(account_id)
    .bind(limit)
    .fetch_all(&state.pool)
    .await?;

    let mut accounts: Vec<Value> = local_following
        .iter()
        .map(|row| account_to_json(row, domain))
        .collect();

    for (rid, username, rdomain, display_name, bio_html) in &remote_following {
        accounts.push(json!({
            "id": rid.to_string(),
            "username": username,
            "acct": format!("{username}@{rdomain}"),
            "display_name": display_name,
            "locked": false,
            "bot": false,
            "discoverable": true,
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
            "emojis": [],
            "fields": []
        }));
    }

    Ok(Json(json!(accounts)))
}

// ---------------------------------------------------------------------------
// POST /api/v1/accounts/:id/block
// ---------------------------------------------------------------------------

async fn block(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    auth.require_scope("write")?;
    let domain = &state.config.server.domain;
    let now = now_millis();

    let target = resolve_target(&state.pool, &id).await?;

    match target {
        TargetAccount::Local(target_id) => {
            if target_id == auth.account_id {
                return Err(AppError::unprocessable("Cannot block yourself"));
            }

            sqlx::query(
                "INSERT OR IGNORE INTO blocks (persona_id, target_persona_id, created_at) \
                 VALUES (?, ?, ?)",
            )
            .bind(auth.account_id)
            .bind(target_id)
            .bind(now)
            .execute(&state.pool)
            .await?;

            // Remove mutual follows
            sqlx::query("DELETE FROM follows WHERE persona_id = ? AND followee_persona_id = ?")
                .bind(auth.account_id)
                .bind(target_id)
                .execute(&state.pool)
                .await?;
            sqlx::query("DELETE FROM follows WHERE persona_id = ? AND followee_persona_id = ?")
                .bind(target_id)
                .bind(auth.account_id)
                .execute(&state.pool)
                .await?;

            build_relationship(&state.pool, auth.account_id, target_id)
                .await
                .map(Json)
        }
        TargetAccount::Remote {
            id: remote_id,
            actor_uri,
            inbox_url,
            shared_inbox_url,
        } => {
            sqlx::query(
                "INSERT OR IGNORE INTO blocks (persona_id, target_remote_id, created_at) \
                 VALUES (?, ?, ?)",
            )
            .bind(auth.account_id)
            .bind(remote_id)
            .bind(now)
            .execute(&state.pool)
            .await?;

            // Remove follow + follower relationships
            sqlx::query("DELETE FROM follows WHERE persona_id = ? AND followee_remote_id = ?")
                .bind(auth.account_id)
                .bind(remote_id)
                .execute(&state.pool)
                .await?;
            sqlx::query(
                "DELETE FROM followers WHERE persona_id = ? AND remote_account_id = ?",
            )
            .bind(auth.account_id)
            .bind(remote_id)
            .execute(&state.pool)
            .await?;

            // Send Block activity to the remote actor's inbox.
            let block_id = generate_id();
            let block_activity = json!({
                "@context": "https://www.w3.org/ns/activitystreams",
                "id": format!("https://{domain}/activities/block-{block_id}"),
                "type": "Block",
                "actor": format!("https://{domain}/users/{}", auth.username),
                "object": actor_uri
            });
            let target_inbox = shared_inbox_url.as_deref().unwrap_or(&inbox_url);
            let _ =
                enqueue_delivery(&state.pool, target_inbox, auth.account_id, &block_activity).await;

            build_relationship_remote(&state.pool, auth.account_id, remote_id)
                .await
                .map(Json)
        }
    }
}

// ---------------------------------------------------------------------------
// POST /api/v1/accounts/:id/unblock
// ---------------------------------------------------------------------------

async fn unblock(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {

    let target = resolve_target(&state.pool, &id).await?;

    match target {
        TargetAccount::Local(target_id) => {
            sqlx::query("DELETE FROM blocks WHERE persona_id = ? AND target_persona_id = ?")
                .bind(auth.account_id)
                .bind(target_id)
                .execute(&state.pool)
                .await?;

            build_relationship(&state.pool, auth.account_id, target_id)
                .await
                .map(Json)
        }
        TargetAccount::Remote { id: remote_id, .. } => {
            sqlx::query("DELETE FROM blocks WHERE persona_id = ? AND target_remote_id = ?")
                .bind(auth.account_id)
                .bind(remote_id)
                .execute(&state.pool)
                .await?;

            build_relationship_remote(&state.pool, auth.account_id, remote_id)
                .await
                .map(Json)
        }
    }
}

// ---------------------------------------------------------------------------
// POST /api/v1/accounts/:id/mute
// ---------------------------------------------------------------------------

async fn mute(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    auth.require_scope("write")?;
    let now = now_millis();

    let target = resolve_target(&state.pool, &id).await?;

    match target {
        TargetAccount::Local(target_id) => {
            if target_id == auth.account_id {
                return Err(AppError::unprocessable("Cannot mute yourself"));
            }

            sqlx::query(
                "INSERT OR IGNORE INTO mutes (persona_id, target_persona_id, created_at) \
                 VALUES (?, ?, ?)",
            )
            .bind(auth.account_id)
            .bind(target_id)
            .bind(now)
            .execute(&state.pool)
            .await?;

            build_relationship(&state.pool, auth.account_id, target_id)
                .await
                .map(Json)
        }
        TargetAccount::Remote { id: remote_id, .. } => {
            sqlx::query(
                "INSERT OR IGNORE INTO mutes (persona_id, target_remote_id, created_at) \
                 VALUES (?, ?, ?)",
            )
            .bind(auth.account_id)
            .bind(remote_id)
            .bind(now)
            .execute(&state.pool)
            .await?;

            build_relationship_remote(&state.pool, auth.account_id, remote_id)
                .await
                .map(Json)
        }
    }
}

// ---------------------------------------------------------------------------
// POST /api/v1/accounts/:id/unmute
// ---------------------------------------------------------------------------

async fn unmute(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {

    let target = resolve_target(&state.pool, &id).await?;

    match target {
        TargetAccount::Local(target_id) => {
            sqlx::query("DELETE FROM mutes WHERE persona_id = ? AND target_persona_id = ?")
                .bind(auth.account_id)
                .bind(target_id)
                .execute(&state.pool)
                .await?;

            build_relationship(&state.pool, auth.account_id, target_id)
                .await
                .map(Json)
        }
        TargetAccount::Remote { id: remote_id, .. } => {
            sqlx::query("DELETE FROM mutes WHERE persona_id = ? AND target_remote_id = ?")
                .bind(auth.account_id)
                .bind(remote_id)
                .execute(&state.pool)
                .await?;

            build_relationship_remote(&state.pool, auth.account_id, remote_id)
                .await
                .map(Json)
        }
    }
}

// ---------------------------------------------------------------------------
// PATCH /api/v1/accounts/update_credentials
// ---------------------------------------------------------------------------

#[derive(Deserialize, Default)]
struct UpdateCredentialsRequest {
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    note: Option<String>,
    #[serde(default)]
    locked: Option<bool>,
    #[serde(default)]
    bot: Option<bool>,
    #[serde(default)]
    discoverable: Option<bool>,
    #[serde(default)]
    fields_attributes: Option<Vec<FieldAttribute>>,
}

#[derive(Deserialize)]
struct FieldAttribute {
    name: String,
    value: String,
}

async fn update_credentials(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Json(body): Json<UpdateCredentialsRequest>,
) -> Result<Json<Value>, AppError> {
    let domain = &state.config.server.domain;
    let now = now_millis();

    let mut changed = false;

    if let Some(ref display_name) = body.display_name {
        sqlx::query("UPDATE personas SET display_name = ? WHERE id = ?")
            .bind(display_name)
            .bind(auth.account_id)
            .execute(&state.pool)
            .await?;
        changed = true;
    }

    if let Some(ref note) = body.note {
        let rendered = render_content(note, domain);
        sqlx::query("UPDATE personas SET bio = ?, bio_html = ? WHERE id = ?")
            .bind(note)
            .bind(&rendered.html)
            .bind(auth.account_id)
            .execute(&state.pool)
            .await?;
        changed = true;
    }

    if let Some(locked) = body.locked {
        sqlx::query("UPDATE personas SET is_locked = ? WHERE id = ?")
            .bind(locked)
            .bind(auth.account_id)
            .execute(&state.pool)
            .await?;
        changed = true;
    }

    if let Some(bot) = body.bot {
        sqlx::query("UPDATE personas SET bot = ? WHERE id = ?")
            .bind(bot)
            .bind(auth.account_id)
            .execute(&state.pool)
            .await?;
        changed = true;
    }

    if let Some(discoverable) = body.discoverable {
        sqlx::query("UPDATE personas SET discoverable = ? WHERE id = ?")
            .bind(discoverable)
            .bind(auth.account_id)
            .execute(&state.pool)
            .await?;
        changed = true;
    }

    if let Some(ref fields) = body.fields_attributes {
        let fields_json: Vec<Value> = fields
            .iter()
            .take(6) // ponytail: cap at 6 fields, same as Mastodon default
            .map(|f| json!({"name": f.name, "value": ammonia::clean(&f.value)}))
            .collect();
        let fields_str =
            serde_json::to_string(&fields_json).map_err(|e| AppError::internal(e.to_string()))?;
        sqlx::query("UPDATE personas SET fields_json = ? WHERE id = ?")
            .bind(&fields_str)
            .bind(auth.account_id)
            .execute(&state.pool)
            .await?;
        changed = true;
    }

    // Enqueue Update{Actor} to all followers if anything changed
    if changed {
        let account_row = fetch_account_row(&state.pool, auth.account_id).await?;
        let actor_uri = format!("https://{domain}/users/{}", auth.username);

        let fields: Vec<Value> = serde_json::from_str(&account_row.fields_json).unwrap_or_default();
        let attachment: Vec<Value> = fields
            .iter()
            .filter_map(|field| {
                let name = field.get("name")?.as_str()?;
                let value = field.get("value")?.as_str()?;
                Some(json!({
                    "type": "PropertyValue",
                    "name": name,
                    "value": value
                }))
            })
            .collect();

        let actor_type = if account_row.bot { "Service" } else { "Person" };
        let published = millis_to_iso(account_row.created_at);

        let update_id = generate_id();
        let update_activity = json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": format!("https://{domain}/activities/update-{update_id}"),
            "type": "Update",
            "actor": &actor_uri,
            "to": ["https://www.w3.org/ns/activitystreams#Public"],
            "object": {
                "@context": "https://www.w3.org/ns/activitystreams",
                "id": &actor_uri,
                "type": actor_type,
                "preferredUsername": auth.username,
                "name": account_row.display_name,
                "summary": account_row.bio_html,
                "url": format!("https://{domain}/@{}", auth.username),
                "manuallyApprovesFollowers": account_row.is_locked,
                "discoverable": account_row.discoverable,
                "published": published,
                "inbox": format!("{actor_uri}/inbox"),
                "outbox": format!("{actor_uri}/outbox"),
                "followers": format!("{actor_uri}/followers"),
                "following": format!("{actor_uri}/following"),
                "attachment": attachment,
                "endpoints": {
                    "sharedInbox": format!("https://{domain}/inbox")
                }
            },
            "published": millis_to_iso(now)
        });

        let _ = enqueue_to_followers(&state.pool, auth.account_id, &update_activity).await;
    }

    // Return updated account with source
    let row = fetch_account_row(&state.pool, auth.account_id).await?;
    let mut v = account_to_json(&row, domain);
    let fields: Vec<Value> = serde_json::from_str(&row.fields_json).unwrap_or_default();
    v["source"] = json!({
        "privacy": "public",
        "sensitive": false,
        "language": "en",
        "note": row.bio,
        "fields": fields,
        "follow_requests_count": 0,
    });
    Ok(Json(v))
}

// ---------------------------------------------------------------------------
// Follow requests
// ---------------------------------------------------------------------------

async fn follow_requests(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
) -> Result<Json<Value>, AppError> {
    let requests: Vec<(i64, i64, i64)> = sqlx::query_as(
        "SELECT fr.id, fr.requester_remote_id, fr.created_at \
         FROM follow_requests fr WHERE fr.target_persona_id = ? \
         ORDER BY fr.created_at DESC",
    )
    .bind(auth.account_id)
    .fetch_all(&state.pool)
    .await?;

    let mut accounts = Vec::with_capacity(requests.len());
    for (_req_id, remote_id, _created_at) in &requests {
        let remote: Option<(i64, String, String, String, String)> = sqlx::query_as(
            "SELECT id, username, domain, display_name, bio_html \
             FROM remote_accounts WHERE id = ?",
        )
        .bind(remote_id)
        .fetch_optional(&state.pool)
        .await?;

        if let Some((rid, username, rdomain, display_name, bio_html)) = remote {
            accounts.push(json!({
                "id": rid.to_string(),
                "username": username,
                "acct": format!("{username}@{rdomain}"),
                "display_name": display_name,
                "locked": false,
                "bot": false,
                "discoverable": true,
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
                "emojis": [],
                "fields": []
            }));
        }
    }

    Ok(Json(json!(accounts)))
}

async fn authorize_follow(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let remote_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("Follow request not found"))?;

    let domain = &state.config.server.domain;

    // Find and validate the follow request
    let request: Option<(i64, String)> = sqlx::query_as(
        "SELECT id, ap_id FROM follow_requests \
         WHERE requester_remote_id = ? AND target_persona_id = ?",
    )
    .bind(remote_id)
    .bind(auth.account_id)
    .fetch_optional(&state.pool)
    .await?;

    let (req_id, follow_ap_id) =
        request.ok_or_else(|| AppError::not_found("Follow request not found"))?;

    let now = now_millis();

    // Accept: insert into followers
    sqlx::query(
        "INSERT OR IGNORE INTO followers (persona_id, user_id, remote_account_id, accepted_at) \
         VALUES (?, ?, ?, ?)",
    )
    .bind(auth.account_id)
    .bind(crate::db::DEFAULT_USER_ID)
    .bind(remote_id)
    .bind(now)
    .execute(&state.pool)
    .await?;

    // Remove from follow_requests
    sqlx::query("DELETE FROM follow_requests WHERE id = ?")
        .bind(req_id)
        .execute(&state.pool)
        .await?;

    // Send Accept activity
    let remote_row: Option<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT actor_uri, inbox_url, shared_inbox_url FROM remote_accounts WHERE id = ?",
    )
    .bind(remote_id)
    .fetch_optional(&state.pool)
    .await?;

    if let Some((actor_uri, inbox_url, shared_inbox_url)) = remote_row {
        let accept_id = generate_id();
        let accept_activity = json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": format!("https://{domain}/activities/accept-{accept_id}"),
            "type": "Accept",
            "actor": format!("https://{domain}/users/{}", auth.username),
            "object": {
                "id": follow_ap_id,
                "type": "Follow",
                "actor": actor_uri,
                "object": format!("https://{domain}/users/{}", auth.username)
            }
        });

        let target_inbox = shared_inbox_url.as_deref().unwrap_or(&inbox_url);
        let _ =
            enqueue_delivery(&state.pool, target_inbox, auth.account_id, &accept_activity).await;
    }

    build_relationship_remote(&state.pool, auth.account_id, remote_id)
        .await
        .map(Json)
}

async fn reject_follow(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let remote_id: i64 = id
        .parse()
        .map_err(|_| AppError::not_found("Follow request not found"))?;

    let domain = &state.config.server.domain;

    // Find and validate the follow request
    let request: Option<(i64, String)> = sqlx::query_as(
        "SELECT id, ap_id FROM follow_requests \
         WHERE requester_remote_id = ? AND target_persona_id = ?",
    )
    .bind(remote_id)
    .bind(auth.account_id)
    .fetch_optional(&state.pool)
    .await?;

    let (req_id, follow_ap_id) =
        request.ok_or_else(|| AppError::not_found("Follow request not found"))?;

    // Remove from follow_requests
    sqlx::query("DELETE FROM follow_requests WHERE id = ?")
        .bind(req_id)
        .execute(&state.pool)
        .await?;

    // Send Reject activity
    let remote_row: Option<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT actor_uri, inbox_url, shared_inbox_url FROM remote_accounts WHERE id = ?",
    )
    .bind(remote_id)
    .fetch_optional(&state.pool)
    .await?;

    if let Some((actor_uri, inbox_url, shared_inbox_url)) = remote_row {
        let reject_id = generate_id();
        let reject_activity = json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": format!("https://{domain}/activities/reject-{reject_id}"),
            "type": "Reject",
            "actor": format!("https://{domain}/users/{}", auth.username),
            "object": {
                "id": follow_ap_id,
                "type": "Follow",
                "actor": actor_uri,
                "object": format!("https://{domain}/users/{}", auth.username)
            }
        });

        let target_inbox = shared_inbox_url.as_deref().unwrap_or(&inbox_url);
        let _ =
            enqueue_delivery(&state.pool, target_inbox, auth.account_id, &reject_activity).await;
    }

    build_relationship_remote(&state.pool, auth.account_id, remote_id)
        .await
        .map(Json)
}

// ---------------------------------------------------------------------------
// GET /api/v2/search
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct SearchQuery {
    q: String,
    #[serde(default)]
    r#type: Option<String>,
    #[serde(default)]
    resolve: Option<bool>,
    #[serde(default)]
    limit: Option<i64>,
}

async fn search(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Query(params): Query<SearchQuery>,
) -> Result<Json<Value>, AppError> {
    let domain = &state.config.server.domain;
    let query = params.q.trim();
    let limit = params.limit.unwrap_or(20).clamp(1, 40);
    let search_type = params.r#type.as_deref();
    let resolve = params.resolve.unwrap_or(false);

    let mut result_accounts: Vec<Value> = Vec::new();
    let mut result_hashtags: Vec<Value> = Vec::new();
    let mut result_statuses: Vec<Value> = Vec::new();

    let search_accounts = search_type.is_none() || search_type == Some("accounts");
    let search_hashtags = search_type.is_none() || search_type == Some("hashtags");
    let search_statuses = search_type.is_none() || search_type == Some("statuses");

    if search_accounts && !query.is_empty() {
        // Check if query looks like user@domain for WebFinger resolution
        if resolve && query.contains('@') {
            let acct = query.strip_prefix('@').unwrap_or(query);
            if let Some((_user, _remote_domain)) = acct.split_once('@') {
                let fed_client = FederationClient::new(&state.config)
                    .map_err(|e| AppError::internal(format!("federation client: {e}")))?;

                match fed_client.resolve_webfinger(acct).await {
                    Ok(actor_uri) => {
                        // Get signing credentials
                        let signing: Option<(String, String)> = sqlx::query_as(
                            "SELECT username, private_key_pem FROM personas WHERE id = ?",
                        )
                        .bind(auth.account_id)
                        .fetch_optional(&state.pool)
                        .await?;

                        if let Some((username, private_key_pem)) = signing {
                            let key_id = format!("https://{domain}/users/{username}#main-key");
                            match fed_client
                                .fetch_actor(&actor_uri, &private_key_pem, &key_id)
                                .await
                            {
                                Ok(actor_data) => {
                                    let remote_id = crate::federation::upsert_remote_account(
                                        &state.pool,
                                        &actor_data,
                                    )
                                    .await
                                    .map_err(|e| {
                                        AppError::internal(format!("upsert remote account: {e}"))
                                    })?;

                                    result_accounts.push(json!({
                                        "id": remote_id.to_string(),
                                        "username": actor_data.username,
                                        "acct": format!("{}@{}", actor_data.username, actor_data.domain),
                                        "display_name": actor_data.display_name,
                                        "locked": actor_data.is_locked,
                                        "bot": actor_data.bot,
                                        "discoverable": true,
                                        "created_at": "1970-01-01T00:00:00.000Z",
                                        "note": actor_data.bio_html,
                                        "url": format!("https://{}/@{}", actor_data.domain, actor_data.username),
                                        "uri": actor_data.actor_uri,
                                        "avatar": actor_data.avatar_url.as_deref().unwrap_or(""),
                                        "avatar_static": actor_data.avatar_url.as_deref().unwrap_or(""),
                                        "header": actor_data.header_url.as_deref().unwrap_or(""),
                                        "header_static": actor_data.header_url.as_deref().unwrap_or(""),
                                        "followers_count": 0,
                                        "following_count": 0,
                                        "statuses_count": 0,
                                        "last_status_at": null,
                                        "emojis": [],
                                        "fields": []
                                    }));
                                }
                                Err(e) => {
                                    tracing::debug!(
                                        acct,
                                        error = %e,
                                        "search: failed to fetch resolved actor"
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::debug!(
                            acct,
                            error = %e,
                            "search: WebFinger resolution failed"
                        );
                    }
                }
            }
        }

        // Local account search by username/display_name
        let escaped_query = query
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        let like_pattern = format!("%{escaped_query}%");
        let local_matches: Vec<AccountRow> = sqlx::query_as(
            "SELECT id, username, display_name, bio, bio_html, is_locked, discoverable, \
             bot, fields_json, created_at, last_status_at \
             FROM personas \
             WHERE username LIKE ? ESCAPE '\\' OR display_name LIKE ? ESCAPE '\\' \
             LIMIT ?",
        )
        .bind(&like_pattern)
        .bind(&like_pattern)
        .bind(limit)
        .fetch_all(&state.pool)
        .await?;

        for row in &local_matches {
            result_accounts.push(account_to_json(row, domain));
        }

        // Remote account search (reuses escaped like_pattern from above)
        let remote_matches: Vec<(i64, String, String, String, String, bool, bool)> =
            sqlx::query_as(
                "SELECT id, username, domain, display_name, bio_html, is_locked, bot \
                 FROM remote_accounts \
                 WHERE username LIKE ? ESCAPE '\\' OR display_name LIKE ? ESCAPE '\\' \
                 LIMIT ?",
            )
            .bind(&like_pattern)
            .bind(&like_pattern)
            .bind(limit)
            .fetch_all(&state.pool)
            .await?;

        for (rid, username, rdomain, display_name, bio_html, is_locked, bot) in &remote_matches {
            result_accounts.push(json!({
                "id": rid.to_string(),
                "username": username,
                "acct": format!("{username}@{rdomain}"),
                "display_name": display_name,
                "locked": is_locked,
                "bot": bot,
                "discoverable": true,
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
                "emojis": [],
                "fields": []
            }));
        }

        // Truncate to limit
        result_accounts.truncate(limit as usize);
    }

    if search_hashtags && !query.is_empty() {
        let tag_query = query.strip_prefix('#').unwrap_or(query).to_lowercase();
        let escaped_tag = tag_query
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        let like_pattern = format!("%{escaped_tag}%");

        let tags: Vec<(String,)> = sqlx::query_as(
            "SELECT DISTINCT tag FROM post_tags WHERE tag LIKE ? ESCAPE '\\' LIMIT ?",
        )
        .bind(&like_pattern)
        .bind(limit)
        .fetch_all(&state.pool)
        .await?;

        for (tag,) in &tags {
            result_hashtags.push(json!({
                "name": tag,
                "url": format!("https://{domain}/tags/{tag}"),
                "history": []
            }));
        }
    }

    if search_statuses && !query.is_empty() {
        if let Some(ref search_idx) = state.search {
            if let Ok(post_ids) = search_idx.search(query, limit as usize) {
                for pid in post_ids {
                    let post = sqlx::query_as::<_, crate::posting::PostRow>(&format!(
                        "SELECT {} FROM posts WHERE id = ?",
                        crate::posting::POST_COLUMNS
                    ))
                    .bind(pid)
                    .fetch_optional(&state.pool)
                    .await?;

                    if let Some(post) = post {
                        let status = crate::posting::load_status(
                            &state.pool,
                            &post,
                            domain,
                            Some(auth.account_id),
                        )
                        .await?;
                        result_statuses.push(status);
                    }
                }
            }
        }
    }

    Ok(Json(json!({
        "accounts": result_accounts,
        "statuses": result_statuses,
        "hashtags": result_hashtags
    })))
}

// ---------------------------------------------------------------------------
// Hashtag following
// ---------------------------------------------------------------------------

fn tag_json(name: &str, domain: &str, following: bool) -> Value {
    json!({
        "name": name,
        "url": format!("https://{domain}/tags/{name}"),
        "history": [],
        "following": following
    })
}

/// GET /api/v1/followed_tags
async fn followed_tags_list(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Value>, AppError> {
    let domain = &state.config.server.domain;
    let limit: i64 = params
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(20)
        .min(100);

    let tags: Vec<(String,)> = sqlx::query_as(
        "SELECT tag FROM followed_tags WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
    )
    .bind(auth.account_id)
    .bind(limit)
    .fetch_all(&state.pool)
    .await?;

    let result: Vec<Value> = tags
        .iter()
        .map(|(tag,)| tag_json(tag, domain, true))
        .collect();

    Ok(Json(json!(result)))
}

/// POST /api/v1/tags/:id/follow
async fn follow_tag(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let domain = &state.config.server.domain;
    let tag = id.to_lowercase();
    let now = now_millis();

    sqlx::query(
        "INSERT OR IGNORE INTO followed_tags (user_id, tag, created_at) VALUES (?, ?, ?)",
    )
    .bind(auth.account_id)
    .bind(&tag)
    .bind(now)
    .execute(&state.pool)
    .await?;

    Ok(Json(tag_json(&tag, domain, true)))
}

/// POST /api/v1/tags/:id/unfollow
async fn unfollow_tag(
    State(state): State<Arc<AppState>>,
    auth: AuthenticatedAccount,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let domain = &state.config.server.domain;
    let tag = id.to_lowercase();

    sqlx::query("DELETE FROM followed_tags WHERE user_id = ? AND tag = ?")
        .bind(auth.account_id)
        .bind(&tag)
        .execute(&state.pool)
        .await?;

    Ok(Json(tag_json(&tag, domain, false)))
}

/// GET /api/v1/tags/:id — returns tag info with optional followed status
async fn get_tag(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    let domain = &state.config.server.domain;
    let tag = id.to_lowercase();

    // Try to extract auth to check followed status (optional — unauthenticated is fine)
    let following = if let Some(auth_header) = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    {
        let token_hash = crate::api::hex_encode(&Sha256::digest(auth_header.as_bytes()));
        let account_id: Option<(i64,)> = sqlx::query_as(
            "SELECT persona_id FROM oauth_tokens WHERE token_hash = ? AND revoked_at IS NULL",
        )
        .bind(&token_hash)
        .fetch_optional(&state.pool)
        .await?;

        if let Some((aid,)) = account_id {
            let (count,): (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM followed_tags WHERE user_id = ? AND tag = ?",
            )
            .bind(aid)
            .bind(&tag)
            .fetch_one(&state.pool)
            .await?;
            count > 0
        } else {
            false
        }
    } else {
        false
    };

    Ok(Json(tag_json(&tag, domain, following)))
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/api/v1/accounts/update_credentials",
            axum::routing::patch(update_credentials),
        )
        .route("/api/v1/accounts/{id}/follow", post(follow))
        .route("/api/v1/accounts/{id}/unfollow", post(unfollow))
        .route("/api/v1/accounts/{id}/block", post(block))
        .route("/api/v1/accounts/{id}/unblock", post(unblock))
        .route("/api/v1/accounts/{id}/mute", post(mute))
        .route("/api/v1/accounts/{id}/unmute", post(unmute))
        .route("/api/v1/accounts/{id}/followers", get(followers_list))
        .route("/api/v1/accounts/{id}/following", get(following_list))
        .route("/api/v1/follow_requests", get(follow_requests))
        .route(
            "/api/v1/follow_requests/{id}/authorize",
            post(authorize_follow),
        )
        .route("/api/v1/follow_requests/{id}/reject", post(reject_follow))
        .route("/api/v2/search", get(search))
        // Hashtag following
        .route("/api/v1/followed_tags", get(followed_tags_list))
        .route("/api/v1/tags/{id}", get(get_tag))
        .route("/api/v1/tags/{id}/follow", post(follow_tag))
        .route("/api/v1/tags/{id}/unfollow", post(unfollow_tag))
}
