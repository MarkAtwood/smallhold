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
    pool: &fieldwork::db::Pool,
    source_account_id: i64,
    target_persona_id: i64,
) -> Result<Value, AppError> {
    let fwp = pool;

    // REMAINING: relationship queries use follow/block/mute tables with local persona IDs.
    // fieldwork has is_following_remote but not is_following_local. These queries check
    // local-to-local relationships which fieldwork doesn't fully cover.
    let following_count = crate::db_extras::count_follows_local(pool, source_account_id, target_persona_id).await?;
    let followed_by_count = crate::db_extras::count_follows_local(pool, target_persona_id, source_account_id).await?;

    let showing_reblogs = crate::db_extras::get_follow_show_reblogs(pool, source_account_id, target_persona_id)
        .await?.unwrap_or(true);
    let notifying = crate::db_extras::get_follow_notify(pool, source_account_id, target_persona_id)
        .await?.unwrap_or(false);

    let blocking = fieldwork::interactions_db::is_blocked(
        &fwp, source_account_id, Some(target_persona_id), None,
    ).await?;

    let blocked_by = fieldwork::interactions_db::is_blocked(
        &fwp, target_persona_id, Some(source_account_id), None,
    ).await?;

    let muting = fieldwork::interactions_db::is_muted(
        &fwp, source_account_id, Some(target_persona_id), None,
    ).await?;

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
        "blocking": blocking,
        "blocked_by": blocked_by,
        "muting": muting,
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
    pool: &fieldwork::db::Pool,
    source_account_id: i64,
    target_remote_id: i64,
) -> Result<Value, AppError> {
    let fwp = pool;

    let following = fieldwork::follows_db::is_following_remote(
        &fwp, source_account_id, target_remote_id,
    ).await?;

    let followed_by = fieldwork::followers_db::is_following(
        &fwp, source_account_id, target_remote_id,
    ).await?;

    let showing_reblogs = crate::db_extras::get_follow_show_reblogs_remote(pool, source_account_id, target_remote_id)
        .await?.unwrap_or(true);

    let blocking = fieldwork::interactions_db::is_blocked(
        &fwp, source_account_id, None, Some(target_remote_id),
    ).await?;

    let muting = fieldwork::interactions_db::is_muted(
        &fwp, source_account_id, None, Some(target_remote_id),
    ).await?;

    Ok(json!({
        "id": target_remote_id.to_string(),
        "following": following,
        "showing_reblogs": showing_reblogs,
        "notifying": false,
        "followed_by": followed_by,
        "blocking": blocking,
        "blocked_by": false,
        "muting": muting,
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

async fn resolve_target(pool: &fieldwork::db::Pool, id_str: &str) -> Result<TargetAccount, AppError> {
    // Parse ID as i64 first
    let id: i64 = id_str.parse().map_err(|_| AppError::not_found("Account not found"))?;
    let fwp = pool;
    let local = fieldwork::persona_db::get_persona_by_id(&fwp, id).await?;
    if let Some(persona) = local {
        return Ok(TargetAccount::Local(persona.id));
    }

    // Check remote (remote_accounts.id is INTEGER)
    let id: i64 = id_str
        .parse()
        .map_err(|_| AppError::not_found("Account not found"))?;
    let remote: Option<(i64, String, String, Option<String>)> = crate::db_extras::get_remote_account_full(pool, id).await?;

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
            fieldwork::follows_db::follow_local(
                &state.pool, auth.account_id, crate::db::DEFAULT_USER_ID, target_id, now,
            ).await?;

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
            fieldwork::follows_db::follow_remote(
                &state.pool, auth.account_id, crate::db::DEFAULT_USER_ID, remote_id, now,
            ).await?;

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
            fieldwork::follows_db::unfollow_local(
                &state.pool, auth.account_id, target_id,
            ).await?;

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
            fieldwork::follows_db::unfollow_remote(
                &state.pool, auth.account_id, remote_id,
            ).await?;

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
    let account_id: i64 = id.parse().map_err(|_| AppError::not_found("Account not found"))?;
    let _account = fetch_account_row(&state.pool, account_id).await?;
    let domain = &state.config.server.domain;
    let limit: i64 = params
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(40)
        .min(80);

    // Local followers (other local accounts following this account)
    let local_followers: Vec<AccountRow> = crate::db_extras::get_local_followers(&state.pool, account_id, limit).await?;
    let remote_followers: Vec<(i64, String, String, String, String)> = crate::db_extras::get_remote_followers(&state.pool, account_id, limit).await?;

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
    let account_id: i64 = id.parse().map_err(|_| AppError::not_found("Account not found"))?;
    let _account = fetch_account_row(&state.pool, account_id).await?;
    let domain = &state.config.server.domain;
    let limit: i64 = params
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(40)
        .min(80);

    // Local following
    let local_following: Vec<AccountRow> = crate::db_extras::get_local_following(&state.pool, account_id, limit).await?;

    // Remote following
    let remote_following: Vec<(i64, String, String, String, String)> = crate::db_extras::get_remote_following(&state.pool, account_id, limit).await?;

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

            fieldwork::interactions_db::block(
                &state.pool, crate::db::DEFAULT_USER_ID, auth.account_id,
                Some(target_id), None, now,
            ).await?;

            // Remove mutual follows
            fieldwork::follows_db::unfollow_local(
                &state.pool, auth.account_id, target_id,
            ).await?;
            fieldwork::follows_db::unfollow_local(
                &state.pool, target_id, auth.account_id,
            ).await?;

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
            fieldwork::interactions_db::block(
                &state.pool, crate::db::DEFAULT_USER_ID, auth.account_id,
                None, Some(remote_id), now,
            ).await?;

            // Remove follow + follower relationships
            fieldwork::follows_db::unfollow_remote(
                &state.pool, auth.account_id, remote_id,
            ).await?;
            fieldwork::followers_db::remove_follower(
                &state.pool, auth.account_id, remote_id,
            ).await?;

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
            fieldwork::interactions_db::unblock(
                &state.pool, auth.account_id, Some(target_id), None,
            ).await?;

            build_relationship(&state.pool, auth.account_id, target_id)
                .await
                .map(Json)
        }
        TargetAccount::Remote { id: remote_id, .. } => {
            fieldwork::interactions_db::unblock(
                &state.pool, auth.account_id, None, Some(remote_id),
            ).await?;

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

            fieldwork::interactions_db::mute(
                &state.pool, crate::db::DEFAULT_USER_ID, auth.account_id,
                Some(target_id), None, now,
            ).await?;

            build_relationship(&state.pool, auth.account_id, target_id)
                .await
                .map(Json)
        }
        TargetAccount::Remote { id: remote_id, .. } => {
            fieldwork::interactions_db::mute(
                &state.pool, crate::db::DEFAULT_USER_ID, auth.account_id,
                None, Some(remote_id), now,
            ).await?;

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
            fieldwork::interactions_db::unmute(
                &state.pool, auth.account_id, Some(target_id), None,
            ).await?;

            build_relationship(&state.pool, auth.account_id, target_id)
                .await
                .map(Json)
        }
        TargetAccount::Remote { id: remote_id, .. } => {
            fieldwork::interactions_db::unmute(
                &state.pool, auth.account_id, None, Some(remote_id),
            ).await?;

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

    if body.display_name.is_some() || body.note.is_some() {
        let bio_html = body.note.as_ref().map(|n| render_content(n, domain).html);
        fieldwork::persona_db::update_persona_profile(
            &state.pool,
            auth.account_id,
            body.display_name.as_deref(),
            body.note.as_deref(),
            bio_html.as_deref(),
        ).await?;
        changed = true;
    }

    // REMAINING: individual persona field updates — fieldwork::persona_db only has update_persona_profile
    if let Some(locked) = body.locked {
        crate::db_extras::update_persona_bool(&state.pool, auth.account_id, "is_locked", locked).await?;
        changed = true;
    }

    if let Some(bot) = body.bot {
        crate::db_extras::update_persona_bool(&state.pool, auth.account_id, "bot", bot).await?;
        changed = true;
    }

    if let Some(discoverable) = body.discoverable {
        crate::db_extras::update_persona_bool(&state.pool, auth.account_id, "discoverable", discoverable).await?;
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
        crate::db_extras::update_persona_fields(&state.pool, auth.account_id, &fields_str).await?;
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
    let requests: Vec<(i64, i64, i64)> = crate::db_extras::get_follow_requests(&state.pool, auth.account_id).await?;

    let mut accounts = Vec::with_capacity(requests.len());
    for (_req_id, remote_id, _created_at) in &requests {
        let remote: Option<(i64, String, String, String, String)> = crate::db_extras::get_remote_account_by_id(&state.pool, *remote_id).await?;

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
    let request: Option<(i64, String)> = crate::db_extras::find_follow_request(&state.pool, remote_id, auth.account_id).await?;

    let (req_id, follow_ap_id) =
        request.ok_or_else(|| AppError::not_found("Follow request not found"))?;

    let now = now_millis();

    // Accept: insert into followers
    fieldwork::followers_db::add_follower(
        &state.pool, auth.account_id, crate::db::DEFAULT_USER_ID, remote_id, now,
    ).await?;

    // Remove from follow_requests
    crate::db_extras::delete_follow_request(&state.pool, req_id).await?;

    // Send Accept activity
    let remote_row: Option<(String, String, Option<String>)> = crate::db_extras::get_remote_inbox(&state.pool, remote_id).await?;

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
    let request: Option<(i64, String)> = crate::db_extras::find_follow_request(&state.pool, remote_id, auth.account_id).await?;

    let (req_id, follow_ap_id) =
        request.ok_or_else(|| AppError::not_found("Follow request not found"))?;

    // Remove from follow_requests
    crate::db_extras::delete_follow_request(&state.pool, req_id).await?;

    // Send Reject activity
    let remote_row: Option<(String, String, Option<String>)> = crate::db_extras::get_remote_inbox(&state.pool, remote_id).await?;

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
                        let signing: Option<(String, String)> = crate::db_extras::get_persona_signing_key(&state.pool, auth.account_id).await?;

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
        let local_matches: Vec<AccountRow> = crate::db_extras::search_local_personas(&state.pool, &like_pattern, limit).await?;

        for row in &local_matches {
            result_accounts.push(account_to_json(row, domain));
        }

        // Remote account search (reuses escaped like_pattern from above)
        let remote_matches: Vec<(i64, String, String, String, String, bool, bool)> =
            crate::db_extras::search_remote_accounts(&state.pool, &like_pattern, limit).await?;

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

        let tags_vec: Vec<String> = crate::db_extras::search_tags(&state.pool, &like_pattern, limit).await?;

        for tag in &tags_vec {
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
                    let post = crate::posting::get_local_post(&state.pool, pid).await?;

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

    let tags = fieldwork::followed_tags_db::get_followed_tags(
        &state.pool,
        auth.account_id,
    )
    .await?;

    let result: Vec<Value> = tags
        .iter()
        .take(limit as usize)
        .map(|(tag, _created_at)| tag_json(tag, domain, true))
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

    fieldwork::followed_tags_db::follow_tag(
        &state.pool,
        auth.account_id,
        &tag,
        now,
    )
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

    fieldwork::followed_tags_db::unfollow_tag(
        &state.pool,
        auth.account_id,
        &tag,
    )
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
        let fwp = state.pool.clone();
        let token_info = fieldwork::oauth_db::verify_token(&fwp, &token_hash).await?;

        if let Some((aid, _username, _scopes)) = token_info {
            fieldwork::followed_tags_db::is_following_tag(&fwp, aid, &tag).await?
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
