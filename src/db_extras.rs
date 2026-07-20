//! Smallhold-specific database queries that don't belong in fieldwork.
//!
//! Covers: admin table operations, aggregate statistics, dynamic pagination,
//! complex JOINs for timelines, and test fixtures.

use sqlx::SqlitePool;

// ---------------------------------------------------------------------------
// Admin table (smallhold-specific, not in fieldwork schema)
// ---------------------------------------------------------------------------

/// Fetch the admin password hash. Returns None if no admin password is set.
pub async fn get_admin_password_hash(pool: &SqlitePool) -> Result<Option<String>, sqlx::Error> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT password_hash FROM admin WHERE id = 1")
            .fetch_optional(pool)
            .await?;
    Ok(row.map(|(h,)| h))
}

/// Upsert the admin password hash.
pub async fn set_admin_password(pool: &SqlitePool, hash: &str, now: i64) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO admin (id, password_hash, created_at) VALUES (1, ?, ?) \
         ON CONFLICT(id) DO UPDATE SET password_hash = excluded.password_hash",
    )
    .bind(hash)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Aggregate statistics (instance endpoints)
// ---------------------------------------------------------------------------

/// Count all posts (for instance metadata).
pub async fn total_post_count(pool: &SqlitePool) -> Result<i64, sqlx::Error> {
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM posts")
        .fetch_one(pool)
        .await?;
    Ok(count)
}

/// Count distinct remote domains (for instance metadata).
pub async fn remote_domain_count(pool: &SqlitePool) -> Result<i64, sqlx::Error> {
    let (count,): (i64,) =
        sqlx::query_as("SELECT COUNT(DISTINCT domain) FROM remote_accounts")
            .fetch_one(pool)
            .await?;
    Ok(count)
}

// ---------------------------------------------------------------------------
// OAuth token helpers (smallhold-specific operations)
// ---------------------------------------------------------------------------

/// Update the last_used_at timestamp for a token by hash.
pub async fn touch_token(pool: &SqlitePool, token_hash: &str, now: i64) -> Result<(), sqlx::Error> {
    let _ = sqlx::query("UPDATE oauth_tokens SET last_used_at = ? WHERE token_hash = ?")
        .bind(now)
        .bind(token_hash)
        .execute(pool)
        .await;
    Ok(())
}

/// Find a token ID by its hash (for revocation by token value).
pub async fn find_token_id_by_hash(pool: &SqlitePool, token_hash: &str) -> Result<Option<i64>, sqlx::Error> {
    let row: Option<(i64,)> = sqlx::query_as(
        "SELECT id FROM oauth_tokens WHERE token_hash = ? AND revoked_at IS NULL",
    )
    .bind(token_hash)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(id,)| id))
}

// ---------------------------------------------------------------------------
// Persona field updates (not covered by fieldwork::persona_db)
// ---------------------------------------------------------------------------

/// Update a single boolean field on a persona.
pub async fn update_persona_bool(
    pool: &SqlitePool,
    persona_id: i64,
    field: &str,
    value: bool,
) -> Result<(), sqlx::Error> {
    // ponytail: field name is not user-supplied, comes from hardcoded match arms
    let sql = format!("UPDATE personas SET {field} = ? WHERE id = ?");
    sqlx::query(&sql)
        .bind(value)
        .bind(persona_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Update the fields_json on a persona.
pub async fn update_persona_fields(
    pool: &SqlitePool,
    persona_id: i64,
    fields_json: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE personas SET fields_json = ? WHERE id = ?")
        .bind(fields_json)
        .bind(persona_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Update last_status_at timestamp on a persona.
pub async fn touch_persona_last_status(
    pool: &SqlitePool,
    persona_id: i64,
    now: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE personas SET last_status_at = ? WHERE id = ?")
        .bind(now)
        .bind(persona_id)
        .execute(pool)
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Media attachment helpers
// ---------------------------------------------------------------------------

/// Attach unattached media to a post (conditional UPDATE).
pub async fn attach_media_to_post(
    pool: &SqlitePool,
    post_id: i64,
    media_id: i64,
    persona_id: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE media SET post_id = ? WHERE id = ? AND persona_id = ? AND post_id IS NULL",
    )
    .bind(post_id)
    .bind(media_id)
    .bind(persona_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Update media description.
pub async fn update_media_description(
    pool: &SqlitePool,
    media_id: i64,
    description: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE media SET description = ? WHERE id = ?")
        .bind(description)
        .bind(media_id)
        .execute(pool)
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Posts: queries, lookups, and mutations
// ---------------------------------------------------------------------------

/// Check if a boost already exists for a given persona and post.
pub async fn find_boost(pool: &SqlitePool, persona_id: i64, boost_of_id: i64) -> Result<Option<i64>, sqlx::Error> {
    let row: Option<(i64,)> = sqlx::query_as("SELECT id FROM posts WHERE persona_id = ? AND boost_of_id = ?")
        .bind(persona_id)
        .bind(boost_of_id)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|(id,)| id))
}

/// Check if the viewer has boosted a given post.
pub async fn count_boosts_by_persona(pool: &SqlitePool, persona_id: i64, post_id: i64) -> Result<i64, sqlx::Error> {
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM posts WHERE persona_id = ? AND boost_of_id = ?")
        .bind(persona_id)
        .bind(post_id)
        .fetch_one(pool)
        .await?;
    Ok(count)
}

/// Check if a post is bookmarked by a persona.
pub async fn count_bookmarks(pool: &SqlitePool, persona_id: i64, post_id: i64) -> Result<i64, sqlx::Error> {
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM bookmarks WHERE persona_id = ? AND post_id = ?")
        .bind(persona_id)
        .bind(post_id)
        .fetch_one(pool)
        .await?;
    Ok(count)
}

/// Check if a post is pinned by a persona.
pub async fn is_pinned(pool: &SqlitePool, persona_id: i64, post_id: i64) -> Result<bool, sqlx::Error> {
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM pinned_posts WHERE persona_id = ? AND post_id = ?")
        .bind(persona_id)
        .bind(post_id)
        .fetch_one(pool)
        .await?;
    Ok(count > 0)
}

/// Look up the ap_id of a post by its ID.
pub async fn get_post_ap_id(pool: &SqlitePool, post_id: i64) -> Result<Option<String>, sqlx::Error> {
    let row: Option<(String,)> = sqlx::query_as("SELECT ap_id FROM posts WHERE id = ?")
        .bind(post_id)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|(ap_id,)| ap_id))
}

/// Look up post id and persona_id by ap_id (for inbox Like/Announce lookups).
pub async fn find_post_by_ap_id(pool: &SqlitePool, ap_id: &str) -> Result<Option<(i64, i64)>, sqlx::Error> {
    sqlx::query_as("SELECT id, persona_id FROM posts WHERE ap_id = ? LIMIT 1")
        .bind(ap_id)
        .fetch_optional(pool)
        .await
}

/// Check if a local post exists by ap_id.
pub async fn post_exists_by_ap_id(pool: &SqlitePool, ap_id: &str) -> Result<Option<i64>, sqlx::Error> {
    let row: Option<(i64,)> = sqlx::query_as("SELECT id FROM posts WHERE ap_id = ? LIMIT 1")
        .bind(ap_id)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|(id,)| id))
}

/// Check if a remote post exists by URI.
pub async fn remote_post_exists_by_uri(pool: &SqlitePool, uri: &str) -> Result<Option<i64>, sqlx::Error> {
    let row: Option<(i64,)> = sqlx::query_as("SELECT id FROM remote_posts WHERE ap_uri = ? LIMIT 1")
        .bind(uri)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|(id,)| id))
}

/// Count public posts for a persona.
pub async fn count_public_posts(pool: &SqlitePool, persona_id: i64) -> Result<i64, sqlx::Error> {
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM posts WHERE persona_id = ? AND visibility = 'public'")
        .bind(persona_id)
        .fetch_one(pool)
        .await?;
    Ok(count)
}

/// Count all posts for a persona.
pub async fn count_posts_for_persona(pool: &SqlitePool, persona_id: i64) -> Result<i64, sqlx::Error> {
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM posts WHERE persona_id = ?")
        .bind(persona_id)
        .fetch_one(pool)
        .await?;
    Ok(count)
}

/// Hard delete a post by ID.
pub async fn hard_delete_post(pool: &SqlitePool, post_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM posts WHERE id = ?")
        .bind(post_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Save a post edit history record (INSERT ... SELECT from current post).
pub async fn save_post_edit_history(pool: &SqlitePool, edit_id: i64, post_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO post_edits (id, post_id, content, content_html, spoiler_text, sensitive, created_at) \
         SELECT ?, id, content, content_html, spoiler_text, sensitive, COALESCE(edited_at, created_at) FROM posts WHERE id = ?",
    )
    .bind(edit_id)
    .bind(post_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Update a post's content and metadata (for edit).
pub async fn update_post_full(
    pool: &SqlitePool,
    post_id: i64,
    content: &str,
    content_html: &str,
    spoiler_text: &str,
    sensitive: bool,
    language: &Option<String>,
    edited_at: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE posts SET content = ?, content_html = ?, spoiler_text = ?, \
         sensitive = ?, language = ?, edited_at = ? WHERE id = ?",
    )
    .bind(content)
    .bind(content_html)
    .bind(spoiler_text)
    .bind(sensitive)
    .bind(language)
    .bind(edited_at)
    .bind(post_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Get post edit history.
pub async fn get_post_edits(pool: &SqlitePool, post_id: i64) -> Result<Vec<(String, String, String, bool, i64)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT content, content_html, spoiler_text, sensitive, created_at \
         FROM post_edits WHERE post_id = ? ORDER BY created_at ASC",
    )
    .bind(post_id)
    .fetch_all(pool)
    .await
}

/// Delete a specific reblog notification.
pub async fn delete_reblog_notification(pool: &SqlitePool, from_persona_id: i64, post_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM notifications WHERE kind = 'reblog' AND from_persona_id = ? AND post_id = ?")
        .bind(from_persona_id)
        .bind(post_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Dismiss a single notification by ID and persona.
pub async fn dismiss_notification(pool: &SqlitePool, notif_id: i64, persona_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM notifications WHERE id = ? AND persona_id = ?")
        .bind(notif_id)
        .bind(persona_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Detach media from a post (set post_id to NULL).
pub async fn detach_media_from_post(pool: &SqlitePool, post_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE media SET post_id = NULL WHERE post_id = ?")
        .bind(post_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Delete related rows for a post in a transaction. Caller provides the transaction.
pub async fn delete_post_related<'a>(
    tx: &mut sqlx::Transaction<'a, sqlx::Sqlite>,
    post_id: i64,
) -> Result<(), sqlx::Error> {
    for table in &[
        "DELETE FROM pinned_posts WHERE post_id = ?",
        "DELETE FROM post_tags WHERE post_id = ?",
        "DELETE FROM mentions WHERE post_id = ?",
        "DELETE FROM favourites WHERE post_id = ?",
        "DELETE FROM bookmarks WHERE post_id = ?",
        "DELETE FROM notifications WHERE post_id = ?",
        "DELETE FROM idempotency_keys WHERE post_id = ?",
        "DELETE FROM conversation_read_markers WHERE post_id = ?",
        "DELETE FROM conversation_hidden WHERE post_id = ?",
        "DELETE FROM post_cards WHERE post_id = ?",
    ] {
        sqlx::query(table).bind(post_id).execute(&mut **tx).await?;
    }
    sqlx::query("UPDATE media SET post_id = NULL WHERE post_id = ?")
        .bind(post_id)
        .execute(&mut **tx)
        .await?;
    sqlx::query("DELETE FROM posts WHERE id = ?")
        .bind(post_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Remote accounts and data
// ---------------------------------------------------------------------------

/// Look up a remote account by ID (basic fields).
pub async fn get_remote_account_by_id(
    pool: &SqlitePool,
    id: i64,
) -> Result<Option<(i64, String, String, String, String)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, username, domain, display_name, bio_html FROM remote_accounts WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}

/// Look up a remote account by ID (with inbox fields for interactions).
pub async fn get_remote_account_full(
    pool: &SqlitePool,
    id: i64,
) -> Result<Option<(i64, String, String, Option<String>)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, actor_uri, inbox_url, shared_inbox_url FROM remote_accounts WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}

/// Get the inbox URL for a remote account by actor_uri (preferring shared inbox).
pub async fn get_remote_inbox_by_actor(pool: &SqlitePool, actor_uri: &str) -> Result<Option<String>, sqlx::Error> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT COALESCE(shared_inbox_url, inbox_url) FROM remote_accounts WHERE actor_uri = ?",
    )
    .bind(actor_uri)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(url,)| url))
}

/// Look up a remote account's display name by ID (for test verification).
pub async fn get_remote_display_name(pool: &SqlitePool, id: i64) -> Result<Option<String>, sqlx::Error> {
    let row: Option<(String,)> = sqlx::query_as("SELECT display_name FROM remote_accounts WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|(name,)| name))
}

/// Find a remote account ID by actor_uri.
pub async fn find_remote_by_actor_uri(pool: &SqlitePool, uri: &str) -> Result<Option<i64>, sqlx::Error> {
    let row: Option<(i64,)> = sqlx::query_as("SELECT id FROM remote_accounts WHERE actor_uri = ?")
        .bind(uri)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|(id,)| id))
}

/// Look up a remote account's actor_uri by username and domain.
pub async fn get_remote_actor_uri_by_webfinger(pool: &SqlitePool, username: &str, domain: &str) -> Result<Option<String>, sqlx::Error> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT actor_uri FROM remote_accounts WHERE username = ? AND domain = ?",
    )
    .bind(username)
    .bind(domain)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(uri,)| uri))
}

// ---------------------------------------------------------------------------
// Remote posts
// ---------------------------------------------------------------------------

/// Insert a remote post.
pub async fn insert_remote_post(
    pool: &SqlitePool,
    id: i64,
    ap_uri: &str,
    remote_account_id: i64,
    in_reply_to_uri: Option<&str>,
    context_url: Option<&str>,
    content_html: &str,
    spoiler_text: &str,
    visibility: &str,
    sensitive: bool,
    language: &Option<String>,
    published: i64,
    now: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT OR IGNORE INTO remote_posts \
         (id, ap_uri, remote_account_id, in_reply_to_uri, context_url, content_html, spoiler_text, visibility, sensitive, language, created_at, fetched_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id)
    .bind(ap_uri)
    .bind(remote_account_id)
    .bind(in_reply_to_uri)
    .bind(context_url)
    .bind(content_html)
    .bind(spoiler_text)
    .bind(visibility)
    .bind(sensitive)
    .bind(language)
    .bind(published)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

/// Update a remote post's content (for inbox Update{Note}).
pub async fn update_remote_post(
    pool: &SqlitePool,
    ap_uri: &str,
    remote_account_id: i64,
    content_html: &str,
    spoiler_text: &str,
    sensitive: bool,
    now: i64,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE remote_posts SET content_html = ?, spoiler_text = ?, sensitive = ?, fetched_at = ? \
         WHERE ap_uri = ? AND remote_account_id = ?",
    )
    .bind(content_html)
    .bind(spoiler_text)
    .bind(sensitive)
    .bind(now)
    .bind(ap_uri)
    .bind(remote_account_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Delete a remote post by URI and account (ownership check).
pub async fn delete_remote_post(pool: &SqlitePool, ap_uri: &str, remote_account_id: i64) -> Result<u64, sqlx::Error> {
    let result = sqlx::query("DELETE FROM remote_posts WHERE ap_uri = ? AND remote_account_id = ?")
        .bind(ap_uri)
        .bind(remote_account_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

/// Clean up orphan mentions (referencing deleted remote posts).
pub async fn cleanup_orphan_mentions(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM mentions WHERE remote_post_id NOT IN (SELECT id FROM remote_posts)")
        .execute(pool)
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Cascade deletes for remote account self-deletion
// ---------------------------------------------------------------------------

/// Delete all data associated with a remote account (cascade).
pub async fn cascade_delete_remote_account(pool: &SqlitePool, remote_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM notifications WHERE from_remote_account_id = ?")
        .bind(remote_id).execute(pool).await?;
    sqlx::query("DELETE FROM favourites WHERE remote_post_id IN (SELECT id FROM remote_posts WHERE remote_account_id = ?)")
        .bind(remote_id).execute(pool).await?;
    sqlx::query("DELETE FROM bookmarks WHERE remote_post_id IN (SELECT id FROM remote_posts WHERE remote_account_id = ?)")
        .bind(remote_id).execute(pool).await?;
    sqlx::query("DELETE FROM mentions WHERE remote_post_id IN (SELECT id FROM remote_posts WHERE remote_account_id = ?)")
        .bind(remote_id).execute(pool).await?;
    sqlx::query("DELETE FROM remote_posts WHERE remote_account_id = ?")
        .bind(remote_id).execute(pool).await?;
    sqlx::query("DELETE FROM followers WHERE remote_account_id = ?")
        .bind(remote_id).execute(pool).await?;
    sqlx::query("DELETE FROM follow_requests WHERE requester_remote_id = ?")
        .bind(remote_id).execute(pool).await?;
    sqlx::query("DELETE FROM follows WHERE followee_remote_id = ?")
        .bind(remote_id).execute(pool).await?;
    sqlx::query("DELETE FROM remote_accounts WHERE id = ?")
        .bind(remote_id).execute(pool).await?;
    Ok(())
}

/// Delete all followers by a remote account.
pub async fn delete_followers_by_remote(pool: &SqlitePool, remote_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM followers WHERE remote_account_id = ?")
        .bind(remote_id).execute(pool).await?;
    Ok(())
}

/// Delete all follows to a remote account.
pub async fn delete_follows_to_remote(pool: &SqlitePool, remote_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM follows WHERE followee_remote_id = ?")
        .bind(remote_id).execute(pool).await?;
    Ok(())
}

/// Delete follow requests from a remote account.
pub async fn delete_follow_requests_from_remote(pool: &SqlitePool, remote_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM follow_requests WHERE requester_remote_id = ?")
        .bind(remote_id).execute(pool).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Mentions and notifications for inbox processing
// ---------------------------------------------------------------------------

/// Insert a mention for a remote post.
pub async fn insert_remote_mention(pool: &SqlitePool, remote_post_id: i64, persona_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT OR IGNORE INTO mentions (remote_post_id, mentioned_persona_id) VALUES (?, ?)")
        .bind(remote_post_id)
        .bind(persona_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Check if a mention notification already exists.
pub async fn mention_notification_exists(pool: &SqlitePool, persona_id: i64, remote_post_id: i64) -> Result<bool, sqlx::Error> {
    let (count,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM notifications WHERE persona_id = ? AND kind = 'mention' AND remote_post_id = ?",
    )
    .bind(persona_id)
    .bind(remote_post_id)
    .fetch_one(pool)
    .await?;
    Ok(count > 0)
}

/// Delete favourite notification for a specific actor and post.
pub async fn delete_favourite_notification(pool: &SqlitePool, persona_id: i64, remote_id: i64, post_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query(
        "DELETE FROM notifications WHERE persona_id = ? AND kind = 'favourite' AND from_remote_account_id = ? AND post_id = ?",
    )
    .bind(persona_id)
    .bind(remote_id)
    .bind(post_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Delete reblog notification for a specific actor and post (inbox Undo Announce).
pub async fn delete_remote_reblog_notification(pool: &SqlitePool, persona_id: i64, remote_id: i64, post_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query(
        "DELETE FROM notifications WHERE persona_id = ? AND kind = 'reblog' AND from_remote_account_id = ? AND post_id = ?",
    )
    .bind(persona_id)
    .bind(remote_id)
    .bind(post_id)
    .execute(pool)
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Follow requests
// ---------------------------------------------------------------------------

/// Insert a follow request (locked accounts).
pub async fn insert_follow_request(
    pool: &SqlitePool,
    id: i64,
    requester_remote_id: i64,
    target_persona_id: i64,
    ap_id: &str,
    created_at: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT OR IGNORE INTO follow_requests (id, requester_remote_id, target_persona_id, ap_id, created_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(id)
    .bind(requester_remote_id)
    .bind(target_persona_id)
    .bind(ap_id)
    .bind(created_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// Delete a follow request by requester and target.
pub async fn delete_follow_request_by_remote(pool: &SqlitePool, remote_id: i64, persona_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM follow_requests WHERE requester_remote_id = ? AND target_persona_id = ?")
        .bind(remote_id)
        .bind(persona_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Delete a follow request by ID.
pub async fn delete_follow_request(pool: &SqlitePool, id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM follow_requests WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Get pending follow requests for a persona.
pub async fn get_follow_requests(pool: &SqlitePool, persona_id: i64) -> Result<Vec<(i64, i64, i64)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT fr.id, fr.requester_remote_id, fr.created_at FROM follow_requests fr WHERE fr.target_persona_id = ? ORDER BY fr.created_at DESC",
    )
    .bind(persona_id)
    .fetch_all(pool)
    .await
}

/// Find a follow request by requester and target.
pub async fn find_follow_request(pool: &SqlitePool, remote_id: i64, persona_id: i64) -> Result<Option<(i64, String)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, ap_id FROM follow_requests WHERE requester_remote_id = ? AND target_persona_id = ?",
    )
    .bind(remote_id)
    .bind(persona_id)
    .fetch_optional(pool)
    .await
}

/// Get remote account inbox info by ID.
pub async fn get_remote_inbox(pool: &SqlitePool, id: i64) -> Result<Option<(String, String, Option<String>)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT actor_uri, inbox_url, shared_inbox_url FROM remote_accounts WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}

// ---------------------------------------------------------------------------
// Follows: local relationship queries
// ---------------------------------------------------------------------------

/// Count follows from source to target (local).
pub async fn count_follows_local(pool: &SqlitePool, persona_id: i64, followee_persona_id: i64) -> Result<i64, sqlx::Error> {
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM follows WHERE persona_id = ? AND followee_persona_id = ?")
        .bind(persona_id)
        .bind(followee_persona_id)
        .fetch_one(pool)
        .await?;
    Ok(count)
}

/// Get show_reblogs setting for a local follow.
pub async fn get_follow_show_reblogs(pool: &SqlitePool, persona_id: i64, followee_persona_id: i64) -> Result<Option<bool>, sqlx::Error> {
    let row: Option<(bool,)> = sqlx::query_as(
        "SELECT show_reblogs FROM follows WHERE persona_id = ? AND followee_persona_id = ?",
    )
    .bind(persona_id)
    .bind(followee_persona_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(v,)| v))
}

/// Get show_reblogs setting for a remote follow.
pub async fn get_follow_show_reblogs_remote(pool: &SqlitePool, persona_id: i64, followee_remote_id: i64) -> Result<Option<bool>, sqlx::Error> {
    let row: Option<(bool,)> = sqlx::query_as(
        "SELECT show_reblogs FROM follows WHERE persona_id = ? AND followee_remote_id = ?",
    )
    .bind(persona_id)
    .bind(followee_remote_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(v,)| v))
}

/// Get notify setting for a local follow.
pub async fn get_follow_notify(pool: &SqlitePool, persona_id: i64, followee_persona_id: i64) -> Result<Option<bool>, sqlx::Error> {
    let row: Option<(bool,)> = sqlx::query_as("SELECT notify FROM follows WHERE persona_id = ? AND followee_persona_id = ?")
        .bind(persona_id)
        .bind(followee_persona_id)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|(v,)| v))
}

// ---------------------------------------------------------------------------
// Followers/following lists (with JOINs)
// ---------------------------------------------------------------------------

/// Get local followers of an account (with AccountRow compatible projection).
pub async fn get_local_followers(pool: &SqlitePool, account_id: i64, limit: i64) -> Result<Vec<crate::api::AccountRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT a.id, a.username, a.display_name, a.bio, a.bio_html, a.is_locked, \
         a.discoverable, a.bot, a.fields_json, a.created_at, a.last_status_at \
         FROM follows f JOIN personas a ON f.persona_id = a.id \
         WHERE f.followee_persona_id = ? ORDER BY f.created_at DESC LIMIT ?",
    )
    .bind(account_id)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// Get remote followers of an account.
pub async fn get_remote_followers(pool: &SqlitePool, account_id: i64, limit: i64) -> Result<Vec<(i64, String, String, String, String)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT ra.id, ra.username, ra.domain, ra.display_name, ra.bio_html \
         FROM followers f JOIN remote_accounts ra ON f.remote_account_id = ra.id \
         WHERE f.persona_id = ? ORDER BY f.accepted_at DESC LIMIT ?",
    )
    .bind(account_id)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// Get local accounts that this account follows.
pub async fn get_local_following(pool: &SqlitePool, account_id: i64, limit: i64) -> Result<Vec<crate::api::AccountRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT a.id, a.username, a.display_name, a.bio, a.bio_html, a.is_locked, \
         a.discoverable, a.bot, a.fields_json, a.created_at, a.last_status_at \
         FROM follows f JOIN personas a ON f.followee_persona_id = a.id \
         WHERE f.persona_id = ? AND f.followee_persona_id IS NOT NULL \
         ORDER BY f.created_at DESC LIMIT ?",
    )
    .bind(account_id)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// Get remote accounts that this account follows.
pub async fn get_remote_following(pool: &SqlitePool, account_id: i64, limit: i64) -> Result<Vec<(i64, String, String, String, String)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT ra.id, ra.username, ra.domain, ra.display_name, ra.bio_html \
         FROM follows f JOIN remote_accounts ra ON f.followee_remote_id = ra.id \
         WHERE f.persona_id = ? AND f.followee_remote_id IS NOT NULL \
         ORDER BY f.created_at DESC LIMIT ?",
    )
    .bind(account_id)
    .bind(limit)
    .fetch_all(pool)
    .await
}

// ---------------------------------------------------------------------------
// OAuth: authz codes, apps, tokens, sessions
// ---------------------------------------------------------------------------

/// Insert an OAuth authorization code.
pub async fn insert_authz_code(
    pool: &SqlitePool,
    code_hash: &str,
    app_id: i64,
    user_id: i64,
    persona_id: i64,
    scopes: &str,
    redirect_uri: &str,
    expires_at: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO oauth_authz_codes (code_hash, app_id, user_id, persona_id, scopes, redirect_uri, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(code_hash)
    .bind(app_id)
    .bind(user_id)
    .bind(persona_id)
    .bind(scopes)
    .bind(redirect_uri)
    .bind(expires_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// Consume (atomically fetch and delete) an OAuth authorization code.
pub async fn consume_authz_code(pool: &SqlitePool, code_hash: &str, now: i64) -> Result<Option<(i64, i64, String, String)>, sqlx::Error> {
    sqlx::query_as(
        "DELETE FROM oauth_authz_codes WHERE code_hash = ? AND expires_at > ? RETURNING app_id, persona_id, scopes, redirect_uri",
    )
    .bind(code_hash)
    .bind(now)
    .fetch_optional(pool)
    .await
}

/// Look up an OAuth app by client_id (returning id and client_secret).
pub async fn get_oauth_app_secret(pool: &SqlitePool, client_id: &str) -> Result<Option<(i64, String)>, sqlx::Error> {
    sqlx::query_as("SELECT id, client_secret FROM oauth_apps WHERE client_id = ?")
        .bind(client_id)
        .fetch_optional(pool)
        .await
}

/// Look up the most recent app for an account (for verify_app_credentials).
pub async fn get_app_for_account(pool: &SqlitePool, persona_id: i64) -> Result<Option<(String, Option<String>)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT oa.name, oa.website FROM oauth_tokens ot JOIN oauth_apps oa ON ot.app_id = oa.id WHERE ot.persona_id = ? AND ot.revoked_at IS NULL ORDER BY ot.last_used_at DESC LIMIT 1",
    )
    .bind(persona_id)
    .fetch_optional(pool)
    .await
}

/// List active sessions for a persona.
pub async fn list_sessions(pool: &SqlitePool, persona_id: i64) -> Result<Vec<(i64, String, String, i64, Option<i64>)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT t.id, oa.name, t.scopes, t.created_at, t.last_used_at \
         FROM oauth_tokens t JOIN oauth_apps oa ON t.app_id = oa.id \
         WHERE t.persona_id = ? AND t.revoked_at IS NULL ORDER BY t.created_at",
    )
    .bind(persona_id)
    .fetch_all(pool)
    .await
}

/// Revoke a specific session.
pub async fn revoke_session(pool: &SqlitePool, token_id: i64, persona_id: i64, now: i64) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE oauth_tokens SET revoked_at = ? WHERE id = ? AND persona_id = ? AND revoked_at IS NULL",
    )
    .bind(now)
    .bind(token_id)
    .bind(persona_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Revoke all sessions except the current one.
pub async fn revoke_all_sessions(pool: &SqlitePool, persona_id: i64, except_token_hash: &str, now: i64) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE oauth_tokens SET revoked_at = ? WHERE persona_id = ? AND token_hash != ? AND revoked_at IS NULL",
    )
    .bind(now)
    .bind(persona_id)
    .bind(except_token_hash)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

// ---------------------------------------------------------------------------
// Lists
// ---------------------------------------------------------------------------

/// Create a list.
pub async fn create_list(pool: &SqlitePool, id: i64, user_id: i64, title: &str, replies_policy: &str, now: i64) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO lists (id, user_id, title, replies_policy, created_at) VALUES (?, ?, ?, ?, ?)")
        .bind(id)
        .bind(user_id)
        .bind(title)
        .bind(replies_policy)
        .bind(now)
        .execute(pool)
        .await?;
    Ok(())
}

/// Update a list's title and replies policy.
pub async fn update_list(pool: &SqlitePool, list_id: i64, title: &str, replies_policy: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE lists SET title = ?, replies_policy = ? WHERE id = ?")
        .bind(title)
        .bind(replies_policy)
        .bind(list_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Get accounts in a list.
pub async fn get_list_account_rows(pool: &SqlitePool, list_id: i64) -> Result<Vec<crate::api::AccountRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT a.id, a.username, a.display_name, a.bio, a.bio_html, a.is_locked, \
         a.discoverable, a.bot, a.fields_json, a.created_at, a.last_status_at \
         FROM personas a JOIN list_accounts la ON a.id = la.persona_id \
         WHERE la.list_id = ? ORDER BY a.id",
    )
    .bind(list_id)
    .fetch_all(pool)
    .await
}

// ---------------------------------------------------------------------------
// Filters
// ---------------------------------------------------------------------------

/// Get a filter row (for filter_to_json).
pub async fn get_filter_row(pool: &SqlitePool, filter_id: i64) -> Result<(i64, String, String, String, Option<i64>, i64), sqlx::Error> {
    sqlx::query_as(
        "SELECT id, title, context, filter_action, expires_at, created_at FROM filters WHERE id = ?",
    )
    .bind(filter_id)
    .fetch_one(pool)
    .await
}

/// Get keywords for a filter.
pub async fn get_filter_keywords(pool: &SqlitePool, filter_id: i64) -> Result<Vec<(i64, String, bool)>, sqlx::Error> {
    sqlx::query_as("SELECT id, keyword, whole_word FROM filter_keywords WHERE filter_id = ? ORDER BY id")
        .bind(filter_id)
        .fetch_all(pool)
        .await
}

/// Create a filter.
pub async fn create_filter(
    pool: &SqlitePool,
    id: i64,
    user_id: i64,
    title: &str,
    context_json: &str,
    filter_action: &str,
    expires_at: Option<i64>,
    now: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO filters (id, user_id, title, context, filter_action, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id)
    .bind(user_id)
    .bind(title)
    .bind(context_json)
    .bind(filter_action)
    .bind(expires_at)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

/// Insert a filter keyword.
pub async fn insert_filter_keyword(pool: &SqlitePool, id: i64, filter_id: i64, keyword: &str, whole_word: bool) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO filter_keywords (id, filter_id, keyword, whole_word) VALUES (?, ?, ?, ?)")
        .bind(id)
        .bind(filter_id)
        .bind(keyword)
        .bind(whole_word)
        .execute(pool)
        .await?;
    Ok(())
}

/// Get a filter row for updating.
pub async fn get_filter_for_update(pool: &SqlitePool, filter_id: i64, user_id: i64) -> Result<Option<(i64, String, String, String, Option<i64>)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, title, context, filter_action, expires_at FROM filters WHERE id = ? AND user_id = ?",
    )
    .bind(filter_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await
}

/// Update a filter.
pub async fn update_filter(pool: &SqlitePool, filter_id: i64, title: &str, context_json: &str, filter_action: &str, expires_at: Option<i64>) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE filters SET title = ?, context = ?, filter_action = ?, expires_at = ? WHERE id = ?")
        .bind(title)
        .bind(context_json)
        .bind(filter_action)
        .bind(expires_at)
        .bind(filter_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Delete a filter keyword by ID with ownership check.
pub async fn delete_filter_keyword_owned(pool: &SqlitePool, keyword_id: i64, user_id: i64) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        "DELETE FROM filter_keywords WHERE id = ? AND filter_id IN (SELECT id FROM filters WHERE user_id = ?)",
    )
    .bind(keyword_id)
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// List v1-compatible filter entries (flat keyword list).
pub async fn list_filters_v1(pool: &SqlitePool, user_id: i64) -> Result<Vec<(i64, String, String, bool, Option<i64>)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT fk.id, fk.keyword, f.context, fk.whole_word, f.expires_at \
         FROM filter_keywords fk JOIN filters f ON fk.filter_id = f.id \
         WHERE f.user_id = ? ORDER BY fk.id",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
}

// ---------------------------------------------------------------------------
// Search: persona/remote/tag search
// ---------------------------------------------------------------------------

/// Search local personas by username or display_name.
pub async fn search_local_personas(pool: &SqlitePool, like_pattern: &str, limit: i64) -> Result<Vec<crate::api::AccountRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, username, display_name, bio, bio_html, is_locked, discoverable, \
         bot, fields_json, created_at, last_status_at \
         FROM personas \
         WHERE username LIKE ? ESCAPE '\' OR display_name LIKE ? ESCAPE '\' LIMIT ?",
    )
    .bind(like_pattern)
    .bind(like_pattern)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// Search remote accounts by username or display_name.
pub async fn search_remote_accounts(pool: &SqlitePool, like_pattern: &str, limit: i64) -> Result<Vec<(i64, String, String, String, String, bool, bool)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, username, domain, display_name, bio_html, is_locked, bot \
         FROM remote_accounts \
         WHERE username LIKE ? ESCAPE '\' OR display_name LIKE ? ESCAPE '\' LIMIT ?",
    )
    .bind(like_pattern)
    .bind(like_pattern)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// Search tags by name.
pub async fn search_tags(pool: &SqlitePool, like_pattern: &str, limit: i64) -> Result<Vec<String>, sqlx::Error> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT DISTINCT tag FROM post_tags WHERE tag LIKE ? ESCAPE '\' LIMIT ?",
    )
    .bind(like_pattern)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|(t,)| t).collect())
}

/// Get signing credentials for a persona (for WebFinger resolve search).
pub async fn get_persona_signing_key(pool: &SqlitePool, persona_id: i64) -> Result<Option<(String, String)>, sqlx::Error> {
    sqlx::query_as("SELECT username, private_key_pem FROM personas WHERE id = ?")
        .bind(persona_id)
        .fetch_optional(pool)
        .await
}

// ---------------------------------------------------------------------------
// Account statuses (paginated queries for GET /api/v1/accounts/{id}/statuses)
// ---------------------------------------------------------------------------

/// Get account statuses with max_id pagination.
pub async fn account_statuses_max_id(pool: &SqlitePool, account_id: i64, max_id: i64, limit: i64) -> Result<Vec<crate::api::StatusRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, persona_id, ap_id, content_html, spoiler_text, visibility, sensitive, language, created_at, edited_at FROM posts WHERE persona_id = ? AND id < ? AND visibility IN ('public', 'unlisted') ORDER BY id DESC LIMIT ?",
    )
    .bind(account_id)
    .bind(max_id)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// Get account statuses with min_id pagination.
pub async fn account_statuses_min_id(pool: &SqlitePool, account_id: i64, min_id: i64, limit: i64) -> Result<Vec<crate::api::StatusRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, persona_id, ap_id, content_html, spoiler_text, visibility, sensitive, language, created_at, edited_at FROM posts WHERE persona_id = ? AND id > ? AND visibility IN ('public', 'unlisted') ORDER BY id ASC LIMIT ?",
    )
    .bind(account_id)
    .bind(min_id)
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// Get account statuses (no pagination).
pub async fn account_statuses_default(pool: &SqlitePool, account_id: i64, limit: i64) -> Result<Vec<crate::api::StatusRow>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, persona_id, ap_id, content_html, spoiler_text, visibility, sensitive, language, created_at, edited_at FROM posts WHERE persona_id = ? AND visibility IN ('public', 'unlisted') ORDER BY id DESC LIMIT ?",
    )
    .bind(account_id)
    .bind(limit)
    .fetch_all(pool)
    .await
}

// ---------------------------------------------------------------------------
// CLI-specific queries
// ---------------------------------------------------------------------------

/// List personas (CLI output).
pub async fn list_personas_cli(pool: &SqlitePool) -> Result<Vec<(String, String, String, i64)>, sqlx::Error> {
    sqlx::query_as("SELECT id, username, display_name, created_at FROM personas ORDER BY created_at")
        .fetch_all(pool)
        .await
}

/// Create a persona (CLI).
pub async fn create_persona(
    pool: &SqlitePool,
    id: i64,
    user_id: i64,
    username: &str,
    display_name: &str,
    private_key_pem: &str,
    public_key_pem: &str,
    locked: bool,
    bot: bool,
    now: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO personas (id, user_id, username, display_name, private_key_pem, public_key_pem, is_locked, bot, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id)
    .bind(user_id)
    .bind(username)
    .bind(display_name)
    .bind(private_key_pem)
    .bind(public_key_pem)
    .bind(locked as i32)
    .bind(bot as i32)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

/// Update DID key for the user.
pub async fn update_user_did(pool: &SqlitePool, user_id: i64, did_key: &str, recovery_pubkey: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE users SET did_key = ?, recovery_pubkey = ? WHERE id = ?")
        .bind(did_key)
        .bind(recovery_pubkey)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Set admin password (CLI).
pub async fn cli_set_admin_password(pool: &SqlitePool, hash: &str, now: i64) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO admin (id, password_hash, created_at) VALUES (1, ?, ?) ON CONFLICT(id) DO UPDATE SET password_hash = excluded.password_hash",
    )
    .bind(hash)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

/// List all active tokens (CLI).
pub async fn list_tokens_cli(pool: &SqlitePool) -> Result<Vec<(String, String, String, i64, Option<i64>, String)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT t.id, a.username, t.scopes, t.created_at, t.last_used_at, oa.name \
         FROM oauth_tokens t JOIN personas a ON t.persona_id = a.id \
         JOIN oauth_apps oa ON t.app_id = oa.id \
         WHERE t.revoked_at IS NULL ORDER BY t.created_at",
    )
    .fetch_all(pool)
    .await
}

/// Revoke a token by ID (CLI).
pub async fn revoke_token_cli(pool: &SqlitePool, token_id: i64, now: i64) -> Result<u64, sqlx::Error> {
    let result = sqlx::query("UPDATE oauth_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL")
        .bind(now)
        .bind(token_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

/// Get persona ID by username.
pub async fn get_persona_id_by_username(pool: &SqlitePool, username: &str) -> Result<Option<i64>, sqlx::Error> {
    let row: Option<(i64,)> = sqlx::query_as("SELECT id FROM personas WHERE username = ?")
        .bind(username)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|(id,)| id))
}

/// Revoke all tokens for a persona (CLI).
pub async fn revoke_tokens_for_persona(pool: &SqlitePool, persona_id: i64, now: i64) -> Result<u64, sqlx::Error> {
    let result = sqlx::query("UPDATE oauth_tokens SET revoked_at = ? WHERE persona_id = ? AND revoked_at IS NULL")
        .bind(now)
        .bind(persona_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

/// Revoke all tokens globally (CLI).
pub async fn revoke_all_tokens(pool: &SqlitePool, now: i64) -> Result<u64, sqlx::Error> {
    let result = sqlx::query("UPDATE oauth_tokens SET revoked_at = ? WHERE revoked_at IS NULL")
        .bind(now)
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

/// List sessions for a persona (CLI).
pub async fn list_sessions_cli(pool: &SqlitePool, persona_id: i64) -> Result<Vec<(String, String, String, Option<i64>)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT t.id, oa.name, t.scopes, t.last_used_at \
         FROM oauth_tokens t JOIN oauth_apps oa ON t.app_id = oa.id \
         WHERE t.persona_id = ? AND t.revoked_at IS NULL \
         ORDER BY t.last_used_at DESC NULLS LAST",
    )
    .bind(persona_id)
    .fetch_all(pool)
    .await
}

/// Get or create the CLI app ID.
pub async fn get_cli_app_id(pool: &SqlitePool) -> Result<Option<i64>, sqlx::Error> {
    let row: Option<(i64,)> = sqlx::query_as("SELECT id FROM oauth_apps WHERE client_id = 'cli'")
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|(id,)| id))
}

/// Create the CLI app.
pub async fn create_cli_app(pool: &SqlitePool, id: i64, now: i64) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO oauth_apps (id, client_id, client_secret, name, redirect_uri, scopes, created_at) VALUES (?, 'cli', 'cli', 'CLI', 'urn:ietf:wg:oauth:2.0:oob', 'read write follow', ?)",
    )
    .bind(id)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

/// Add a domain block (CLI).
pub async fn add_domain_block(pool: &SqlitePool, domain: &str, severity: &str, reject_media: bool, reason: &str, now: i64) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO domain_blocks (domain, severity, reject_media, reason, created_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(domain) DO UPDATE SET severity = excluded.severity, reject_media = excluded.reject_media, reason = excluded.reason",
    )
    .bind(domain)
    .bind(severity)
    .bind(reject_media as i32)
    .bind(reason)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

/// List domain blocks (CLI).
pub async fn list_domain_blocks(pool: &SqlitePool) -> Result<Vec<(String, String, String)>, sqlx::Error> {
    sqlx::query_as("SELECT domain, severity, reason FROM domain_blocks ORDER BY domain")
        .fetch_all(pool)
        .await
}

/// Count pending deliveries.
pub async fn count_pending_deliveries(pool: &SqlitePool) -> Result<i64, sqlx::Error> {
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM delivery_queue WHERE delivered_at IS NULL AND dead_at IS NULL")
        .fetch_one(pool)
        .await?;
    Ok(count)
}

/// Count dead deliveries.
pub async fn count_dead_deliveries(pool: &SqlitePool) -> Result<i64, sqlx::Error> {
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM delivery_queue WHERE dead_at IS NOT NULL")
        .fetch_one(pool)
        .await?;
    Ok(count)
}

/// Count delivered items.
pub async fn count_delivered(pool: &SqlitePool) -> Result<i64, sqlx::Error> {
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM delivery_queue WHERE delivered_at IS NOT NULL")
        .fetch_one(pool)
        .await?;
    Ok(count)
}

/// Reset dead deliveries for retry.
pub async fn retry_dead_deliveries(pool: &SqlitePool, now: i64) -> Result<u64, sqlx::Error> {
    let result = sqlx::query("UPDATE delivery_queue SET dead_at = NULL, attempts = 0, next_attempt_at = ? WHERE dead_at IS NOT NULL")
        .bind(now)
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

/// Look up account by DID key (CLI recover).
pub async fn find_account_by_did(pool: &SqlitePool, did_key: &str) -> Result<Option<(i64, String, String)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT u.id, p.username, p.display_name FROM users u JOIN personas p ON p.user_id = u.id WHERE u.did_key = ?",
    )
    .bind(did_key)
    .fetch_optional(pool)
    .await
}

/// Check if user needs DID backfill.
pub async fn user_needs_did(pool: &SqlitePool) -> Result<bool, sqlx::Error> {
    let row: Option<(i64,)> = sqlx::query_as("SELECT id FROM users WHERE did_key IS NULL")
        .fetch_optional(pool)
        .await?;
    Ok(row.is_some())
}

/// List personas for DID backfill.
pub async fn list_personas_for_backfill(pool: &SqlitePool) -> Result<Vec<(i64, String)>, sqlx::Error> {
    sqlx::query_as("SELECT id, username FROM personas ORDER BY created_at")
        .fetch_all(pool)
        .await
}

/// Get first persona (for relay and other commands).
pub async fn get_first_persona_with_key(pool: &SqlitePool) -> Result<Option<(i64, String, String)>, sqlx::Error> {
    sqlx::query_as("SELECT id, username, private_key_pem FROM personas ORDER BY created_at LIMIT 1")
        .fetch_optional(pool)
        .await
}

/// Get first persona (id and username only).
pub async fn get_first_persona(pool: &SqlitePool) -> Result<Option<(i64, String)>, sqlx::Error> {
    sqlx::query_as("SELECT id, username FROM personas ORDER BY created_at LIMIT 1")
        .fetch_optional(pool)
        .await
}

/// Insert a relay subscription.
pub async fn insert_relay(pool: &SqlitePool, id: i64, inbox_url: &str, actor_uri: &str, follow_id: &str, now: i64) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO relays (id, inbox_url, actor_uri, follow_id, state, created_at) VALUES (?, ?, ?, ?, 'pending', ?) \
         ON CONFLICT(inbox_url) DO UPDATE SET state = 'pending', follow_id = excluded.follow_id",
    )
    .bind(id)
    .bind(inbox_url)
    .bind(actor_uri)
    .bind(follow_id)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

/// List relays (CLI).
pub async fn list_relays(pool: &SqlitePool) -> Result<Vec<(String, String, String)>, sqlx::Error> {
    sqlx::query_as("SELECT actor_uri, inbox_url, state FROM relays ORDER BY created_at")
        .fetch_all(pool)
        .await
}

// ---------------------------------------------------------------------------
// ActivityPub: actor, outbox, profile queries
// ---------------------------------------------------------------------------

/// Fetch account row with DID data for AP actor documents.
pub async fn fetch_ap_account(pool: &SqlitePool, username: &str) -> Result<Option<sqlx::sqlite::SqliteRow>, sqlx::Error> {
    sqlx::query(
        "SELECT p.username, p.display_name, p.bio_html, p.public_key_pem, \
         p.is_locked, p.discoverable, p.bot, p.fields_json, p.created_at, \
         u.did_key, u.recovery_pubkey \
         FROM personas p JOIN users u ON p.user_id = u.id \
         WHERE p.username = ? LIMIT 1",
    )
    .bind(username)
    .fetch_optional(pool)
    .await
}

/// Get persona ID by username (for outbox, context, featured).
pub async fn get_persona_id(pool: &SqlitePool, username: &str) -> Result<Option<i64>, sqlx::Error> {
    let row: Option<(i64,)> = sqlx::query_as("SELECT id FROM personas WHERE username = ? LIMIT 1")
        .bind(username)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|(id,)| id))
}

/// List personas for index page.
pub async fn list_personas_display(pool: &SqlitePool) -> Result<Vec<(String, String)>, sqlx::Error> {
    sqlx::query_as("SELECT username, display_name FROM personas ORDER BY created_at")
        .fetch_all(pool)
        .await
}

/// Check if a post exists and belongs to a user.
pub async fn post_exists_for_user(pool: &SqlitePool, post_id: i64, user_id: i64) -> Result<bool, sqlx::Error> {
    let row: Option<(i64,)> = sqlx::query_as("SELECT id FROM posts WHERE id = ? AND user_id = ?")
        .bind(post_id)
        .bind(user_id)
        .fetch_optional(pool)
        .await?;
    Ok(row.is_some())
}

// ---------------------------------------------------------------------------
// Federation: follower sync digest
// ---------------------------------------------------------------------------

/// Get follower actor URIs for a domain (FEP-8fcf sync digest).
pub async fn get_follower_uris_by_domain(pool: &SqlitePool, account_id: i64, target_domain: &str) -> Result<Vec<String>, sqlx::Error> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT ra.actor_uri FROM followers f \
         JOIN remote_accounts ra ON f.remote_account_id = ra.id \
         WHERE f.persona_id = ? AND ra.domain = ?",
    )
    .bind(account_id)
    .bind(target_domain)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|(uri,)| uri).collect())
}

/// Get local followers of a remote account (for Move processing).
pub async fn get_local_followers_of_remote(pool: &SqlitePool, remote_id: i64) -> Result<Vec<(i64, String, String)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT a.id, a.username, a.private_key_pem FROM follows f \
         JOIN personas a ON a.id = f.persona_id WHERE f.followee_remote_id = ?",
    )
    .bind(remote_id)
    .fetch_all(pool)
    .await
}

// ---------------------------------------------------------------------------
// Delivery
// ---------------------------------------------------------------------------

/// Fetch pending deliveries with persona join (for the delivery worker).
pub async fn fetch_pending_deliveries(pool: &SqlitePool, now: i64, limit: i64) -> Result<Vec<sqlx::sqlite::SqliteRow>, sqlx::Error> {
    sqlx::query(
        "SELECT d.id, d.target_inbox, d.sender_persona_id, d.activity_json, d.attempts, \
                a.private_key_pem, a.username \
         FROM delivery_queue d \
         JOIN personas a ON d.sender_persona_id = a.id \
         WHERE d.delivered_at IS NULL AND d.dead_at IS NULL AND d.next_attempt_at <= ? \
         ORDER BY d.next_attempt_at \
         LIMIT ?",
    )
    .bind(now)
    .bind(limit)
    .fetch_all(pool)
    .await
}

// ---------------------------------------------------------------------------
// Feeds
// ---------------------------------------------------------------------------

/// Get public posts for RSS/Atom feeds.
pub async fn get_public_feed_posts(pool: &SqlitePool, account_id: i64) -> Result<Vec<(i64, String, i64)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, content_html, created_at FROM posts \
         WHERE persona_id = ? AND visibility = 'public' AND boost_of_id IS NULL \
         ORDER BY created_at DESC LIMIT 20",
    )
    .bind(account_id)
    .fetch_all(pool)
    .await
}

// ---------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------

/// Get persona ID for import.
pub async fn get_persona_id_for_import(pool: &SqlitePool, username: &str) -> Result<Option<i64>, sqlx::Error> {
    let row: Option<(i64,)> = sqlx::query_as("SELECT id FROM personas WHERE username = ?")
        .bind(username)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|(id,)| id))
}

/// Update persona profile from import.
pub async fn update_persona_profile_import(
    pool: &SqlitePool,
    account_id: i64,
    display_name: &str,
    bio: &str,
    bio_html: &str,
    fields_json: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE personas SET display_name = ?, bio = ?, bio_html = ?, fields_json = ? WHERE id = ?",
    )
    .bind(display_name)
    .bind(bio)
    .bind(bio_html)
    .bind(fields_json)
    .bind(account_id)
    .execute(pool)
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Import transaction queries (operate on Transaction)
// ---------------------------------------------------------------------------

/// Insert a post during import (transaction).
pub async fn import_insert_post<'a>(
    tx: &mut sqlx::Transaction<'a, sqlx::Sqlite>,
    id: i64, user_id: i64, account_id: i64, ap_id: &str, in_reply_to_uri: Option<&str>,
    context_url: &str, content: &str, content_html: &str, spoiler_text: &str,
    visibility: &str, sensitive: bool, language: Option<&str>, published_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO posts (id, user_id, persona_id, ap_id, in_reply_to_uri, context_url, content, content_html, spoiler_text, visibility, sensitive, language, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id).bind(user_id).bind(account_id).bind(ap_id)
    .bind(in_reply_to_uri).bind(context_url).bind(content).bind(content_html)
    .bind(spoiler_text).bind(visibility).bind(sensitive as i32).bind(language).bind(published_ms)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Insert a tag during import (transaction).
pub async fn import_insert_tag<'a>(tx: &mut sqlx::Transaction<'a, sqlx::Sqlite>, post_id: i64, tag: &str) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT OR IGNORE INTO post_tags (post_id, tag) VALUES (?, ?)")
        .bind(post_id)
        .bind(tag)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Find a remote account by actor_uri during import (transaction).
pub async fn import_find_remote_by_uri<'a>(tx: &mut sqlx::Transaction<'a, sqlx::Sqlite>, uri: &str) -> Result<Option<i64>, sqlx::Error> {
    let row: Option<(i64,)> = sqlx::query_as("SELECT id FROM remote_accounts WHERE actor_uri = ?")
        .bind(uri)
        .fetch_optional(&mut **tx)
        .await?;
    Ok(row.map(|(id,)| id))
}

/// Insert a mention during import (transaction).
pub async fn import_insert_mention<'a>(tx: &mut sqlx::Transaction<'a, sqlx::Sqlite>, post_id: i64, remote_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT OR IGNORE INTO mentions (post_id, mentioned_remote_id) VALUES (?, ?)")
        .bind(post_id)
        .bind(remote_id)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Insert media during import (transaction).
pub async fn import_insert_media<'a>(
    tx: &mut sqlx::Transaction<'a, sqlx::Sqlite>,
    id: i64, user_id: i64, account_id: i64, post_id: i64,
    file_path: &str, mime_type: &str, file_size: i64, description: &str, created_at: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO media (id, user_id, persona_id, post_id, file_path, mime_type, file_size, description, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id).bind(user_id).bind(account_id).bind(post_id)
    .bind(file_path).bind(mime_type).bind(file_size).bind(description).bind(created_at)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Search: reindex
// ---------------------------------------------------------------------------

/// Get all posts for search reindexing.
pub async fn get_all_posts_for_search(pool: &SqlitePool) -> Result<Vec<(i64, String, String)>, sqlx::Error> {
    sqlx::query_as("SELECT id, content, persona_id FROM posts ORDER BY id")
        .fetch_all(pool)
        .await
}

// ---------------------------------------------------------------------------
// Webauthn
// ---------------------------------------------------------------------------

/// Get admin password hash (for webauthn registration auth).
pub async fn get_admin_hash_for_webauthn(pool: &SqlitePool) -> Result<Option<String>, sqlx::Error> {
    let row: Option<(String,)> = sqlx::query_as("SELECT password_hash FROM admin WHERE id = 1")
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|(h,)| h))
}

// ---------------------------------------------------------------------------
// Remote timeline (home timeline remote posts)
// ---------------------------------------------------------------------------

/// Fetch remote posts from followed accounts for the home timeline.
#[allow(clippy::type_complexity)]
pub async fn fetch_remote_timeline_posts(
    pool: &SqlitePool,
    account_id: i64,
    limit: i64,
) -> Result<Vec<(i64, String, String, String, i64, String, Option<String>, i64, i64, String, String, Option<String>, Option<String>)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT rp.id, rp.ap_uri, rp.content_html, rp.visibility, rp.created_at, \
         rp.spoiler_text, rp.language, rp.remote_account_id, rp.sensitive, \
         ra.actor_uri, ra.display_name, ra.avatar_url, ra.username \
         FROM remote_posts rp \
         JOIN remote_accounts ra ON rp.remote_account_id = ra.id \
         WHERE rp.remote_account_id IN ( \
             SELECT followee_remote_id FROM follows WHERE persona_id = ? AND followee_remote_id IS NOT NULL \
         ) \
         ORDER BY rp.id DESC LIMIT ?",
    )
    .bind(account_id)
    .bind(limit)
    .fetch_all(pool)
    .await
}

// ---------------------------------------------------------------------------
// Test fixtures (used only in #[cfg(test)] blocks in federation.rs)
// ---------------------------------------------------------------------------

/// Insert a test user (for test fixtures).
pub async fn test_insert_user(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT OR IGNORE INTO users (id, email, display_name, role, created_at) VALUES (1000000000001, 'test@test', 'Test', 'admin', 0)")
        .execute(pool)
        .await?;
    Ok(())
}

/// Insert a test persona (for test fixtures).
pub async fn test_insert_persona(pool: &SqlitePool, id: i64) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO personas (id, user_id, username, display_name, private_key_pem, public_key_pem, created_at) VALUES (?, 1000000000001, 'testuser', 'Test', 'privkey', 'pubkey', 0)",
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Insert a test follower (for test fixtures).
pub async fn test_insert_follower(pool: &SqlitePool, persona_id: i64, user_id: i64, remote_account_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO followers (persona_id, user_id, remote_account_id, accepted_at) VALUES (?, ?, ?, 0)",
    )
    .bind(persona_id)
    .bind(user_id)
    .bind(remote_account_id)
    .execute(pool)
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// ActivityPub: complex JOIN queries for outbox, featured, context, post_page
// ---------------------------------------------------------------------------

/// Get a post for the profile post page (JOIN with persona for username check).
pub async fn get_post_for_page(pool: &SqlitePool, post_id: i64, username: &str) -> Result<Option<(i64, String, i64)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT p.id, p.content_html, p.created_at FROM posts p \
         JOIN personas a ON p.persona_id = a.id \
         WHERE p.id = ? AND a.username = ? AND p.visibility IN ('public', 'unlisted')",
    )
    .bind(post_id)
    .bind(username)
    .fetch_optional(pool)
    .await
}

/// Get outbox posts (public only, with context_url).
pub async fn get_outbox_posts(pool: &SqlitePool, persona_id: i64) -> Result<Vec<(i64, String, Option<String>, i64)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT id, content_html, context_url, created_at \
         FROM posts \
         WHERE persona_id = ? AND visibility = 'public' \
         ORDER BY created_at DESC \
         LIMIT 20",
    )
    .bind(persona_id)
    .fetch_all(pool)
    .await
}

/// Get featured (pinned) posts.
pub async fn get_featured_posts(pool: &SqlitePool, persona_id: i64) -> Result<Vec<(i64, String, Option<String>, i64)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT p.id, p.content_html, p.context_url, p.created_at \
         FROM pinned_posts pp JOIN posts p ON pp.post_id = p.id \
         WHERE pp.persona_id = ? AND p.visibility = 'public' \
         ORDER BY pp.pinned_at DESC",
    )
    .bind(persona_id)
    .fetch_all(pool)
    .await
}

/// Get posts in a context collection (FEP-f228).
pub async fn get_context_posts(pool: &SqlitePool, context_url: &str) -> Result<Vec<(i64, String, Option<String>, i64, String)>, sqlx::Error> {
    sqlx::query_as(
        "SELECT p.id, p.content_html, p.context_url, p.created_at, a.username \
         FROM posts p \
         JOIN personas a ON p.persona_id = a.id \
         WHERE p.context_url = ? \
           AND p.visibility IN ('public', 'unlisted') \
         ORDER BY p.created_at ASC",
    )
    .bind(context_url)
    .fetch_all(pool)
    .await
}

/// Fetch paginated dynamic SQL query (for posting.rs timelines, notifications, etc.).
/// The caller provides the full SQL string and bind values. Limit is appended.
pub async fn execute_dynamic_query(pool: &SqlitePool, sql: &str, binds: &[String], limit: i64) -> Result<Vec<sqlx::sqlite::SqliteRow>, sqlx::Error> {
    let mut query = sqlx::query(sql);
    for b in binds {
        query = query.bind(b);
    }
    query = query.bind(limit);
    query.fetch_all(pool).await
}

/// Execute a raw dynamic SQL query with string bind values (no appended limit).
pub async fn execute_raw_query(pool: &SqlitePool, sql: &str, binds: &[String]) -> Result<Vec<sqlx::sqlite::SqliteRow>, sqlx::Error> {
    let mut query = sqlx::query(sql);
    for b in binds {
        query = query.bind(b);
    }
    query.fetch_all(pool).await
}

/// Fetch a single notification by ID and persona.
pub async fn get_notification_row(pool: &SqlitePool, notif_id: i64, persona_id: i64) -> Result<Option<sqlx::sqlite::SqliteRow>, sqlx::Error> {
    sqlx::query(
        "SELECT id, persona_id, kind, from_persona_id, from_remote_account_id, \
         post_id, created_at \
         FROM notifications WHERE id = ? AND persona_id = ?",
    )
    .bind(notif_id)
    .bind(persona_id)
    .fetch_optional(pool)
    .await
}

