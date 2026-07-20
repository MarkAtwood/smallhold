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
