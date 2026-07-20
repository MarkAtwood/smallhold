use anyhow::{Context, Result};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::SqlitePool;
use std::str::FromStr;

/// The single owner user ID. Matches the legacy migration value and is used
/// for all user-level columns in the canonical schema.
pub const DEFAULT_USER_ID: &str = "legacy-owner";

/// Ensure the default single-user row exists. Called on startup and before
/// persona creation on fresh installs.
pub async fn ensure_default_user(pool: &SqlitePool) -> Result<()> {
    let fwp = fieldwork::db::Pool::Sqlite(pool.clone());
    let existing = fieldwork::tenant_db::get_user_by_id(&fwp, DEFAULT_USER_ID).await?;
    if existing.is_none() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        fieldwork::tenant_db::create_user(&fwp, DEFAULT_USER_ID, "admin@localhost", None, "admin", now)
            .await
            .context("Failed to ensure default user")?;
    }
    Ok(())
}

pub async fn create_pool(database_path: &str) -> Result<SqlitePool> {
    let options = SqliteConnectOptions::from_str(database_path)?
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .foreign_keys(true)
        .create_if_missing(true)
        .busy_timeout(std::time::Duration::from_secs(5))
        .pragma("cache_size", "-64000");

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await
        .context("Failed to connect to SQLite database")?;

    // Delegate schema creation and migration to fieldwork's canonical schema.
    let fw_pool = fieldwork::db::Pool::Sqlite(pool.clone());
    fieldwork::db::migrate_full(&fw_pool, Some(&fieldwork::db::LEGACY_SMALLHOLD), &[])
        .await
        .context("Failed to run fieldwork schema migrations")?;

    // Ensure the admin table exists (smallhold-specific, not in fieldwork schema).
    sqlx::raw_sql(
        "CREATE TABLE IF NOT EXISTS admin (
            id            INTEGER PRIMARY KEY CHECK (id = 1),
            password_hash TEXT NOT NULL,
            totp_secret   TEXT,
            created_at    INTEGER NOT NULL
        )"
    )
    .execute(&pool)
    .await
    .context("Failed to create admin table")?;

    // Ensure the single-owner user row exists for FK references.
    ensure_default_user(&pool).await?;

    Ok(pool)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_pool() {
        let pool = create_pool("sqlite::memory:").await.unwrap();
        // Verify tables exist
        let result: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM sqlite_master WHERE type='table'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(
            result.0 >= 20,
            "Expected at least 20 tables, got {}",
            result.0
        );
    }
}
