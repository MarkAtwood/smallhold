use anyhow::{Context, Result};
use fieldwork::db::sqlx;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use std::str::FromStr;

/// The single owner user ID. Matches fieldwork's LEGACY_SMALLHOLD migration
/// value (1000000000001) and is used for all user-level columns.
pub const DEFAULT_USER_ID: i64 = 1_000_000_000_001;

/// Ensure the default single-user row exists. Called on startup and before
/// persona creation on fresh installs.
pub async fn ensure_default_user(pool: &fieldwork::db::Pool) -> Result<()> {
    let existing = fieldwork::tenant_db::get_user_by_id(pool, DEFAULT_USER_ID).await?;
    if existing.is_none() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        fieldwork::tenant_db::create_user(pool, DEFAULT_USER_ID, "admin@localhost", None, "admin", now)
            .await
            .context("Failed to ensure default user")?;
    }
    Ok(())
}

pub async fn create_pool(database_path: &str) -> Result<fieldwork::db::Pool> {
    let options = SqliteConnectOptions::from_str(database_path)?
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .foreign_keys(true)
        .create_if_missing(true)
        .busy_timeout(std::time::Duration::from_secs(5))
        .pragma("cache_size", "-64000");

    let sqlite_pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await
        .context("Failed to connect to SQLite database")?;

    let pool = fieldwork::db::Pool::Sqlite(sqlite_pool.clone());

    // Delegate schema creation and migration to fieldwork's canonical schema.
    fieldwork::db::migrate_full(&pool, Some(&fieldwork::db::LEGACY_SMALLHOLD), &[])
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
    .execute(&sqlite_pool)
    .await
    .context("Failed to create admin table")?;

    // Ensure the single-owner user row exists for FK references.
    ensure_default_user(&pool).await?;

    Ok(pool)
}

/// Begin a SQLite transaction from the pool abstraction.
pub async fn begin_tx(pool: &fieldwork::db::Pool) -> Result<sqlx::Transaction<'static, sqlx::Sqlite>> {
    match pool {
        fieldwork::db::Pool::Sqlite(sq) => sq.begin().await.context("Failed to begin transaction"),
    }
}

/// Create an in-memory pool for tests.
#[cfg(test)]
pub async fn test_pool() -> fieldwork::db::Pool {
    create_pool("sqlite::memory:").await.unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_pool() {
        let pool = test_pool().await;
        // Verify tables exist — extract the inner SqlitePool for the raw query
        match &pool {
            fieldwork::db::Pool::Sqlite(sq) => {
                let result: (i64,) =
                    sqlx::query_as("SELECT COUNT(*) FROM sqlite_master WHERE type='table'")
                        .fetch_one(sq)
                        .await
                        .unwrap();
                assert!(
                    result.0 >= 20,
                    "Expected at least 20 tables, got {}",
                    result.0
                );
            }
        }
    }
}
