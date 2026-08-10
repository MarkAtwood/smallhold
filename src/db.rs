use anyhow::{Context, Result};
use fieldwork_db::db::sqlx;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use std::str::FromStr;

/// The single owner user ID. Matches fieldwork's LEGACY_SMALLHOLD migration
/// value (1000000000001) and is used for all user-level columns.
pub const DEFAULT_USER_ID: i64 = 1_000_000_000_001;

/// Ensure the default single-user row exists. Called on startup and before
/// persona creation on fresh installs.
pub async fn ensure_default_user(pool: &fieldwork_db::db::Pool) -> Result<()> {
    let existing = fieldwork_db::tenant_db::get_user_by_id(pool, DEFAULT_USER_ID).await?;
    if existing.is_none() {
        let now = crate::api::now_millis();
        fieldwork_db::tenant_db::create_user(pool, DEFAULT_USER_ID, "admin@localhost", None, "admin", now)
            .await
            .context("Failed to ensure default user")?;
    }
    Ok(())
}

pub async fn create_pool(database_path: &str) -> Result<fieldwork_db::db::Pool> {
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

    let pool = fieldwork_db::db::Pool::Sqlite(sqlite_pool.clone());

    // Delegate schema creation and migration to fieldwork's canonical schema.
    fieldwork_db::db::migrate_full(&pool, Some(&fieldwork_db::db::LEGACY_SMALLHOLD), &[])
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
pub async fn begin_tx(pool: &fieldwork_db::db::Pool) -> Result<sqlx::Transaction<'static, sqlx::Sqlite>> {
    match pool {
        fieldwork_db::db::Pool::Sqlite(sq) => sq.begin().await.context("Failed to begin transaction"),
    }
}

/// Create an in-memory pool for tests.
#[cfg(test)]
pub async fn test_pool() -> fieldwork_db::db::Pool {
    create_pool("sqlite::memory:").await.unwrap()
}

/// Build a test AppState with in-memory DB and dummy config.
#[cfg(test)]
pub async fn test_app_state() -> std::sync::Arc<crate::server::AppState> {
    let pool = test_pool().await;
    let config: crate::config::Config = toml::from_str(
        r#"
[server]
listen = "127.0.0.1:0"
domain = "test.example.com"
secret_key = "test-secret-key-at-least-32-chars-long!!"

[storage]
database_path = ":memory:"
media_dir = "/tmp/smallhold-test-media"

[federation]
[limits]
[defaults]
"#,
    )
    .unwrap();
    std::sync::Arc::new(crate::server::AppState {
        config,
        pool,
        search: None,
    })
}

/// Insert an admin row with a known password hash for testing.
#[cfg(test)]
pub async fn test_set_admin_password(pool: &fieldwork_db::db::Pool, password: &str) {
    use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
    let salt = SaltString::generate(&mut rand::thread_rng());
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string();
    match pool {
        fieldwork_db::db::Pool::Sqlite(sq) => {
            sqlx::query("INSERT OR REPLACE INTO admin (id, password_hash, created_at) VALUES (1, ?, 0)")
                .bind(&hash)
                .execute(sq)
                .await
                .unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_pool() {
        let pool = test_pool().await;
        // Verify tables exist — extract the inner SqlitePool for the raw query
        match &pool {
            fieldwork_db::db::Pool::Sqlite(sq) => {
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
