use anyhow::{Context, Result};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::SqlitePool;
use std::str::FromStr;

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

    initialize_schema(&pool).await?;
    Ok(pool)
}

async fn initialize_schema(pool: &SqlitePool) -> Result<()> {
    sqlx::raw_sql(SCHEMA)
        .execute(pool)
        .await
        .context("Failed to initialize database schema")?;
    Ok(())
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS admin (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    password_hash TEXT NOT NULL,
    totp_secret   TEXT,
    created_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS accounts (
    id              INTEGER PRIMARY KEY,
    username        TEXT NOT NULL UNIQUE,
    display_name    TEXT NOT NULL,
    bio             TEXT NOT NULL DEFAULT '',
    bio_html        TEXT NOT NULL DEFAULT '',
    private_key_pem TEXT NOT NULL,
    public_key_pem  TEXT NOT NULL,
    avatar_media_id INTEGER,
    header_media_id INTEGER,
    is_locked       INTEGER NOT NULL DEFAULT 0,
    discoverable    INTEGER NOT NULL DEFAULT 1,
    bot             INTEGER NOT NULL DEFAULT 0,
    fields_json     TEXT NOT NULL DEFAULT '[]',
    created_at      INTEGER NOT NULL,
    last_status_at  INTEGER
);
CREATE INDEX IF NOT EXISTS idx_accounts_username ON accounts(username);

CREATE TABLE IF NOT EXISTS remote_accounts (
    id                  INTEGER PRIMARY KEY,
    actor_uri           TEXT NOT NULL UNIQUE,
    username            TEXT NOT NULL,
    domain              TEXT NOT NULL,
    display_name        TEXT NOT NULL,
    bio_html            TEXT NOT NULL DEFAULT '',
    avatar_url          TEXT,
    header_url          TEXT,
    public_key_pem      TEXT NOT NULL,
    public_key_id       TEXT NOT NULL UNIQUE,
    inbox_url           TEXT NOT NULL,
    shared_inbox_url    TEXT,
    followers_url       TEXT,
    is_locked           INTEGER NOT NULL DEFAULT 0,
    bot                 INTEGER NOT NULL DEFAULT 0,
    last_fetched_at     INTEGER NOT NULL,
    fetched_failed_at   INTEGER,
    fetch_fail_count    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_remote_accounts_webfinger ON remote_accounts(username, domain);

CREATE TABLE IF NOT EXISTS posts (
    id                INTEGER PRIMARY KEY,
    account_id        INTEGER NOT NULL REFERENCES accounts(id),
    ap_id             TEXT NOT NULL UNIQUE,
    in_reply_to_id    INTEGER,
    in_reply_to_uri   TEXT,
    boost_of_id       INTEGER,
    boost_of_uri      TEXT,
    content           TEXT NOT NULL,
    content_html      TEXT NOT NULL,
    spoiler_text      TEXT NOT NULL DEFAULT '',
    visibility        TEXT NOT NULL,
    sensitive         INTEGER NOT NULL DEFAULT 0,
    language          TEXT,
    created_at        INTEGER NOT NULL,
    edited_at         INTEGER
);
CREATE INDEX IF NOT EXISTS idx_posts_account_created ON posts(account_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_posts_in_reply_to ON posts(in_reply_to_id);

CREATE TABLE IF NOT EXISTS remote_posts (
    id                INTEGER PRIMARY KEY,
    ap_uri            TEXT NOT NULL UNIQUE,
    remote_account_id INTEGER NOT NULL REFERENCES remote_accounts(id),
    in_reply_to_uri   TEXT,
    content_html      TEXT NOT NULL,
    spoiler_text      TEXT NOT NULL DEFAULT '',
    visibility        TEXT NOT NULL,
    sensitive         INTEGER NOT NULL DEFAULT 0,
    language          TEXT,
    created_at        INTEGER NOT NULL,
    fetched_at        INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_remote_posts_account_created ON remote_posts(remote_account_id, created_at DESC);

CREATE TABLE IF NOT EXISTS mentions (
    post_id            INTEGER,
    remote_post_id     INTEGER,
    mentioned_account_id INTEGER,
    mentioned_remote_id  INTEGER,
    CHECK ((post_id IS NOT NULL) != (remote_post_id IS NOT NULL)),
    CHECK ((mentioned_account_id IS NOT NULL) != (mentioned_remote_id IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS idx_mentions_post ON mentions(post_id);
CREATE INDEX IF NOT EXISTS idx_mentions_local ON mentions(mentioned_account_id);

CREATE TABLE IF NOT EXISTS media (
    id             INTEGER PRIMARY KEY,
    account_id     INTEGER NOT NULL REFERENCES accounts(id),
    post_id        INTEGER REFERENCES posts(id),
    file_path      TEXT NOT NULL,
    mime_type      TEXT NOT NULL,
    file_size      INTEGER NOT NULL,
    width          INTEGER,
    height         INTEGER,
    blurhash       TEXT,
    description    TEXT NOT NULL DEFAULT '',
    created_at     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS follows (
    follower_id         INTEGER NOT NULL REFERENCES accounts(id),
    followee_id         INTEGER REFERENCES accounts(id),
    followee_remote_id  INTEGER REFERENCES remote_accounts(id),
    created_at          INTEGER NOT NULL,
    show_reblogs        INTEGER NOT NULL DEFAULT 1,
    notify              INTEGER NOT NULL DEFAULT 0,
    CHECK ((followee_id IS NOT NULL) != (followee_remote_id IS NOT NULL)),
    UNIQUE (follower_id, followee_id, followee_remote_id)
);
CREATE INDEX IF NOT EXISTS idx_follows_follower ON follows(follower_id);
CREATE INDEX IF NOT EXISTS idx_follows_followee ON follows(followee_id);
CREATE INDEX IF NOT EXISTS idx_follows_followee_remote ON follows(followee_remote_id);

CREATE TABLE IF NOT EXISTS follow_requests (
    id                  INTEGER PRIMARY KEY,
    requester_remote_id INTEGER NOT NULL REFERENCES remote_accounts(id),
    target_account_id   INTEGER NOT NULL REFERENCES accounts(id),
    ap_id               TEXT NOT NULL UNIQUE,
    created_at          INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS followers (
    local_account_id    INTEGER NOT NULL REFERENCES accounts(id),
    remote_account_id   INTEGER NOT NULL REFERENCES remote_accounts(id),
    accepted_at         INTEGER NOT NULL,
    UNIQUE (local_account_id, remote_account_id)
);
CREATE INDEX IF NOT EXISTS idx_followers_local ON followers(local_account_id);

CREATE TABLE IF NOT EXISTS favourites (
    account_id      INTEGER NOT NULL REFERENCES accounts(id),
    post_id         INTEGER REFERENCES posts(id),
    remote_post_id  INTEGER REFERENCES remote_posts(id),
    created_at      INTEGER NOT NULL,
    CHECK ((post_id IS NOT NULL) != (remote_post_id IS NOT NULL)),
    UNIQUE (account_id, post_id, remote_post_id)
);

CREATE TABLE IF NOT EXISTS notifications (
    id             INTEGER PRIMARY KEY,
    account_id     INTEGER NOT NULL REFERENCES accounts(id),
    kind           TEXT NOT NULL,
    from_account_id        INTEGER REFERENCES accounts(id),
    from_remote_account_id INTEGER REFERENCES remote_accounts(id),
    post_id        INTEGER REFERENCES posts(id),
    remote_post_id INTEGER REFERENCES remote_posts(id),
    created_at     INTEGER NOT NULL,
    read_at        INTEGER
);
CREATE INDEX IF NOT EXISTS idx_notifications_account_created ON notifications(account_id, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_notifications_dedup ON notifications(account_id, kind, COALESCE(from_account_id, 0), COALESCE(from_remote_account_id, 0), COALESCE(post_id, 0), COALESCE(remote_post_id, 0));

CREATE TABLE IF NOT EXISTS oauth_apps (
    id            INTEGER PRIMARY KEY,
    client_id     TEXT NOT NULL UNIQUE,
    client_secret TEXT NOT NULL,
    name          TEXT NOT NULL,
    website       TEXT,
    redirect_uri  TEXT NOT NULL,
    scopes        TEXT NOT NULL,
    created_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_tokens (
    id             INTEGER PRIMARY KEY,
    token_hash     TEXT NOT NULL UNIQUE,
    app_id         INTEGER NOT NULL REFERENCES oauth_apps(id),
    account_id     INTEGER REFERENCES accounts(id),
    scopes         TEXT NOT NULL,
    created_at     INTEGER NOT NULL,
    last_used_at   INTEGER,
    revoked_at     INTEGER
);

CREATE TABLE IF NOT EXISTS oauth_authz_codes (
    code_hash     TEXT PRIMARY KEY,
    app_id        INTEGER NOT NULL REFERENCES oauth_apps(id),
    account_id    INTEGER NOT NULL REFERENCES accounts(id),
    scopes        TEXT NOT NULL,
    redirect_uri  TEXT NOT NULL,
    expires_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS domain_blocks (
    domain         TEXT PRIMARY KEY,
    severity       TEXT NOT NULL,
    reject_media   INTEGER NOT NULL DEFAULT 0,
    reject_reports INTEGER NOT NULL DEFAULT 0,
    reason         TEXT NOT NULL DEFAULT '',
    created_at     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS delivery_queue (
    id             INTEGER PRIMARY KEY,
    target_inbox   TEXT NOT NULL,
    sender_account_id INTEGER NOT NULL REFERENCES accounts(id),
    activity_json  TEXT NOT NULL,
    attempts       INTEGER NOT NULL DEFAULT 0,
    next_attempt_at INTEGER NOT NULL,
    last_error     TEXT,
    created_at     INTEGER NOT NULL,
    delivered_at   INTEGER,
    dead_at        INTEGER
);
CREATE INDEX IF NOT EXISTS idx_delivery_pending ON delivery_queue(next_attempt_at) WHERE delivered_at IS NULL AND dead_at IS NULL;

CREATE TABLE IF NOT EXISTS idempotency_keys (
    key_hash       TEXT PRIMARY KEY,
    account_id     INTEGER NOT NULL REFERENCES accounts(id),
    post_id        INTEGER NOT NULL REFERENCES posts(id),
    created_at     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS also_known_as (
    account_id     INTEGER NOT NULL REFERENCES accounts(id),
    uri            TEXT NOT NULL,
    UNIQUE (account_id, uri)
);

CREATE TABLE IF NOT EXISTS bookmarks (
    account_id     INTEGER NOT NULL REFERENCES accounts(id),
    post_id        INTEGER REFERENCES posts(id),
    remote_post_id INTEGER REFERENCES remote_posts(id),
    created_at     INTEGER NOT NULL,
    UNIQUE (account_id, post_id, remote_post_id)
);

CREATE TABLE IF NOT EXISTS markers (
    account_id     INTEGER NOT NULL REFERENCES accounts(id),
    timeline       TEXT NOT NULL,
    last_read_id   TEXT NOT NULL,
    version        INTEGER NOT NULL DEFAULT 0,
    updated_at     INTEGER NOT NULL,
    UNIQUE (account_id, timeline)
);

CREATE TABLE IF NOT EXISTS post_tags (
    post_id        INTEGER NOT NULL REFERENCES posts(id),
    tag             TEXT NOT NULL,
    UNIQUE (post_id, tag)
);
CREATE INDEX IF NOT EXISTS idx_post_tags_tag ON post_tags(tag);

CREATE TABLE IF NOT EXISTS pinned_posts (
    account_id INTEGER NOT NULL REFERENCES accounts(id),
    post_id    INTEGER NOT NULL REFERENCES posts(id),
    pinned_at  INTEGER NOT NULL,
    UNIQUE (account_id, post_id)
);

CREATE TABLE IF NOT EXISTS lists (
    id             INTEGER PRIMARY KEY,
    account_id     INTEGER NOT NULL REFERENCES accounts(id),
    title          TEXT NOT NULL,
    replies_policy TEXT NOT NULL DEFAULT 'list',
    created_at     INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS list_accounts (
    list_id    INTEGER NOT NULL REFERENCES lists(id) ON DELETE CASCADE,
    account_id INTEGER NOT NULL,
    UNIQUE (list_id, account_id)
);

CREATE TABLE IF NOT EXISTS followed_tags (
    account_id INTEGER NOT NULL REFERENCES accounts(id),
    tag        TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE (account_id, tag)
);

CREATE TABLE IF NOT EXISTS filters (
    id            INTEGER PRIMARY KEY,
    account_id    INTEGER NOT NULL REFERENCES accounts(id),
    title         TEXT NOT NULL,
    context       TEXT NOT NULL DEFAULT '[]',
    filter_action TEXT NOT NULL DEFAULT 'warn',
    expires_at    INTEGER,
    created_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS filter_keywords (
    id         INTEGER PRIMARY KEY,
    filter_id  INTEGER NOT NULL REFERENCES filters(id) ON DELETE CASCADE,
    keyword    TEXT NOT NULL,
    whole_word INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS scheduled_statuses (
    id            INTEGER PRIMARY KEY,
    account_id    INTEGER NOT NULL REFERENCES accounts(id),
    scheduled_at  INTEGER NOT NULL,
    params_json   TEXT NOT NULL,
    created_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scheduled_due ON scheduled_statuses(scheduled_at);
"#;

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
