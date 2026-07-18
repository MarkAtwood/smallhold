use crate::config::Config;
use crate::db;
use crate::id::generate_id;
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "smallhold", about = "A minimal fediverse server")]
pub struct Cli {
    /// Path to config file
    #[arg(long, default_value = "config.toml", global = true)]
    pub config: PathBuf,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize database and generate config skeleton
    Init,

    /// Start the server
    Serve,

    /// Manage personas
    #[command(subcommand)]
    Persona(PersonaCommands),

    /// Manage admin account
    #[command(subcommand)]
    Admin(AdminCommands),

    /// Manage OAuth tokens
    #[command(subcommand)]
    Token(TokenCommands),

    /// Follow a remote account
    Follow {
        /// Local persona username
        username: String,
        /// Remote account (user@domain)
        acct: String,
    },

    /// Unfollow a remote account
    Unfollow {
        /// Local persona username
        username: String,
        /// Remote account (user@domain)
        acct: String,
    },

    /// Manage domain blocks
    #[command(subcommand)]
    DomainBlock(DomainBlockCommands),

    /// Inspect delivery queue
    #[command(subcommand)]
    Queue(QueueCommands),
}

#[derive(Subcommand)]
pub enum PersonaCommands {
    /// Create a new persona
    Create {
        /// Username (alphanumeric, lowercase)
        username: String,
        /// Display name
        #[arg(long)]
        display_name: String,
        /// Require manual follow approval
        #[arg(long)]
        locked: bool,
        /// Mark as bot account
        #[arg(long)]
        bot: bool,
    },
    /// List all personas
    List,
    /// Update a persona's profile
    Update {
        username: String,
        #[arg(long)]
        display_name: Option<String>,
        #[arg(long)]
        bio: Option<String>,
    },
    /// Delete a persona
    Delete { username: String },
    /// Rotate a persona's RSA keypair
    RotateKey { username: String },
}

#[derive(Subcommand)]
pub enum AdminCommands {
    /// Set admin password
    SetPassword,
    /// Enable TOTP
    EnableTotp,
}

#[derive(Subcommand)]
pub enum TokenCommands {
    /// Mint a new token for a persona
    Mint {
        username: String,
        #[arg(long, default_value = "read,write,follow")]
        scopes: String,
    },
    /// List all tokens
    List,
    /// Revoke a token
    Revoke { token_id: String },
}

#[derive(Subcommand)]
pub enum DomainBlockCommands {
    /// Block a domain
    Add {
        domain: String,
        #[arg(long, default_value = "suspend")]
        severity: String,
        #[arg(long)]
        reject_media: bool,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Unblock a domain
    Remove { domain: String },
    /// List blocked domains
    List,
}

#[derive(Subcommand)]
pub enum QueueCommands {
    /// Show pending deliveries
    Inspect,
    /// Retry permanently failed deliveries
    RetryDead,
}

impl Cli {
    pub async fn run(self) -> Result<()> {
        match self.command {
            Commands::Init => cmd_init(&self.config).await,
            Commands::Serve => cmd_serve(&self.config).await,
            Commands::Persona(cmd) => cmd_persona(cmd, &self.config).await,
            Commands::Admin(cmd) => cmd_admin(cmd, &self.config).await,
            Commands::Token(cmd) => cmd_token(cmd, &self.config).await,
            Commands::Follow { username, acct } => {
                eprintln!("Follow {acct} as {username} — not yet implemented");
                Ok(())
            }
            Commands::Unfollow { username, acct } => {
                eprintln!("Unfollow {acct} as {username} — not yet implemented");
                Ok(())
            }
            Commands::DomainBlock(cmd) => cmd_domain_block(cmd, &self.config).await,
            Commands::Queue(cmd) => cmd_queue(cmd, &self.config).await,
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn generate_secret_key() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex_encode(&bytes)
}

async fn cmd_init(config_path: &Path) -> Result<()> {
    if config_path.exists() {
        anyhow::bail!("Config file already exists: {}", config_path.display());
    }

    let secret_key = generate_secret_key();

    let config_content = format!(
        r#"[server]
listen = "127.0.0.1:8080"
domain = "yourdomain.example"
secret_key = "{secret_key}"

[storage]
database_path = "smallhold.db"
media_dir = "media"

[federation]
user_agent = "smallhold/0.1"
delivery_timeout_secs = 30
delivery_concurrency = 16
fetch_timeout_secs = 20
max_incoming_body_mb = 10
authorized_fetch = true

[limits]
max_post_chars = 5000
max_attachments = 4
max_media_mb = 40

[defaults]
default_visibility = "public"
default_sensitive = false
default_language = "en"
"#
    );

    std::fs::write(config_path, &config_content)
        .with_context(|| format!("Failed to write config: {}", config_path.display()))?;

    let config = Config::load(config_path)?;

    std::fs::create_dir_all(&config.storage.media_dir)
        .with_context(|| format!("Failed to create media dir: {}", config.storage.media_dir))?;

    let _pool = db::create_pool(&config.storage.database_path).await?;

    eprintln!("Initialized smallhold:");
    eprintln!("  Config: {}", config_path.display());
    eprintln!("  Database: {}", config.storage.database_path);
    eprintln!("  Media: {}", config.storage.media_dir);
    eprintln!();
    eprintln!(
        "Edit {} and set your domain before starting.",
        config_path.display()
    );

    Ok(())
}

async fn cmd_serve(config_path: &Path) -> Result<()> {
    let config = Config::load(config_path)?;
    let pool = db::create_pool(&config.storage.database_path).await?;

    let state = std::sync::Arc::new(crate::server::AppState {
        config: config.clone(),
        pool: pool.clone(),
    });

    // Start delivery worker
    tokio::spawn(crate::delivery::run_delivery_worker(
        pool,
        config.clone(),
    ));

    let app = crate::server::create_router(state);
    let listener = tokio::net::TcpListener::bind(&config.server.listen).await?;
    tracing::info!("Listening on {}", config.server.listen);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("Failed to listen for ctrl_c");
    tracing::info!("Shutting down");
}

async fn cmd_persona(cmd: PersonaCommands, config_path: &Path) -> Result<()> {
    let config = Config::load(config_path)?;
    let pool = db::create_pool(&config.storage.database_path).await?;

    match cmd {
        PersonaCommands::Create {
            username,
            display_name,
            locked,
            bot,
        } => {
            anyhow::ensure!(
                username
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "Username must be lowercase alphanumeric with underscores only"
            );
            anyhow::ensure!(
                !username.is_empty() && username.len() <= 30,
                "Username must be 1-30 characters"
            );

            use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
            use rsa::RsaPrivateKey;

            let mut rng = rand::thread_rng();
            let private_key =
                RsaPrivateKey::new(&mut rng, 2048).context("Failed to generate RSA keypair")?;
            let private_key_pem = private_key
                .to_pkcs8_pem(LineEnding::LF)
                .context("Failed to encode private key")?;
            let public_key_pem = private_key
                .to_public_key()
                .to_public_key_pem(LineEnding::LF)
                .context("Failed to encode public key")?;

            let id = generate_id();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64;

            sqlx::query(
                "INSERT INTO accounts (id, username, display_name, private_key_pem, public_key_pem, is_locked, bot, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(id)
            .bind(&username)
            .bind(&display_name)
            .bind(private_key_pem.as_str())
            .bind(&public_key_pem)
            .bind(locked as i32)
            .bind(bot as i32)
            .bind(now)
            .execute(&pool)
            .await
            .context("Failed to create persona (username may already exist)")?;

            eprintln!("Created persona: @{username} (id: {id})");
        }
        PersonaCommands::List => {
            let rows: Vec<(i64, String, String, i64)> = sqlx::query_as(
                "SELECT id, username, display_name, created_at FROM accounts ORDER BY created_at",
            )
            .fetch_all(&pool)
            .await?;

            if rows.is_empty() {
                eprintln!("No personas.");
            } else {
                for (id, username, display_name, _created_at) in rows {
                    eprintln!("  @{username} — {display_name} (id: {id})");
                }
            }
        }
        PersonaCommands::Update {
            username,
            display_name,
            bio,
        } => {
            if let Some(dn) = &display_name {
                sqlx::query("UPDATE accounts SET display_name = ? WHERE username = ?")
                    .bind(dn)
                    .bind(&username)
                    .execute(&pool)
                    .await?;
            }
            if let Some(b) = &bio {
                let html = render_bio(b);
                sqlx::query("UPDATE accounts SET bio = ?, bio_html = ? WHERE username = ?")
                    .bind(b)
                    .bind(&html)
                    .bind(&username)
                    .execute(&pool)
                    .await?;
            }
            eprintln!("Updated @{username}");
        }
        PersonaCommands::Delete { username } => {
            eprintln!("Delete @{username} — not yet implemented (needs federation)");
        }
        PersonaCommands::RotateKey { username } => {
            eprintln!("Rotate key for @{username} — not yet implemented (needs federation)");
        }
    }
    Ok(())
}

fn render_bio(input: &str) -> String {
    use pulldown_cmark::{html, Parser};
    let parser = Parser::new(input);
    let mut html_output = String::new();
    html::push_html(&mut html_output, parser);
    ammonia::clean(&html_output)
}

async fn cmd_admin(cmd: AdminCommands, config_path: &Path) -> Result<()> {
    let config = Config::load(config_path)?;
    let pool = db::create_pool(&config.storage.database_path).await?;

    match cmd {
        AdminCommands::SetPassword => {
            eprintln!("Enter new admin password:");
            let password = rpassword_fallback()?;
            let hash = hash_password(&password)?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64;

            sqlx::query(
                "INSERT INTO admin (id, password_hash, created_at) VALUES (1, ?, ?) ON CONFLICT(id) DO UPDATE SET password_hash = excluded.password_hash",
            )
            .bind(&hash)
            .bind(now)
            .execute(&pool)
            .await?;

            eprintln!("Admin password set.");
        }
        AdminCommands::EnableTotp => {
            eprintln!("TOTP setup — not yet implemented");
        }
    }
    Ok(())
}

fn rpassword_fallback() -> Result<String> {
    use std::io::{self, BufRead};
    let stdin = io::stdin();
    let line = stdin
        .lock()
        .lines()
        .next()
        .ok_or_else(|| anyhow::anyhow!("No input"))?
        .context("Failed to read password")?;
    Ok(line.trim().to_string())
}

fn hash_password(password: &str) -> Result<String> {
    use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
    let salt = SaltString::generate(&mut rand::thread_rng());
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("Failed to hash password: {e}"))?;
    Ok(hash.to_string())
}

async fn cmd_token(cmd: TokenCommands, config_path: &Path) -> Result<()> {
    let config = Config::load(config_path)?;
    let pool = db::create_pool(&config.storage.database_path).await?;

    match cmd {
        TokenCommands::Mint { username, scopes } => {
            let account: Option<(i64,)> =
                sqlx::query_as("SELECT id FROM accounts WHERE username = ?")
                    .bind(&username)
                    .fetch_optional(&pool)
                    .await?;

            let (account_id,) =
                account.ok_or_else(|| anyhow::anyhow!("Persona @{username} not found"))?;

            use rand::RngCore;
            let mut token_bytes = [0u8; 64];
            rand::thread_rng().fill_bytes(&mut token_bytes);
            let token =
                base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, token_bytes);

            use sha2::{Digest, Sha256};
            let token_hash = hex_encode(&Sha256::digest(token.as_bytes()));

            let app_id = get_or_create_cli_app(&pool).await?;

            let id = generate_id();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64;

            sqlx::query(
                "INSERT INTO oauth_tokens (id, token_hash, app_id, account_id, scopes, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind(id)
            .bind(&token_hash)
            .bind(app_id)
            .bind(account_id)
            .bind(&scopes)
            .bind(now)
            .execute(&pool)
            .await?;

            eprintln!("Token minted for @{username} (scopes: {scopes}):");
            eprintln!("{token}");
            eprintln!();
            eprintln!("This token will not be shown again.");
        }
        TokenCommands::List => {
            let rows: Vec<(i64, String, String, i64)> = sqlx::query_as(
                "SELECT t.id, a.username, t.scopes, t.created_at FROM oauth_tokens t JOIN accounts a ON t.account_id = a.id WHERE t.revoked_at IS NULL ORDER BY t.created_at",
            )
            .fetch_all(&pool)
            .await?;

            if rows.is_empty() {
                eprintln!("No active tokens.");
            } else {
                for (id, username, scopes, _created_at) in rows {
                    eprintln!("  {id} — @{username} [{scopes}]");
                }
            }
        }
        TokenCommands::Revoke { token_id } => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64;

            let result = sqlx::query(
                "UPDATE oauth_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
            )
            .bind(now)
            .bind(token_id.parse::<i64>().context("Invalid token ID")?)
            .execute(&pool)
            .await?;

            if result.rows_affected() == 0 {
                eprintln!("Token not found or already revoked.");
            } else {
                eprintln!("Token revoked.");
            }
        }
    }
    Ok(())
}

async fn get_or_create_cli_app(pool: &sqlx::SqlitePool) -> Result<i64> {
    let existing: Option<(i64,)> =
        sqlx::query_as("SELECT id FROM oauth_apps WHERE client_id = 'cli'")
            .fetch_optional(pool)
            .await?;

    if let Some((id,)) = existing {
        return Ok(id);
    }

    let id = generate_id();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;

    sqlx::query(
        "INSERT INTO oauth_apps (id, client_id, client_secret, name, redirect_uri, scopes, created_at) VALUES (?, 'cli', 'cli', 'CLI', 'urn:ietf:wg:oauth:2.0:oob', 'read write follow', ?)",
    )
    .bind(id)
    .bind(now)
    .execute(pool)
    .await?;

    Ok(id)
}

async fn cmd_domain_block(cmd: DomainBlockCommands, config_path: &Path) -> Result<()> {
    let config = Config::load(config_path)?;
    let pool = db::create_pool(&config.storage.database_path).await?;

    match cmd {
        DomainBlockCommands::Add {
            domain,
            severity,
            reject_media,
            reason,
        } => {
            anyhow::ensure!(
                matches!(severity.as_str(), "silence" | "suspend"),
                "Severity must be 'silence' or 'suspend'"
            );
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64;

            sqlx::query(
                "INSERT INTO domain_blocks (domain, severity, reject_media, reason, created_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(domain) DO UPDATE SET severity = excluded.severity, reject_media = excluded.reject_media, reason = excluded.reason",
            )
            .bind(&domain)
            .bind(&severity)
            .bind(reject_media as i32)
            .bind(reason.as_deref().unwrap_or(""))
            .bind(now)
            .execute(&pool)
            .await?;

            eprintln!("Blocked domain: {domain} ({severity})");
        }
        DomainBlockCommands::Remove { domain } => {
            sqlx::query("DELETE FROM domain_blocks WHERE domain = ?")
                .bind(&domain)
                .execute(&pool)
                .await?;
            eprintln!("Unblocked domain: {domain}");
        }
        DomainBlockCommands::List => {
            let rows: Vec<(String, String, String)> = sqlx::query_as(
                "SELECT domain, severity, reason FROM domain_blocks ORDER BY domain",
            )
            .fetch_all(&pool)
            .await?;

            if rows.is_empty() {
                eprintln!("No domain blocks.");
            } else {
                for (domain, severity, reason) in rows {
                    let r = if reason.is_empty() {
                        String::new()
                    } else {
                        format!(" — {reason}")
                    };
                    eprintln!("  {domain} [{severity}]{r}");
                }
            }
        }
    }
    Ok(())
}

async fn cmd_queue(cmd: QueueCommands, config_path: &Path) -> Result<()> {
    let config = Config::load(config_path)?;
    let pool = db::create_pool(&config.storage.database_path).await?;

    match cmd {
        QueueCommands::Inspect => {
            let pending: (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM delivery_queue WHERE delivered_at IS NULL AND dead_at IS NULL",
            )
            .fetch_one(&pool)
            .await?;
            let dead: (i64,) =
                sqlx::query_as("SELECT COUNT(*) FROM delivery_queue WHERE dead_at IS NOT NULL")
                    .fetch_one(&pool)
                    .await?;
            let delivered: (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM delivery_queue WHERE delivered_at IS NOT NULL",
            )
            .fetch_one(&pool)
            .await?;

            eprintln!("Delivery queue:");
            eprintln!("  Pending: {}", pending.0);
            eprintln!("  Dead: {}", dead.0);
            eprintln!("  Delivered: {}", delivered.0);
        }
        QueueCommands::RetryDead => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64;

            let result = sqlx::query(
                "UPDATE delivery_queue SET dead_at = NULL, attempts = 0, next_attempt_at = ? WHERE dead_at IS NOT NULL",
            )
            .bind(now)
            .execute(&pool)
            .await?;

            eprintln!("Reset {} dead deliveries.", result.rows_affected());
        }
    }
    Ok(())
}
