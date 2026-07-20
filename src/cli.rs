use crate::config::Config;
use crate::db;
use crate::id::generate_id;
use crate::server::fw_pool;
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

    /// Manage search index
    #[command(subcommand)]
    Search(SearchCommands),

    /// Import data from another server
    #[command(subcommand)]
    Import(ImportCommands),

    /// Register with fediverse census services
    Census,

    /// Manage relay subscriptions
    #[command(subcommand)]
    Relay(RelayCommands),

    /// DID identity management
    #[command(subcommand)]
    Did(DidCommands),
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
    /// Register a passkey (opens browser registration page)
    RegisterPasskey,
}

#[derive(Subcommand)]
pub enum TokenCommands {
    /// Mint a new token for a persona
    Mint {
        username: String,
        #[arg(long, default_value = "read write follow")]
        scopes: String,
    },
    /// List all tokens
    List,
    /// Revoke a token
    Revoke { token_id: String },
    /// Revoke all active tokens
    RevokeAll {
        /// Only revoke tokens for this persona
        #[arg(long)]
        username: Option<String>,
    },
    /// Show active sessions grouped by persona
    Sessions,
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

#[derive(Subcommand)]
pub enum SearchCommands {
    /// Rebuild the full-text search index from the database
    Reindex,
}

#[derive(Subcommand)]
pub enum ImportCommands {
    /// Import a Mastodon archive (.tar.gz)
    Mastodon {
        /// Local persona to import into
        username: String,
        /// Path to the Mastodon archive file
        archive: PathBuf,
    },
}

#[derive(Subcommand)]
pub enum DidCommands {
    /// Recover an account using a BIP-39 mnemonic phrase (read from stdin)
    Recover,
    /// Backfill DID keys for existing accounts that lack them
    Backfill,
}

#[derive(Subcommand)]
pub enum RelayCommands {
    /// Subscribe to a relay
    Add {
        /// Relay actor URL (e.g. https://relay.fedi.buzz/actor)
        url: String,
    },
    /// Unsubscribe from a relay
    Remove {
        /// Relay actor URL
        url: String,
    },
    /// List subscribed relays
    List,
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
            Commands::Search(cmd) => cmd_search(cmd, &self.config).await,
            Commands::Import(cmd) => cmd_import(cmd, &self.config).await,
            Commands::Census => cmd_census(&self.config).await,
            Commands::Relay(cmd) => cmd_relay(cmd, &self.config).await,
            Commands::Did(cmd) => cmd_did(cmd, &self.config).await,
        }
    }
}

async fn cmd_census(config_path: &Path) -> Result<()> {
    let config = Config::load(config_path)?;
    let domain = &config.server.domain;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    eprintln!("Registering {domain} with fediverse census services...");
    eprintln!();

    // the-federation.info — instant registration
    let url = format!("https://the-federation.info/register/{domain}");
    match client.get(&url).send().await {
        Ok(resp) => eprintln!(
            "  the-federation.info: {} {}",
            resp.status(),
            if resp.status().is_success() {
                "OK"
            } else {
                "FAILED"
            }
        ),
        Err(e) => eprintln!("  the-federation.info: FAILED ({e})"),
    }

    // FediDB — just ping, their crawler does the rest
    let url = "https://fedidb.org/software/smallhold".to_string();
    match client.get(&url).send().await {
        Ok(resp) => eprintln!(
            "  fedidb.org: {} (crawler will pick up NodeInfo)",
            resp.status()
        ),
        Err(e) => eprintln!("  fedidb.org: FAILED ({e})"),
    }

    // Fediverse Observer — ping the instance page
    let url = format!("https://fediverse.observer/api/v1/instance/{domain}");
    match client.get(&url).send().await {
        Ok(resp) => eprintln!(
            "  fediverse.observer: {} (crawler will discover via peers)",
            resp.status()
        ),
        Err(e) => eprintln!("  fediverse.observer: FAILED ({e})"),
    }

    eprintln!();
    eprintln!("Census services discover instances automatically once you federate.");
    eprintln!("This command nudges them. Full indexing may take 24-48 hours.");
    eprintln!();
    eprintln!("Verify at:");
    eprintln!("  https://the-federation.info/{domain}");
    eprintln!("  https://fedidb.org/network?s={domain}");
    eprintln!("  https://fediverse.observer/{domain}");

    Ok(())
}

fn generate_secret_key() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut bytes);
    crate::api::hex_encode(&bytes)
}

fn format_millis_human(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms)
        .unwrap_or_default()
        .format("%Y-%m-%d %H:%M:%S UTC")
        .to_string()
}

fn format_millis_relative(ms: i64) -> String {
    let now = chrono::Utc::now().timestamp_millis();
    let delta_secs = (now - ms) / 1000;
    if delta_secs < 60 {
        format!("{delta_secs}s ago")
    } else if delta_secs < 3600 {
        format!("{}m ago", delta_secs / 60)
    } else if delta_secs < 86400 {
        format!("{}h ago", delta_secs / 3600)
    } else {
        format!("{}d ago", delta_secs / 86400)
    }
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

# [branding]
# site_title = "smallhold"
# site_description = ""
# custom_css_path = ""  # path to a CSS file for visual customization
# theme_tokens_path = ""  # path to a W3C Design Tokens JSON file
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

    let search_dir = std::path::Path::new(&config.storage.media_dir)
        .parent()
        .unwrap_or(std::path::Path::new("."));
    let search = match crate::search::SearchIndex::open(search_dir) {
        Ok(idx) => Some(std::sync::Arc::new(idx)),
        Err(e) => {
            tracing::warn!("search index unavailable: {e}");
            None
        }
    };

    let state = std::sync::Arc::new(crate::server::AppState {
        config: config.clone(),
        pool: pool.clone(),
        search,
    });

    // Start delivery worker
    tokio::spawn(crate::delivery::run_delivery_worker(pool, config.clone()));

    // Periodic census registration (the-federation.info)
    {
        let domain = config.server.domain.clone();
        tokio::spawn(async move {
            // Wait 7 days after startup, then every 7 days
            tokio::time::sleep(std::time::Duration::from_secs(7 * 24 * 3600)).await;
            let client = match reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
            {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("census client init failed: {e}");
                    return;
                }
            };
            loop {
                let url = format!("https://the-federation.info/register/{domain}");
                match client.get(&url).send().await {
                    Ok(resp) => tracing::info!(
                        status = %resp.status(),
                        "census registration ping to the-federation.info"
                    ),
                    Err(e) => tracing::debug!("census ping failed (non-fatal): {e}"),
                }
                tokio::time::sleep(std::time::Duration::from_secs(7 * 24 * 3600)).await;
            }
        });
    }

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

            let private_key =
                RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).context("Failed to generate RSA keypair")?;
            let private_key_pem = private_key
                .to_pkcs8_pem(LineEnding::LF)
                .context("Failed to encode private key")?;
            let public_key_pem = private_key
                .to_public_key()
                .to_public_key_pem(LineEnding::LF)
                .context("Failed to encode public key")?;

            // Generate Ed25519 recovery keypair for DID
            let (recovery_priv, recovery_pub) = crate::did::generate_recovery_keypair();
            let did_key = crate::did::ed25519_to_did_key(&recovery_pub);
            let recovery_pubkey_hex = crate::api::hex_encode(&recovery_pub);
            let recovery_phrase = crate::did::private_key_to_mnemonic(&recovery_priv);

            let id = generate_id();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64;

            // Ensure the single-owner user exists for FK reference
            crate::db::ensure_default_user(&pool).await?;

            

            crate::db_extras::create_persona(&pool, id, crate::db::DEFAULT_USER_ID, &username, &display_name, private_key_pem.as_str(), &public_key_pem, locked, bot, now)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to create persona (username may already exist): {e}"))?;

            // Store DID keys on the users table (canonical schema)
            
            crate::db_extras::update_user_did(&pool, crate::db::DEFAULT_USER_ID, &did_key, &recovery_pubkey_hex).await?;

            eprintln!("Created persona: @{username} (id: {id})");
            eprintln!("  DID: {did_key}");
            eprintln!();
            eprintln!("RECOVERY PHRASE (save this — it will NOT be shown again):");
            eprintln!("{recovery_phrase}");
        }
        PersonaCommands::List => {
            let rows: Vec<(String, String, String, i64)> = crate::db_extras::list_personas_cli(&pool).await?;

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
            let persona = fieldwork::persona_db::get_persona_by_username(
                &fw_pool(&pool), &username,
            ).await?
            .ok_or_else(|| anyhow::anyhow!("Persona @{username} not found"))?;

            let bio_html = bio.as_ref().map(|b| render_bio(b));
            fieldwork::persona_db::update_persona_profile(
                &fw_pool(&pool),
                persona.id,
                display_name.as_deref(),
                bio.as_deref(),
                bio_html.as_deref(),
            ).await?;
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

            

            crate::db_extras::cli_set_admin_password(&pool, &hash, now).await?;

            eprintln!("Admin password set.");
        }
        AdminCommands::EnableTotp => {
            eprintln!("TOTP setup — not yet implemented");
        }
        AdminCommands::RegisterPasskey => {
            eprintln!("Start the server (`smallhold serve`) and visit:");
            eprintln!("  https://{}/admin/webauthn/register", config.server.domain);
            eprintln!();
            eprintln!("The registration page requires your admin password and a");
            eprintln!("browser that supports WebAuthn/passkeys.");
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
                
                {
                    let p = fieldwork::persona_db::get_persona_by_username(&fw_pool(&pool), &username).await?;
                    p.map(|p| (p.id,))
                };

            let (account_id,) =
                account.ok_or_else(|| anyhow::anyhow!("Persona @{username} not found"))?;

            use rand::RngCore;
            let mut token_bytes = [0u8; 64];
            rand::thread_rng().fill_bytes(&mut token_bytes);
            let token = base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                token_bytes,
            );

            use sha2::{Digest, Sha256};
            let token_hash = crate::api::hex_encode(&Sha256::digest(token.as_bytes()));

            let app_id = get_or_create_cli_app(&pool).await?;

            let id = generate_id();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64;

            fieldwork::oauth_db::create_token(
                &fw_pool(&pool),
                id, &token_hash, app_id, crate::db::DEFAULT_USER_ID, account_id, &scopes, now,
            ).await?;

            eprintln!("Token minted for @{username} (scopes: {scopes}):");
            eprintln!("{token}");
            eprintln!();
            eprintln!("This token will not be shown again.");
        }
        TokenCommands::List => {
            let rows: Vec<(String, String, String, i64, Option<i64>, String)> = crate::db_extras::list_tokens_cli(&pool).await?;

            if rows.is_empty() {
                eprintln!("No active tokens.");
            } else {
                for (id, username, scopes, created_at, last_used_at, app_name) in &rows {
                    let created = format_millis_human(*created_at);
                    let used = match last_used_at {
                        Some(ms) => format_millis_human(*ms),
                        None => "never".to_string(),
                    };
                    eprintln!(
                        "  {id} — @{username} [{scopes}] — {app_name} — created {created} — last used {used}"
                    );
                }
            }
        }
        TokenCommands::Revoke { token_id } => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64;

            let result = crate::db_extras::revoke_token_cli(&pool, token_id.parse::<i64>().context("Invalid token ID")?, now).await?;

            if result == 0 {
                eprintln!("Token not found or already revoked.");
            } else {
                eprintln!("Token revoked.");
            }
        }
        TokenCommands::RevokeAll { username } => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64;

            let result = if let Some(ref uname) = username {
                let account: Option<(i64,)> = crate::db_extras::get_persona_id_by_username(&pool, uname)
                    .await?
                    .map(|id| (id,));
                let (account_id,) =
                    account.ok_or_else(|| anyhow::anyhow!("Persona @{uname} not found"))?;

                

                crate::db_extras::revoke_tokens_for_persona(&pool, account_id, now).await?
            } else {
                crate::db_extras::revoke_all_tokens(&pool, now).await?
            };

            let scope = username
                .as_deref()
                .map(|u| format!(" for @{u}"))
                .unwrap_or_default();
            eprintln!("Revoked {result} token(s){scope}.");
        }
        TokenCommands::Sessions => {
            let accounts: Vec<(i64, String)> =
                
                {
                    let personas = fieldwork::persona_db::list_personas(&fw_pool(&pool)).await?;
                    personas.iter().map(|p| (p.id, p.username.clone())).collect::<Vec<_>>()
                };

            for (account_id, username) in &accounts {
                eprintln!("Sessions for @{username}:");

                let rows: Vec<(String, String, String, Option<i64>)> = crate::db_extras::list_sessions_cli(&pool, *account_id).await?;

                if rows.is_empty() {
                    eprintln!("  (none)");
                } else {
                    for (id, app_name, scopes, last_used_at) in &rows {
                        let used = match last_used_at {
                            Some(ms) => format_millis_relative(*ms),
                            None => "never".to_string(),
                        };
                        eprintln!("  ID {id} — {app_name} [{scopes}] — last used {used}");
                    }
                }
                eprintln!();
            }
        }
    }
    Ok(())
}

async fn get_or_create_cli_app(pool: &sqlx::SqlitePool) -> Result<i64> {
    let existing: Option<(i64,)> = crate::db_extras::get_cli_app_id(pool)
        .await?
        .map(|id| (id,));

    if let Some((id,)) = existing {
        return Ok(id);
    }

    let id = generate_id();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;

    

    crate::db_extras::create_cli_app(pool, id, now).await?;

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

            

            crate::db_extras::add_domain_block(&pool, &domain, &severity, reject_media, reason.as_deref().unwrap_or(""), now).await?;

            eprintln!("Blocked domain: {domain} ({severity})");
        }
        DomainBlockCommands::Remove { domain } => {
            
            fieldwork::domain_blocks_db::unblock_domain(
                &fw_pool(&pool), &domain,
            ).await?;
            eprintln!("Unblocked domain: {domain}");
        }
        DomainBlockCommands::List => {
            let rows: Vec<(String, String, String)> = crate::db_extras::list_domain_blocks(&pool).await?;

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
            let pending = crate::db_extras::count_pending_deliveries(&pool).await?;
            let dead = crate::db_extras::count_dead_deliveries(&pool).await?;
            let delivered = crate::db_extras::count_delivered(&pool).await?;

            eprintln!("Delivery queue:");
            eprintln!("  Pending: {pending}");
            eprintln!("  Dead: {dead}");
            eprintln!("  Delivered: {delivered}");
        }
        QueueCommands::RetryDead => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;

            let result = crate::db_extras::retry_dead_deliveries(&pool, now).await?;
            eprintln!("Reset {result} dead deliveries.");
        }
    }
    Ok(())
}

async fn cmd_search(cmd: SearchCommands, config_path: &Path) -> Result<()> {
    let config = Config::load(config_path)?;
    let pool = db::create_pool(&config.storage.database_path).await?;

    match cmd {
        SearchCommands::Reindex => {
            let search_dir = std::path::Path::new(&config.storage.media_dir)
                .parent()
                .unwrap_or(std::path::Path::new("."));
            let search = crate::search::SearchIndex::open(search_dir)
                .context("Failed to open search index")?;
            let count = search.reindex_all(&pool).await?;
            eprintln!("Reindexed {count} posts");
        }
    }
    Ok(())
}

async fn cmd_import(cmd: ImportCommands, config_path: &Path) -> Result<()> {
    let config = Config::load(config_path)?;
    let pool = db::create_pool(&config.storage.database_path).await?;

    match cmd {
        ImportCommands::Mastodon { username, archive } => {
            let stats =
                crate::import::import_mastodon_archive(&pool, &config, &username, &archive).await?;
            eprintln!("Import complete:");
            eprintln!(
                "  Posts: {} imported, {} skipped",
                stats.posts_imported, stats.posts_skipped
            );
            eprintln!("  Media: {} files", stats.media_imported);
            eprintln!(
                "  Follows: {} found (resolve with `smallhold follow` commands)",
                stats.follows_found
            );
            if stats.blocks_found > 0 {
                eprintln!(
                    "  Blocks: {} found (not yet implemented)",
                    stats.blocks_found
                );
            }
            if stats.mutes_found > 0 {
                eprintln!("  Mutes: {} found (not yet implemented)", stats.mutes_found);
            }
            if stats.profile_updated {
                eprintln!("  Profile: updated");
            }
        }
    }
    Ok(())
}

async fn cmd_did(cmd: DidCommands, config_path: &Path) -> Result<()> {
    let config = Config::load(config_path)?;
    let pool = db::create_pool(&config.storage.database_path).await?;

    match cmd {
        DidCommands::Recover => {
            eprint!("Enter recovery phrase: ");
            let mnemonic = {
                use std::io::BufRead;
                let stdin = std::io::stdin();
                stdin.lock().lines().next()
                    .ok_or_else(|| anyhow::anyhow!("No input"))?
                    .context("Failed to read recovery phrase")?
                    .trim().to_string()
            };
            let priv_key = crate::did::mnemonic_to_private_key(&mnemonic)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            let pub_key = crate::did::ed25519_public_from_private(&priv_key);
            let did_key = crate::did::ed25519_to_did_key(&pub_key);

            let account: Option<(i64, String, String)> = crate::db_extras::find_account_by_did(&pool, &did_key).await?;

            match account {
                Some((id, username, display_name)) => {
                    eprintln!("Found account:");
                    eprintln!("  User ID: {id}");
                    eprintln!("  Username: @{username}");
                    eprintln!("  Display name: {display_name}");
                    eprintln!("  DID: {did_key}");
                    eprintln!();
                    eprintln!("To reset the admin password, run:");
                    eprintln!("  smallhold admin set-password");
                }
                None => {
                    eprintln!("No account found for DID: {did_key}");
                    eprintln!("The recovery phrase may be for a different instance.");
                }
            }
        }
        DidCommands::Backfill => {
            // Check if the single user already has a DID key
            if !crate::db_extras::user_needs_did(&pool).await? {
                eprintln!("All accounts already have DID keys.");
                return Ok(());
            }

            let personas: Vec<(i64, String)> = crate::db_extras::list_personas_for_backfill(&pool).await?;

            eprintln!("Backfilling DID keys...");
            eprintln!();

            let (recovery_priv, recovery_pub) = crate::did::generate_recovery_keypair();
            let did_key = crate::did::ed25519_to_did_key(&recovery_pub);
            let recovery_pubkey_hex = crate::api::hex_encode(&recovery_pub);
            let recovery_phrase = crate::did::private_key_to_mnemonic(&recovery_priv);

            

            crate::db_extras::update_user_did(&pool, crate::db::DEFAULT_USER_ID, &did_key, &recovery_pubkey_hex)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to update user DID keys: {e}"))?;

            for (_id, username) in &personas {

                eprintln!("@{username}:");
                eprintln!("  DID: {did_key}");
                eprintln!("  RECOVERY PHRASE (save this — it will NOT be shown again):");
                eprintln!("  {recovery_phrase}");
                eprintln!();
            }

            eprintln!("Backfill complete.");
        }
    }
    Ok(())
}

async fn cmd_relay(cmd: RelayCommands, config_path: &Path) -> Result<()> {
    let config = Config::load(config_path)?;
    let pool = db::create_pool(&config.storage.database_path).await?;

    match cmd {
        RelayCommands::Add { url } => {
            // Fetch the relay's actor document to get its inbox URL.
            let first_account: Option<(i64, String, String)> = crate::db_extras::get_first_persona_with_key(&pool).await?;

            let (account_id, username, private_key_pem) = first_account
                .ok_or_else(|| anyhow::anyhow!("No local persona exists. Create one first."))?;

            let fed_client = crate::federation::FederationClient::new(&config)
                .context("Failed to create federation client")?;

            let key_id = format!(
                "https://{}/users/{}#main-key",
                config.server.domain, username
            );
            let actor_data = fed_client
                .fetch_actor(&url, &private_key_pem, &key_id)
                .await
                .with_context(|| format!("Failed to fetch relay actor: {url}"))?;

            let inbox_url = &actor_data.inbox_url;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64;

            // Enqueue a Follow activity to the relay.
            let follow_id = generate_id();
            let domain = &config.server.domain;
            let follow_uri = format!("https://{domain}/activities/follow-{follow_id}");

            let relay_id = generate_id();
            
            crate::db_extras::insert_relay(&pool, relay_id, inbox_url, &url, &follow_uri, now)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to insert relay: {e}"))?;
            let actor = format!("https://{domain}/users/{username}");
            let follow_activity = serde_json::json!({
                "@context": "https://www.w3.org/ns/activitystreams",
                "id": &follow_uri,
                "type": "Follow",
                "actor": &actor,
                "object": &url
            });

            crate::delivery::enqueue_delivery(&pool, inbox_url, account_id, &follow_activity)
                .await
                .context("Failed to enqueue Follow activity")?;

            eprintln!("Subscribed to relay (pending acceptance): {url}");
        }
        RelayCommands::Remove { url } => {
            let relay = fieldwork::relay::find_by_actor(&fw_pool(&pool), &url)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Relay not found: {url}"))?;

            let inbox_url = relay.inbox_url.clone();
            let stored_follow_id = relay.follow_id.clone();

            // Get the first local account to send the Undo.
            let first_account: Option<(i64, String)> = crate::db_extras::get_first_persona(&pool).await?;

            let (account_id, username) =
                first_account.ok_or_else(|| anyhow::anyhow!("No local persona exists."))?;

            let domain = &config.server.domain;
            let actor = format!("https://{domain}/users/{username}");
            let undo_id = generate_id();
            let undo_activity = serde_json::json!({
                "@context": "https://www.w3.org/ns/activitystreams",
                "id": format!("https://{domain}/activities/undo-{undo_id}"),
                "type": "Undo",
                "actor": &actor,
                "object": {
                    "id": &stored_follow_id,
                    "type": "Follow",
                    "actor": &actor,
                    "object": &url
                }
            });

            crate::delivery::enqueue_delivery(&pool, &inbox_url, account_id, &undo_activity)
                .await
                .context("Failed to enqueue Undo activity")?;

            fieldwork::relay::unsubscribe(&fw_pool(&pool), relay.id).await?;

            eprintln!("Unsubscribed from relay: {url}");
        }
        RelayCommands::List => {
            let rows: Vec<(String, String, String)> = crate::db_extras::list_relays(&pool).await?;

            if rows.is_empty() {
                eprintln!("No relay subscriptions.");
            } else {
                for (actor_uri, _inbox_url, state) in rows {
                    eprintln!("  {actor_uri} [{state}]");
                }
            }
        }
    }
    Ok(())
}
