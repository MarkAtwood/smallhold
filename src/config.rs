use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub storage: StorageConfig,
    pub federation: FederationConfig,
    pub limits: LimitsConfig,
    pub defaults: DefaultsConfig,
    #[serde(default)]
    pub branding: BrandingConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BrandingConfig {
    #[serde(default = "default_site_title")]
    pub site_title: String,
    #[serde(default)]
    pub site_description: String,
    #[serde(default)]
    pub custom_css_path: String,
    #[serde(default)]
    pub theme_tokens_path: String,
}

impl Default for BrandingConfig {
    fn default() -> Self {
        Self {
            site_title: default_site_title(),
            site_description: String::new(),
            custom_css_path: String::new(),
            theme_tokens_path: String::new(),
        }
    }
}

fn default_site_title() -> String {
    "smallhold".into()
}

#[derive(Clone, Deserialize)]
pub struct ServerConfig {
    pub listen: String,
    pub domain: String,
    pub secret_key: String,
}

impl std::fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerConfig")
            .field("listen", &self.listen)
            .field("domain", &self.domain)
            .field("secret_key", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct StorageConfig {
    pub database_path: String,
    pub media_dir: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FederationConfig {
    #[serde(default = "default_user_agent")]
    pub user_agent: String,
    #[serde(default = "default_delivery_timeout")]
    pub delivery_timeout_secs: u64,
    #[serde(default = "default_delivery_concurrency")]
    pub delivery_concurrency: usize,
    #[serde(default = "default_fetch_timeout")]
    pub fetch_timeout_secs: u64,
    #[serde(default = "default_max_incoming_body")]
    pub max_incoming_body_mb: usize,
    #[serde(default = "default_authorized_fetch")]
    pub authorized_fetch: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LimitsConfig {
    #[serde(default = "default_max_post_chars")]
    pub max_post_chars: usize,
    #[serde(default = "default_max_attachments")]
    pub max_attachments: usize,
    #[serde(default = "default_max_media_mb")]
    pub max_media_mb: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DefaultsConfig {
    #[serde(default = "default_visibility")]
    pub default_visibility: String,
    #[serde(default)]
    pub default_sensitive: bool,
    #[serde(default = "default_language")]
    pub default_language: String,
}

fn default_user_agent() -> String {
    "smallhold/0.1".into()
}
fn default_delivery_timeout() -> u64 {
    30
}
fn default_delivery_concurrency() -> usize {
    16
}
fn default_fetch_timeout() -> u64 {
    20
}
fn default_max_incoming_body() -> usize {
    10
}
fn default_authorized_fetch() -> bool {
    true
}
fn default_max_post_chars() -> usize {
    5000
}
fn default_max_attachments() -> usize {
    4
}
fn default_max_media_mb() -> usize {
    40
}
fn default_visibility() -> String {
    "public".into()
}
fn default_language() -> String {
    "en".into()
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;
        let config: Config = toml::from_str(&content)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            !self.server.domain.is_empty(),
            "server.domain must not be empty"
        );
        anyhow::ensure!(
            !self.server.secret_key.is_empty(),
            "server.secret_key must not be empty"
        );
        anyhow::ensure!(
            self.server.secret_key.len() >= 32,
            "server.secret_key must be at least 32 characters"
        );
        anyhow::ensure!(
            matches!(
                self.defaults.default_visibility.as_str(),
                "public" | "unlisted" | "private" | "direct"
            ),
            "defaults.default_visibility must be one of: public, unlisted, private, direct"
        );
        Ok(())
    }
}
