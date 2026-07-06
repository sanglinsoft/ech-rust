use std::{path::Path, time::Duration};

use anyhow::{bail, Context};
use serde::Deserialize;
use tokio::fs;

const ENV_LISTEN: &str = "LISTEN";
const ENV_TOKENS: &str = "TOKENS";

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub auth: AuthConfig,
    pub policy: PolicyConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub listen: String,
    pub cert: Option<std::path::PathBuf>,
    pub key: Option<std::path::PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthConfig {
    #[serde(default)]
    pub tokens: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PolicyConfig {
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
    #[serde(default = "default_max_concurrent_streams")]
    pub max_concurrent_streams: u32,
    #[serde(default = "default_true")]
    pub deny_private_ip: bool,
    #[serde(default)]
    pub allowed_ports: Vec<u16>,
}

impl Config {
    pub async fn load(path: Option<&Path>) -> anyhow::Result<Self> {
        let mut config = match path {
            Some(path) => {
                let raw = fs::read_to_string(path)
                    .await
                    .with_context(|| format!("failed to read config {}", path.display()))?;
                toml::from_str(&raw)
                    .with_context(|| format!("failed to parse config {}", path.display()))?
            }
            None => Config::default(),
        };

        config.apply_env()?;
        Ok(config)
    }

    fn apply_env(&mut self) -> anyhow::Result<()> {
        if let Ok(listen) = std::env::var(ENV_LISTEN) {
            let listen = listen.trim();
            if listen.is_empty() {
                bail!("{ENV_LISTEN} must not be empty");
            }
            self.server.listen = listen.to_owned();
        }

        if let Ok(tokens) = std::env::var(ENV_TOKENS) {
            self.auth.tokens = parse_tokens(&tokens)?;
        }

        Ok(())
    }
}

impl PolicyConfig {
    pub fn connect_timeout(&self) -> Duration {
        Duration::from_millis(self.connect_timeout_ms)
    }

    pub fn idle_timeout(&self) -> Duration {
        Duration::from_secs(self.idle_timeout_secs)
    }
}

fn default_connect_timeout_ms() -> u64 {
    8_000
}

fn default_idle_timeout_secs() -> u64 {
    300
}

fn default_max_concurrent_streams() -> u32 {
    4_096
}

fn default_true() -> bool {
    true
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                listen: default_listen(),
                cert: None,
                key: None,
            },
            auth: AuthConfig { tokens: Vec::new() },
            policy: PolicyConfig {
                connect_timeout_ms: default_connect_timeout_ms(),
                idle_timeout_secs: default_idle_timeout_secs(),
                max_concurrent_streams: default_max_concurrent_streams(),
                deny_private_ip: default_true(),
                allowed_ports: Vec::new(),
            },
        }
    }
}

fn default_listen() -> String {
    "0.0.0.0:50051".to_owned()
}

fn parse_tokens(raw: &str) -> anyhow::Result<Vec<String>> {
    let tokens = raw
        .split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();

    if tokens.is_empty() {
        bail!("{ENV_TOKENS} must contain at least one non-empty token");
    }

    Ok(tokens)
}
