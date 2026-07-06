use std::{path::Path, time::Duration};

use anyhow::Context;
use serde::Deserialize;
use tokio::fs;

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
    pub async fn load(path: &Path) -> anyhow::Result<Self> {
        let raw = fs::read_to_string(path)
            .await
            .with_context(|| format!("failed to read config {}", path.display()))?;
        toml::from_str(&raw).with_context(|| format!("failed to parse config {}", path.display()))
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
