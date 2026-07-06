use std::{collections::HashMap, path::Path, time::Duration};

use anyhow::Context;
use serde::Deserialize;
use tokio::fs;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub listen: ListenConfig,
    #[serde(default)]
    pub users: HashMap<String, UserConfig>,
    #[serde(default)]
    pub backends: HashMap<String, BackendConfig>,
    #[serde(default)]
    pub ech: EchConfig,
    #[serde(default)]
    pub route: RouteConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListenConfig {
    #[serde(default = "default_socks5_listen")]
    pub socks5: String,
    #[serde(default = "default_http_listen")]
    pub http: String,
    #[serde(default)]
    pub socks5_allow_no_auth: bool,
    pub socks5_default_user: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UserConfig {
    pub backend: String,
    pub password: Option<String>,
    pub password_hash: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BackendConfig {
    pub endpoint: String,
    pub connect_addr: Option<String>,
    pub auth_token: String,
    #[serde(default)]
    pub ech: bool,
    pub ech_name: Option<String>,
    #[serde(default)]
    pub ech_bootstrap_doh: Option<String>,
    #[serde(default = "default_pool_size")]
    pub pool_size: usize,
    #[serde(default = "default_max_streams_per_channel")]
    pub max_streams_per_channel: usize,
    #[serde(default)]
    pub ech_policy: Option<String>,
    pub tls_domain: Option<String>,
    pub ca_cert: Option<std::path::PathBuf>,
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EchConfig {
    #[serde(default = "default_ech_bootstrap_doh")]
    pub bootstrap_doh: String,
    #[serde(default = "default_ech_policy")]
    pub policy: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RouteConfig {
    #[serde(default = "default_true")]
    pub china_ip_direct: bool,
    #[serde(default = "default_domain_strategy")]
    pub domain_strategy: DomainStrategy,
    #[serde(default = "default_geoip_v4")]
    pub china_ipv4_cidrs: std::path::PathBuf,
    #[serde(default = "default_geoip_v6")]
    pub china_ipv6_cidrs: std::path::PathBuf,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DomainStrategy {
    RemoteForProxy,
    SystemDns,
}

impl Config {
    pub async fn load(path: &Path) -> anyhow::Result<Self> {
        let raw = fs::read_to_string(path)
            .await
            .with_context(|| format!("failed to read config {}", path.display()))?;
        toml::from_str(&raw).with_context(|| format!("failed to parse config {}", path.display()))
    }
}

impl Default for RouteConfig {
    fn default() -> Self {
        Self {
            china_ip_direct: true,
            domain_strategy: default_domain_strategy(),
            china_ipv4_cidrs: default_geoip_v4(),
            china_ipv6_cidrs: default_geoip_v6(),
        }
    }
}

impl Default for EchConfig {
    fn default() -> Self {
        Self {
            bootstrap_doh: default_ech_bootstrap_doh(),
            policy: default_ech_policy(),
        }
    }
}

impl BackendConfig {
    pub fn connect_timeout(&self) -> Duration {
        Duration::from_millis(self.connect_timeout_ms)
    }

    pub fn effective_ech_bootstrap_doh<'a>(&'a self, ech: &'a EchConfig) -> &'a str {
        self.ech_bootstrap_doh
            .as_deref()
            .unwrap_or(&ech.bootstrap_doh)
    }

    pub fn effective_ech_policy<'a>(&'a self, ech: &'a EchConfig) -> &'a str {
        self.ech_policy.as_deref().unwrap_or(&ech.policy)
    }
}

fn default_socks5_listen() -> String {
    "127.0.0.1:1080".to_owned()
}

fn default_http_listen() -> String {
    "127.0.0.1:8080".to_owned()
}

fn default_pool_size() -> usize {
    2
}

fn default_max_streams_per_channel() -> usize {
    128
}

fn default_ech_bootstrap_doh() -> String {
    "https://dns.alidns.com/dns-query".to_owned()
}

fn default_ech_policy() -> String {
    "strict".to_owned()
}

fn default_connect_timeout_ms() -> u64 {
    8_000
}

fn default_true() -> bool {
    true
}

fn default_domain_strategy() -> DomainStrategy {
    DomainStrategy::RemoteForProxy
}

fn default_geoip_v4() -> std::path::PathBuf {
    "chn_ip.txt".into()
}

fn default_geoip_v6() -> std::path::PathBuf {
    "chn_ip_v6.txt".into()
}
