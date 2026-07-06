mod auth;
mod china_ip;
mod config;
mod ech_connector;
mod ech_tls;
mod grpc_pool;
mod ingress_http;
mod ingress_socks5;
mod proto;
mod router;
mod tunnel;

use std::{path::PathBuf, sync::Arc};

use anyhow::{bail, Context};
use clap::{Parser, Subcommand};
use tracing::info;

use crate::{
    auth::AuthStore, china_ip::ChinaIpSet, config::Config, grpc_pool::PoolRegistry, router::Router,
};

#[derive(Debug, Parser)]
#[command(name = "ech-grpc-client")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Run {
        #[arg(short, long, default_value = "client/example.toml")]
        config: PathBuf,
    },
    TestBackend {
        #[arg(short, long, default_value = "client/example.toml")]
        config: PathBuf,
        #[arg(long)]
        backend: String,
    },
    UpdateGeoip,
    Service {
        #[command(subcommand)]
        command: ServiceCommand,
    },
}

#[derive(Debug, Subcommand)]
enum ServiceCommand {
    Install {
        #[arg(short, long)]
        config: PathBuf,
    },
    Uninstall,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    match args.command {
        Command::Run { config } => run(config).await,
        Command::TestBackend { config, backend } => test_backend(config, backend).await,
        Command::UpdateGeoip => {
            bail!("update-geoip is not implemented; update chn_ip.txt and chn_ip_v6.txt manually")
        }
        Command::Service { command } => match command {
            ServiceCommand::Install { .. } | ServiceCommand::Uninstall => {
                bail!("Windows service management is not implemented in this build")
            }
        },
    }
}

async fn run(path: PathBuf) -> anyhow::Result<()> {
    let config = Config::load(&path).await?;
    let auth = AuthStore::from_config(config.users.clone())?;
    let china_ip = ChinaIpSet::load(&config.route).await?;
    let pools = PoolRegistry::connect(config.backends.clone()).await?;
    let router = Arc::new(Router::new(config.route.clone(), china_ip, pools));

    validate_users_backends(&config)?;

    let socks_addr = config.listen.socks5.clone();
    let socks_options = ingress_socks5::Socks5Options {
        allow_no_auth: config.listen.socks5_allow_no_auth,
        default_user: config.listen.socks5_default_user.clone(),
    };
    let http_addr = config.listen.http.clone();
    let socks_auth = auth.clone();
    let socks_router = Arc::clone(&router);
    let http_auth = auth;
    let http_router = router;

    let socks = tokio::spawn(async move {
        ingress_socks5::serve(socks_addr, socks_auth, socks_router, socks_options).await
    });
    let http =
        tokio::spawn(async move { ingress_http::serve(http_addr, http_auth, http_router).await });

    tokio::select! {
        result = socks => result.context("SOCKS5 task panicked")??,
        result = http => result.context("HTTP proxy task panicked")??,
        result = tokio::signal::ctrl_c() => result.context("failed to listen for Ctrl-C")?,
    }

    info!("client stopped");
    Ok(())
}

async fn test_backend(path: PathBuf, backend_id: String) -> anyhow::Result<()> {
    let config = Config::load(&path).await?;
    let backend = config
        .backends
        .get(&backend_id)
        .with_context(|| format!("backend {backend_id} not found"))?
        .clone();
    let channel = ech_tls::connect_channel(&backend).await?;
    drop(channel);
    info!(backend = %backend_id, "backend connection succeeded");
    Ok(())
}

fn validate_users_backends(config: &Config) -> anyhow::Result<()> {
    for (username, user) in &config.users {
        if !config.backends.contains_key(&user.backend) {
            bail!(
                "users.{username}.backend references missing backend {}",
                user.backend
            );
        }
    }
    Ok(())
}
