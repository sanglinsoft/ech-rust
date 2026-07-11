mod auth;
mod config;
mod policy;
mod proto;
mod service;
mod tcp_util;

use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::Context;
use clap::Parser;
use tokio::fs;
use tonic::transport::{Identity, Server, ServerTlsConfig};
use tracing::info;

use crate::{
    auth::TokenAuth, config::Config, policy::Policy,
    proto::tunnel::v1::tunnel_service_server::TunnelServiceServer, service::TunnelServer,
};

#[derive(Debug, Parser)]
#[command(name = "ech-grpc-server")]
struct Args {
    #[arg(short, long)]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    let config = Config::load(args.config.as_deref()).await?;
    let listen: SocketAddr = config
        .server
        .listen
        .parse()
        .with_context(|| format!("invalid listen address {}", config.server.listen))?;

    let auth = Arc::new(TokenAuth::new(config.auth.tokens.clone())?);
    let policy = Arc::new(Policy::from_config(config.policy.clone())?);
    let service = TunnelServer::new(auth, policy, config.policy.idle_timeout());

    let mut builder = Server::builder()
        .http2_keepalive_interval(Some(std::time::Duration::from_secs(30)))
        .http2_keepalive_timeout(Some(std::time::Duration::from_secs(10)))
        .concurrency_limit_per_connection(config.policy.max_concurrent_streams as usize);

    if let (Some(cert), Some(key)) = (&config.server.cert, &config.server.key) {
        let cert = fs::read(cert)
            .await
            .with_context(|| format!("failed to read cert {}", cert.display()))?;
        let key = fs::read(key)
            .await
            .with_context(|| format!("failed to read key {}", key.display()))?;
        builder =
            builder.tls_config(ServerTlsConfig::new().identity(Identity::from_pem(cert, key)))?;
        info!(addr = %listen, "starting TLS gRPC tunnel server");
    } else {
        info!(addr = %listen, "starting plaintext gRPC tunnel server");
    }

    builder
        .add_service(TunnelServiceServer::new(service))
        .serve(listen)
        .await?;

    Ok(())
}
