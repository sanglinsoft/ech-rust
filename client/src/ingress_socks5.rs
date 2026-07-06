use std::sync::Arc;

use anyhow::Context;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tracing::{debug, warn};

use crate::{
    auth::{AuthStore, UserProfile},
    router::{connect_direct, RouteDecision, Router},
    tunnel,
};

const SOCKS_VERSION: u8 = 0x05;
const AUTH_NO_AUTH: u8 = 0x00;
const AUTH_USER_PASS: u8 = 0x02;
const NO_ACCEPTABLE_METHODS: u8 = 0xff;

#[derive(Debug, Clone)]
pub struct Socks5Options {
    pub allow_no_auth: bool,
    pub default_user: Option<String>,
}

pub async fn serve(
    addr: String,
    auth: AuthStore,
    router: Arc<Router>,
    options: Socks5Options,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("failed to bind SOCKS5 listener {addr}"))?;
    tracing::info!(
        addr = %addr,
        allow_no_auth = options.allow_no_auth,
        default_user = ?options.default_user,
        "SOCKS5 proxy listening"
    );

    loop {
        let (stream, peer) = listener.accept().await?;
        let auth = auth.clone();
        let router = Arc::clone(&router);
        let options = options.clone();
        tokio::spawn(async move {
            if let Err(err) = handle(stream, auth, router, options).await {
                debug!(peer = %peer, error = %err, "SOCKS5 connection ended");
            }
        });
    }
}

async fn handle(
    mut stream: TcpStream,
    auth: AuthStore,
    router: Arc<Router>,
    options: Socks5Options,
) -> anyhow::Result<()> {
    let method = negotiate_auth(&mut stream, &options).await?;
    let user = authenticate(&mut stream, auth, method, &options).await?;
    let (host, port) = read_connect_request(&mut stream).await?;
    debug!(username = %user.username, target_host = %host, target_port = port, "SOCKS5 CONNECT");

    let decision = router.decide(&user, &host, port).await?;
    match decision {
        RouteDecision::Direct { connect_host } => {
            let target = match connect_direct(&connect_host, port).await {
                Ok(target) => target,
                Err(err) => {
                    send_reply(&mut stream, 0x05).await?;
                    return Err(err);
                }
            };
            send_reply(&mut stream, 0x00).await?;
            tunnel::relay_direct(stream, target, Vec::new()).await?;
        }
        RouteDecision::Proxy { pool } => {
            send_reply(&mut stream, 0x00).await?;
            tunnel::relay_grpc(stream, pool, host, port, Vec::new()).await?;
        }
    }

    Ok(())
}

async fn negotiate_auth(stream: &mut TcpStream, options: &Socks5Options) -> anyhow::Result<u8> {
    let version = stream.read_u8().await?;
    if version != SOCKS_VERSION {
        anyhow::bail!("unsupported SOCKS version {version}");
    }
    let methods_len = stream.read_u8().await? as usize;
    let mut methods = vec![0_u8; methods_len];
    stream.read_exact(&mut methods).await?;

    if options.allow_no_auth && methods.contains(&AUTH_NO_AUTH) {
        stream.write_all(&[SOCKS_VERSION, AUTH_NO_AUTH]).await?;
        return Ok(AUTH_NO_AUTH);
    }

    if methods.contains(&AUTH_USER_PASS) {
        stream.write_all(&[SOCKS_VERSION, AUTH_USER_PASS]).await?;
        Ok(AUTH_USER_PASS)
    } else {
        stream
            .write_all(&[SOCKS_VERSION, NO_ACCEPTABLE_METHODS])
            .await?;
        anyhow::bail!("client did not offer an acceptable auth method");
    }
}

async fn authenticate(
    stream: &mut TcpStream,
    auth: AuthStore,
    method: u8,
    options: &Socks5Options,
) -> anyhow::Result<UserProfile> {
    if method == AUTH_NO_AUTH {
        let username = options
            .default_user
            .as_deref()
            .context("socks5_default_user is required when no-auth is selected")?;
        return auth
            .user(username)
            .with_context(|| format!("socks5_default_user {username} not found"));
    }

    let auth_version = stream.read_u8().await?;
    if auth_version != 0x01 {
        stream.write_all(&[0x01, 0x01]).await?;
        anyhow::bail!("unsupported SOCKS auth version {auth_version}");
    }

    let username = read_socks_string(stream).await?;
    let password = read_socks_string(stream).await?;
    match auth.authenticate(&username, &password) {
        Some(user) => {
            stream.write_all(&[0x01, 0x00]).await?;
            Ok(user)
        }
        None => {
            stream.write_all(&[0x01, 0x01]).await?;
            anyhow::bail!("invalid SOCKS credentials for {username}");
        }
    }
}

async fn read_socks_string(stream: &mut TcpStream) -> anyhow::Result<String> {
    let len = stream.read_u8().await? as usize;
    let mut buf = vec![0_u8; len];
    stream.read_exact(&mut buf).await?;
    String::from_utf8(buf).context("SOCKS auth field is not UTF-8")
}

async fn read_connect_request(stream: &mut TcpStream) -> anyhow::Result<(String, u16)> {
    let version = stream.read_u8().await?;
    let command = stream.read_u8().await?;
    let reserved = stream.read_u8().await?;
    let atyp = stream.read_u8().await?;

    if version != SOCKS_VERSION || reserved != 0 {
        anyhow::bail!("invalid SOCKS request header");
    }
    if command != 0x01 {
        send_reply(stream, 0x07).await?;
        anyhow::bail!("unsupported SOCKS command {command}");
    }

    let host = match atyp {
        0x01 => {
            let mut buf = [0_u8; 4];
            stream.read_exact(&mut buf).await?;
            std::net::Ipv4Addr::from(buf).to_string()
        }
        0x03 => {
            let len = stream.read_u8().await? as usize;
            let mut buf = vec![0_u8; len];
            stream.read_exact(&mut buf).await?;
            String::from_utf8(buf).context("SOCKS domain is not UTF-8")?
        }
        0x04 => {
            let mut buf = [0_u8; 16];
            stream.read_exact(&mut buf).await?;
            std::net::Ipv6Addr::from(buf).to_string()
        }
        _ => {
            send_reply(stream, 0x08).await?;
            anyhow::bail!("unsupported SOCKS address type {atyp}");
        }
    };

    let port = stream.read_u16().await?;
    if port == 0 {
        send_reply(stream, 0x04).await?;
        anyhow::bail!("SOCKS port must not be 0");
    }

    Ok((host, port))
}

async fn send_reply(stream: &mut TcpStream, reply: u8) -> anyhow::Result<()> {
    if let Err(err) = stream
        .write_all(&[SOCKS_VERSION, reply, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
    {
        warn!(error = %err, "failed to write SOCKS reply");
    }
    Ok(())
}
