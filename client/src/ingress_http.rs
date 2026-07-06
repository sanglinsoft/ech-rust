use std::sync::Arc;

use anyhow::{bail, Context};
use base64::{engine::general_purpose, Engine as _};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tracing::debug;

use crate::{
    auth::{AuthStore, UserProfile},
    router::{connect_direct, RouteDecision, Router},
    tunnel,
};

const MAX_HEADER_SIZE: usize = 64 * 1024;

pub async fn serve(addr: String, auth: AuthStore, router: Arc<Router>) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("failed to bind HTTP proxy listener {addr}"))?;
    tracing::info!(addr = %addr, "HTTP proxy listening");

    loop {
        let (stream, peer) = listener.accept().await?;
        let auth = auth.clone();
        let router = Arc::clone(&router);
        tokio::spawn(async move {
            if let Err(err) = handle(stream, auth, router).await {
                debug!(peer = %peer, error = %err, "HTTP proxy connection ended");
            }
        });
    }
}

async fn handle(mut stream: TcpStream, auth: AuthStore, router: Arc<Router>) -> anyhow::Result<()> {
    let header = read_header(&mut stream).await?;
    let request = parse_request(&header)?;
    let user = match authenticate(&request, auth) {
        Ok(user) => user,
        Err(err) => {
            write_response(&mut stream, "407 Proxy Authentication Required", true).await?;
            return Err(err);
        }
    };

    if request.method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = parse_authority(request.target, 443)?;
        debug!(username = %user.username, target_host = %host, target_port = port, "HTTP CONNECT");
        let decision = router.decide(&user, &host, port).await?;
        write_response(&mut stream, "200 Connection Established", false).await?;
        match decision {
            RouteDecision::Direct { connect_host } => {
                let target = connect_direct(&connect_host, port).await?;
                tunnel::relay_direct(stream, target, Vec::new()).await?;
            }
            RouteDecision::Proxy { pool } => {
                tunnel::relay_grpc(stream, pool, host, port, Vec::new()).await?;
            }
        }
    } else {
        let absolute = parse_absolute_uri(request.target)?;
        let port = absolute
            .port
            .unwrap_or(if absolute.scheme == "https" { 443 } else { 80 });
        debug!(
            username = %user.username,
            target_host = %absolute.host,
            target_port = port,
            "HTTP absolute-form request"
        );
        let first_payload = rewrite_absolute_request(&header, request, &absolute)?;
        let decision = router.decide(&user, &absolute.host, port).await?;
        match decision {
            RouteDecision::Direct { connect_host } => {
                let target = connect_direct(&connect_host, port).await?;
                tunnel::relay_direct(stream, target, first_payload).await?;
            }
            RouteDecision::Proxy { pool } => {
                tunnel::relay_grpc(stream, pool, absolute.host, port, first_payload).await?;
            }
        }
    }

    Ok(())
}

async fn read_header(stream: &mut TcpStream) -> anyhow::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(4096);
    let mut one = [0_u8; 1];
    while buf.len() < MAX_HEADER_SIZE {
        let n = stream.read(&mut one).await?;
        if n == 0 {
            bail!("client closed before HTTP headers completed");
        }
        buf.push(one[0]);
        if buf.ends_with(b"\r\n\r\n") {
            return Ok(buf);
        }
    }
    bail!("HTTP headers exceed {} bytes", MAX_HEADER_SIZE);
}

#[derive(Debug)]
struct RequestParts<'a> {
    method: &'a str,
    target: &'a str,
    version: &'a str,
    headers: Vec<(&'a str, &'a str)>,
}

fn parse_request(header: &[u8]) -> anyhow::Result<RequestParts<'_>> {
    let text = std::str::from_utf8(header).context("HTTP request header is not UTF-8")?;
    let text = text
        .strip_suffix("\r\n\r\n")
        .context("HTTP header missing CRLF terminator")?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().context("missing request line")?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().context("missing HTTP method")?;
    let target = parts.next().context("missing HTTP target")?;
    let version = parts.next().context("missing HTTP version")?;
    if parts.next().is_some() || !version.starts_with("HTTP/") {
        bail!("malformed HTTP request line");
    }

    let mut headers = Vec::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            bail!("malformed HTTP header");
        };
        headers.push((name.trim(), value.trim()));
    }

    Ok(RequestParts {
        method,
        target,
        version,
        headers,
    })
}

fn authenticate(request: &RequestParts<'_>, auth: AuthStore) -> anyhow::Result<UserProfile> {
    let Some((_, value)) = request
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("Proxy-Authorization"))
    else {
        bail!("missing Proxy-Authorization header");
    };

    let value = value.trim();
    let encoded = value
        .strip_prefix("Basic ")
        .or_else(|| value.strip_prefix("basic "))
        .context("unsupported proxy auth scheme")?;
    let decoded = general_purpose::STANDARD
        .decode(encoded)
        .context("invalid Basic auth base64")?;
    let decoded = String::from_utf8(decoded).context("Basic auth is not UTF-8")?;
    let (username, password) = decoded
        .split_once(':')
        .context("Basic auth payload missing colon")?;

    auth.authenticate(username, password)
        .ok_or_else(|| anyhow::anyhow!("invalid HTTP proxy credentials for {username}"))
}

#[derive(Debug)]
struct AbsoluteUri {
    scheme: String,
    host: String,
    port: Option<u16>,
    path: String,
}

fn parse_absolute_uri(target: &str) -> anyhow::Result<AbsoluteUri> {
    let (scheme, rest) = target
        .split_once("://")
        .context("absolute-form request target is required")?;
    if !scheme.eq_ignore_ascii_case("http") {
        bail!("unsupported absolute-form scheme {scheme}");
    }
    let (authority, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };
    let (host, port) = parse_authority(authority, 80)?;
    Ok(AbsoluteUri {
        scheme: scheme.to_ascii_lowercase(),
        host,
        port: Some(port),
        path: path.to_owned(),
    })
}

fn parse_authority(authority: &str, default_port: u16) -> anyhow::Result<(String, u16)> {
    if authority.is_empty() || authority.contains('@') {
        bail!("invalid authority");
    }

    if let Some(rest) = authority.strip_prefix('[') {
        let (host, after) = rest.split_once(']').context("invalid IPv6 authority")?;
        let port = if after.is_empty() {
            default_port
        } else {
            after
                .strip_prefix(':')
                .context("invalid IPv6 authority port")?
                .parse::<u16>()?
        };
        return Ok((host.to_owned(), port));
    }

    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => {
            (host, port.parse::<u16>()?)
        }
        _ => (authority, default_port),
    };

    if host.is_empty() || port == 0 || host.bytes().any(|b| b.is_ascii_whitespace()) {
        bail!("invalid authority");
    }

    Ok((host.to_owned(), port))
}

fn rewrite_absolute_request(
    original_header: &[u8],
    request: RequestParts<'_>,
    uri: &AbsoluteUri,
) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(original_header.len());
    out.extend_from_slice(
        format!("{} {} {}\r\n", request.method, uri.path, request.version).as_bytes(),
    );

    let mut has_host = false;
    for (name, value) in request.headers {
        if name.eq_ignore_ascii_case("Proxy-Authorization")
            || name.eq_ignore_ascii_case("Proxy-Connection")
        {
            continue;
        }
        if name.eq_ignore_ascii_case("Host") {
            has_host = true;
        }
        out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }

    if !has_host {
        let host = match uri.port {
            Some(80) | None => uri.host.clone(),
            Some(port) => format!("{}:{port}", uri.host),
        };
        out.extend_from_slice(format!("Host: {host}\r\n").as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    Ok(out)
}

async fn write_response(
    stream: &mut TcpStream,
    status: &str,
    auth_required: bool,
) -> anyhow::Result<()> {
    let mut response = format!("HTTP/1.1 {status}\r\n");
    if auth_required {
        response.push_str("Proxy-Authenticate: Basic realm=\"ech-grpc\"\r\n");
    }
    response.push_str("Content-Length: 0\r\n\r\n");
    stream.write_all(response.as_bytes()).await?;
    Ok(())
}
