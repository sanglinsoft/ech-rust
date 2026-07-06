use anyhow::{bail, Context};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};
use tracing::{info, warn};

use crate::{config::BackendConfig, ech_connector::EchConnector};

pub async fn connect_channel(backend: &BackendConfig) -> anyhow::Result<Channel> {
    if backend.ech {
        let ech_config = bootstrap_ech_config(backend).await;
        match (&backend.ech_policy[..], ech_config) {
            ("strict", Ok(config)) => return connect_ech_channel(backend, config).await,
            ("strict", Err(err)) => {
                bail!(
                    "strict ECH bootstrap failed for {:?}: {err}",
                    backend.ech_name
                )
            }
            (_, Ok(config)) => match connect_ech_channel(backend, config).await {
                Ok(channel) => return Ok(channel),
                Err(err) => warn!(
                    ech_name = ?backend.ech_name,
                    error = %err,
                    "ECH transport failed; falling back to ordinary TLS"
                ),
            },
            (_, Err(err)) => warn!(
                ech_name = ?backend.ech_name,
                error = %err,
                "ECH bootstrap failed; falling back to ordinary TLS"
            ),
        }
    }

    let mut endpoint = Endpoint::from_shared(backend.endpoint.clone())
        .with_context(|| format!("invalid backend endpoint {}", backend.endpoint))?
        .connect_timeout(backend.connect_timeout())
        .http2_keep_alive_interval(std::time::Duration::from_secs(30))
        .keep_alive_timeout(std::time::Duration::from_secs(10))
        .keep_alive_while_idle(true);

    if backend.endpoint.starts_with("https://") {
        let mut tls = ClientTlsConfig::new();
        if let Some(domain) = backend.tls_domain.as_ref().or(backend.ech_name.as_ref()) {
            tls = tls.domain_name(domain.clone());
        }
        if let Some(path) = &backend.ca_cert {
            let pem = tokio::fs::read(path)
                .await
                .with_context(|| format!("failed to read CA certificate {}", path.display()))?;
            tls = tls.ca_certificate(Certificate::from_pem(pem));
        }
        endpoint = endpoint.tls_config(tls)?;
    }

    endpoint
        .connect()
        .await
        .with_context(|| format!("failed to connect backend {}", backend.endpoint))
}

async fn connect_ech_channel(
    backend: &BackendConfig,
    ech_config: Vec<u8>,
) -> anyhow::Result<Channel> {
    let uri = backend
        .endpoint
        .parse::<http::Uri>()
        .with_context(|| format!("invalid backend endpoint {}", backend.endpoint))?;
    let authority = uri
        .authority()
        .context("backend endpoint must include authority")?
        .as_str();
    let connector_uri = format!("http://{authority}")
        .parse::<http::Uri>()
        .context("failed to build internal ECH connector URI")?;

    let endpoint = Endpoint::from_shared(connector_uri.to_string())
        .context("invalid internal ECH endpoint URI")?
        .connect_timeout(backend.connect_timeout())
        .http2_keep_alive_interval(std::time::Duration::from_secs(30))
        .keep_alive_timeout(std::time::Duration::from_secs(10))
        .keep_alive_while_idle(true);

    let connector = EchConnector::new(backend, ech_config)?;
    endpoint
        .connect_with_connector(connector)
        .await
        .with_context(|| format!("failed to connect ECH backend {}", backend.endpoint))
}

async fn bootstrap_ech_config(backend: &BackendConfig) -> anyhow::Result<Vec<u8>> {
    let name = backend
        .ech_name
        .as_deref()
        .context("ech_name is required when ech = true")?;
    let doh = backend
        .ech_bootstrap_doh
        .as_deref()
        .context("ech_bootstrap_doh is required when ech = true")?;

    let query = build_https_query(name)?;
    let response = reqwest::Client::new()
        .post(doh)
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .body(query)
        .send()
        .await
        .with_context(|| format!("failed to query ECH DoH endpoint {doh}"))?
        .error_for_status()
        .with_context(|| format!("ECH DoH endpoint returned an error status: {doh}"))?
        .bytes()
        .await
        .context("failed to read ECH DoH response body")?;

    let ech = parse_https_response_for_ech(&response)
        .context("failed to parse HTTPS/SVCB response for ECHConfigList")?;
    info!(ech_name = %name, ech_config_len = ech.len(), "bootstrapped ECHConfigList");
    Ok(ech)
}

fn build_https_query(name: &str) -> anyhow::Result<Vec<u8>> {
    if name.is_empty() || name.len() > 253 {
        bail!("invalid ECH DNS name");
    }

    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(&0x4543_u16.to_be_bytes());
    out.extend_from_slice(&0x0100_u16.to_be_bytes());
    out.extend_from_slice(&1_u16.to_be_bytes());
    out.extend_from_slice(&0_u16.to_be_bytes());
    out.extend_from_slice(&0_u16.to_be_bytes());
    out.extend_from_slice(&0_u16.to_be_bytes());

    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            bail!("invalid ECH DNS label");
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&65_u16.to_be_bytes());
    out.extend_from_slice(&1_u16.to_be_bytes());
    Ok(out)
}

fn parse_https_response_for_ech(message: &[u8]) -> anyhow::Result<Vec<u8>> {
    if message.len() < 12 {
        bail!("DNS response is too short");
    }

    let flags = read_u16(message, 2)?;
    if flags & 0x8000 == 0 {
        bail!("DNS message is not a response");
    }
    if flags & 0x000f != 0 {
        bail!("DNS response returned rcode {}", flags & 0x000f);
    }

    let qdcount = read_u16(message, 4)? as usize;
    let ancount = read_u16(message, 6)? as usize;
    let mut offset = 12;

    for _ in 0..qdcount {
        skip_name(message, &mut offset)?;
        skip_bytes(message, &mut offset, 4)?;
    }

    for _ in 0..ancount {
        skip_name(message, &mut offset)?;
        let rr_type = read_u16_at(message, &mut offset)?;
        let _class = read_u16_at(message, &mut offset)?;
        let _ttl = read_u32_at(message, &mut offset)?;
        let rdlen = read_u16_at(message, &mut offset)? as usize;
        let rdata_start = offset;
        let rdata_end = offset
            .checked_add(rdlen)
            .context("DNS RDATA length overflow")?;
        if rdata_end > message.len() {
            bail!("DNS RDATA exceeds message length");
        }

        if rr_type == 65 {
            if let Some(ech) = parse_https_rdata_for_ech(message, rdata_start, rdata_end)? {
                return Ok(ech);
            }
        }

        offset = rdata_end;
    }

    bail!("HTTPS response did not contain an ech SVCB parameter");
}

fn parse_https_rdata_for_ech(
    message: &[u8],
    mut offset: usize,
    end: usize,
) -> anyhow::Result<Option<Vec<u8>>> {
    skip_bytes(message, &mut offset, 2)?;
    skip_name_bounded(message, &mut offset, end)?;

    while offset < end {
        if end - offset < 4 {
            bail!("truncated SVCB parameter");
        }
        let key = read_u16_at(message, &mut offset)?;
        let len = read_u16_at(message, &mut offset)? as usize;
        let value_end = offset
            .checked_add(len)
            .context("SVCB parameter length overflow")?;
        if value_end > end {
            bail!("SVCB parameter exceeds RDATA length");
        }
        if key == 5 {
            return Ok(Some(message[offset..value_end].to_vec()));
        }
        offset = value_end;
    }

    Ok(None)
}

fn skip_name(message: &[u8], offset: &mut usize) -> anyhow::Result<()> {
    skip_name_inner(message, offset, message.len())
}

fn skip_name_bounded(message: &[u8], offset: &mut usize, end: usize) -> anyhow::Result<()> {
    skip_name_inner(message, offset, end)
}

fn skip_name_inner(message: &[u8], offset: &mut usize, end: usize) -> anyhow::Result<()> {
    let mut pos = *offset;
    loop {
        if pos >= end || pos >= message.len() {
            bail!("truncated DNS name");
        }
        let len = message[pos];
        if len & 0xc0 == 0xc0 {
            if pos + 1 >= end || pos + 1 >= message.len() {
                bail!("truncated DNS compression pointer");
            }
            *offset = pos + 2;
            return Ok(());
        }
        if len & 0xc0 != 0 {
            bail!("unsupported DNS label type");
        }
        pos += 1;
        if len == 0 {
            *offset = pos;
            return Ok(());
        }
        pos = pos
            .checked_add(len as usize)
            .context("DNS label length overflow")?;
    }
}

fn skip_bytes(message: &[u8], offset: &mut usize, count: usize) -> anyhow::Result<()> {
    let end = offset.checked_add(count).context("offset overflow")?;
    if end > message.len() {
        bail!("truncated DNS message");
    }
    *offset = end;
    Ok(())
}

fn read_u16(message: &[u8], offset: usize) -> anyhow::Result<u16> {
    let end = offset.checked_add(2).context("offset overflow")?;
    let bytes = message
        .get(offset..end)
        .context("truncated DNS u16 field")?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u16_at(message: &[u8], offset: &mut usize) -> anyhow::Result<u16> {
    let value = read_u16(message, *offset)?;
    *offset += 2;
    Ok(value)
}

fn read_u32_at(message: &[u8], offset: &mut usize) -> anyhow::Result<u32> {
    let end = offset.checked_add(4).context("offset overflow")?;
    let bytes = message
        .get(*offset..end)
        .context("truncated DNS u32 field")?;
    *offset = end;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}
