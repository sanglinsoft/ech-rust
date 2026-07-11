use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use anyhow::{bail, Context};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};
use tracing::{info, warn};

use crate::{
    config::{BackendConfig, EchConfig},
    ech_connector::EchConnector,
};

const DEFAULT_ECH_CACHE_TTL: Duration = Duration::from_secs(300);
const MIN_ECH_CACHE_TTL: Duration = Duration::from_secs(30);
const MAX_ECH_CACHE_TTL: Duration = Duration::from_secs(3600);

#[derive(Clone)]
struct CachedEchConfig {
    config: Vec<u8>,
    expires_at: Instant,
}

pub async fn connect_channel(backend: &BackendConfig, ech: &EchConfig) -> anyhow::Result<Channel> {
    if backend.ech {
        let ech_name = backend_tls_name(backend)?;
        let ech_config = bootstrap_ech_config(backend, ech).await;
        match (backend.effective_ech_policy(ech), ech_config) {
            ("strict", Ok(config)) => return connect_ech_channel(backend, config).await,
            ("strict", Err(err)) => bail!("strict ECH bootstrap failed for {ech_name}: {err}"),
            (_, Ok(config)) => match connect_ech_channel(backend, config).await {
                Ok(channel) => return Ok(channel),
                Err(err) => warn!(
                    ech_name = %ech_name,
                    error = %err,
                    "ECH transport failed; falling back to ordinary TLS"
                ),
            },
            (_, Err(err)) => warn!(
                ech_name = %ech_name,
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
        tls = tls.domain_name(backend_tls_name(backend)?);
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

async fn bootstrap_ech_config(backend: &BackendConfig, ech: &EchConfig) -> anyhow::Result<Vec<u8>> {
    let name = backend_tls_name(backend)?;
    let doh = backend.effective_ech_bootstrap_doh(ech).to_owned();
    let cache_key = format!("{doh}\0{name}");

    if let Some(cached) = get_cached_ech_config(&cache_key) {
        info!(
            ech_name = %name,
            ech_config_len = cached.len(),
            "using cached ECHConfigList"
        );
        return Ok(cached);
    }

    let query = build_https_query(&name)?;
    let response = doh_client()
        .post(&doh)
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

    let (ech_config, ttl) = parse_https_response_for_ech(&response)
        .context("failed to parse HTTPS/SVCB response for ECHConfigList")?;
    put_cached_ech_config(cache_key, ech_config.clone(), ttl);
    info!(
        ech_name = %name,
        ech_config_len = ech_config.len(),
        ttl_secs = ttl.as_secs(),
        "bootstrapped ECHConfigList"
    );
    Ok(ech_config)
}

fn doh_client() -> reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .pool_max_idle_per_host(2)
                .build()
                .expect("failed to build DoH HTTP client")
        })
        .clone()
}

fn ech_config_cache() -> &'static Mutex<HashMap<String, CachedEchConfig>> {
    static CACHE: OnceLock<Mutex<HashMap<String, CachedEchConfig>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn get_cached_ech_config(key: &str) -> Option<Vec<u8>> {
    let mut cache = ech_config_cache()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let now = Instant::now();
    if let Some(entry) = cache.get(key) {
        if entry.expires_at > now {
            return Some(entry.config.clone());
        }
    }
    cache.remove(key);
    None
}

fn put_cached_ech_config(key: String, config: Vec<u8>, ttl: Duration) {
    let ttl = ttl.clamp(MIN_ECH_CACHE_TTL, MAX_ECH_CACHE_TTL);
    let mut cache = ech_config_cache()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    cache.insert(
        key,
        CachedEchConfig {
            config,
            expires_at: Instant::now() + ttl,
        },
    );
}

pub fn backend_tls_name(backend: &BackendConfig) -> anyhow::Result<String> {
    if let Some(name) = backend
        .tls_domain
        .as_deref()
        .or(backend.ech_name.as_deref())
    {
        return Ok(name.to_owned());
    }

    let uri = backend
        .endpoint
        .parse::<http::Uri>()
        .with_context(|| format!("invalid backend endpoint {}", backend.endpoint))?;
    uri.host()
        .map(ToOwned::to_owned)
        .context("backend endpoint must include a host")
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

fn parse_https_response_for_ech(message: &[u8]) -> anyhow::Result<(Vec<u8>, Duration)> {
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
        let ttl = read_u32_at(message, &mut offset)?;
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
                let ttl = if ttl == 0 {
                    DEFAULT_ECH_CACHE_TTL
                } else {
                    Duration::from_secs(u64::from(ttl))
                };
                return Ok((ech, ttl));
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
