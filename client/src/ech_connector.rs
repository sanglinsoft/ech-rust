use std::{
    collections::HashMap,
    future::Future,
    io,
    path::PathBuf,
    pin::Pin,
    sync::{Mutex, OnceLock},
    task::{Context, Poll},
};

use anyhow::{bail, Context as _};
use boring::ssl::{SslConnector, SslMethod, SslVerifyMode};
use boring::x509::X509;
use http::Uri;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};
use tokio_boring::SslStream;
use tower_service::Service;
use tracing::info;

use crate::{config::BackendConfig, ech_tls::backend_tls_name, tcp_util::configure_proxy_tcp};

#[derive(Clone)]
pub struct EchConnector {
    connect_addr: String,
    sni_name: String,
    ech_config_list: Vec<u8>,
    ssl_connector: SslConnector,
}

pub struct EchTlsStream {
    inner: SslStream<TcpStream>,
}

impl EchConnector {
    pub fn new(backend: &BackendConfig, ech_config_list: Vec<u8>) -> anyhow::Result<Self> {
        let uri = backend
            .endpoint
            .parse::<Uri>()
            .with_context(|| format!("invalid backend endpoint {}", backend.endpoint))?;
        if uri.scheme_str() != Some("https") {
            bail!("ECH transport requires an https backend endpoint");
        }

        let endpoint_host = uri
            .host()
            .context("backend endpoint must include a host")?
            .to_owned();
        let port = uri.port_u16().unwrap_or(443);
        let sni_name = backend_tls_name(backend)?;
        let connect_addr = backend
            .connect_addr
            .clone()
            .unwrap_or_else(|| format!("{endpoint_host}:{port}"));
        let ssl_connector = cached_ssl_connector(backend.ca_cert.clone())?;

        Ok(Self {
            connect_addr,
            sni_name,
            ech_config_list,
            ssl_connector,
        })
    }

    async fn connect(&self) -> anyhow::Result<EchTlsStream> {
        let tcp = TcpStream::connect(&self.connect_addr)
            .await
            .with_context(|| format!("failed to connect {}", self.connect_addr))?;
        configure_proxy_tcp(&tcp);

        let mut config = self
            .ssl_connector
            .configure()
            .context("failed to configure BoringSSL connector")?;
        config.set_verify_hostname(true);
        let mut ssl = config
            .into_ssl(&self.sni_name)
            .with_context(|| format!("failed to create SSL for {}", self.sni_name))?;
        ssl.set_ech_config_list(&self.ech_config_list)
            .context("failed to configure ECHConfigList")?;

        let stream = tokio_boring::SslStreamBuilder::new(ssl, tcp)
            .connect()
            .await
            .map_err(|err| anyhow::anyhow!("BoringSSL ECH handshake failed: {err}"))?;

        if stream.ssl().selected_alpn_protocol() != Some(b"h2") {
            bail!("backend did not negotiate h2 ALPN");
        }

        if !stream.ssl().ech_accepted() {
            if let Some(retry) = stream.ssl().get_ech_retry_configs() {
                bail!(
                    "backend rejected ECH and provided retry configs ({} bytes)",
                    retry.len()
                );
            }
            bail!("backend did not accept ECH");
        }

        info!(sni = %self.sni_name, "BoringSSL ECH handshake accepted");
        Ok(EchTlsStream { inner: stream })
    }
}

fn cached_ssl_connector(ca_cert: Option<PathBuf>) -> anyhow::Result<SslConnector> {
    static CACHE: OnceLock<Mutex<HashMap<Option<PathBuf>, SslConnector>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));

    {
        let guard = cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(connector) = guard.get(&ca_cert) {
            return Ok(connector.clone());
        }
    }

    let connector = build_ssl_connector(ca_cert.as_ref())?;
    let mut guard = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    Ok(guard
        .entry(ca_cert)
        .or_insert_with(|| connector.clone())
        .clone())
}

fn build_ssl_connector(ca_cert: Option<&PathBuf>) -> anyhow::Result<SslConnector> {
    let mut builder =
        SslConnector::builder(SslMethod::tls()).context("failed to create BoringSSL connector")?;
    builder
        .set_default_verify_paths()
        .context("failed to load default certificate roots")?;
    load_native_roots(&mut builder).context("failed to load native certificate roots")?;
    builder.set_verify(SslVerifyMode::PEER);
    builder
        .set_alpn_protos(b"\x02h2")
        .context("failed to configure h2 ALPN")?;
    if let Some(path) = ca_cert {
        builder
            .set_ca_file(path)
            .with_context(|| format!("failed to load CA certificate {}", path.display()))?;
    }
    Ok(builder.build())
}

fn load_native_roots(builder: &mut boring::ssl::SslConnectorBuilder) -> anyhow::Result<()> {
    let certs = rustls_native_certs::load_native_certs()?;
    let mut loaded = 0usize;
    for cert in certs {
        let cert =
            X509::from_der(cert.as_ref()).context("failed to parse native root certificate")?;
        if builder.cert_store_mut().add_cert(&cert).is_ok() {
            loaded += 1;
        }
    }

    if loaded == 0 {
        bail!("native certificate store did not provide any usable roots");
    }

    Ok(())
}

impl Service<Uri> for EchConnector {
    type Response = EchTlsStream;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: Uri) -> Self::Future {
        let connector = self.clone();
        Box::pin(async move { connector.connect().await.map_err(io::Error::other) })
    }
}

impl hyper::client::connect::Connection for EchTlsStream {
    fn connected(&self) -> hyper::client::connect::Connected {
        hyper::client::connect::Connected::new()
    }
}

impl AsyncRead for EchTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for EchTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
