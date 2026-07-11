use tokio::net::TcpStream;

/// Apply low-latency defaults used by relay sockets.
pub fn configure_proxy_tcp(stream: &TcpStream) {
    if let Err(err) = stream.set_nodelay(true) {
        tracing::debug!(error = %err, "failed to set TCP_NODELAY");
    }
}
