use std::{net::SocketAddr, pin::Pin, sync::Arc, time::Duration};

use bytes::{Bytes, BytesMut};
use futures_core::Stream;
use futures_util::StreamExt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::mpsc,
    time,
};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::{debug, info, warn};

use crate::{
    auth::TokenAuth,
    policy::{Policy, PolicyError},
    proto::tunnel::v1::{
        client_frame, server_frame, tunnel_service_server::TunnelService, ClientFrame, HalfClose,
        OpenResult, Pong, Reset, ServerFrame,
    },
    tcp_util::configure_proxy_tcp,
};

const DATA_CHUNK_SIZE: usize = 64 * 1024;
const OUTBOUND_QUEUE: usize = 64;

type ResponseStream = Pin<Box<dyn Stream<Item = Result<ServerFrame, Status>> + Send + 'static>>;

#[derive(Debug)]
pub struct TunnelServer {
    auth: Arc<TokenAuth>,
    policy: Arc<Policy>,
    idle_timeout: Duration,
}

impl TunnelServer {
    pub fn new(auth: Arc<TokenAuth>, policy: Arc<Policy>, idle_timeout: Duration) -> Self {
        Self {
            auth,
            policy,
            idle_timeout,
        }
    }
}

#[tonic::async_trait]
impl TunnelService for TunnelServer {
    type TunnelStream = ResponseStream;

    async fn tunnel(
        &self,
        request: Request<tonic::Streaming<ClientFrame>>,
    ) -> Result<Response<Self::TunnelStream>, Status> {
        let principal = self.auth.authenticate(request.metadata())?;
        let mut inbound = request.into_inner();
        let policy = Arc::clone(&self.policy);
        let idle_timeout = self.idle_timeout;

        let (tx, rx) = mpsc::channel(OUTBOUND_QUEUE);

        tokio::spawn(async move {
            if let Err(err) = handle_tunnel(principal, policy, idle_timeout, &mut inbound, tx).await
            {
                warn!(error = %err, "tunnel ended with error");
            }
        });

        Ok(Response::new(
            Box::pin(ReceiverStream::new(rx)) as Self::TunnelStream
        ))
    }
}

async fn handle_tunnel(
    principal: String,
    policy: Arc<Policy>,
    idle_timeout: Duration,
    inbound: &mut tonic::Streaming<ClientFrame>,
    tx: mpsc::Sender<Result<ServerFrame, Status>>,
) -> anyhow::Result<()> {
    let first = match time::timeout(idle_timeout, inbound.next()).await {
        Ok(Some(Ok(frame))) => frame,
        Ok(Some(Err(status))) => {
            send_reset(&tx, status.message()).await;
            return Ok(());
        }
        Ok(None) => return Ok(()),
        Err(_) => {
            send_reset(&tx, "idle timeout waiting for Open").await;
            return Ok(());
        }
    };

    let open = match first.payload {
        Some(client_frame::Payload::Open(open)) => open,
        _ => {
            send_open_result(&tx, false, "first frame must be Open").await;
            return Ok(());
        }
    };

    let addrs = match policy
        .resolve_target(&open.target_host, open.target_port)
        .await
    {
        Ok(addrs) => addrs,
        Err(err) => {
            send_open_result(&tx, false, &err.to_string()).await;
            return Ok(());
        }
    };

    let mut target = match connect_any(&policy, &addrs).await {
        Ok(stream) => stream,
        Err(err) => {
            send_open_result(&tx, false, &err.to_string()).await;
            return Ok(());
        }
    };

    info!(
        principal = %redact_token(&principal),
        target_host = %open.target_host,
        target_port = open.target_port,
        "opened tunnel"
    );

    if !open.first_payload.is_empty() {
        if let Err(err) = target.write_all(&open.first_payload).await {
            send_open_result(&tx, false, &format!("failed to write first payload: {err}")).await;
            return Ok(());
        }
    }

    send_open_result(&tx, true, "").await;

    let (mut target_reader, mut target_writer) = target.into_split();
    let tx_from_target = tx.clone();

    let target_to_grpc = tokio::spawn(async move {
        let mut buf = BytesMut::with_capacity(DATA_CHUNK_SIZE);
        loop {
            buf.resize(DATA_CHUNK_SIZE, 0);
            match target_reader.read(&mut buf[..]).await {
                Ok(0) => {
                    let _ = tx_from_target.send(Ok(server_half_close())).await;
                    return;
                }
                Ok(n) => {
                    buf.truncate(n);
                    let data = buf.split().freeze();
                    if tx_from_target.send(Ok(server_data(data))).await.is_err() {
                        return;
                    }
                }
                Err(err) => {
                    let _ = tx_from_target
                        .send(Ok(server_reset(format!("target read failed: {err}"))))
                        .await;
                    return;
                }
            }
        }
    });

    loop {
        let next = match time::timeout(idle_timeout, inbound.next()).await {
            Ok(next) => next,
            Err(_) => {
                send_reset(&tx, "idle timeout").await;
                break;
            }
        };

        let Some(frame) = next else {
            debug!("client stream closed");
            let _ = target_writer.shutdown().await;
            break;
        };

        let frame = match frame {
            Ok(frame) => frame,
            Err(status) => {
                let _ = target_writer.shutdown().await;
                send_reset(&tx, status.message()).await;
                break;
            }
        };

        match frame.payload {
            Some(client_frame::Payload::Data(data)) => {
                if let Err(err) = target_writer.write_all(&data).await {
                    send_reset(&tx, &format!("target write failed: {err}")).await;
                    break;
                }
            }
            Some(client_frame::Payload::HalfClose(_)) => {
                let _ = target_writer.shutdown().await;
            }
            Some(client_frame::Payload::Reset(reset)) => {
                debug!(reason = %reset.reason, "client reset tunnel");
                let _ = target_writer.shutdown().await;
                break;
            }
            Some(client_frame::Payload::Ping(ping)) => {
                let _ = tx
                    .send(Ok(ServerFrame {
                        payload: Some(server_frame::Payload::Pong(Pong {
                            unix_millis: ping.unix_millis,
                        })),
                    }))
                    .await;
            }
            Some(client_frame::Payload::Open(_)) => {
                send_reset(&tx, "unexpected Open after tunnel established").await;
                break;
            }
            None => {
                send_reset(&tx, "empty client frame").await;
                break;
            }
        }
    }

    target_to_grpc.abort();
    Ok(())
}

async fn connect_any(policy: &Policy, addrs: &[SocketAddr]) -> Result<TcpStream, PolicyError> {
    let mut last_err = None;

    for addr in addrs {
        match time::timeout(policy.connect_timeout(), TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                configure_proxy_tcp(&stream);
                if let Ok(peer) = stream.peer_addr() {
                    policy.check_connected_addr(peer)?;
                }
                return Ok(stream);
            }
            Ok(Err(err)) => last_err = Some(err.to_string()),
            Err(_) => last_err = Some(format!("connect to {addr} timed out")),
        }
    }

    Err(PolicyError::Resolve(last_err.unwrap_or_else(|| {
        "all target addresses failed".to_owned()
    })))
}

async fn send_open_result(tx: &mpsc::Sender<Result<ServerFrame, Status>>, ok: bool, error: &str) {
    let _ = tx
        .send(Ok(ServerFrame {
            payload: Some(server_frame::Payload::OpenResult(OpenResult {
                ok,
                error: error.to_owned(),
            })),
        }))
        .await;
}

async fn send_reset(tx: &mpsc::Sender<Result<ServerFrame, Status>>, reason: &str) {
    let _ = tx.send(Ok(server_reset(reason.to_owned()))).await;
}

fn server_data(data: Bytes) -> ServerFrame {
    ServerFrame {
        payload: Some(server_frame::Payload::Data(data)),
    }
}

fn server_half_close() -> ServerFrame {
    ServerFrame {
        payload: Some(server_frame::Payload::HalfClose(HalfClose {})),
    }
}

fn server_reset(reason: String) -> ServerFrame {
    ServerFrame {
        payload: Some(server_frame::Payload::Reset(Reset { reason })),
    }
}

fn redact_token(token: &str) -> String {
    if token.len() <= 8 {
        return "<redacted>".to_owned();
    }
    format!("{}...", &token[..4])
}
