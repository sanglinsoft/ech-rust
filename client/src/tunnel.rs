use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use futures_util::StreamExt;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::mpsc,
};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{metadata::MetadataValue, Request};

use crate::{
    grpc_pool::BackendPool,
    proto::tunnel::v1::{
        client_frame, server_frame, tunnel_service_client::TunnelServiceClient, ClientFrame,
        HalfClose, Open, Reset,
    },
    tcp_util::configure_proxy_tcp,
};

/// Larger chunks amortize protobuf/HTTP2 framing for bulk transfers.
const DATA_CHUNK_SIZE: usize = 64 * 1024;
/// Deeper queue absorbs short bursts without stalling the reader as early.
const OUTBOUND_QUEUE: usize = 64;
const MAX_MESSAGE_SIZE: usize = DATA_CHUNK_SIZE * 2;

pub async fn relay_grpc<S>(
    stream: S,
    pool: Arc<BackendPool>,
    target_host: String,
    target_port: u16,
    first_payload: Vec<u8>,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let _permit = pool.acquire_stream_permit().await?;
    let channel = pool.pick();
    let mut client = TunnelServiceClient::new(channel)
        .max_decoding_message_size(MAX_MESSAGE_SIZE)
        .max_encoding_message_size(MAX_MESSAGE_SIZE);

    let (tx, rx) = mpsc::channel(OUTBOUND_QUEUE);
    tx.send(open_frame(
        target_host,
        target_port,
        Bytes::from(first_payload),
    ))
    .await?;

    let token = format!("Bearer {}", pool.auth_token());
    let mut request = Request::new(ReceiverStream::new(rx));
    request
        .metadata_mut()
        .insert("authorization", MetadataValue::try_from(token.as_str())?);

    let mut inbound = client.tunnel(request).await?.into_inner();
    let open_result = match inbound.message().await? {
        Some(frame) => match frame.payload {
            Some(server_frame::Payload::OpenResult(result)) => result,
            Some(server_frame::Payload::Reset(reset)) => {
                anyhow::bail!("backend reset tunnel before open: {}", reset.reason)
            }
            _ => anyhow::bail!("backend sent unexpected first frame"),
        },
        None => anyhow::bail!("backend closed tunnel before OpenResult"),
    };

    if !open_result.ok {
        anyhow::bail!("backend failed to open target: {}", open_result.error);
    }

    let (mut local_reader, mut local_writer) = tokio::io::split(stream);
    let tx_from_local = tx.clone();

    let local_to_grpc = tokio::spawn(async move {
        let mut buf = BytesMut::with_capacity(DATA_CHUNK_SIZE);
        loop {
            buf.resize(DATA_CHUNK_SIZE, 0);
            match local_reader.read(&mut buf[..]).await {
                Ok(0) => {
                    let _ = tx_from_local.send(half_close_frame()).await;
                    return;
                }
                Ok(n) => {
                    buf.truncate(n);
                    let data = buf.split().freeze();
                    if tx_from_local.send(data_frame(data)).await.is_err() {
                        return;
                    }
                }
                Err(err) => {
                    let _ = tx_from_local
                        .send(reset_frame(format!("local read failed: {err}")))
                        .await;
                    return;
                }
            }
        }
    });

    while let Some(frame) = inbound.next().await {
        let frame = frame?;
        match frame.payload {
            Some(server_frame::Payload::Data(data)) => {
                local_writer.write_all(&data).await?;
            }
            Some(server_frame::Payload::HalfClose(_)) => {
                local_writer.shutdown().await?;
                break;
            }
            Some(server_frame::Payload::Reset(reset)) => {
                anyhow::bail!("backend reset tunnel: {}", reset.reason);
            }
            Some(server_frame::Payload::Pong(_)) => {}
            Some(server_frame::Payload::OpenResult(_)) => {
                anyhow::bail!("backend sent duplicate OpenResult");
            }
            None => anyhow::bail!("backend sent empty frame"),
        }
    }

    local_to_grpc.abort();
    Ok(())
}

pub async fn relay_direct<S>(
    mut local: S,
    mut target: tokio::net::TcpStream,
    first_payload: Vec<u8>,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    configure_proxy_tcp(&target);
    if !first_payload.is_empty() {
        target.write_all(&first_payload).await?;
    }

    tokio::io::copy_bidirectional(&mut local, &mut target).await?;
    Ok(())
}

fn open_frame(target_host: String, target_port: u16, first_payload: Bytes) -> ClientFrame {
    ClientFrame {
        payload: Some(client_frame::Payload::Open(Open {
            target_host,
            target_port: u32::from(target_port),
            first_payload,
        })),
    }
}

fn data_frame(data: Bytes) -> ClientFrame {
    ClientFrame {
        payload: Some(client_frame::Payload::Data(data)),
    }
}

fn half_close_frame() -> ClientFrame {
    ClientFrame {
        payload: Some(client_frame::Payload::HalfClose(HalfClose {})),
    }
}

fn reset_frame(reason: String) -> ClientFrame {
    ClientFrame {
        payload: Some(client_frame::Payload::Reset(Reset { reason })),
    }
}
