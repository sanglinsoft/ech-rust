# ECH + gRPC Rust Proxy Design

## 1. Goal

Build a Windows command-line proxy client in Rust with:

- HTTP proxy and SOCKS5 local ingress.
- Username/password authentication.
- Per-user routing to different backend servers.
- China mainland IP direct connection.
- Backend connection pooling and multiplexing.
- ECH-enabled TLS for client-to-backend gRPC transport where supported.

The remote backend is a Rust gRPC bidirectional streaming TCP relay. ECH is only used at the TLS transport layer. It hides the client-facing TLS SNI where the selected TLS entrypoint supports ECH; it does not define the tunnel protocol itself.

## 2. High-Level Architecture

```text
Windows application
  -> HTTP proxy / SOCKS5 proxy
  -> username/password auth
  -> route engine
      -> China mainland IP: direct TCP
      -> other targets: select backend by username
  -> backend gRPC channel pool
  -> ECH + TLS + HTTP/2 + gRPC bidirectional stream
  -> Rust relay server
  -> target TCP server
```

Recommended module layout:

```text
client/
  main.rs
  config.rs
  auth.rs
  ingress_http.rs
  ingress_socks5.rs
  router.rs
  china_ip.rs
  dns.rs
  ech_tls.rs
  grpc_pool.rs
  tunnel.rs

server/
  main.rs
  config.rs
  auth.rs
  grpc_service.rs
  dialer.rs
  relay.rs
  policy.rs

proto/
  tunnel/v1/tunnel.proto
```

## 3. Transport Model

Each accepted local TCP connection maps to one gRPC bidirectional stream.

HTTP/2 already provides stream multiplexing, so the first version should avoid adding a second custom mux layer inside one gRPC stream. Multiple local TCP connections can share a small pool of HTTP/2 gRPC channels.

```text
Local TCP connection A -> gRPC stream A
Local TCP connection B -> gRPC stream B
Local TCP connection C -> gRPC stream C

gRPC stream A/B/C -> shared HTTP/2 TLS channel
```

Application-level stream IDs can still be reserved in the protocol for a later custom mux version.

## 4. gRPC Protocol

```proto
syntax = "proto3";

package tunnel.v1;

service TunnelService {
  rpc Tunnel(stream ClientFrame) returns (stream ServerFrame);
}

message ClientFrame {
  oneof payload {
    Open open = 2;
    bytes data = 3;
    HalfClose half_close = 4;
    Reset reset = 5;
    Ping ping = 6;
  }
}

message ServerFrame {
  oneof payload {
    OpenResult open_result = 2;
    bytes data = 3;
    HalfClose half_close = 4;
    Reset reset = 5;
    Pong pong = 6;
  }
}

message Open {
  string target_host = 1;
  uint32 target_port = 2;
  bytes first_payload = 3;
}

message OpenResult {
  bool ok = 1;
  string error = 2;
}

message HalfClose {}

message Reset {
  string reason = 1;
}

message Ping {
  int64 unix_millis = 1;
}

message Pong {
  int64 unix_millis = 1;
}
```

Basic flow:

```text
client -> server: Open { target_host, target_port, first_payload }
server -> target: TCP connect
server -> client: OpenResult { ok: true }
client <-> server: data frames
client/server -> peer: HalfClose or Reset
```

`first_payload` avoids an extra round trip for protocols where the client already sent data immediately after CONNECT.

The first protocol version intentionally has no application-level `stream_id`: one local TCP connection maps to one gRPC stream, and HTTP/2 provides multiplexing across streams. If a later custom mux version is added, it should use a new protocol version or add a clearly defined stream identifier with strict validation.

The backend must not trust any client-supplied username. Local usernames are only client-side routing inputs. Server-side identity, auditing, quota, and access control must be derived from the authenticated backend credential, such as metadata token identity or mTLS client identity.

## 5. Local Ingress

### 5.1 SOCKS5

Supported commands:

- `CONNECT`: required.
- `UDP ASSOCIATE`: optional first-version support for DNS only.
- `BIND`: unsupported.

Authentication:

- Default: username/password required.
- Optional config flag may allow no-auth for localhost-only deployments.

SOCKS5 username maps to a local user profile, which then maps to a backend.

### 5.2 HTTP Proxy

Supported modes:

- `CONNECT host:port HTTP/1.1`.
- Absolute-form requests such as `GET http://example.com/path HTTP/1.1`.

Authentication:

- `Proxy-Authorization: Basic <base64(username:password)>`.

For HTTP CONNECT, the client returns:

```http
HTTP/1.1 200 Connection Established
```

Then the connection becomes a raw TCP tunnel.

For absolute-form HTTP requests, the proxy must:

- Parse the URI authority as the TCP target.
- Rewrite the request target from absolute-form to origin-form before forwarding.
- Preserve or synthesize a valid `Host` header for the origin server.
- Remove proxy-only headers, especially `Proxy-Authorization`.
- Reject malformed authorities, unsupported schemes, and requests without a usable host.

## 6. User Routing

Local authentication produces:

```text
username
backend_id
route_policy
quota_policy
```

Example config:

```toml
[listen]
socks5 = "127.0.0.1:1080"
http = "127.0.0.1:8080"

[users.alice]
password_hash = "$argon2id$..."
backend = "cf-edge-a"

[users.bob]
password_hash = "$argon2id$..."
backend = "vps-b"

[backends.cf-edge-a]
endpoint = "https://grpc.example.com:443"
ech = true
ech_name = "grpc.example.com"
ech_bootstrap_doh = "https://dns.alidns.com/dns-query"
auth_token = "change-me-backend-token-a"
pool_size = 4
max_streams_per_channel = 128
ech_policy = "strict"

[backends.vps-b]
endpoint = "https://vps.example.net:443"
ech = false
auth_token = "change-me-backend-token-b"
pool_size = 2
max_streams_per_channel = 128

[route]
china_ip_direct = true
domain_strategy = "remote_for_proxy"
```

Routing algorithm:

```text
authenticate local ingress user
  -> load user's backend profile
  -> classify target
      -> China mainland IP: direct TCP
      -> otherwise: proxy through selected backend
  -> take channel from user's backend pool
  -> create gRPC tunnel stream
```

For proxied traffic, the client authenticates to the backend with the selected backend credential. The backend credential is the server-visible identity and is the only identity the remote server may use for authorization, quota, and audit decisions.

## 7. China Mainland IP Direct Connection

Rules:

- If target is a literal IP, match it against the local China mainland CIDR table.
- If target is a domain, default to proxying it without local DNS resolution.
- If domain classification is required, resolve through configured DoH and classify returned A/AAAA records.
- For DoH classification, direct connection is allowed only when every usable returned A/AAAA address is inside the China mainland CIDR table.
- When a domain is classified as direct, connect to one of the classified IP addresses instead of resolving the domain again through the system resolver. Preserve the original hostname for protocol semantics such as TLS SNI or HTTP `Host`.
- If DNS resolution returns a mix of direct and non-direct addresses, no usable address, or an error, fail closed to the proxy path.

Recommended domain strategies:

```toml
domain_strategy = "remote_for_proxy" # default, avoids local DNS leakage
domain_strategy = "doh_classify"     # uses DoH to classify domains
domain_strategy = "system_dns"       # simpler but leaks local DNS
```

Direct path:

```text
local client TCP <-> target TCP
```

Proxy path:

```text
local client TCP <-> gRPC stream <-> relay server TCP <-> target TCP
```

The CIDR table should support hot reload and periodic updates. Use a prefix lookup structure instead of linear matching.

## 8. Backend Connection Pool

Each backend has an independent pool:

```text
BackendPool {
  backend_id,
  channels: Vec<GrpcChannel>,
  picker,
  health_state,
  stream_counters,
}
```

Channel selection:

- Round-robin is enough for the first version.
- Later versions may use least-active-streams.

Pool behavior:

- Preconnect `pool_size` channels per backend.
- Each channel carries up to `max_streams_per_channel` active gRPC streams.
- Failed channels are marked degraded and reconnected in the background.
- Health checks run periodically.
- Keepalive is enabled at HTTP/2/gRPC level.

`tonic::transport::Channel` is cloneable and can carry concurrent HTTP/2 streams. The explicit pool exists to maintain multiple underlying TCP/TLS connections per backend, isolate channel failures, and avoid putting all traffic behind one HTTP/2 connection limit.

Retry policy:

- A failed backend channel can be retried before a gRPC stream is opened.
- After `Open` is sent, transparent retry is unsafe because `first_payload` or later data may already have reached the target. Close the local connection and report failure instead.

## 9. Multiplexing

The first version uses HTTP/2 stream multiplexing:

```text
one local TCP connection = one gRPC stream
many gRPC streams = one HTTP/2 connection
several HTTP/2 connections = one backend pool
```

Advantages:

- Lower implementation risk.
- Backpressure and flow control are provided by HTTP/2 and tonic/hyper.
- Stream cancellation maps naturally to local connection close.

Custom mux inside a gRPC stream should be deferred unless a specific deployment needs fewer HTTP/2 streams or custom scheduling.

## 10. ECH Design

ECH is a transport plugin for backend channels. It is not visible to the tunnel protocol.

```text
client -> ECH TLS -> CDN/edge/origin -> gRPC server
```

Responsibilities:

- Query HTTPS/SVCB DNS records for the backend ECH name.
- Extract the `ech` HTTPS/SVCB parameter, decode it into an ECHConfig, and cache it according to DNS TTL.
- Build an ECH-capable TLS connector.
- Fail closed when `ech_policy = "strict"`.
- Optionally fall back to ordinary TLS when `ech_policy = "fallback_plain_tls"`.

Suggested abstraction:

```rust
#[async_trait::async_trait]
pub trait BackendConnector {
    async fn connect(&self, backend: &BackendConfig) -> anyhow::Result<GrpcChannel>;
}
```

Implementation note:

Rust ECH support depends on the TLS stack API available at implementation time. Keep ECH isolated in `ech_tls.rs` so the rest of the proxy does not depend directly on a specific rustls ECH API shape.

If the high-level `tonic::transport::Channel` API cannot accept the needed ECH TLS configuration, implement a custom connector through hyper/tonic lower-level transport integration.

Implementation requirements:

- Maintain a separate TLS configuration and channel pool per backend/ECHConfig.
- Enable ALPN `h2`; gRPC over TLS will fail without HTTP/2 negotiation.
- Keep SNI enabled for the public ECH name and certificate verification.
- Treat strict ECH failure, missing ECHConfig, incompatible TLS version, or ECH rejection as backend connection failure.
- Assume ECH requires TLS 1.3 unless the chosen TLS stack explicitly documents otherwise.
- Rebuild affected backend channels when cached ECHConfig records expire or change.

ECH DNS bootstrap notes:

- Query the backend ECH name with DNS record type `HTTPS`/`TYPE65`, not `TXT`.
- Prefer DoH wire-format (`application/dns-message`) for ECH bootstrap so the client can receive modern HTTPS/SVCB records consistently.
- Do not assume a provider's plain UDP resolver and DoH endpoint return identical HTTPS/SVCB answers. In field testing, `https://dns.alidns.com/dns-query` returned Cloudflare's `ech=` HTTPS record for `ech.yinl.de`, while plain UDP `223.5.5.5` returned `NOERROR` with zero answers at the same time.
- The current practical bootstrap choice for China-adjacent deployments is `https://dns.alidns.com/dns-query`; Cloudflare DoH can work in general but may be unreachable or TLS-blocked on some networks.
- A successful ECH bootstrap response should look like:

```text
ech.yinl.de. 300 IN HTTPS 1 . alpn="h3,h2" ipv4hint=104.21.61.43,172.67.206.1 ech="AEX+..." ipv6hint=...
```

- The `ech` parameter value is the base64-encoded ECHConfigList. Decode it before passing it to the TLS stack.
- `NOERROR` with zero HTTPS answers means the name exists but no ECHConfig is currently published through that resolver. In strict ECH mode, treat this as a connection failure.

## 11. Remote Server

The remote server is a normal Rust service:

```text
TLS listener
  -> tonic gRPC server
  -> authenticate metadata token or mTLS identity
  -> TunnelService::Tunnel
  -> target TCP connect
  -> bidirectional relay
```

Server config example:

```toml
[server]
listen = "0.0.0.0:50051"
cert = "server.pem"
key = "server.key"

[auth]
tokens = ["change-me-backend-token-a", "change-me-backend-token-b"]

[policy]
connect_timeout_ms = 8000
idle_timeout_secs = 300
max_concurrent_streams = 4096
deny_private_ip = true
allowed_ports = [80, 443, 8080, 8443]
```

Security defaults:

- Deny private, loopback, link-local, multicast, and documentation IP ranges by default.
- Restrict destination ports.
- Enforce idle timeout.
- Limit concurrent streams.
- Avoid logging full target URLs with credentials.
- For domain targets, resolve on the server and apply IP deny rules to every candidate address before connecting.
- Re-check the selected remote address after connect to reduce DNS rebinding and resolver race risks.

## 12. Data Relay

Local side:

```text
read local TCP
  -> send ClientFrame::data

read ServerFrame::data
  -> write local TCP
```

Server side:

```text
read ClientFrame::data
  -> write target TCP

read target TCP
  -> send ServerFrame::data
```

Half close:

- Local read EOF sends `HalfClose`.
- Peer receiving `HalfClose` shuts down the write half of its TCP socket where supported.
- Any protocol or I/O error sends `Reset`.

Backpressure:

- Bound all internal channels.
- Do not read unlimited local data if the gRPC sender is stalled.
- Use bytes buffers and avoid unnecessary copies.
- Split `data` frames into bounded chunks, for example 16-64 KiB.
- Configure explicit gRPC encode/decode message limits and keep them close to the maximum frame size.
- Set bounded mpsc queue depths for each relay direction; stalled writes must eventually stop reads from the corresponding TCP side.

## 13. Windows CLI

Commands:

```powershell
ech-grpc-client.exe run --config .\client.toml
ech-grpc-client.exe test-backend --backend cf-edge-a
ech-grpc-client.exe update-geoip
ech-grpc-client.exe service install --config C:\ech-grpc\client.toml
ech-grpc-client.exe service uninstall
```

Windows behavior:

- Use Tokio async runtime.
- Bind to `127.0.0.1` by default.
- Support Windows Service installation as an optional feature.
- Write logs to console and rotating files.
- Store default config under `%ProgramData%\ech-grpc\client.toml`.
- Restrict config and token file permissions to the current user or service account.

## 14. Recommended Rust Stack

```toml
tokio = { version = "1", features = ["full"] }
tonic = { version = "0.14", features = ["transport", "tls-ring"] }
prost = "0.14"
rustls = "0.23"
tokio-rustls = "0.26"
hickory-resolver = "0.26"
ipnet = "2"
clap = { version = "4", features = ["derive"] }
serde = { version = "1", features = ["derive"] }
toml = "0.8"
tracing = "0.1"
tracing-subscriber = "0.3"
argon2 = "0.5"
base64 = "0.22"
bytes = "1"
anyhow = "1"
thiserror = "1"
```

## 15. MVP Plan

1. Implement the gRPC tunnel protocol without ECH.
2. Implement the Rust relay server.
3. Implement SOCKS5 CONNECT with username/password.
4. Implement HTTP CONNECT with Basic proxy authentication.
5. Add per-user backend routing.
6. Add gRPC channel pooling and HTTP/2 stream multiplexing.
7. Add China mainland IP direct routing.
8. Add DoH-based domain classification as an optional route strategy.
9. Add ECHConfig fetching and strict ECH transport.
10. Add Windows CLI polish, logging, service installation, and hot reload.

## 16. Key Engineering Decisions

- Use HTTP/2 stream multiplexing first; postpone custom mux.
- Keep ECH isolated behind a backend connector abstraction.
- Default domain routing should avoid local DNS resolution.
- Make ECH strict by default for ECH-enabled backends.
- Treat user routing as a local client policy, not a server-side policy.
- Fail closed on authentication and policy errors.
- Keep the server generic: authenticate, connect target, relay bytes.
