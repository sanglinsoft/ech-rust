# ECH gRPC Rust Proxy

Rust implementation of the proxy described in `ECH_GRPC_RUST_DESIGN.md`.

The current repository contains a working MVP:

- Local HTTP proxy ingress.
- Local SOCKS5 proxy ingress.
- Local username/password authentication.
- Per-user backend selection.
- China IP direct routing for literal IP targets, with geoip tables in CIDR, single-IP, or `start_ip end_ip` range format.
- gRPC bidirectional TCP relay over HTTP/2.
- Backend token authentication through `authorization: Bearer <token>` metadata.
- TLS backend transport for `https://` endpoints.
- ECH HTTPS/SVCB bootstrap over DoH and BoringSSL ECH TLS transport.

For ordinary TLS, the client uses tonic's default rustls transport. When `ech = true`, the client bootstraps ECHConfigList from HTTPS/SVCB records over DoH, performs the backend TLS handshake with BoringSSL, verifies `h2` ALPN, checks that ECH was accepted, and then hands the encrypted HTTP/2 stream to tonic through a custom connector. If `ech_policy = "strict"`, any bootstrap or ECH handshake failure fails closed. If `ech_policy = "fallback_plain_tls"`, the client falls back to ordinary TLS after an ECH failure.

## Repository Layout

```text
client/                 Rust proxy client
server/                 Rust gRPC relay server
proto/tunnel/v1/        Shared tunnel protocol
chn_ip.txt              China IPv4 table, currently IP ranges
chn_ip_v6.txt           China IPv6 table, currently IP ranges
ECH_GRPC_RUST_DESIGN.md Design document
```

## Build

```bash
cargo build --workspace
```

Check and format:

```bash
cargo fmt --all --check
cargo check --workspace
```

## Server

Example config: `server/example.toml`

```toml
[server]
listen = "127.0.0.1:50051"
# cert = "server.pem"
# key = "server.key"

[auth]
tokens = ["change-me-backend-token"]

[policy]
connect_timeout_ms = 8000
idle_timeout_secs = 300
max_concurrent_streams = 1024
deny_private_ip = true
allowed_ports = [80, 443, 8080, 8443]
```

Run:

```bash
cargo run -p ech-grpc-server -- --config server/example.toml
```

Set both `server.cert` and `server.key` to enable TLS. Clients must use a matching backend `auth_token`.

## Client

Example config: `client/example.toml`

```toml
[listen]
socks5 = "127.0.0.1:1080"
http = "127.0.0.1:8080"
socks5_allow_no_auth = true
socks5_default_user = "alice"

[users.alice]
password = "change-me-local-password"
backend = "ech-yinl"

[backends.ech-yinl]
endpoint = "https://ech.yinl.de:443"
auth_token = "change-me-backend-token"
pool_size = 2
max_streams_per_channel = 128
ech = true
ech_name = "ech.yinl.de"
ech_bootstrap_doh = "https://dns.alidns.com/dns-query"
ech_policy = "fallback_plain_tls"

[route]
china_ip_direct = true
domain_strategy = "remote_for_proxy"
china_ipv4_cidrs = "chn_ip.txt"
china_ipv6_cidrs = "chn_ip_v6.txt"
```

Run:

```bash
cargo run -p ech-grpc-client -- run --config client/example.toml
```

Test backend connectivity:

```bash
cargo run -p ech-grpc-client -- test-backend --config client/example.toml --backend ech-yinl
```

## Proxy Usage

HTTP proxy:

```bash
curl --proxy http://alice:change-me-local-password@127.0.0.1:8080 http://example.com/
```

SOCKS5 proxy:

```bash
curl --socks5 alice:change-me-local-password@127.0.0.1:1080 http://example.com/
```

Use `--socks5-hostname` if you want curl to send the hostname through SOCKS5 instead of resolving it locally.

Browser SOCKS settings often do not send SOCKS5 username/password, especially when using the operating system proxy UI. For browser use, enable:

```toml
[listen]
socks5_allow_no_auth = true
socks5_default_user = "alice"
```

Then configure the browser as a SOCKS5 proxy at `127.0.0.1:1080` without username/password. The no-auth connection is mapped to `socks5_default_user`.

## Routing Behavior

The client routes each local connection as follows:

1. Authenticate the local HTTP/SOCKS5 user.
2. Resolve the user's configured backend.
3. If `china_ip_direct = true` and the target is a literal China IP, connect directly.
4. If `domain_strategy = "system_dns"`, locally resolve domains and direct only when every resolved address is in the China IP table.
5. Otherwise proxy through the selected gRPC backend.

Default `domain_strategy = "remote_for_proxy"` avoids local DNS resolution for proxied domain targets.

## Security Notes

- Server authorization is based only on backend token metadata, not local usernames.
- The server denies private, loopback, link-local, multicast, documentation, and unspecified target IPs by default.
- The server restricts target ports with `allowed_ports` when configured.
- HTTP proxy removes `Proxy-Authorization` and `Proxy-Connection` before forwarding absolute-form requests.
- Client example passwords are plain text for MVP testing. Do not use example credentials in production.

## Current Limitations

- ECH is implemented through BoringSSL for client backend transport only; server TLS still uses tonic/rustls.
- Client Argon2 password hashes are not implemented; `password_hash` is accepted as a plain-text compatibility field only.
- Client channel reconnection and health checking are minimal.
- `update-geoip` and Windows service install/uninstall commands are placeholders.
- No mTLS, quotas, metrics, or integration test suite yet.
