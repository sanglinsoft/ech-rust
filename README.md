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

For ordinary TLS, the client uses tonic's default rustls transport. When `ech = true`, the client bootstraps ECHConfigList from HTTPS/SVCB records over the global `[ech].bootstrap_doh`, performs the backend TLS handshake with BoringSSL, verifies `h2` ALPN, checks that ECH was accepted, and then hands the encrypted HTTP/2 stream to tonic through a custom connector. If `[ech].policy = "strict"`, any bootstrap or ECH handshake failure fails closed. If `[ech].policy = "fallback_plain_tls"`, the client falls back to ordinary TLS after an ECH failure. Per-backend `ech_bootstrap_doh` and `ech_policy` are still accepted as compatibility overrides.

## Repository Layout

```text
client/                 Rust proxy client
server/                 Rust gRPC relay server
proto/tunnel/v1/        Shared tunnel protocol
chn_ip.txt              China IPv4 table, currently IP ranges
chn_ip_v6.txt           China IPv6 table, currently IP ranges
dist/                   Local packaging output (not committed)
ECH_GRPC_RUST_DESIGN.md Design document
```

## Build

```bash
cargo build --workspace
```

Release builds:

```bash
# Linux server (native amd64)
cargo build -p ech-grpc-server --release --target x86_64-unknown-linux-gnu

# Windows client (MinGW cross-compile from Linux)
# Requires: mingw-w64, cmake, nasm, zip
CMAKE_TOOLCHAIN_FILE="$PWD/.cargo/boringssl-windows-gnu-toolchain.cmake" \
  cargo build -p ech-grpc-client --release --target x86_64-pc-windows-gnu
```

Check and format:

```bash
cargo fmt --all --check
cargo check --workspace
```

## Packaging

After the release builds above, package artifacts into `dist/`:

```bash
mkdir -p dist/pkg dist/ech-grpc-client-windows-amd64

# Linux server tarball
cp target/x86_64-unknown-linux-gnu/release/ech-grpc-server \
  dist/pkg/ech-grpc-server-linux-amd64
chmod +x dist/pkg/ech-grpc-server-linux-amd64
tar -C dist/pkg -czf dist/ech-grpc-server-linux-amd64.tar.gz \
  ech-grpc-server-linux-amd64

# Windows client zip (include MinGW runtime DLLs)
cp target/x86_64-pc-windows-gnu/release/ech-grpc-client.exe \
  dist/ech-grpc-client-windows-amd64/
cp "$(find /usr/lib/gcc/x86_64-w64-mingw32 -path '*/libstdc++-6.dll' -print -quit)" \
  dist/ech-grpc-client-windows-amd64/
cp "$(find /usr/lib/gcc/x86_64-w64-mingw32 -path '*/libgcc_s_seh-1.dll' -print -quit)" \
  dist/ech-grpc-client-windows-amd64/
cp /usr/x86_64-w64-mingw32/lib/libwinpthread-1.dll \
  dist/ech-grpc-client-windows-amd64/
(cd dist && zip -r ech-grpc-client-windows-amd64.zip ech-grpc-client-windows-amd64)
```

Expected outputs:

| Artifact | Path |
|----------|------|
| Windows client | `dist/ech-grpc-client-windows-amd64.zip` |
| Linux server | `dist/ech-grpc-server-linux-amd64.tar.gz` |

Tagged releases (`v*`) are also built by `.github/workflows/release.yml` for additional targets (server arm64/freebsd, client linux amd64, Docker image).

Windows MinGW cross builds force `OPENSSL_NO_ASM` via `.cargo/boringssl-windows-gnu-toolchain.cmake` so BoringSSL does not require ADX/NASM objects that fail to link under MinGW.

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

Or from a packaged binary:

```bash
tar -xzf ech-grpc-server-linux-amd64.tar.gz
./ech-grpc-server-linux-amd64 --config server/example.toml
```

Set both `server.cert` and `server.key` to enable TLS. Clients must use a matching backend `auth_token`.

`LISTEN` overrides `server.listen`, and `TOKENS` overrides `auth.tokens` with a comma-separated token list. Without `--config`, the server uses default policy values plus these environment overrides.

Docker quick start:

```bash
docker run -d \
  --name ech-grpc-server \
  --restart unless-stopped \
  -p 50051:50051 \
  -e LISTEN=0.0.0.0:50051 \
  -e TOKENS=change-me-backend-token \
  ghcr.io/<owner>/<repo>/ech-grpc-server:latest
```

## Client

Example config: `client/example.toml`

```toml
[listen]
socks5 = "127.0.0.1:1080"
http = "127.0.0.1:8080"
socks5_allow_no_auth = true
socks5_default_user = "alice"

[ech]
bootstrap_doh = "https://dns.alidns.com/dns-query"
policy = "strict"

[users.alice]
password = "change-me-local-password"
backend = "ech-yinl"

[backends.ech-yinl]
endpoint = "https://ech.xxx.xx:443"
# Optional TCP dial override for ECH backends. Keep endpoint as the real
# gRPC authority/TLS host, and use connect_addr only to bypass DNS.
# Set tls_domain only if TLS/ECH should use a different name.
# connect_addr = "104.21.61.43:443"
auth_token = "change-me-backend-token"
pool_size = 2
max_streams_per_channel = 128
ech = true

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

Windows packaged binary:

```text
ech-grpc-client.exe run --config client\example.toml
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

China IP tables are loaded at startup, normalized into sorted merged ranges, and matched with binary search.

## Performance Notes

Short-term relay path improvements currently in tree:

- `TCP_NODELAY` on local ingress, direct targets, backend ECH sockets, and server dial-out sockets.
- Protobuf `bytes` fields generated as `Bytes`; tunnel relay uses `BytesMut` to avoid per-chunk `Vec` copies.
- Larger data chunks (64 KiB) and deeper outbound queues (64) for bulk transfers.
- China IP lookup is O(log n) after range merge, not linear scan.
- ECHConfigList cached by DoH endpoint + name with DNS TTL; shared DoH HTTP client; cached BoringSSL `SslConnector` / trust store.

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
