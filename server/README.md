# ECH gRPC Tunnel Server

This is the first server-side MVP for the design in `ECH_GRPC_RUST_DESIGN.md`.

## Run

```bash
/root/.cargo/bin/cargo run -p ech-grpc-server -- --config server/example.toml
```

The example config starts a plaintext gRPC server on `127.0.0.1:50051`.
Set `server.cert` and `server.key` to enable TLS.

For Docker or other environment-driven deployments, omit `--config` and set:

```bash
LISTEN=0.0.0.0:50051
TOKENS=change-me-backend-token
```

## Authentication

Clients must send backend token metadata:

```text
authorization: Bearer change-me-backend-token
```

The token is the server-visible identity for this MVP. The service does not trust
client-supplied local usernames.

## Implemented

- `TunnelService/Tunnel` bidirectional gRPC stream.
- First frame must be `Open`.
- Server-side target resolution and TCP connect.
- Token authentication.
- Allowed-port policy.
- Private, loopback, link-local, multicast, documentation, and unspecified IP denial.
- Domain targets are resolved server-side and all candidate IPs are checked before connect.
- Connected peer address is re-checked after connect.
- Bounded relay queue and 32 KiB data chunks from target to gRPC.
- Half-close, reset, ping/pong, idle timeout, and connect timeout handling.

## Not Yet Implemented

- mTLS client identity.
- Per-token quota accounting.
- Server-side metrics.
- Native health-check service.
- Integration tests with a generated client.
