# ShadowTLS patches over upstream rustls

Base: **rustls 0.23.43** (`fcf61cdbba30913cfd5b40aefa83989c6233812d`)

## New files

| File | Purpose |
|------|---------|
| `rustls/src/client/fingerprint.rs` | Chrome partial ClientHello profile |
| `rustls/src/client/reality.rs` | VLESS REALITY client authentication (session_id + ed25519 verify) |

## Modified files

| File | Change |
|------|--------|
| `rustls/src/lib.rs` | Export `ClientHelloFingerprint`, `RealityConfig` |
| `rustls/src/client/builder.rs` | Default fingerprint fields; `with_reality()` |
| `rustls/src/client/client_conn.rs` | Fingerprint config fields; `enable_ech_grease()`; `new_with_session_id_generator`; `reality_config` |
| `rustls/src/client/hs.rs` | `SessionIdGenerator`; fingerprint; REALITY session_id; skip session-id hook when REALITY active |
| `rustls/src/msgs/handshake.rs` | GREASE in supported versions; `extra_extensions`; fingerprint encode order |
| `rustls/src/server/test.rs` | `SupportedProtocolVersions { grease: None }` test fix |
| `tokio-rustls/src/client.rs` | `connect_with_session_id_generator` |

## Intentionally not patched

- Server-side TLS stack (ShadowTLS client only).
- Full uTLS parrots (`firefox`, `safari`, …).
- RSA/CBC cipher advertisement (rustls aws-lc cannot negotiate them).

## tokio-rustls base

**0.26.4** (`0c14e1496ef50adade4ac7c7d1f0270dfb3cdda5`) — only `connect_with_session_id_generator` added; depends on path `../rustls`.
