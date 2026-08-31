# ShadowTLS patches over upstream rustls

Base: **rustls 0.23.43** (`fcf61cdbba30913cfd5b40aefa83989c6233812d`)

## New files

| File | Purpose |
|------|---------|
| `rustls/src/client/fingerprint.rs` | Chrome partial ClientHello profile |

## Modified files

| File | Change |
|------|--------|
| `rustls/src/lib.rs` | Export `ClientHelloFingerprint` |
| `rustls/src/client/builder.rs` | Default fingerprint fields on `ClientConfig` |
| `rustls/src/client/client_conn.rs` | Fingerprint config fields; `enable_ech_grease()`; `new_with_session_id_generator` |
| `rustls/src/client/hs.rs` | `SessionIdGenerator`; apply fingerprint; session-id rewrite after CH encode |
| `rustls/src/msgs/handshake.rs` | GREASE in supported versions; `extra_extensions`; fingerprint encode order |
| `rustls/src/server/test.rs` | `SupportedProtocolVersions { grease: None }` test fix |
| `tokio-rustls/src/client.rs` | `connect_with_session_id_generator` |

## Intentionally not patched

- Server-side TLS stack (ShadowTLS client only).
- Full uTLS parrots (`firefox`, `safari`, …).
- RSA/CBC cipher advertisement (rustls aws-lc cannot negotiate them).

## tokio-rustls base

**0.26.4** (`0c14e1496ef50adade4ac7c7d1f0270dfb3cdda5`) — only `connect_with_session_id_generator` added; depends on path `../rustls`.
