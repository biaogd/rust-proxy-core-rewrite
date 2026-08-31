# shadow-rustls

Fork of [rustls](https://github.com/rustls/rustls) **0.23.43** and [tokio-rustls](https://github.com/rustls/tokio-rustls) **0.26.4** with the minimal hooks required for [ShadowTLS](https://github.com/ihciah/shadow-tls) camouflage in the rust-proxy-core-rewrite project.

Crate names stay **`rustls`** and **`tokio-rustls`** so consumers can keep using `[patch.crates-io]` as a drop-in replacement.

## Why fork instead of a wrapper crate?

ShadowTLS needs to change ClientHello construction inside rustls (`emit_client_hello_for_retry`) and TLS message encoding (`SupportedProtocolVersions` GREASE, `extra_extensions`). A thin wrapper cannot do that without vendoring or forking.

## Upstream bases

| Crate | Version | Upstream git SHA |
|-------|---------|------------------|
| rustls | 0.23.43 | `fcf61cdbba30913cfd5b40aefa83989c6233812d` |
| tokio-rustls | 0.26.4 | `0c14e1496ef50adade4ac7c7d1f0270dfb3cdda5` |

See [docs/PATCHES.md](docs/PATCHES.md) for the full patch list.

## Patches (summary)

### rustls

- **`client/fingerprint.rs`** — partial Chrome / uTLS `HelloChrome_Auto` ClientHello shaping (cipher list minus aws-lc unsupported suites, GREASE, extension shuffle, BoringGREASEECH).
- **`ClientConfig`** — `client_hello_fingerprint`, `client_hello_fingerprint_mlkem`, `enable_ech_grease()`.
- **`ClientHelloInput` / `hs.rs`** — optional `session_id_generator` callback for ShadowTLS v3 session-id HMAC.
- **`msgs/handshake.rs`** — GREASE supported versions, `extra_extensions`, fingerprint extension ordering.
- **`ClientConnection::new_with_session_id_generator`** — public API for session-id hook.

### tokio-rustls

- **`TlsConnector::connect_with_session_id_generator`** — async entry point for the session-id hook.

## Usage in a workspace

```toml
[patch.crates-io]
rustls = { git = "https://github.com/biaogd/shadow-rustls", rev = "<tag-or-sha>" }
tokio-rustls = { git = "https://github.com/biaogd/shadow-rustls", rev = "<tag-or-sha>" }
```

For local development next to rust-proxy-core-rewrite:

```toml
[patch.crates-io]
rustls = { path = "../shadow-rustls/rustls" }
tokio-rustls = { path = "../shadow-rustls/tokio-rustls" }
```

Enable Chrome fingerprint on a `ClientConfig`:

```rust
config.client_hello_fingerprint = Some(rustls::ClientHelloFingerprint::Chrome);
config.client_hello_fingerprint_mlkem = true; // false for ShadowTLS v2
```

ShadowTLS v3 session-id HMAC:

```rust
tokio_rustls::TlsConnector::from(config)
    .connect_with_session_id_generator(server_name, io, |client_hello| { /* 32 bytes */ })
    .await?;
```

## Maintenance

1. Track upstream rustls releases on the `upstream/rustls-0.23` branch (or rebase tags).
2. Re-apply `docs/PATCHES.md` changes; run `cargo test` in this workspace.
3. Tag `rustls-<version>-shadow.<n>` and bump the git `rev` in consumers.

## License

Same as upstream: Apache-2.0 OR ISC OR MIT (rustls), MIT OR Apache-2.0 (tokio-rustls).
