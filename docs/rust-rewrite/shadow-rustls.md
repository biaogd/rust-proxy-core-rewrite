# shadow-rustls dependency

ShadowTLS needs to shape TLS ClientHello bytes inside rustls. That cannot be done with a thin wrapper, so **`rewrite-outbound` alone** depends on the fork [biaogd/shadow-rustls](https://github.com/biaogd/shadow-rustls) (rustls **0.23.43** + tokio-rustls **0.26.4**).

All other workspace crates use the default **crates.io** `tokio-rustls` / `rustls` (via `[workspace.dependencies]`).

## Scope

| Stack | rustls source | Used by |
|-------|---------------|---------|
| Default TLS | crates.io `0.26` / `0.23.43` | HTTP/SOCKS outbound, DNS, controller, runtime, reqwest, quinn, … |
| ShadowTLS camouflage | git `biaogd/shadow-rustls` | `rewrite-outbound` only (`shadow_tls.rs`, `shadow_tls_config.rs`) |

There is **no** `[patch.crates-io]` — the fork is imported as renamed packages:

```toml
# rewrite-outbound/Cargo.toml
shadow-rustls = { git = "https://github.com/biaogd/shadow-rustls", tag = "rustls-0.23.43-shadow.1", package = "rustls" }
shadow-tokio-rustls = { git = "...", package = "tokio-rustls", ... }
tokio-rustls.workspace = true   # default crates.io for non-ShadowTLS paths in outbound
```

## Releases

| Tag | rustls base | tokio-rustls base |
|-----|-------------|-------------------|
| `rustls-0.23.43-shadow.1` | 0.23.43 | 0.26.4 |

After publishing a new fork tag, bump both git deps in `rust/crates/outbound/Cargo.toml`.

## Patch summary

See [shadow-rustls/docs/PATCHES.md](https://github.com/biaogd/shadow-rustls/blob/main/docs/PATCHES.md).
