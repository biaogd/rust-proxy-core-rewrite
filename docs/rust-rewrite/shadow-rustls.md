# shadow-rustls dependency

ShadowTLS needs to shape TLS ClientHello bytes inside rustls. That cannot be done with a thin wrapper, so **`rewrite-transport`** depends on the fork [biaogd/shadow-rustls](https://github.com/biaogd/shadow-rustls) (rustls **0.23.43** + tokio-rustls **0.26.4**).

All other workspace crates use the default **crates.io** `tokio-rustls` / `rustls` (via `[workspace.dependencies]`).

## Scope

| Stack | rustls source | Used by |
|-------|---------------|---------|
| Default TLS | crates.io `0.26` / `0.23.43` | HTTP/SOCKS outbound, DNS, controller, runtime, reqwest, quinn, … |
| ShadowTLS + REALITY | git `biaogd/shadow-rustls` | `rewrite-transport` (`shadow_tls.rs`, `reality.rs`, …) |

There is **no** `[patch.crates-io]` — the fork is imported as renamed packages:

```toml
# rewrite-transport/Cargo.toml
shadow-rustls = { git = "https://github.com/biaogd/shadow-rustls", rev = "40a767d6fa3c519167026d4c42e21187c80798f3", package = "rustls" }
shadow-tokio-rustls = { git = "...", package = "tokio-rustls", ... }
tokio-rustls.workspace = true   # default crates.io for non-ShadowTLS paths
```

## Releases

| Tag | rustls base | tokio-rustls base | Notes |
|-----|-------------|-------------------|-------|
| `rustls-0.23.43-shadow.1` | 0.23.43 | 0.26.4 | ShadowTLS ClientHello fingerprint |
| `rustls-0.23.43-shadow.2` | 0.23.43 | 0.26.4 | + VLESS REALITY client (`with_reality()`) |
| `40a767d6fa3c519167026d4c42e21187c80798f3` | 0.23.43 | 0.26.4 | Full uTLS Chrome 133 cipher advertisement; used pending the next fork tag |

After publishing a new fork tag, bump both git deps in `rust/crates/transport/Cargo.toml`.

### Publishing a new fork tag

Work in the **`biaogd/shadow-rustls` repository** (not this repo):

```bash
git clone https://github.com/biaogd/shadow-rustls.git
cd shadow-rustls
git checkout rustls-0.23.43-shadow.1 -B main
git apply /path/to/rust-proxy-core-rewrite/docs/rust-rewrite/shadow-rustls-reality.patch
git commit -am "Add VLESS REALITY client support"
git tag rustls-0.23.43-shadow.2
git push origin main --tags
```

The patch file lives in this repo only as a convenience for the above workflow; **`rewrite-transport` never depends on `rust-proxy-core-rewrite` for rustls**.

## Patch summary

See [shadow-rustls/docs/PATCHES.md](https://github.com/biaogd/shadow-rustls/blob/main/docs/PATCHES.md).
