# shadow-rustls dependency

ShadowTLS needs to shape TLS ClientHello bytes inside rustls. That cannot be done with a thin wrapper, so we depend on the fork [biaogd/shadow-rustls](https://github.com/biaogd/shadow-rustls) (rustls **0.23.43** + tokio-rustls **0.26.4**) as a normal git dependency.

## Why fork, not patch-in-tree?

The old `rust/third_party/rustls` vendored copy duplicated the entire crate inside the proxy repo. A dedicated repository keeps upstream alignment, licensing, and release tags separate from application code.

## Consumer wiring

`rust/Cargo.toml` declares the fork in `[workspace.dependencies]` (not `[patch.crates-io]`):

```toml
rustls = { git = "https://github.com/biaogd/shadow-rustls", tag = "rustls-0.23.43-shadow.1" }
tokio-rustls = { git = "https://github.com/biaogd/shadow-rustls", tag = "rustls-0.23.43-shadow.1", default-features = false, features = ["aws_lc_rs", "brotli", "ring", "tls12"] }
```

Member crates use `rustls.workspace = true` / `tokio-rustls.workspace = true` where needed. Runtime use remains opt-in: only ShadowTLS / outbound TLS paths set `client_hello_fingerprint` or `connect_with_session_id_generator`.

`reqwest` and `quinn` still pull their own crates.io `rustls` transitively; that is intentional — only our direct TLS stack uses the fork.

## Releases

| Tag | rustls base | tokio-rustls base |
|-----|-------------|-------------------|
| `rustls-0.23.43-shadow.1` | 0.23.43 | 0.26.4 |

Bump the `tag` in `[workspace.dependencies]` after publishing a new shadow-rustls release, then run `cargo update`.

## Patch summary

See [shadow-rustls/docs/PATCHES.md](https://github.com/biaogd/shadow-rustls/blob/main/docs/PATCHES.md) on the fork repository.

## Publishing updates

1. Edit the fork on `github.com/biaogd/shadow-rustls`.
2. Tag `rustls-<version>-shadow.<n>`.
3. Bump the git `tag` in this repo's `[workspace.dependencies]`.
