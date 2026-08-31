# shadow-rustls dependency

ShadowTLS needs to shape TLS ClientHello bytes inside rustls. That cannot be done with a thin wrapper, so we maintain a **fork** of rustls **0.23.43** and tokio-rustls **0.26.4** in the standalone repository [biaogd/shadow-rustls](https://github.com/biaogd/shadow-rustls).

## Why fork, not patch-in-tree?

The old `rust/third_party/rustls` vendored copy duplicated the entire crate inside the proxy repo. A dedicated repository keeps upstream alignment, licensing, and release tags separate from application code.

## Consumer wiring

`rust/Cargo.toml` patches crates.io workspace-wide:

```toml
[patch.crates-io]
rustls = { git = "https://github.com/biaogd/shadow-rustls", tag = "rustls-0.23.43-shadow.1" }
tokio-rustls = { git = "https://github.com/biaogd/shadow-rustls", tag = "rustls-0.23.43-shadow.1" }
```

Runtime use remains opt-in: only ShadowTLS / outbound TLS paths set `client_hello_fingerprint` or `connect_with_session_id_generator`.

For local fork development, clone `shadow-rustls` next to this repo and temporarily switch to path patches:

```toml
rustls = { path = "../shadow-rustls/rustls" }
tokio-rustls = { path = "../shadow-rustls/tokio-rustls" }
```

## Releases

| Tag | rustls base | tokio-rustls base |
|-----|-------------|-------------------|
| `rustls-0.23.43-shadow.1` | 0.23.43 | 0.26.4 |

Bump the `tag` in `rust/Cargo.toml` after publishing a new shadow-rustls release, then run `cargo update -p rustls -p tokio-rustls`.

## Patch summary

See [shadow-rustls/docs/PATCHES.md](https://github.com/biaogd/shadow-rustls/blob/main/docs/PATCHES.md) on the fork repository.

## Publishing updates

1. Edit the fork on `github.com/biaogd/shadow-rustls`.
2. Tag `rustls-<version>-shadow.<n>`.
3. Bump the git `tag` in this repo's `[patch.crates-io]` section.

The **Sync shadow-rustls** workflow (`.github/workflows/sync-shadow-rustls.yml`) can mirror branch `shadow-rustls-export` when secret `SHADOW_RUSTLS_PUSH_TOKEN` is configured; it is optional now that the remote is live.
