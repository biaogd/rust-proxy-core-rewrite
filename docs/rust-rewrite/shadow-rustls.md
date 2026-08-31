# shadow-rustls dependency

ShadowTLS needs to shape TLS ClientHello bytes inside rustls. That cannot be done with a thin wrapper, so we maintain a **fork** of rustls **0.23.43** and tokio-rustls **0.26.4** in the [`shadow-rustls`](../../shadow-rustls/) tree (canonical remote: `https://github.com/biaogd/shadow-rustls` once published).

## Why fork, not patch-in-tree?

The old `rust/third_party/rustls` vendored copy duplicated the entire crate inside the proxy repo. A dedicated repository keeps upstream alignment, licensing, and release tags separate from application code.

## Consumer wiring

`rust/Cargo.toml` patches crates.io workspace-wide:

```toml
[patch.crates-io]
rustls = { path = "../shadow-rustls/rustls" }
tokio-rustls = { path = "../shadow-rustls/tokio-rustls" }
```

Runtime use remains opt-in: only ShadowTLS / outbound TLS paths set `client_hello_fingerprint` or `connect_with_session_id_generator`.

After publishing the standalone repo, prefer a git dependency:

```toml
[patch.crates-io]
rustls = { git = "https://github.com/biaogd/shadow-rustls", tag = "rustls-0.23.43-shadow.1" }
tokio-rustls = { git = "https://github.com/biaogd/shadow-rustls", tag = "rustls-0.23.43-shadow.1" }
```

## Publish the standalone repository

The Cloud Agent token cannot create new GitHub repositories. On a machine with `gh` authenticated as `biaogd`:

```bash
cd shadow-rustls
chmod +x scripts/publish-to-github.sh
./scripts/publish-to-github.sh
```

Or manually:

```bash
gh repo create biaogd/shadow-rustls --public --source . --remote origin --push
git tag rustls-0.23.43-shadow.1
git push origin rustls-0.23.43-shadow.1
```

Then bump `rust/Cargo.toml` to the git `tag`/`rev` above and delete the vendored `shadow-rustls/` directory from this repo (or convert it to a git submodule).

## Patch summary

See [`shadow-rustls/docs/PATCHES.md`](../../shadow-rustls/docs/PATCHES.md).
