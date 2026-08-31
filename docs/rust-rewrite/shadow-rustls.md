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

`biaogd/shadow-rustls` exists on GitHub but is still empty. The Cloud Agent (`cursor[bot]`) only has write access to `rust-proxy-core-rewrite`, not `shadow-rustls`. Publish from your machine (one command):

```bash
# Option A — mirror the export branch (no local checkout of shadow-rustls needed)
git clone --branch shadow-rustls-export --depth 1 \
  https://github.com/biaogd/rust-proxy-core-rewrite.git /tmp/shadow-rustls-publish
cd /tmp/shadow-rustls-publish
git remote add origin https://github.com/biaogd/shadow-rustls.git
git push -u origin shadow-rustls-export:main
git tag -a rustls-0.23.43-shadow.1 -m "shadow-rustls release (rustls 0.23.43 base)"
git push origin rustls-0.23.43-shadow.1
```

```bash
# Option B — from a rust-proxy-core-rewrite checkout
cd shadow-rustls
chmod +x scripts/publish-to-github.sh
./scripts/publish-to-github.sh
```

To let Cloud Agent push directly in future runs, grant the Cursor GitHub App write access to `biaogd/shadow-rustls` (Settings → Collaborators and apps).

**CI mirror (no local clone):** add repository secret `SHADOW_RUSTLS_PUSH_TOKEN` (classic PAT with `repo` scope) to `rust-proxy-core-rewrite`, then run the **Sync shadow-rustls** workflow from the Actions tab. It pushes branch `shadow-rustls-export` to `biaogd/shadow-rustls` `main` and tags it.

After the remote has content, bump `rust/Cargo.toml` to the git `tag`/`rev` below and delete the vendored `shadow-rustls/` directory (or convert it to a git submodule):

```toml
[patch.crates-io]
rustls = { git = "https://github.com/biaogd/shadow-rustls", tag = "rustls-0.23.43-shadow.1" }
tokio-rustls = { git = "https://github.com/biaogd/shadow-rustls", tag = "rustls-0.23.43-shadow.1" }
```

## Patch summary

See [`shadow-rustls/docs/PATCHES.md`](../../shadow-rustls/docs/PATCHES.md).
