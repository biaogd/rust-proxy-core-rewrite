#!/usr/bin/env bash
# Publish this directory to https://github.com/biaogd/shadow-rustls
# Run from the shadow-rustls repo root (standalone clone or this folder after `git init`).
set -euo pipefail

REMOTE="${SHADOW_RUSTLS_REMOTE:-https://github.com/biaogd/shadow-rustls.git}"
TAG="${SHADOW_RUSTLS_TAG:-rustls-0.23.43-shadow.1}"

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "error: not a git repository; run: git init && git add -A && git commit -m 'Initial shadow-rustls'" >&2
  exit 1
fi

if ! gh repo view biaogd/shadow-rustls >/dev/null 2>&1; then
  echo "Creating GitHub repository biaogd/shadow-rustls ..."
  gh repo create biaogd/shadow-rustls \
    --public \
    --description "rustls 0.23.43 + tokio-rustls 0.26.4 fork with ShadowTLS ClientHello hooks" \
    --source . \
    --remote origin \
    --push
else
  git remote add origin "$REMOTE" 2>/dev/null || git remote set-url origin "$REMOTE"
  git push -u origin HEAD:main
fi

git tag -a "$TAG" -m "shadow-rustls release (rustls 0.23.43 base)" 2>/dev/null || true
git push origin "$TAG"

echo ""
echo "Published. In rust-proxy-core-rewrite/rust/Cargo.toml switch to:"
echo ""
echo '[patch.crates-io]'
echo "rustls = { git = \"https://github.com/biaogd/shadow-rustls\", tag = \"$TAG\" }"
echo "tokio-rustls = { git = \"https://github.com/biaogd/shadow-rustls\", tag = \"$TAG\" }"
echo ""
echo "Then remove the vendored shadow-rustls/ tree from the main repo and run cargo update."
