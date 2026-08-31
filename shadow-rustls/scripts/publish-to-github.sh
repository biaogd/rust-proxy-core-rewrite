#!/usr/bin/env bash
# Publish shadow-rustls to https://github.com/biaogd/shadow-rustls
#
# Run locally with your GitHub credentials (Cloud Agent / cursor[bot] cannot
# push to shadow-rustls until the app is granted access to that repository).
set -euo pipefail

REMOTE="${SHADOW_RUSTLS_REMOTE:-https://github.com/biaogd/shadow-rustls.git}"
TAG="${SHADOW_RUSTLS_TAG:-rustls-0.23.43-shadow.1}"
EXPORT_BRANCH="${SHADOW_RUSTLS_EXPORT_BRANCH:-shadow-rustls-export}"
MAIN_REPO="${SHADOW_RUSTLS_MAIN_REPO:-https://github.com/biaogd/rust-proxy-core-rewrite.git}"

publish_from_local_tree() {
  if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "error: not a git repository" >&2
    exit 1
  fi
  git remote add origin "$REMOTE" 2>/dev/null || git remote set-url origin "$REMOTE"
  git branch -M main
  git push -u origin main
  git tag -a "$TAG" -m "shadow-rustls release (rustls 0.23.43 base)" 2>/dev/null || true
  git push origin "$TAG"
}

publish_from_export_branch() {
  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  git clone --branch "$EXPORT_BRANCH" --depth 1 "$MAIN_REPO" "$tmp"
  cd "$tmp"
  git remote add origin "$REMOTE" 2>/dev/null || git remote set-url origin "$REMOTE"
  git push -u origin "$EXPORT_BRANCH:main"
  git tag -a "$TAG" -m "shadow-rustls release (rustls 0.23.43 base)"
  git push origin "$TAG"
}

if [[ "${1:-}" == "--from-export-branch" ]]; then
  publish_from_export_branch
else
  publish_from_local_tree
fi

echo ""
echo "Published to $REMOTE (tag $TAG)."
echo ""
echo "In rust-proxy-core-rewrite/rust/Cargo.toml switch to:"
echo ""
echo '[patch.crates-io]'
echo "rustls = { git = \"https://github.com/biaogd/shadow-rustls\", tag = \"$TAG\" }"
echo "tokio-rustls = { git = \"https://github.com/biaogd/shadow-rustls\", tag = \"$TAG\" }"
echo ""
echo "Then remove the vendored shadow-rustls/ directory from the main repo and run cargo update."
