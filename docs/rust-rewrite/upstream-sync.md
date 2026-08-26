# Upstream synchronization policy

## Pinned baseline

| Field | Value |
| --- | --- |
| Upstream remote | `https://github.com/MetaCubeX/mihomo.git` |
| Upstream branch | `Alpha` |
| Initial commit | `c0e43ebecf3be9b223f1015c1fc38689bb073467` |
| Short commit | `c0e43ebe` |
| Baseline date observed | 2026-08-21 |

The initial rewrite is evaluated against this commit. Do not move the baseline
as an incidental part of a Rust implementation change.

The branch is high velocity: the phase 0 audit observed 84 commits in the 30
days ending 2026-08-21. Periodic upstream review is therefore a planned
workstream, not cleanup postponed until the end.

## Branch and worktree model

- Keep an unmodified ref/worktree capable of building the pinned Go oracle.
- Do rewrite work on a dedicated `codex/`-prefixed branch, for example
  `codex/rust-rewrite`, rather than directly on `Alpha`.
- Track the moving `origin/Alpha` separately from the compatibility baseline.
- Build oracle binaries into `/tmp` or another out-of-tree cache and embed the
  full source commit in the test artifact metadata.
- Never use destructive reset/checkout commands to synchronize. Preserve user
  changes and use explicit commits/cherry-picks/merges after review.

## Read-only upstream audit

Use an explicit baseline variable; do not repurpose system environment names:

```sh
git fetch origin Alpha
rewrite_baseline=c0e43ebecf3be9b223f1015c1fc38689bb073467
git log --oneline --decorate "$rewrite_baseline"..origin/Alpha
git diff --stat "$rewrite_baseline"..origin/Alpha
git diff --name-status "$rewrite_baseline"..origin/Alpha
```

Then classify changed files against the compatibility matrix:

| Class | Examples | Required action |
| --- | --- | --- |
| Observable contract | CLI/config/API/wire/status/log semantics | Add/update oracle fixture and matrix row |
| Correctness/security fix | Parser validation, crypto, routing, resource lifetime | Prioritize equivalent Rust fix and regression test |
| New feature/protocol | New listener, adapter, rule, endpoint | Add Not started row; do not silently expand current phase |
| Refactor/internal optimization | No intended behavior change | Run affected differential suite; no snapshot churn expected |
| Dependency/toolchain/platform | Go fork/version/build matrix change | Reassess Rust dependency and target feasibility |
| Documentation/release only | Docs, packaging metadata | Record only if it changes advertised compatibility |

## Baseline move procedure

A baseline move is its own reviewable change and requires:

1. Record the previous and proposed full commit IDs.
2. Produce the categorized upstream change list.
3. Build and run both Go baselines against the current fixture corpus.
4. Review every oracle observation change; distinguish intended upstream
   behavior from nondeterminism or regression.
5. Add regression fixtures for security/correctness changes before updating
   Rust behavior.
6. Update `architecture.md` for boundary/call-flow changes.
7. Update `compatibility-matrix.md` for added/removed/changed features.
8. Update `status.md` with validation commands and results.
9. Change the pinned commit in all six migration documents and `AGENTS.md` in
   one commit.
10. Preserve artifacts for the previous baseline until the next phase gate
    passes, so rollback and comparison remain possible.

Do not regenerate every snapshot automatically. Snapshot churn without a
semantic review defeats the oracle.

## Upstream change ledger template

Add entries to the bottom of this file when a baseline is moved:

```text
## Sync YYYY-MM-DD: <old-short> -> <new-short>

- Upstream range: <old-full>..<new-full>
- Contract changes:
- Security/correctness changes:
- New/deferred features:
- Fixture changes:
- Rust changes:
- Validation platforms/profiles:
- Known gaps:
- Rollback artifact/reference:
```

## Sync cadence

- Run a read-only audit at least once per completed rewrite phase and before
  starting a protocol slice.
- Review urgent upstream security/correctness fixes immediately; they may
  justify a focused baseline move.
- Avoid continuously chasing `Alpha` inside an unfinished slice. Finish or
  explicitly pause the slice, audit the delta, then move the baseline in a
  dedicated change.
- Release replacement requires a fresh audit and a documented maximum allowed
  distance from upstream.

## Conflict policy

- Go behavior is authoritative for compatibility unless the team explicitly
  records a deliberate deviation.
- A known Go defect may be fixed in Rust, but the difference must have a named
  test, rationale, security/compatibility impact and matrix annotation.
- Do not modify Go tests merely because Rust behaves differently. First prove
  whether the difference is a Rust bug, fixture problem, platform difference or
  accepted deviation.
- Protocol changes must retain cross-version fixtures where peers in the field
  may still use older behavior.
