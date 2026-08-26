# Rust rewrite working agreement

This file governs the repository-wide Rust rewrite. More-specific `AGENTS.md`
files may add constraints for a subtree, but may not weaken these rules.

## Reference implementation and baseline

- The Go implementation remains the behavioral oracle. Do not delete it,
  mechanically replace it, or hide failures in it to make the Rust port pass.
- The initial compatibility baseline is commit
  `c0e43ebecf3be9b223f1015c1fc38689bb073467` on `Alpha`.
- Treat a change in observable Go behavior as an upstream compatibility change,
  not as permission to silently change a Rust expectation.
- Keep migration code isolated under `rust/` when that workspace is introduced.
  Compatibility fixtures and runners may live under `compat/`.
- Preserve the repository's GPL-3.0 licensing and copyright notices. Resolve the
  downstream binary and crate names before publishing; the existing README has
  an additional naming condition for projects not affiliated with MetaCubeX.

## Unit of work

- Work in one independently testable vertical slice at a time. A slice must
  start at an external input and end at an observable result.
- Do not migrate several unrelated protocols or subsystems in one change.
- Before coding, name the exact rows in
  `docs/rust-rewrite/compatibility-matrix.md` that the slice intends to change.
- Do not add speculative abstractions for future protocols. Introduce a shared
  abstraction only after the current slice needs it and its boundary is tested.
- Keep Go-to-Rust dependencies one-way: the Rust product must not require Go at
  runtime. Go may be invoked by development-only differential tests.

## Compatibility evidence

- Every Rust behavior must have a differential or contract test against the Go
  oracle unless the behavior is deliberately Rust-only and documented as such.
- Compare observable behavior: exit status, stdout/stderr, normalized logs,
  accepted and rejected configuration, REST status/body/headers, bytes on the
  wire, connection lifecycle, and relevant side effects.
- Normalize only nondeterministic values such as timestamps, ephemeral ports,
  UUIDs, temporary paths, timing, and map order. Never normalize semantic
  differences.
- Prefer local deterministic fixtures (echo servers, DNS authorities, test TLS
  certificates, fixed clocks/seeds) over public network services.
- A feature is not compatible merely because it compiles or passes Rust unit
  tests. Mark it compatible only after its matrix acceptance tests pass on the
  declared platform/build profile.

## Required checks

After the Cargo workspace exists, every Rust change must pass:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

Changes that affect the Go oracle, shared fixtures, or migration assumptions
must also pass:

```sh
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./...
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./... -tags with_gvisor -count=1
CGO_ENABLED=0 go build -tags with_gvisor -trimpath -o /tmp/mihomo-go-oracle .
```

Run the full unskipped interop and stress suites at release gates and for
protocol work when the environment can tolerate their runtime and network use.

## Rust quality and platform rules

- Keep `unsafe` out of protocol and policy code. Any required `unsafe` platform
  boundary needs a safety comment and focused tests.
- Isolate OS-specific code behind a small platform crate/module and explicit
  `cfg` gates. Do not spread platform conditionals through core policy code.
- Use bounded queues and explicit cancellation, timeout, shutdown, and
  half-close behavior in async code. Do not rely on task abortion as normal
  cleanup.
- Preserve wire bytes and error classes before optimizing. Performance claims
  require a reproducible benchmark against the pinned Go baseline.
- Do not introduce a Rust dependency only because a Go dependency has a similar
  name. Record protocol coverage, maintenance, licensing, and platform support.

## Documentation discipline

- Update `docs/rust-rewrite/status.md` in every migration change.
- Update `docs/rust-rewrite/compatibility-matrix.md` whenever support or test
  evidence changes.
- Update `docs/rust-rewrite/upstream-sync.md` when the Go baseline moves.
- Record partial support explicitly. Never use "compatible", "complete", or
  "drop-in replacement" without the corresponding matrix evidence.
- Stop at the requested phase boundary and report remaining gaps; do not expand
  a focused task into a repository-wide translation.
