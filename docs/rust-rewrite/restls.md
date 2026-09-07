# Restls client boundary (Phase 6G-F)

TLS dependency: `rustls-0.23.43-shadow.3` (`f10697d`), published to
`biaogd/shadow-rustls`; Cargo.lock pins the resolved commit. Its three TLS hook
integration tests and focused Clippy pass locally. The local Go-server Restls
contract also passes. Product differential and cross-platform CI are pending.
Local main-workspace formatting and scoped config/transport/outbound Clippy
(`--all-targets --all-features -- -D warnings`) pass. Full-workspace checks stay
enabled in CI; they are not represented as completed local evidence.

Scope: AnyTLS outbound over Restls TLS 1.3. Existing Go implementation and its
`metacubex/restls-client-go v0.1.9` dependency remain the oracle. No inbound is
implemented and no Go runtime is required by the Rust product.

## Ownership

- `shadow-rustls`: an opt-in TLS 1.3 first-encrypted-record authentication hook.
  Trial decryption uses a distinct cipher and a copy of the ciphertext. Ordinary
  TLS fallback uses the untouched cipher and original bytes. Certificate and
  handshake signature validation remain active. Default TLS users are unchanged.
- `transport/restls`: BLAKE3 authentication, key-share Session ID, ClientFinished
  binding, authenticated record codec and script execution. Standard TLS and
  framing use rustls/tokio-util; crypto uses BLAKE3. Custom code is limited to the
  Go-specific protocol, not a reimplementation of TLS or cryptographic primitives.
- AnyTLS runtime/controller share the carrier dialer. Pool policy, routing and
  UDP/UoT stay outside Restls.

## Declared limits

TLS 1.2 is rejected at config and dial boundaries. Resumption/PSK and early data
are disabled; HelloRetryRequest authentication is not an accepted profile.
Exact browser fingerprints remain the existing shadow-rustls limitation;
unsupported labels are rejected. Only AnyTLS is wired, not SS/Trojan or inbound.

Scripts support fixed lengths, `~`, `?`, and `<n`. `?` is currently sampled when
the carrier is created, not once for the lifetime of a Go proxy configuration;
cross-connection sampling lifetime parity remains open. Overlarge padding that
would panic in Go returns an explicit Rust error. Ordinary TLS application data
is never exposed as proxy bytes after failed Restls record authentication.

The worker uses bounded 64 KiB application buffers, a 15-second handshake
deadline, a 30-second carrier-write deadline and explicit cancellation on Drop.
These limits are Rust policy, not exact Go timeout parity. Half-close/stress and
long-duration traffic-shape evidence remain release gates.

## Evidence commands

```sh
go build -o /Users/ren/data/rust-target/restls-authority ./compat/helpers/restls_authority
RESTLS_AUTHORITY=/Users/ren/data/rust-target/restls-authority cargo test --manifest-path rust/Cargo.toml -p rewrite-transport restls_go_oracle -- --ignored --nocapture
python3 compat/scripts/phase6g_anytls_restls.py
```

The first contract exercises Rust against the Go Restls server with local TLS,
default/custom scripts, large transfers, wrong passwords and ordinary TLS peers.
The second runs both product binaries through the same Go Restls/AnyTLS authority.
All three CI quality jobs run the otherwise ignored Go contract; the AnyTLS shard
includes the product differential. This does not establish full Restls parity.
