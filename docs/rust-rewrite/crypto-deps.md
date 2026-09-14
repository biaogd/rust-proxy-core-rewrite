# RustCrypto dependency generations

The Cargo lockfile intentionally carries two RustCrypto generations for several
primitives. This is an accepted dependency-tree state, not an open cleanup
ticket.

## Observed dual versions

| Crate | Workspace / “old” path | Transitive / “new” path |
| --- | --- | --- |
| `aes` | 0.8.x | 0.9.x |
| `aes-gcm` | 0.10.x | 0.11.x |
| `chacha20poly1305` | 0.10.x | 0.11.x |
| `cipher` | 0.4.x | 0.5.x |
| `digest` | 0.10.x | 0.11.x |

Exact patch versions live in `rust/Cargo.lock`.

## Why both generations stay

First-party protocol adapters still call the older RustCrypto API surface that
their differential gates were written against:

- VMess (`rewrite-protocol-vmess`)
- Snell (`rewrite-protocol-snell`)
- ShadowsocksR (`rewrite-protocol-shadowsocksr`)
- related transport helpers that share those AEAD crates

Shadowsocks outbound uses the maintained `shadowsocks` / `shadowsocks-crypto`
0.8 stack, which already depends on the newer generation. SSH (`russh` /
`ssh-cipher`) and `age` also pull older-generation crates transitively.

So even a complete first-party API bump would not collapse the tree to a single
generation while those third-party crates remain on their current majors.

## Policy

- Prefer gradual, behavior-neutral migration of **our own** algorithm call sites
  when a slice already needs crypto work and existing differentials stay green.
- Do **not** force a workspace-wide RustCrypto major bump only to make
  `cargo tree` look tidy.
- Protocol encryption regressions are higher cost than duplicate crate majors.
- Third-party major bumps (for example waiting for `russh`, `age`, or
  `shadowsocks-crypto` consumers to converge) are opportunistic follow-ups, not
  compatibility expansions.

Workspace pins in `rust/Cargo.toml` remain on the older generation used by
first-party adapters until a focused, differential-backed migration moves them.
