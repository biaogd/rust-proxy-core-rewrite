# Compatibility matrix

Baseline: `c0e43ebecf3be9b223f1015c1fc38689bb073467` (`Alpha`).

This is the authority for support claims. A Rust implementation is compatible
only when the relevant row is marked **Parity** with named test evidence.
`go-capability-inventory.md` is the exhaustive planning census: future slices
must cite both its stable inventory IDs and the exact rows changed here. An
aggregate row in this matrix does not erase a more-specific inventory gap.

## Legend

| State | Meaning |
| --- | --- |
| Oracle | Present in the pinned Go reference implementation |
| Not started | No Rust behavior exists |
| Partial | Some declared cases work; exclusions are listed |
| Parity | Declared cases pass Go/Rust differential tests |
| Deferred | Intentionally outside the current roadmap |

Phase 1 through Phase 4D3A parity claims below are deliberately narrow. Existing
Go unit tests are useful evidence but are not Go/Rust differential evidence.

## CLI and process lifecycle

| Capability | Go | Rust | Required parity evidence |
| --- | --- | --- | --- |
| Phase 5A1 default config/home resolution | Oracle | **Parity** | Existing legacy home, absolute/relative `-d` and `CLASH_HOME_DIR`, conditional absolute/relative XDG fallback, default/explicit initial-file creation and missing-parent behavior in `compat/scripts/phase5a1.py` |
| Phase 1 explicit `-f` configuration file | Oracle | **Parity** | `compat/scripts/phase1.py` on Darwin arm64 and Linux amd64 |
| Phase 5A1 `-d`, `-config`, stdin config and input precedence | Oracle | **Parity** | CLI-over-environment and base64 > stdin > explicit/env file > default selection, normalized success paths, exit and error classes in `compat/scripts/phase5a1.py` |
| Phase 1 `-t` configuration corpus | Oracle | **Parity** | Valid minimal, malformed YAML, invalid mode/rule/port-type and out-of-range integer |
| Full `-t` configuration surface | Oracle | Not started | Expanded valid/invalid golden corpus |
| Phase 5A2a `-v` default version output | Oracle | **Parity** | Product/version, Go-compatible OS/architecture names, implementation compiler version, build time, clean stderr, zero exit and config short-circuit in `compat/scripts/phase5a2a.py`; Rust truthfully reports `rustc` rather than `go` |
| `-v` feature-tag build variants | Oracle | Not started | One native build/output gate per supported feature profile |
| Phase 5A2b `-m` geodata-mode default | Oracle | **Parity** | Default false, CLI-enabled default and explicit YAML true/false precedence observed from the live `/configs` surface in `compat/scripts/phase5a2b.py` |
| Phase 5A3a controller address/secret overrides | Oracle | **Parity** | CLI, environment, CLI-over-environment, explicit-empty disablement, old-listener absence, Bearer auth and SIGHUP reapplication in `compat/scripts/phase5a3a.py` |
| Remaining controller/UI/routing-mark process overrides | Oracle | Not started | Split by listener/resource boundary under 5A3b onward |
| Controller/UI/secret CLI overrides | Oracle | Not started | Config plus override differential |
| `convert-ruleset` | Oracle | Partial | Phases 5A5a–5A5f accept IP-CIDR/domain text/YAML ↔ MRS v1, streaming YAML preamble/malformed-entry recovery, no-newline boundary and pinned classical rejection; invalid-rule warning text and exhaustive malformed records remain unclaimed |
| `generate` | Oracle | **Parity** | Phases 5A6a–5A6g cover UUID, Reality/WireGuard, ECH, VLESS X25519/ML-KEM-768 and Sudoku commands plus missing/unknown/trailing command lifecycle |
| Phase 5A4a X25519 age-encrypted config | Oracle | **Parity** | File/base64 input, CLI/environment/explicit-empty precedence, wrong key, invalid-key warning on plaintext and live applied config in `compat/scripts/phase5a4a.py` |
| Phase 5A4b `age convert` for X25519 | Oracle | **Parity** | Exact recipient output, ignored trailing argument and invalid/missing-key exit classes in `compat/scripts/phase5a4b.py` |
| Phase 5A4c X25519 `age encrypt` / `decrypt` | Oracle | **Parity** | Binary file/stdin/stdout round trips, plaintext pass-through, error exits and bidirectional Go/Rust armor interoperability in `compat/scripts/phase5a4c.py` |
| Phase 5A4d X25519 `age keygen` | Oracle | **Parity** | Three-line RFC3339/public/secret output shape, config short-circuit, ignored trailing argument and cross-implementation conversion in `compat/scripts/phase5a4d.py` |
| Phase 5A5a IP-CIDR MRS to text | Oracle | **Parity** | Go-produced zstd MRS v1 fixture, merged IPv4/IPv6 minimal-prefix output, startup short-circuit, ignored trailing argument and basic CLI error classes in `compat/scripts/phase5a5a.py` |
| Phase 5A5b IP-CIDR text/YAML to MRS | Oracle | **Parity** | Valid text/YAML comments and payloads, merged IPv4/IPv6 ranges, empty-rule failure and Go↔Rust MRS frame interchange in `compat/scripts/phase5a5b.py`; compressed bytes are encoder-specific, so decoded records are compared |
| Phase 5A5c domain MRS to text | Oracle | **Parity** | Go-produced zstd MRS v1 succinct-domain-set decoding, exact/wildcard/complex-wildcard normalization, sorted text, startup short-circuit and malformed-frame exit class in `compat/scripts/phase5a5c.py` |
| Phase 5A5d domain text/YAML to MRS | Oracle | **Parity** | Text/YAML (`payload`/`rules`) exact, `*`, `+.` and dot-wildcard inputs, case normalization, empty-rule lifecycle and Go↔Rust succinct-domain-set frame interchange in `compat/scripts/phase5a5d.py`; invalid-entry warning text remains unclaimed |
| Phase 5A5e classical conversion rejection | Oracle | **Parity** | Pinned baseline rejects classical text/YAML/empty-format/MRS after source read and empty-target creation; exit/stdout/stderr class, trailing argument and startup short-circuit in `compat/scripts/phase5a5e.py` |
| Phase 5A5f streaming YAML rulesets | Oracle | **Parity** | Unrelated preamble skipping, `payload`/`rules` header discovery, per-entry malformed YAML recovery, later valid domain/IP-CIDR records, single-line/no-newline failure and bidirectional MRS decoding in `compat/scripts/phase5a5f.py` |
| Phase 5A6a `generate uuid` | Oracle | **Parity** | Canonical lowercase RFC 4122 UUID v4 structure, ignored trailing argument, startup short-circuit, unknown-command silence and missing-command exit class in `compat/scripts/phase5a6a.py` |
| Phase 5A6b `generate reality-keypair` | Oracle | **Parity** | Two labeled raw URL-safe Base64 32-byte keys, explicit private clamp, independently recomputed X25519 public relation, ignored trailing argument and startup short-circuit in `compat/scripts/phase5a6b.py` |
| Phase 5A6c `generate wg-keypair` | Oracle | **Parity** | Two labeled padded standard-Base64 32-byte keys, explicit private clamp, independently recomputed X25519 public relation, ignored trailing argument and startup short-circuit in `compat/scripts/phase5a6c.py` |
| Phase 5A6d `generate vless-x25519` | Oracle | **Parity** | Fixed-key byte-exact eight-line output, generated/clamped private and related public password, BLAKE3 Hash32/lazy-config interpolation, invalid-length exit and startup short-circuit in `compat/scripts/phase5a6d.py` |
| Phase 5A6e `generate ech-keypair` | Oracle | **Parity** | Parsed ECHConfigList version/id/KEM/cipher suites/name/extensions, `ECH KEYS` PEM records, independently recomputed X25519 relation, trailing argument, missing-name exit and startup short-circuit in `compat/scripts/phase5a6e.py` |
| Phase 5A6f `generate vless-mlkem768` | Oracle | **Parity** | Fixed 64-byte `d || z` seed produces byte-exact Go/Rust encapsulation key, BLAKE3 Hash32 and eight-line lazy config; generated shape, invalid-length exit and startup short-circuit in `compat/scripts/phase5a6f.py` |
| Phase 5A6g `generate sudoku-keypair` | Oracle | **Parity** | Two canonical Edwards25519 split scalars, compressed public point, independent scalar-sum/basepoint recovery, exact lowercase hex labels, trailing argument and startup short-circuit in `compat/scripts/phase5a6g.py` |
| Full age identities and encrypted config | Oracle | Partial | Multiple identities and hybrid/PQ, SSH, encrypted-identity and plugin forms remain unclaimed |
| Phase 1 SIGTERM cleanup | Oracle | **Parity** | Exit 0, listener/idle stream closure and bounded task drain |
| Phase 5A7b SIGINT/SIGTERM local-resource shutdown | Oracle | **Parity** | Zero exit, bounded idle-stream closure and immediate mixed/controller/DNS TCP plus DNS UDP port release in `compat/scripts/phase5a7b.py` |
| Full shutdown/profile semantics | Oracle | Partial | Local resources and Phase 4F14 fake-IP persistence have evidence; future providers, TUN and remote adapters require their own shutdown gates |
| Phase 3 local SIGHUP rule/listener reload | Oracle | **Parity** | Same-port rule switch, invalid-config rollback and port migration in `compat/scripts/phase3.py` |
| Phase 5A7a invalid SIGHUP recovery | Oracle | **Parity** | Malformed-YAML rollback, continued old-generation TCP routing and a following valid reload through the same signal loop in `compat/scripts/phase5a7a.py` |
| Full SIGHUP reload across all Mihomo resources | Oracle | Partial | Local listener/config generations exist; providers, broader DNS state, TUN and remote adapters are not started |
| Phase 5A8a Unix `post-up` / `post-down` hooks | Oracle | **Parity** | CLI/environment/explicit-empty precedence, system-shell operators, startup readiness, Go-compatible post-down boundary and asymmetric failure exits in `compat/scripts/phase5a8a.py` |
| Cross-platform and future-resource hook ordering | Oracle | Partial | Windows uses `cmd.exe /C` but needs native differential evidence; every future runtime resource must join the readiness/shutdown barrier |

## Configuration surface

| Capability group | Go | Rust | Required parity evidence |
| --- | --- | --- | --- |
| Phase 1 minimal YAML (`mixed-port`, Rule mode, log level, IPv6 flag, one rule) | Oracle | **Parity** | `compat/fixtures/config/phase1-*` differential corpus |
| Phase 2 declared default overlay and malformed YAML | Oracle | **Parity** | 37 fixed plus 96 seeded generated Go/Rust observations in `compat/scripts/phase2.py` |
| Phase 2 general ports, mode, logging, IPv6, interface and keepalive fields (spec only) | Oracle | **Parity** | Default/override/null/error observations; no listener/resource application claim |
| Phase 3 local authentication records | Oracle | **Parity** | HTTP Basic, SOCKS4 USERID and SOCKS5 username/password accept/reject cases |
| LAN allow/deny and skip-auth prefixes | Oracle | Not started | Parser plus remote-address connection decisions |
| Phase 3 controller TCP address and secret | Oracle | **Parity** | Live loopback TCP controller and Bearer authorization observations |
| Controller TLS/Unix/pipe | Oracle | Not started | Per-platform live controller fixtures |
| `external-controller-cors` defaults/config/reload | Oracle | **Parity** | Allow-all defaults/empty list, exact/single-wildcard origins, Private Network, denied method/header, auth ordering and hot reload in `compat/scripts/phase5d_cors.py` |
| UI paths/download settings and safe-path checks | Oracle | Not started | Path traversal and normalization cases |
| Proxies and built-in proxy insertion | Oracle | Not started | Normalized inventory/error corpus |
| Proxy groups and cycle/order validation | Oracle | Not started | DAG, duplicate and reserved-name cases |
| Proxy providers and health checks | Oracle | Not started | Local provider server, refresh/state tests |
| Rules, sub-rules and rule providers | Oracle | Partial | Phase 2 pure rule/sub-rule subset only; providers and runtime resources are not started |
| Named listeners | Oracle | Not started | Type-specific accepted/rejected configs |
| Hosts | Oracle | Partial | Phase 4B exact configured IP/CNAME plus native Darwin system-host subset; wildcard, `lan` and broad platform behavior are not started |
| DNS and fake-IP configuration | Oracle | Partial | Phase 4A/4B classic/hosts, Phase 4C fake settings, Phase 4D1 policy, Phase 4D2 fallback and Phase 4D3A single local direct resolver; general fallback, proxy-server/respect-rules and encrypted DNS remain unclaimed |
| TUN and route settings | Oracle | Not started | Per-OS parse/apply fixtures |
| Static tunnels and proxy validation | Oracle | Not started | TCP/UDP target fixtures |
| NTP | Oracle | Not started | Local NTP server and ordering tests |
| iptables | Oracle | Not started | Linux namespace integration tests |
| TLS/custom CA/client auth/ECH | Oracle | Not started | Certificate and handshake fixtures |
| Profile persistence | Oracle | Partial | Phase 4C fake-IP mapping/allocation restart behavior only; Go `cache.db` format/interchange, corruption and other profile state are unclaimed |
| Sniffer | Oracle | Not started | HTTP/TLS/QUIC payload fixtures |
| Geodata URLs/loaders/matchers/updates | Oracle | Not started | Pinned local data files, no public latest |
| Experimental and build-feature settings | Oracle | Not started | Feature-profile parser/runtime tests |
| Deprecated/removed configuration behavior | Oracle | Not started | Accepted aliases, warnings and Go-compatible rejection corpus, including removed relay groups |

## Inbound listeners

| Listener | TCP | UDP | Go | Rust | Differential evidence |
| --- | --- | --- | --- | --- | --- |
| Phase 1 mixed HTTP/SOCKS5 TCP subset | Yes | No | Oracle | **Parity** | Fragmented HTTP absolute-form, CONNECT, SOCKS5 IPv4/domain, disabled-IPv6 close and auth-method reply; Phase 1 re-passes after HTTP syntax parsing moved to `httparse` |
| Full mixed HTTP/SOCKS listener | Yes | SOCKS UDP | Oracle | Partial | Phase 3 declared HTTP/SOCKS4/4a/5 TCP and local SOCKS5 UDP subset; broader HTTP/UDP semantics remain |
| Phase 3 fixed HTTP TCP subset | Yes | No | Oracle | **Parity** | Absolute-form/CONNECT, Basic 407/403/success, relay and half-close observations re-pass after the `httparse` migration |
| Phase 3 fixed/mixed SOCKS subset | Yes | Yes | Oracle | **Parity** | SOCKS4/4a/5 CONNECT, USERID/user-pass, UDP ASSOCIATE, IPv4 DIRECT write-back and FRAG drop |
| Redir | Yes | Platform-dependent | Oracle | Not started | Linux/Darwin/FreeBSD socket tests |
| TProxy | Yes | Linux-real semantics | Oracle | Not started | Linux network namespace tests |
| Tunnel | Yes | Yes | Oracle | Not started | Fixed target and write-back tests |
| TUN | Yes | Yes | Oracle | Not started | Per-stack/per-OS integration tests |
| Shadowsocks | Yes | Yes | Oracle | Not started | Upstream interop matrix |
| Snell | Yes | Yes | Oracle | Not started | Version and UDP interop matrix |
| VMess | Yes | Transport-dependent | Oracle | Not started | v2ray interop and transport matrix |
| VLESS | Yes | Transport-dependent | Oracle | Not started | Interop, Vision/Reality/transports |
| Trojan | Yes | Yes | Oracle | Not started | TLS/auth/fallback/UDP interop |
| Hysteria2 | Yes | Yes | Oracle | Not started | QUIC/congestion/obfs interop |
| Hysteria2 realm | Yes | Yes | Oracle | Not started | Realm routing/interoperability |
| TUIC | Yes | Yes | Oracle | Not started | v4/v5/QUIC interop |
| ShadowQUIC | Yes | Yes | Oracle | Not started | QUIC extension and datagram interop |
| AnyTLS | Yes | Protocol-dependent | Oracle | Not started | Padding/session/auth interop |
| Mieru | Yes | Yes | Oracle | Not started | TCP/UDP/mux interop |
| Sudoku | Yes | Yes | Oracle | Not started | Handshake/obfs/mux/replay interop |
| TrustTunnel | Yes | Yes/ICMP | Oracle | Not started | HTTP/2/TCP/packet/ICMP interop |
| Legacy fixed VMess/SS/TUIC ports | Yes | Varies | Oracle | Not started | Legacy config and rebind behavior |
| Shared inbound transport/security variants | Varies | Varies | Oracle | Not started | Reality, ShadowTLS, ReSTLS, JLS, TLSMirror, mux, WebSocket, HTTP/2, gRPC/Gun, xHTTP, mKCP and Mekya fixtures per consuming protocol |

## Rules and routing

| Rule family | Go | Rust | Required parity evidence |
| --- | --- | --- | --- |
| Phase 1 Rule mode with exactly `MATCH,DIRECT` | Oracle | **Parity** | Valid/malformed rule corpus and live DIRECT routing |
| Full MATCH behavior and routing modes | Oracle | Partial | `phase5d_modes.py` proves live Rule/Direct/Global switching through PATCH and inline PUT on current mixed TCP and SOCKS UDP, plus GLOBAL DIRECT/REJECT selection effects; configured remote targets and future inbound families remain unclaimed |
| Domain exact/suffix/keyword | Oracle | **Parity in current local host path** | Phase 2 proves fixed/seeded matching and sniff-host precedence; the aggregate 5B core suite proves all three families through hosts-backed mixed-TCP DIRECT/REJECT routing; no exhaustive IDNA/sniffer claim |
| Domain regex/wildcard | Oracle | **Partial** | Phases 5B1a–5B1b prove `DOMAIN-REGEX` ignore-case/lookahead/comma-bearing parsing and `DOMAIN-WILDCARD` byte-level `*`/`?`, errors and mixed TCP DIRECT/REJECT routing; exhaustive regexp2/Unicode corpus remains pending |
| IPv4/IPv6 CIDR source/destination | Oracle | **Partial** | Phase 2 proves `IP-CIDR`, `IP-CIDR6`, `SRC-IP-CIDR` and `src`; Phase 4D3A plus aggregate 5B core prove live destination/source IPv4, lazy DNS and `no-resolve`; native IPv6 live routing remains pending |
| IP suffix, unmap, no-resolve and resolver interaction | Oracle | **Partial** | Phases 5B2a–5B2b plus aggregate 5B core prove destination/source IPv4, non-byte suffixes, mapped-IPv4 unmapping, IPv6 pure match/miss/source, invalid width and live DIRECT/REJECT; native IPv6 live and exhaustive resolver interaction remain pending |
| Source/destination/inbound ports and TCP/UDP network | Oracle | **Parity in current fixed local scope** | Phase 2 proves pure range/list/reversal/error cases; Phases 5B2d–5B2e and 5B UDP prove live SOCKS/mixed TCP+UDP SRC/DST/IN port and network routing; future inbound families retain their own gates |
| DSCP and remaining metadata matchers | Oracle | **Partial** | Phases 5B2c and 5B UDP prove default DSCP `0` across current TCP/UDP listeners, nonzero miss, slash/reversed ranges, wildcard and invalid values above 63; capture of nonzero DSCP from transparent/TUN paths remains pending |
| Process name/path variants and UID | Oracle | Not started | Per-OS process fixtures |
| Phase 2 rematch-name pure metadata matcher | Oracle | **Parity** | Rematch mutation followed by `REMATCH-NAME` observation |
| Inbound type/user/name matchers | Oracle | **Parity in current fixed local scope** | Phases 5B3a–5B3c plus 5B UDP prove fixed HTTP/SOCKS/mixed TCP+UDP metadata; both default UDP sockets report SOCKS5/`DEFAULT-SOCKS` and intentionally carry no TCP auth user; named listeners and future protocols remain pending |
| GEOIP/GEOSITE/ASN | Oracle | Not started | Pinned geodata corpus |
| RULE-SET/providers | Oracle | Not started | Classical/domain/IP formats and refresh |
| SUB-RULE and AND/OR/NOT logic | Oracle | **Partial** | Phase 2 proves nested pure matching, missing references and cycles; Phases 5B3d/5B3f prove basic AND/OR/NOT and SUB-RULE mixed-TCP DIRECT/REJECT routing; lazy DNS/process helpers and the broader nested corpus remain pending |
| PASS/PASS-RULE/REMATCH scan | Oracle | **Partial** | Phase 2 proves pure ordered scan and cycles; Phases 5B3e–5B3g prove live PASS/PASS-RULE plus REMATCH name mutation and sub-rule switching; live cycle/failure behavior remains pending |
| Proxy groups/select/fallback/url-test/load-balance | Oracle | Partial | `phase5c_selector.py` proves flat selector control/routing; `phase5c_selector_reload.py` proves valid-member selection retention, invalid-config rollback and first-member fallback when the old choice disappears on SIGHUP. Nested/provider members, restart persistence and automatic strategies remain unclaimed |
| Lazy DNS/process resolution | Oracle | Not started | Call-count, ordering and error tests |
| Rule hit/miss statistics and disable API | Oracle | Not started | REST and concurrent match tests |

## Outbound adapters

| Outbound type | Go | Rust | Required parity evidence |
| --- | --- | --- | --- |
| Phase 1 DIRECT TCP | Oracle | **Parity** | HTTP/echo, domain/IP, dial failure, binary relay and half-close |
| Full DIRECT TCP/UDP/platform options | Oracle | Partial | Phase 1/3 local TCP plus IPv4 SOCKS UDP subset; interface/mark/TFO/MPTCP/general NAT are not claimed |
| REJECT / REJECT-DROP | Oracle | Partial | Phase 3 immediate TCP REJECT parity only; REJECT-DROP timing and full UDP behavior are not claimed |
| DNS / PASS / PASS-RULE / REMATCH | Oracle | Not started | Routing semantics and metadata mutation |
| HTTP | Oracle | Partial | `phase6b_http.py` proves configured plaintext HTTP proxy parsing, Basic authentication, exact CONNECT authority/Host and bidirectional mixed-TCP relay with a rejecting fallback; TLS, unauthenticated/error/timeout matrices, UDP and controller adapter views remain unclaimed |
| SOCKS5 | Oracle | Partial | `phase6b_socks5.py` proves configured username/password, strict auth-method offer, CONNECT address bytes, exact adapter JSON and bidirectional mixed-TCP relay with a rejecting fallback; unauthenticated/failure matrices, domain-resolution policy, TLS, UDP/UoT and chaining remain unclaimed |
| Shadowsocks (`ss`) | Oracle | Not started | Cipher/plugin/UoT interop |
| ShadowsocksR (`ssr`) | Oracle | Not started | Cipher/protocol/obfs interop |
| VMess | Oracle | Not started | Security/early-data/transport interop |
| VLESS | Oracle | Not started | Encryption/Vision/Reality/transports |
| Snell | Oracle | Not started | Version/UDP/pool interop |
| Trojan | Oracle | Not started | TLS/fallback/UDP interop |
| Hysteria / Hysteria2 | Oracle | Not started | QUIC/fake-TCP/obfs/congestion interop |
| TUIC | Oracle | Not started | v4/v5/0-RTT/congestion interop |
| ShadowQUIC | Oracle | Not started | QUIC stream/datagram interop |
| WireGuard / AmneziaWG | Oracle | Not started | Tunnel, routing and DNS integration |
| SSH | Oracle | Not started | Auth/host-key/keepalive/mux tests |
| Mieru | Oracle | Not started | Client/mux interop |
| AnyTLS | Oracle | Not started | Session/padding/TLS interop |
| Sudoku | Oracle | Not started | Handshake/obfs/mux interop |
| MASQUE | Oracle | Not started | CONNECT-IP/QUIC interop |
| TrustTunnel | Oracle | Not started | HTTP/2/packet/ICMP interop |
| OpenVPN | Oracle | Not started | Control/data/rekey/cipher interop |
| Gost relay | Oracle | Not started | Chain and addressing tests |
| Tailscale | Oracle (`with_gvisor`) | Not started | tsnet/DNS/tailnet integration |
| ZeroTier | Oracle (unless disabled) | Not started | Network lifecycle/integration |
| Dialer-proxy chains and sing-mux | Oracle | Not started | Nested dial path, TCP/UDP, statistics, cycle/error and close behavior |
| Shared outbound transport/security variants | Oracle | Not started | WebSocket, HTTP/2, gRPC/Gun, xHTTP/H3, mKCP, Mekya, plugins, Reality, ECH, JLS, ReSTLS, ShadowTLS and TLSMirror interop per consumer |

## DNS

| Capability | Go | Rust | Required parity evidence |
| --- | --- | --- | --- |
| Phase 4A UDP/TCP DNS server subset | Oracle | **Parity** | UDP and TCP queries, framing, ID echo, AA/flags and A response semantics in `compat/scripts/phase4.py` |
| Common DNS wire codec infrastructure | Oracle | **Parity** in the declared 4A/4F1/4F15 scope | `hickory-proto` now builds ordinary queries and decodes questions/compressed names; Phase 4A, 4F1 and 4F15 re-pass while oracle-specific EDNS/flags/truncation remain explicit |
| Phase 4F1 full local UDP/TCP DNS server semantics | Oracle | **Parity** | `DNS-01`; header accept/reject/ignore matrix, malformed wire, representative name-bearing/text/address/SOA/unknown RR relay, RCODE behavior, EDNS and UDP truncation in `compat/scripts/phase4f1.py` |
| Phase 4A IP-literal UDP/TCP upstream | Oracle | **Parity** | Both transports observed by the deterministic loopback authoritative server |
| Phase 4F2 general classic main-upstream selection | Oracle | **Parity** | `DNS-02`; non-loopback config, UDP/TCP domain bootstrap, concurrent fastest-valid selection, connection/RCODE failover, five-second timeout and UDP-TC retry in `compat/scripts/phase4f2.py` |
| Phase 4F3 system resolver selection | Oracle | **Partial** | Both `system` spellings, POSIX parser, five-minute refresh/disable/restore/delete contract, Windows adapter filter and Android-CMFA replace/clear contract; deterministic native port-53 Go/Rust wire parity and Android native execution remain pending |
| Phase 4E1 loopback insecure DoT main-upstream subset | Oracle | **Parity** | Local TLS server, DNS/TCP framing, cache behavior and config/process observations in `compat/scripts/phase4e1.py` |
| Phase 4E2 custom-CA verified DoT main-upstream subset | Oracle | **Parity** | Inline root/leaf chain, explicit SNI/name verification, wrong-name SERVFAIL, DNS/TCP framing and cache observations in `compat/scripts/phase4e2.py` |
| Phase 4E3 multiple inline custom roots for verified DoT | Oracle | **Parity** | Decoy + issuing root selection, issuing-root order, untrusted-chain SERVFAIL and cache observations in `compat/scripts/phase4e3.py` |
| Phase 4E4 verified main-DoT connection reuse subset | Oracle | **Parity** | Cross-client reuse, positive-cache separation, stale pooled-connection one-shot reconnect and bounded pool observations in `compat/scripts/phase4e4.py` |
| Phase 4E5 verified HTTPS DoH GET main-upstream subset | Oracle | **Parity** | HTTP/1.1 GET query encoding, zero upstream DNS ID, media headers, custom-root/name validation, response restoration and cache observations in `compat/scripts/phase4e5.py` |
| Phase 4E6 verified HTTP/1.1 DoH connection-reuse subset | Oracle | **Parity** | Persistent cross-client reuse, positive-cache separation and stale pooled-connection recovery observations in `compat/scripts/phase4e6.py` |
| Phase 4E7 custom absolute DoH path subset | Oracle | **Parity** | Config acceptance, exact HTTP request target, response/ID and positive-cache observations in `compat/scripts/phase4e7.py` |
| Phase 4E8 percent-encoded unreserved DoH path subset | Oracle | **Parity** | Encoded-path config acceptance, Go-compatible decoded HTTP target, response/ID and cache observations in `compat/scripts/phase4e8.py` |
| Phase 4E9 domain DoT/default-port/bootstrap subset | Oracle | **Parity** | `DNS-06`; domain endpoint config, implicit 853 normalization, one classic loopback `default-nameserver`, bootstrap A query, verified DoT wire/cache/process observations in `compat/scripts/phase4e9.py` |
| Phase 4E10 DoT trust/verification matrix subset | Oracle | **Parity** | `DNS-06`; default system + embedded + global roots, `skip-cert-verify`, `name-cert-verify` precedence, reuse toggle and deterministic trusted/untrusted/name-mismatch observations in `compat/scripts/phase4e10.py` |
| Phase 4E11 DoT concurrency/timeout/reset/retry subset | Oracle | **Parity** | `DNS-06`; 12 concurrent misses/8 idle cap, five-second response timeout, SIGHUP pool reset, stale one-shot reconnect and fresh-failure retry bound in `compat/scripts/phase4e11.py` |
| Phase 4E12 plaintext HTTP DoH/default URL subset | Oracle | **Parity** | `DNS-07`; explicit/default port, empty/root/custom path normalization, RFC 8484 GET wire, ID restoration, cache and sequential reuse in `compat/scripts/phase4e12.py` |
| Phase 4E13 HTTPS root/query/userinfo/redirect subset | Oracle | **Parity** | `DNS-07`; implicit/default port and root path, discarded configured query, ASCII Basic userinfo, persistent same-origin relative redirects and Go-compatible ten-request limit in `compat/scripts/phase4e13.py` |
| Phase 4E14 domain-host HTTPS bootstrap/trust subset | Oracle | **Parity** | `DNS-07`; one loopback UDP bootstrap A lookup, URL-domain Host/SNI, default/name-override/skip verification precedence and trusted/untrusted outcomes in `compat/scripts/phase4e14.py` |
| Phase 4E15 DoH HTTP/2 negotiation/GET subset | Oracle | **Parity** | `DNS-08`; TLS ALPN `h2`, RFC 8484 GET pseudo/header fields, zero DNS ID, response restoration, sequential stream reuse and HTTP/1.1 fallback in `compat/scripts/phase4e15.py` |
| DoH HTTP/1 client infrastructure | Oracle | **Parity** in the declared 4E scope | Hyper owns HTTP/1 framing and connection driving; 4E5–4E8 and 4E12–4E15 re-pass for GET wire, bounded body, reuse/reconnect, paths, redirects, trust/bootstrap and H2 fallback |
| Phase 4E16 DoH HTTP/3 selection/reconnect subset | Oracle | **Parity** | `DNS-08`; `#h3=true`, `dns.prefer-h3`, H3-faster race, H2-only fallback, RFC 8484 GET, sequential QUIC reuse, closed-connection recovery and oracle-compatible `Used0RTT=false` in `compat/scripts/phase4e16.py` |
| Phase 4E17 verified DoQ framing subset | Oracle | **Parity** | `DNS-09`; loopback explicit-port `quic://`, custom root/name verification, ALPN `doq`, one bidirectional stream, exact two-octet framing, zero upstream ID, FIN, response-ID restoration, wrong-name and empty-response SERVFAIL in `compat/scripts/phase4e17.py` |
| Phase 4E18 DoQ reuse/concurrency/retry/reset subset | Oracle | **Parity** | `DNS-09`; sequential and eight overlapping streams on one connection, two bounded `NO_ERROR` reconnect attempts, same-config SIGHUP reset and full-handshake `DidResume=false`/`Used0RTT=false` observations in `compat/scripts/phase4e18.py` |
| Phase 4E19 encrypted-upstream wrapper subset | Oracle | **Parity** | `DNS-10`; verified DoQ IPv4/IPv6 ECS injection, existing-ECS preserve/override, A/AAAA/TYPE65 request short-circuit, one-A-answer filtering, authoritative empty response and upstream call count in `compat/scripts/phase4e19.py` |
| Full DoH/DoT/DoQ | Oracle | Partial | Multiple/system bootstrap and broader domain/IPv6 combinations, encoded userinfo, absolute/cross-origin and connection-closing redirects, cross-platform positive system-store fixtures, broader DoH/DoQ retry and pool behavior, HTTP/3 token/rejection/concurrency/flow-control/GOAWAY and accepted-resumption behavior, DoQ default/domain endpoints, broader trust, timeout/cancellation, token rejection/stateless reset/idle timeout and encrypted policy/fallback/direct upstreams remain unclaimed; custom-certificate paths are not a Go feature |
| Phase 4F4 DHCP upstream | Oracle | **Partial** | Named-interface config, `dhcp://system` alias, exact DHCPDISCOVER/OFFER wire contract, 20-second interface/one-hour DNS invalidation and address-change refresh re-pass after DHCPv4 codecs moved to `dhcproto`; privileged native DHCP exchange and reload/native-platform parity remain pending |
| Phase 4F5 synthetic RCODE and Tailscale DNS registration | Oracle | **Partial** | Six RCODE values over UDP/TCP plus accepted/rejected config and registered/missing/replacement/unregister lifecycle in `compat/scripts/phase4f5.py`; actual tsnet `QueryDNS` transport remains Phase 7K |
| Phase 4F6 classic UDP/TCP query wrappers | Oracle | **Parity** | Per-upstream IPv4/IPv6 ECS inject/preserve/override, disabled requests, compressed multi-record filtering in all RR sections, false/invalid values and wrapper/raw-transport identity in `compat/scripts/phase4f6.py` |
| Full DNS upstream wrapper parameters | Oracle | Partial | TLS verification/reuse, H3 selection and encrypted/classic ECS/disable slices pass; proxy-name, `respect-rules`, and wrapper combinations across broader resolver sets remain unclaimed |
| Phase 4F7 resolver-set composition core | Oracle | **Partial** | All accepted transport forms compose in default/main/fallback/direct/proxy-server sets; deterministic multi-client selection, fallback filtering, direct-follow-policy and explicit default/proxy lookups pass in `compat/scripts/phase4f7.py`; complete bootstrap consumers and real proxy-outbound use remain pending |
| Phase 4F8 ordered resolver policies | Oracle | **Partial** | Main/proxy multi-upstream policies, YAML matcher barriers, same-node overwrite, comma expansion, all four GeoSite domain types and inline domain/classical rule-set matchers pass in `compat/scripts/phase4f8.py`; external provider vehicles, GeoSite attributes, `respect-rules` and a real proxy consumer remain pending |
| Phase 4F9 fallback decision core | Oracle | **Partial** | File-backed geodata-mode GeoIP including inversion/private-address behavior, GeoSite/domain and IPv4/IPv6 CIDR filters, multiple fallback clients, eager/lazy SERVFAIL and shared five-second timeout ordering pass in `compat/scripts/phase4f9.py`; MMDB-mode GeoIP and broader transport/retry integration remain pending |
| Phase 4F10 dual-stack/ECH/lazy tunnel core | Oracle | **Parity** | Concurrent A/AAAA start, A-first ordering, default/configured IPv6 wait windows, primary-IPv4 early return and AAAA fallback, IP literals, HTTPS ECH extraction/missing-ECH error and mixed SOCKS rule-stage lazy resolution pass in `compat/scripts/phase4f10.py` |
| Phase 4F11 DNS cache lifecycle core | Oracle | **Parity** | Configured LRU/ARC capacity and scan behavior, positive/SOA-negative cache lifetime, TTL=1 stale return with refresh, caller-ID-safe singleflight, uncached SERVFAIL background retry and SIGHUP invalidation pass in `compat/scripts/phase4f11.py`; pooled connection teardown remains jointly covered by Phase 4E11/4E18 |
| Phase 4F12 complete hosts core | Oracle | **Parity** | Exact/`*`/inner-`*`/`.`/`+.` priority, scalar IP/domain and multi-IP values, `lan`, alias chains, A/AAAA/CNAME plus non-address/class pass-through, `dns.use-hosts`, native system hosts and randomized tunnel address selection pass in `compat/scripts/phase4f12.py` on Darwin |
| Phase 4F13 redir-host local-inbound core | Oracle | **Parity** | HTTP/SOCKS/mixed TCP, SOCKS/mixed UDP, upstream/configured CNAME identity, same-listener reload preservation, TTL-past retention and size-only LRU contract pass in `compat/scripts/phase4f13.py` and focused state tests |
| Phase 4F14 fake-IP lifecycle core | Oracle | **Parity** | Blacklist/whitelist domain trie, GeoSite and inline domain/classical rule-set filters; ordered domain/suffix/keyword/regex/wildcard/GeoSite/rule-set/MATCH actions; v4/v6 Go bbolt interchange; TCP/UDP reverse routing; memory range migration; persistent range reset; persistent REST flush/restart and corrupt-cache recovery pass in `compat/scripts/phase4f14.py` |
| Phase 4D1 simple nameserver policy | Oracle | **Parity** | Exact, `*` one-label and `+.` root/deep suffix selection across local UDP/TCP authorities, overlap priority and policy cache hit in `compat/scripts/phase4d1.py` |
| Full policy and proxy/direct nameservers | Oracle | Partial | Phase 4F8 proves the ordered main/proxy policy core and Phase 4D3A proves direct-follow-policy; external rule-provider vehicles, GeoSite attributes, proxy data-plane consumption and `respect-rules` remain unclaimed |
| Phase 4D2 single main/fallback answer-filter subset | Oracle | **Parity** | One local fallback, `+.` domain forcing, IPv4 CIDR answer filtering, eager/lazy call behavior, policy precedence and selected-response cache hit in `compat/scripts/phase4d2.py` |
| Full main/fallback filters and lazy fallback | Oracle | Partial | Phase 4F9 proves the deterministic geodata-mode filter and scheduling core; MMDB-mode GeoIP, broader accepted-transport runtime combinations, cache/retry interaction and non-loopback integration remain unclaimed |
| Phase 4D3A direct resolver and lazy IP-rule TCP subset | Oracle | **Parity** | Ordered domain/IP-CIDR rule queries, `no-resolve`, one local direct nameserver, policy-follow behavior and DIRECT TCP result in `compat/scripts/phase4d3a.py` |
| Cache TTL, stale refresh, singleflight/retry | Oracle | **Parity** | Phase 4F11 product differential covers LRU/ARC max-size eviction, positive and SOA-negative TTL, stale refresh, eight-way singleflight, one observable background retry and reload invalidation; unusual non-trailing OPT layouts and cancellation races remain outside the declared deterministic core |
| Phase 4B exact hosts and CNAME subset | Oracle | **Parity** | Configured A/AAAA, CNAME-only, CNAME-to-upstream and Darwin system-host observations in `compat/scripts/phase4b.py` |
| Full hosts and CNAME behavior | Oracle | **Partial** | Phase 4F12 proves the portable trie/value/query/tunnel core and current native-host lookup on Darwin; editable hosts-file refresh, native Windows behavior and Linux CI evidence remain unclaimed |
| Phase 4B redir-host TCP mapping subset | Oracle | **Parity** | Local DNS A answer -> IP SOCKS5 CONNECT -> recovered DOMAIN rule -> DIRECT echo chain |
| Full redir-host mapping | Oracle | **Partial** | Phase 4F13 proves all currently implemented local HTTP/SOCKS/mixed TCP and SOCKS/mixed UDP paths, both CNAME identities, reload and baseline size-only-LRU retention; redir-port, TProxy, TUN and future inbound families remain unclaimed |
| Phase 4C fake IPv4/IPv6 pool subset | Oracle | **Parity** | First/+4 allocation, case-stable reuse, v4/v6 separation, exact blacklist/whitelist bypass, /29 wrap, 1000-entry memory eviction and graceful-restart recovery in `compat/scripts/phase4c.py`; the fixture enables the oracle's IPv6 test escape hatch on hosts without global-unicast IPv6 |
| Full fake-IP behavior and persistence format | Oracle | **Partial** | Phase 4F14 proves every filter rule kind, GeoSite plus inline domain/classical providers, v4/v6 Go bbolt interchange, current TCP/UDP reverse routing, reload/range behavior, REST flush and malformed-cache recovery; file/HTTP/MRS providers, redir/TProxy/TUN and future inbound families, concurrent writers and broader native platforms remain unclaimed |
| EDNS0 echo, UDP size and truncation | Oracle | **Parity** | Phase 4F1; 1232 OPT echo with DO preservation, upstream OPT preservation, implicit 512, advertised 256-as-512 and advertised 900 truncation, plus untruncated TCP evidence |
| DNS hijack through TUN | Oracle | Not started | Platform TUN integration |
| Phase 4D4 local DNS REST A/AAAA/CNAME query and positive-cache flush subset | Oracle | **Parity** | Authenticated query JSON plus REST/local-listener shared cache hit/flush/refetch behavior in `compat/scripts/phase4d4.py` |
| Full DNS REST query and cache control | Oracle | Partial | Phase 4F15 accepts the oracle RR type-name table, renders representative simple/structured/character-string RR JSON, and proves authenticated DNS/fake-IP flush status, method handling and ordinary cache invalidation; exhaustive presentation vectors for every legacy/obsolete Go-known RDATA type remain unclaimed |

## REST controller

| Surface | Go | Rust | Required parity evidence |
| --- | --- | --- | --- |
| TCP/TLS/Unix/Windows pipe listeners | Oracle | Partial | Phase 3 loopback TCP only; TLS/Unix/pipe are not started |
| Secret auth, WebSocket token and CORS | Oracle | **Parity** | Current TCP controller Bearer/query-token acceptance/rejection plus default/configured/reloaded CORS actual/preflight contracts pass in `phase5d_streams.py` and `phase5d_cors.py` |
| `/`, `/version`, `/memory`, `/traffic` | Oracle | Partial | Phase 3 root/version/traffic HTTP evidence plus Phase 5D memory HTTP/WS first frames and traffic WS first frame; sustained cadence and real process-memory accounting remain unclaimed |
| `/logs` WebSocket/stream | Oracle | Partial | Plain HTTP info/invalid-level and WebSocket info-event contracts pass; structured format, exhaustive filtering, lag/backpressure and sustained cadence remain unclaimed |
| `/configs` GET/PUT/PATCH and `/configs/geo` | Oracle | Partial | `phase5d_configs.py` proves the current GET snapshot, PATCH for HTTP/SOCKS/mixed ports plus log level/IPv6, transactional listener migration, inline-YAML PUT, payload-over-path precedence, controller preservation, parse rollback and malformed/unknown input contracts; remaining PATCH fields, safe absolute/default path loading and `/configs/geo` remain unclaimed |
| `/proxies`, `/group`, delay and selection | Oracle | Partial | `phase5d_proxies.py` proves all seven built-ins and GLOBAL; `phase5c_selector.py` adds exact configured HTTP/selector detail and live selection-driven routing; local HEAD delay, expected/timeout validation, history/extra health and current TCP/UDP mode effects pass; other groups, provider members, HTTPS and exhaustive failure/reload/persistence remain unclaimed |
| `/rules` and disable operation | Oracle | Partial | `phase5d_rules.py` proves ordered DomainSuffix/MATCH inventory fields, shared hit/miss counters and timestamps, disable/enable routing side effects, ignored indexes and malformed-body behavior; exhaustive rule payload rendering, GeoIP/GeoSite size and reload-state behavior remain unclaimed |
| `/connections` stream/list/delete | Oracle | **Parity** | Current local TCP tracking, totals, query-token/Bearer WebSocket snapshots and interval plus DELETE one/missing/all with live tunnel closure pass in Phase 3 and `phase5d_streams.py`/`phase5d_connections.py` |
| Proxy and rule provider APIs | Oracle | Partial | `phase5d_providers.py` proves the implicit `default` provider core; `phase5c_selector.py` proves configured HTTP and selector members also appear with exact detail views. No-op update/health, missing-resource errors and the empty rule-provider collection pass; external vehicles, real refresh/health state, rule-provider detail and persistence remain unclaimed |
| Cache, DNS and storage APIs | Oracle | Partial | Phase 4F15 completes `/dns/query` and both cache flush routes; `phase5d_storage.py` proves process-local `/storage/{key}` missing/read/raw-JSON write/replace/delete behavior, escaped keys, validation/size errors and rollback; storage restart persistence and Go cache-database interchange remain unclaimed |
| Restart and upgrade APIs | Oracle | Not started | Subprocess/re-exec/download fixtures |
| External UI and DoH mount | Oracle | Partial | Phase 4F15 proves the public configured DoH mount, exact and child paths, GET, fixed/chunked POST, DNS wire response and error contracts; the Axum/Hyper refactor preserves those framing and mount-before-auth observations; external UI static paths and redirect remain unimplemented |
| Debug routes | Oracle when debug | Not started | Feature exposure and GC endpoint |
| Exact route-wide error/stream/concurrency contracts | Oracle | Partial | Existing REST contracts plus first HTTP/WS observability frames and disconnect-aware cancellation pass; sustained cadence, backpressure and concurrent mutation evidence remain per-route gaps |

## Platforms, architectures and build profiles

The release workflow is broader than the first Rust target. Each row needs a
separate build and runtime claim.

| Target/profile | Go | Rust | Notes/evidence needed |
| --- | --- | --- | --- |
| Darwin arm64 — Phase 1 slice | Oracle | **Parity** | Native `compat/scripts/phase1.py`, 2026-08-25 |
| Linux amd64 — Phase 1 slice | Oracle | **Parity** | `rust:1.95-bookworm` amd64 container differential, 2026-08-25 |
| Darwin arm64 — Phase 2 pure config/rules | Oracle | **Parity** | Native `compat/scripts/phase2.py`, 2026-08-25; no privileged/platform I/O |
| Darwin arm64 — Phase 3 local product | Oracle | **Parity** | Native `compat/scripts/phase3.py`, 2026-08-25; loopback TCP/UDP and signals only |
| Darwin arm64 — Phase 4A classic DNS | Oracle | **Parity** | Native `compat/scripts/phase4.py`, 2026-08-25; loopback UDP/TCP only |
| Darwin arm64 — Phase 4B hosts/mapping | Oracle | **Parity** | Native `compat/scripts/phase4b.py`, 2026-08-25; local DNS, system hosts and interface-local TCP only |
| Darwin arm64 — Phase 4C fake IP | Oracle | **Parity** | Native `compat/scripts/phase4c.py`, 2026-08-25; local DNS, interface-local TCP and temporary profile homes only |
| Darwin arm64 — Phase 4D1 nameserver policy | Oracle | **Parity** | Native `compat/scripts/phase4d1.py`, 2026-08-25; four deterministic loopback UDP/TCP authorities |
| Darwin arm64 — Phase 4D2 DNS fallback | Oracle | **Parity** | Native `compat/scripts/phase4d2.py`, 2026-08-25; deterministic local main/fallback/policy authorities |
| Darwin arm64 — Phase 4D3A direct/lazy DNS | Oracle | **Parity** | Native `compat/scripts/phase4d3a.py`, 2026-08-25; mixed SOCKS TCP, three local DNS authorities and local echo |
| Darwin arm64 — Phase 4E2 verified DoT | Oracle | **Parity** | Native `compat/scripts/phase4e2.py`, 2026-08-25; deterministic inline CA/leaf and loopback TLS authority |
| Darwin arm64 — Phase 4E3 multiple DoT roots | Oracle | **Parity** | Native `compat/scripts/phase4e3.py`, 2026-08-25; deterministic decoy/issuing roots and loopback TLS authority |
| Darwin arm64 — Phase 4E4 DoT reuse | Oracle | **Parity** | Native `compat/scripts/phase4e4.py`, 2026-08-25; persistent and server-closed loopback TLS connections |
| Darwin arm64 — Phase 4E5 HTTPS DoH GET | Oracle | **Parity** | Native `compat/scripts/phase4e5.py`, 2026-08-25; deterministic custom CA and loopback HTTP/1.1 TLS authority |
| Darwin arm64 — Phase 4E6 HTTP/1.1 DoH reuse | Oracle | **Parity** | Native `compat/scripts/phase4e6.py`, 2026-08-25; persistent and server-closed loopback HTTP/1.1 TLS connections |
| Darwin arm64 — Phase 4E7 custom DoH path | Oracle | **Parity** | Native `compat/scripts/phase4e7.py`, 2026-08-25; deterministic custom-path loopback HTTP/1.1 TLS authority |
| Darwin arm64 — Phase 4E8 encoded DoH path | Oracle | **Parity** | Native `compat/scripts/phase4e8.py`, 2026-08-25; deterministic percent-encoded-path loopback HTTP/1.1 TLS authority |
| Darwin arm64 — Phase 4E9 domain DoT bootstrap | Oracle | **Parity** | Native `compat/scripts/phase4e9.py`, 2026-08-25; deterministic loopback bootstrap DNS plus verified DoT authority |
| Darwin arm64 — Phase 4E10 DoT trust matrix | Oracle | **Parity** | Native `compat/scripts/phase4e10.py`, 2026-08-25; deterministic default/global-root, untrusted, name-override, skip-verification and reuse cases |
| Darwin arm64 — Phase 4E11 DoT lifecycle | Oracle | **Parity** | Native `compat/scripts/phase4e11.py`, 2026-08-25; deterministic concurrent, delayed, reset and retry authority cases |
| Darwin arm64 — Phase 4E12 HTTP DoH | Oracle | **Parity** | Native `compat/scripts/phase4e12.py`, 2026-08-25; deterministic plaintext HTTP/1.1 authority and default URL observations |
| Darwin arm64 — Phase 4E13 HTTPS URL semantics | Oracle | **Parity** | Native `compat/scripts/phase4e13.py`, 2026-08-26; deterministic TLS HTTP/1.1 root/query/ASCII-userinfo/persistent-relative-redirect observations |
| Darwin arm64 — Phase 4E14 domain HTTPS | Oracle | **Parity** | Native `compat/scripts/phase4e14.py`, 2026-08-26; deterministic bootstrap DNS and TLS HTTP/1.1 trust/SNI/Host observations |
| Darwin arm64 — Phase 4E15 DoH HTTP/2 | Oracle | **Parity** | Native `compat/scripts/phase4e15.py`, 2026-08-26; deterministic local HTTP/2 TLS authority and HTTP/1.1 fallback |
| Darwin arm64 — Phase 4E16 DoH HTTP/3 | Oracle | **Parity** | Native `compat/scripts/phase4e16.py`, 2026-08-26; deterministic forced/preferred/fallback/reconnect HTTP/3 observations |
| Darwin arm64 — Phase 4E17 verified DoQ framing | Oracle | **Parity** | Native `compat/scripts/phase4e17.py`, 2026-08-26; deterministic local ALPN/framing/trust/failure observations |
| Darwin arm64 — Phase 4E18 DoQ lifecycle | Oracle | **Parity** | Native `compat/scripts/phase4e18.py`, 2026-08-26; deterministic reuse/concurrency/retry/reset/full-handshake observations |
| Darwin arm64 — Phase 4E19 encrypted wrappers | Oracle | **Parity** | Native `compat/scripts/phase4e19.py`, 2026-08-26; deterministic ECS and disabled request/response observations over DoQ |
| Darwin arm64 — Phase 4F1 local DNS semantics | Oracle | **Parity** | Native `compat/scripts/phase4f1.py`, 2026-08-26; deterministic validation, RR/RCODE, EDNS and UDP-size observations |
| Darwin arm64 — Phase 4F2 classic upstreams | Oracle | **Parity** | Native `compat/scripts/phase4f2.py`, 2026-08-26; deterministic domain/bootstrap, scheduling, timeout and TC-retry observations |
| Darwin arm64 — Phase 4F3 system resolver | Oracle | **Partial** | Native config differential plus Rust POSIX/platform contracts, 2026-08-26; sandbox cannot bind deterministic UDP/TCP port 53, so native wire parity is not claimed |
| Darwin arm64 — Phase 4F4 DHCP resolver | Oracle | **Partial** | Native config and exact Go/Rust DHCP packet differential plus interface/invalidation contracts, 2026-08-26; privileged UDP 67/68 exchange unavailable |
| Darwin arm64 — Phase 4F5 RCODE/Tailscale registration | Oracle | **Partial** | Native RCODE UDP/TCP differential and Go/Rust named-registry contracts passed, 2026-08-26; actual tsnet client remains Phase 7K |
| Darwin arm64 — Phase 4F6 classic DNS wrappers | Oracle | **Parity** | Native UDP/TCP wrapper differential plus Go/Rust transport-identity contracts passed, 2026-08-26 |
| Darwin arm64 — Phase 4F7 resolver-set core | Oracle | **Partial** | Native deterministic default/main/fallback/direct/proxy set differential passed, 2026-08-26; remaining consumers are not claimed |
| Darwin arm64 — Phase 4F8 resolver policies | Oracle | **Partial** | Native ordered domain/GeoSite/rule-set and main/proxy multi-client differential passed, 2026-08-26; provider/adapter integration gaps remain |
| Darwin arm64 — Phase 4F9 fallback core | Oracle | **Partial** | Native deterministic GeoIP.dat/GeoSite/domain/IPv4/IPv6 and eager/lazy failure/timeout differential passed, 2026-08-26; MMDB and broader integration remain |
| Darwin arm64 — Phase 4F10 dual-stack/ECH/lazy tunnel | Oracle | **Parity** | Native helper and mixed SOCKS tunnel differential passed, 2026-08-26 |
| Darwin arm64 — Phase 4F11 DNS cache lifecycle | Oracle | **Parity** | Native product differential passed, 2026-08-26; deterministic eviction, TTL, stale, negative, singleflight, retry and SIGHUP evidence |
| Darwin arm64 — Phase 4F12 complete hosts core | Oracle | **Parity** | Native product differential passed, 2026-08-26; trie priority, values/aliases, DNS pass-through, native hosts and randomized tunnel selection evidence |
| Darwin arm64 — Phase 4F13 redir-host local-inbound core | Oracle | **Parity** | Native product differential passed, 2026-08-26; TCP/UDP inbound, CNAME identity, reload and TTL-past-retention evidence |
| Darwin arm64 — Phase 4F14 fake-IP lifecycle core | Oracle | **Parity** | Native product differential and bidirectional Go/Rust bbolt interchange passed, 2026-08-26; filters, reload/range, TCP/UDP reverse, flush/restart and malformed-cache evidence |
| Darwin arm64 — Phase 5A1 configuration input | Oracle | **Parity** | Native 25-case Go/Rust path, environment, precedence, creation, empty-source fallthrough, error and frozen-source reload differential passed, 2026-08-26 |
| Darwin arm64 — Phase 5A2a default version output | Oracle | **Parity** | Native default-banner and configuration-short-circuit differential passed, 2026-08-26; tagged profiles remain unclaimed |
| Darwin arm64 — Phase 5A2b geodata-mode CLI default | Oracle | **Parity** | Native four-case live controller differential passed, 2026-08-26 |
| Darwin arm64 — Phase 5A3a controller/secret overrides | Oracle | **Parity** | Native CLI/environment/empty-precedence, listener, auth and reload differential passed, 2026-08-26 |
| Darwin arm64 — Phase 5A4a X25519 encrypted config | Oracle | **Parity** | Native file/base64, key precedence, live application and failure differential passed, 2026-08-26 |
| Darwin arm64 — Phase 5A4b X25519 age convert | Oracle | **Parity** | Native exact recipient and invalid/missing-key exit differential passed, 2026-08-26 |
| Darwin arm64 — Phase 5A4c X25519 age encrypt/decrypt | Oracle | **Parity** | Native binary file/stream and bidirectional Go/Rust armor interoperability differential passed, 2026-08-26 |
| Darwin arm64 — Phase 5A4d X25519 age keygen | Oracle | **Parity** | Native structured output and cross-implementation key conversion differential passed, 2026-08-26 |
| Darwin arm64 — Phase 5A5a IP-CIDR MRS to text | Oracle | **Parity** | Native Go-produced zstd MRS v1 decode and CLI differential passed, 2026-08-26 |
| Darwin arm64 — Phase 5A5b IP-CIDR text/YAML to MRS | Oracle | **Parity** | Native bidirectional Go/Rust zstd MRS v1 interchange and semantic record differential passed, 2026-08-26 |
| Darwin arm64 — Phase 5A5c domain MRS to text | Oracle | **Parity** | Native Go-produced succinct domain-set MRS decode and CLI differential passed, 2026-08-26 |
| Darwin arm64 — Phase 5A5d domain text/YAML to MRS | Oracle | **Parity** | Native bidirectional Go/Rust succinct domain-set MRS interchange and semantic record differential passed, 2026-08-26 |
| Darwin arm64 — Phase 5A5e classical rejection | Oracle | **Parity** | Native text/YAML/empty-format/MRS rejection and target-side-effect differential passed, 2026-08-26 |
| Darwin arm64 — Phase 5A5f streaming YAML | Oracle | **Parity** | Native preamble/recovery/no-newline and bidirectional semantic record differential passed, 2026-08-26 |
| Darwin arm64 — Phase 5A6a UUID generation | Oracle | **Parity** | Native UUID v4 structure and command-lifecycle differential passed, 2026-08-26 |
| Darwin arm64 — Phase 5A6b Reality keypair | Oracle | **Parity** | Native X25519 clamp/relation and output-contract differential passed, 2026-08-26 |
| Darwin arm64 — Phase 5A6c WireGuard keypair | Oracle | **Parity** | Native X25519 clamp/relation and standard-Base64 output differential passed, 2026-08-26 |
| Darwin arm64 — Phase 5A6d VLESS X25519 | Oracle | **Parity** | Native fixed-key byte-exact output and independent X25519 relation differential passed, 2026-08-26 |
| Darwin arm64 — Phase 5A6e ECH keypair | Oracle | **Parity** | Native parsed ECHConfigList/PEM and independent X25519 relation differential passed, 2026-08-26 |
| Darwin arm64 — Phase 5A6f VLESS ML-KEM-768 | Oracle | **Parity** | Native fixed-seed byte-exact ML-KEM output and command-lifecycle differential passed, 2026-08-26 |
| Darwin arm64 — Phase 5A6g Sudoku keypair | Oracle | **Parity** | Native canonical split-scalar and independent Edwards25519 public recovery differential passed, 2026-08-26 |
| Darwin arm64 — Phase 5A7a invalid SIGHUP recovery | Oracle | **Parity** | Native malformed-config rollback and following-valid-reload differential passed, 2026-08-26 |
| Darwin arm64 — Phase 5A7b local-resource shutdown | Oracle | **Parity** | Native SIGINT/SIGTERM exit, stream closure and mixed/controller/DNS TCP/UDP release differential passed, 2026-08-26 |
| Darwin arm64 — Phase 5A8a lifecycle hooks | Oracle | **Parity** | Native CLI/environment precedence, shell, resource-ordering and failure differential passed, 2026-08-26 |
| Darwin arm64 — Phase 5D controller core | Oracle | **Parity in declared rows** | Native HTTP/WS streams, Bearer/query-token/CORS, single/all live connection deletion and the declared executable `/configs` transaction subset passed, 2026-08-27 |
| Darwin arm64 beyond declared Phase 5 slices | Oracle | Not started | Capability-specific native evidence |
| Linux amd64 — Phase 1–4E15 declared slices | Oracle | **Parity** | Default GitHub Actions full differential run `32923792731`, 2026-08-26; deterministic local fixtures only |
| Linux amd64 — Phase 4E16 DoH HTTP/3 | Oracle | Pending | Default GitHub Actions run is configured; no result is claimed before that run completes |
| Linux amd64 — Phase 4E17 verified DoQ framing | Oracle | Pending | Default GitHub Actions run is configured; no result is claimed before that run completes |
| Linux amd64 — Phase 4E18 DoQ lifecycle | Oracle | Pending | Default GitHub Actions run is configured; no result is claimed before that run completes |
| Linux amd64 — Phase 4E19 encrypted wrappers | Oracle | Pending | Default GitHub Actions run is configured; no result is claimed before that run completes |
| Linux amd64 — Phase 4F1 local DNS semantics | Oracle | Pending | Default GitHub Actions run is configured; no result is claimed before that run completes |
| Linux amd64 — Phase 4F2 classic upstreams | Oracle | Pending | Default GitHub Actions run is configured; no result is claimed before that run completes |
| Linux amd64 — Phase 4F3 system resolver | Oracle | Pending | Default config differential and native `rewrite-platform` contract job are configured; no result is claimed before that run completes |
| Linux amd64 — Phase 4F4 DHCP resolver | Oracle | Pending | Default exact wire/config differential and platform-contract job are configured; privileged native UDP 67/68 parity remains pending |
| Linux amd64 — Phase 4F5 RCODE/Tailscale registration | Oracle | Pending | Default RCODE wire differential and named-registry contracts are configured; no result is claimed before completion |
| Linux amd64 — Phase 4F6 classic DNS wrappers | Oracle | Pending | Default UDP/TCP wrapper differential and identity contracts are configured; no result is claimed before completion |
| Linux amd64 — Phase 4F7 resolver-set core | Oracle | Pending | Default resolver-set differential is configured; no result is claimed before completion |
| Linux amd64 — Phase 4F8 resolver policies | Oracle | Pending | Default ordered policy differential is configured; no result is claimed before completion |
| Linux amd64 — Phase 4F9 fallback core | Oracle | Pending | Default fallback differential is configured; no result is claimed before completion |
| Linux amd64 — Phase 4F10 dual-stack/ECH/lazy tunnel | Oracle | Pending | Default focused differential is configured; no result is claimed before completion |
| Linux amd64 — Phase 4F11 DNS cache lifecycle | Oracle | Pending | Default focused differential and prior pooled-reset suites are configured; no result is claimed before completion |
| Linux amd64 — Phase 4F12 complete hosts core | Oracle | Pending | Default focused differential is configured; no result is claimed before completion |
| Linux amd64 — Phase 4F13 redir-host local-inbound core | Oracle | Pending | Default focused differential is configured; no result is claimed before completion |
| Linux amd64 — Phase 4F14 fake-IP lifecycle core | Oracle | Pending | Default focused differential and bbolt interchange gate are configured; no result is claimed before completion |
| Linux amd64 — Phase 5A1 configuration input | Oracle | Pending | Default GitHub Actions differential is configured; no result is claimed before completion |
| Linux amd64 — Phase 5A2a default version output | Oracle | Pending | Default GitHub Actions differential is configured; no result is claimed before completion |
| Linux amd64 — Phase 5A2b geodata-mode CLI default | Oracle | Pending | Default GitHub Actions differential is configured; no result is claimed before completion |
| Linux amd64 — Phase 5A3a controller/secret overrides | Oracle | Pending | Default GitHub Actions differential is configured; no result is claimed before completion |
| Linux amd64 — Phase 5A4a X25519 encrypted config | Oracle | Pending | Default GitHub Actions differential is configured; no result is claimed before completion |
| Linux amd64 — Phase 5A4b X25519 age convert | Oracle | Pending | Default GitHub Actions differential is configured; no result is claimed before completion |
| Linux amd64 — Phase 5A4c X25519 age encrypt/decrypt | Oracle | Pending | Default GitHub Actions differential is configured; no result is claimed before completion |
| Linux amd64 — Phase 5A4d X25519 age keygen | Oracle | Pending | Default GitHub Actions differential is configured; no result is claimed before completion |
| Linux amd64 — Phase 5A5a IP-CIDR MRS to text | Oracle | Pending | Default GitHub Actions differential is configured; no result is claimed before completion |
| Linux amd64 — Phase 5A5b IP-CIDR text/YAML to MRS | Oracle | Pending | Default GitHub Actions bidirectional interchange differential is configured; no result is claimed before completion |
| Linux amd64 — Phase 5A5c domain MRS to text | Oracle | Pending | Default GitHub Actions differential is configured; no result is claimed before completion |
| Linux amd64 — Phase 5A5d domain text/YAML to MRS | Oracle | Pending | Default GitHub Actions bidirectional interchange differential is configured; no result is claimed before completion |
| Linux amd64 — Phase 5A5e classical rejection | Oracle | Pending | Default GitHub Actions differential is configured; no result is claimed before completion |
| Linux amd64 — Phase 5A5f streaming YAML | Oracle | Pending | Default GitHub Actions differential is configured; no result is claimed before completion |
| Linux amd64 — Phase 5A6a UUID generation | Oracle | Pending | Default GitHub Actions differential is configured; no result is claimed before completion |
| Linux amd64 — Phase 5A6b Reality keypair | Oracle | Pending | Default GitHub Actions differential is configured; no result is claimed before completion |
| Linux amd64 — Phase 5A6c WireGuard keypair | Oracle | Pending | Default GitHub Actions differential is configured; no result is claimed before completion |
| Linux amd64 — Phase 5A6d VLESS X25519 | Oracle | Pending | Default GitHub Actions differential is configured; no result is claimed before completion |
| Linux amd64 — Phase 5A6e ECH keypair | Oracle | Pending | Default GitHub Actions differential is configured; no result is claimed before completion |
| Linux amd64 — Phase 5A6f VLESS ML-KEM-768 | Oracle | Pending | Default GitHub Actions differential is configured; no result is claimed before completion |
| Linux amd64 — Phase 5A6g Sudoku keypair | Oracle | Pending | Default GitHub Actions differential is configured; no result is claimed before completion |
| Linux amd64 — Phase 5A7a invalid SIGHUP recovery | Oracle | Pending | Default GitHub Actions differential is configured; no result is claimed before completion |
| Linux amd64 — Phase 5A7b local-resource shutdown | Oracle | Pending | Default GitHub Actions differential is configured; no result is claimed before completion |
| Linux amd64 — Phase 5A8a lifecycle hooks | Oracle | Pending | Default GitHub Actions differential is configured; no result is claimed before completion |
| Linux amd64 — Phase 5B aggregate local rules | Oracle | Pending | Default aggregate rule differentials are configured; no result is claimed before completion |
| Linux amd64 — Phase 5D controller core | Oracle | Pending | Default HTTP/WebSocket, CORS, live connection deletion and executable `/configs` transaction differentials are configured; no result is claimed before completion |
| Linux amd64 beyond declared Phase 5 slices | Oracle | Not started | Later namespace/TUN and capability-specific evidence |
| Linux arm64 — Phase 4F14 bbolt interchange | Oracle | **Partial** | Native Docker execution on 2026-08-26 proved Go→Rust→Go v4/v6 mapping interchange and zero exits after an observable reload/signal-readiness barrier; the rest of Phase 4F14 is unclaimed |
| Linux arm64 beyond the Phase 4F14 interchange gate | Oracle | Not started | Cross-build then capability-specific native integration |
| Windows amd64 — Phase 4F3 system resolver | Oracle | Cross-build passed; native pending | Rust 1.95 GNU target check passed; native safe `ipconfig` discovery/adapter contract job is configured, while Go/Rust wire parity remains pending |
| Windows amd64 — Phase 4F4 DHCP resolver | Oracle | Cross-build passed; native pending | Interface enumeration, packet and socket code compile for Rust 1.95 GNU; privileged native client/server parity remains pending |
| Windows arm64/386 and other behavior | Oracle | Not started | Named pipe, process/socket behavior |
| FreeBSD 386/amd64/arm64 | Oracle | Not started | Redir/TUN/socket behavior |
| Android 386/amd64/arm/arm64 | Oracle | **Partial contract only** | CMFA injected resolver replace/clear model is host-tested; Android native execution, reset callbacks, NDK/package and TUN behavior remain pending |
| Linux 386/armv5-7/mips/mips64 | Oracle | Not started | Toolchain/dependency feasibility gate |
| Linux riscv64/loong64/s390x/ppc64le | Oracle | Not started | Toolchain/dependency feasibility gate |
| Default build | Oracle | Not started | Feature inventory and tests |
| `with_gvisor` | Oracle | Not started | gVisor TUN and Tailscale-enabled tests |
| `with_low_memory` | Oracle | Not started | Buffer limits/memory benchmarks |
| `no_fake_tcp` | Oracle | Not started | Hysteria feature exclusion |
| `no_tailscale` | Oracle | Not started | Config rejection/stub behavior |
| `no_zerotier` | Oracle | Not started | Config rejection/stub behavior |
| `cmfa` | Oracle | Not started | Android-specific integration |
| Packaging, executable metadata and reproducible archives | Oracle | Not started | Artifact names, archive/package contents, version/build metadata and reproducibility checks |

## Phase 1 declared compatibility target

Only these rows may move from Not started in the first implementation phase:

- minimal YAML/default parsing required by the fixture;
- `-t` for the declared minimal valid and invalid fixtures;
- mixed TCP listener dispatching HTTP and SOCKS5;
- Rule mode with `MATCH,DIRECT`;
- DIRECT TCP dialing and bidirectional relay;
- SIGINT/SIGTERM cleanup needed by the test harness.

Everything else remains explicitly unsupported even if incidental code exists.

Phase 1 evidence is the local-only `compat/scripts/phase1.py` run on native
Darwin arm64 and an emulated Linux amd64 container. The minimal fixture keeps
`ipv6: false`; the IPv6-address SOCKS case therefore asserts the oracle's close
behavior. Enabled IPv6 proxying is not a Phase 1 compatibility claim.

## Phase 2 declared compatibility target

Phase 2 parity is limited to normalized specification behavior and pure rule
evaluation exercised by `compat/scripts/phase2.py`:

- declared Go defaults and overlays for general ports, LAN/bind, mode/logging,
  IPv6/interface/routing mark, concurrency, keepalive and ETag fields;
- MATCH, exact/suffix/keyword domain (with sniff-host precedence), IPv4/IPv6
  destination/source CIDR, source/destination/inbound ports and TCP/UDP network;
- AND, OR, NOT, SUB-RULE, PASS, PASS-RULE, rematch-name and REMATCH metadata
  transitions, including invalid references and cycles.

At the Phase 2 exit, executable conversion remained restricted to the Phase 1
mixed listener and exact `MATCH,DIRECT` route. Later live additions are claimed
only by their separate Phase 3 rows; Phase 2 evidence alone does not establish
runtime compatibility.

## Phase 3 declared compatibility target

Phase 3 evidence in `compat/scripts/phase3.py` is limited to:

- authentication records needed by legacy local listeners;
- fixed HTTP and SOCKS TCP listeners plus the existing mixed TCP listener;
- HTTP Basic authentication and SOCKS4 USERID/SOCKS5 username-password;
- SOCKS4, SOCKS4a and SOCKS5 CONNECT over TCP;
- pure rule selection ending in live DIRECT or immediate REJECT TCP behavior;
- authenticated and rejected connection shutdown/lifecycle observations;
- declared read-only controller TCP/Bearer and normalized snapshot/stream
  fields for version, configs, connections, traffic and logs;
- SIGHUP rule switching, invalid-config rollback and listener port migration;
- SOCKS5 UDP ASSOCIATE and local IPv4 DIRECT request/write-back behavior.

The Rust-only occupied-port rollback contract is deliberately stronger than the
pinned Go listener recreation and is documented as a safety property, not Go
parity. REST mutation and WebSocket behavior beyond the later Phase 5D stream
gate, general-purpose UDP NAT, broader DNS, TUN, remote proxy protocols and
broader platforms remain later phases. DNS support is
claimed only by the separate Phase 4A rows below.

## Phase 4A declared compatibility target

Phase 4A evidence in `compat/scripts/phase4.py` is limited to:

- an explicit loopback IPv4 DNS listener and exactly one loopback IP-literal
  `udp://` or `tcp://` upstream;
- one-question A requests over both UDP and length-prefixed TCP client paths;
- positive upstream answers with matching transaction ID, local authoritative
  flag behavior, question/answer counts, record type/class/address and TTL;
- a bounded in-memory positive cache, client transaction-ID restoration and
  the pinned Go remaining-TTL behavior on an immediate cache hit;
- valid configuration and the enabled-with-empty-nameserver rejection case.

The Phase 4A fixture explicitly disables configured and system hosts. It does
not claim IPv6 DNS, multiple/system/domain upstreams, upstream failure/SERVFAIL,
negative or stale caching, request coalescing/retry, EDNS, UDP truncation,
hosts/CNAME, redir-host tunnel mapping, fake IP, resolver policy, DNS REST,
DoH/DoT/DoQ or TUN hijack.

## Phase 4B declared compatibility target

Phase 4B evidence in `compat/scripts/phase4b.py` is limited to:

- exact hosts keys with a single or list-valued IPv4/IPv6
  address, plus rejection of configured domain-mapping cycles;
- configured A and AAAA direct answers with TTL 10 and no upstream call;
- a configured CNAME-only answer and a CNAME whose terminal is resolved by the
  declared local UDP upstream, including cached terminal TTL behavior;
- one non-`localhost` entry from the native Darwin `/etc/hosts` file when such
  an entry is available to both binaries;
- redir-host recovery for a locally authoritative IPv4 answer: a subsequent
  SOCKS5 CONNECT addressed only by that IP recovers the queried domain before
  rule evaluation and reaches an interface-local TCP echo server through
  `DOMAIN,...,DIRECT`.

The mapping table is capped at 4096 entries. Phase 4F13 later establishes the
pinned baseline's access-order capacity and effective non-expiring behavior;
mapping persistence across reload/restart, UDP rule mapping, configured-host
use by DIRECT domain dialing, wildcard/`lan` hosts, randomized address choice,
IDNA, non-IP DNS types and non-Darwin system-host discovery are not compatibility
claims; they are not implied by Phase 4B evidence.

## Phase 4C declared compatibility target

Phase 4C evidence in `compat/scripts/phase4c.py` is limited to:

- fake-IP configuration with explicit IPv4/IPv6 ranges, TTL, exact-domain
  `blacklist` or `whitelist` filtering, and `profile.store-fake-ip`;
- deterministic dual-stack execution using the oracle-supported
  `SKIP_SYSTEM_IPV6_CHECK=1` environment input on IPv4-only hosts;
- deterministic network-address-plus-four allocation, case-insensitive stable
  reuse, independent A/AAAA pools, final-address reservation and cyclic
  overwrite on a `/29` IPv4 fixture;
- the pinned 1000-entry nonpersistent memory limit and observable eviction of
  the least-recently-used mapping;
- filtered queries falling through to the declared local classic upstream;
- DNS A fake response -> IP-only SOCKS5 CONNECT -> recovered DOMAIN rule ->
  configured real dual-stack lookup -> IPv4 DIRECT TCP echo relay;
- graceful process stop/restart with one temporary home, preserving existing
  mappings and continuing the allocation offset.

The Rust candidate stores its restart state in candidate-local JSON sidecars;
the Go oracle uses bbolt `cache.db`. Only the observable restart result is in
parity. Cross-reading either implementation's files, atomic crash recovery,
corruption handling, `rule`/provider/wildcard filters, UDP fake-IP routing,
reload/prefix changes, REST flush/query control, TUN hijack and resolver policy
are not compatibility claims.

## Phase 4D1 declared compatibility target

Phase 4D1 evidence in `compat/scripts/phase4d1.py` is limited to:

- `dns.nameserver-policy` entries whose keys are ASCII exact domains,
  whole-label `*` patterns or a leading `+.` suffix pattern;
- exactly one loopback IP-literal `udp://` or `tcp://` upstream per policy;
- main-upstream fallback for misses, `+.` matching both its root domain and
  arbitrary subdomain depth, and `*` matching exactly one label;
- Go-trie precedence where a static exact path wins over an overlapping
  suffix policy;
- selected upstream transport/address in the positive cache key, transaction
  ID restoration and remaining-TTL behavior on a policy cache hit;
- matching configuration acceptance plus malformed-pattern/non-string-value
  rejection.

Four local authorities return distinct addresses and record the received
transport/name/type, so policy selection cannot pass merely by producing a
syntactically valid DNS answer. Multiple upstreams per policy, patterns that
write the same trie node and depend on YAML overwrite order, Unicode, geosite
or rule-set matchers, system/domain upstreams, fallback, proxy/direct DNS,
`respect-rules`, DNS REST control and encrypted DNS remain unclaimed.

## Phase 4D2 declared compatibility target

Phase 4D2 evidence in `compat/scripts/phase4d2.py` is limited to:

- one loopback IP-literal main upstream over UDP and one fallback over TCP;
- explicit `fallback-filter.geoip: false`, one `+.` ASCII domain filter and one
  IPv4 CIDR answer filter;
- domain-filter matches querying only fallback, a safe positive main answer,
  and a filtered main answer selecting fallback;
- eager mode sending both safe main and fallback queries while returning main,
  versus lazy mode avoiding fallback when main is accepted;
- a selected fallback response cache hit with restored transaction ID and a
  positive aged TTL;
- a matching nameserver policy bypassing the fallback path;
- valid configuration plus malformed CIDR/domain-pattern rejection.

The local authorities return distinct A records and log transport/name/type.
Only the exact cached TTL decrement at wall-clock boundaries is normalized;
whether it aged and remained positive is semantic. Multiple main or fallback
servers, GeoIP/GeoSite, IPv6 answer filters, empty/error/timeout/retry behavior,
general system/domain upstreams, proxy/direct DNS, `respect-rules`, DNS REST
control and encrypted DNS remain unclaimed.

## Phase 4D3A declared compatibility target

Phase 4D3A evidence in `compat/scripts/phase4d3a.py` is limited to:

- SOCKS5 domain TCP input with ordered DOMAIN, destination IP-CIDR and MATCH
  rules targeting DIRECT or REJECT;
- no DNS query when an earlier domain rule decides the route;
- destination `IP-CIDR` requesting one main-resolver A lookup only when its
  target IP is missing, while `no-resolve` falls through without DNS;
- one loopback IP-literal `direct-nameserver` over TCP resolving the domain
  again for the final DIRECT connection;
- `direct-nameserver-follow-policy: false` selecting the direct authority even
  after a main policy lookup, and `true` selecting the matching policy for both
  lazy rule resolution and DIRECT resolution;
- exact upstream transport/name/type observations, relay/close results,
  process exit and valid/invalid configuration outcomes.

The main authority deliberately returns a different loopback address from the
direct authority: a test can pass only if the main result selects the IP rule
and the direct result reaches the TCP echo server. The harness waits for both
candidate listeners plus the documented Go resolver-publication stabilization
window; no in-scenario DNS result is delayed or normalized.

UDP lazy rules, IPv6 answers, resolver failure/retry/cache semantics, multiple
direct servers, general policy matchers, proxy-server nameservers, remote
proxy adapters, `respect-rules`, DNS REST and encrypted DNS remain unclaimed.
