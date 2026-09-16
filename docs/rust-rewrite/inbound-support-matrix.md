# Inbound support matrix (IN-A census)

Last updated: 2026-09-14

This document is the **IN-A** deliverable: an accurate Go vs Rust inbound
inventory so later server-direction work does not re-implement local listeners,
TUN, or the Phase 6C-N Shadowsocks first-server slice, and does not copy the
outbound protocol checklist wholesale.

Authoritative roadmap phases: **IN-A … IN-H** in
[`roadmap.md`](roadmap.md). Inventory IDs remain `IN-01` … `IN-14` in
[`go-capability-inventory.md`](go-capability-inventory.md).

## Shared data-plane architecture

```text
listen TCP/UDP
  → TLS / WS / gRPC / ShadowTLS / … carriers (protocol-agnostic where shared)
  → protocol authenticate + decode
  → unified TCP session / UDP datagram
  → Metadata → DNS / rules → existing outbound
  → encode response back to the client
```

### Crate roles (target)

| Layer | Responsibility |
| --- | --- |
| `protocol-*` | Shared client/server address, crypto, framing; server auth and session |
| `rewrite-transport` | Protocol-agnostic carriers (TLS, WS, gRPC, …) |
| `rewrite-inbound` | Local HTTP/SOCKS/mixed framing only today; not a generic remote-server framework |
| `rewrite-runtime` | Listeners, generations, routing, stats, timeouts, cancel, reload, reclaim |
| Protocol test authorities | Interop fixtures only — never a production server surface |

### Rust public access boundary (verified against existing SS)

Remote and local TCP servers already converge on one post-handshake path:

1. Protocol listener accepts and authenticates (`LocalTcpListener`,
   `ShadowsocksListener`, TUN stack).
2. Build `rewrite_model::Metadata` (`InboundProtocol`, user, name, network).
3. Call `serve_stream_session` in `rust/crates/runtime/src/tcp.rs`
   (SS via `serve_shadowsocks_connection`; TUN via the same helper).
4. Host/fake-IP mapping → rules → outbound dial/relay owned by runtime.

UDP uses generation-scoped session tables (`UdpSessions` /
`ShadowsocksUdpSessions`) and the shared reply-sink contract. **IN-A does not
extract a larger shared server framework.** Extract interfaces only when a
second remote protocol needs the same boundary (expected at IN-C Trojan).

Do not treat protocol unit-test authorities as production inbounds: production
paths must own authentication, replay defense where required, resource caps,
and lifecycle independently of fixture servers.

## A. Go inbound catalog

Named-listener switch: `listener/parse.go`. Shared named base fields
(`listener/inbound/base.go`): `name`, `listen`, `port` (ranges), `rule`,
`proxy`, `routing-mark`.

Legacy fixed surfaces in `listener/listener.go`: `port` / `socks-port` /
`mixed-port` / `redir-port` / `tproxy-port`, `ss-config`, `vmess-config`, TUN,
static tunnels, TUIC recreate.

| Type | Primary paths | TCP | UDP | Auth | Carriers / transports | Multi-user | Notable options | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| HTTP | `listener/inbound/http.go`, `listener/http/` | Yes | No | Basic `users` | TLS, client-auth, ECH, Reality | Yes | Fixed `port` + named | |
| SOCKS | `listener/inbound/socks.go`, `listener/socks/` | Yes | Opt-in | user/pass; SOCKS4 USERID | TLS / Reality / ECH | Yes | Fixed `socks-port` | |
| Mixed | `listener/inbound/mixed.go`, `listener/mixed/` | Yes | SOCKS UDP | Same as HTTP/SOCKS | TLS / Reality / ECH | Yes | Fixed `mixed-port` | |
| Redir | `listener/inbound/redir.go`, `listener/redir/` | Yes | Platform | None | Orig-dst | N/A | Linux/Darwin/FreeBSD | |
| TProxy | `listener/inbound/tproxy.go`, `listener/tproxy/` | Yes | Opt-in | None | Linux transparent | N/A | | |
| Tunnel | `listener/inbound/tunnel.go`, `listener/tunnel/` | Opt | Opt | None | Fixed target | N/A | `network`, `target` | |
| TUN | `listener/inbound/tun.go`, `listener/sing_tun/` | L3 | L3 | N/A | system / gVisor / mixed | N/A | Large stack/route/DNS surface | |
| Shadowsocks | `listener/inbound/shadowsocks.go`, `listener/sing_shadowsocks/`, fallback `listener/shadowsocks/` | Yes | Opt-in | Shared password; 2022 EIH via sing | simple-obfs; shadow-tls; res-tls; jls; kcp-tun; mux | Password EIH / ShadowTLS users | Legacy `ss-config` | |
| Snell | `listener/inbound/snell.go`, `listener/snell/` | Yes | Opt-in | PSK | obfs; shadow-tls; res-tls; jls | Single PSK | versions 1–5 | |
| VMess | `listener/inbound/vmess.go`, `listener/sing_vmess/` | Yes | Transport-dep. | UUID + AlterID | WS, gRPC, TLS, Reality, ShadowTLS, ReSTLS, JLS, TLSMirror, Mekya, mKCP, mux | Yes | Legacy `vmess-config` | |
| VLESS | `listener/inbound/vless.go`, `listener/sing_vless/` | Yes | Transport-dep. | UUID + flow | WS, xHTTP, gRPC, TLS, Reality, … | Yes | `decryption`, flow | |
| Trojan | `listener/inbound/trojan.go`, `listener/trojan/` | Yes | Yes | Password users | WS, gRPC, TLS, Reality, …; nested `ss-option` | Yes | | |
| Hysteria2 | `listener/inbound/hysteria2.go`, `listener/sing_hysteria2/` | QUIC | Yes | `users` map | TLS/ECH; salamander; mux; realm opts | Yes | | |
| Hysteria2-realm | `listener/inbound/hysteria2_realm.go` | Control | N/A | `token` | TLS | Realm limits | Separate type | |
| TUIC | `listener/inbound/tuic.go`, `listener/tuic/` | Yes | Yes | `token[]` and/or UUID users | QUIC TLS | Yes | v4/v5 surface | |
| ShadowQUIC | `listener/inbound/shadowquic.go` | Yes | Yes | `users[]` | QUIC + required JLS upstream | Yes | | |
| AnyTLS | `listener/inbound/anytls.go`, `listener/anytls/` | Yes | Protocol-dep. | `users` map | TLS + padding / camouflage carriers | Yes | | |
| Mieru / Sudoku / TrustTunnel | respective `listener/inbound/*` | Yes | Varies | Key / users | Protocol-specific | Varies | | |
| Reality / ShadowTLS / ReSTLS / JLS / TLSMirror / mKCP / Mekya / Mux | `listener/inbound/*.go` | Carriers | Varies | Varies | Composed into protocol listeners | Varies | Not top-level `type` (except via host protocols) | |
| Inner | `listener/inner/` | Pipe | Path exists | N/A | Internal `IN-TYPE=INNER` | N/A | Not YAML `listeners` | |

**Absent in Go (do not invent as Go parity):** WireGuard server, SSH server,
SSR inbound.

## B. Rust inbound catalog

| Type | Status | Paths | TCP | UDP | Auth | Carriers | Multi-user | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| HTTP / SOCKS / Mixed | **Implemented** (fixed ports) | `rewrite-inbound`, `runtime` local listeners | Yes | SOCKS UDP | users / USERID | None on listener | Local auth lists | Named `type: http\|socks\|mixed` **missing**; no listener TLS/Reality |
| Shadowsocks | **Partial — 6C-N + IN-B SS2022 UDP** | `config/shadowsocks_inbound.rs`, `named_listeners.rs`, `runtime/shadowsocks_listener.rs` | Yes | Pre-2022 + standard SS2022 (not ChaCha8) | Shared password; AES-2022 EIH colon split | simple-obfs http/tls; ShadowTLS **v3 only** | EIH (AES); ShadowTLS users | Legacy `ss-config` + named `type: shadowsocks` |
| TUN | **Partial — Phase 8A/B/C/F** | `runtime/tun.rs`, `rewrite-tun`, platform | L3 | L3 | N/A | `stack: smoltcp` only | N/A | Go stacks rejected without remap |
| Redir / TProxy / Tunnel | Missing | — | — | — | — | — | — | `IN-03`/`IN-04`/`IN-05` |
| Trojan | **Partial — IN-C TLS + WSS + gRPC** | `named_listeners.rs`, `runtime/trojan_listener.rs`, `protocol-trojan`, `transport` `accept_websocket_path` / `V2rayGrpcServerConnection` | Yes | UDP-over-TLS | Password users (SHA-224) | Native TLS; WS via `ws-path`; Gun via `grpc-service-name` | Yes | Named `type: trojan`; combined ws+grpc / Reality / `ss-option` rejected |
| VLESS | **Partial — IN-D TLS + Vision + WSS + gRPC + XUDP + REALITY** | `named_listeners.rs`, `runtime/vless_listener.rs`, `protocol-vless::server`, `transport` `accept_vision_tls` / `accept_reality` / `accept_websocket_path` / `V2rayGrpcServerConnection` | Yes | Standard-mode UDP on TLS; Mux/XUDP multi-dest on TLS; Vision TCP on native TLS; REALITY TCP auth Accept | UUID users + optional `flow: xtls-rprx-vision` (not with REALITY yet) | Native TLS; REALITY via `reality-config`; WS via `ws-path`; Gun via `grpc-service-name` | Yes | Named `type: vless`; combined ws+grpc rejected; REALITY dest fallback deferred |
| VMess | **Partial — IN-E TLS + WSS + gRPC + XUDP** | `named_listeners.rs`, `runtime/vmess_listener.rs`, `protocol-vmess` AEAD Accept + XUDP framing | Yes | Standard body-record UDP on TLS; Mux/XUDP multi-dest on TLS | UUID users; `alterId` must be 0/absent | Native TLS; WS via `ws-path`; Gun via `grpc-service-name` | Yes | Named `type: vmess`; combined ws+grpc / Reality / nonzero alterId / mKCP/Mekya rejected |
| Hysteria2 | **Partial — IN-F first slice** | `named_listeners.rs`, `runtime/hysteria2_listener.rs`, `protocol-hysteria2` server Accept | QUIC TCP | Direct UDP multi-session datagrams | `users` name→password | QUIC TLS (ALPN h3); optional Salamander | Yes | Named `type: hysteria2`; stock BBR; realm/gecko/ECH/masquerade/Brutal rejected |
| TUIC v5 | **Partial — IN-F TUIC slice** | `named_listeners.rs`, `runtime/tuic_listener.rs`, `protocol-tuic` server Accept | QUIC TCP | Direct UDP associations (native + uni Packet) | `users` uuid→password | QUIC TLS (ALPN h3); cubic/bbr/new_reno | Yes | Named `type: tuic`; v4 token/ECH/client-auth/Brutal/cwnd rejected |
| Snell / Hy2-realm / ShadowQUIC / AnyTLS / Mieru / Sudoku / TrustTunnel | Missing | Protocol crates are **outbound/client** oriented (Hy2/TUIC inbound above) | — | — | — | — | — | Server gates = later IN-F (ShadowQUIC) … IN-G |

`ListenerKind` today: `Http | Socks | Mixed | Shadowsocks | Trojan | Vless | Vmess | Hysteria2 | Tuic`
(`rust/crates/config/src/model.rs`). `InboundProtocol` today:
`Http | Https | Socks4 | Socks5 | Shadowsocks | Trojan | Vless | Vmess | Hysteria2 | Tuic | Tun | Inner`.

## C. Shadowsocks inbound deep-dive (Rust vs Go)

### In scope today (Phase 6C-N — do not re-build in IN-A)

- Legacy `ss-config` URI and named `listeners` `type: shadowsocks` (one IP, one
  port).
- Representative SIP004 AEAD + legacy stream TCP; SS2022 TCP; pre-2022 native
  UDP; UoT v1/v2 non-connect.
- DIRECT / DNS / SOCKS5 / SS / SS-UoT UDP targets for inbound UDP sessions.
- simple-obfs HTTP/TLS server unwrap.
- ShadowTLS v3 auth, plain-TLS fallback, `handshake.dest` /
  `handshake.proxy`, `IN-TYPE,INNER` discrimination, identity-changing reload,
  fail-closed unknown fields.
- Evidence: `compat/scripts/phase6c_shadowsocks_inbound.py` (Darwin arm64
  declared Parity; Linux amd64 pending).

### Explicitly out of current SS inbound claim

| Item | Classification |
| --- | --- |
| SS2022 UDP inbound | **IN-B (this checkout):** three standard methods + replay on product path; ChaCha8 UDP still rejected |
| Complete inbound cipher matrix | Partial — config accepts many; exercised differential matrix still representative |
| UoT v2 connect mode | Rejected |
| ShadowTLS v1/v2, advanced SNI map, wildcard-sni | Deferred / reject |
| `mux-option`, `res-tls`, `jls-config`, `kcp-tun` | Go-compatible gap; reject today |
| Common named-listener `rule` / `proxy` / `routing-mark` | Go-compatible gap; reject today (distinct from `shadow-tls.handshake.proxy`) |
| Port lists/ranges | Go-compatible gap; reject today |
| SS2022 EIH inbound + ShadowTLS `IN-USER` | **Rust extension** (not Go parity) |
| Snell server | Out of IN-B; backlog with other deferred servers |

### Auth / TCP / UDP / users / listen options (SS)

| Concern | Go | Rust 6C-N |
| --- | --- | --- |
| Auth | Shared password; 2022 multi-user via sing EIH | Shared password; AES-2022 EIH colon split (Rust-only evidence) |
| TCP | Yes | Yes |
| UDP | Opt-in including 2022 where library allows | Pre-2022 + three standard SS2022 methods; ChaCha8 UDP fail-closed |
| Users | ShadowTLS users; password EIH | ShadowTLS v3 users required; EIH for AES-2022 |
| Listen | Base listen/port ranges + legacy URI | Single listen + port; URI or named allowlist |

## D. Compatibility classification legend

Use these labels in later IN phases:

| Label | Meaning |
| --- | --- |
| **Go parity** | Same scenario: Go client → Go server vs Go client → Rust server (or reverse) against pinned baseline |
| **Interop** | Fixed-version reference client/server because Go lacks the surface; must not be labeled Go parity |
| **Rust extension** | Behavior Go does not expose (e.g. ShadowTLS `IN-USER`); documented, not normalized into parity |
| **Rejected** | Config fail-closed until a named phase opens it |

## E. Inventory ID crosswalk

| ID | Capability | Rust state after IN-A census | Owning gates |
| --- | --- | --- | --- |
| IN-01 | Mixed HTTP+SOCKS TCP/UDP | Complete in declared local scope | Phase 1/3 (preserve) |
| IN-02 | Fixed HTTP/SOCKS auth/LAN/TFO/MPTCP | Complete in fixed-listener scope | Phase 3/5F (preserve) |
| IN-03 | Redir | Not started | Phase 8A–8C |
| IN-04 | TProxy | Not started | Phase 8A |
| IN-05 | Static tunnel | Not started | 5B6 / later |
| IN-06 | TUN | Partial smoltcp 8A/B/C/F | Phase 8 (preserve; do not duplicate) |
| IN-07 | Shadowsocks + Snell server | SS 6C-N + **IN-B** SS2022 UDP/replay; Snell open | Later SS matrix / Snell deferred |
| IN-08 | VMess + VLESS server | VLESS **Partial — IN-D** TLS+WSS+gRPC+XUDP+Vision+REALITY; VMess **Partial — IN-E** TLS+WSS+gRPC+XUDP (AEAD alterId 0) | **IN-D** / **IN-E** (declared carriers done; Reality dest fallback / legacy alterId open) |
| IN-09 | Trojan server | **Partial — IN-C** named TLS + WSS + gRPC TCP/UDP UoT; Reality/mux open | **IN-C** (TLS+WSS+gRPC done); Reality/mux later |
| IN-10 | Hysteria2 (+ realm) server | Partial — Hy2 first slice | **IN-F** (Hy2 portion); realm later |
| IN-11 | TUIC + ShadowQUIC server | Partial — TUIC v5 named inbound | **IN-F** (TUIC v5 done); ShadowQUIC later |
| IN-12 | AnyTLS (+ Mieru/Sudoku/TrustTunnel) | Not started | **IN-G** (AnyTLS); others deferred |
| IN-13 | Inbound carriers | Partial SS obfs + ShadowTLS v3 | Per-protocol IN-B…IN-G + later 7T |
| IN-14 | Hot rebind / drain / stats | Partial local + SS reload | **IN-H** + per-family |

## F. IN-A exit checklist

- [x] Go named types from `parse.go` enumerated (20 cases including realm).
- [x] Rust implemented surface listed without claiming missing named local TLS.
- [x] SS 6C-N in-scope / out-of-scope / Rust-extension rows recorded.
- [x] Shared TCP access boundary documented (`serve_stream_session`); no new
      generic server framework introduced.
- [x] Recommended implementation order recorded: **IN-B → IN-C → IN-D** after
      IN-A; full matrix in roadmap IN-A…IN-H.
- [x] Optional machine check that `parse.go` cases ⊆ this table (follow-up).

## Explicit non-goals (all IN phases)

- SSR inbound; VMess nonzero / legacy AlterID server work beyond what Go still
  requires for `alterId: 0` AEAD.
- Snell, SSH, WireGuard **servers**.
- mKCP / Mekya and complex camouflage carriers as early inbound work.
- Generic fallback diversion, subscription panels, dynamic user management,
  billing.
- Exposing protocol test authorities on the public internet.
