# OUT-21 / Phase 7T1-A — TCP `dialer-proxy` chained outbound

Status: **In progress (7T1-A)** — TCP proxy chains only. UDP chains,
`sing-mux`, and new protocols are out of scope.

## Target topology

```text
mixed inbound → rule selects B
                     ↓
           B has dialer-proxy: A
                     ↓
         local → A → B's server → final destination
```

Core semantics: **A dials B's server address; B still owns its own handshake
and the final-destination request.** Intermediate dials use Go's INNER-style
path (no ordinary business-rule rematch on B's server address).

## Go contract (oracle)

| Topic | Go behavior | 7T1-A Rust policy |
| --- | --- | --- |
| Field | `BasicOption.DialerProxy` on leaf proxies; not applied to groups as owners | Same: leaf proxies may set `dialer-proxy`; groups may be **targets** |
| Dial | `NewDialer` → `proxydialer.NewByName` → `proxy.DialContext` with metadata address = B `server:port` | Shared runtime dial entry; preserve B's host string for A |
| DNS | B does not pre-resolve for A's CONNECT/SOCKS target; domain may be passed through | When `dialer-proxy` is set, pass unresolved `proxy_server(B)` to A; PSN resolve only for DIRECT outer dials |
| TLS / SNI | After A returns the byte stream, B's TLS/SNI/pinning still apply | Unchanged: B's TLS options wrap the dialer-supplied stream |
| Missing ref | Config error: `dialer-proxy […] not found` | Fail closed at load; never fall through to DIRECT |
| Self / cycle | Static DFS over dialer-proxy edges | Same + runtime visited set for group/provider dynamics |
| Groups / providers | Name may resolve to a group; members can change | Unwrap via existing selector/fallback/url-test/LB; new dials see current leaf |
| Failure | Dial/handshake errors propagate; no silent DIRECT bypass | Same |
| Reload | New generation uses new graph; existing sockets are not rewritten | Same lifecycle as other outbound reloads |
| UDP server dial | Some adapters use dialer-proxy for UDP/WG | **Not in 7T1-A** — `dialer-proxy` + `udp: true` / `udp-over-tcp` is rejected at load; UDP session mode also refuses chained leaves |
| Health / delay | Go delay uses the same dialer stack as traffic | Rust delay/health uses the shared runtime dial entry when installed |
| Snell v2 pool | Unchained v2 reuses `ConnectV2` pool | Unchained Snell keeps the pool; chained Snell dials on-stream (no pool share across dialer identities) |
| sing-mux | Separate composition | **Not in 7T1-A** |

## Supported combinations (7T1-A)

B (selected outbound) may set `dialer-proxy` to A when **both** are TCP-capable
leaf adapters (or A unwraps to one), and A can dial B's `server:port` as a
normal TCP destination:

| B \ A | HTTP | SOCKS5 | SS | SSR | VMess | VLESS | Trojan | AnyTLS | Snell | SSH | Hy2/TUIC/WG | DIRECT |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| HTTP / SOCKS5 | yes | yes | yes | yes | later | later | later | no* | yes | no | no | yes |
| SS / SSR / Snell | yes | yes | yes | yes | later | later | later | no* | yes | no | no | yes |
| VMess / VLESS / Trojan | later\* | later\* | later\* | later\* | later\* | later\* | later\* | no\* | later\* | no | no | later\* |
| AnyTLS | no\* | no\* | no\* | no\* | no\* | no\* | no\* | no\* | no\* | no | no | no\* |
| SSH | rejected | rejected | rejected | rejected | rejected | rejected | rejected | rejected | rejected | rejected | rejected | rejected |
| Hy2 / TUIC / WG | rejected | rejected | rejected | rejected | rejected | rejected | rejected | rejected | rejected | rejected | rejected | rejected |

\* **Parse vs runtime:** VMess / VLESS / Trojan / AnyTLS may still **parse** a
`dialer-proxy` field on the leaf, but the shared TCP dial entry **rejects** that
combination at runtime until those carriers are wired. Treat them as unsupported
for 7T1-A. AnyTLS stays deferred until the pooled DialOut path can carry chain
context without silent DIRECT fallback.

## Explicit rejects

- Missing, self, or cyclic `dialer-proxy` references at load time.
- `dialer-proxy` combined with `udp: true` or `udp-over-tcp` (no UDP chains).
- `dialer-proxy` on SSH, Hysteria2, TUIC, WireGuard (UDP/session-owned dial).
- `dialer-proxy` on DIRECT/REJECT/DNS/REMATCH and on proxy **groups as owners**.
- UDP association chains and `sing-mux`.
- Any failure path that would "recover" by dialing B's server DIRECT while a
  non-empty `dialer-proxy` was configured.

## Evidence

- Config contract tests under `rewrite-config` (missing/self/cycle/group/provider).
- `compat/scripts/phase7t1_dialer_proxy_tcp.py` — Go/Rust path, data, error,
  and lifecycle differentials with hop observations (not echo-only).
- Runtime unit coverage for cancel, mid-hop failure, and no DIRECT bypass.

## Non-goals for 7T1-A

UDP dialer chains, sing-mux, NTP `dialer-proxy`, new protocols, and claiming
Hy2/TUIC/WG as chain upstreams without separate UDP-capable verification.
