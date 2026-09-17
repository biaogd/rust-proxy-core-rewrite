# Go → Rust capability alignment roadmap

**Goal:** bring Rust `rewrite-core` to feature parity with the pinned Go oracle
on every capability we still want to keep, then delete the Go tree.

**Not a goal:** re-implement every historical Go helper. Inventory IDs that are
explicit non-goals stay exclusions (see §7).

Living companions:

| Doc | Role |
| --- | --- |
| [`go-capability-inventory.md`](go-capability-inventory.md) | Stable capability IDs (`IN-*`, `OUT-*`, …) |
| [`inbound-support-matrix.md`](inbound-support-matrix.md) | Server-direction census |
| [`compatibility-matrix.md`](compatibility-matrix.md) | Per-row Parity evidence |
| [`roadmap.md`](roadmap.md) | Historical phase detail (1–9, IN-A…IN-H, 6*/7*/8*) |
| [`status.md`](status.md) | Checkout ledger |

This document is the **ordering plan** for closing gaps. Prefer updating this
file when priorities change; keep phase narratives in `roadmap.md`.

---

## 0. Principles

1. **Fail closed.** Unsupported YAML stays rejected until its alignment slice
   lands — never silently remap Go stack names or ignore keys.
2. **One vertical slice per PR train.** Config parse → runtime →
   Go↔Rust differential → matrix row → status note.
3. **Client and server are separate claims.** Closing VLESS outbound does not
   close VLESS inbound carriers.
4. **Three-platform evidence** (Linux amd64, Darwin arm64, Windows x86_64)
   before calling a family “done enough to drop Go for it”.
5. **Delete Go only at Gate D** (§6). Differential harnesses may keep a
   *frozen* Go binary artifact after source deletion if needed; that is a
   packaging choice, not a reason to keep the Go tree in-tree.

---

## 1. Current baseline (already usable)

Declared-scope near-parity — safe to treat as “Rust owns this” once three-
platform CI is green for that family:

| Track | Surface |
| --- | --- |
| Local ingress | Fixed HTTP / SOCKS / mixed (+ SOCKS UDP) |
| Common clients | HTTP, SOCKS5, SS (broad), SSR outbound, VMess, VLESS (+ Vision/REALITY/xHTTP declared), Trojan (+ REALITY), AnyTLS, Hy2, TUIC v5, WG single-peer, SSH TCP, Snell v1–3 |
| Named servers (first slices) | SS (+ SS2022 UDP), Trojan TLS/WSS/gRPC, VLESS TLS/Vision/WSS/gRPC/XUDP/REALITY auth, VMess AEAD alterId0 TLS/WSS/gRPC/XUDP, Hy2, TUIC v5, AnyTLS TLS TCP |
| DNS / controller / groups | Declared 4F / 5C / 5D scopes |
| TUN | `stack: smoltcp` on Linux/Darwin/Windows (native Parity still open) |

Known product-visible perf debt (does not block feature alignment, but should
ride along):

| Issue | Target |
| --- | --- |
| SS pre-2022 AEAD inbound ~0.5× Go; large bulk fragile | ≥0.9× Go; 256 KiB exchanges stable |
| vless-grpc bulk ~0.92× Go | ≥1.0× or documented exclusion |

---

## 2. Workstreams (what to align)

Ordered by **delete-Go risk** (users hit these first) then by dependency.

### W1 — Transparent & platform ingress

| ID | Work | Exit |
| --- | --- | --- |
| W1.1 | **redir** TCP (Linux/Darwin/FreeBSD; reject elsewhere) | `IN-03` Parity |
| W1.2 | **tproxy** TCP/UDP (Linux) | `IN-04` Parity |
| W1.3 | Static **tunnel** TCP/UDP | `IN-05` / `CFG-10` Parity |
| W1.4 | Named `http` / `socks` / `mixed` listeners (+ TLS/Reality/ECH as Go) | `CFG-07` local named + `IN-01`/`IN-02` extension |
| W1.5 | TUN stacks decision: keep `smoltcp`-only **or** add Go-compatible stack names with real behavior (no silent remap) | Documented exclusion **or** `IN-06` stack Parity |
| W1.6 | Close privileged TUN CI (8A/8B/8C/8F) to Parity | Matrix TUN rows Parity |
| W1.7 | `iptables` inbound-interface / bypass (`CFG-12`) if still advertised | Parity or exclusion |

### W2 — Routing metadata completeness

| ID | Work | Exit |
| --- | --- | --- |
| W2.1 | **PROCESS** name/path/UID rules | `RULE-07` Parity on supported OS |
| W2.2 | **Sniffer** HTTP/TLS/QUIC + config surface | `CFG-16` / `RUN-04` Parity |
| W2.3 | GEOIP **MMDB mode** + **IP-ASN** | `RULE-09` / `SVC-04` completion |
| W2.4 | Geodata download/update/ETag/rollback product path | `SVC-04` / `API-04` geo |
| W2.5 | External UI download + `/upgrade` core/UI/geo | `SVC-05` / `API-11` |

### W3 — Inbound carrier completion (existing protocol families)

Finish Go-compatible options that today fail-closed on named listeners.

| ID | Family | Work | Exit |
| --- | --- | --- | --- |
| W3.1 | Trojan | Reality, `ss-option`, combined ws+grpc / mux | `IN-09` declared complete |
| W3.2 | VLESS | REALITY dest camouflage fallback; Vision+REALITY; xHTTP; combined carriers | `IN-08` VLESS complete |
| W3.3 | VMess | Reality; plain TCP; mKCP/Mekya if still advertised; reject nonzero alterId unless required | `IN-08` VMess complete |
| W3.4 | SS | Remaining ciphers; ShadowTLS v1/v2; mux / ReSTLS / JLS / kcp-tun; port ranges; `rule`/`proxy`/`routing-mark` | `IN-07` SS complete |
| W3.5 | Hy2 | realm listener; gecko/ECH/masquerade; Brutal policy (accurate or reject) | `IN-10` |
| W3.6 | TUIC | v4 token path; ECH/client-auth; congestion knobs policy | `IN-11` TUIC |
| W3.7 | AnyTLS | UoT UDP; ShadowTLS / ReSTLS / JLS carriers | `IN-12` AnyTLS |
| W3.8 | IN-H | Cross-family reload, cert rotation, soak, 3-platform, caps | `IN-14` / IN-H |

### W4 — Missing outbound (and matching inbound where Go has both)

Whole `ProxyKind` gaps today:

| ID | Type | Notes |
| --- | --- | --- |
| W4.1 | **shadowquic** | Client + server (`OUT-13`, `IN-11`) |
| W4.2 | **mieru** | Client + server |
| W4.3 | **sudoku** | Client + server |
| W4.4 | **trusttunnel** | Client + server |
| W4.5 | **masque** / CONNECT-IP | `OUT-17` |
| W4.6 | **openvpn** | `OUT-18` |
| W4.7 | **gost-relay** | `OUT-18` |
| W4.8 | **hysteria** v1 | Separate from Hy2 (`OUT-11` v1) |
| W4.9 | **tailscale** / tsnet (+ DNS) | `OUT-19`; may need `with_gvisor` build story |
| W4.10 | **zerotier** | `OUT-20` |

Each type: YAML → dial/listen → rules/groups/providers → controller view →
differential gate. Prefer implementing **client first**, then server when Go
exposes one.

### W5 — Shared transports & dial composition

| ID | Work | Exit |
| --- | --- | --- |
| W5.1 | **ReSTLS** client transport (unblocks AnyTLS Restls) | Shared transport gate + AnyTLS Restls Parity |
| W5.2 | TLSMirror / remaining JLS / ECH consumers | `OUT-22` rows |
| W5.3 | xHTTP/H3 completion for inbound+outbound consumers | Matrix rows |
| W5.4 | Chrome / uTLS fingerprint wire identity (or documented subset) | Fingerprint rows |
| W5.5 | Finish **dialer-proxy** TCP for VMess/VLESS/Trojan/AnyTLS | `OUT-21` TCP complete |
| W5.6 | UDP dialer-proxy policy (implement or permanently reject) | Explicit |
| W5.7 | **sing-mux** | Implement or approved exclusion |

### W6 — Outbound leftovers on existing types

| ID | Work |
| --- | --- |
| W6.1 | SS: ChaCha8 UDP, 2022 UoT, multi-hop EIH, Go-only extra ciphers |
| W6.2 | TUIC outbound: v4, 0-RTT |
| W6.3 | Hy2 outbound: production BBR evidence; Brutal accuracy or keep rejected |
| W6.4 | WireGuard: multi-peer, AmneziaWG |
| W6.5 | Snell: remaining obfs (shadow-tls/restls/jls); v4/v5 policy |
| W6.6 | SSH: dialer-proxy assessment; keepalive identity |
| W6.7 | SSR: mudb multi-user e2e if still advertised |

### W7 — Services, DNS edges, packaging

| ID | Work |
| --- | --- |
| W7.1 | NTP: proxy dial + `write-to-system` (`SVC-01`) |
| W7.2 | Global TLS CA / client certs / ECH (`SVC-02` / `CFG-13`) |
| W7.3 | DNS system/DHCP native wire; `respect-rules`; named download proxy |
| W7.4 | Profile/selected-proxy persistence completeness (`SVC-03`) |
| W7.5 | Arch / build profiles (`PLAT-*`, Android/FreeBSD/low-mem) — only for advertised targets |
| W7.6 | SS AEAD inbound perf recovery (see §1) |
| W7.7 | Phase 9 packaging, upgrade/rollback, security/license review |

---

## 3. Delivery waves (recommended order)

Waves are sequential at the **program** level; PRs inside a wave may parallelize
across owners.

### Wave A — “Daily driver without Go” (highest leverage)

Unblocks the common self-hosted / desktop path.

1. **W1.1–W1.3** redir / tproxy / tunnel  
2. **W1.4** named local listeners  
3. **W2.1–W2.2** PROCESS + sniffer  
4. **W2.3–W2.4** GEOIP MMDB + geodata product path  
5. **W1.5–W1.6** TUN stack policy + privileged Parity  
6. **W3.1–W3.3** Trojan / VLESS / VMess inbound carrier gaps users hit first  
7. **W5.5** dialer-proxy for remaining major TCP protocols  

**Wave A exit:** a Clash config using fixed+named local ports, TUN smoltcp,
PROCESS/sniffer, GEOIP, and common VMess/VLESS/Trojan/SS in+out runs on Rust
alone with Parity evidence on Linux (Darwin/Windows for TUN + local listeners).

### Wave B — “Carrier & chain completeness”

1. **W5.1–W5.4** ReSTLS / ECH / fingerprint / xHTTP  
2. **W3.4–W3.7** SS / Hy2 / TUIC / AnyTLS inbound leftovers  
3. **W6.*** outbound leftovers on existing types  
4. **W3.8** IN-H production acceptance for the release inbound set  

**Wave B exit:** no fail-closed gaps on advertised options for protocols we
already ship; IN-H soak green for that set.

### Wave C — “Long-tail protocols”

1. **W4.1–W4.4** ShadowQUIC / Mieru / Sudoku / TrustTunnel  
2. **W4.5–W4.8** MASQUE / OpenVPN / Gost / Hysteria v1  
3. **W4.9–W4.10** Tailscale / ZeroTier (or **exclude** from product — see §7)  
4. **W5.6–W5.7** UDP chains / sing-mux decisions  

**Wave C exit:** every remaining `adapter/parser.go` type is either Parity or
an approved exclusion listed in §7 and rejected at parse with a stable error.

### Wave D — “Replace & delete Go”

1. **W7.*** services / DNS edges / packaging  
2. Phase **9A–9D** (`roadmap.md`): artifacts, migration, stress/perf, security  
3. Compatibility matrix: every **advertised** row is Parity or approved
   exclusion  
4. Remove Go sources from the default tree; keep oracle binary only if still
   required for external regression (optional)  
5. Retarget CI to Rust-only; archive `compat` Go half or point at frozen
   artifact  

**Wave D exit:** Go source deleted; `rewrite-core` is the product binary.

---

## 4. Slice template (every alignment PR train)

```text
1. Inventory ID(s) named in PR + this roadmap row
2. Config: accept or keep reject (no silent ignore)
3. Runtime path + resource caps / reload reclaim
4. compat differential (Go client↔Rust, or pinned reference if Go lacks surface)
5. compatibility-matrix.md row → Partial / Parity
6. inbound-support-matrix.md or inventory Rust-state line updated
7. status.md checkout note (short)
```

Label evidence correctly:

- **Go parity** — same scenario vs pinned Go  
- **Interop** — pinned third-party reference (Go has no surface)  
- **Rust extension** — beyond Go (keep documented; do not require for delete-Go)  
- **Exclusion** — will not ship; parse-reject forever  

---

## 5. Tracking checklist (summary)

Copy into project tracking as needed; update statuses here when waves move.

| Wave | Item | Status |
| --- | --- | --- |
| A | W1.1 redir | **Partial** — Linux fixed `redir-port` TCP (this checkout); Darwin/FreeBSD/named open |
| A | W1.2 tproxy | **Partial** — Linux fixed `tproxy-port` TCP + `IP_TRANSPARENT`; UDP/named open |
| A | W1.3 tunnel | **Partial** — top-level `tunnels:` TCP/UDP + SpecialProxy; named open |
| A | W1.4 named http/socks/mixed | Not started |
| A | W2.1 PROCESS | Not started |
| A | W2.2 sniffer | **Partial** — config + TCP TLS SNI / HTTP Host; QUIC/HTTP2 open |
| A | W2.3–W2.4 geodata/MMDB/ASN | Partial |
| A | W1.5–W1.6 TUN policy + CI Parity | Partial |
| A | W3.1–W3.3 Trojan/VLESS/VMess carriers | Partial |
| A | W5.5 dialer-proxy majors | Partial |
| B | W5 ReSTLS/ECH/fingerprint/xHTTP | Partial |
| B | W3.4–W3.7 SS/Hy2/TUIC/AnyTLS inbound | Partial |
| B | W6 outbound leftovers | Partial |
| B | W3.8 IN-H | Partial (Trojan lifecycle only) |
| C | W4 long-tail protocols | Not started |
| C | W5.6–W5.7 UDP chain / sing-mux | Not started |
| D | W7 + Phase 9 + delete Go | Not started |

---

## 6. Delete-Go gate (Gate D)

All must be true:

1. Every capability in [`go-capability-inventory.md`](go-capability-inventory.md)
   that is still **advertised** is **Parity** (or listed in §7).  
2. Wave A–C exits recorded in `status.md` with matrix links.  
3. Phase 9A–9D complete for the release matrix.  
4. No CI job requires building Go from this repository.  
5. Perf: no undeclared regression worse than 0.85× Go on protocols we claim
   as defaults (SS AEAD plan in W7.6).  

Until Gate D, keep the Go tree and the dual-binary `compat/` harness.

---

## 7. Approved / candidate exclusions

Decide early; each exclusion must be parse-rejected and documented.

| Candidate | Recommendation |
| --- | --- |
| SSR / Snell / SSH / WireGuard **servers** | Exclude (inbound non-goals today) |
| VMess nonzero AlterID server expansion | Exclude beyond `alterId: 0` |
| Go TUN `system` / `gvisor` / `mixed` names | Exclude **or** implement real stacks (W1.5) — pick one in Wave A |
| Tailscale / ZeroTier | Exclude unless product commits to gVisor/mobile build matrix |
| Go pprof / expvar semantics | Exclude (runtime-specific) |
| Exact quic-go congestion identity | Exclude; name-map only |
| Chrome fingerprint bit-identical ClientHello | Subset OK if documented |

Exclusions are how we delete Go without boiling the ocean. Anything not
excluded must pass through Waves A–C.

---

## 8. Suggested near-term execution (first 6 slices)

Concrete next slices after this doc lands:

1. **W1.1** Linux redir TCP → `serve_stream_session` ✅  
2. **W1.2** Linux tproxy TCP (UDP next) ✅ partial  
3. **W1.3** static tunnels TCP/UDP ✅ partial (named open)  
4. **W2.2** sniffer config + HTTP/TLS sniff on local/TUN path ✅ partial (QUIC open)  
5. **W2.1** PROCESS rules (Linux first)  
6. **W3.1** Trojan inbound Reality  

Parallel track: **W1.6** TUN privileged CI to Parity; **W7.6** SS AEAD perf.

---

## 9. Doc maintenance

- When a wave item flips status, update §5 and the relevant inventory /
  inbound-matrix / compatibility-matrix rows in the same PR.  
- Do not duplicate long phase prose here — link `roadmap.md` gates.  
- If inventory rows are stale (e.g. still “Not started” after IN-C/D/E), fix
  them when touching that family; do not wait for Gate D.
