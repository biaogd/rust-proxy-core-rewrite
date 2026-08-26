# Go oracle capability inventory

Baseline: `c0e43ebecf3be9b223f1015c1fc38689bb073467` (`Alpha`).

This inventory defines what “cover every Go feature” means for the Rust
rewrite. It inventories externally observable product capabilities, not every
Go helper function. A capability is covered only when its compatibility-matrix
row is **Parity** with named Go/Rust evidence on every advertised platform and
build profile.

## Inventory rules

- Every inventory ID must map to one or more compatibility-matrix rows before
  implementation starts.
- A grouped ID lists its complete public surface. A migration slice must split
  the group when it cannot be accepted by one deterministic test boundary.
- Parser acceptance, runtime behavior, wire interoperability, persistence and
  platform behavior are separate claims even when they share one YAML key.
- Rejected, deprecated and build-disabled Go configurations are observable
  contracts and remain in scope.
- Go source anchors identify the discovery point, not the only implementation
  file. Protocol behavior also spans `transport/`, `tunnel/` and shared
  components.
- The counts below are a planning census, not a completion percentage. Existing
  matrix rows contain narrow slices, aggregate rows and platform evidence rows.

At this audit point the source census contains 146 stable inventory IDs. The
expanded compatibility matrix contains 54 narrow **Parity** rows, 26 **Partial**
rows and 105 **Not started** rows with the standard `Oracle` state; conditional
Oracle/build rows are additional. These counts are diagnostics only. The source
audit below also identifies surfaces that were previously hidden inside
aggregate rows.

## CLI and process lifecycle

Primary anchors: [`main.go`](../../main.go), [`hub/hub.go`](../../hub/hub.go),
[`hub/executor`](../../hub/executor).

| ID | Go capability | Rust state | Planned gate |
| --- | --- | --- | --- |
| CLI-01 | Home/config resolution: default home, `-d`, `CLASH_HOME_DIR`, `-f`, `CLASH_CONFIG_FILE`, relative/absolute paths | Partial (`-f`) | 5A1 |
| CLI-02 | Configuration input precedence: base64 `-config`/`CLASH_CONFIG_STRING`, `-f -` stdin, file/default file | Not started | 5A1 |
| CLI-03 | `-t` full configuration validation, exit status and output/error classes | Partial | One corpus gate per config family |
| CLI-04 | `-v` version, OS/architecture, Go version, build time and feature-tag output | Not started | 5A2 |
| CLI-05 | `-m` geodata-mode override | Not started | 5A2 |
| CLI-06 | Controller/UI/secret/routing-mark override flags and environment variables | Not started | 5A3 |
| CLI-07 | `-age-secret-key` and encrypted configuration loading | Not started | 5A4 |
| CLI-08 | `convert-ruleset` subcommand and MRS/classical/domain/IP output | Not started | 5A5 |
| CLI-09 | `generate` subcommand family | Not started | 5A6 |
| CLI-10 | `age` subcommand family | Not started | 5A4 |
| CLI-11 | Startup, readiness, SIGINT/SIGTERM, SIGHUP, invalid-reload rollback and complete resource shutdown | Partial | 5A7, then repeated per resource family |
| CLI-12 | `post-up` and `post-down` hook ordering, shell behavior and failure handling | Not started | 5A8 |
| CLI-13 | Fatal panic/error/log formatting and exit-code classes | Partial | Cross-cutting contract gates |

## Configuration and application

Primary anchors: [`config/config.go`](../../config/config.go),
[`hub/executor/executor.go`](../../hub/executor/executor.go).

| ID | Go capability | Rust state | Planned gate |
| --- | --- | --- | --- |
| CFG-01 | General ports, bind/LAN/auth, mode, logging, IPv6, interface, routing mark, TFO, MPTCP, TCP concurrency and keepalive | Partial | 5A9 plus listener/platform gates |
| CFG-02 | Controller TCP/TLS/Unix/Windows pipe, routing mark, CORS, secret, external UI/URL/name and external DoH mount | Partial | 5D1–5D3 |
| CFG-03 | Proxies, reserved built-ins, duplicate/reserved-name checks and dependency ordering | Not started | 6A0 |
| CFG-04 | Proxy groups, cycles, filters, include-all, expected status, empty fallback and removed `relay` rejection | Not started | 5C1 |
| CFG-05 | Proxy/rule providers, vehicles, health checks, refresh, persistence and overrides | Not started | 5C2–5C4 |
| CFG-06 | Rules, sub-rules and provider-backed rule construction | Partial | 5B1–5B5 |
| CFG-07 | Named listeners and legacy fixed protocol listener fields | Not started | One gate per IN ID |
| CFG-08 | Hosts and DNS configuration, including all defaults and validation dependencies | Partial | 4-completion gates |
| CFG-09 | TUN, route, auto-route/redirect, stack and DNS-hijack settings | Not started | 8A–8D |
| CFG-10 | Static TCP/UDP tunnels and validation | Not started | 5B6 |
| CFG-11 | NTP enable/listen/server/port/interval/dialer-proxy/write-to-system | Not started | 5E1 |
| CFG-12 | iptables inbound-interface and bypass rules | Not started | 8A |
| CFG-13 | TLS certificate/private key, custom roots and client authentication | Not started | 5E2 and protocol gates |
| CFG-14 | Profile selected-proxy/fake-IP persistence | Partial | 5E3 |
| CFG-15 | Geodata mode/loader/matcher/URLs/update interval and ETag behavior | Not started | 5B4, 5E4 |
| CFG-16 | Sniffer enablement, HTTP/TLS/QUIC sniffers, force/skip domains and addresses, port ranges and destination override | Not started | 5B7 |
| CFG-17 | Experimental QUIC GSO/ECN, Android/CFA fields and feature-gated settings | Not started | 8E/build-profile gates |
| CFG-18 | Transactional application/reload ordering for every resource above | Partial | Repeated exit gate for each family |

## Inbound listeners

The named-listener parser is authoritative at
[`listener/parse.go`](../../listener/parse.go). Fixed HTTP/SOCKS/mixed ports and
legacy SS/VMess/TUIC fields are applied through `hub/executor`.

| ID | Go capability | Rust state | Planned gate |
| --- | --- | --- | --- |
| IN-01 | Mixed HTTP plus SOCKS4/4a/5 TCP and SOCKS5 UDP | Partial | 5F1 full local semantics |
| IN-02 | Fixed HTTP and SOCKS listeners, authentication, LAN policy, TFO/MPTCP and UDP association lifecycle | Partial | 5F1 |
| IN-03 | Redir TCP on Linux/Darwin/FreeBSD and platform rejection elsewhere | Not started | 8A–8C |
| IN-04 | Linux TProxy TCP/UDP, original destination, socket options and write-back | Not started | 8A |
| IN-05 | Static tunnel TCP/UDP listener | Not started | 5B6 |
| IN-06 | TUN listener, system/gVisor/mixed stacks, routing and DNS hijack | Not started | 8A–8D |
| IN-07 | Shadowsocks and Snell server, TCP/UDP/version/plugin behavior | Not started | 6/7 protocol gates |
| IN-08 | VMess and VLESS server, TCP/UDP and transport/security variants | Not started | 6 protocol gates |
| IN-09 | Trojan server, TLS/auth/fallback/TCP/UDP | Not started | 6 protocol gates |
| IN-10 | Hysteria2 and Hysteria2-realm server | Not started | 6 protocol gates |
| IN-11 | TUIC v4/v5 and ShadowQUIC server | Not started | 6/7 protocol gates |
| IN-12 | AnyTLS, Mieru, Sudoku and TrustTunnel server | Not started | 7 protocol gates |
| IN-13 | Transport/security extensions used by inbound protocols: Reality, ShadowTLS, ReSTLS, JLS, TLSMirror, mux, WebSocket, HTTP/2, gRPC/Gun, xHTTP, mKCP and Mekya | Not started | 7T gates |
| IN-14 | Listener hot rebind, same-port update, graceful drain and per-listener statistics for every type | Partial only for local listeners | Repeated protocol exit gate |

## Rules, metadata and routing

The complete rule switch is in [`rules/parser.go`](../../rules/parser.go); the
central TCP/UDP data plane is in [`tunnel`](../../tunnel).

| ID | Go capability | Rust state | Planned gate |
| --- | --- | --- | --- |
| RULE-01 | MATCH plus Rule/Direct/Global modes and target resolution | Partial | 5B1 |
| RULE-02 | DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD | Partial | 5B1 completion |
| RULE-03 | DOMAIN-REGEX and DOMAIN-WILDCARD | Not started | 5B1 |
| RULE-04 | IP-CIDR/IP-CIDR6/SRC-IP-CIDR and lazy/no-resolve semantics | Partial | 5B2 |
| RULE-05 | IP-SUFFIX/SRC-IP-SUFFIX, address unmapping and family behavior | Not started | 5B2 |
| RULE-06 | SRC/DST/IN-PORT, NETWORK and DSCP | Partial | 5B2 completion |
| RULE-07 | PROCESS name/path exact/regex/wildcard and UID across supported OSes | Not started | 5B3 plus platform gates |
| RULE-08 | IN-TYPE, IN-USER and IN-NAME | Not started | 5B3 |
| RULE-09 | GEOIP, GEOSITE, IP-ASN and source variants | Not started | 5B4 |
| RULE-10 | RULE-SET classical/domain/IP strategies, MRS, providers and refresh | Not started | 5B5, 5C4 |
| RULE-11 | SUB-RULE, AND/OR/NOT with lazy DNS/process helpers and cycle/error behavior | Partial | 5B3 |
| RULE-12 | PASS, PASS-RULE, REMATCH/REMATCH-NAME and rescan mutation semantics | Partial pure core only | 5B3 live routing |
| RULE-13 | Rule hit/miss counters, disabled state and concurrent mutation API | Not started | 5D5 |
| RULE-14 | TCP and UDP routing lifecycle, adapter unwrap, retries, NAT/write-back and close behavior | Partial | Cross-cutting protocol gates |

## Outbound adapters and transports

The product parser enumerates outbound types in
[`adapter/parser.go`](../../adapter/parser.go). Transport variants live below
[`transport`](../../transport).

| ID | Go capability | Rust state | Planned gate |
| --- | --- | --- | --- |
| OUT-01 | DIRECT TCP/UDP, interface, routing mark, IP strategy, TFO, MPTCP and dial concurrency | Partial | 6A1 plus platform gates |
| OUT-02 | REJECT, REJECT-DROP, COMPATIBLE, PASS, PASS-RULE, DNS and REMATCH built-ins | Partial/Not started | 6A2 |
| OUT-03 | HTTP proxy client: plaintext/TLS, auth, CONNECT and UDP limitations | Not started | 6B1 |
| OUT-04 | SOCKS5 proxy client: TCP/UDP, auth and remote/local resolution | Not started | 6B2 |
| OUT-05 | Shadowsocks: cipher matrix, plugins, UDP and UoT | Not started | 6C |
| OUT-06 | ShadowsocksR: cipher/protocol/obfs and UDP | Not started | 7A |
| OUT-07 | VMess: security/alter-id, TCP/UDP, early data and packet modes | Not started | 6D |
| OUT-08 | VLESS: encryption, Vision/Reality, TCP/UDP and packet modes | Not started | 6E |
| OUT-09 | Trojan: TLS/security extensions, fallback and UDP | Not started | 6F |
| OUT-10 | Snell versions, obfs/security extensions, UDP and pool | Not started | 7B |
| OUT-11 | Hysteria v1/v2: QUIC/fake TCP, obfs, congestion, UDP and PMTUD | Not started | 6G |
| OUT-12 | TUIC v4/v5: QUIC, 0-RTT, congestion and UDP relay | Not started | 6H |
| OUT-13 | ShadowQUIC | Not started | 7C |
| OUT-14 | WireGuard and AmneziaWG: userspace stacks, peers, routes and DNS | Not started | 6I |
| OUT-15 | SSH: authentication, host-key policy, keepalive and multiplexing | Not started | 6J |
| OUT-16 | Mieru, AnyTLS and Sudoku | Not started | 7D–7F |
| OUT-17 | MASQUE/CONNECT-IP and TrustTunnel | Not started | 7G–7H |
| OUT-18 | OpenVPN and Gost relay | Not started | 7I–7J |
| OUT-19 | Tailscale/tsnet and Tailscale DNS | Not started | 7K plus `with_gvisor` |
| OUT-20 | ZeroTier network lifecycle, state and managed DNS | Not started | 7L |
| OUT-21 | Per-proxy dialer-proxy chains and sing-mux | Not started | 7T1 |
| OUT-22 | Shared transports/security: WebSocket, HTTP/2, gRPC/Gun, xHTTP/H3, mKCP, Mekya, simple-obfs, v2ray-plugin, ShadowTLS, ReSTLS, JLS, TLSMirror, Reality and ECH | Not started | One 7T gate per transport/security boundary |
| OUT-23 | Common adapter JSON, delay/history, liveness, UDP support, unwrap and lifecycle | Not started | Repeated adapter contract gate |

## Proxy groups and providers

Primary anchors: [`adapter/outboundgroup`](../../adapter/outboundgroup),
[`adapter/provider`](../../adapter/provider), [`rules/provider`](../../rules/provider).

| ID | Go capability | Rust state | Planned gate |
| --- | --- | --- | --- |
| GRP-01 | Selector and manual selection/persistence | Not started | 5C1 |
| GRP-02 | URL-test, fallback and load-balance strategies | Not started | 5C1 |
| GRP-03 | Group filters, include-all, provider composition, empty fallback, lazy health checks and URL/status policies | Not started | 5C1 |
| PROV-01 | Proxy providers: file/HTTP vehicles, parsing, override, refresh, health checks and persistence | Not started | 5C2–5C3 |
| PROV-02 | Rule providers: text/YAML/MRS formats, classical/domain/IP behavior, refresh and persistence | Not started | 5C4 |
| PROV-03 | Concurrent update, failure rollback, resource cleanup and SIGHUP interaction | Not started | 5C5 |

## DNS

Configuration is parsed in [`config/config.go`](../../config/config.go) and
runtime behavior is under [`dns`](../../dns).

| ID | Go capability | Rust state | Planned gate |
| --- | --- | --- | --- |
| DNS-01 | Local UDP/TCP server: complete question validation, all RR types, flags, rcode, EDNS, truncation and UDP-size behavior | Complete in the Phase 4F1 declared local-listener scope | 4F1 |
| DNS-02 | Classic UDP/TCP upstreams: IP/domain targets, multiple servers, parallel selection, timeout/failure and UDP-TC retry over TCP | Complete in the Phase 4F2 declared classic-main scope | 4F2 |
| DNS-03 | System resolver on POSIX/Windows/Android-CMFA, refresh/reset behavior | Partial: config/runtime and host-side platform contracts; native wire/platform gates pending | 4F3 plus platform gates |
| DNS-04 | DHCP-discovered upstream and invalidation | Partial: config, DHCPv4 wire and refresh/interface-change contracts; privileged native discovery pending | 4F4 plus platform gates |
| DNS-05 | RCODE synthetic upstream and Tailscale DNS upstream | Partial: all synthetic RCODE behavior and named resolver registration/replacement/missing lifecycle pass Phase 4F5; real tsnet `QueryDNS` transport remains | 4F5/7K |
| DNS-06 | DoT URL/default-port/bootstrap, TLS trust/name options, reuse/retry/reset/concurrency | Partial | 4E9–4E11 |
| DNS-07 | DoH HTTP and HTTPS URL semantics, GET wire behavior, redirects/auth, bootstrap and HTTP/1.1 pooling | Partial | 4E12–4E14 |
| DNS-08 | DoH HTTP/2 and HTTP/3 forced/preferred/race/fallback/0-RTT behavior | Partial: 4E15 HTTP/2 and 4E16 declared H3 subset accepted; broader lifecycle remains | 4E15–4E16 plus later lifecycle gates |
| DNS-09 | DoQ TLS/QUIC, framing, reuse, streams, retry/token/reset/concurrency | Partial: 4E17 framing and 4E18 declared reuse/concurrency/retry/reset subset accepted; broader endpoint/trust/token rejection remains | 4E17–4E18 plus later endpoint/trust gates |
| DNS-10 | Upstream params: proxy name/respect-rules, skip/name verification, H3, reuse, ECS/override, disable IPv4/IPv6/qtype | Partial: TLS/H3 options plus encrypted and classic ECS/disable wrappers pass 4E19/4F6; proxy routing and cross-resolver-set combinations remain | 4D3B, 4E19, 4F6–4F9 |
| DNS-11 | Default/main/fallback/direct/proxy-server resolver sets, all transports, shared transport identity and direct-follow-policy | Partial: 4F7 common set model, multi-client selection and direct-follow-policy pass; complete default-bootstrap and real proxy-outbound consumers remain | 4D3B, 4F7 plus consumer gates |
| DNS-12 | Nameserver and proxy-server policy: multiple upstreams, exact/wildcard ordering, same-node overwrite, geosite and rule-set | Partial: Phase 4F8 ordered multi-resolver policies, all four GeoSite domain types and inline domain/classical rule-set matchers pass; external provider vehicles, GeoSite attributes, real proxy-outbound consumption and `respect-rules` remain | 4F8 plus provider/adapter gates |
| DNS-13 | Fallback: multiple servers, GeoIP/GeoSite/domain/IPv4/IPv6 filters, lazy/eager, failure and ordering | Partial: Phase 4F9 deterministic geodata-mode GeoIP/GeoSite/domain/IP filters, multi-client selection, eager/lazy SERVFAIL and shared five-second timeout ordering pass; MMDB-mode GeoIP and broader transport/retry integration remain | 4F9 plus database/integration gates |
| DNS-14 | IPv4/IPv6 lookup ordering, IPv6 timeout, primary IPv4, ECH/HTTPS RR and lazy tunnel resolution | Partial | 4F10 |
| DNS-15 | Cache algorithms LRU/ARC, max size, TTL, stale, negative/error behavior, singleflight, retry and transport reset | Partial | 4F11 |
| DNS-16 | Hosts: exact/wildcard/`lan`, IP/CNAME/multiple values, system hosts, randomized selection and all query types/platforms | Partial | 4F12 |
| DNS-17 | Redir-host mapping: TCP/UDP, all inbounds, CNAME identity, reload and expiry | Partial | 4F13 |
| DNS-18 | Fake IP v4/v6, all filter modes/rules/providers, persistence/interchange, reverse routing, reload/range migration and flush | Partial | 4F14 |
| DNS-19 | Local DNS REST and external DoH server: GET/POST, arbitrary RR JSON, auth/errors and all cache controls | Partial | 4F15/5D6 |
| DNS-20 | TUN DNS hijack and intercepted routing on each supported stack/OS | Not started | 8A–8D |

The 4E numbering is therefore extended only through DoQ and encrypted-transport
parameters. General classic DNS, policy, cache, hosts and fake-IP completion use
4F gates rather than turning every DNS feature into an encrypted-DNS claim.

## Tunnel, runtime state and observability

Primary anchors: [`tunnel`](../../tunnel),
[`tunnel/statistic`](../../tunnel/statistic), [`hub/executor`](../../hub/executor).

| ID | Go capability | Rust state | Planned gate |
| --- | --- | --- | --- |
| RUN-01 | TCP routing, relay, half-close, cancellation, metadata mutation and adapter retries | Partial | Repeated routing/protocol gates |
| RUN-02 | UDP NAT/session lifecycle, packet routing, write-back, timeout and rule changes | Partial local subset | 5F2 then protocol gates |
| RUN-03 | Mode/global proxy changes and live rule/sub-rule/provider updates | Not started | 5B/5C/5D |
| RUN-04 | Sniffing and destination replacement for HTTP/TLS/QUIC | Not started | 5B7 |
| RUN-05 | Process lookup, interface binding, routing marks, socket options, TFO/MPTCP and keepalive | Not started | Platform gates |
| RUN-06 | Connection tracking, upload/download totals, memory and traffic/log streams | Partial | 5D4 |
| RUN-07 | Graceful resource replacement for listeners, DNS, adapters, groups, providers, TUN, NTP and controller | Partial local subset | Repeated family gate |
| RUN-08 | Power/network change handling and resolver/connection reset | Not started | 8F |
| RUN-09 | Bounded queues, backpressure, concurrency limits, cancellation and leak/stress behavior | Partial | Every release/protocol gate |

## REST controller

Route registration is in [`hub/route/server.go`](../../hub/route/server.go) and
the mounted route files below [`hub/route`](../../hub/route).

| ID | Go capability | Rust state | Planned gate |
| --- | --- | --- | --- |
| API-01 | TCP/TLS/Unix/Windows-pipe controller listeners, routing mark and replacement | Partial TCP only | 5D1 plus platform gates |
| API-02 | Bearer/query/WebSocket authentication and CORS | Partial Bearer only | 5D2 |
| API-03 | `/`, `/version`, `/memory`, `/traffic`, `/logs` HTTP/WebSocket contracts | Partial | 5D3–5D4 |
| API-04 | `/configs` GET/PUT/PATCH and `/configs/geo` | Partial GET subset | 5D5 |
| API-05 | `/proxies` list/detail/delay/select/delete and `/group` list/detail/delay | Not started | 5D7 |
| API-06 | `/rules` list/statistics and disable mutation | Not started | 5D8 |
| API-07 | `/connections` list/WebSocket/delete-one/delete-all | Partial list subset | 5D9 |
| API-08 | Proxy/rule provider list/detail/update/health endpoints | Not started | 5D10 |
| API-09 | `/cache/fakeip/flush`, `/cache/dns/flush`, `/dns/query` | Partial | 4F15 |
| API-10 | `/storage/{key}` GET/PUT/DELETE | Not started | 5D11 |
| API-11 | `/restart`, `/upgrade`, `/upgrade/ui`, `/upgrade/geo` | Not started | 5D12 |
| API-12 | External UI static serving/redirect, external DoH GET/POST mount and debug/GC routes | Not started | 5D13 |
| API-13 | Exact JSON fields, headers, status/error bodies, stream cadence and concurrent behavior across all routes | Partial | Required in each API gate |

## Supporting services and persistence

| ID | Go capability | Rust state | Planned gate |
| --- | --- | --- | --- |
| SVC-01 | NTP polling, proxy dialing, clock write and reload/shutdown | Not started | 5E1 |
| SVC-02 | Global TLS CA/client certificates and ECH | Not started | 5E2 |
| SVC-03 | Profile/cache database selected-group, fake-IP and storage state, corruption/migration/interchange | Partial Rust-only fake-IP JSON | 5E3 |
| SVC-04 | Geodata/MMDB/MRS loading, matching, download/update, ETag and failure rollback | Not started | 5E4 |
| SVC-05 | External UI download/update and safe path handling | Not started | 5E5 |
| SVC-06 | Memory accounting, buffer pools and low-memory behavior | Not started | 8E |
| SVC-07 | Interface discovery, DHCP, process lookup, power/network events and platform command execution | Not started | 8F |

## Platforms, packaging and build profiles

Release targets are enumerated in [`.github/workflows/build.yml`](../../.github/workflows/build.yml)
and the [`Makefile`](../../Makefile). Build success and runtime parity remain
separate claims.

| ID | Go capability | Rust state | Planned gate |
| --- | --- | --- | --- |
| PLAT-01 | Linux 386/amd64/armv5-7/arm64/mips/mips64/riscv64/loong64/s390x/ppc64le builds | Not started beyond limited Linux amd64 evidence | 8A/8E |
| PLAT-02 | Darwin amd64/arm64 builds and native behavior | Partial Darwin arm64 | 8B |
| PLAT-03 | Windows 386/amd64/arm32/arm64, named pipes and Windows system integration | Not started | 8C |
| PLAT-04 | FreeBSD 386/amd64/arm64 and redirect/TUN behavior | Not started | 8D |
| PLAT-05 | Android 386/amd64/arm/arm64, NDK, CMFA and package integration | Not started | 8D |
| PLAT-06 | Default and `with_gvisor` product profiles | Not started as Rust product claims | 8E |
| PLAT-07 | `with_low_memory`, `no_fake_tcp`, `no_tailscale`, `no_zerotier`, `cmfa` behavior/rejection | Not started | 8E |
| PLAT-08 | Release archives/packages, executable naming, version metadata and reproducibility | Not started | 9A |
| PLAT-09 | Long-lived stability, performance, memory, security, licensing, upgrade and rollback | Not started | 9B–9D |

## Planning conclusions

1. Phase 4E8 is not the end of encrypted DNS parity. The inventory reserves
   4E9–4E19 for the remaining DoT, DoH, DoQ and encrypted-upstream parameter
   boundaries.
2. Phase 4F1–4F15 completes general DNS server, upstream, policy, cache, hosts,
   fake-IP and REST behavior without mislabeling it as encrypted DNS.
3. Phases 5A–5F cover lifecycle/configuration, routing/geodata, groups/providers,
   controller APIs, supporting services and remaining local data-plane behavior.
4. Every outbound client, inbound server direction and shared transport needs a
   separate Phase 6/7 interop gate; an aggregate protocol name is insufficient.
5. Phase 8 must test behavior natively per OS/stack/build profile. Cross-builds
   alone cannot move a runtime row to **Parity**.
6. Phase 9 is the only replacement gate. It requires every advertised inventory
   ID to resolve to **Parity** or an explicitly approved exclusion.

## Completeness gate

Before a future phase starts, its proposal must name inventory IDs and exact
compatibility-matrix rows. Before release, search this document for every
`Partial` and `Not started` state, reconcile it with the matrix, and record any
intentional exclusion with rationale. No aggregate statement such as “protocol
parity” or “full Go compatibility” is permitted while an applicable inventory
ID lacks evidence.
