# Rust rewrite status

Last updated: 2026-08-26

Go oracle: `c0e43ebecf3be9b223f1015c1fc38689bb073467` (`Alpha`)

## Overall status

| Workstream | State | Evidence / next gate |
| --- | --- | --- |
| Phase 0 baseline and governance | Complete | Six migration documents and root `AGENTS.md` |
| Phase 0B exhaustive Go capability census | Complete | Stable CLI/config/inbound/rule/outbound/DNS/runtime/API/service/platform inventory IDs and planned gates |
| Go reference implementation | Preserved | No existing Go source modified or deleted |
| Phase 1 vertical slice | Complete | Native Darwin arm64 and containerized Linux amd64 differential suites passed |
| Phase 2 config and pure rule core | Complete | 37 fixed + 96 generated config + 256 generated rule Go/Rust observations passed |
| Phase 3 local proxy product | Complete in declared scope | Native TCP/auth/controller/reload/SOCKS UDP differential suite passed |
| Phase 4A classic local DNS | Complete in declared scope | Native UDP/TCP client × UDP/TCP upstream differential suite passed |
| Phase 4B hosts and redir-host mapping | Complete in declared scope | Configured/system hosts, CNAME and DNS-to-SOCKS mapping differential suite passed |
| Phase 4C fake IP | Complete in declared scope | IPv4/IPv6 allocation, filters, bounded pool, TCP reverse mapping and restart differential suite passed |
| Phase 4D1 nameserver policy | Complete in declared scope | Exact/`*`/`+.` domain selection across deterministic local UDP/TCP authorities passed |
| Phase 4D2 DNS fallback | Complete in declared scope | Single main/fallback, domain/IP filtering, eager/lazy behavior, policy precedence and cache differential suite passed |
| Phase 4D3A direct/lazy DNS | Complete in declared scope | Lazy destination IP-CIDR resolution, `no-resolve`, direct resolver and follow-policy TCP differential suite passed |
| Phase 4D4 DNS REST control | Complete in declared scope | Authenticated A/AAAA/CNAME query JSON and shared positive-cache flush differential suite passed |
| Phase 4E1 loopback DoT | Complete in declared scope | Explicit insecure/no-reuse TLS main upstream, DNS framing and cache differential suite passed |
| Phase 4E2 verified DoT | Complete in declared scope | One inline custom root, explicit name/SNI verification, cache and wrong-name SERVFAIL differential suite passed |
| Phase 4E3 multiple verified-DoT roots | Complete in declared scope | Issuing/decoy root order, cache and untrusted-chain SERVFAIL differential suite passed |
| Phase 4E4 verified-DoT reuse | Complete in declared scope | Persistent cross-client reuse, cache separation and stale pooled-connection reconnect differential suite passed |
| Phase 4E5 verified HTTPS DoH GET | Complete in declared scope | HTTP/1.1 GET wire contract, custom-root/name validation, response ID restoration and cache differential suite passed |
| Phase 4E6 HTTP/1.1 DoH reuse | Complete in declared scope | Persistent cross-client reuse, cache separation and stale pooled-connection recovery differential suite passed |
| Phase 4E7 custom DoH path | Complete in declared scope | Safe custom-path config acceptance, exact GET target and cache differential suite passed |
| Phase 4E8 encoded DoH path bytes | Complete in declared scope | Encoded-unreserved config acceptance, canonical GET target and cache differential suite passed |
| Phase 4E9 domain DoT bootstrap | Complete in declared scope | `DNS-06`; domain endpoint, implicit port 853, classic bootstrap A query and verified DoT/cache differential suite passed |
| Phase 4E10 DoT trust/verification matrix | Complete in declared scope | `DNS-06`; default system/embedded/global roots, verification precedence and reuse-toggle differential suite passed |
| Phase 4E11 DoT lifecycle | Complete in declared scope | `DNS-06`; concurrent pool cap, five-second timeout, reload reset and bounded-retry differential suite passed |
| Phase 4E12 plaintext HTTP DoH | Complete in declared scope | `DNS-07`; default URL forms, RFC 8484 GET, cache and sequential-reuse differential suite passed |
| Phase 4E13 HTTPS URL semantics | Complete in declared scope | `DNS-07`; root/default-port, discarded configured query, ASCII Basic userinfo and persistent same-origin relative redirect differential suite passed |
| Phase 4E14 domain HTTPS bootstrap/trust | Complete in declared scope | `DNS-07`; one loopback UDP bootstrap, URL-domain Host/SNI and default/name-override/skip verification-precedence differential suite passed |
| Phase 4E15 DoH HTTP/2 | Complete in declared scope | `DNS-08`; ALPN `h2`, RFC 8484 GET, sequential stream reuse and HTTP/1.1 fallback differential suite passed |
| Cargo workspace | Implemented | Twelve focused crates under `rust/crates/`; `Cargo.lock` is present with the workspace |
| Differential harness | Implemented | Phase 1 network, Phase 2 pure policy, Phase 3 local-product and Phase 4A–4E15 DNS suites run by default in GitHub Actions |
| First mixed-to-DIRECT slice | Parity in declared scope | Minimal YAML -> mixed HTTP/SOCKS5 TCP -> `MATCH,DIRECT` -> DIRECT relay |
| Phase 2 declared spec/rule subset | Parity in declared scope | Normalized general config plus pure domain/IP/port/network/logic/sub-rule/rematch behavior |
| Broader Mihomo functionality | Not started | Exhaustively planned in `go-capability-inventory.md`; behavior beyond the declared Phase 4E15 subset remains unimplemented |

## Phase 0 deliverables

- `architecture.md`: current call graph, state/application ordering, data plane,
  controller and proposed crate boundaries.
- `compatibility-matrix.md`: CLI, config, inbound, routing, outbound, DNS, REST,
  platform and build-profile inventory.
- `roadmap.md`: phased delivery plan and black-box Go/Rust differential test
  architecture.
- `upstream-sync.md`: pinned baseline, audit/classification workflow and
  controlled baseline-move procedure.
- `go-capability-inventory.md`: stable product capability IDs, Go discovery
  anchors, current Rust states and planned acceptance gates.
- root `AGENTS.md`: rules for preserving the oracle, vertical slices, evidence,
  Rust quality checks and status discipline.

## Phase 0B deliverables and evidence

The pinned Go source was audited by external product surface rather than by Go
package. The census covers:

- CLI/config input and lifecycle contracts from `main.go`, `config/` and
  `hub/executor`;
- all named-listener types exposed by `listener/parse.go` plus fixed and legacy
  listener fields;
- every rule family in `rules/parser.go`, every outbound type in
  `adapter/parser.go`, proxy groups/providers and shared transport/security
  variants;
- DNS transports, wrappers, resolver roles/policies, cache, hosts, fake IP,
  REST and TUN interception;
- all mounted controller routes, supporting services, release platforms,
  architectures and build tags.

`go-capability-inventory.md` assigns stable IDs and planned gates. The roadmap
now reserves 4E9–4E19 for remaining encrypted DNS, 4F1–4F15 for general DNS
completion, 5A–5F for local product completion, protocol/transport gates under
6/7 and native platform/build gates under 8. Previously implicit gaps including
synthetic RCODE and Tailscale DNS upstreams, dialer chains/sing-mux and shared
JLS/ReSTLS/ShadowTLS/TLSMirror/mKCP/Mekya boundaries now have explicit matrix
rows.

This was a documentation/planning phase. It added no Rust behavior and changes
no existing **Parity** claim. The census contains 146 stable inventory IDs. At
the snapshot, standard `Oracle` matrix rows comprised 54 narrow **Parity**, 26
**Partial** and 105 **Not started** entries; conditional Oracle/build rows are
additional, and the counts are planning diagnostics rather than a completion
percentage.

## Phase 1 deliverables and evidence

Implemented workspace boundaries:

- `rewrite-config`: the declared minimal YAML and `-t` validation surface;
- `rewrite-model` and `rewrite-rules`: owned destination metadata and exactly
  one `MATCH,DIRECT` rule;
- `rewrite-inbound`: mixed first-byte detection, HTTP absolute-form/CONNECT and
  SOCKS5 CONNECT parsing;
- `rewrite-outbound` and `rewrite-net`: DIRECT TCP dial and half-close-aware
  bidirectional relay;
- `rewrite-runtime` and `rewrite-cli`: loopback listener, bounded handshakes,
  cancellation, SIGTERM and the `-f`/`-t` process surface.

The black-box suite runs the pinned Go binary and Rust candidate separately
against the same local echo, half-close and HTTP servers. It compares config
acceptance/error classes, wire replies, origin observations, arbitrary relay
bytes, dial-failure closure and shutdown. Passing runs remove the known diff
artifact; failing runs retain observations, rendered YAML and raw logs.

Observed Phase 1 differential results on 2026-08-25:

| Platform | Result | Environment |
| --- | --- | --- |
| Darwin arm64 | Passed | Native Go 1.26.5 and Rust 1.95.0 |
| Linux amd64 | Passed | `rust:1.95-bookworm` amd64 container, Go 1.26.5 oracle |

The fixture sets `ipv6: false`, so an IPv6-address SOCKS request is expected to
close in parity. Enabled IPv6 operation is not claimed. The oracle-specific
`05 02` response to a sole SOCKS username/password method offer is preserved,
but authenticated SOCKS operation is not implemented or claimed.

Phase 1 intentionally rejects configuration keys outside its declared surface
instead of silently accepting settings it cannot apply. That guard is covered
by a Rust contract test; it is not a claim of full Go parser parity.

### Phase 1 exit-gate commands

All of the following passed on 2026-08-25:

```sh
cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features

cd ..
python3 compat/scripts/phase1.py
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./...
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./... -tags with_gvisor -count=1
CGO_ENABLED=0 go build -tags with_gvisor -trimpath -o /tmp/mihomo-go-oracle .
```

The compatibility script also passed inside an amd64 Linux container with an
x86_64 Rust 1.95.0 candidate and the pinned Go 1.26.5 oracle.

## Phase 2 deliverables and evidence

Phase 2 added an owned `ConfigSpec` layer which overlays the declared Go
defaults and validates normalized configuration before any runtime resource is
constructed. Conversion to executable `Config` remains a separate gate and
still accepts only the Phase 1 mixed listener plus exact `MATCH,DIRECT` slice.
Parser parity therefore does not silently enable unimplemented listeners or
protocols.

The pure rule core now covers the declared subset of domain, IPv4/IPv6 CIDR,
source/destination/inbound port, TCP/UDP network, AND/OR/NOT and sub-rule
matching. Ordered evaluation covers PASS, PASS-RULE, rematch-name, rematch
metadata transitions and cycle detection. It does not dial, reject, resolve DNS
or construct any new adapter.

`compat/oracle/phase2` is a test-only Go adapter over the pinned implementation;
`rewrite-test-support` exposes the equivalent Rust observation protocol. The
local-only suite compares exact normalized JSON for:

- 37 reviewed default, override, invalid, matcher, scan and cycle cases;
- 96 deterministically generated configuration overlays;
- 256 deterministically generated rule/matcher cases;
- fixed seed `0xc0e43ebe`, retained in any mismatch artifact.

Observed Phase 2 differential result on 2026-08-25:

| Platform | Result | Environment |
| --- | --- | --- |
| Darwin arm64 | Passed | Native Go 1.26.5 and Rust 1.95.0; no public network or privileges |

Phase 1 differential regression, Rust formatting, strict Clippy and all
workspace tests also passed after the Phase 2 changes.

### Phase 2 exit-gate commands

The following passed on 2026-08-25:

```sh
python3 compat/scripts/phase2.py
python3 compat/scripts/phase1.py

cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features

cd ..
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./...
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./... -tags with_gvisor -count=1
CGO_ENABLED=0 go build -tags with_gvisor -trimpath -o /tmp/mihomo-go-oracle .
```

## Phase 3 deliverables and evidence

Phase 3 was completed as four ordered local-only gates:

1. fixed HTTP/SOCKS plus mixed listeners, HTTP Basic, SOCKS4/4a/5
   authentication and CONNECT, DIRECT and immediate REJECT TCP behavior;
2. shared connection/traffic state and a read-only loopback TCP controller for
   the declared `/version`, `/configs`, `/connections`, `/traffic` and `/logs`
   observations with Bearer auth;
3. SIGHUP-driven configuration generations with same-port rule switching,
   invalid-config rollback and listener port migration;
4. SOCKS5 UDP ASSOCIATE plus local IPv4 DIRECT datagram write-back on fixed
   SOCKS and mixed ports, including nonzero-FRAG drop.

The new `rewrite-state` crate owns connection snapshots, totals and bounded log
broadcasting. `rewrite-controller` is read-only and consumes that state; it does
not mutate runtime resources. The runtime publishes a new owned config only
after every newly required listener socket binds successfully, while unchanged
listener tasks read the current generation for new connections.

`compat/scripts/phase3.py` runs all declared cases against the pinned Go and
Rust binaries with local TCP/UDP echo servers. Exact parity evidence includes
HTTP 407/403, SOCKS auth replies, SOCKS4 result codes, REJECT EOF, Go JSON
null/array distinctions, tracker chains, traffic totals, log error bodies,
reload behavior, UDP headers/payloads/source ports and fragmentation drop.

Observed Phase 3 result on 2026-08-25:

| Platform | Result | Environment |
| --- | --- | --- |
| Darwin arm64 | Passed | Native Go 1.26.5 and Rust 1.95.0; ephemeral loopback TCP/UDP only |

One explicit Rust-only safety contract also passed: when a replacement port is
already occupied, the old generation remains live. The pinned Go implementation
closes the old listener before attempting the new bind, so this is documented
as a deliberate stronger rollback property rather than a compatibility claim.

Phase 3 evidence by itself does not claim controller mutation, WebSocket
parity, general-purpose UDP NAT, DNS, TUN, remote adapters, REJECT-DROP timing
or non-Darwin runtime evidence. The separate narrow DNS claim begins in Phase
4A below.

### Phase 3 exit-gate commands

```sh
python3 compat/scripts/phase3.py
python3 compat/scripts/phase2.py
python3 compat/scripts/phase1.py

cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features

cd ..
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./...
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./... -tags with_gvisor -count=1
CGO_ENABLED=0 go build -tags with_gvisor -trimpath -o /tmp/mihomo-go-oracle .
```

## Phase 4A deliverables and evidence

Phase 4A adds `rewrite-dns` as a narrow classic-DNS boundary. Executable
configuration accepts an explicit loopback IPv4 DNS address, disabled
configured/system hosts and exactly one loopback IP-literal UDP or TCP
upstream. A DNS-only process is permitted; existing proxy listeners remain
optional and unchanged.

The runtime prepares both the UDP and TCP DNS sockets before publishing a new
configuration generation. The DNS task handles UDP datagrams and
length-prefixed TCP messages with bounded upstream deadlines. Its cache is
bounded to 256 positive entries, keys the upstream and query independently of
the client transaction ID, restores that ID on a hit, expires entries by the
minimum response TTL and ages record TTLs with the pinned Go rounding behavior.

`compat/scripts/phase4.py` runs the same fixture against Go and Rust with a
local authoritative server that speaks both UDP and TCP. The cross-product of
UDP/TCP client transport and UDP/TCP upstream transport passed. Compared fields
include configuration exit codes, process exit, upstream call counts, client
ID echo, flags including Go's local AA bit, question/answer counts, A record
type/class/address and first/cached TTL.

Observed Phase 4A result on 2026-08-25:

| Platform | Result | Environment |
| --- | --- | --- |
| Darwin arm64 | Passed | Native Go 1.26.5 and Rust 1.95.0; ephemeral loopback UDP/TCP only |

Phase 4A does not claim hosts/system-hosts, CNAME, redir-host tunnel mapping,
fake IP, IPv6 DNS, multiple or domain/system upstreams, SERVFAIL parity,
negative/stale/singleflight cache behavior, EDNS/truncation, resolver policy,
DNS REST APIs, DoH/DoT/DoQ or TUN hijack.

### Phase 4A exit-gate commands

```sh
python3 compat/scripts/phase4.py
python3 compat/scripts/phase3.py
python3 compat/scripts/phase2.py
python3 compat/scripts/phase1.py

cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features

cd ..
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./...
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./... -tags with_gvisor -count=1
CGO_ENABLED=0 go build -tags with_gvisor -trimpath -o /tmp/mihomo-go-oracle .
```

## Phase 4B deliverables and evidence

Phase 4B extends `rewrite-config` with an exact-name host table. Values may be
one IP, multiple IPv4/IPv6 addresses or one domain target; `localhost` mirrors
the pinned Go default, and domain-mapping cycles are rejected. The DNS service
can answer configured A/AAAA records directly with TTL 10, produce configured
CNAME responses, rewrite an A/AAAA question to an external CNAME terminal and
fall back to the native Unix host file when enabled.

`rewrite-state` now owns a 4096-entry TTL-bounded IP-to-domain map. Classic DNS
answers populate it, and the runtime consults it before TCP or UDP rule
evaluation. The declared live evidence is narrower: an authoritative local A
answer for a native non-loopback interface address is queried first, then a
SOCKS5 client connects using only that IP. Both Go and Rust recover the domain,
select `DOMAIN,mapped.phase4.test,DIRECT` and relay bytes through an
interface-local echo server.

`compat/scripts/phase4b.py` also compares configured A/AAAA and CNAME record
owners, types, classes, data and TTLs; verifies that configured answers avoid
the upstream; verifies that an external CNAME terminal is cached; exercises a
non-`localhost` `/etc/hosts` entry when available; and compares valid/cyclic
configuration exit codes.

Observed Phase 4B result on 2026-08-25:

| Platform | Result | Environment |
| --- | --- | --- |
| Darwin arm64 | Passed | Native Go 1.26.5 and Rust 1.95.0; local DNS, `/etc/hosts` and interface-local TCP only |

Phase 4B does not claim wildcard or `lan` hosts, IDNA, random multi-address
DIRECT selection, configured-host resolution inside DIRECT dialing, UDP mapping
parity, mapping persistence, broad system-host platforms, fake IP, resolver
policy, encrypted DNS, DNS REST or TUN hijack.

### Phase 4B exit-gate commands

```sh
python3 compat/scripts/phase4b.py
python3 compat/scripts/phase4.py
python3 compat/scripts/phase3.py
python3 compat/scripts/phase2.py
python3 compat/scripts/phase1.py

cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features

cd ..
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./...
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./... -tags with_gvisor -count=1
CGO_ENABLED=0 go build -tags with_gvisor -trimpath -o /tmp/mihomo-go-oracle .
```

## Phase 4C deliverables and evidence

Phase 4C extends executable DNS configuration with fake-IP mode, explicit
IPv4/IPv6 ranges, a configured TTL, exact-domain blacklist/whitelist filters
and `profile.store-fake-ip`. Pool allocation mirrors the pinned Go sequence:
each family begins at network address + 4, preserves case-insensitive domain
mappings, reserves the final range address and cyclically overwrites addresses
after wrap. Nonpersistent pools use the pinned 1000-entry LRU limit.

The TCP vertical slice shares the pool through `rewrite-state`. A DNS A query
allocates a fake address; a later SOCKS5 CONNECT that supplies only that address
recovers the domain before rule evaluation. After `DOMAIN,...,DIRECT` is
selected, `rewrite-dns` bypasses fake generation, performs both dual-stack
configured-upstream questions, chooses the usable IPv4 result and
relays the exact payload to an interface-local echo server.

When fake-IP profile storage is enabled, the Rust candidate persists both
mapping and allocation offset under its temporary candidate home. A graceful
stop and second process start retain the old address and allocate the next one,
matching the oracle observation. Rust uses candidate-local JSON sidecars while
Go uses bbolt `cache.db`; the file formats are deliberately not claimed as
interchangeable.

`compat/scripts/phase4c.py` additionally compares A/AAAA response flags,
owners, TTL and data; case-stable reuse; blacklist and whitelist upstream
bypass; a `/29` wrap; eviction after 1000 in-memory mappings; invalid range and
filter-mode configuration exit codes; configured upstream query multiset; process
exit codes; and restart behavior. The harness sets the pinned Go oracle's
`SKIP_SYSTEM_IPV6_CHECK=1` test escape hatch for both processes so the explicit
dual-stack fixture is deterministic on IPv4-only CI runners; this does not
normalize either implementation's DNS response.

Observed Phase 4C result on 2026-08-25:

| Platform | Result | Environment |
| --- | --- | --- |
| Darwin arm64 | Passed | Native Go 1.26.5 and Rust 1.95.0; local DNS, interface-local TCP and temporary homes only |

Phase 4C does not claim wildcard, rule or provider-backed fake-IP filters; UDP
fake-IP reverse routing; reload/prefix migration; REST cache flush/query APIs;
crash/corruption or Go-cache-file interoperability; nameserver policy,
fallback, encrypted DNS, TUN hijack or broader platforms.

### Phase 4C exit-gate commands

```sh
python3 compat/scripts/phase4c.py
python3 compat/scripts/phase4b.py
python3 compat/scripts/phase4.py
python3 compat/scripts/phase3.py
python3 compat/scripts/phase2.py
python3 compat/scripts/phase1.py

cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features

cd ..
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./...
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./... -tags with_gvisor -count=1
CGO_ENABLED=0 go build -tags with_gvisor -trimpath -o /tmp/mihomo-go-oracle .
```

## Phase 4D1 deliverables and evidence

Phase 4D1 extends `rewrite-config` with a deliberately narrow
`dns.nameserver-policy` surface: ASCII exact domains, whole-label `*` and a
leading `+.` suffix, with exactly one loopback IP-literal UDP or TCP upstream
per entry. It rejects malformed patterns and non-string policy values instead
of silently accepting a policy it cannot execute.

`rewrite-dns` selects the policy before every classic upstream exchange. Its
matching rank mirrors the declared Go trie behavior: static labels win over
`*`, which wins over the `+.` suffix fallback; `+.` covers both the root and
arbitrary subdomain depth, while `*` consumes one label. The positive cache key
contains the selected transport and address, preserving policy separation.

`compat/scripts/phase4d1.py` starts four local authorities with distinct A
answers. It compares main misses, suffix root/deep matches, one-label wildcard
matches, deep wildcard fallback to main, exact-over-suffix priority, UDP/TCP
transport received by each authority, cached policy response TTL/transaction
ID behavior, process exit and the declared configuration outcomes.

Observed Phase 4D1 result on 2026-08-25:

| Platform | Result | Environment |
| --- | --- | --- |
| Darwin arm64 | Passed | Native Go 1.26.5 and Rust 1.95.0; four loopback UDP/TCP authorities only |

Phase 4D1 does not claim multiple upstreams per policy, ambiguous patterns
whose result depends on YAML overwrite order, Unicode, geosite/rule-set policy
matchers, system/domain upstreams, fallback, proxy/direct DNS,
`respect-rules`, resolver failure/retry parity, DNS REST or encrypted DNS.

### Phase 4D1 exit-gate commands

```sh
python3 compat/scripts/phase4d1.py
python3 compat/scripts/phase4c.py
python3 compat/scripts/phase4b.py
python3 compat/scripts/phase4.py
python3 compat/scripts/phase3.py
python3 compat/scripts/phase2.py
python3 compat/scripts/phase1.py

cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features

cd ..
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./...
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./... -tags with_gvisor -count=1
CGO_ENABLED=0 go build -tags with_gvisor -trimpath -o /tmp/mihomo-go-oracle .
```

## Phase 4D2 deliverables and evidence

Phase 4D2 adds one deliberately bounded `dns.fallback` configuration to
`rewrite-config`: one loopback IP-literal UDP/TCP server,
`fallback-lazy-query`, ASCII domain filters, IP CIDR filters and an explicit
requirement that `fallback-filter.geoip` be `false`. GeoSite and multiple
fallback servers are rejected rather than accepted without implementation.

`rewrite-dns` first honors a matching Phase 4D1 nameserver policy. Without a
policy, a matching fallback domain queries fallback only. Other questions use
main; eager mode also starts fallback immediately, while lazy mode starts it
only if main has no address or an address falls inside the configured CIDR.
The final selected response is cached, and the cache identity includes the
main/fallback transport, addresses and filter settings.

`compat/scripts/phase4d2.py` runs fresh Go and Rust candidates in eager and
lazy modes against distinct local main, fallback and policy authorities. It
compares configuration exit codes, response flags/records, authority
transport/name/type logs, forced-domain fallback, safe-main selection,
IPv4-CIDR fallback, cache reuse, policy precedence and graceful exit. Exact
cached TTL rounding at a wall-clock second boundary is normalized only after
asserting it is positive and lower than the original TTL.

Observed Phase 4D2 result on 2026-08-25:

| Platform | Result | Environment |
| --- | --- | --- |
| Darwin arm64 | Passed | Native Go 1.26.5 and Rust 1.95.0; three loopback UDP/TCP authorities only |

Phase 4D2 does not claim multiple upstreams, GeoIP/GeoSite, IPv6 answer
filters, empty/error/timeout/retry ordering, general system/domain upstreams,
proxy/direct DNS, `respect-rules`, DNS REST or encrypted/intercepted DNS.

### Phase 4D2 exit-gate commands

```sh
python3 compat/scripts/phase4d2.py
python3 compat/scripts/phase4d1.py
python3 compat/scripts/phase4c.py
python3 compat/scripts/phase4b.py
python3 compat/scripts/phase4.py
python3 compat/scripts/phase3.py
python3 compat/scripts/phase2.py
python3 compat/scripts/phase1.py

cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features

cd ..
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./...
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./... -tags with_gvisor -count=1
CGO_ENABLED=0 go build -tags with_gvisor -trimpath -o /tmp/mihomo-go-oracle .
```

## Phase 4D3A deliverables and evidence

Phase 4D3A adds one loopback IP-literal `dns.direct-nameserver` and
`direct-nameserver-follow-policy` to the executable configuration. Matcher
evaluation now carries three internal states—matched, unmatched or destination
IP required—and exposes either a completed decision or a resolution request to
the runtime. Ordered domain rules therefore decide without DNS; destination
`IP-CIDR` requests resolution only when reached and needed; `no-resolve`
remains a non-querying fallthrough.

The TCP runtime resolves an IP needed for rule matching through the normal
main/policy/fallback resolver, then independently resolves a selected DIRECT
domain through the direct resolver. With follow-policy enabled, an existing
Phase 4D1 policy overrides the direct upstream just as it does in the pinned Go
resolver. DNS-disabled configurations retain the existing system-resolution
path.

`compat/scripts/phase4d3a.py` uses a mixed SOCKS listener, a local TCP echo
server and distinct main/direct/policy authorities. It proves that an earlier
domain REJECT and an IP-CIDR `no-resolve` case issue no DNS query; a matching
IP-CIDR asks main and then direct before relaying; a main-IP miss asks no direct
resolver; and follow-policy changes the second lookup from direct to policy.
It compares every authority's transport/name/type log, relay or close result,
configuration/process exit code and graceful shutdown.

Observed Phase 4D3A result on 2026-08-25:

| Platform | Result | Environment |
| --- | --- | --- |
| Darwin arm64 | Passed | Native Go 1.26.5 and Rust 1.95.0; loopback SOCKS/DNS/TCP only |

Phase 4D3A deliberately does not claim proxy-server nameserver behavior or
`respect-rules`: both require a remote proxy adapter to produce meaningful
end-to-end evidence, and remote protocols remain in Phase 6. UDP lazy rules,
IPv6, errors/retries/cache behavior, multiple direct upstreams, DNS REST and
encrypted/intercepted DNS are also outside this gate.

### Phase 4D3A exit-gate commands

```sh
python3 compat/scripts/phase4d3a.py
python3 compat/scripts/phase4d2.py
python3 compat/scripts/phase4d1.py
python3 compat/scripts/phase4c.py
python3 compat/scripts/phase4b.py
python3 compat/scripts/phase4.py
python3 compat/scripts/phase3.py
python3 compat/scripts/phase2.py
python3 compat/scripts/phase1.py

cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features

cd ..
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./...
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./... -tags with_gvisor -count=1
CGO_ENABLED=0 go build -tags with_gvisor -trimpath -o /tmp/mihomo-go-oracle .
```

## Phase 4D4 deliverables and evidence

Phase 4D4 introduces a runtime-owned `DnsService` shared by the local DNS
listener and controller. Its positive resolver cache therefore has one explicit
lifetime across both entry points and config generations. Controller queries
bypass hosts and fake-IP enhancement, matching the Go route's direct use of
`DefaultResolver`; this declared subset renders A, AAAA and CNAME records.

The authenticated controller now handles `GET /dns/query` with Go-compatible
success, invalid-type and DNS-disabled JSON, and `POST /cache/dns/flush` with a
204 empty response. The existing secret middleware applies before either
operation. Cache clearing affects the shared positive cache but does not claim
fake-IP pool or storage mutation.

`compat/scripts/phase4d4.py` runs enabled and disabled configurations against
the pinned Go binary and Rust candidate. It compares status, content type,
empty-body behavior, full parsed JSON, A/AAAA/CNAME wire-derived records,
authorization failures, authority question logs and process exit status. A
repeat REST query followed by a local UDP DNS query proves cross-entry-point
cache reuse; after the flush becomes observable, the next REST query must reach
the authority again. The only normalization is bounded positive TTL aging. A
100ms post-flush window accounts for the Go oracle's asynchronous `ClearCache`
goroutine without removing the required refetch side effect.

Observed Phase 4D4 result on 2026-08-25:

| Platform | Result | Environment |
| --- | --- | --- |
| Darwin arm64 | Passed | Native Go 1.26.5 and Rust 1.95.0; loopback HTTP/DNS only |

Phase 4D4 does not claim arbitrary DNS RR rendering, negative/stale cache
control, fake-IP flush, full route method/slash behavior, encrypted DNS or
storage APIs. Phase 4D3B remains deferred until a remote proxy adapter can
provide meaningful proxy-server and `respect-rules` evidence.

### Phase 4D4 exit-gate commands

```sh
python3 compat/scripts/phase4d4.py
python3 compat/scripts/phase4d3a.py
python3 compat/scripts/phase4d2.py
python3 compat/scripts/phase4d1.py
python3 compat/scripts/phase4c.py
python3 compat/scripts/phase4b.py
python3 compat/scripts/phase4.py
python3 compat/scripts/phase3.py
python3 compat/scripts/phase2.py
python3 compat/scripts/phase1.py

cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features

cd ..
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./...
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./... -tags with_gvisor -count=1
CGO_ENABLED=0 go build -tags with_gvisor -trimpath -o /tmp/mihomo-go-oracle .
```

## Phase 4E1 deliverables and evidence

Phase 4E1 adds one encrypted DNS transport without broadening resolver policy:
the sole main nameserver may use
`tls://127.0.0.1:PORT#skip-cert-verify=true&disable-reuse=true`. The config
parser rejects this transport on policy, fallback and direct nameservers and
requires both parameters, keeping the implementation boundary explicit.

`rewrite-dns` opens a fresh TCP connection, completes a rustls TLS handshake,
writes and reads the standard two-byte DNS/TCP length frame, validates the DNS
response and then uses the existing positive cache. The custom certificate
verifier skips chain, expiry and hostname checks only as requested by the
declared config; TLS 1.2/1.3 handshake signatures are still verified using the
ring provider. There is no plaintext fallback.

`compat/scripts/phase4e1.py` serves the repository's existing self-signed,
expired `example.org` test certificate over a loopback TLS-only authority.
Distinct UDP and TCP client names each cause exactly one TLS connection and
one framed upstream query, while the repeat query is served from cache. Config
and process exit codes, connection/query counts, response ID/flags/counts,
record fields, address and first/cached TTL are compared exactly.

Observed Phase 4E1 result on 2026-08-25:

| Platform | Result | Environment |
| --- | --- | --- |
| Darwin arm64 | Passed | Native Go 1.26.5, Rust 1.95.0 and Python TLS loopback authority |

Dependency review for this gate:

| Dependency | Resolved version | Purpose and coverage | Declared license | Evidence boundary |
| --- | --- | --- | --- | --- |
| `tokio-rustls` | 0.26.4 | Tokio async adapter for the rustls client stream | MIT OR Apache-2.0 | Project metadata points to the rustls-maintained repository; native evidence is Darwin arm64 only |
| `rustls` | 0.23.43 | TLS 1.2/1.3 client handshake and signature verification | Apache-2.0 OR ISC OR MIT | Ring provider selected explicitly; verified PKI behavior is not claimed |
| `ring` | 0.17.14 | Cryptographic provider used by rustls | Apache-2.0 AND ISC | Pulled through rustls with a locked checksum; release platform review remains required |
| `rustls-webpki` | 0.103.15 | Signature algorithm mapping/verification behind rustls | ISC | Transitive locked dependency; no independent PKI compatibility claim |

These licenses are recorded as compatible candidates for the GPL-3.0-only
workspace, but final distribution/legal review remains a Phase 9 gate. The
local crate manifests declare Rust 1.71 or earlier minimums and their upstream
repositories; this phase makes no broader maintenance or platform guarantee.

Verified certificate chains, hostname/SNI overrides, connection reuse,
handshake failure/retry parity, DoT on policy/fallback/direct resolvers, DoH,
DoQ and TUN interception remain unclaimed.

### Phase 4E1 exit-gate commands

```sh
python3 compat/scripts/phase4e1.py
python3 compat/scripts/phase4d4.py
python3 compat/scripts/phase4d3a.py
python3 compat/scripts/phase4d2.py
python3 compat/scripts/phase4d1.py
python3 compat/scripts/phase4c.py
python3 compat/scripts/phase4b.py
python3 compat/scripts/phase4.py
python3 compat/scripts/phase3.py
python3 compat/scripts/phase2.py
python3 compat/scripts/phase1.py

cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features

cd ..
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./...
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./... -tags with_gvisor -count=1
CGO_ENABLED=0 go build -tags with_gvisor -trimpath -o /tmp/mihomo-go-oracle .
```

## Phase 4E2 deliverables and evidence

Phase 4E2 adds verified DoT without enabling any other encrypted transport. The
sole main nameserver may use
`tls://127.0.0.1:PORT#name-cert-verify=dot.phase4.test&disable-reuse=true`, paired
with exactly one inline PEM root in the Go-compatible, intentionally misspelled
`tls.custom-certifactes` field. TLS remains rejected on policy, fallback and
direct nameservers.

`rewrite-config` carries the explicit verification name and root into the owned
DNS generation. `rewrite-dns` creates a fresh rustls client connection, sends
the verification name as SNI, validates the root chain, validity period and SAN,
then uses the existing two-byte framed exchange and positive cache. The cache
identity includes both name and root. A rejected TLS handshake is surfaced to
local UDP and TCP clients as the same transaction-ID-preserving SERVFAIL packet
as the pinned Go resolver.

`compat/scripts/phase4e2.py` uses repository-owned deterministic root, leaf and
key fixtures. Its valid-name case proves two unique queries create two accepted
TLS connections while repeats hit cache. Its wrong-name case proves neither
candidate accepts a TLS connection and both emit `8102` SERVFAIL responses with
zero answers. Config/process exit codes and the successful DNS record fields are
also compared exactly.

Observed Phase 4E2 result on 2026-08-25:

| Platform | Result | Environment |
| --- | --- | --- |
| Darwin arm64 | Passed | Native Go 1.26.5, Rust 1.95.0 and deterministic Python TLS loopback authority |

The Phase 4E1 TLS dependencies remain in use. This gate additionally introduces
`rustls-pemfile` 2.2.0 (Apache-2.0 OR ISC OR MIT) to decode the explicit PEM
root into rustls certificate objects. Final distribution/legal and broader
platform review remain Phase 9 requirements.

Root certificate paths, system roots, multiple custom roots, connection reuse,
retry/fallback ordering, encrypted policy/fallback/direct resolvers, DoH, DoQ
and TUN interception remain unclaimed.

### Phase 4E2 exit-gate commands

```sh
python3 compat/scripts/phase4e2.py
python3 compat/scripts/phase4e1.py
python3 compat/scripts/phase4d4.py
python3 compat/scripts/phase4d3a.py
python3 compat/scripts/phase4d2.py
python3 compat/scripts/phase4d1.py
python3 compat/scripts/phase4c.py
python3 compat/scripts/phase4b.py
python3 compat/scripts/phase4.py
python3 compat/scripts/phase3.py
python3 compat/scripts/phase2.py
python3 compat/scripts/phase1.py

cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features

cd ..
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./...
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./... -tags with_gvisor -count=1
CGO_ENABLED=0 go build -tags with_gvisor -trimpath -o /tmp/mihomo-go-oracle .
```

## Phase 4E3 deliverables and evidence

Phase 4E3 broadens the Phase 4E2 trust input from one to multiple inline PEM
roots while preserving the same verified, loopback, no-reuse main DoT boundary.
No transport or resolver-selection branch was added. The configuration parser
continues to reject non-PEM values; inspection of the pinned Go `AddCertificate`
path confirmed that `tls.custom-certifactes` values are certificate bytes, not
filesystem paths.

`compat/scripts/phase4e3.py` adds a deterministic decoy CA. It runs the issuing
root after and before that decoy and compares successful UDP/TCP responses,
accepted TLS connection/query counts and positive-cache hits. A decoy-only case
proves the server chain is rejected before the authority accepts a connection
and that both client transports receive the Go-compatible ID-preserving `8102`
SERVFAIL response.

Observed Phase 4E3 result on 2026-08-25:

| Platform | Result | Environment |
| --- | --- | --- |
| Darwin arm64 | Passed | Native Go 1.26.5, Rust 1.95.0 and deterministic issuing/decoy CA fixtures |

No new Rust dependency was introduced. System-root interaction, connection
reuse, retry/fallback ordering, encrypted policy/fallback/direct resolvers,
DoH, DoQ and TUN interception remain unclaimed.

### Phase 4E3 exit-gate commands

```sh
python3 compat/scripts/phase4e3.py
python3 compat/scripts/phase4e2.py
python3 compat/scripts/phase4e1.py
python3 compat/scripts/phase4d4.py
python3 compat/scripts/phase4d3a.py
python3 compat/scripts/phase4d2.py
python3 compat/scripts/phase4d1.py
python3 compat/scripts/phase4c.py
python3 compat/scripts/phase4b.py
python3 compat/scripts/phase4.py
python3 compat/scripts/phase3.py
python3 compat/scripts/phase2.py
python3 compat/scripts/phase1.py

cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features

cd ..
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./...
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./... -tags with_gvisor -count=1
CGO_ENABLED=0 go build -tags with_gvisor -trimpath -o /tmp/mihomo-go-oracle .
```

## Phase 4E4 deliverables and evidence

Phase 4E4 permits the verified main nameserver form
`tls://127.0.0.1:PORT#name-cert-verify=dot.phase4.test` without
`disable-reuse=true`. Insecure reusable TLS and encrypted policy, fallback and
direct nameservers remain rejected.

The shared `DnsService` owns a bounded eight-stream LIFO pool keyed by upstream
address, verification name and all trust roots. It removes old streams when
that identity changes and never holds the mutex during DNS/TLS I/O. Successful
streams return to the pool. Only failure on a reused stream permits one fresh
connect/exchange retry; failure on a newly established stream is returned.

`compat/scripts/phase4e4.py` proves two different UDP/TCP client misses share
one persistent TLS connection and a repeated name remains a resolver-cache hit.
A second authority closes each stream after its first response: both candidates
detect the stale pooled stream and complete the next miss over exactly one new
connection.

Observed Phase 4E4 result on 2026-08-25:

| Platform | Result | Environment |
| --- | --- | --- |
| Darwin arm64 | Passed | Native Go 1.26.5, Rust 1.95.0 and persistent/server-closed Python TLS authorities |

No new dependency was introduced. General concurrent pool ordering,
fresh-connection retry, pool behavior outside the shared DNS/controller
service, system trust, DoH, DoQ and TUN interception remain unclaimed.

### Phase 4E4 exit-gate commands

```sh
python3 compat/scripts/phase4e4.py
python3 compat/scripts/phase4e3.py
python3 compat/scripts/phase4e2.py
python3 compat/scripts/phase4e1.py
python3 compat/scripts/phase4d4.py
python3 compat/scripts/phase4d3a.py
python3 compat/scripts/phase4d2.py
python3 compat/scripts/phase4d1.py
python3 compat/scripts/phase4c.py
python3 compat/scripts/phase4b.py
python3 compat/scripts/phase4.py
python3 compat/scripts/phase3.py
python3 compat/scripts/phase2.py
python3 compat/scripts/phase1.py

cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features

cd ..
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./...
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./... -tags with_gvisor -count=1
CGO_ENABLED=0 go build -tags with_gvisor -trimpath -o /tmp/mihomo-go-oracle .
```

## Phase 4E5 deliverables and evidence

Phase 4E5 permits only
`https://127.0.0.1:PORT/dns-query#name-cert-verify=dot.phase4.test` as the main
nameserver, together with one or more inline `tls.custom-certifactes` roots.
The Rust configuration model records the loopback endpoint, explicit
verification name and `/dns-query` path without enabling HTTPS for policy,
fallback or direct resolvers.

For each cache miss, `rewrite-dns` copies the DNS request with ID zero, encodes
it as an unpadded base64url `dns=` parameter and sends an HTTP/1.1 GET with the
DNS media-type Accept header over a verified TLS connection. The bounded
response is read according to `Content-Length`; its zero DNS ID is checked and
the original local-client ID is restored before normal validation and positive
caching. Phase 4E5's one-miss evidence did not claim connection reuse; Phase
4E6 records that behavior separately.

`compat/scripts/phase4e5.py` observes the Go and Rust HTTPS wire requests at a
deterministic custom-CA authority. It proves the GET/path/query/header/body
contract, one upstream miss followed by a cross-transport cache hit, strict
wrong-name rejection before an accepted connection, local UDP/TCP SERVFAIL
parity, configuration validation and process exit behavior.

Observed Phase 4E5 result on 2026-08-25:

| Platform | Result | Environment |
| --- | --- | --- |
| Darwin arm64 | Passed | Native Go 1.26.5, Rust 1.95.0 and deterministic Python HTTP/1.1 TLS authority |

No new workspace dependency was introduced; the config and DNS crates use the
already locked `url` and `base64` workspace dependencies. System trust, DoH
connection reuse, HTTP/2/3, POST, redirects, arbitrary paths, general
retry/pool behavior, encrypted policy/fallback/direct resolvers, DoQ and TUN
interception remain unclaimed.

### Phase 4E5 exit-gate commands

```sh
python3 compat/scripts/phase4e5.py
python3 compat/scripts/phase4e4.py
python3 compat/scripts/phase4e3.py
python3 compat/scripts/phase4e2.py
python3 compat/scripts/phase4e1.py
python3 compat/scripts/phase4d4.py
python3 compat/scripts/phase4d3a.py
python3 compat/scripts/phase4d2.py
python3 compat/scripts/phase4d1.py
python3 compat/scripts/phase4c.py
python3 compat/scripts/phase4b.py
python3 compat/scripts/phase4.py
python3 compat/scripts/phase3.py
python3 compat/scripts/phase2.py
python3 compat/scripts/phase1.py

cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features

cd ..
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./...
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./... -tags with_gvisor -count=1
CGO_ENABLED=0 go build -tags with_gvisor -trimpath -o /tmp/mihomo-go-oracle .
```

## Phase 4E6 deliverables and evidence

Phase 4E6 keeps the Phase 4E5 configuration surface unchanged and adds only
HTTP/1.1 connection lifecycle behavior. Requests no longer ask the server to
close the connection. A reusable verified TLS stream returns to the existing
bounded eight-entry LIFO pool, whose identity now includes the DoH path in
addition to endpoint, verification name and all configured roots.

If an exchange on a pooled stream fails, that stream is discarded and exactly
one fresh connection/exchange is attempted. A failure on a fresh connection is
returned immediately. A successful response with `Connection: close` is
delivered but its stream is not pooled. The pool lock is held only while
selecting or returning a stream, never during TLS or HTTP I/O.

`compat/scripts/phase4e6.py` compares two deterministic authorities. A
persistent authority must observe two distinct misses on one connection and no
request for a repeated cached name. An authority that closes each connection
after its response must observe the same two successful requests over exactly
two connections. The suite also preserves the Phase 4E5 GET, path, zero-ID,
Accept header, empty body, response-ID and process/config contracts.

Observed Phase 4E6 result on 2026-08-25:

| Platform | Result | Environment |
| --- | --- | --- |
| Darwin arm64 | Passed | Native Go 1.26.5, Rust 1.95.0 and persistent/server-closed Python HTTP/1.1 TLS authorities |

No new dependency was introduced. Concurrent pool scheduling, HTTP/2/3
multiplexing, system trust, general timeout/retry behavior, redirects,
encrypted policy/fallback/direct resolvers, DoQ and TUN interception remain
unclaimed.

### Phase 4E6 exit-gate commands

```sh
python3 compat/scripts/phase4e6.py
python3 compat/scripts/phase4e5.py
python3 compat/scripts/phase4e4.py
python3 compat/scripts/phase4e3.py
python3 compat/scripts/phase4e2.py
python3 compat/scripts/phase4e1.py
python3 compat/scripts/phase4d4.py
python3 compat/scripts/phase4d3a.py
python3 compat/scripts/phase4d2.py
python3 compat/scripts/phase4d1.py
python3 compat/scripts/phase4c.py
python3 compat/scripts/phase4b.py
python3 compat/scripts/phase4.py
python3 compat/scripts/phase3.py
python3 compat/scripts/phase2.py
python3 compat/scripts/phase1.py

cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features

cd ..
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./...
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./... -tags with_gvisor -count=1
CGO_ENABLED=0 go build -tags with_gvisor -trimpath -o /tmp/mihomo-go-oracle .
```

## Phase 4E7 deliverables and evidence

Phase 4E7 changes only the HTTPS DoH path boundary. The parser now accepts a
non-root absolute path when every segment is non-empty and consists only of
ASCII alphanumeric bytes or `-._~`. It continues to require an explicit
loopback port, no URL query or userinfo, an explicit verification name and
inline custom roots. Root paths and empty/trailing segments remain outside the
declared subset; encoded unreserved bytes are isolated in Phase 4E8.

The accepted path is stored in `DnsTlsConfig`, emitted verbatim before the
generated `dns=` query parameter and included in cache and TLS-pool identities.
No HTTP transport, trust or resolver-selection branch changes in this gate.

`compat/scripts/phase4e7.py` compares three safe custom-path configuration
forms. Its runtime authority requires the exact `/custom/dns-query` request
path and observes one upstream miss followed by a cross-transport positive
cache hit, including upstream zero ID and local response-ID restoration.

The full regression also made two existing readiness boundaries explicit:
Phase 4B now waits until the already-returned DNS mapping is observable to the
proxy listener, and encrypted-DNS UDP clients allow an 11-second cold-start
window while leaving the candidate's own upstream timeout unchanged. Phase
4E6 normalizes only wall-clock-dependent cached TTL aging; exact TTL behavior
remains covered by Phase 4A.

Observed Phase 4E7 result on 2026-08-25:

| Platform | Result | Environment |
| --- | --- | --- |
| Darwin arm64 | Passed | Native Go 1.26.5, Rust 1.95.0 and deterministic custom-path Python HTTP/1.1 TLS authority |

No new dependency was introduced. URL queries, percent-encoded paths,
redirects, userinfo, non-loopback endpoints, system trust, HTTP/2/3, DoQ,
encrypted policy/fallback/direct resolvers and TUN interception remain
unclaimed.

### Phase 4E7 exit-gate commands

```sh
python3 compat/scripts/phase4e7.py
python3 compat/scripts/phase4e6.py
python3 compat/scripts/phase4e5.py
python3 compat/scripts/phase4e4.py
python3 compat/scripts/phase4e3.py
python3 compat/scripts/phase4e2.py
python3 compat/scripts/phase4e1.py
python3 compat/scripts/phase4d4.py
python3 compat/scripts/phase4d3a.py
python3 compat/scripts/phase4d2.py
python3 compat/scripts/phase4d1.py
python3 compat/scripts/phase4c.py
python3 compat/scripts/phase4b.py
python3 compat/scripts/phase4.py
python3 compat/scripts/phase3.py
python3 compat/scripts/phase2.py
python3 compat/scripts/phase1.py

cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features

cd ..
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./...
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./... -tags with_gvisor -count=1
CGO_ENABLED=0 go build -tags with_gvisor -trimpath -o /tmp/mihomo-go-oracle .
```

## Phase 4E8 deliverables and evidence

Phase 4E8 extends only the Phase 4E7 path parser. A valid percent triplet is
decoded when and only when its byte is RFC 3986 unreserved ASCII: alphanumeric
or `-._~`. The resulting canonical path is stored in `DnsTlsConfig`, used in
the HTTP request target and included in cache and connection-pool identities.

Encoded `/`, `%`, reserved or control bytes, malformed triplets and non-ASCII
path data remain rejected. URL queries, redirects, userinfo, trust behavior and
resolver selection are unchanged.

`compat/scripts/phase4e8.py` compares `%2D`, `%7E` and `%41` configuration
forms. Its deterministic authority proves that a configured
`/custom/dns%2Dquery` becomes the Go-compatible `/custom/dns-query?dns=...`
wire target, followed by the existing response-ID and cross-transport cache
observations. A focused Rust test proves encoded separators remain outside the
declared subset.

Observed Phase 4E8 result on 2026-08-25:

| Platform | Result | Environment |
| --- | --- | --- |
| Darwin arm64 | Passed | Native Go 1.26.5, Rust 1.95.0 and deterministic encoded-path Python HTTP/1.1 TLS authority |

No new dependency was introduced. Reserved/control encodings, general URL
canonicalization, URL queries, redirects, non-loopback endpoints, system
trust, HTTP/2/3, DoQ, encrypted policy/fallback/direct resolvers and TUN
interception remain unclaimed.

### Phase 4E8 exit-gate commands

```sh
python3 compat/scripts/phase4e8.py
python3 compat/scripts/phase4e7.py
python3 compat/scripts/phase4e6.py
python3 compat/scripts/phase4e5.py
python3 compat/scripts/phase4e4.py
python3 compat/scripts/phase4e3.py
python3 compat/scripts/phase4e2.py
python3 compat/scripts/phase4e1.py
python3 compat/scripts/phase4d4.py
python3 compat/scripts/phase4d3a.py
python3 compat/scripts/phase4d2.py
python3 compat/scripts/phase4d1.py
python3 compat/scripts/phase4c.py
python3 compat/scripts/phase4b.py
python3 compat/scripts/phase4.py
python3 compat/scripts/phase3.py
python3 compat/scripts/phase2.py
python3 compat/scripts/phase1.py

cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features

cd ..
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./...
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./... -tags with_gvisor -count=1
CGO_ENABLED=0 go build -tags with_gvisor -trimpath -o /tmp/mihomo-go-oracle .
```

## Phase 4E9 deliverables and evidence

Phase 4E9 extends only verified DoT main upstream addressing. A `tls://`
endpoint may now contain a normalized DNS hostname and may omit its port, in
which case both IP-literal and domain forms use Go's default port 853. A domain
endpoint requires exactly one explicit classic loopback UDP or TCP
`dns.default-nameserver`; system/bootstrap defaults and multiple bootstrap
servers remain outside the declared subset.

Before opening TLS, Rust sends one A query for the endpoint hostname through
that bootstrap server and connects the returned IPv4 address at the configured
or default DoT port. TLS continues to use `name-cert-verify` and the already
declared inline root. Endpoint hostname, port and bootstrap identity participate
in resolver-cache and TLS-pool identities.

`compat/scripts/phase4e9.py` compares domain/IP implicit-port configuration,
explicit domain ports and rejection of a non-IP bootstrap endpoint. Its runtime
fixture proves the exact bootstrap A question, verified TLS DNS framing, one
upstream miss, a cross-transport local cache hit with restored client ID and
clean process shutdown.

Observed Phase 4E9 result on 2026-08-25:

| Platform | Result | Environment |
| --- | --- | --- |
| Darwin arm64 | Passed | Native Go 1.26.5, Rust 1.95.0, deterministic loopback UDP bootstrap authority and verified DoT authority |

No new dependency was introduced. Bootstrap AAAA/multiple-address selection,
multiple/default/system/bootstrap transports, system trust, DoH domain
endpoints, fallback/policy/direct/proxy resolvers, `respect-rules`, DoQ and TUN
interception remain unclaimed.

### Phase 4E9 exit-gate commands

```sh
python3 compat/scripts/phase4e9.py
python3 compat/scripts/phase4e8.py
python3 compat/scripts/phase4e7.py
python3 compat/scripts/phase4e6.py
python3 compat/scripts/phase4e5.py
python3 compat/scripts/phase4e4.py
python3 compat/scripts/phase4e3.py
python3 compat/scripts/phase4e2.py
python3 compat/scripts/phase4e1.py
python3 compat/scripts/phase4d4.py
python3 compat/scripts/phase4d3a.py
python3 compat/scripts/phase4d2.py
python3 compat/scripts/phase4d1.py
python3 compat/scripts/phase4c.py
python3 compat/scripts/phase4b.py
python3 compat/scripts/phase4.py
python3 compat/scripts/phase3.py
python3 compat/scripts/phase2.py
python3 compat/scripts/phase1.py

cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features

cd ..
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./...
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./... -tags with_gvisor -count=1
CGO_ENABLED=0 go build -tags with_gvisor -trimpath -o /tmp/mihomo-go-oracle .
```

## Phase 4E10 deliverables and evidence

Phase 4E10 completes the declared IP-literal main-DoT trust and verification
matrix. Verified connections now compose the native platform certificate
store, the same embedded CA bundle used by Go and all inline global
`tls.custom-certifactes` roots. The Rust loader recognizes the same true forms
for `DISABLE_SYSTEM_CA` and `DISABLE_EMBED_CA` as Go's `strconv.ParseBool` use
in this path.

A DoT URL with no verification fragment now uses its endpoint host/IP as the
verification name. `name-cert-verify` replaces that name and, like the Go
`ca.GetTLSConfig` path, takes precedence over `skip-cert-verify` when both are
present. `skip-cert-verify=true` alone keeps handshake-signature validation but
skips chain, expiry and name checks. `disable-reuse=true` selects a fresh
connection; its absence enables the existing bounded LIFO behavior for both
verified and insecure DoT.

`compat/scripts/phase4e10.py` compares seven accepted configuration forms plus
an invalid scheme. Six deterministic runtime cases prove: rejection by the
default trust path of a local self-signed chain; rejection of a globally
trusted chain under the endpoint IP name; success with the global root plus
name override; insecure success with and without reuse; and name-override
precedence over skip by rejecting that same untrusted chain. The successful
misses also compare exact query/connection counts and clean shutdown.

Observed Phase 4E10 result on 2026-08-25:

| Platform | Result | Environment |
| --- | --- | --- |
| Darwin arm64 | Passed | Native Go 1.26.5, Rust 1.95.0, deterministic global CA/leaf and loopback persistent DoT authority |

All Phase 4E10 exit-gate commands listed below passed on 2026-08-25.

This gate adds direct dependency `rustls-native-certs` 0.8.4
(Apache-2.0 OR ISC OR MIT, Rust 1.71 minimum) for native platform root loading.
It is maintained in the rustls repository and uses Security Framework on this
Darwin evidence host; Linux/Windows platform loaders remain subject to native
acceptance gates. The repository's existing embedded Go CA bundle is compiled
into `rewrite-dns`, avoiding a public-network dependency. Final license and
distribution review remains Phase 9.

Cross-platform positive system-store acceptance, domain DoT skip verification,
custom trust paths (not a Go feature), 4E11 timeout/reset/concurrency/retry,
DoH trust combinations, DoQ, wrapper parameters, proxy resolver routing and
TUN interception remain unclaimed.

### Phase 4E10 exit-gate commands

```sh
python3 compat/scripts/phase4e10.py
python3 compat/scripts/phase4e9.py
python3 compat/scripts/phase4e8.py
python3 compat/scripts/phase4e7.py
python3 compat/scripts/phase4e6.py
python3 compat/scripts/phase4e5.py
python3 compat/scripts/phase4e4.py
python3 compat/scripts/phase4e3.py
python3 compat/scripts/phase4e2.py
python3 compat/scripts/phase4e1.py
python3 compat/scripts/phase4d4.py
python3 compat/scripts/phase4d3a.py
python3 compat/scripts/phase4d2.py
python3 compat/scripts/phase4d1.py
python3 compat/scripts/phase4c.py
python3 compat/scripts/phase4b.py
python3 compat/scripts/phase4.py
python3 compat/scripts/phase3.py
python3 compat/scripts/phase2.py
python3 compat/scripts/phase1.py

cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features

cd ..
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./...
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./... -tags with_gvisor -count=1
CGO_ENABLED=0 go build -tags with_gvisor -trimpath -o /tmp/mihomo-go-oracle .
```

## Phase 4E11 deliverables and evidence

Phase 4E11 closes the declared IP-literal main-DoT connection lifecycle gate.
The existing Rust pool already released its mutex before every connect and
exchange, capped idle TLS streams at eight, retried only after a failed reused
stream and applied a five-second response deadline. This phase adds the missing
reload behavior: every successfully published configuration generation drops
idle encrypted connections and changes the pool identity, preventing an
exchange that began before reload from returning its stream to the new pool.
Failed configuration reloads still leave the active generation and pool intact.

`compat/scripts/phase4e11.py` uses five local authority modes. A barrier holds
12 distinct concurrent misses until all TLS connections have sent a framed DNS
query, after which the idle pool converges to eight and a thirteenth query reuses
one. A silent authority proves the five-second response timeout. A fresh-close
authority proves no retry after a newly opened stream fails. A two-stage
authority proves one retry from a stale pooled stream followed by termination
when the fresh stream also fails. Finally, an unchanged valid config is applied
with SIGHUP; the existing persistent stream closes before the next distinct
query creates exactly one replacement.

Observed Phase 4E11 result on 2026-08-25:

| Platform | Result | Environment |
| --- | --- | --- |
| Darwin arm64 | Passed | Native Go 1.26.5, Rust 1.95.0, deterministic barrier/delayed/closing/persistent loopback DoT authorities |

All Phase 4E11 exit-gate commands listed below passed on 2026-08-25.

No new Rust dependency was introduced. Cancellation races at the exact timeout
boundary, domain/bootstrap concurrency, multiple DoT upstream selection,
DoH/DoQ pool behavior, proxy routing, wrapper parameters and TUN interception
remain unclaimed.

### Phase 4E11 exit-gate commands

```sh
python3 compat/scripts/phase4e11.py
python3 compat/scripts/phase4e10.py
python3 compat/scripts/phase4e9.py
python3 compat/scripts/phase4e8.py
python3 compat/scripts/phase4e7.py
python3 compat/scripts/phase4e6.py
python3 compat/scripts/phase4e5.py
python3 compat/scripts/phase4e4.py
python3 compat/scripts/phase4e3.py
python3 compat/scripts/phase4e2.py
python3 compat/scripts/phase4e1.py
python3 compat/scripts/phase4d4.py
python3 compat/scripts/phase4d3a.py
python3 compat/scripts/phase4d2.py
python3 compat/scripts/phase4d1.py
python3 compat/scripts/phase4c.py
python3 compat/scripts/phase4b.py
python3 compat/scripts/phase4.py
python3 compat/scripts/phase3.py
python3 compat/scripts/phase2.py
python3 compat/scripts/phase1.py

cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features

cd ..
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./...
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./... -tags with_gvisor -count=1
CGO_ENABLED=0 go build -tags with_gvisor -trimpath -o /tmp/mihomo-go-oracle .
```

## Phase 4E12 deliverables and evidence

Phase 4E12 adds the declared loopback plaintext HTTP/1.1 main-DoH slice. An
omitted port normalizes to 80. Empty and explicit root paths both produce `/`
on the wire, while `/dns-query` and the existing unreserved-path grammar remain
available with explicit ports. Query strings, fragments, userinfo and domain
hosts remain rejected by this Rust gate even where later Go behavior accepts
or transforms them.

The DNS service now owns a plaintext `TcpStream` pool separate from its rustls
stream pool. Both call the same HTTP message exchange so zero upstream DNS IDs,
base64url GET parameters, Accept headers, response validation, client-ID
restoration and connection-close handling cannot drift between HTTP and HTTPS.
Successful reload clears both pools. Cache and pool identities include the
effective transport, endpoint and canonical path.

`compat/scripts/phase4e12.py` compares five accepted URL forms and one rejected
scheme. Runtime authorities cover an omitted path, explicit `/` and
`/dns-query`. Each case observes two distinct UDP/TCP client misses on one
persistent upstream connection, exact HTTP request metadata and path, then a
cache hit with a third client ID.

Observed Phase 4E12 result on 2026-08-25:

| Platform | Result | Environment |
| --- | --- | --- |
| Darwin arm64 | Passed | Native Go 1.26.5, Rust 1.95.0 and deterministic persistent loopback plaintext HTTP/1.1 DoH authority |

All Phase 4E12 exit-gate commands listed below passed on 2026-08-25.

No new dependency was introduced. HTTPS root/query/userinfo/redirect behavior,
domain bootstrap and trust combinations, HTTP/2/3, broader DoH retry/pool
semantics, DoQ, proxy routing and wrapper parameters remain unclaimed.

### Phase 4E12 exit-gate commands

```sh
python3 compat/scripts/phase4e12.py
python3 compat/scripts/phase4e11.py
python3 compat/scripts/phase4e10.py
python3 compat/scripts/phase4e9.py
python3 compat/scripts/phase4e8.py
python3 compat/scripts/phase4e7.py
python3 compat/scripts/phase4e6.py
python3 compat/scripts/phase4e5.py
python3 compat/scripts/phase4e4.py
python3 compat/scripts/phase4e3.py
python3 compat/scripts/phase4e2.py
python3 compat/scripts/phase4e1.py
python3 compat/scripts/phase4d4.py
python3 compat/scripts/phase4d3a.py
python3 compat/scripts/phase4d2.py
python3 compat/scripts/phase4d1.py
python3 compat/scripts/phase4c.py
python3 compat/scripts/phase4b.py
python3 compat/scripts/phase4.py
python3 compat/scripts/phase3.py
python3 compat/scripts/phase2.py
python3 compat/scripts/phase1.py

cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features

cd ..
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./...
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./... -tags with_gvisor -count=1
CGO_ENABLED=0 go build -tags with_gvisor -trimpath -o /tmp/mihomo-go-oracle .
```

## Phase 4E13 deliverables and evidence

Phase 4E13 adds the declared loopback HTTPS URL-semantics slice. HTTPS URLs may
now omit the port (normalizing to 443) and use an empty or explicit root path.
As in the pinned Go oracle, a query present in the configured URL is discarded
and replaced on every request by the RFC 8484 `dns=` parameter. Plain ASCII URL
userinfo becomes an HTTP Basic Authorization header.

The shared HTTP/1.1 exchange follows status 301, 302, 303, 307 and 308 when the
Location is a same-origin absolute path and the current connection remains
reusable. Authorization is retained across that same-origin redirect. The
client sends at most ten requests in one redirect chain, matching Go's default
redirect limit. DoH cache and connection-pool identities now include Basic
credentials so a reload cannot reuse data or a stream across credential sets.

`compat/scripts/phase4e13.py` compares default-port root validation, explicit
root/query validation, ASCII userinfo and a custom path. It also records the
intentional scope boundary that Go accepts percent-encoded userinfo while this
Rust gate explicitly rejects it. Runtime cases prove root-path canonicalization,
configured-query clearing, Basic authentication, one-connection relative
redirect success, positive caching and an exact ten-request redirect loop
ending in SERVFAIL.

Observed Phase 4E13 result on 2026-08-26:

| Platform | Result | Environment |
| --- | --- | --- |
| Darwin arm64 | Passed | Native Go 1.26.5, Rust 1.95.0 and deterministic persistent loopback TLS HTTP/1.1 authority |

All Phase 4E13 exit-gate commands listed below passed across 2026-08-25 and
2026-08-26; the final differential suite and Rust quality gates were re-run on
2026-08-26. No Go source or Cargo dependency changed.

Encoded userinfo, absolute or cross-origin redirects, redirects that close the
current connection, chunked redirect bodies, domain-host HTTPS bootstrap and
trust combinations, HTTP/2/3, DoQ, proxy routing and wrapper parameters remain
unclaimed.

### Phase 4E13 exit-gate commands

```sh
python3 compat/scripts/phase4e13.py
python3 compat/scripts/phase4e12.py
python3 compat/scripts/phase4e11.py
python3 compat/scripts/phase4e10.py
python3 compat/scripts/phase4e9.py
python3 compat/scripts/phase4e8.py
python3 compat/scripts/phase4e7.py
python3 compat/scripts/phase4e6.py
python3 compat/scripts/phase4e5.py
python3 compat/scripts/phase4e4.py
python3 compat/scripts/phase4e3.py
python3 compat/scripts/phase4e2.py
python3 compat/scripts/phase4e1.py
python3 compat/scripts/phase4d4.py
python3 compat/scripts/phase4d3a.py
python3 compat/scripts/phase4d2.py
python3 compat/scripts/phase4d1.py
python3 compat/scripts/phase4c.py
python3 compat/scripts/phase4b.py
python3 compat/scripts/phase4.py
python3 compat/scripts/phase3.py
python3 compat/scripts/phase2.py
python3 compat/scripts/phase1.py

cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features

cd ..
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./...
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./... -tags with_gvisor -count=1
CGO_ENABLED=0 go build -tags with_gvisor -trimpath -o /tmp/mihomo-go-oracle .
```

## Phase 4E14 deliverables and evidence

Phase 4E14 adds the declared domain-host HTTPS DoH slice. One classic loopback
UDP `dns.default-nameserver` resolves the URL domain with an A query before the
TLS connection is opened to the returned address. The URL domain and configured
port remain the HTTP Host authority and the URL domain remains TLS SNI; neither
is replaced by the bootstrap result.

TLS endpoint identity and certificate verification identity are now separate
configuration values. The standard case verifies the certificate against the
URL domain. `name-cert-verify` changes only the verification identity while SNI
and Host retain the URL domain. `skip-cert-verify=true` disables chain/name
verification only when no non-empty name override is present, matching the Go
precedence. Pool and cache identities include SNI, verification name and the
skip-verification state.

`compat/scripts/phase4e14.py` compares domain default/explicit ports, default
verification, name override, skip verification, an IP-literal boundary and an
invalid domain bootstrap. Runtime authorities cover trusted default-name
success, default-trust untrusted failure, trusted name mismatch, trusted name
override, untrusted skip success and name-override precedence over skip. Every
case records the bootstrap question, TLS SNI, successful connection count, HTTP
Host/path, DNS wire result and positive-cache behavior.

Observed Phase 4E14 result on 2026-08-26:

| Platform | Result | Environment |
| --- | --- | --- |
| Darwin arm64 | Passed | Native Go 1.26.5, Rust 1.95.0, deterministic loopback UDP bootstrap and TLS HTTP/1.1 DoH authorities |

All Phase 4E14 exit-gate commands listed below passed on 2026-08-26. No Go
source or Cargo dependency changed.

Multiple or system bootstrap resolvers, bootstrap AAAA/IPv6 endpoint selection,
positive public system-store fixtures, encoded userinfo, broader redirect
forms, HTTP/2/3, DoQ, proxy routing and wrapper parameters remain unclaimed.

### Phase 4E14 exit-gate commands

```sh
python3 compat/scripts/phase4e14.py
python3 compat/scripts/phase4e13.py
python3 compat/scripts/phase4e12.py
python3 compat/scripts/phase4e11.py
python3 compat/scripts/phase4e10.py
python3 compat/scripts/phase4e9.py
python3 compat/scripts/phase4e8.py
python3 compat/scripts/phase4e7.py
python3 compat/scripts/phase4e6.py
python3 compat/scripts/phase4e5.py
python3 compat/scripts/phase4e4.py
python3 compat/scripts/phase4e3.py
python3 compat/scripts/phase4e2.py
python3 compat/scripts/phase4e1.py
python3 compat/scripts/phase4d4.py
python3 compat/scripts/phase4d3a.py
python3 compat/scripts/phase4d2.py
python3 compat/scripts/phase4d1.py
python3 compat/scripts/phase4c.py
python3 compat/scripts/phase4b.py
python3 compat/scripts/phase4.py
python3 compat/scripts/phase3.py
python3 compat/scripts/phase2.py
python3 compat/scripts/phase1.py

cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features

cd ..
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./...
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./... -tags with_gvisor -count=1
CGO_ENABLED=0 go build -tags with_gvisor -trimpath -o /tmp/mihomo-go-oracle .
```

## Phase 4E15 deliverables and evidence

Phase 4E15 adds the declared HTTPS DoH HTTP/2 slice. The Rust HTTPS client now
offers ALPN protocols in Go order, `h2` followed by `http/1.1`. An `h2`
selection performs the client preface/SETTINGS handshake and sends the existing
RFC 8484 GET as one bodyless stream; an `http/1.1` selection continues through
the previously accepted persistent-connection implementation.

The HTTP/2 request uses `https` scheme and the configured URL authority, keeps
only the `dns` query parameter, sends `accept: application/dns-message`, clears
the upstream DNS ID and restores the client ID after a successful response.
The bounded TLS pool retains one cloneable HTTP/2 request sender per transport
identity, so two sequential cache misses share one connection while a repeated
name remains a DNS cache hit. A failed pooled sender is discarded before one
fresh connection attempt.

`compat/scripts/phase4e15.py` runs the pinned Go oracle and Rust candidate
against a deterministic loopback, TLS, HTTP/2-only authority implemented by
`rewrite-h2-authority`. The authority records ALPN, SNI, connection count,
HTTP/2 pseudo-header semantics, media header, empty request body and zero DNS
ID. The differential case sends distinct UDP and TCP client queries followed by
a cached repeat, proving two streams on one connection and response-ID
restoration. A separate HTTP/1.1-only TLS authority proves negotiated fallback
without broadening redirect behavior.

Observed Phase 4E15 result on 2026-08-26:

| Platform | Result | Environment |
| --- | --- | --- |
| Darwin arm64 | Passed | Native Go 1.26.5, Rust 1.95.0 and deterministic loopback TLS HTTP/2/HTTP/1.1 authorities |
| Linux amd64 | Passed | GitHub Actions run `32923792731`; complete Phase 1–4E15 differential regression with Go 1.26.5 and Rust 1.95.0 |

Dependency review for this gate:

| Dependency | Resolved version | Purpose and coverage | Declared license | Evidence boundary |
| --- | --- | --- | --- | --- |
| `h2` | 0.4.19 | HTTP/2 client connection/stream state machine and local test authority | MIT | Sequential GET streams and one connection only; no concurrency, GOAWAY or flow-control stress claim |
| `http` | 1.5.0 | Typed request, URI, header, status and response values used by `h2` | MIT OR Apache-2.0 | HTTP/2 DoH request/response construction only |
| `bytes` | 1.12.1 | Bounded HTTP/2 DATA payloads | MIT | DNS messages remain capped by the existing maximum message size |

The versions and checksums are locked in `rust/Cargo.lock`. These licenses are
recorded as compatible candidates for the GPL-3.0-only workspace, but final
distribution/legal review remains a Phase 9 gate. The crates are maintained in
the Tokio/hyper ecosystem; this phase records resolved metadata and passing
native evidence, not a broader maintenance or platform guarantee.

All Phase 1–4E15 differential suites passed on Darwin arm64 and in the default
Linux amd64 GitHub Actions regression on 2026-08-26. The exit-gate commands
below also passed. Phase 1 was rerun successfully after one isolated Go `-t` process
exceeded its five-second harness deadline while separate Cargo targets were
still compiling. No Go source was modified.

Concurrent HTTP/2 streams, redirects after HTTP/2 selection, non-200 response
handling parity, GOAWAY and retry matrices, connection flow-control stress,
ping/idle lifecycle, HTTP/3 and 0-RTT, DoQ, proxy routing and encrypted-upstream
wrapper parameters remain unclaimed.

### Phase 4E15 exit-gate commands

```sh
python3 compat/scripts/phase4e15.py
python3 compat/scripts/phase4e14.py
python3 compat/scripts/phase4e13.py
python3 compat/scripts/phase4e12.py
python3 compat/scripts/phase4e11.py
python3 compat/scripts/phase4e10.py
python3 compat/scripts/phase4e9.py
python3 compat/scripts/phase4e8.py
python3 compat/scripts/phase4e7.py
python3 compat/scripts/phase4e6.py
python3 compat/scripts/phase4e5.py
python3 compat/scripts/phase4e4.py
python3 compat/scripts/phase4e3.py
python3 compat/scripts/phase4e2.py
python3 compat/scripts/phase4e1.py
python3 compat/scripts/phase4d4.py
python3 compat/scripts/phase4d3a.py
python3 compat/scripts/phase4d2.py
python3 compat/scripts/phase4d1.py
python3 compat/scripts/phase4c.py
python3 compat/scripts/phase4b.py
python3 compat/scripts/phase4.py
python3 compat/scripts/phase3.py
python3 compat/scripts/phase2.py
python3 compat/scripts/phase1.py

cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features

cd ..
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./...
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./... -tags with_gvisor -count=1
CGO_ENABLED=0 go build -tags with_gvisor -trimpath -o /tmp/mihomo-go-oracle .
```

## Reproducible baseline

Observed toolchain on the phase 0 development host:

```text
OS/architecture: darwin/arm64
Go:             go1.26.5
Rust:           rustc 1.95.0
Cargo:          cargo 1.95.0
```

### Default Go tests

Command:

```sh
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./...
```

Result on 2026-08-21: **passed** (exit 0).

### `with_gvisor` Go tests

Command:

```sh
SKIP_INTEROP_TEST=1 SKIP_CONCURRENT_TEST=1 go test ./... -tags with_gvisor -count=1
```

Result on 2026-08-21: **passed** (exit 0).

### `with_gvisor` oracle build

Command:

```sh
CGO_ENABLED=0 go build -tags with_gvisor -trimpath -o /tmp/mihomo-phase0-go .
```

Result on 2026-08-21: **passed** (exit 0), artifact kept outside the repository.

The skip variables match the repository CI's treatment of costly inbound
interop/concurrency cases. They do not prove the skipped cases. The full
unskipped interop and stress suites remain required at protocol/release gates.

## Decisions recorded in phase 0

1. The Go implementation is an executable oracle, not source material to be
   removed as files are ported.
2. Compatibility is measured at process, config, API and wire boundaries with
   semantic differential tests.
3. The first Rust implementation is a narrow TCP-only vertical slice:
   minimal YAML -> mixed HTTP/SOCKS -> `MATCH,DIRECT` -> TCP relay.
4. UDP, DNS, TUN, REST mutation, remote protocols and broad platform support are
   explicitly outside phase 1.
5. Rust code will use owned runtime generations and isolate platform I/O rather
   than reproduce Go package globals.
6. The Cargo workspace is not scaffolded until phase 1, so its boundaries can be
   validated by a real slice instead of empty speculative crates.
7. Binary and crate names remain unresolved pending review of the GPL-3.0
   distribution obligations and the additional downstream naming condition in
   the existing README.

## Open decisions before release, not blockers for later phases

- Final product/binary/crate name.
- Minimum supported release platforms and architectures versus build-only
  targets.
- Protocol priority after the local core and DNS phases.
- Whether deliberate fixes for known Go behavior are allowed, and the approval
  process for marking documented deviations.
- Maximum acceptable upstream `Alpha` drift at each phase/release gate.

## Phase boundary

Rust behavior stops at the Phase 4E15 DoH HTTP/2 boundary. Phase 4D3B, 4E16 or
another implementation gate must not begin without a separate instruction and
the exact inventory IDs/matrix rows. HTTP/3 and 0-RTT, broader HTTP/2 lifecycle,
general encrypted-DNS pool/retry behavior, concurrent DoH scheduling, DoQ,
arbitrary RR/cache control, proxy-server nameservers, `respect-rules`,
intercepted DNS, TUN, remote proxy protocols, providers and broader
REST/platform compatibility are planned but not implied by this status.
