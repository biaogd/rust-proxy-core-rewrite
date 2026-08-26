# Rust rewrite roadmap and differential test plan

## Delivery rule

The rewrite proceeds as a sequence of independently runnable vertical slices.
Each phase must name its compatibility-matrix rows, preserve the Go oracle, add
deterministic tests, pass all required checks, and leave unsupported behavior
explicit. A phase is complete only when its exit gate passes.

## Phase 0 — baseline and governance

Deliverables:

- pin the Go oracle at
  `c0e43ebecf3be9b223f1015c1fc38689bb073467`;
- map startup, configuration/reload, listener, DNS, tunnel, rules, adapters,
  transports, controller and platform boundaries;
- establish this roadmap, the compatibility matrix, status ledger and upstream
  sync process;
- establish repository-wide agent instructions;
- verify the reproducible Go test/build commands;
- design, but do not yet populate, the Cargo workspace.

Exit gate: all documents exist and agree on the baseline; existing Go source is
unchanged; default and `with_gvisor` baseline commands are recorded with honest
results. No Rust compatibility claim is allowed in this phase.

## Phase 0B — exhaustive Go capability census

Before adding another Rust feature, inventory the pinned Go oracle by stable
product capability rather than by Go package. The authoritative census is
`go-capability-inventory.md`; every item has an ID, a Go discovery anchor, a
current Rust state and a planned acceptance gate.

Exit gate:

- CLI/process, configuration, inbound, rules/routing, outbound/transport,
  groups/providers, DNS, runtime, REST, supporting service and platform/build
  surfaces are all represented;
- previously aggregated omissions such as DNS RCODE/Tailscale upstreams and
  JLS/ReSTLS/ShadowTLS/TLSMirror/mKCP/Mekya transport boundaries are named;
- every future phase must name inventory IDs and compatibility-matrix rows;
- the baseline remains unchanged and no new Rust product behavior is added.

## Black-box differential test architecture

### Principle

The harness runs one scenario twice: once against the pinned Go binary and once
against the Rust candidate. Scenario input is identical after placeholders are
resolved. The harness captures each result into a structured observation,
normalizes only declared nondeterminism, and compares semantic fields.

```text
fixture + local dependencies
        |
        +-------------------+
        |                   |
        v                   v
   Go oracle run       Rust candidate run
        |                   |
        v                   v
 structured capture    structured capture
        |                   |
        +--------+----------+
                 v
        declared normalization
                 |
                 v
       semantic diff + artifacts
```

### Proposed repository layout

The layout is introduced only when the first executable harness is built:

```text
compat/
  README.md                 harness usage and normalization policy
  fixtures/
    cli/                    config-test/version cases
    config/                 valid and invalid YAML corpus
    rules/                  metadata and expected selection cases
    rest/                   method/request/response scenarios
    network/                HTTP/SOCKS/DNS/protocol scenarios
  certs/                    committed test-only CA/server/client material
  scenarios/                declarative scenario definitions
  snapshots/go/<baseline>/  captured stable oracle observations
  scripts/                  orchestration entry points

rust/crates/test-support/   local echo/DNS/TLS servers and Rust-side helpers
target/compat/              transient logs, packet captures and diffs
```

Oracle snapshots are review aids, not a substitute for running the oracle. Any
snapshot update must state the old and new Go baseline and explain the semantic
change.

### Build and launch contract

- Build the Go oracle from the exact baseline into an out-of-tree path such as
  `/tmp/mihomo-go-oracle`; never rely on an unrelated installed binary.
- Build the Rust candidate from the current worktree.
- Give each process a fresh temporary home, fixed environment and local-only
  dependencies.
- Allocate ports through the harness and render them into a config template.
  Do not let the two runs overlap or reuse persisted state.
- Wait for an observable readiness event (listener connection or controller
  response), not a fixed sleep.
- Enforce startup, request, idle and shutdown deadlines. Always collect process
  output and kill only the exact child process group on timeout.
- Deny public network access in deterministic suites. Protocol suites use local
  reference servers or pinned containers/binaries.

### Observation schema

Every scenario records the applicable fields:

| Field | Examples |
| --- | --- |
| Process | exit code/signal, readiness, shutdown duration |
| Output | stdout, stderr, ordered normalized log events |
| Configuration | accepted/rejected, error class/path, normalized effective values |
| HTTP/REST | method, status, selected headers, canonical JSON/body |
| Stream | bytes in each direction, EOF/half-close/reset, selected target |
| Datagram | payload, source/destination, write-back address, timeout/drop |
| DNS | header flags, question/answers, TTL policy, EDNS0, truncation, rcode |
| State | connections, rule statistics, cache/profile/storage changes |
| Timing | only threshold classes where timing is part of behavior |

### Allowed normalization

- RFC3339/log timestamps;
- elapsed durations where no threshold behavior is under test;
- UUIDs and generated connection IDs, with stable within-run aliases;
- ephemeral ports and temporary directory prefixes;
- JSON object key order;
- platform-specific error text only after mapping it to a documented error
  class. The presence, operation and destination of an error remain semantic.

Disallowed normalization includes missing records, reordered rule decisions,
different status codes, extra accepted configuration, changed close behavior,
wire-byte changes and any dropped semantic JSON field.

### Test layers

1. **Golden parser tests:** run CLI/config/rule inputs and compare exit/error and
   normalized output.
2. **Local black-box tests:** launch full binaries against local echo, HTTP,
   DNS, TLS and failure servers.
3. **Protocol interop tests:** candidate client with Go/reference server and
   candidate server with Go/reference client; compare negotiated features and
   payloads.
4. **Platform integration tests:** isolated Linux namespaces/TUN/iptables,
   Windows named pipes and per-OS process lookup.
5. **Stress/property tests:** fragmentation, concurrency, cancellation,
   fuzzed parser input, long-lived connections and bounded-resource checks.
6. **Performance gates:** only after semantic parity; record throughput,
   latency distribution, allocations/RSS and connection counts.

### Failure artifacts

On mismatch, retain the rendered config, command/environment allowlist,
normalized and raw output, request/response data, random seed, platform/build
profile, exact Go/Rust commits and a minimal semantic diff. Secrets from user
configs must never enter fixtures or artifacts.

## Phase 1 — first executable vertical slice

Goal:

```text
minimal YAML
  -> mixed TCP listener
  -> HTTP or SOCKS5 request decoding
  -> metadata
  -> Rule mode: MATCH,DIRECT
  -> DIRECT TCP dial
  -> bidirectional relay
```

This slice establishes the Cargo workspace, async runtime conventions, owned
configuration/runtime boundaries and the differential harness. It must not add
UDP, TUN, DNS, remote proxy protocols, providers or broad REST compatibility.

### Minimal configuration fixture

The harness renders `${MIXED_PORT}` into:

```yaml
mixed-port: ${MIXED_PORT}
mode: rule
log-level: info
ipv6: false
rules:
  - MATCH,DIRECT
```

The first slice may parse additional defaults needed to represent this file,
but must reject or report unsupported runtime features rather than silently
ignore them.

### Phase 1 scenarios

1. `-t` accepts the minimal fixture and rejects malformed YAML, invalid mode,
   malformed MATCH rules and invalid ports consistently with the Go oracle.
2. Mixed-port protocol detection preserves peeked bytes.
3. HTTP absolute-form proxying reaches a local HTTP origin and preserves
   method, path, body and essential headers.
4. HTTP CONNECT reaches a local TCP echo/TLS fixture and relays arbitrary binary
   data in both directions.
5. SOCKS5 no-auth CONNECT works for IPv4, IPv6 where available, and domain
   destinations; unsupported authentication methods have oracle-compatible
   replies.
6. `MATCH,DIRECT` is the selected routing decision and DIRECT dial failures are
   observable with the correct connection closure/error class.
7. Client and remote half-close, early disconnect, idle timeout and SIGTERM
   cleanup do not leak tasks or sockets.
8. At least one fragmented request case validates buffered parsing.

### Phase 1 exit gate

- All phase 1 matrix rows are Parity for Darwin arm64 and Linux amd64.
- `cargo fmt --all --check`, strict Clippy and workspace tests pass.
- The Go baseline checks still pass.
- Differential artifacts are empty on success and actionable on failure.
- Unsupported features remain Not started in the matrix and are not advertised.

## Phase 2 — configuration model and pure rule core

- Expand default-overlay, error and normalized configuration coverage without
  instantiating every protocol.
- Port metadata types and pure rule families: MATCH, domain, IP, port, network
  and Boolean logic.
- Add PASS, REMATCH and sub-rule semantics with cycle tests.
- Separate parsing/specification from runtime resource construction.
- Add property/fuzz tests that compare Go and Rust parser/matcher observations.

Exit gate: declared config/rule rows have differential parity without public
network or platform privileges.

## Phase 3 — core local proxy product

Phase 3 is delivered through ordered gates so unrelated runtime concerns are
not migrated in one change:

1. **Phase 3A — authenticated local TCP:** fixed HTTP/SOCKS ports plus mixed,
   HTTP Basic and SOCKS username/password authentication, SOCKS4/4a/5 CONNECT,
   DIRECT/REJECT selection and connection lifecycle parity.
2. **Phase 3B — observability:** connection tracking and essential controller
   read APIs (`/version`, `/configs`, `/connections`, `/traffic`, `/logs`).
3. **Phase 3C — generations:** transactional listener generations and
   controller-independent SIGHUP reload, including failed-reload rollback.
4. **Phase 3D — local UDP:** SOCKS UDP and the UDP NAT/write-back core. This gate
   cannot begin until the Phase 3A TCP lifecycle matrix is Parity.

Each gate has its own differential exit evidence. Passing Phase 3A does not
authorize a controller, reload or UDP compatibility claim.

## Phase 4 — DNS and host mapping

Phase 4 is delivered through ordered DNS-specific gates. Evidence from one gate
must not be used to claim a later resolver or mapping behavior:

1. **Phase 4A — classic local DNS:** explicit loopback DNS configuration,
   UDP/TCP listeners, one deterministic IP-literal UDP or TCP upstream, and a
   bounded positive-response TTL cache. Raw message semantics, client IDs,
   upstream transport, cache hits and TCP framing are differential-test gates.
2. **Phase 4B — hosts and mapping:** three ordered sub-gates cover exact-name
   configured A/AAAA hosts, configured CNAME handling (including an upstream
   terminal), then optional local system-host lookup and TTL-bounded redir-host
   reverse mapping before proxy rule selection. Wildcard hosts, `lan`, broad
   cross-platform host-file discovery and fake IP remain outside this gate.
3. **Phase 4C — fake IP:** three independently checked sub-gates cover
   deterministic IPv4/IPv6 pool allocation and domain-filter bypass; fake-IP
   reverse lookup before TCP rule evaluation followed by a real configured
   upstream resolution for DIRECT; then bounded in-memory eviction and
   profile-backed allocation/mapping recovery across a graceful restart.
   Domain `blacklist`/`whitelist` filters are in scope. Rule-provider filters,
   UDP fake-IP reverse routing and the cache-flush REST endpoint remain later
   gates.
4. **Phase 4D — resolver policy and control:** separate acceptance gates are
   required: **4D1** simple exact/`*`/`+` domain `nameserver-policy` selection
   between deterministic local classic upstreams; **4D2** main/fallback answer
   filtering and lazy fallback; **4D3A** direct DNS routing plus lazy
   destination-IP rule resolution; **4D3B** proxy-server DNS routing and
   `respect-rules` once a remote proxy adapter exists; **4D4** authenticated
   local A/AAAA/CNAME query and shared positive-cache flush REST APIs. Full RR,
   negative/stale cache and fake-IP cache control remain separate later claims.
   Evidence from one gate does not imply any later gate, and 4D3A does not
   authorize pulling a remote proxy protocol forward from Phase 6.
5. **Phase 4E — encrypted and intercepted DNS:** **4E1** is a single loopback
   DoT main-upstream gate with explicit `skip-cert-verify` and no reuse. **4E2**
   adds exactly one inline custom root, explicit `name-cert-verify`, strict
   chain/name validation and wrong-name SERVFAIL parity. **4E3** accepts multiple
   inline custom roots and verifies issuing-root selection independently of list
   order, including untrusted-chain SERVFAIL. **4E4** adds bounded LIFO reuse for
   the verified main DoT transport and exactly one reconnect when a reused
   connection is stale. **4E5** adds one loopback HTTPS DoH main upstream using
   RFC 8484 GET over HTTP/1.1, a zero-ID base64url query, one inline custom root,
   explicit name validation, response-ID restoration and positive-cache
   evidence. **4E6** adds bounded HTTP/1.1 connection reuse across distinct
   misses and recovery when a pooled connection was closed by the server.
   **4E7** permits one custom non-root absolute URL path and compares its exact
   HTTP request target without enabling URL queries or redirects. **4E8**
   permits percent encodings only when they represent RFC 3986 unreserved path
   bytes and verifies Go-compatible decoding in the on-wire target. General
   retry/pool behavior, concurrent DoH scheduling,
   HTTP/2, HTTP/3 and DoQ remain separate transport gates. To cover the pinned Go
   oracle, continue with independently accepted slices: **4E9** domain/default-
   port DoT plus default-resolver bootstrap; **4E10** system/global trust and
   the complete DoT verification-option matrix; **4E11** DoT concurrency,
   timeout, reset and broader retry behavior; **4E12** plaintext HTTP DoH and
   default URL forms; **4E13** HTTPS URL root/query/userinfo/redirect behavior;
   **4E14** domain-host HTTPS bootstrap and trust combinations; **4E15** DoH
   HTTP/2; **4E16** forced/preferred/raced HTTP/3, fallback and 0-RTT; **4E17**
   verified DoQ framing; **4E18** DoQ reuse, streams, retry, token/reset and
   concurrency; and **4E19** encrypted-upstream wrapper parameters such as ECS
   and disabled query types. Proxy routing and `respect-rules` remain 4D3B
   because their vertical result depends on a remote adapter. Custom trust
   certificate paths are not a Go feature. TUN DNS hijack remains a separate
   privileged gate.

   Phase 4E10 acceptance is limited to IP-literal main DoT trust and
   verification-option behavior. Phase 4E11 then accepts only DoT concurrency,
   timeout, reset and bounded retry; it does not consume any DoH or DoQ
   lifecycle gate. Phase 4E12 accepts only loopback plaintext HTTP/1.1 DoH and
   default URL forms. Phase 4E13 accepts loopback HTTPS root/default-port URL
   validation, configured-query clearing, ASCII Basic userinfo and persistent
   same-origin relative redirects with the Go ten-request limit. Domain HTTPS,
   encoded credentials, absolute/cross-origin or connection-closing redirects
   and DoQ remain later gates. Phase 4E14 accepts one domain-host HTTPS
   main upstream bootstrapped by one classic loopback A resolver, with distinct
   URL-domain Host/SNI and certificate-name override semantics plus the
   default/name-override/skip trust precedence. Multiple/system bootstrap and
   broader domain/IPv6 combinations remain later gates. Phase 4E15
   accepts HTTPS DoH negotiation with ALPN preference `h2`, then `http/1.1`,
   RFC 8484 GET pseudo/header semantics, zero upstream DNS IDs, response-ID
   restoration, two sequential misses as streams on one HTTP/2 connection and
   deterministic HTTP/1.1 fallback. Concurrent streams, redirects after HTTP/2
   selection, GOAWAY/retry and flow-control stress remain later gates. Phase
   4E16 accepts `#h3=true` forced HTTP/3 and `dns.prefer-h3: true` raced
   selection. The race is accepted against a deterministic H3-faster dual
   authority and an H2-only fallback authority. The selected HTTP/3 path must
   preserve the RFC 8484 GET contract, reuse a live QUIC connection for
   sequential misses and recover after the authority closes the first
   connection. The pinned Go oracle constructs its TLS config without a client
   session cache, so reconnect requests are 0-RTT-capable in method
   classification but the authority observes `Used0RTT=false`; Rust must match
   that observable result and must not claim accepted 0-RTT. QUIC token and
   rejection matrices, accepted resumption, concurrent streams,
   flow-control/GOAWAY behavior and proxy routing remain later gates. Phase
   4E17 accepts one explicit-port loopback `quic://` main upstream with one
   inline custom root and an explicit certificate-name override. It verifies
   ALPN `doq`, one bidirectional QUIC stream, the two-octet request and response
   length fields, zero upstream DNS ID, request FIN, response-ID restoration,
   wrong-name rejection and zero-length-response failure. The test sends only
   one successful request per runtime, so it does not claim connection reuse,
   multiple streams, retry, token/0-RTT, reset or concurrency; those remain
   Phase 4E18. Phase 4E18 accepts two sequential misses and eight overlapping
   misses as distinct streams on one verified DoQ connection, followed by a
   cached-connection case in which two server `NO_ERROR` closes consume the
   Go-compatible two reconnect attempts before success. A same-config SIGHUP
   must close the active connection and the next query must establish a new
   one. Every observed reconnect remains a full handshake with
   `DidResume=false` and `Used0RTT=false`, matching the pinned Go TLS config.
   The Rust endpoint retains its QUIC address-validation token store across
   ordinary reconnect and same-config connection reset, but token rejection,
   stateless reset, idle timeout and packet-level token use are not claimed
   without dedicated wire evidence. Default-port/domain DoQ, broader trust,
   cancellation/timeout stress and proxy routing also remain later gates.
   Phase 4E19 accepts the encrypted-upstream query-wrapper subset on the
   verified DoQ path: IPv4 and IPv6 ECS injection, preservation of a client ECS
   option unless `ecs-override=true`, configured override with host-bit masking,
   local authoritative empty responses for disabled A, AAAA and one numeric
   qtype, and filtering one disabled A answer returned for a non-A question.
   The gate compares configuration/process results, authority observations,
   response bytes and whether the authority was contacted. It does not claim
   the invalid/false parameter matrix, arbitrary compressed or multi-record RR
   filtering, or wrappers on classic upstreams; those remain Phase 4F6.
   `proxy-name` and `respect-rules` remain Phase 4D3B, and multiple-upstream
   scheduling remains outside this slice.

Phase 4A does not claim system resolvers, multiple-upstream selection,
negative/stale/singleflight cache behavior, EDNS rewriting, hosts, fake IP,
policy routing, controller APIs or DNS use by the proxy data plane.

## Phase 4F — complete non-encrypted DNS behavior

Phase 4F prevents remaining general DNS work from being mislabeled as encrypted
DNS. Each subphase is an independent Go/Rust differential gate:

1. **4F1:** full local UDP/TCP message validation, RR/rcode/EDNS/truncation and
   UDP-size behavior (`DNS-01`).
2. **4F2:** classic upstream domain targets, multiple-server scheduling,
   timeout/failure ordering and UDP truncation retry over TCP (`DNS-02`).
3. **4F3:** POSIX, Windows and Android-CMFA system resolvers (`DNS-03`).
4. **4F4:** DHCP discovery, invalidation and interface changes (`DNS-04`).
5. **4F5:** synthetic RCODE and registered Tailscale DNS clients (`DNS-05`).
6. **4F6:** ECS/override and disabled address/qtype wrappers on classic
   transports, including transport-sharing identity (`DNS-10`).
7. **4F7:** default/main/fallback/direct/proxy-server resolver sets using every
   already accepted transport (`DNS-11`).
8. **4F8:** multi-upstream domain/geosite/rule-set nameserver and proxy-server
   policies with ordering/overwrite semantics (`DNS-12`).
9. **4F9:** complete fallback filters, multiple upstreams, lazy/eager failure
   and timeout ordering (`DNS-13`).
10. **4F10:** IPv4/IPv6 lookup ordering and timeout, primary IPv4, HTTPS/ECH RR
    and tunnel lazy-resolution interaction (`DNS-14`).
11. **4F11:** LRU/ARC/max-size, positive/negative/stale TTL, singleflight,
    retries and connection reset (`DNS-15`).
12. **4F12:** wildcard/`lan`/multi-value/system hosts and all relevant query
    types/platforms (`DNS-16`).
13. **4F13:** redir-host over TCP/UDP and all inbounds, CNAME identity, reload
    and expiry (`DNS-17`).
14. **4F14:** all fake-IP filters, persistence/interchange, reverse routing,
    reload/range migration and flush (`DNS-18`).
15. **4F15:** arbitrary DNS REST queries, complete cache controls and external
    DoH GET/POST (`DNS-19`).

Phase 4F3 implements the isolated system-resolver runtime path and platform
contracts, but remains a **partial** matrix row until native deterministic
Go/Rust port-53 wire fixtures pass on the advertised POSIX/Windows/Android
targets. Configuration acceptance and pure platform contracts alone do not
close `DNS-03`.

Phase 4F4 similarly keeps `DNS-04` **partial** after the portable DHCPv4 wire,
interface-selection and invalidation contracts land. Closing the row requires
privileged native DHCP client/server fixtures on advertised platforms; config
acceptance and packet vectors are necessary but not sufficient evidence.

Phase 4F5 closes the synthetic RCODE behavior and the named Tailscale resolver
registry contract. Its differential gate covers all six accepted RCODE names
over both local DNS transports, invalid configuration, missing registrations,
replacement ordering and unregister guards. `DNS-05` remains **partial** until
the Phase 7K Tailscale outbound supplies and proves the real tsnet `QueryDNS`
lifecycle; Phase 4F5 does not introduce TUN, tsnet startup or tailnet traffic.

Phase 4F6 closes the classic UDP/TCP portion of `DNS-10`. Its gate covers IPv4
and IPv6 ECS injection, preserve/override behavior, disabled A/AAAA/numeric
qtypes, all three response sections, compressed multi-record responses, false
and invalid parameter values, exact duplicate removal and raw-transport versus
wrapper identity. Proxy names and `respect-rules` remain Phase 4D3B; combining
these wrappers across main/default/fallback/direct/policy resolver sets remains
Phase 4F7–4F9.

Phase 4F7 accepts the common resolver-set core: exact deduplication and
fastest-valid selection for default/main/fallback/direct/proxy-server sets,
multiple fallback and direct clients, direct-follow-policy, and configuration
composition with every transport already accepted by earlier gates. Runtime
selection is re-proved with deterministic UDP/TCP clients; protocol-specific
handshakes retain their Phase 4E evidence. `DNS-11` remains **partial** until a
multi-client default set is wired through every domain-bootstrap consumer and a
real remote outbound consumes the proxy-server resolver; those consumers must
not be inferred from the development lookup contract.

Phase 4F8 accepts ordered main and proxy-server resolver policies. Policy
values may contain multiple clients from the already accepted resolver set;
domain entries retain exact/wildcard/suffix trie priority and later writes to
the same node win. GeoSite and rule-set matchers are order barriers exactly as
in the Go resolver. The gate covers all four GeoSite domain matcher types and
inline `domain` plus domain-bearing `classical` rule providers. File/HTTP/MRS
rule-provider loading, GeoSite attributes, `respect-rules`, and consumption by
a real remote proxy outbound remain later integration gates rather than
implicit Phase 4F8 claims.

Phase 4F9 accepts the deterministic fallback decision core. Domain and
GeoSite matchers select fallback without contacting main; GeoIP.dat and
IPv4/IPv6 CIDR matchers evaluate main answers. Multiple fallback clients retain
fastest-valid selection. Eager and lazy modes preserve Go's main-first decision
and single five-second query budget, including the observable case where a lazy
main timeout leaves no budget to contact fallback. MMDB-mode GeoIP and broader
transport/cache/retry integration remain explicit `DNS-13` gaps.

Phase 4F10 accepts the configured-resolver `DNS-14` core. A and AAAA start
concurrently, A remains primary, and AAAA is included only within the default
or configured post-A wait window. Primary-IPv4 returns immediately on A success
and uses AAAA only after A failure. The gate also covers IP-literal
short-circuiting, HTTPS ECH parameter extraction and missing-ECH behavior, plus
the mixed-tunnel distinction between a domain rule that avoids main DNS and an
IP rule that requests lazy resolution. Outbound TLS ECH consumption and remote
adapter/platform integration remain with their owning gates.

Phase 4F1 accepts the local-listener boundary on both UDP and TCP. The gate
checks the Go server's header acceptance matrix (FORMERR, NOTIMP and silent
ignore), malformed question handling, semantic forwarding of name-bearing,
text, address, SOA and unknown RR data, non-success RCODE handling, EDNS OPT
echo/preservation and DO bit behavior, and UDP truncation at implicit 512,
advertised-below-512 and larger advertised sizes. TCP must retain the complete
answer independent of the advertised UDP size. Classic upstream domain names,
multiple-server selection, failure scheduling and UDP-TC retry remain Phase
4F2; cache retry/negative/stale behavior remains Phase 4F11.

Phase 4F2 accepts classic main-upstream behavior for nonzero IP sockets and
explicit-port domain endpoints bootstrapped by one classic IP resolver. It
proves UDP and TCP domain targets, ordered duplicate removal, concurrent
fastest-valid selection, connection-error and SERVFAIL failover, one shared
five-second all-upstream timeout, direct TCP exchange and same-endpoint UDP-TC
retry over TCP. System/DHCP/RCODE clients remain 4F3–4F5, classic wrapper
parameters remain 4F6, combining multiple encrypted and policy resolver sets
remains 4F7–4F9, and background/cache retry behavior remains 4F11.

No 4F gate may pull TUN or remote proxy protocols forward merely because DNS
can consume them. Those end-to-end claims close only in Phase 8 or the relevant
Phase 6/7 adapter gate.

## Phase 5 — local product completion

Phase 5 is split into independently accepted workstreams; the inventory IDs in
parentheses are mandatory scope declarations:

- **5A — CLI, configuration and lifecycle:** input/home precedence, version and
  overrides, age/generate/convert subcommands, hooks, full `-t`, signals and
  transactional resource application (`CLI-*`, `CFG-01`, `CFG-18`).
- **5B — rules and local routing:** every remaining rule/metadata family,
  geodata, static tunnels, sniffing and live TCP/UDP routing (`RULE-*`,
  `CFG-10`, `CFG-15`, `CFG-16`, `RUN-01`–`RUN-05`).
- **5C — groups and providers:** selector, URL-test, fallback, load-balance,
  provider vehicles/formats, health checks, persistence, refresh and failure
  rollback (`GRP-*`, `PROV-*`).
- **5D — controller:** every listener/auth/route/method/JSON/stream contract,
  config mutation, provider operations, restart/upgrade and UI/DoH mounts
  (`API-*`).
- **5E — supporting services:** NTP, global TLS/ECH, profile/storage format,
  geodata updating and UI updating (`SVC-*`).
- **5F — remaining local ingress/data plane:** full HTTP/SOCKS/mixed and local
  UDP session behavior before remote protocols (`IN-01`, `IN-02`, `RUN-02`).

Each subphase must be split further when its external input cannot reach one
observable result in a single deterministic fixture.

## Phase 6 — established remote protocols

Port in small interop-gated slices, initially prioritizing commonly deployed
protocols and available maintained Rust primitives. A likely order is SOCKS5,
HTTP, Shadowsocks, Trojan, VMess/VLESS, WireGuard and Hysteria2/TUIC, but the
order must be approved against actual product needs and dependency feasibility.
Each client and server direction is a separate matrix claim.

The current planning order is: **6A** DIRECT and built-ins, **6B** HTTP/SOCKS5,
**6C** Shadowsocks, **6D** VMess, **6E** VLESS, **6F** Trojan, **6G**
Hysteria/Hysteria2, **6H** TUIC, **6I** WireGuard/AmneziaWG and **6J** SSH.
TCP and UDP, client and server, and each security/transport variant remain
separate exit gates inside these labels.

## Phase 7 — advanced and project-specific protocols

Snell, Mieru, AnyTLS, ShadowQUIC, Sudoku, TrustTunnel, MASQUE, OpenVPN,
Tailscale, ZeroTier, SSR, obfuscation plugins and less common transports are
separate slices. No aggregate "protocol parity" claim is allowed.

Use **7A–7L** for the protocol families listed in `OUT-06` and `OUT-10` through
`OUT-20`. Use **7T** subphases for shared dialer chains, mux, WebSocket,
HTTP/2, gRPC/Gun, xHTTP/H3, mKCP, Mekya, plugins, Reality, ECH, JLS, ReSTLS,
ShadowTLS and TLSMirror. A protocol gate may depend on a 7T transport gate but
cannot inherit its wire-compatibility claim.

## Phase 8 — TUN, transparent proxying and platform breadth

- Linux TUN stacks, routing, TProxy, redir, socket marks and iptables in isolated
  namespaces first.
- Darwin, Windows, FreeBSD and Android each receive their own platform gate.
- Cross-compilation is only a build claim; runtime parity needs native tests.
- Additional architectures are admitted after dependency/toolchain feasibility
  and native smoke coverage.

Track **8A** Linux, **8B** Darwin, **8C** Windows, **8D** FreeBSD/Android,
**8E** architecture/build profiles and **8F** platform services/network-change
behavior. Every advertised OS receives native configuration, listener, routing,
process, persistence and shutdown evidence; unsupported combinations require
Go-compatible rejection evidence.

## Phase 9 — release replacement gate

- **9A packaging:** verify artifact names, archive/package contents, version
  metadata and reproducibility for the release matrix.
- **9B migration:** validate upgrade/restart, storage/profile migration and
  rollback.
- **9C stability/performance:** run the full unskipped Go and Rust interop/stress
  suites and benchmark memory, throughput, latency and long-lived connections.
- **9D replacement review:** complete security and license/dependency review;
  require every advertised matrix row to be **Parity** or an explicitly
  approved exclusion, and keep a supported rollback to the pinned/last-known-
  good Go binary.

Only this gate may consider a default-binary switch. It does not require deleting
the Go oracle.
