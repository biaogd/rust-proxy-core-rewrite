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

Phase 4F15 is accepted on the loopback TCP controller boundary. The focused
gate compares the complete Go RR type-name table, representative address,
name, character-string and structured RR JSON, shared-cache hit/flush/refetch,
cache authentication and method handling, plus public external DoH GET,
fixed-length/chunked POST, mount-prefix, content-type, method and malformed
payload behavior. External UI/static serving and non-TCP controller transports
remain Phase 5D/platform work rather than part of this DNS slice.

After Phase 4F15, the controller HTTP infrastructure was refactored without
expanding the phase boundary: Axum/Hyper now provide routing, request framing,
connection handling and graceful shutdown. Phase 3, 4D4, 4F14 and 4F15
differentials are the acceptance gate for that behavior-neutral migration. No
new route, transport or protocol is credited by the refactor.

The same behavior-neutral cleanup then moved mixed-inbound HTTP syntax parsing
to `httparse`, DoH HTTP/1 framing to Hyper, common DNS query/name codecs to the
existing `hickory-proto`, and DHCPv4 packet/options codecs to `dhcproto`. Each
change is an independent commit accepted by its existing Phase 1/3, 4E, 4A/
4F1/4F15 or 4F4 differential gate. Product policy remains in the owning crate,
and none of these library migrations advances the Phase 5 boundary.

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

Phase 4F11 accepts the deterministic `DNS-15` cache lifecycle core. The config
selects LRU or ARC and a bounded live capacity; the gate distinguishes ordinary
recency eviction from ARC scan resistance. Positive and SOA-bearing negative
responses use the minimum non-OPT TTL, expired entries return once at TTL one
while refreshing, concurrent misses share one exchange with per-caller IDs,
and a first uncached SERVFAIL triggers the oracle's observable background
retry. Same-config SIGHUP invalidates cache state and enters the pooled
connection-reset path already proven at the encrypted transport gates. Unusual
non-trailing OPT layouts, caller-cancellation races and REST/external-DoH cache
controls remain later focused work rather than implicit Phase 4F11 claims.

Phase 4F12 accepts the portable `DNS-16` hosts core. Configured host keys use
the Go trie priority for exact labels, whole-label wildcards, root-inclusive
`+.` suffixes and subdomain-only `.` suffixes. Scalar IP/domain values,
multi-IP values and local-interface `lan` expansion are validated before the
owned table is published. A/AAAA queries follow configured aliases, CNAME
queries preserve the oracle's IP-versus-domain behavior, and unrelated types
or classes pass through to the selected upstream. Tunnel routing applies the
same table independently of `dns.use-hosts` and randomly selects configured
addresses. Native hosts-file lookup uses the five-second metadata refresh
boundary and `DISABLE_SYSTEM_HOSTS` switch. The deterministic gate proves these
paths on Darwin; native Linux and Windows refresh evidence remains a platform
gate rather than an implicit cross-platform claim.

Phase 4F13 accepts the `DNS-17` core across every local inbound currently
implemented by the Rust product: HTTP, SOCKS and both mixed TCP protocol paths,
plus SOCKS and mixed UDP. Ordinary upstream CNAME answers retain the original
query identity in the reverse map, while a configured external hosts alias
retains the rewritten target identity. Mapping state survives a validated
same-listener SIGHUP and uses the oracle's 4096-entry access-order LRU.
Although Go inserts mappings with a DNS-derived expiration timestamp, the
pinned baseline creates this LRU with size only and therefore never consults
that timestamp; Phase 4F13 records and reproduces the observable retention past
TTL rather than claiming idealized expiration. Redir-port, TProxy, TUN and
future inbound families remain their owning inbound/platform gates, so
`DNS-17` stays partial outside the implemented local-inbound surface.

Phase 4F14 accepts the `DNS-18` lifecycle core on the current local surface.
Blacklist/whitelist filters cover Go domain-trie syntax, GeoSite and inline
domain/classical rule providers; ordered rule mode covers every accepted
domain rule kind plus MATCH and the `fake-ip`/`real-ip` actions. Persistent
IPv4/IPv6 pools use the oracle's bbolt buckets and allocation-state keys, with
an explicit Go-to-Rust-to-Go interchange gate. Reload proves memory cloning
and persistent prefix reset, the REST flush proves on-disk deletion across a
restart, malformed cache recovery is compared, and current mixed TCP/UDP
inbounds prove reverse routing. External file/HTTP/MRS provider vehicles,
redir/TProxy/TUN and future inbound/platform consumers remain their owning
gates, so the full inventory row stays partial rather than implying those
subsystems from local evidence.

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

### Phase 5A1 accepted scope

Phase 5A1 accepts `CLI-01` and `CLI-02` only. The Rust CLI now applies the Go
oracle's CLI-over-environment rules for `-d`, `-f` and `-config`, resolves
relative home and file overrides from the process working directory, preserves
the existing `$HOME/.config/mihomo` versus `XDG_CONFIG_HOME` fallback, and
selects base64, stdin, explicit file or default file in that order. File mode
also creates the home directory and the oracle's minimal initial configuration
when the selected file is absent, without creating an unrelated missing parent
for an explicit path.

The deterministic gate covers successful selection, normalized success paths,
creation side effects, invalid base64/YAML and missing-parent error classes.
Inline and stdin runtime cases additionally prove that a processed SIGHUP
reapplies the frozen bytes, resets DNS cache state and does not switch to a
lower-priority shadow file.
It does not expand the configuration schema, full `-t` corpus, version/build
output, CLI overrides, age encryption, subcommands, hooks or lifecycle/resource
application; those remain 5A2 onward.

### Phase 5A2a accepted scope

Phase 5A2a accepts only the default, untagged portion of `CLI-04`. `-v`
short-circuits configuration initialization and prints the pinned product
version, Go-compatible OS/architecture names, implementation compiler version
and build time. The Rust binary deliberately identifies `rustc`; claiming a Go
compiler would make diagnostics misleading. Release builds may inject
`MIHOMO_VERSION` and `MIHOMO_BUILD_TIME` at compile time. CMFA, gVisor,
low-memory and negative feature-tag banners remain separate build-profile
gates and are not claimed by this slice.

### Phase 5A2b accepted scope

Phase 5A2b accepts `CLI-05`. The `-m` flag changes the process-level default
used when `geodata-mode` is absent; an explicit YAML `true` or `false` remains
authoritative, matching the oracle's initialize-then-unmarshal order. The
black-box gate starts the complete Go and Rust products and reads the applied
value from `/configs` for all four default/CLI/YAML combinations. It does not
claim geodata loaders, matchers, updates or individual GEOIP/GEOSITE rules,
which retain their existing Phase 4/5B/5E gates.

### Phase 5A3a accepted scope

Phase 5A3a accepts the external-controller address and secret subset of
`CLI-06`. `-ext-ctl` and `-secret` override their corresponding environment
variables, while an explicitly empty CLI value disables the environment value
and leaves YAML authoritative. Non-empty process overrides are applied after
initial parsing and after every successful SIGHUP parse. The gate proves the
selected listener, absence of superseded listeners, Bearer authentication and
reload persistence through live REST requests. Controller TLS/Unix/Windows
pipe, UI fields, routing mark and their platform behavior remain 5A3b onward.

### Phase 5A4a accepted scope

Phase 5A4a accepts the single native X25519 identity subset of `CLI-07`.
ASCII-armored age configuration can be supplied through a file or base64
configuration string and is decrypted before validation/application and again
on reload. CLI, environment and explicit-empty precedence match the oracle;
wrong/absent keys fail encrypted input, while an invalid configured key only
warns when the input is plaintext. The implementation delegates the age wire
format and cryptography to pure-Rust `age` 0.12.1 (MIT OR Apache-2.0), whose
documented wire format interoperates with the reference Go implementation.
Multiple identities, hybrid/PQ, SSH, encrypted-identity and plugin identities
remain outside this claim.

### Phase 5A4b accepted scope

Phase 5A4b accepts only the native X25519 `age convert` subset of `CLI-10`.
The subcommand short-circuits normal configuration startup, emits the exact
public recipient for a valid identity, ignores trailing arguments like the
oracle and preserves the oracle's exit class for invalid or missing keys.
Key generation, hybrid/PQ conversion and encrypt/decrypt remain later 5A4
slices.

### Phase 5A4c accepted scope

Phase 5A4c accepts native X25519 `age encrypt` and `age decrypt` from `CLI-10`.
Both file and `-` standard-stream forms preserve arbitrary bytes, produce or
consume ASCII armor and retain the oracle's plaintext-decrypt pass-through and
failure exit class. Bidirectional Go→Rust and Rust→Go ciphertext interchange is
required. Key generation, hybrid/PQ and other identity/recipient types remain
outside this slice.

### Phase 5A4d accepted scope

Phase 5A4d accepts native X25519 `age keygen` from `CLI-10`. It preserves the
oracle's three-line created/public/secret output structure, accepts ignored
trailing arguments and short-circuits all normal configuration setup. Generated
keys must convert to the same recipient in the opposite implementation.
`keygen-pq` and hybrid/PQ configuration identities remain outside the X25519
claim.

### Phase 5A5a accepted scope

Phase 5A5a accepts only the IP-CIDR MRS v1 to canonical text direction of
`CLI-08`. It decodes the oracle's zstd frame and binary header/range records,
then emits the same minimal ordered IPv4 and IPv6 prefixes. The command
short-circuits configuration startup, ignores trailing arguments and preserves
the basic missing/unknown-argument exit class. Rust delegates compression to
the maintained cross-platform `zstd` 0.13.3 binding (MIT; native zstd is BSD),
while the MRS record parser remains focused, safe Rust. Text/YAML to MRS,
domain/classical rules, every malformed-record diagnostic and native Windows
evidence remain later 5A5 slices.

### Phase 5A5b accepted scope

Phase 5A5b accepts the valid IP-CIDR text and YAML payload to MRS v1 direction
of `CLI-08`. It skips the oracle's text comment forms, accepts `payload` and
`rules` YAML lists, counts valid source prefixes, masks host bits, merges
overlapping/adjacent IPv4 and IPv6 ranges and writes the documented MRS header
and range-set records through `zstd` 0.13.3. Because the Go and Rust zstd
encoders need not choose byte-identical frames, acceptance requires both Go and
Rust outputs to be decoded successfully by both implementations into identical
canonical records. Empty valid rule sets retain the oracle's failure/empty
target behavior. The oracle's permissive streaming-YAML recovery, invalid-rule
warning text, domain/classical records and exhaustive malformed inputs remain
later 5A5 slices.

### Phase 5A5c accepted scope

Phase 5A5c accepts only domain MRS v1 to sorted text from `CLI-08`. A focused
safe-Rust decoder reads the oracle's versioned succinct-domain-set leaves,
label bitmap and label bytes with explicit bounds checks, reconstructs exact
and wildcard patterns and removes the internal exact key paired with a `+.`
pattern just as the oracle does. The differential uses a Go-produced frame and
compares complete output bytes plus malformed-frame lifecycle. Domain
text/YAML encoding, exhaustive Unicode/malformed trie cases, classical records
and runtime provider consumption remain later slices.

### Phase 5A5d accepted scope

Phase 5A5d accepts valid domain text/YAML to MRS v1 from `CLI-08`. The safe-Rust
builder applies the oracle's case, exact, `*`, `+.`, and leading-dot wildcard
normalization, including the internal exact key required by complex-wildcard
matching, then writes the same breadth-first succinct leaves/label-bitmap/label
layout. Acceptance is semantic rather than compressed-byte identity: MRS frames
produced by either implementation must decode through both implementations to
the same sorted patterns. Comment-only input proves the empty-rule/empty-target
failure path. Invalid-entry warning log parity, permissive streaming-YAML
recovery, classical records and runtime provider consumption remain later
slices.

### Phase 5A5e accepted scope

Phase 5A5e records and reproduces the pinned oracle's actual classical
`convert-ruleset` behavior: classical is a recognized behavior name but is not
an MRS-capable strategy, so text, YAML (including the empty-string YAML alias)
and MRS requests terminate with exit 2 after reading the source and creating a
zero-length target. Rust now preserves those observable side effects instead
of rejecting the behavior before file I/O. This is explicit unsupported-feature
parity, not a claim that classical MRS exists. Invalid-rule warning text,
permissive streaming-YAML recovery and exhaustive malformed-record diagnostics
remain later CLI-08/CLI-13 slices.

### Phase 5A5f accepted scope

Phase 5A5f accepts the oracle's line-oriented YAML recovery semantics for
domain and IP-CIDR conversion. The parser discovers `payload` or `rules` after
unrelated top-level preamble, evaluates each subsequent non-comment entry
against only the retained header, skips a malformed entry without poisoning
later valid records and preserves the peculiar single-line/no-final-newline
`file must have a payload` failure boundary. The differential converts both
behaviors and cross-decodes every Go/Rust MRS output. Semantic invalid-rule
warning logs and exhaustive malformed binary/YAML diagnostics remain explicit
CLI-08/CLI-13 gaps.

### Phase 5A6a accepted scope

Phase 5A6a accepts only `generate uuid` from `CLI-09`. Rust delegates random
UUID construction and canonical formatting to `uuid` 1.25.0 (Apache-2.0 OR
MIT), a maintained portable crate requiring no platform-specific implementation
in this slice. The differential validates lowercase canonical shape, RFC 4122
variant and version 4 bits rather than comparing random values, plus ignored
trailing arguments, configuration-startup short-circuit, the oracle's silent
unknown-command result and missing-command exit class. Reality/WireGuard/ECH,
VLESS and Sudoku key generators remain later 5A6 slices.

### Phase 5A6b accepted scope

Phase 5A6b accepts only `generate reality-keypair` from `CLI-09`. Random bytes
are explicitly clamped at the same boundary as the oracle and the public key is
derived by `x25519-dalek` 2.0.1 (BSD-3-Clause), a maintained pure-Rust library
with broad platform support. The CLI emits the exact two labels using unpadded
URL-safe Base64. The black-box gate independently performs the RFC 7748 ladder
to prove each random public key belongs to the emitted private key, in addition
to length, clamp, output and startup-lifecycle checks. WireGuard formatting and
the ECH/VLESS/Sudoku generators remain later 5A6 slices.

### Phase 5A6c accepted scope

Phase 5A6c accepts only `generate wg-keypair` from `CLI-09`. It deliberately
reuses the Phase 5A6b clamped X25519 generator and changes only the externally
observable encoding to the oracle's padded standard Base64. The black-box gate
independently recomputes the public key from each emitted private key and checks
both 32-byte payloads, exact labels/padding, ignored trailing arguments and
startup short-circuit. It does not claim WireGuard transport behavior; ECH,
VLESS and Sudoku generation remain later 5A6 slices.

### Phase 5A6d accepted scope

Phase 5A6d accepts `generate vless-x25519` from `CLI-09`, with either generated
or supplied raw URL-safe Base64 private material. It reuses the clamped X25519
core and delegates the password digest to `blake3` 1.8.7 (CC0-1.0 OR
Apache-2.0 variants), then emits the oracle's complete eight-line key/hash/lazy
configuration contract. A fixed private-key differential compares every output
byte with Go, while an independent RFC 7748 ladder verifies the public password
relationship and an invalid-length case preserves the exit class. This does
not claim VLESS transport/encryption runtime behavior; ML-KEM, ECH and Sudoku
generation remain later slices.

### Phase 5A6e accepted scope

Phase 5A6e accepts `generate ech-keypair <plain_server_name>` from `CLI-09`.
The generator writes the oracle's ECHConfigList v0xfe0d record with X25519
HKDF-SHA256 KEM, the ordered AES-128-GCM/AES-256-GCM/ChaCha20-Poly1305 suite
list, public name and empty extensions, then packages the raw private key and
matching config through `pem` 4.0.0 (MIT). The black-box gate parses both the
Base64 config and `ECH KEYS` PEM rather than snapshotting randomness, verifies
every declared field and independently derives the public key. This establishes
generation-format compatibility only, not TLS ECH handshake behavior. ML-KEM
and Sudoku generation remain later 5A6 slices.

### Phase 5A6f accepted scope

Phase 5A6f accepts `generate vless-mlkem768` from `CLI-09`, with generated or
supplied 64-byte `d || z` seed material. Rust uses the maintained pure-Rust
`ml-kem` 0.2.3 implementation (Apache-2.0 OR MIT) in deterministic FIPS 203
mode and the already selected BLAKE3 crate. The fixed-seed differential compares
the complete 1184-byte encapsulation key, hash and all eight output lines byte
for byte against Go, while generated-output lengths and invalid-seed lifecycle
are also covered. This is generation-format evidence, not VLESS or ML-KEM
transport interoperability. Sudoku remains the final unimplemented `generate`
subcommand family member.

### Phase 5A6g accepted scope

Phase 5A6g accepts `generate sudoku-keypair` and closes `CLI-09` for the pinned
default baseline. Rust uses `curve25519-dalek` 4.1.3 (BSD-3-Clause) to reduce
two independent 64-byte random values into canonical Edwards25519 scalars,
split the master scalar as `r || (x-r) mod L`, and compress `x * G`; the CLI
uses lowercase hex with the oracle's exact labels. The differential implements
Edwards point arithmetic independently, reconstructs `(r+k) * G` for both Go
and Rust outputs and compares it with each emitted public point. This is key
generation-format evidence only; Sudoku transport belongs to its later adapter
and protocol gates.

### Phase 5A7a accepted scope

Phase 5A7a accepts the invalid-configuration recovery subset of `CLI-11`. A
malformed YAML SIGHUP leaves the active listener and routing generation intact,
does not terminate the process, and does not poison the signal loop: a later
valid SIGHUP is still applied. Phase 3C already proves listener bind rollback;
this gate adds the consecutive invalid-then-valid process lifecycle contract.
Providers, TUN, remote adapters and resources not yet implemented in Rust remain
outside the claim.

### Phase 5A7b accepted scope

Phase 5A7b accepts the currently implemented local-resource shutdown subset of
`CLI-11`. Both SIGINT and SIGTERM must exit zero within the bounded shutdown
window, close an idle DIRECT TCP tunnel and release the mixed, controller and
DNS TCP listeners plus the DNS UDP socket before process exit. Phase 4F14 owns
the existing fake-IP persistence evidence. Providers, remote adapters, TUN and
other future resources must add their own shutdown gate before the aggregate
shutdown row can become complete.

### Phase 5A8a accepted scope

Phase 5A8a accepts the Unix local-resource subset of `CLI-12`. `-post-up` and
`-post-down` use the platform shell rather than an application command parser;
their environment defaults and explicit-empty CLI overrides match the oracle.
The explicit-empty gate owns hook suppression, not the clean shutdown contract
already covered by Phase 5A7b, so normal and direct SIGTERM termination are
treated as the same bounded fixture outcome there.
The startup hook can observe mixed, controller and DNS listeners within its
bounded execution window. The pinned Go process initiates executor shutdown
before its deferred post-down hook, while listener closure proceeds
asynchronously; individual listener availability during that hook is therefore
a timing diagnostic, not a deterministic compatibility predicate. Acceptance
requires post-down invocation and shell completion. A failed startup hook exits
nonzero and skips the shutdown hook, while a failed shutdown hook is logged
without changing a successful process exit. Windows command execution is
implemented with `cmd.exe /C`, but native Windows ordering and failure parity
remain unclaimed.

### Phase 5B1a accepted scope

Phase 5B1a accepts the first half of `RULE-03`: `DOMAIN-REGEX` parsing and
mixed TCP routing. The target is the final comma-separated field so regular
expressions may contain commas; matching is case-insensitive like the pinned
Go `regexp2` rule. The acceptance corpus requires valid/invalid expressions,
lookahead and a comma-bearing quantifier, rule-kind observation, one DIRECT
local echo and one REJECT fallback through HTTP CONNECT. This gate does not
claim exhaustive .NET regular-expression syntax, pathological timeout parity,
Unicode-category parity or `DOMAIN-WILDCARD`; each remains a later gate.

### Phase 5B1b accepted scope

Phase 5B1b accepts `DOMAIN-WILDCARD` in the same local mixed TCP boundary. Its
`*` and `?` operators match bytes exactly like the oracle's project-local
wildcard package, including empty and multi-byte input boundaries; it is not a
filesystem glob or Unicode-scalar matcher. Acceptance requires unit vectors,
matched-kind observation, one DIRECT local echo and one REJECT fallback.
Broader Unicode/normalization, sub-rule and recovered/intercepted-host coverage
remains part of the aggregate RULE-03 exit gate.

### Phase 5B2a accepted scope

Phase 5B2a accepts destination literal IPv4 `IP-SUFFIX` only. The parser must
retain host bits and compare the declared suffix width rather than normalize it
as a network prefix. Acceptance uses a deterministic native-interface echo,
the shortest whole-byte suffix that separates that address from loopback, a
DIRECT hit, REJECT fallback and invalid `/33` configuration. IPv6, partial-byte
widths, mapped addresses, source forms and observable lazy/no-resolve resolver
calls remain independent gates.

### Phase 5B2b accepted scope

Phase 5B2b accepts the IPv4 source forms `SRC-IP-SUFFIX` and
`IP-SUFFIX,...,src` on the local mixed TCP path. The loopback client source must
produce DIRECT for both spellings, a different last byte must fall through to
REJECT, and both matches must report the source rule kind. IPv6, partial-byte
suffixes, mapped addresses and resolver-call instrumentation remain later
RULE-05 gates.

### Phase 5B2c accepted scope

Phase 5B2c accepts `DSCP` matching against the current local mixed TCP
metadata, whose observable default is zero. Acceptance requires a zero hit,
nonzero miss, slash-separated and reversed inclusive range, wildcard, invalid
value above 63, and distinct DIRECT/REJECT network outcomes in both products.
Nonzero socket metadata from transparent proxy, TUN and UDP paths remains a
later RULE-06 gate and must not be simulated by this slice.

### Phase 5B2d accepted scope

Phase 5B2d accepts live destination-port, inbound-port and TCP network metadata
on the local mixed TCP path. Dynamically reserved ports must produce exact hit
and adjacent miss outcomes; the same TCP connection must match TCP and reject
UDP. Source-port binding, UDP ingress and nonzero DSCP capture remain separate
RULE-06 gates.

### Phase 5B2e accepted scope

Phase 5B2e accepts live source-port metadata on the local mixed TCP path. Two
clients must hold distinct pre-bound source ports across startup; after an
independent provider-readiness probe, the configured port must reach DIRECT
and the other must reach REJECT in both products. UDP source ports and nonzero
DSCP remain later RULE-06 gates.

### Phase 5B3a accepted scope

Phase 5B3a accepts `IN-TYPE` for the current mixed TCP input set. HTTP
absolute-form must be distinguishable from HTTPS CONNECT, SOCKS4 from SOCKS5,
slash-separated payloads must preserve ordering-independent membership, and
`SOCKS` must expand to both SOCKS versions. Each wire input receives an
observable DIRECT echo or REJECT close after an explicit provider-readiness
barrier. `IN-USER`, `IN-NAME`, UDP and protocol kinds without a Rust inbound
remain later RULE-08 gates.

### Phase 5B3b accepted scope

Phase 5B3b accepts `IN-USER` on authenticated HTTP CONNECT, SOCKS5 and SOCKS4
local TCP inputs. Successful authentication must populate one shared metadata
field; exact and slash-list rules are case-sensitive and must create distinct
DIRECT/REJECT outcomes for `alice`, `Alice` and `socks4`. Authentication error
behavior remains owned by Phase 3. Invalid UTF-8 usernames, UDP associations,
remote inbound families and `IN-NAME` remain later gates.

### Phase 5B3c accepted scope

Phase 5B3c accepts `IN-NAME` for the fixed HTTP, SOCKS and mixed TCP listeners.
Their exact names are `DEFAULT-HTTP`, `DEFAULT-SOCKS` and `DEFAULT-MIXED`;
slash lists are case-sensitive and must create observable DIRECT/REJECT
differences while all listeners coexist. UDP associations, general YAML named
listeners and future inbound names remain attached to their own inbound gates.

### Phase 5B3d accepted scope

Phase 5B3d accepts basic live `AND`, `OR` and `NOT` evaluation on the local
mixed TCP path. Conditions must combine real domain and inbound-type metadata,
and every operator must produce observable DIRECT and REJECT outcomes against
the oracle. Live `SUB-RULE`, lazy destination resolution, process helpers and
the broader nested/error corpus remain independent RULE-11 gates.

### Phase 5B3e accepted scope

Phase 5B3e accepts live `PASS` scan continuation on the local mixed TCP path.
A matched PASS must produce no adapter selection and must allow a following
rule to choose either DIRECT or REJECT, with both outcomes compared to the Go
oracle. `PASS-RULE`, live sub-rule escape and REMATCH mutation/rescan remain
separate RULE-12 gates.

### Phase 5B3f accepted scope

Phase 5B3f accepts live `SUB-RULE` entry and `PASS-RULE` control flow on the
local mixed TCP path. Acceptance requires one PASS-RULE to continue within a
named branch, one exhausted branch to resume the main scan, and observable
DIRECT/REJECT outcomes against the oracle. Lazy helper evaluation, live nested
cycles and REMATCH remain separate gates.

### Phase 5B3g accepted scope

Phase 5B3g accepts live REMATCH mutation and rescan on the local mixed TCP
path. Both `target-rematch-name` and `target-sub-rule` must change the next
rule scan and yield distinct DIRECT/REJECT outcomes against the oracle. The
action is executable without becoming a network outbound. Cycle termination
and update-failure behavior remain a separate RULE-12 gate.

### Phase 5B current SOCKS5 UDP metadata accepted scope

This aggregate gate accepts the complete rule metadata carried by the current
fixed SOCKS5 UDP ingress: source/destination/inbound ports, UDP network, default
DSCP, inbound type, user and name. Acceptance requires live packets through
both `socks-port` and `mixed-port`, one composite rule that depends on every
nonempty field, and a source-port miss that receives no response. It must also
preserve the oracle's two counterintuitive defaults: both UDP listeners use
`DEFAULT-SOCKS`, and UDP packets do not inherit a TCP authentication username.
Transparent/TUN DSCP, named listeners and future protocols remain later gates.

### Phase 5B aggregate core domain/IP accepted scope

This aggregate gate accepts the current local execution paths for RULE-02,
RULE-04 and RULE-05 together because they share one host/destination metadata
boundary. Acceptance requires live exact/suffix/keyword domains, destination
and source IPv4 CIDR, `no-resolve`, partial-bit IPv4 suffixes and mapped-IPv4
normalization, plus pure IPv6 suffix hit/miss/source and invalid-width cases.
Native IPv6 live routing, sniffer/static-tunnel contexts and exhaustive resolver
instrumentation remain later contextual gates.

### Phase 5D aggregate controller core accepted scope

This aggregate gate advances `API-02`, `API-03`, `API-07` and `RUN-06` through
one shared read-only controller boundary. Axum owns the WebSocket handshake and
framing. A configured secret accepts the existing Bearer header or a nonempty
`token` query parameter only on WebSocket upgrades, and rejects a wrong query
token before upgrade. `/memory`, `/traffic`, `/logs` and `/connections` expose
their declared JSON shapes over WebSocket; `/memory` also preserves the
oracle's zero-valued first HTTP and WebSocket frames, and `/connections`
supports its millisecond interval query.

Acceptance compares handshake status/headers, first-frame JSON shapes, both
authorization forms and one live TCP log event in
`compat/scripts/phase5d_streams.py`. The same aggregate controller family also
completes the current local-TCP `API-07` boundary: deleting a returned ID closes
only that live tunnel, deleting a missing ID remains idempotent, and deleting
the collection closes every tracked tunnel and clears the snapshot. These
side effects are compared in `compat/scripts/phase5d_connections.py`.

The same controller core gate completes `API-02` on the current TCP surface.
`external-controller-cors` preserves the oracle's allow-all defaults and empty
list, case-insensitive exact and single-`*` origins, allowed method/header
validation, 300-second preflight age, Private Network toggle, `Vary` contract,
preflight-before-auth ordering and same-address hot reload. `tower-http` owns
the standard CORS service; a narrow compatibility wrapper validates the fixed
Go method/header set and normalizes its request-dependent `Vary` values.

The executable configuration transaction gate extends the same controller
family through the current `API-04` subset. `GET /configs` remains the live
generation snapshot. `PATCH /configs` applies the currently executable HTTP,
SOCKS and mixed ports plus log level and IPv6 settings. `PUT /configs` parses
inline YAML, preserves the serving controller's address/secret/CORS boundary,
and publishes a generation only after all replacement listeners have bound.
Acceptance moves a live mixed listener, changes a MATCH route from DIRECT to
REJECT and back, verifies payload-over-path precedence, and proves malformed
YAML leaves both routing and the reported generation unchanged in
`compat/scripts/phase5d_configs.py`.

The rules control gate exposes the current top-level executable program at
`GET /rules`, including stable indexes, normalized type/payload/target fields,
wrapper-style disabled state and atomic hit/miss counters with their latest
timestamps. `PATCH /rules/disable` changes that same state in place, so a
disabled matching rule is skipped immediately without rebuilding the runtime
generation. Acceptance proves ordered DomainSuffix/MATCH inventory, both
counter directions, ignored indexes, malformed JSON, DIRECT-to-REJECT disable
side effects and restoration after enable in `compat/scripts/phase5d_rules.py`.

The controller storage gate accepts the complete process-local JSON lifecycle
at `/storage/{key}`. Axum owns path decoding and body framing, `serde_json`
validates values, and runtime state preserves the submitted JSON bytes exactly.
Acceptance covers missing values, escaped Unicode/path keys, create, raw-byte
readback, replacement, idempotent deletion, the 1 MiB boundary and rollback
after invalid or oversized writes in `compat/scripts/phase5d_storage.py`.
Cross-restart persistence and database-format interchange remain a separate
storage migration gate.

The built-in proxy control gate exposes the seven oracle built-ins and the
implicit GLOBAL selector through `/proxies` and `/group`. It preserves each
adapter's JSON shape, UUID convention, initial health state, selector members
and exact list/detail/mutation errors. GLOBAL selection is shared controller
state and supports the current DIRECT/REJECT members. A Hyper HTTP/1 client
performs deterministic local HEAD delay tests; the resulting history and
per-URL health state are returned by subsequent proxy views, while GLOBAL
group delay reports the successful DIRECT member. Acceptance is consolidated
in `compat/scripts/phase5d_proxies.py`.

Configured remote adapters and groups, HTTPS health checks, health
failure/timeout exhaustiveness and selection reload/persistence remain later
`API-05` gates.

The live routing-mode gate connects the configuration and proxy-control
surfaces to the data plane. Rule mode retains ordered rule evaluation, Direct
mode bypasses a rejecting rule, and Global mode reads the current GLOBAL
DIRECT/REJECT selection for every new TCP connection and SOCKS UDP session.
Both PATCH and inline-YAML PUT can switch modes transactionally. Acceptance in
`compat/scripts/phase5d_modes.py` exercises every transition on real mixed TCP
and UDP echo paths, invalid-mode rollback and live selector changes. The UDP
fixture deliberately creates a new client session after each change because
the oracle retains the selected adapter for an existing SOCKS UDP association.

The implicit-provider gate begins `API-08` without introducing speculative
provider loading. `/providers/proxies` exposes the oracle-created `default`
compatible provider and its DIRECT/REJECT member snapshots; detail, no-op
update and health-check operations preserve the pinned baseline's status/body
contracts. `/providers/rules` exposes the empty registry, and missing provider
or member operations return the exact resource error. Acceptance in
`compat/scripts/phase5d_providers.py` compares all list/detail/member/mutation
and negative paths. Configured file/HTTP vehicles, refresh scheduling, real
health state, rule-provider resources and persistence remain the later 5C/5D
integration gate.

That initial aggregate intentionally left TLS/Unix/pipe transports, real
process-memory accounting, structured logs, path loading and persistent
storage to the completion boundary below. Service-backed routes such as
`/configs/geo` remain owned by their service gate.

### Phase 5D completion boundary

Phase 5D is complete when the controller is a transport-neutral front end for
every service that already exists in the Rust runtime. It does **not** make an
unimplemented service compatible merely by registering its future route.
Accepted work is grouped into independently reproducible differentials:

- `5D1–5D3`: simultaneous TCP/TLS/Unix controllers, native Windows named
  pipe, local-transport secret bypass, TLS validation, public UI/DoH/debug
  ordering, routing-mark socket boundary, CORS/auth and hot replacement;
- `5D4`: real process RSS, repeated memory/traffic WebSocket frames,
  monotonic totals, plain and structured live logs;
- `5D5`: executable GET/PATCH/PUT configuration transactions plus inline,
  default-current and safe absolute path loading with rollback;
- `5D6–5D10`: the DNS/cache, proxy/group, rules, connections and provider
  surfaces for all currently executable Rust implementations;
- `5D11`: bounded persistent `/storage` state using the Go `cache.db` bbolt
  bucket and MessagePack record layout, including restart and bidirectional
  Go/Rust interchange;
- `5D12`: authenticated process restart/re-exec with the observable Go method,
  body, PID and readiness contract;
- `5D13`: public external UI serving/reload, external DoH and debug GC route,
  with exact status/header/body evidence.

Darwin acceptance is recorded by `phase5d_*.py`. Linux runs the same set in
the default differential matrix. Windows named-pipe behavior has its own
native job because a cross-build cannot validate pipe lifecycle. Phase 5F now
implements Linux/Android `SO_MARK`, accepts bounded local NAT pressure and adds
the release build; nonzero marks still need privileged native evidence. Go
`pprof`/`expvar` payloads and allocator-specific release are recorded as
runtime-specific API gaps rather than normalized into portable Rust parity.

The following controller paths remain dependent rather than unfinished 5D
plumbing: `/configs/geo` and `/upgrade/geo` require `SVC-04`; `/upgrade/ui`
requires `SVC-05`; core `/upgrade` requires a signed/versioned executable
update policy. They are accepted only with the service in Phase 5E, never as
stub routes.

## Phase 5E — shared services and durable resources

Phase 5E follows the controller boundary and supplies services used by several
later protocols. The order is `5E1` NTP, `5E2` global TLS/client-auth/ECH,
`5E3` remaining profile persistence, `5E4` geodata/MMDB/MRS loading and update,
and `5E5` external UI download/update. Each service must include startup,
reload, failure rollback, shutdown and its REST side effects where applicable.

### Phase 5E accepted slices

- `5E1`: configuration/defaults and a bounded direct SNTP exchange update the
  process clock, retry three times, follow reload/disable/shutdown and reset the
  offset. A deterministic UDP contract covers offset calculation. Named
  `dialer-proxy` UDP routing and privileged `write-to-system` remain explicit
  platform/outbound gaps.
- `5E2`: the adjusted clock is shared by controller and configured HTTP-proxy
  TLS. Controller `request`, `require-any`, `verify-if-given` and
  `require-and-verify` modes have a generated-certificate Go/Rust handshake
  differential. Server ECH and propagation of the adjusted clock through every
  DNS TLS client remain open, so the global TLS row remains partial.
- `5E3`: current fake-IP, selector/fixed-fallback and controller storage state
  retain the Go-compatible bbolt/MessagePack formats and existing bidirectional
  interchange gates. No incompatible replacement database was introduced.
- `5E4`: `geox-url`, automatic scheduling, safe validation and atomic update
  cover GeoIP.dat/GeoSite.dat and MMDB for currently executable consumers;
  both Geo REST aliases and invalid-payload rollback pass. General
  geodata-mode `GEOSITE`, `GEOIP` and `SRC-GEOIP` rules now load from the
  configured home, drive mixed TCP routing, expose oracle-compatible REST
  type/payload/record-size fields and register their data files with the
  updater. MMDB-mode general GEOIP, ASN and broader loader variants remain
  open.
- `5E5`: explicitly configured external UI directories auto-download when
  empty; authenticated manual updates use bounded `reqwest` downloads and the
  `zip`/`tar` libraries with traversal/link rejection, single-root flattening
  and failure rollback. `/upgrade/ui` passes against the oracle.

`compat/scripts/phase5e_services.py` and
`compat/scripts/phase5e_tls_client_auth.py` cover the shared-service and TLS
boundaries; `compat/scripts/phase5e_geo_rules.py` covers the general Geo rule
boundary. Phase 5E is not globally closed until the listed 5E1/5E2/5E4 gaps
are accepted rather than normalized away.

## Phase 5F — local runtime and platform completion

Phase 5F closes local listener/runtime/platform behavior before broader remote
protocol coverage is considered release-ready. `5F1` completes fixed local
HTTP/SOCKS/mixed semantics and socket options, `5F2` completes UDP NAT/session
lifecycle, and later 5F gates cover routing marks, native process/platform
behavior, diagnostics, backpressure/stress and build-profile evidence. A
successful host cross-build is never sufficient for a native behavior claim.

### Phase 5F accepted slices

- `5F1a`: fixed HTTP, SOCKS and mixed TCP accept `allow-lan`, IPv4 literal or
  wildcard `bind-address`, `lan-allowed-ips`, `lan-disallowed-ips` and
  `skip-auth-prefixes`. Allowed prefixes are evaluated before disallowed
  prefixes, and skip-auth selects the existing unauthenticated protocol path
  without mutating configured users. `allow-lan: false` retains the oracle's
  loopback-only override regardless of `bind-address`. The differential proves
  all three fixed listener families plus `/configs` rendering. IPv6 wildcard
  binding, same-port bind-address reload, TFO/MPTCP and native non-loopback
  reachability remain later `5F1` gates.
- `5F1b`: the library-backed socket boundary binds `*` as an IPv4/IPv6
  dual-stack wildcard and accepts bracketed explicit IPv6 addresses. Fixed
  listener identity now includes its address, so controller PATCH can change
  the bind address on the same port and recreate TCP/UDP sockets like the Go
  oracle. PATCH also validates and applies all three LAN prefix lists. The
  native differential proves IPv4 plus IPv6 wildcard relay, IPv4-to-IPv6
  same-port replacement, old-address retirement, auth policy replacement and
  malformed-prefix rollback. TFO/MPTCP and native non-loopback reachability
  remain later `5F1` gates.
- `5F2a`: fixed SOCKS and mixed UDP now use a bounded 64-packet NAT session
  keyed by the client socket address instead of creating one outbound socket
  per packet. The DIRECT session keeps one outbound socket, relays multiple
  responses, resets its 60-second idle deadline on traffic, observes shutdown
  and controller cancellation, and retains the routing generation that created
  it. `compat/scripts/phase5f_udp_nat.py` proves stable outbound source-port
  reuse, two write-backs from one request, and reload behavior where the old
  session remains DIRECT while a new client is rejected. General destination
  fan-out, IPv6, remote UDP adapters/UoT, timeout-expiry timing and association
  ownership remain later `5F2` gates.
- `5F2b`: the same Go/Rust NAT differential now proves IPv4 destination
  fan-out through one stable outbound socket, retention after the SOCKS5 UDP
  ASSOCIATE control connection closes, and IPv6 request/write-back plus source
  port reuse through the dual-stack mixed listener. These observations match
  the fixed Go SOCKS UDP listener, whose packet lifecycle is source-keyed and
  not owned by the control connection. The exact 60-second expiry boundary,
  capacity/backpressure stress and remote UDP adapters/UoT remain later gates.
- `5F1c`: the fixed TCP listeners apply keepalive policy through `socket2`,
  enable inbound TFO through the maintained MIT-licensed `tokio-tfo` adapter,
  and request Linux MPTCP with the same ordinary-TCP fallback as Go. Global
  interface, routing-mark, keepalive and concurrent-domain-dial policy now
  reaches DIRECT TCP/UDP plus every currently executable HTTP/SOCKS5 upstream
  and health-check dial. The LAN differential proves the live `/configs`
  values, a real non-loopback wildcard connection, TFO/MPTCP-enabled relay,
  platform-specific invalid-interface handling, a concurrent domain dial and
  a nonzero routing-mark snapshot. Applying a nonzero mark to a global-unicast
  socket remains a privileged Linux evidence claim rather than being
  normalized to success on Darwin.
- `5F2c`: the NAT differential sends a burst larger than the 64-packet session
  queue and requires a following marker round trip, so overload cannot wedge
  the session. The default Linux CI gate additionally waits across the real
  60-second idle deadline and requires the same client address to receive a
  newly allocated upstream source port in both Go and Rust. Local focused runs
  omit only that wall-clock wait through an explicit environment gate.
- `5F3`: the default quality job builds the all-feature `rewrite-cli` release
  binary after fmt, clippy and tests. A separate root-only Linux job writes and
  reads back a nonzero `SO_MARK`, while native platform jobs retain the other
  socket contracts. Existing bounded traffic/memory/log/connection diagnostics are
  the portable Phase 5F observability boundary. Go-runtime `pprof` and `expvar`
  payloads are recorded as deliberately non-portable API gaps, and process
  lookup remains coupled to future PROCESS-rule/original-flow metadata rather
  than being falsely claimed by the local proxy slice.

Phase 5F implementation is closed for the declared local HTTP/SOCKS/mixed,
DIRECT TCP/UDP and currently executable upstream-adapter boundary. The Darwin
fast differentials pass; the Linux exact-timeout, privileged-mark and release
results remain pending until their configured native CI gates report success.
This closure does not imply remote UDP/UoT, TUN/redir/TProxy, process rules,
Go-runtime diagnostics or protocols not already executable in Rust.

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

### Phase 6A1 accepted scope

The reserved built-in adapter slice now closes the TCP/control behavior that
precedes configured remote protocols. `COMPATIBLE` uses the same DIRECT socket
path, `PASS` continues ordered rule scanning, `REJECT` closes immediately and
`REJECT-DROP` retains the accepted mixed TCP connection for the oracle's
60-second drop interval. PASS-RULE and REMATCH rule-flow behavior remains
covered by the existing Phase 5B gates rather than being reimplemented as a
transport.

The implicit GLOBAL selector is assembled in Go order from DIRECT, REJECT,
top-level configured proxies and configured groups. Its selection is shared by
the controller and data plane, and a user-defined `GLOBAL` group replaces the
implicit selector. Duplicate proxy names, reserved proxy names and proxy/group
collisions fail configuration validation.
`compat/scripts/phase6a_builtins.py` compares built-in views, live TCP outcomes,
default and custom GLOBAL selection and configuration acceptance. Fast local
runs prove the hold contract; the isolated Linux CI shard additionally waits
for and compares the exact default-timeout expiry.

### Phase 6A2 accepted scope

The configured simple-adapter slice completes the Phase 6A product boundary.
Top-level `direct`, `reject`, `dns` and `rematch` records now participate in
validation, GLOBAL ordering, groups, controller views and live routing. Inline
providers accept configured DIRECT records; provider REMATCH remains rejected
like the pinned Go parser because its rule dependency is not self-contained.

Configured DIRECT relays TCP and UDP through the existing local socket policy.
Configured REJECT closes TCP and silently drops UDP. Configured DNS exposes the
shared DNS service as a two-byte framed TCP adapter and a DNS-message UDP
adapter. Configured REMATCH mutates the active rule context and restarts rule
evaluation, including when selected through a group, with cycle protection.
`compat/scripts/phase6a_simple_adapters.py` compares configuration acceptance,
exact GLOBAL member order, controller fields and deterministic TCP/UDP outcomes
against the pinned Go oracle.

Phase 6A is therefore implementation-complete for the declared simple-adapter,
current listener and local TCP/UDP boundary. Per-adapter interface, routing
mark, IP-version, TFO/MPTCP and dialer-proxy combinations remain cross-cutting
OUT-01/platform or later-protocol dependency gates. The exact 60-second
REJECT-DROP expiry remains a Linux CI evidence gate and is not claimed locally.

### Phase 6B1a accepted scope

The first remote-protocol slice accepts a single configured plaintext HTTP
proxy as a rule target. Configuration requires a nonempty unique name, server
and nonzero port and accepts an optional complete username/password pair. The
outbound uses Hyper's HTTP/1 client upgrade path for CONNECT, preserves the
destination authority and Host, emits Basic proxy authentication and relays
TCP bytes after a successful response. `compat/scripts/phase6b_http.py` places
a deterministic authenticated CONNECT server between mixed ingress and a TCP
echo server, compares the upstream request fields and proves a separate rule
still rejects. TLS, broader authentication/error combinations, groups,
providers, UDP and adapter-controller rendering remain separate gates.

### Phase 6B1b accepted scope

The HTTP adapter can wrap its proxy connection in TLS before Hyper performs
the existing HTTP/1 CONNECT exchange. Configuration accepts `tls`, explicit
`sni` and `skip-cert-verify` only for HTTP adapters; runtime and controller
health paths pass those policies through the same narrow `tokio-rustls`
boundary. The deterministic authority in
`compat/scripts/phase6b_http_tls.py` observes SNI, Basic authentication,
CONNECT authority/Host and bidirectional echo, then compares untrusted
certificate rejection, an authority-rejected SNI and HTTP 502 failure without
terminating the product. rustls uses the workspace's explicit ring provider,
while Hyper continues to own CONNECT framing and upgrades.

Positive system/custom-root verification, `name-cert-verify`, client
certificates, fingerprints, partial credential shapes, malformed/delayed
response handling and the protocol's lack of UDP are closed by Phase 6B3.
Dialer chains remain the cross-cutting OUT-21 gate.

### Phase 6B1c accepted scope

The HTTP CONNECT request path now emits the oracle's default `Host`,
`User-Agent: Go-http-client/1.1` and `Proxy-Connection: Keep-Alive` fields,
accepts string-valued custom `headers`, and applies configured Basic
credentials after those overrides. Unauthenticated and authenticated TCP
tunnels share that path. The response boundary accepts exactly status 200,
matching the oracle rather than treating every 2xx status as success.
`compat/scripts/phase6b_http_contract.py` compares default and overridden
headers, credential precedence, bidirectional echo, and rejection of 204,
301, 400, 405, 407 and 500 while the product remains alive.

The remaining TLS identity, client-certificate, malformed/delayed response and
partial-credential combinations are closed by Phase 6B3. HTTP remains a TCP
CONNECT adapter and does not advertise UDP or UoT. Dialer chains remain the
cross-cutting OUT-21 gate.

### Phase 5C1a accepted scope

The first group slice accepts one or more flat `select` groups whose members
are current DIRECT/REJECT or configured proxy names. A valid
`default-selected` initializes the process-local choice, and controller PUT
changes the target used by new TCP connections immediately. The controller
renders the configured HTTP adapter and selector with the oracle's exact
current fields, including the selected member's UDP capability.
`compat/scripts/phase5c_selector.py` proves initial REJECT, selection of the
authenticated HTTP outbound, echo relay, invalid-choice rollback and reset to
REJECT. Nested groups, provider composition, reload/persistence and
URL-test/fallback/load-balance remain separate gates.

### Phase 6B2a accepted scope

The first SOCKS5 outbound slice accepts a configured server/port plus a complete
username/password pair as a TCP rule target. `fast-socks5` owns target address
encoding, CONNECT reply parsing and the upgraded async stream. A narrow auth
adapter offers only username/password when credentials are configured, matching
the oracle's greeting bytes. The oracle's acceptance of a server-selected
no-auth method is covered separately by Phase 6B2b.
`compat/scripts/phase6b_socks5.py` observes greeting/auth/request bytes at a
deterministic local SOCKS5 server, compares the configured adapter view and
proves relay plus an independent REJECT route. No-auth, domain-resolution
policy, TLS, errors/timeouts, UDP/UoT and dialer chains remain later gates.

### Phase 6B2b accepted scope

The SOCKS5 TCP handshake contract now covers no-authentication and the pinned
Go credential boundary: a nonempty username enables RFC 1929, a missing
password becomes empty, and a password without a username leaves no-auth active.
It preserves the oracle's method-selection behavior, including accepting a
server-selected no-auth method after offering password authentication and
rejecting password selection when no username is configured.

Domain, IPv4 and IPv6 destinations retain their exact SOCKS address type and
bytes. The narrow compatibility adapter also preserves the pinned client's
CONNECT-reply behavior: version/method negotiation errors retry ten times, but
a well-formed bind address completes CONNECT even when the reply status is
nonzero. `fast-socks5` remains responsible for standardized target encoding and
reply-address parsing; only the oracle-specific negotiation and status policy
is custom. `compat/scripts/phase6b_socks5_contract.py` compares wire bytes,
success/failure lifecycle, retry count and process survival. TLS, UDP and
overlength credential behavior are closed by Phase 6B3. The native SOCKS5
adapter does not advertise UoT; dialer chains remain the cross-cutting OUT-21
gate.

### Phase 6B3 completion scope

Phase 6B3 closes the native HTTP and SOCKS5 adapter boundary rather than
starting another protocol. Both adapters accept verified TLS with the global
custom root pool, an independent `name-cert-verify`, SHA-256 certificate
pinning and optional client certificate/private-key authentication. HTTP keeps
its configured SNI distinct from the verification name, and partial HTTP
credentials emit no Basic header exactly like the oracle. Its CONNECT parser
accepts a delayed valid response and rejects EOF, malformed framing and every
representative non-200 status without terminating the process.

SOCKS5 now composes the same TLS policy with CONNECT and UDP ASSOCIATE. A
single inbound UDP session retains its TCP control connection, replaces an
unspecified relay address with the proxy address, carries multiple resolved
destinations over one association, validates relay packets and reports
`udp: true`, `uot: false`. The username/password encoder deliberately preserves
the pinned oracle's uint8 length wrap while writing the full overlength bytes.

`compat/scripts/phase6b_tls_identity.py`,
`compat/scripts/phase6b_socks5_udp.py`, the expanded HTTP contract and the
expanded SOCKS5 contract compare all of those external outcomes. Phase 6B is
complete for native HTTP/SOCKS5 configuration, controller views and the
current mixed TCP/UDP data plane. Common `dialer-proxy` composition, richer
per-adapter platform combinations and later provider override expressions are
owned by OUT-21/Phase 7T and are not relabeled as Phase 6B protocol gaps.

### Phase 6C-A accepted scope

The first Shadowsocks slice accepts one top-level `type: ss` outbound with a
nonempty server, port and password and the `aes-128-gcm` SIP004 AEAD cipher.
The existing mixed HTTP/SOCKS TCP ingress and rule engine may select it; the
runtime preserves the rewrite's platform socket policy while the official
`shadowsocks` core crate owns encryption and framing on the established
upstream stream. Product DNS/routing policy therefore remains outside the
third-party adapter boundary.

`compat/scripts/phase6c_shadowsocks.py` uses the same deterministic local
Shadowsocks authority for Go and Rust, then compares a domain-address TCP echo,
the following MATCH rejection and the controller's name/type/UDP/UoT fields.
The authority itself uses the official Rust protocol implementation, so the
gate is real wire interoperability rather than an in-process mock.

This is deliberately not aggregate Shadowsocks completion. Other legacy AEAD
and stream ciphers, Shadowsocks 2022, UDP, UoT, plugins, provider/group use,
server/inbound direction, per-adapter socket options and dialer chains require
independent Phase 6C gates. Unsupported Phase 6C-A options are rejected rather
than silently ignored.

### Phase 6C-B accepted scope

The SIP004 AEAD TCP client matrix adds `aes-256-gcm` and
`chacha20-ietf-poly1305` beside the Phase 6C-A `aes-128-gcm` path. These are the
three standard legacy AEAD methods enabled by the selected official library
feature; the product still rejects stream, extra AEAD and Shadowsocks 2022
methods until their own dependency and oracle review.

`compat/scripts/phase6c_shadowsocks_ciphers.py` starts a fresh authority and
product generation for each cipher and compares Go/Rust domain and IPv4 target
relay, a 128 KiB payload spanning encrypted records, TCP half-close response
delivery and process survival. Phase 6C-A continues to own the exact controller
view and MATCH rejection checks.

Phase 6C-B closes only the native SIP004 AEAD TCP cipher/address/framing
boundary. UDP, UoT, plugins, provider/group consumption, server/inbound mode,
Shadowsocks 2022 and shared dialer/transport composition remain later gates.

### Phase 6C-C accepted scope

The three accepted SIP004 AEAD methods may now opt into native UDP with
`udp: true`. Mixed and SOCKS5 UDP ingress selects the configured Shadowsocks
adapter through the existing rule engine, retains one encrypted upstream socket
per inbound client, forwards both IPv4 and domain target addresses, and expires
through the existing bounded queue, cancellation and one-minute idle lifecycle.
The platform crate still binds the upstream socket and applies the global
interface/routing-mark policy; the official `shadowsocks` crate exclusively
owns SIP004 UDP authentication, encryption and address framing.

`compat/scripts/phase6c_shadowsocks_udp.py` starts the same dual TCP/UDP local
authority for Go and Rust and runs every accepted cipher independently. One
client on each mixed and SOCKS5 UDP listener sends an IPv4 packet, a domain
packet and a later 4 KiB IPv4 packet over the same product-side session. The fixture also compares the
adapter's `udp: true`, `uot: false` controller view and process survival. A
bounded readiness retry accounts for the oracle exposing its TCP mixed port
slightly before the paired UDP listener; it does not normalize data-plane
failures.

Phase 6C-C does not add UoT, plugins, stream/extra/2022 ciphers, IPv6 UDP,
provider/group consumption, inbound/server mode or shared dialer/transport
composition. Those remain separately testable gates.

### Phase 6C-D accepted scope

Shadowsocks records using the Phase 6C A–C option set are accepted from local
inline and file proxy providers and can be expanded into a `select` group. The
controller exposes provider ownership plus the member's Shadowsocks type and
UDP/UoT capability, and a selector mutation immediately directs new TCP and
new UDP sessions through the chosen provider member. This reuses the tested
generic provider/group boundaries; it does not duplicate protocol dispatch or
introduce a Shadowsocks-specific provider abstraction.

`compat/scripts/phase6c_shadowsocks_provider.py` gives Go and Rust identical
inline and file providers backed by two deterministic local SS authorities.
It compares provider/member and group controller summaries, selects each member
in turn, and proves domain TCP plus IPv4 UDP echo through both selections. The
authorities use different ports and passwords, and the first is stopped before
the second selection, so successful wire relay proves the selected provider
record reaches the native SS adapter.

This gate does not claim HTTP-provider download/refresh/cache or automatic
health behavior for Shadowsocks members. Those lifecycle paths, UoT, plugins,
2022, IPv6 UDP, inbound/server mode and shared dialer/transport composition
remain separate work.

### Phase 6C-E accepted scope

An HTTP proxy provider may initially download a Shadowsocks member, persist its
payload, replace that member transactionally through the manual provider refresh
endpoint and restore the fresh cached member on process restart without a
successful network fetch. The selected member's new TCP and UDP sessions use
the refreshed server credentials immediately. Provider health checks open the
configured HEAD request through the native SS TCP adapter and publish the
result in the member's standard history and per-URL state.

`compat/scripts/phase6c_shadowsocks_http_provider.py` starts independent A and
B SS authorities with different ports and passwords. It proves initial A TCP/
UDP relay, refreshes the same member name to B, stops A and proves B relay,
restarts each product while the provider endpoint returns 500 and proves the
fresh B cache is retained. Finally it invokes provider healthcheck and requires
a successful history entry for a deterministic local 204 endpoint reached
through B. Cache bytes, controller capability and process survival are compared
as well.

This does not re-run the generic provider's scheduled refresh, ETag, malformed/
oversized rollback, concurrent reload or transform corpus with SS payloads;
those remain bounded integration evidence rather than protocol implementation.
UoT, plugins, 2022, IPv6 UDP, inbound/server direction and shared dialer/
transport composition also remain separate gates.

### Phase 6C-F accepted scope

The existing SIP004 AEAD Shadowsocks client may opt into sing-compatible
UDP-over-TCP with `udp-over-tcp: true`. An omitted or zero
`udp-over-tcp-version` selects legacy v1, explicit versions 1 and 2 are
accepted, and every other version is rejected as the pinned Go oracle rejects
it. The option only changes UDP routing when `udp: true`; TCP remains on the
existing SIP004 stream path. Controller member views report the configured UoT
capability.

The official `shadowsocks` crate continues to own encryption and SIP004 TCP
framing. It does not expose sing UoT, while available AnyTLS-specific and
generic UDP-over-TCP crates do not provide the oracle's v1/v2 non-connect wire
format over an arbitrary encrypted stream. A narrow outbound adapter therefore
owns only the two magic destinations, the v2 request prefix and the tested
address/length datagram envelope. Product DNS policy resolves UoT destinations
before framing, matching the oracle, and the normal bounded UDP session queue,
cancellation, tracker and idle timeout remain in force.

`compat/scripts/phase6c_shadowsocks_uot.py` compares accepted/rejected version
configuration, controller `udp`/`uot` fields, v1 and v2 magic-address selection,
IPv4 and domain-originated datagrams, multi-packet session reuse and process
survival. Its deterministic authority terminates the official Shadowsocks TCP
stream and logs the negotiated UoT version before relaying framed datagrams to
a local UDP echo server.

Phase 6C-F does not add plugin transports, stream/extra/2022 ciphers, IPv6 UDP,
inbound/server direction, UoT connect mode or shared dialer/transport
composition. Those remain independent gates.

### Phase 6C-G accepted scope

The client cipher set adds the eight legacy stream methods implemented by both
the pinned Go oracle and the selected official Rust library:
`aes-128/192/256-ctr`, `aes-128/192/256-cfb`, `rc4-md5` and
`chacha20-ietf`. They use the existing Shadowsocks TCP and native UDP adapter
boundaries; enabling the library's stream-cipher feature is the only protocol
implementation change. Configuration continues to reject methods that have no
tested Rust implementation.

`compat/scripts/phase6c_shadowsocks_legacy.py` starts a fresh official-library
authority and product generation for every method. It compares domain TCP,
large IPv4 TCP framing, half-close delivery, IPv4 and domain-originated native
UDP relay, and process survival for Go and Rust. This makes every newly accepted
method carry both config and wire evidence instead of relying on a library
method-name lookup.

Go's `chacha20`, `xchacha20`, `aes-192-gcm` and broader nonstandard AEAD set are
not implemented by this Rust dependency and remain rejected. Plugins,
Shadowsocks 2022, IPv6 UDP, inbound/server direction and common dialer/
transport composition remain separate gates.

### Phase 6C-H accepted scope

The non-2022 AEAD client matrix adds the five extra methods implemented by both
the pinned Go oracle and the official Rust library:
`xchacha20-ietf-poly1305`, `aes-128-ccm`, `aes-256-ccm`,
`aes-128-gcm-siv` and `aes-256-gcm-siv`. The official library's extra-AEAD
feature supplies their cryptography and existing TCP/native-UDP adapters supply
the data plane; no product cipher implementation is introduced.

`compat/scripts/phase6c_shadowsocks_extra_aead.py` reuses the deterministic
Phase 6C-G lifecycle and starts a fresh authority/product pair for every method.
It compares domain and large IPv4 TCP relay, half-close response delivery,
IPv4 and domain-originated UDP relay, and process survival.

Go-only `aes-192-ccm`, ChaCha8/XChaCha8, AEGIS, AEZ, Deoxys, LEA, Ascon and
other methods remain rejected. Shadowsocks 2022 and plugins remain separate
protocol/transport gates, as do IPv6 UDP and inbound/server direction.

### Phase 6C-I accepted scope

The Shadowsocks 2022 TCP client accepts the three standard methods shared by
the pinned Go oracle and official Rust library:
`2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm` and
`2022-blake3-chacha20-poly1305`. Configuration validates a single standard
base64 PSK with the method's exact 16- or 32-byte decoded length. EIH identity
key chains are deliberately outside this first 2022 slice.

`compat/scripts/phase6c_shadowsocks_2022.py` compares valid and malformed key
acceptance, then runs each method against an independent official-library
authority. Domain TCP, 128 KiB IPv4 TCP, half-close response delivery and
process survival must match.

Native 2022 UDP is not enabled. During development, the pinned Go oracle's
`sing-shadowsocks2` client panicked at `clientPacketConn.readPacket` when it
received the first AES-2022 UDP response from the official Rust authority due
to a nil `remoteCipher`. Rust therefore rejects `udp: true` for these methods
until a deterministic cross-implementation oracle can verify the path. The
2022-extra methods, EIH, plugins, IPv6 UDP and server direction remain separate
gates.

### Phase 6C-J accepted scope

The Shadowsocks 2022 client adds single-hop Extensible Identity Headers for
the AES-128-GCM and AES-256-GCM methods. Configuration accepts exactly
`iPSK:uPSK`; both standard-base64 components must decode to the method's exact
16- or 32-byte key length. The existing official Shadowsocks library owns EIH
framing and cryptography behind the tested outbound adapter boundary.

`compat/scripts/phase6c_shadowsocks_2022_eih.py` compares the pinned Go oracle
and Rust config decisions, then runs both AES methods against an independent
official-library authority configured with the server PSK and one named user.
Domain TCP, 128 KiB IPv4 TCP, half-close delivery and process survival must
match.

ChaCha20-2022 EIH and AES chains with more than one identity key remain
rejected. Multi-hop EIH, native 2022 UDP, 2022-extra methods, plugins, IPv6 UDP
and server direction remain separate gates.

### Phase 6C-K accepted scope

The client cipher set adds `2022-blake3-chacha8-poly1305` through the official
library's 2022-extra feature. Configuration requires one standard-base64
32-byte PSK and rejects EIH and native UDP. The differential uses an
independent official-library authority and compares domain TCP, 128 KiB IPv4
TCP, half-close delivery and process survival.

### Phase 6C-L accepted scope

The shared pre-2022 UDP path accepts explicit IPv6 destinations when global
IPv6 is enabled. `compat/scripts/phase6c_shadowsocks_ipv6_udp.py` compares
mixed and SOCKS5 ingress through representative AEAD, stream and extra-AEAD
ciphers, preserving the returned IPv6 source address and payload. Domain
resolution preference, 2022 UDP, plugins and server direction remain separate
gates.

### Phase 6C-M1 accepted scope

A top-level Shadowsocks client may use Mihomo's embedded `plugin: obfs` with
`plugin-opts.mode: http` and an optional `host` (default `bing.com`). A focused
HTTP masking transport wraps the official Shadowsocks TCP stream boundary; it
does not replace cipher or routing policy. The deterministic authority unwraps
the HTTP request independently, verifies the configured Host, and then hands
the byte stream to the official Shadowsocks server implementation.

`compat/scripts/phase6c_shadowsocks_obfs_http.py` compares accepted and
rejected configuration, domain TCP, 128 KiB IPv4 TCP, process survival and the
pinned oracle's lack of response-direction preservation after client
half-close. Native UDP continues to bypass the TCP plugin, matching Go. TLS
simple-obfs, other plugins, provider/plugin combinations and server direction
remain separate gates.

### Phase 6C-M2 accepted scope

The same embedded `plugin: obfs` boundary accepts `plugin-opts.mode: tls`.
Rust emits the pinned Go simple-obfs ClientHello shape, places the first
Shadowsocks bytes in the session-ticket extension, carries the configured Host
as SNI, and frames subsequent traffic as bounded TLS application records. The
test authority independently parses the ClientHello and records before handing
bytes to the official Shadowsocks server.

`compat/scripts/phase6c_shadowsocks_obfs_tls.py` compares custom/default Host
configuration, invalid modes, domain and 128 KiB TCP relay, process survival
and the oracle's lack of half-close preservation. Other SIP003 plugins,
provider/plugin combinations and server direction remain separate gates.

### Phase 6C-M3 accepted scope

A top-level Shadowsocks client may use `plugin: v2ray-plugin` with
`mode: websocket`, plaintext WebSocket and explicit `mux: false`. Host defaults
to `bing.com`; path defaults to `/` and receives a leading slash when omitted.
The product client uses `tokio-tungstenite`, the same WebSocket engine exposed
by Axum, while the independent authority uses Axum's `WebSocketUpgrade` before
passing the binary message stream to the official Shadowsocks server.

`compat/scripts/phase6c_shadowsocks_v2ray_websocket.py` compares the common
configuration and proves exact Host/path, domain TCP, 128 KiB IPv4 TCP,
process survival and the oracle's non-preserved half-close. Default/enabled
mux, TLS, headers, early data and HTTP-upgrade mode remain separate gates.

### Phase 6C-M4 accepted scope

The non-mux v2ray-plugin WebSocket client may set `tls: true` and
`skip-cert-verify`. Rustls wraps the existing platform TCP dial before the
standard WebSocket handshake. The configured Host is both TLS SNI and the
WebSocket Host; global inline `tls.custom-certifactes` roots participate in
verification through the shared TLS client boundary.

`compat/scripts/phase6c_shadowsocks_v2ray_websocket_tls.py` compares trusted
custom-root success, explicit verification bypass, untrusted-certificate
rejection, exact Host/path, domain and 128 KiB TCP, process survival and the
oracle's non-preserved half-close. Mux, headers, client certificates,
fingerprints/name overrides, ECH, early data and raw HTTP-upgrade remain
separate gates.

### Phase 6C-M5 accepted scope — complete v2ray-plugin TCP surface

This gate closes the remaining documented Mihomo `v2ray-plugin` TCP client
surface in one vertical slice. It adds custom headers and Host override,
Go-compatible default single-session mux framing, `path?ed=N` lazy early data,
raw HTTP Upgrade and fast-open, TLS verification-name override, DER SHA-256
certificate pinning, inline client certificate/key authentication, and ECH
from either inline configuration or the existing DNS HTTPS-record resolver.
WebSocket framing remains library-backed by Tungstenite; Axum/Hyper owns the
test-side upgrade boundary and `httparse` is used only at the raw-upgrade
framing boundary.

`compat/scripts/phase6c_shadowsocks_v2ray_plugin.py` compares Go and Rust for
configuration acceptance plus real TCP relay through ordinary WebSocket,
normal/fast raw upgrade, custom headers, default mux, early data, name override,
certificate pinning, mTLS and a Go authority that rejects TLS connections where
ECH was not accepted. A second ECH case proves that `query-server-name` uses
`proxy-server-nameserver`, not the ordinary resolver, before completing the
same ECH-required TLS relay. v2ray-plugin does not wrap native
Shadowsocks UDP in the Go implementation, so UDP is not part of this plugin
surface. Rust deliberately splits writes larger than 65,535 bytes into valid
mux frames instead of reproducing the pinned Go writer's corrupt-frame edge.
This documented safety divergence is not normalized or presented as exact
wire parity for that invalid edge.

### Phase 6C-M6 accepted scope — Shadowsocks ShadowTLS client

A top-level Shadowsocks outbound may use native `plugin: shadow-tls` v1, v2 or
v3 over the declared SS2022 TCP path. The focused client owns the ShadowTLS
session-id authentication, camouflage TLS 1.2/1.3 relay and post-handshake
HMAC/XOR framing while the existing Shadowsocks adapter continues to own SS
encryption, routing and lifecycle.

`compat/scripts/phase6c_shadowsocks_shadow_tls.py` is the protocol gate for
configuration, domain and large-payload TCP relay, process survival and the
pinned oracle's half-close behavior. The separate
`compat/scripts/phase6c_shadowtls_clienthello_regression.py` records each
runtime's production ClientHello baseline; it is not Go/Rust fingerprint wire
parity. The Rust path now advertises the complete 16-suite Chrome 133 cipher
list, but the ShadowTLS wrappers still produce different extension sets.
Unsupported fingerprint names are rejected instead of silently falling back.

This phase does not claim exact Chrome fingerprint parity, native 2022 UDP,
multi-hop EIH, inbound/server behavior or other shared security consumers.

### Phase 6C-N accepted scope — Shadowsocks inbound first server slice

This gate introduces the first named server-direction slice. It accepts the
legacy `ss-config` URI and a named `listeners` entry with
`type: shadowsocks`, one IP address and one port. The external path starts with
an encrypted Shadowsocks client connection and ends at an observable TCP or
UDP result selected by the existing rule and outbound engines.

The declared data-plane scope is:

- representative SIP004 AEAD and legacy stream TCP, SS2022 TCP, and pre-2022
  native UDP;
- UoT v1 and v2 non-connect framing;
- DIRECT, DNS, SOCKS5, Shadowsocks and Shadowsocks-UoT UDP targets;
- named simple-obfs HTTP/TLS server wrapping;
- ShadowTLS v3 authenticated TCP, plain-TLS fallback, concurrent fallback and
  SS accepts, proxy-observed leaf/group `handshake.proxy`, and empty-proxy
  routing with `IN-TYPE,INNER` distinct from the outer Shadowsocks flow;
- password-identity reload while fallback is active, bounded shutdown and
  fail-closed rejection of unimplemented listener/security fields.

`compat/scripts/phase6c_shadowsocks_inbound.py` is the Go/Rust differential
gate. A valid result must prove the selected handshake proxy observed the
authenticated CONNECT, make an incorrect `SHADOWSOCKS` type reject the
camouflage handshake destination, and change the listener reload identity
before requiring replacement credentials. ShadowTLS `IN-USER` and SS2022 EIH
inbound remain explicitly Rust-only evidence because the pinned Go paths do
not expose equivalent behavior; they are not normalized into parity.

The exit checks are the repository-wide fmt, clippy and test gates plus a
passing corrected Phase 6C-N differential on a declared platform. Until the
corrected differential passes, status remains "implemented; validation
pending".

This phase does not claim port lists/ranges, common named-listener `rule`,
`proxy` or `routing-mark` fields, `mux-option`, UoT v2 connect mode, SS2022
UDP, the complete inbound cipher matrix, ShadowTLS v1/v2 or advanced SNI
selection, ResTLS, JLS, KCP-TUN, exact UDP timeout/socket parity, or full
cross-platform runtime evidence. Those fields are rejected when necessary so
an unimplemented behavior cannot be accepted silently. The common listener
`proxy` gap is distinct from the implemented
`shadow-tls.handshake.proxy` field.

### Phase 6D-A accepted scope — VMess AEAD native-TCP client

This slice changes inventory rows `CFG-03` and `OUT-07`, and only the
compatibility-matrix rows **Proxies and built-in proxy insertion**, **VMess**,
**Darwin arm64 — Phase 6D-A VMess AEAD native TCP** and
**Linux amd64 — Phase 6D-A VMess AEAD native TCP**. `OUT-22` remains open:
this phase deliberately does not add or claim a shared outer transport.

The external path starts with a top-level YAML `type: vmess` proxy consumed
directly and through one selector/file-provider path, enters through the
existing mixed HTTP or SOCKS listener, selects the VMess member through an
existing rule/group, and ends at an observable TCP echo result behind a local
VMess AEAD authority. The accepted protocol/configuration scope is:

- `server`, nonzero `port`, RFC 4122 `uuid`, `alterId: 0`, and
  `cipher: auto`;
- VMess AEAD request/response headers and AEAD body records over a native TCP
  transport with no TLS or transport plugin;
- domain and IPv4 destinations, binary small/large bidirectional relay,
  connection failure, wrong credentials, server close and bounded process
  shutdown;
- fail-closed rejection of unsupported VMess fields and values, including
  nonzero `alterId`, UDP, TLS, non-TCP `network`, transport/security options
  and unknown fields;
- exact controller capability fields and selector/provider membership already
  shared by implemented adapters.

`compat/scripts/phase6d_vmess_tcp.py` is the Go/Rust differential gate. Both
clients run the same generated configuration against the same deterministic
local authority. The authority independently opens the request header,
validates the destination and records, and emits a conforming response; unit
tests also pin KDF, Auth ID, header layout, address encoding, response
verification and record nonces. Random Auth IDs, nonces, padding and timestamps
are validated structurally rather than normalized into byte equality.

No narrowly scoped, maintained embeddable VMess client crate was available at
the phase boundary. Depending on an entire alternate proxy core would also
import unrelated configuration, routing and transport policy. The product
therefore keeps a small adapter boundary and uses maintained RustCrypto
primitives (`aes`, `aes-gcm`, `chacha20poly1305`, `md-5`, `sha2`, `sha3`)
rather than
implementing cryptographic primitives. This decision must be revisited before
expanding beyond the declared protocol core.

This phase does not claim `cipher` modes beyond the oracle behavior selected by
`auto`, legacy VMess headers or AlterID, UDP/XUDP/packet-address modes,
authenticated-length/global-padding, TLS, WebSocket, HTTP, HTTP/2, gRPC,
HTTPUpgrade, mKCP, Mekya, Reality, ShadowTLS, ReSTLS, JLS, TLSMirror, mux,
health-check breadth, VMess inbound/server behavior or cross-platform runtime
parity. Every excluded field is rejected rather than silently ignored.

### Phase 6D-B accepted scope — explicit VMess AEAD framing options

This slice continues inventory rows `CFG-03` and `OUT-07`, and only the
compatibility-matrix rows **Proxies and built-in proxy insertion**, outbound
**VMess**, **Darwin arm64 — Phase 6D-B VMess explicit AEAD** and
**Linux amd64 — Phase 6D-B VMess explicit AEAD**. It does not advance
`OUT-22` or any inbound row.

The external path remains mixed HTTP/SOCKS TCP to a native-TCP VMess client and
the deterministic local authority. The additional accepted surface is:

- explicit case-insensitive `cipher: aes-128-gcm` and
  `cipher: chacha20-poly1305`, while retaining explicit `auto`;
- `global-padding` and `authenticated-length`, independently and together,
  including the oracle's shared SHAKE stream ordering and per-record AEAD
  length nonces;
- domain, IPv4 and IPv6 destination encoding across both explicit ciphers;
- small and multi-record bidirectional relay, half-close, malformed-option
  rejection and process survival through the existing lifecycle boundary.

`compat/scripts/phase6d_vmess_aead.py` is the Go/Rust differential gate. It
runs every explicit cipher × framing-option combination through the same
independent Go authority, including a 128 KiB record sequence and an explicit
IPv6 destination. Focused Rust tests separately verify ordinary masked length,
global-padding ordering and authenticated-length tamper rejection.

This phase still rejects `none`, `zero`, `aes-128-cfb`, nonzero AlterID,
UDP/XUDP/packet addressing, TLS, every outer transport/security plugin and mux.
Those are separate vertical gates and are not implied by explicit AEAD framing
parity.

### Phase 6D-C accepted scope — remaining AlterID-zero native-TCP security modes

This slice continues inventory rows `CFG-03` and `OUT-07`, and only the
compatibility-matrix rows **Proxies and built-in proxy insertion**, outbound
**VMess**, **Darwin arm64 — Phase 6D-C VMess native-TCP security modes** and
**Linux amd64 — Phase 6D-C VMess native-TCP security modes**. It does not
advance `OUT-22`, any inbound row, or the legacy-header/nonzero-AlterID gate.

The external path remains mixed HTTP/SOCKS TCP to a native-TCP VMess client and
the deterministic independent Go authority. This slice completes the oracle's
AlterID-zero `cipher` vocabulary:

- `none` and its `zero` alias use VMess security value 5 and an unframed raw TCP
  body after the AEAD request/response headers;
- `aes-128-cfb` uses security value 1, continuous AES-128-CFB encryption and
  length-prefixed FNV-1a-protected body chunks;
- cipher labels remain case-insensitive and controller/config views preserve a
  normalized label;
- the oracle accepts `global-padding` and `authenticated-length` on these
  non-AEAD modes but deliberately does not put those flags on the wire; Rust
  reproduces that observable behavior instead of applying AEAD framing;
- domain, IPv4 and IPv6 destinations, small and 128 KiB multi-chunk relay,
  half-close, malformed security rejection and process survival are covered.

`compat/scripts/phase6d_vmess_security.py` is the Go/Rust differential gate.
RustCrypto's maintained `cfb-mode` crate owns streaming CFB state; the local
adapter owns only VMess chunk length, checksum and lifecycle policy. This is a
protocol-compatibility dependency with MIT OR Apache-2.0 licensing, Rust 1.56
MSRV and portable `no_std` core support.

Nonzero AlterID/legacy request headers and response-key derivation, UDP/XUDP,
packet addressing, TLS, WebSocket/HTTP/H2/gRPC/mKCP/Mekya transports and mux
remain independent later gates.

### Phase 6D-D accepted scope — legacy AlterID native-TCP client

This slice continues inventory rows `CFG-03` and `OUT-07`, and only the
compatibility-matrix rows **Proxies and built-in proxy insertion**, outbound
**VMess**, **Darwin arm64 — Phase 6D-D VMess legacy AlterID native TCP** and
**Linux amd64 — Phase 6D-D VMess legacy AlterID native TCP**. It does not
advance `OUT-22`, any inbound row, UDP/XUDP, packet addressing, mux or an outer
transport/security layer.

The external path remains mixed HTTP/SOCKS TCP to the native-TCP VMess client
and the independent Go VMess authority. The accepted configuration and wire
scope is:

- positive signed `alterId` values select the oracle's legacy-header path; the
  numeric count is retained in configuration, while the client wire behavior
  uses the first UUID-derived AlterID exactly as `sing-vmess` 0.2.5 does;
- the request starts with HMAC-MD5(AlterID, Unix timestamp), followed by the
  ordinary request plaintext encrypted with AES-128-CFB under the command key
  and the four-times timestamp MD5 IV;
- the response header uses MD5-derived body key/IV and AES-128-CFB; for
  `aes-128-cfb`, that response cipher stream continues into the first body
  frame instead of being restarted;
- all Phase 6D-A–C security labels and framing combinations remain available,
  with domain, IPv4 and IPv6 targets, small/128 KiB relay and half-close;
- zero `alterId` continues to use the AEAD header path and existing Phase
  6D-A–C gates remain mandatory regressions.

`compat/scripts/phase6d_vmess_alterid.py` is the Go/Rust differential gate. It
runs representative positive counts against an authority provisioned with the
same derived AlterID set and covers every supported body security mode. The
standard HMAC/MD5/AES-CFB primitives remain library-owned; local code owns only
VMess key derivation, header layout and the response cipher-continuation rule.

Negative `alterId`, UDP/XUDP, packet addressing, TLS,
WebSocket/HTTP/H2/gRPC/mKCP/Mekya transports, mux and VMess inbound/server
behavior remain outside this slice.

### Phase 6D-E accepted scope — VMess UDP packet modes over native TCP

This slice continues inventory rows `CFG-03` and `OUT-07`, and only the
compatibility-matrix rows **Proxies and built-in proxy insertion**, outbound
**VMess**, **Darwin arm64 — Phase 6D-E VMess UDP packet modes** and
**Linux amd64 — Phase 6D-E VMess UDP packet modes**. Existing SOCKS5 UDP
listener/NAT/rule behavior is reused and is not re-claimed as a new inbound
implementation. `OUT-22`, TLS/outer transports, TCP mux and VMess inbound remain
outside this phase.

The accepted path is YAML `udp: true` through mixed/SOCKS5 UDP, rules and one
native-TCP VMess association to the independent Go authority:

- ordinary VMess UDP uses command 2 and one fixed resolved IP destination per
  association; writes to another destination fail closed as in the Go adapter;
- `packet-addr: true` and `packet-encoding: packetaddr|packet` target
  `sp.packet-addr.v2fly.arpa:443` and prefix every body datagram with its IPv4
  or IPv6 address and port;
- `xudp: true` and `packet-encoding: xudp` use VMess command 3 to
  `v1.mux.cool:666`, encode new/keep UDP frames and allow multiple destinations
  on one client association; XUDP takes precedence when both packet switches
  are set, matching the oracle;
- all Phase 6D-A–D body security and AlterID header modes remain usable;
  focused differential cases cover AEAD/legacy headers, AEAD, raw and CFB body
  modes rather than multiplying every already-proven cross-product;
- deterministic tests cover IPv4/IPv6, domain-to-IP resolution, association
  reuse, multi-destination packet modes, controller `udp`/`uot`/`xudp` shape,
  bounded datagrams, malformed packet-mode rejection and process survival.

`compat/scripts/phase6d_vmess_udp.py` is the Go/Rust differential gate. The Go
authority uses `sing-vmess` server, packet-address and XUDP implementations as
an independent decoder/encoder. Rust owns VMess packet-mode framing while the
existing RustCrypto-backed body layer retains encryption and authentication.

This phase does not claim FQDN payloads in packet-address mode, jumbo datagrams
above the VMess 15,000-byte body limit, negative AlterID, TLS,
WebSocket/HTTP/H2/gRPC/mKCP/Mekya transports, general TCP mux or VMess inbound.

### Phase 6D-F accepted scope — VMess TLS and WebSocket TCP transports

This slice continues inventory rows `CFG-03` and `OUT-07`, begins VMess reuse
of `OUT-22`, and only changes the compatibility-matrix rows **Proxies and
built-in proxy insertion**, outbound **VMess**, **Shared outbound
transport/security variants**, **Darwin arm64 — Phase 6D-F VMess TLS and
WebSocket TCP** and **Linux amd64 — Phase 6D-F VMess TLS and WebSocket TCP**.
It does not expand the existing listener, rule or controller API claims.

The accepted external paths are YAML through mixed HTTP/SOCKS TCP and rules to:

- native TCP VMess wrapped directly in standard TLS;
- plaintext RFC 6455 WebSocket carrying VMess binary records;
- verified or explicitly insecure WebSocket-over-TLS with `http/1.1` ALPN;
- `network: tcp|ws`, `tls`, `servername`, `skip-cert-verify`,
  `name-cert-verify`, inline custom roots, and `ws-opts.path` plus string
  `ws-opts.headers` configuration;
- explicit `servername` and WebSocket `Host` TLS-name selection, matching the
  pinned oracle in both exercised branches;
- every Phase 6D-A–D VMess security/AlterID body mode above the transport,
  represented by focused AEAD and legacy cases instead of repeating the full
  already-proven cross-product.

`compat/scripts/phase6d_vmess_websocket.py` is the Go/Rust differential gate.
It uses the independent Go `sing-vmess` authority behind standard-library TLS
and an independently parsed RFC 6455 server boundary. The gate compares
configuration acceptance, exact WebSocket Host/path and TLS SNI observations,
domain and large IPv4 relay, half-close outcome, trusted/custom-root,
skip-verification and untrusted failure lifecycle, and process survival.

This phase deliberately rejects UDP over WebSocket, WebSocket early data and
raw HTTP-upgrade variants. Custom ALPN, ECH, client-fingerprint emulation,
ShadowTLS/ReSTLS/JLS/Reality/TLSMirror, HTTP/2, gRPC/Gun, xHTTP/H3, mKCP,
Mekya, general TCP mux and VMess inbound remain later `6D`/`7T` gates.

### Phase 6D-G accepted scope — VMess WebSocket early data and HTTP Upgrade

This slice continues inventory rows `CFG-03`, `OUT-07` and `OUT-22`, and only
changes the compatibility-matrix rows **Proxies and built-in proxy insertion**,
outbound **VMess**, **Shared outbound transport/security variants**, **Darwin
arm64 — Phase 6D-G VMess WebSocket variants** and **Linux amd64 — Phase 6D-G
VMess WebSocket variants**. Existing listener, rule, controller and UDP claims
do not expand.

The accepted external paths are YAML through mixed HTTP/SOCKS TCP and rules to:

- RFC 6455 VMess with `max-early-data` placed in either an explicitly named
  request header or appended to the configured URL path;
- the Xray-compatible `path?ed=N` convention, which removes `ed`, canonicalizes
  the remaining query and places early data in `Sec-WebSocket-Protocol`;
- unframed `v2ray-http-upgrade` with ordinary response validation and the
  `v2ray-http-upgrade-fast-open` write-before-response variant;
- raw HTTP Upgrade combined with the same explicit/query early-data behavior;
- plaintext and WSS outer transports, with representative zero and positive
  AlterID/security modes rather than repeating the Phase 6D-A–F cross-product.

`compat/scripts/phase6d_vmess_websocket_variants.py` is the Go/Rust
differential gate. The independent Go authority parses the HTTP request,
extracts and decodes early VMess bytes before invoking `sing-vmess`, then uses
either RFC 6455 framing or the unframed upgraded stream. It compares exact
Host/request-target/early-data placement, raw-versus-framed mode, large relay,
half-close outcome, TLS use, fast-open lifecycle and process survival.

This phase does not claim UDP over WebSocket, certificate pinning/client
identity, custom ALPN, ECH, fingerprint emulation, ShadowTLS/ReSTLS/JLS/
Reality/TLSMirror, HTTP/2, gRPC/Gun, xHTTP/H3, mKCP, Mekya, general TCP mux or
VMess inbound. Invalid header names/values and negative early-data sizes fail
closed; broader Go acceptance/error wording remains outside this gate.

### Phase 6D-H accepted scope — VMess HTTP/1 obfuscation and HTTP/2 streams

This slice continues inventory rows `CFG-03`, `OUT-07` and `OUT-22`, and only
changes the compatibility-matrix rows **Proxies and built-in proxy insertion**,
outbound **VMess**, **Shared outbound transport/security variants**, **Darwin
arm64 — Phase 6D-H VMess HTTP transports** and **Linux amd64 — Phase 6D-H
VMess HTTP transports**. Existing listener, rule, controller and UDP claims do
not expand.

The accepted external paths are YAML through mixed HTTP/SOCKS TCP and rules to:

- `network: http`, where the first VMess write is the exact body of one
  HTTP/1.1 request and later writes are unframed; method, path candidates,
  multi-value headers and Host override follow the pinned oracle;
- plaintext HTTP and HTTPS outer connections, with HTTP/1.1 ALPN constrained
  for TLS;
- `network: h2`, where one HTTP/2 PUT request carries the VMess byte stream in
  its request DATA frames and the response DATA frames form the receive stream;
- configured/default HTTP/2 Host and path, the oracle's `https` pseudo-scheme
  over plaintext h2c or TLS, SNI/certificate policy, and negotiated `h2` ALPN
  for TLS;
- representative zero and positive AlterID/security modes above both transports,
  plus large relay, the oracle's response-dropping half-close behavior and
  transport-failure process survival.

`compat/scripts/phase6d_vmess_http.py` is the Go/Rust differential gate. The
independent Go authority records HTTP/1 request line, Host, selected path,
headers and exact first-body boundary, or HTTP/2 method/authority/path,
ALPN and bidirectional stream lifecycle before invoking `sing-vmess`. Fixed
single-element path/Host lists make the wire comparison deterministic; list
selection is separately contract-tested as membership rather than order.

This phase does not claim VMess UDP over HTTP/H2, HTTP connection pooling or
multi-stream reuse, certificate pinning/client identity, custom ALPN, ECH,
fingerprint emulation, ShadowTLS/ReSTLS/JLS/Reality/TLSMirror, gRPC/Gun,
xHTTP/H3, mKCP, Mekya, general TCP mux or VMess inbound. Invalid methods,
paths, header names/values and unsupported transport combinations fail closed;
broader Go acceptance/error wording remains outside this gate.

### Phase 6D-I accepted scope — VMess gRPC/Gun single streams

This slice continues inventory rows `CFG-03`, `OUT-07` and `OUT-22`, and only
changes the compatibility-matrix rows **Proxies and built-in proxy insertion**,
outbound **VMess**, **Shared outbound transport/security variants**, **Darwin
arm64 — Phase 6D-I VMess gRPC/Gun** and **Linux amd64 — Phase 6D-I VMess
gRPC/Gun**. Existing listener, rule, controller and UDP claims do not expand.

The accepted external path is YAML through mixed HTTP/SOCKS TCP and rules to
one Gun stream per application connection:

- `network: grpc` over plaintext h2c or TLS with negotiated `h2` ALPN;
- HTTP/2 `POST`, `Content-Type: application/grpc`, oracle-default
  `grpc-go/1.36.0` User-Agent, configured User-Agent override and the oracle's
  `https` pseudo-scheme even over h2c;
- default `GunService` and configured service names mapped to
  `/<service>/Tun`, while names beginning with `/` remain exact custom paths;
- Gun's five-byte gRPC prefix plus protobuf field-1 varint envelope around each
  VMess write, with the inverse envelope removed from response DATA frames;
- default authority selection (`server:port`) and explicit `servername`, plus
  representative zero/positive AlterID and raw/AEAD/CFB body modes, large
  relay, close behavior and process survival.

`compat/scripts/phase6d_vmess_grpc.py` is the Go/Rust differential gate. Its
independent Go authority validates method, authority, path, content type,
User-Agent, TLS ALPN and Gun frame boundaries before invoking `sing-vmess`.
It does not reuse Mihomo's Gun client/server implementation.

This gate deliberately exercises only the default zero-valued `ping-interval`,
`max-connections`, `min-streams` and `max-streams` configuration. Stateful
transport reuse, concurrent stream balancing, keepalive ping and pool lifecycle
advance independently in Phase 6D-J below. VMess UDP over Gun, advanced
TLS/camouflage, xHTTP/H3, mKCP, Mekya, general TCP mux and VMess inbound remain
outside Phase 6D-I.

### Phase 6D-J accepted scope — VMess gRPC/Gun pooling and health ping

This slice continues inventory rows `CFG-03`, `OUT-07` and `OUT-22`, and only
changes the compatibility-matrix rows **Proxies and built-in proxy insertion**,
outbound **VMess**, **Shared outbound transport/security variants**, **Darwin
arm64 — Phase 6D-J VMess gRPC/Gun pool** and **Linux amd64 — Phase 6D-J VMess
gRPC/Gun pool**. Existing listener, rule, controller and UDP claims do not
expand.

The accepted external path remains YAML through mixed HTTP/SOCKS TCP and rules,
but concurrent application connections now share and balance reusable Gun
transports:

- all-zero pool controls preserve the oracle default of one physical HTTP/2
  connection with independent concurrent logical streams;
- positive `max-connections` and `min-streams` use the least-active transport
  and create connections at the same threshold as Go;
- when `max-connections` is not positive, positive `max-streams` caps logical
  streams per physical connection with the same least-active selection;
- signed pool values are accepted, including Go's non-positive disable
  semantics; stream leases are released on every success/error/drop path;
- positive `ping-interval` emits HTTP/2 health PING frames, requires an ACK
  within the oracle's 15-second bound and retires failed transports; and
- successful generation replacement retires the previous generation's idle
  pool without aborting logical streams that are still active.

`compat/scripts/phase6d_vmess_grpc_pool.py` is the Go/Rust differential gate.
Its independent authority releases fixed concurrent-stream barriers, assigns
physical-connection identities and parses raw h2c PING frames. The gate proves
one-connection default reuse, the `2/2` connection/stream threshold, a
one-stream-per-connection cap, ping followed by physical-connection reuse,
signed option acceptance and process survival.

This slice uses the maintained `h2` codec directly; a generated gRPC RPC library
would add HTTP/2/protobuf policy while Gun requires only a byte-stream envelope
and Mihomo-specific pool selection. Exact frame-activity-based ping scheduling,
ACK-timeout fault injection and reload during live streams remain release/stress
gates. VMess UDP over Gun, advanced TLS/camouflage, xHTTP/H3, mKCP, Mekya,
general TCP mux and VMess inbound remain outside Phase 6D-J.

### Phase 6D-K/L accepted scope — VMess mKCP and Mekya TCP

These two adjacent transport slices continue inventory rows `CFG-03`, `OUT-07`
and `OUT-22`. They only change the compatibility-matrix rows **Proxies and
built-in proxy insertion**, outbound **VMess**, **Shared outbound
transport/security variants**, and the corresponding Darwin/Linux Phase 6D-K/L
platform rows. Listener, controller, rule and UDP claims do not expand.

Phase 6D-K carries one VMess TCP session over V2Ray's custom mKCP wire format:

- typed `mkcp-opts` parsing covers MTU, TTI, capacity, congestion, buffer sizes,
  seed and header, with `network: kcp` retained as an alias;
- the carrier implements V2Ray segment, ACK, retransmit and close messages,
  default simple authentication and seeded AES-128-GCM authentication; and
- no-op, SRTP, uTP, WeChat-video, DTLS and WireGuard camouflage headers are
  exercised against an independent Go authority.

Phase 6D-L carries the same mKCP packets through Mihomo's Mekya request/response
packet bundles. The production client uses Hyper for HTTP framing and supports
TLS with negotiated HTTP/2 or HTTP/1.1, polling intervals, maximum request size,
long-lived response bodies and H2 pool selection. `mekya-opts.kcp` is normalized
through the same typed mKCP boundary.

`compat/scripts/phase6d_vmess_mkcp_mekya.py` is the shared Go/Rust differential
gate. It validates all camouflage variants, seeded and default authentication,
small and 128 KiB TCP relays, Mekya H2/HTTP1 negotiation, packet aggregation,
pool configuration, independent-authority VMess CONNECT observations and
process survival. Its semantic UDP relay additionally strips the simple
authentication envelope only for inspection and applies the same segment-level
faults to both products: 14% and 25% first-transmission DATA loss with
congestion disabled/enabled, one ACK loss, duplication and reordering. Payload
integrity, retransmission of every dropped segment and a Go-derived runaway
bound must match.

The same gate fixes close semantics to the oracle rather than inventing a
transport FIN that mKCP does not have. For each of mKCP, Mekya H2 and Mekya
HTTP/1.1, ten client write-half closes must produce the oracle's immediate EOF
without an EOF-triggered response, while three peer closes must deliver the
final payload followed by EOF. Focused Rust contracts pin Go's six-state
connection lifecycle, smoothed RTT/RTO, fast-ACK and congestion-window formulas.

This scope does not claim non-native-carrier UDP, an inbound/server endpoint,
randomized long-duration network impairment, xHTTP/H3, advanced TLS camouflage
or general TCP mux.

### Phase 6E-A accepted scope — VLESS version-zero native-TCP client

Phase 6E-A changes the configuration `Proxies and built-in proxy insertion`,
outbound `VLESS` and Darwin/Linux Phase 6E-A rows. It implements one vertical
slice: YAML `type: vless` -> mixed HTTP/SOCKS5 TCP -> rule/group/provider
selection -> VLESS version-zero native TCP -> an independently implemented
authority -> destination TCP. This is the first partial implementation of
inventory row `OUT-08`.

`rewrite-protocol-vless` owns the transport-independent request and response
framing. It preserves the Go oracle's UUID parsing, including UUIDv5 with a nil
namespace for non-UUID user strings; lazily emits the version-zero request with
the first application payload in one write; encodes domain, IPv4 and IPv6
destinations; accepts and consumes response addons; and keeps the TCP
half-close lifecycle explicit. `rewrite-outbound` remains a thin dial facade,
while runtime routing and controller/provider views consume the normalized
typed configuration.

`compat/scripts/phase6e_vless_tcp.py` is the shared Go/Rust differential gate.
Its Python authority is independent of production protocol code and validates
the exact request bytes, command and destination. The gate covers a canonical
UUID and Go-compatible mapped user string, all address types, small and 128 KiB
relays, a non-empty response addon, half-close, provider/selector/controller
views, refused dials, bad response versions, process survival and invalid
configuration. Explicit contracts prevent a matching pair of failures from
being accepted as parity.

This phase accepts only `network: tcp`, `tls: false`, `udp: false`, empty or
`none` encryption and no flow or outer transport. The controller reports the
Go default `xudp: true` capability field, but no UDP/XUDP data path is claimed.
VLESS UDP/packet modes, encryption extensions, TLS, WebSocket/HTTP/H2/gRPC,
Vision, Reality, multiplexing and inbound/server behavior remain later Phase
6E slices. The framing is small and Mihomo-specific enough that no maintained,
narrowly scoped VLESS crate preserves the required lazy-write and oracle UUID
behavior; the local crate uses Tokio primitives and has byte-level contracts.

### Phase 6E-B accepted scope — VLESS native TCP over TLS

Phase 6E-B changes the same configuration and outbound `VLESS` rows plus the
Darwin/Linux Phase 6E-B rows. It composes the Phase 6E-A VLESS v0 session over
the existing maintained rustls carrier: YAML -> mixed TCP -> rule/group -> TCP
dial -> TLS -> VLESS -> destination. The protocol crate remains independent of
certificate and transport policy.

The accepted configuration adds `tls: true`, `servername`/`sni`,
`name-cert-verify`, `skip-cert-verify` and global inline custom roots. Like the
Go oracle, dormant TLS name/verification fields are accepted when TLS is false
and do not wrap the connection. Native VLESS TLS is also used by controller
delay and automatic group health checks. Fingerprint pinning, client
certificates, custom ALPN, ECH and camouflage-specific TLS are not included.

`compat/scripts/phase6e_vless_tls.py` uses Python's TLS stack and an independent
VLESS parser. It compares trusted-root verification, exact ClientHello SNI with
an independent certificate verification name, skip verification, rejection of
an untrusted root and wrong name, large relay, half-close, process survival and
a real controller group health request. Matching failures cannot satisfy the
gate because each product must meet explicit positive and negative contracts.

This phase does not add WebSocket/HTTP/H2/gRPC/xHTTP carriers, Vision, Reality,
VLESS encryption extensions, UDP/XUDP data paths, mux or inbound/server
behavior. No new dependency is introduced: the shared `rewrite-transport` TLS
adapter already owns roots, name policy, rustls configuration and handshake.

### Phase 6E-C–F accepted scope — VLESS transports and UDP

These slices update the configuration **Proxies and built-in proxy insertion**,
outbound **VLESS**, **Shared outbound transport/security variants**, and their
Darwin/Linux Phase 6E platform rows. C–E compose the Phase 6E-A framing with
the existing WebSocket/WSS, HTTP/1/H2 and single-stream gRPC/Gun carriers. F
adds plaintext native-TCP UDP packet-address and XUDP associations. XUDP keeps
a process-stable global ID for each inbound source, and controller capability
fields remain compatible with Go even when a VLESS proxy has `udp: false`.

The four `compat/scripts/phase6e_vless_{websocket,http,grpc,udp}.py` gates are
the acceptance evidence. Phase 6E-F is limited to plaintext native TCP;
composed carrier evidence is added separately in Phase 6E-I. UDP over HTTP/H2,
pooled Gun, xHTTP, encryption, general mux and inbound/server behavior remain
open.

### Phase 6E-G accepted scope — VLESS Vision native TCP/TLS

This slice updates outbound **VLESS** and the Phase 6E-G platform rows. It covers
the protobuf flow addon, bounded padding/end frames, fragmented VLESS response
headers/addons, server UUID validation and unknown-command rejection over
native TLS 1.3. A dedicated record-bounded TLS carrier preserves decrypted
plaintext already buffered by rustls and then switches each direction to the
underlying raw TCP stream after `commandPaddingDirect`.

`compat/scripts/phase6e_vless_vision.py` performs a real nested-TLS exchange
through both Go and Rust. This proves the direct splice rather than merely
observing the Vision command. Its REALITY composition is added in Phase 6E-J;
non-TCP carriers and server mode remain later scopes.

### Phase 6E-H accepted scope — VLESS REALITY native TCP/TLS

This slice updates outbound **VLESS**, **Shared outbound transport/security
variants**, and the Phase 6E-H platform rows. The patched `shadow-rustls` fork
implements REALITY session-ID authentication and verification. Rust accepts
zero-to-eight-byte short IDs like Go and actually enables the only accepted
`client-fingerprint: chrome` profile.

The fork advertises the complete Chrome 133 cipher list and its GREASE,
extension bodies, key shares, ALPS and ECH shape are checked by a normalized
raw-ClientHello Go/Rust differential. The same gate proves authenticated relay,
half-close and both default X25519 and `support-x25519mlkem768` handshakes.
Random values and shuffled middle-extension order are normalized, but semantic
fields are not. Other browser fingerprints, legacy-only TLS 1.2 cipher
selection, non-TCP carriers and server mode remain open. The common
REALITY+Vision composition is accepted separately in Phase 6E-J.

### Phase 6E-I accepted scope — VLESS UDP over common carriers

This slice updates outbound **VLESS**, **Shared outbound transport/security
variants**, and the Phase 6E-I platform rows. It composes the existing XUDP
association with native TLS, plaintext WebSocket and TLS gRPC/Gun. The carrier
is established before VLESS UDP framing, so `tls: true` cannot silently dial
plaintext and WS/gRPC request metadata remains observable.

`compat/scripts/phase6e_vless_udp_carriers.py` compares Go and Rust through an
independent `sing-vless` packet authority. It proves exact TLS SNI/ALPN,
WebSocket Host/path, gRPC path/User-Agent, XUDP destinations and payloads, and
process survival. UDP over HTTP/H2, WSS as a separate matrix point, xHTTP,
Vision/REALITY, pooled gRPC and server mode are not claimed.

### Phase 6E-J accepted scope — VLESS REALITY + Vision

This slice composes the Phase 6E-G record-bounded Vision stream with the Phase
6E-H authenticated REALITY client. REALITY uses the same bounded TLS-record
reader, drains any already-decrypted plaintext, and promotes reads and writes
independently to the underlying raw TCP stream after Vision DIRECT commands.

`compat/scripts/phase6e_vless_reality_vision.py` compares small and large relay,
half-close and a nested TLS 1.3 exchange against a Go `sing-vless` authority
with the same REALITY keys and Vision flow. This is behavioral evidence for the
common native-TCP Chrome-133 combination; other fingerprints, non-TCP
carriers, UDP and server mode remain open.

### Phase 6E-K accepted scope — basic VLESS xHTTP stream-one

This slice adds the common HTTP/2 `stream-one` client over TLS. It accepts only
explicit `xhttp-opts.mode: stream-one`, normalizes the path with Go's trailing
slash behavior, and supports Host/path, string-valued custom headers,
`no-grpc-header` and bounded `x-padding-bytes`. Unsupported modes and unknown
xHTTP fields fail configuration instead of silently degrading.

`compat/scripts/phase6e_vless_xhttp.py` compares Go and Rust request metadata,
TLS SNI/ALPN, fixed padding, small/128-KiB relay and process survival through an
independent HTTP/2 VLESS authority. HTTP/1.1 and HTTP/3, `auto`, `stream-up`,
`packet-up`, XMUX/reuse/download settings, obfuscation-placement controls, UDP,
REALITY composition and server mode remain open.

### Phase 6E-L accepted scope — VLESS gRPC/Gun pool lifecycle

This slice changes outbound **VLESS**, **Shared outbound transport/security
variants**, the Phase 6E platform rows, and the **Differential harness**. VLESS
now uses the same reusable Gun client boundary as VMess. The all-zero default,
`max-connections`/`min-streams`, `max-streams`, signed configuration values and
closed-H2 reconnection are compared in
`compat/scripts/phase6e_vless_grpc_pool.py`. The VLESS gates have their own
Linux x86_64, Windows x86_64 and macOS arm64 CI shard, so unrelated controller
tests cannot consume their execution budget. Native non-gRPC transports and
general-purpose mux are not implied.

### Phase 6E-M accepted scope — common xHTTP modes, REALITY and basic XMUX

This slice extends xHTTP to Go's common HTTP/2 modes: `stream-one`,
`stream-up`, `packet-up`, and `auto` (`packet-up` normally and `stream-one`
with REALITY). Split modes use one physical H2 connection for their download
and upload requests. Basic `reuse-settings.max-concurrency` and
`max-connections` ranges create a reusable cross-session H2 pool with
closed-connection replacement.

Three differentials cover mode selection/chunked upload, one/two-connection
XMUX reuse and reconnection, and authenticated xHTTP-over-REALITY. HTTP/1.1,
H3, download-settings, alternate metadata/data placement, padding obfuscation,
the remaining reuse lifetime/request-count controls and UDP over xHTTP remain
fail-closed and are not claimed.

### Phase 6E-N accepted scope — bounded VLESS production gate

This gate uses Mihomo's maintained `sing-vless` service rather than the small
manual parser. It compares 32 concurrent pooled gRPC streams, 16 concurrent
xHTTP/XMUX streams, 16 rejected HTTP-status sessions, recovery after those
failures, and process survival. A deterministic malformed-response corpus also
proves that truncated and arbitrary VLESS response prefixes finish within a
bounded timeout without panicking.

These are CI-sized regression and pressure gates, not a long-running soak or a
public-Internet interoperability claim. Release qualification still requires
multi-hour churn/packet-loss testing, real external server versions, resource
ceilings, H3, broader xHTTP controls, additional REALITY fingerprints and the
VLESS inbound/server direction.

### Phase 5C1b accepted scope

Selector state now participates in transactional SIGHUP generations. A choice
that remains a member survives reordered/expanded membership even when
`default-selected` differs; malformed configuration leaves both generation and
choice untouched. If the selected member disappears, the pinned oracle falls
back to the new first member rather than reapplying `default-selected`, and
Rust preserves that behavior. `compat/scripts/phase5c_selector_reload.py`
compares controller state and live HTTP/DIRECT routing across all three cases.
Cross-process persistence and nested/provider membership remain later gates.

### Phase 5C2a accepted scope

The first provider vehicle slice loads one or more local YAML files at
configuration validation time. Each file must contain nonempty supported
HTTP/SOCKS5 proxies with globally unique names. A flat selector may append
their ordered members through `use`; after provider readiness, controller
selection drives the existing TCP outbound path. Provider list/detail/member
and health-trigger responses preserve File vehicle fields, provider-name and
file modification time. Group-compatible providers expose only explicit
`proxies`, matching Go rather than leaking `use` members.
`compat/scripts/phase5c_file_provider.py` compares all views and live routing.
Refresh mutation, HTTP vehicles, filters/overrides and persistence remain later
gates.

### Phase 5C2b accepted scope

Manual `PUT /providers/proxies/{name}` refresh reuses the owned configuration
generation transaction. The file is parsed and globally validated first;
provider members and every dependent selector are rebuilt in a cloned config,
then published together. A successful refresh removes old member lookups and
enables selection/routing through the replacement. File, YAML or duplicate
errors return 503 without changing controller views, selection or data-plane
behavior. `compat/scripts/phase5c_provider_refresh.py` compares this lifecycle.
Concurrent/coalesced refresh, connection cleanup, scheduled/file-watch refresh,
HTTP vehicles and persistence remain separate gates.

### Phase 5C2c accepted scope

The first HTTP proxy-provider vehicle accepts a plaintext local URL plus an
explicit cache path. Runtime startup uses Hyper HTTP/1 to fetch an absent
cache through the direct dial path with a four-MiB body bound, parses and
duplicate-checks the complete YAML before publication, atomically writes the
validated bytes, rebuilds dependent group membership and exposes the oracle's
HTTP vehicle REST view. `compat/scripts/phase5c_http_provider.py` runs a local
HTTP authority and authenticated CONNECT proxy, observes the GET target,
cache bytes, provider/group/member views, controller selection and mixed-TCP
routing on Go and Rust.

HTTPS, optional hashed paths, headers, size-limit configuration, provider
proxy/rule routing, stale-cache refresh, intervals, ETag, manual remote update,
failure rollback and concurrent lifecycle behavior remain later gates.

### Phase 5C2d accepted scope

Plaintext HTTP proxy providers now retain their configured second interval and
share one runtime-owned refresh transaction between controller PUT and the
interval scheduler. Each refresh obtains a bounded payload, validates all
provider and dependent-group state, atomically replaces the explicit cache and
only then publishes the new generation. Manual refresh returns 204 after the
new generation is live; malformed YAML and non-success HTTP status return 503
while preserving cache bytes, provider views, group selection and routing.
`compat/scripts/phase5c_http_provider_refresh.py` compares initial-to-replaced
members, cache contents, old-member removal, authenticated TCP forwarding,
manual failure rollback and an autonomous one-second refresh on Go and Rust.

HTTPS, conditional ETag requests, custom headers, hashed default paths,
provider proxy/rule routing, concurrent/coalesced refresh, interval mutation
across SIGHUP and shutdown races remain later gates.

### Phase 5C2e accepted scope

The plaintext HTTP vehicle now carries ordered repeated request-header values,
honors the configured byte limit and participates in the global
`etag-support` switch. A successful response stores its ETag in the active
runtime generation; later manual or scheduled refresh sends `If-None-Match`,
accepts 304 without parsing or changing cache bytes, refreshes cache freshness,
and replaces that ETag only after a changed payload validates and publishes.
Disabled ETag support keeps
all refreshes unconditional. An over-limit response returns the existing 503
class while provider members, selected routing and cache bytes remain intact.
`compat/scripts/phase5c_http_provider_contract.py` compares all of these request
and data-plane observations against Go.

HTTPS, redirect/proxy download policy, global User-Agent interaction, hashed
default cache paths, ETag database/restart interchange, concurrent refresh and
provider override expressions remain later gates.

### Phase 5C2f accepted scope

The CLI now passes its resolved Mihomo home directory into the configuration
layer explicitly for file, base64 and stdin sources. Relative provider paths
are rooted there, and an HTTP provider without `path` uses the oracle's
`proxies/<lowercase URL MD5>` default. The validated first download is written
to that location; a subsequent process loads valid cache bytes before runtime
startup and does not contact a fresh remote while the configured interval is
not stale. Controller PUT after restart still replaces members/cache and a
malformed later response rolls back to that replacement.
`compat/scripts/phase5c_http_provider_cache.py` compares the exact derived path,
request count, restart views, selection and TCP routing against Go.

HTTPS, durable ETag metadata, stale-on-start forced refresh, cache permission/
corruption matrices, provider-aware download routing, concurrent refresh and
override expressions remain later gates.

### Phase 5C2g accepted scope

HTTP provider configuration now records the modification time only after a
cache file parses successfully. The runtime scheduler derives its first delay
from that age: a fresh cache waits for the remaining configured interval,
while a cache older than the interval requests an immediate transactional
refresh. A successful response validates before atomically replacing cache and
members; a non-success response leaves the valid old cache, provider view,
selection and TCP data plane active. An unreadable-as-YAML cache takes the
existing initial remote hydration path and is replaced only by valid remote
bytes. `compat/scripts/phase5c_http_provider_stale.py` compares stale success,
stale HTTP failure and corrupt-cache recovery against the Go oracle.

Cache permission/platform errors, durable ETag database interchange, retry
backoff timing, concurrent/coalesced refresh, HTTPS, provider-aware download
routing and override expressions remain later gates.

### Phase 5C2h accepted scope

The runtime scheduler now keys each pending HTTP-provider deadline by provider
name plus interval, URL, cache path and successfully parsed cache modification
time. A SIGHUP generation that changes that schedule replaces the old deadline
instead of inheriting it. The acceptance gate starts from a fresh 600-second
cache, reloads to one second and observes the new remote member/cache/routing;
it then reloads URL and path onto a deliberately stale valid cache and observes
an immediate request to the replacement source. All publication still uses the
existing validated generation transaction.
`compat/scripts/phase5c_http_provider_reload.py` compares the lifecycle against
the Go oracle.

Zero-interval retirement races, retry backoff timing, concurrent/coalesced
refresh, HTTPS, provider-aware download routing, durable ETag metadata and
override expressions remain later gates.

### Phase 5C3 accepted scope

Proxy providers now cover inline, file, HTTP and HTTPS vehicles for the
currently implemented HTTP/SOCKS5 adapters. Provider-level backtick filters,
name exclusion, type exclusion, regex name replacement and additional
prefix/suffix transforms run before adapter construction. Configured provider
health checks share the existing real HTTP delay engine, including startup,
manual REST, interval, timeout, expected-status and lazy touch behavior. HTTP
cache `ETag` metadata is atomically persisted with the URL and payload digest,
so a post-restart PUT can safely send `If-None-Match`; changed bytes cannot
reuse stale metadata. `compat/scripts/phase5c_provider_features.py`,
`phase5c_provider_https.py` and the extended
`phase5c_http_provider_contract.py` are the differential gates.

Provider `proxy`/`dialer-proxy`, protocol-specific structured overrides,
encrypted subscription payloads and the general `override-expr` language
depend on later outbound/crypto adapter slices and are not claimed by Phase
5C3.

### Phase 5C4 accepted scope

Rule providers cover inline, file, HTTP and HTTPS vehicles; YAML, text and MRS
formats; domain, IP-CIDR and classical behavior; `RULE-SET` evaluation with
`no-resolve`; initial cache reuse; manual REST refresh; interval refresh;
cross-platform file watching; atomic cache replacement and failure rollback.
`/providers/rules` and `PUT /providers/rules/{name}` expose the same declared
snapshot/status contract. `compat/scripts/phase5c_rule_provider.py` and the
HTTPS gate compare routing, REST, cache bytes and lifecycle behavior against
Go.

Provider-aware downloads through a named proxy remain owned by the later
dialer-proxy slice; file/HTTP providers can already feed the Phase 4F14 fake-IP
consumer once that integration is separately gated.

### Phase 5C5 accepted scope

The controller may receive provider updates concurrently, but every candidate
is validated and published through one serialized runtime generation channel.
Valid update bursts converge without corrupting cache/config state; invalid
bursts all roll back to the last valid generation. `notify` watches parent
directories so atomic file replacement is observed on supported desktop
platforms, coalesces event bursts, and rebinds watches on generation changes.
Provider/group schedulers and watchers use cancellation tokens, removed
providers lose REST and health state, and a shutdown deadline aborts only a
task that ignored normal cancellation. `compat/scripts/phase5c_provider_concurrency.py`
is the concurrent PUT, rollback, SIGHUP removal and live-process gate.

This completes Phase 5C for the adapter/rule surface available before Phase 6.
Future proxy protocols add their own provider parsing, override and health
evidence in their owning slices; this statement is not a whole-Mihomo provider
compatibility claim.

### Phase 5C1c accepted scope

Flat select groups may compose explicit proxies and local-file providers with
`filter`, `exclude-filter`, `include-all-proxies`, `include-all-providers` or
`include-all`. Provider matches preserve the pinned oracle's backtick-regex
ordering and de-duplication, while top-level include-all names use the oracle's
sorted inventory. Empty filtered sets expose `empty-fallback`; controller PUT
and mixed TCP routing use the resulting member list. Acceptance in
`compat/scripts/phase5c_group_filters.py` compares all five composition forms
and live authenticated HTTP forwarding. Nested groups, type exclusion,
automatic strategies and health/status policies remain separate gates.

### Phase 5C1d accepted scope

Select groups may reference other select groups before or after their own YAML
entry. The complete dependency graph is cycle-checked before configuration
publication. TCP routing recursively resolves every current selection into
HTTP, DIRECT or REJECT, and controller snapshots project nested UDP support and
compatible-provider members. `compat/scripts/phase5c_nested_selector.py`
compares forward-reference startup, both inner and outer live mutations,
direct-versus-proxied wire behavior and two-node cycle rejection. Automatic
group types, cross-process persistence and provider-driven nested reloads remain
separate gates.

### Phase 5C1e accepted scope

Select groups apply case-insensitive `exclude-type` after name filtering across
explicit built-ins, configured HTTP/SOCKS5 proxies, local-provider members and
nested selectors. Empty results use `empty-fallback`; compatible-provider views
retain the pre-filter explicit inventory exactly like the oracle. Acceptance in
`compat/scripts/phase5c_exclude_type.py` compares membership, fallback, adapter
views and DIRECT versus authenticated SOCKS5 wire routing. Later protocol types
and automatic health strategies remain separate gates.

### Phase 5C1f accepted scope

Configured selector choices persist across clean process restarts when
`profile.store-selected` is enabled (the Go-compatible default), and disabling
that setting keeps mutations process-local. Rust reads and writes the
`selected` bucket in the same profile bbolt `cache.db` already used by the Go
oracle and fake-IP persistence. Acceptance in
`compat/scripts/phase5c_selector_persistence.py` proves each implementation's
own restart lifecycle and both Go→Rust and Rust→Go file interchange while also
observing REJECT versus authenticated HTTP TCP routing. Malformed-database
recovery, concurrent writers and automatic group health state remain separate
gates.

### Phase 5C1g accepted scope

The first automatic-group slice accepts `fallback` with ordered members plus
`url`, `expected-status`, `hidden`, `icon` and `disable-udp`. It renders the
oracle's Fallback REST shape, routes TCP through the first currently healthy
member, and reuses the compatible-provider healthcheck endpoint to recover from
an unavailable configured HTTP member to DIRECT. The deterministic fixture
starts with live authenticated HTTP forwarding, removes that member, crosses
the oracle's one-second coalescing window, triggers healthcheck and observes
both REST selection and DIRECT echo. `compat/scripts/phase5c_fallback.py` is the
acceptance gate. Background interval/lazy scheduling, arbitrary remote-member
health tests, fallback PUT/fixed persistence, group-delay, UDP forwarding,
URL-test and load-balance remain separate gates.

### Phase 5C1h accepted scope

Fallback groups implement the oracle's SelectAble control boundary: controller
PUT fixes a valid member, rejects an unknown member without changing state and
immediately affects new TCP connections. Fixed choices use the shared
`selected` bbolt bucket, survive restart and interchange in both Go→Rust and
Rust→Go directions. `compat/scripts/phase5c_fallback_control.py` distinguishes
authenticated HTTP from DIRECT on the wire as well as comparing `now`/`fixed`.
Automatic health scheduling and unhealthy-fixed recovery remain separate.

### Phase 5C1i accepted scope

`GET /group/{fallback}/delay` tests the accepted built-in DIRECT/REJECT member
set concurrently and returns the successful delay map or the oracle's 400/504
error classes. Like Go, it clears and durably stores the empty fixed choice
before query validation, so invalid expected-status and zero-timeout requests
also unfix the group. `compat/scripts/phase5c_fallback_delay.py` proves this
ordering and restart persistence. Configured remote-member delay measurement,
group-delay for selectors and other automatic groups, and scheduler policy are
later gates.

### Phase 5C1j accepted scope

`url-test` accepts the current common group composition and metadata plus
`tolerance`. Health measurement now opens the actual configured HTTP CONNECT
outbound (and shares the same implementation boundary with SOCKS5) before
sending the HEAD probe. Explicit compatible-provider healthcheck records two
deterministically separated delays, selects the fastest healthy member and
applies tolerance to the retained automatic choice. PUT fixes a member,
invalid PUT rolls back, bbolt restores it after restart, and group-delay tests
all members concurrently while durably returning to automatic selection.
`compat/scripts/phase5c_url_test.py` observes exact REST fields and which proxy
carried every TCP echo. Background interval/lazy scheduling, complete
timeout/error/status policy, SOCKS5 health evidence and load-balance remain
later gates.

### Phase 5C1k accepted scope

`load-balance` accepts the explicit `round-robin` strategy over current group
composition. Its REST shape intentionally has neither `now` nor `fixed`, PUT
returns the oracle's non-selector error, and `disable-udp` controls the group
capability. Each new TCP connection advances to the next healthy member;
unhealthy entries are skipped and all-unhealthy behavior retains the first
member fallback. Compatible-provider healthcheck and group-delay reuse real
HTTP CONNECT measurement. `compat/scripts/phase5c_load_balance.py` proves
A→B→A→B wire routing, A failure followed by B-only routing, remote delay keys
and REST/error parity. Consistent-hashing, sticky-sessions, UDP and automatic
scheduling remain separate gates because Go's hash seed is process-random and
requires property-based rather than member-by-member differential evidence.

### Phase 5C1l accepted scope

`load-balance` accepts the oracle's default/explicit `consistent-hashing` and
explicit `sticky-sessions` strategies. Destination keys use the registrable
domain or destination IP; sticky keys additionally include source IP and are
held in a 1000-entry, ten-minute LRU. The differential treats Go's process-
random hash seed and sticky initial choice as nondeterministic: on each product
it proves four same-key TCP connections remain on one member, an explicit
health transition moves all later connections to the survivor, and REST/non-
selector behavior stays equal. `psl` supplies public-suffix semantics and
`lru` supplies bounded recency. UDP and automatic health scheduling were
reserved for separate gates.

### Phase 5C1m accepted scope

Automatic fallback, URL-test and load-balance health checks run once at startup
and then at the configured second-based `interval`. `lazy: false` checks every
interval; the default/explicit lazy mode skips idle intervals until data-plane
group resolution touches the group. `timeout` bounds each member probe, probes
run concurrently, the scheduler reads committed generations, and runtime
shutdown cancels it. `compat/scripts/phase5c_health_schedule.py` closes the
preferred HTTP
member without invoking controller healthcheck and proves eager discovery,
lazy skip, post-touch discovery and survivor TCP routing on Go and Rust.
Dial-failure `max-failed-times`, exhaustive error/status policy, SOCKS5 health
evidence, concurrent reload races and UDP remain later gates.

### Phase 5C1n accepted scope

Configured HTTP members reached through fallback, URL-test or load-balance
groups now participate in the oracle's dial-failure activation boundary.
`max-failed-times` defaults to five; ordinary proxy errors accumulate during
the bounded group retry loop and request a coalesced health check at the
configured threshold, while a refused TCP connection requests one
immediately. The health result updates the existing per-URL state and later
TCP connections use the surviving member. `compat/scripts/phase5c_dial_failure.py`
proves a threshold of two activates, a threshold of 99 does not activate
during the same bounded attempt, and connection refusal bypasses that high
threshold. The initiating tunnel's success or closure is not compared because
Go runs the health check asynchronously and randomizes retry backoff; the
stable compatibility boundary is eventual health state and subsequent route.

The exact timeout-window reset under scheduler pressure, delayed-handshake
success reset, SOCKS5 errors, UDP and exhaustive status/error classes remain
later gates.

### Phase 5C1o accepted scope

Authenticated SOCKS5 members now have black-box evidence through the shared
automatic-group health path. A fallback group performs real HEAD probes over
SOCKS5 CONNECT at startup and through the explicit compatible-provider
healthcheck endpoint, detects a closed member on an eager interval, and uses
the surviving SOCKS5 member for later mixed-TCP traffic. A separate lazy group
with `max-failed-times: 99` proves connection refusal still requests an
immediate coalesced health check and failover. The initiating tunnel remains
outside the comparison because the oracle schedules that check asynchronously.
`compat/scripts/phase5c_socks5_health.py` is the acceptance gate.

SOCKS5 health behavior in URL-test/load-balance groups, authentication and
CONNECT status exhaustiveness, exact failure-window reset, delayed-handshake
success reset, UDP/UoT and concurrent reload remain later gates.

### Phase 6R-1 accepted scope — SS/VMess protocol ownership refactor

This behavior-neutral slice changes inventory rows `OUT-04` and `OUT-07` and
prepares, without implementing, the server boundary in `IN-08`. The exact
compatibility-matrix rows revalidated are **Configuration surface — Proxies and
built-in proxy insertion**, **Configuration surface — Named listeners**,
**Inbound listeners — Shadowsocks**, **Remote adapters — Shadowsocks (`ss`)**,
and the Darwin arm64 Phase 6C/6D platform rows. No VMess inbound or new protocol
option is claimed.

Accepted ownership boundary:

- `rewrite-io` contains only the type-erased async duplex stream;
- one crate each owns transport-independent Shadowsocks and VMess wire/session
  behavior;
- shared TLS, ShadowTLS, simple-obfs, WS/Upgrade, HTTP/1, H2, gRPC/Gun and v2ray
  mux carriers live in `rewrite-transport` with protocol-neutral names;
- `rewrite-outbound` retains direct socket policy and thin adapter composition;
- configuration parsing stays in `rewrite-config`, and runtime retains routing,
  pooling ownership and listener lifecycle.

Acceptance requires all moved unit tests, the Phase 6C client gates, corrected
Phase 6C-N inbound gate and Phase 6D-A–J differentials to pass without semantic
normalization changes. It also requires workspace fmt and all-target/all-feature
clippy. The full workspace test is also run locally before merge; unrelated
differential regression remains the GitHub Actions responsibility requested for
this development workflow.

This slice does not start VMess server framing, non-native-carrier UDP, mKCP,
Mekya, advanced TLS/camouflage or general mux work.

### Phase 6F-A — Trojan native TCP over standard TLS

This slice changes inventory rows `CFG-03`, `OUT-09` and `OUT-23`. It adds a
transport-independent `rewrite-protocol-trojan` crate and the first complete
client path: YAML proxy record → mixed HTTP/SOCKS TCP inbound → rule selection
→ verified TLS carrier → Trojan SHA-224 authentication/address request → TCP
relay. Domain, IPv4 and IPv6 framing, the Go-default `h2,http/1.1` ALPN list,
custom roots, SNI/ALPN, password rejection, large payloads and half-close are
acceptance targets. Name override and skip verification remain accepted
configuration backed by the shared TLS transport, but are not claimed as
Trojan-specific differential evidence in this slice.

The phase is deliberately TCP-only. `udp: true`, WebSocket, gRPC, REALITY,
fallback/server behavior and all Trojan inbound configuration remain rejected
or unimplemented until their own 6F subphase. Acceptance requires protocol and
configuration unit tests plus `compat/scripts/phase6f_trojan_tcp.py` against
the pinned Go oracle on the native CI matrix.

### Phase 6F-B — Trojan UDP over native TLS

This slice continues `CFG-03`, `OUT-09` and `OUT-23`. It enables `udp: true`
for native Trojan and reuses the mixed SOCKS5 UDP session lifecycle. The shared
protocol crate owns command `3`, per-packet SOCKS addresses, big-endian length,
CRLF framing, the oracle's 8192-byte maximum frame/splitting rule and bounded
malformed-response handling.

Acceptance requires same-association destination changes, payload round trips,
TLS framing observations and exact controller `udp: true`, `uot: true`,
`xudp: false` evidence in `compat/scripts/phase6f_trojan_udp.py`. UDP from the
separate Shadowsocks inbound remains explicitly unsupported. WS/gRPC carriers,
REALITY, fallback and Trojan server direction remain later slices.

### Phase 6F-C — Trojan TCP and UDP over WebSocket/WSS

This slice continues `CFG-03`, `OUT-09` and `OUT-23`. `network: ws` composes
the shared verified TLS client and library-backed WebSocket carrier before the
shared Trojan protocol framing. The configuration boundary owns path, Host and
custom headers and rejects early-data/raw-upgrade options outside this slice;
the default WebSocket ALPN is `http/1.1` like the Go oracle.

`compat/scripts/phase6f_trojan_websocket.py` is the acceptance gate for TCP
and UDP over WSS, large TCP payloads, reused UDP destinations, WebSocket request
path/headers and command framing. gRPC, REALITY, fallback and Trojan inbound
remain separate slices.

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
