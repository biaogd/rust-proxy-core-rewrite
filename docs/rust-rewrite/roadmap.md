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
certificates, fingerprints, arbitrary proxy headers, unauthenticated and
exhaustive status/timeout matrices, UDP and chaining remain later OUT-03
gates.

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

Positive trust-store verification, `name-cert-verify`, client certificates,
fingerprints, malformed/slow response boundaries, UDP and dialer chains remain
later OUT-03 gates.

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
success/failure lifecycle, retry count and process survival. TLS, UDP, UoT,
credential lengths above 255 bytes and dialer chains remain later OUT-04 gates.

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
