# Rust rewrite architecture baseline

## Scope and source of truth

This document describes the Go implementation at
`c0e43ebecf3be9b223f1015c1fc38689bb073467`. It is an implementation map for
compatibility work, not a claim that the proposed Rust boundaries already
exist. The Go process remains the oracle until a matrix row has explicit Rust
parity evidence.

`go-capability-inventory.md` is the product-surface census layered on this
implementation map. Architecture explains where behavior originates; the
inventory assigns stable IDs and acceptance gates to every observable family.

The repository contains roughly 958 Go files and 162,529 lines of Go. The
largest areas are:

| Area | Approximate Go lines | Responsibility |
| --- | ---: | --- |
| `transport/` | 68,263 | Wire protocols, obfuscation, multiplexing and QUIC/KCP helpers |
| `component/` | 20,410 | DNS/geodata/process/dialer/profile/sniffer/platform services |
| `listener/` | 19,599 | Fixed-port and named inbound servers, including TUN/TProxy |
| `adapter/` | 18,206 | Inbound/outbound adapters, groups and providers |
| `common/` | 17,420 | Buffers, networking, collections, concurrency and utilities |
| `dns/` | 3,881 | DNS clients, cache, policy, fake IP and server middleware |
| `rules/` | 2,941 | Rule parsing, matching, logic and rule providers |
| `hub/` | 2,898 | Configuration application and REST controller |
| `config/` | 2,300 | YAML defaults, decoding, validation and object construction |
| `tunnel/` | 1,644 | Central TCP/UDP routing data plane and statistics |

## Phase 1–4F14 Rust boundary now implemented

Phase 1 introduced an isolated Cargo workspace under `rust/`; Phase 2 expanded
the pure configuration/rule boundary; Phase 3 added only the local proxy
product, observability and generation boundaries; Phase 4A adds a narrow
classic local DNS path; Phase 4B adds exact hosts and bounded redir-host
state; Phase 4C adds the declared fake-IP pool and TCP reverse-resolution
slice; Phases 4D1 through 4D4 add the declared resolver policy, fallback,
direct-resolution and REST-control slices; Phases 4E1 and 4E2 add insecure and
custom-root verified DoT main upstreams, including multiple inline roots in
Phase 4E3 and bounded reuse in Phase 4E4. Phase 4E5 adds one verified HTTPS DoH
GET main-upstream path, and Phase 4E6 adds its bounded HTTP/1.1 connection
reuse. Phase 4E7 adds a constrained custom absolute path. It remains
intentionally much narrower than the Go architecture described below; Phase
4E8 additionally canonicalizes encoded unreserved path bytes:

```text
rewrite-cli -> rewrite-config -> rewrite-rules
     |                              |
     v                              v
rewrite-runtime -> rewrite-inbound -> rewrite-model
     |       |       |          |
     |       |       +-> rewrite-dns
     |       +-> rewrite-state  +-> rewrite-net
     |                ^             ^
     +-> rewrite-controller    +-> rewrite-outbound
```

Phase 2 makes `rewrite-config` produce an owned `ConfigSpec` before any runtime
resource is created. The spec layer overlays the declared Go defaults, validates
the Phase 2 YAML/rule surface and can emit normalized observations. Converting a
spec into executable `Config` is a separate fallible step which accepts only
the incrementally declared Phase 1–4F14 runtime slices. This prevents parser
coverage from being mistaken for implemented protocol behavior.

`rewrite-rules` now contains the declared pure metadata matchers, ordered scan,
sub-rule graph validation and rematch state transitions. The test-only
`rewrite-test-support` binary and `compat/oracle/phase2` Go adapter expose the
same JSON observation contract for deterministic differential and generated
tests. Neither is linked into the product runtime.

Phase 3 makes `rewrite-runtime` the owner of transactional local listener
generations. Unchanged listener tasks receive the current `Arc<Config>` through
a watch channel; new TCP/UDP/controller sockets are all bound before the config
is published, and obsolete tasks are cancelled afterward. SIGHUP parsing stays
in `rewrite-cli` and sends only validated owned configs to runtime.

The post-Phase 4F15 inbound cleanup delegates HTTP/1 request-line and header
syntax parsing to `httparse`. `rewrite-inbound` still owns mixed-protocol
detection, proxy authentication, CONNECT handling, absolute-form rewriting and
unread preface bytes because those are proxy-product behavior rather than
generic HTTP server behavior. SOCKS framing is unchanged.

`rewrite-state` owns bounded log broadcasting, active connection snapshots and
byte totals. `rewrite-controller` reads that state and current config; its only
declared mutation path is the Phase 4D4 clear operation on the runtime-owned DNS
service, not config or listener mutation. Local SOCKS UDP is an explicit
listener boundary: it decodes one SOCKS datagram, applies the pure rule core,
uses a local DIRECT UDP socket and restores the remote source in the SOCKS
write-back header.

Phase 4A makes `rewrite-dns` responsible for classic DNS message validation,
bounded positive caching and direct UDP/TCP upstream exchange. The runtime
still owns socket lifetimes: it binds both local DNS transports before a
generation is published, while a same-address task reads the latest upstream
configuration for each query. The DNS cache key includes upstream identity but
not the client transaction ID, which is restored on cache hits. At the Phase 4A
exit, DNS had no path into tunnel metadata, rules, hosts or fake-IP state.

After Phase 4F15, common query construction plus question and compressed-name
decoding use `hickory-proto`'s `Message`, `Query`, `Name` and binary decoder.
The resolver retains explicit code for oracle-specific flags, raw question
echo, EDNS handling, UDP truncation, hosts/fake-IP responses and cache keys;
those are policy/compatibility behavior rather than generic DNS wire parsing.

Phase 4F1 completes the local DNS message boundary before resolver dispatch.
`rewrite-dns` classifies raw UDP/TCP frames as accepted, rejected or silently
ignored using the oracle's header rules; TCP ignore keeps the stream alive.
Successful replies converge through one EDNS echo/preservation step, then only
UDP replies pass through RR-boundary truncation using the client's advertised
size (with the RFC minimum of 512). Upstream selection and UDP-to-TCP retry stay
behind the resolver boundary for Phase 4F2.

Phase 4F2 represents classic main resolvers as an ordered, deduplicated list.
Each UDP/TCP entry is either a socket address or a domain plus port and one
explicit classic bootstrap resolver. `rewrite-dns` resolves domain endpoints
before transport exchange, races all main entries under one five-second
window, accepts the first valid non-SERVFAIL/non-REFUSED response and cancels
the remainder. A UDP response with TC set is retried over TCP against the same
resolved socket. Cache identity includes the complete main-resolver list;
system resolver discovery and cache retry state remain separate later gates.

Phases 4F3 and 4F4 route system and DHCP-discovered resolver addresses through
the same classic exchange boundary while keeping interface discovery and
platform cache decisions in `rewrite-platform`. After Phase 4F15, `dhcproto`
owns DHCPv4 message and option encoding/decoding; the platform crate retains
interface selection, socket binding, transaction matching and refresh policy.
Phase 4F5 adds two deliberately
small non-socket clients. The synthetic RCODE client turns the original query
into an authoritative response without retrying SERVFAIL or REFUSED and without
creating a positive cache entry. The Tailscale client looks up an async resolver
by proxy name in a generation-safe registry: the newest registration wins and
dropping an older guard cannot remove its replacement. The registry accepts no
tsnet or outbound dependency; a future Tailscale adapter supplies the actual
resolver only at the Phase 7K boundary.

Phase 4F6 moves query wrappers onto each classic upstream rather than treating
them as one resolver-wide option. Exact endpoint/transport/wrapper duplicates
collapse, while the same raw UDP/TCP transport with different wrapper options
remains as distinct clients. Each client short-circuits disabled questions,
then applies ECS, exchanges on its classic transport and filters disabled RR
types from Answer, Authority and Additional sections. Wrapper identity is also
part of the DNS cache key, so different visible behavior cannot share a cached
answer. Resolver-set composition and proxy/rule routing remain outside this
boundary.

Phase 4F7 introduces one `DnsResolverClient` representation shared by
default, main, fallback, direct and proxy-server resolver sets. A client is an
existing classic, encrypted or special transport plus its own query wrappers;
sets remove exact duplicates and race remaining clients under the existing
five-second selection window. Main and fallback use the runtime-owned pools
when a single client is selected, while multi-client execution preserves the
already proven transport wire paths. Direct-follow-policy is evaluated before
the direct set. Default and proxy sets expose the same lookup boundary used by
their future product consumers, without introducing a remote proxy adapter.

Phase 4F8 replaces the Phase 4D1 single-socket policy value with an ordered
`DnsPolicy` stream whose value is a resolver set. Contiguous domain entries
are evaluated as one Go-compatible trie group: exact labels outrank wildcard
labels, and later entries overwrite an equal trie node. GeoSite and rule-set
matchers split those groups and are evaluated in YAML order. Main and
proxy-server resolver policies are independent; a selected policy enters the
same multi-client query path and cache identity as every other resolver set.
File-backed configs load `GeoSite.dat` beside the config, while Phase 4F8 rule
sets deliberately accept inline `domain` and domain-bearing `classical`
providers only.

Phase 4F9 extends the existing fallback branch rather than introducing a
second resolver pipeline. Domain and GeoSite matchers can bypass main entirely;
otherwise main and fallback resolver sets retain eager or lazy scheduling.
Answer selection evaluates IPv4/IPv6 CIDR and file-backed GeoIP networks, with
Go-compatible GeoIP inversion and LAN-address exceptions. Lazy scheduling owns
one five-second main-plus-fallback budget, while eager scheduling starts both
sets immediately but still waits for the main decision before returning an
already available fallback result. GeoIP database decoding stays in config;
the DNS crate receives owned networks and performs no asset I/O.

Phase 4F10 gives every configured resolver lookup the same dual-stack
scheduler: A and AAAA futures start together, A establishes the primary result,
and AAAA receives only the configured additional wait window. The primary-IPv4
entrypoint shares that scheduler but returns as soon as A succeeds. HTTPS/ECH
parsing remains inside `rewrite-dns` as a bounded raw-wire walk; it does not
couple DNS to any outbound TLS implementation. Tunnel rule evaluation remains
lazy: `rewrite-rules` requests destination resolution only when an unresolved
IP rule is reached, and the runtime then enters the same DNS lookup boundary.

Phase 4F11 makes cache policy explicit in the owned DNS config. `rewrite-dns`
owns either an LRU list or ARC recent/frequent plus ghost lists, while cached
wire messages retain their stored time and minimum non-OPT lifetime. A stale
read returns an isolated TTL-one message and starts a background exchange.
An in-flight map publishes one cloneable result to concurrent callers and
restores each transaction ID before the local listener writes it. Runtime
reload clears this cache and then resets all DNS transport pools before the
generation continues serving new queries.

Phase 4F12 replaces the exact-name host map with a Go-priority domain table in
`rewrite-config`. Exact and wildcard labels plus `.`/`+.` suffix nodes produce
one owned lookup surface shared by validation, DNS and tunnel routing. The
parser expands `lan` from eligible interface addresses and rejects mixed-value
lists and alias cycles. `rewrite-dns` follows aliases for A/AAAA, preserves the
oracle's CNAME and non-address pass-through rules, and consults a native
hosts-file cache with a five-second metadata refresh. `rewrite-runtime` uses
the same configured table independently of DNS middleware enablement and
randomly selects a mapped address before rule evaluation. The host table owns
no sockets and the Rust product retains no Go runtime dependency.

Phase 4F13 makes the reverse DNS map an access-order 4096-entry LRU shared by
all current listener generations. DNS writes either the original query identity
or the configured-alias target according to the same middleware position as
Go; HTTP, SOCKS and mixed TCP plus SOCKS/mixed UDP read it before rule
evaluation. Runtime state ownership naturally preserves entries across SIGHUP.
The pinned Go cache is constructed without a max-age option, so its stored
per-entry timestamps are not consulted; Rust reproduces that observable
TTL-past retention and documents it instead of claiming expiration.

Phase 4B adds an owned exact-name host table to `rewrite-config`. `rewrite-dns`
uses it before classic upstream resolution, supports the declared A/AAAA/CNAME
paths and can read the native Unix host file when enabled. DNS A/AAAA answers
publish capacity-bounded reverse entries into `rewrite-state`; the runtime consults
that state before rule evaluation so an IP-addressed inbound can recover the
queried domain. This is shared runtime state, not a package global, and remains
separate from the DNS response cache.

Phase 4C keeps fake-IP allocation in `rewrite-state` so DNS generation and
proxy listeners share one bidirectional mapping. Each address family owns an
independent pool: allocation starts at network address + 4, never returns the
final range address, wraps cyclically and uses a 1000-entry LRU limit when
profile storage is disabled. The DNS layer applies the declared exact-domain
blacklist/whitelist before allocation and emits configured-TTL A/AAAA answers.

For the TCP vertical slice, runtime preprocessing distinguishes a fake mapping
from a TTL redir-host mapping. It replaces the rule-visible host with the
original domain, then DIRECT bypasses fake response generation and issues both
AAAA and A questions to the configured classic upstream when IPv6 is enabled
before dialing.
Profile-enabled pools persisted mapping and offset into Rust-specific JSON
files in the Phase 4C slice. Phase 4F14 replaces those sidecars with the Go
profile layout: one bbolt `cache.db`, `fakeip`/`fakeip6` buckets,
bidirectional host/address keys and the oracle's offset/cycle keys. The state
crate opens the database only at the persistence boundary and keeps filtering,
allocation and routing code free of database types. The dependency is
`bbolt-rs` 1.3.10 with its explicit Go-compatibility feature; it is MIT
licensed, supports the declared Darwin/Linux architectures, and is used only
because the gate reads and commits the pinned Go oracle's real files in both
directions.

Phase 4F14 also moves fake-IP filtering from an exact string list to owned
domain/GeoSite/rule-set matchers and ordered rule actions. DNS evaluates those
matchers before allocation. Runtime state clones a nonpersistent family map
when a reload changes its prefix, while a persistent prefix mismatch follows
Go's stored-offset guard and clears that family bucket. The controller invokes
the same pool flush through `POST /cache/fakeip/flush`; current TCP and UDP
inbounds both consume the reverse map before rule evaluation.

Phase 4D1's original single-classic-upstream policy remains compatibility
evidence but its implementation is subsumed by the Phase 4F8 ordered
multi-resolver policy stream. The selected resolver-set identity is part of the
cache key. This stays inside the DNS crate and does not introduce a callback
into the tunnel or claim a real remote proxy outbound.

Phase 4D2 adds a single classic fallback and answer filters within the same DNS
boundary. Phase 4D3A lets ordered IP rules request lazy main resolution and
gives a selected DIRECT domain an independent direct resolver, optionally
following Phase 4D1 policy. Proxy-server routing and `respect-rules` remain
deferred because no remote proxy adapter is available to test them end to end.

Phase 4D4 makes one `DnsService` owned by runtime and passes it to both the DNS
listener and controller. `GET /dns/query` uses its classic upstream/cache path
without hosts or fake-IP enhancement; `POST /cache/dns/flush` clears that
shared positive cache. This preserves one-way dependencies and makes the cache
side effect visible across both external entry points.

Phase 4E1 adds one transport branch beneath that same resolver/cache boundary.
A declared insecure/no-reuse DoT main upstream creates a fresh tokio-rustls
client stream, verifies the TLS handshake signature with ring, then carries the
existing DNS/TCP length-framed exchange. It does not alter policy selection,
hosts/fake-IP processing, controller behavior or runtime ownership.

Phase 4E2 adds a second no-reuse DoT branch at the same boundary. Configuration
passes one inline `tls.custom-certifactes` PEM root and an explicit
`name-cert-verify` value into an owned DNS TLS setting. Each exchange builds an
isolated rustls root store, sends that DNS name as SNI, validates chain, time and
SAN, and returns the Go-compatible DNS SERVFAIL packet to UDP/TCP clients when
verification fails. The cache key includes the verification name and root so a
reload cannot reuse data obtained under different trust settings.

Phase 4E3 broadens only that owned root list. Each inline PEM entry is decoded
into the same isolated rustls root store; list order does not affect chain
selection, while the existing cache identity includes every root in configured
order. No filesystem resolution is added because the Go oracle's custom trust
field passes values directly to its certificate pool rather than reading paths.

Phase 4E4 gives the shared `DnsService` one bounded verified-DoT pool. The pool
holds at most eight streams in LIFO order and is keyed by upstream address,
verification name and every configured root. A changed key drops old streams.
An exchange failure on a reused stream drops it and permits exactly one fresh
connect/exchange attempt; a failure on a fresh stream is returned immediately.
Network I/O never runs while the pool mutex is held.

Phase 4E5 adds a separate HTTPS DoH branch beneath the same resolver and
positive cache. It copies the DNS request with ID zero, serializes it as an
unpadded base64url `dns=` query parameter, sends an HTTP/1.1 GET with
`Accept: application/dns-message`, reads the bounded response according to
`Content-Length`, verifies the zero upstream response ID and restores the
client ID. It reuses the Phase 4E2 isolated custom-root store and explicit
name/SNI verification. The parser restricts this evidence to a loopback
`/dns-query` main nameserver.

Phase 4E6 reuses the verified TLS stream when the HTTP/1.1 response permits
persistence. The existing eight-stream LIFO pool key now also includes the DoH
path, so reloads cannot cross trust, upstream, transport or path identities.
An exchange failure on a pooled stream drops it and permits one fresh
connect/exchange attempt; fresh failures are returned without another retry.
Responses carrying `Connection: close` are never pooled, and no network I/O is
performed while the pool mutex is held.

Phase 4E7 replaces the fixed `/dns-query` parser check with a deliberately
narrow absolute-path grammar. The path must be non-root, contain no empty
segments and use only ASCII alphanumeric or `-._~` bytes within each segment.
The owned path is used verbatim as the GET target and remains part of both the
resolver cache identity and TLS connection-pool identity. URL queries,
userinfo and redirects remain rejected or unclaimed.

Phase 4E8 permits a percent triplet only when it decodes to the same RFC 3986
unreserved byte set. The parser decodes those triplets into the owned canonical
path, matching the Go oracle's request target. Encoded separators, percent
bytes, reserved bytes, controls, malformed triplets and non-ASCII path data are
still rejected. Cache/pool keys and the HTTP target all use the canonical path.

Phase 4E9 allows a verified main DoT endpoint to be a normalized DNS hostname
and applies port 853 when either a domain or loopback IP omits its port. The
owned TLS configuration carries the endpoint hostname and exactly one classic
loopback bootstrap upstream. A fresh TLS connection resolves the endpoint with
one A query, connects the returned IPv4 address at the preserved port and still
verifies the separately configured certificate name. Resolver-cache and TLS-
pool identities include the endpoint and bootstrap identity. Multiple/system
bootstrap resolvers, AAAA selection and non-main encrypted resolver roles remain
outside this boundary.

Phase 4E10 makes verified DoT trust construction match the Go oracle's three
sources on each connection: the native platform store, the repository's
embedded CA bundle and globally configured inline `tls.custom-certifactes`
roots. `DISABLE_SYSTEM_CA` and `DISABLE_EMBED_CA` use Go's accepted true forms.
For IP-literal main DoT, omission of a fragment performs normal endpoint-name
verification, `name-cert-verify` replaces that name and takes precedence when
combined with `skip-cert-verify`, while `skip-cert-verify=true` alone installs
the existing signature-only dangerous verifier. `disable-reuse=true` selects
fresh connections; otherwise both verified and insecure DoT use the bounded
pool keyed by their effective trust/verification identity.

Phase 4E11 fixes the DoT pool lifecycle as an externally observed contract.
Concurrent misses never hold the pool mutex during network I/O and may create
independent connections; returning connections form a bounded eight-entry LIFO
pool, closing the oldest excess entry. A failed reused exchange is discarded
and receives exactly one fresh connect/exchange attempt, while a failure on
that fresh connection is returned without a loop. TLS framing reads retain the
five-second upstream deadline. Every successfully applied configuration
generation clears the idle pool and invalidates pre-reload returns, so a later
miss cannot inherit an obsolete encrypted connection.

Phase 4E12 adds a separate plaintext HTTP/1.1 DoH pool whose entries can never
be confused with TLS streams. After Phase 4F15, both plaintext and TLS HTTP/1
pools store Hyper request senders rather than raw streams; Hyper owns request/
response framing and drives each connection, while the resolver retains pool
identity, bounded LIFO return, fresh-connect retry and reload reset. Loopback URLs use port
80 when omitted; an empty path and `/` both canonicalize to the HTTP root,
while an already accepted unreserved absolute path is preserved. The shared
DoH exchange emits a zero-ID RFC 8484 GET, validates the response framing,
restores the client ID and returns persistent senders to the transport-specific
pool. Successful reload resets both plaintext and TLS pools.

There is no dependency on the Go binary at runtime; Go is invoked only by the
compatibility scripts as a development oracle. Proxy-server resolver routing,
`respect-rules`, broader DoH URL and retry/concurrency behavior,
concurrent DoH pool scheduling, HTTP/2/3, DoQ, TUN, remote adapters, providers
and broader controller mutation still have no Rust implementation.

## Process-level flow

```text
CLI / environment / config file / stdin / base64 config
                        |
                        v
                    main.go
        flags, subcommands, paths, signals
                        |
                        v
                   hub.Parse
              /                     \
             v                       v
     config.Parse             hub.applyRoute
 defaults -> YAML ->        controller HTTP/TLS/
 validate -> construct       Unix/named-pipe servers
             |
             v
      executor.ApplyConfig
             |
             +--> global services, DNS, rules, proxies
             +--> listeners and TUN
             +--> providers/profile/updaters
             |
             v
       tunnel enters Running
```

`main.go` also dispatches the `convert-ruleset`, `generate`, and `age`
subcommands before normal startup. `-v` prints build/runtime information. `-t`
parses and validates configuration without applying it. Normal startup installs
SIGINT/SIGTERM shutdown and SIGHUP reload handling.

Configuration input precedence is observable and must be preserved:

1. `-config` / `CLASH_CONFIG_STRING` supplies base64-encoded bytes.
2. `-f -` reads stdin.
3. `-f` / `CLASH_CONFIG_FILE` selects a path.
4. Otherwise the configured home directory and default config filename are
   used; `config.Init` creates a minimal `mixed-port: 7890` file if absent.

Phase 5A1 implements this same source selection in the Rust CLI. File-backed
inputs retain their resolved path for SIGHUP reloads, while base64 and stdin
inputs retain their original bytes instead of reopening stdin or an unrelated
file. Versioning, override flags, encrypted configuration and subcommands stay
outside this input-selection boundary.

Process-level configuration defaults and overrides remain outside the YAML
source itself. Phase 5A2b supplies `-m` as a parse default that explicit YAML
may replace. Phase 5A3a applies controller address and secret overrides after
each successful parse, including SIGHUP reloads, so the immutable process
options cannot be silently replaced by changed file contents.

CLI overrides for controller/UI/secret are applied after parsing and before
the configuration is dispatched.

## Configuration construction

The high-level path is:

```text
executor.Parse[WithPath|WithBytes]
  -> config.Parse
    -> config.UnmarshalRawConfig
      -> age.DecryptBytes
      -> DefaultRawConfig
      -> YAML unmarshal over defaults
    -> config.ParseRawConfig
```

`ParseRawConfig` constructs and validates objects in a significant order:

1. general settings;
2. a temporary general-setting update used by geodata/rule parsing;
3. controller, experimental settings, iptables, NTP, profile and TLS;
4. proxies, proxy groups and proxy providers;
5. named listeners;
6. rule providers, sub-rules and rules;
7. hosts;
8. global IPv6 state;
9. DNS and TUN validation;
10. TUIC server, users, static tunnels and sniffer.

Important compatibility hazards:

- YAML decoding overlays a large default object; absent, zero and explicit
  values are therefore not interchangeable.
- Parsing currently touches temporary global state because rule/geodata loading
  depends on general settings.
- Proxy groups are DAG-sorted and duplicate/reserved names are rejected.
- Built-ins (`DIRECT`, `REJECT`, `REJECT-DROP`, `COMPATIBLE`, `PASS`,
  `PASS-RULE`, and synthesized `GLOBAL`) are inserted during parsing.
- Sub-rule cycles, missing proxy targets, dialer-proxy references, listeners,
  providers, paths and TUN/DNS relationships are validated during parsing.
- Configuration parsing may decrypt data and load/download external resources;
  the Rust parser needs explicit I/O boundaries rather than hidden global I/O.

## Configuration application and reload

`executor.ApplyConfig` holds a process-wide mutex, suspends the tunnel, then
applies configuration in this order:

```text
log level
  -> tunnel suspend
  -> CA reset/custom certificates
  -> experimental flags
  -> users
  -> proxies/providers
  -> rules/rule providers
  -> sniffer
  -> hosts
  -> general settings
  -> DNS
  -> NTP (after DNS by design)
  -> fixed and named listeners
  -> TUN
  -> iptables
  -> static tunnels
  -> inner listener
  -> proxy providers
  -> profile
  -> rule providers
  -> tunnel running
  -> updater and resolver connection reset
```

Reload paths are not equivalent:

| Trigger | Parse | Controller recreation | Runtime application |
| --- | --- | --- | --- |
| Initial startup | `hub.Parse` | Yes | Forced listener application |
| SIGHUP | `hub.Parse` | Yes | Forced listener application |
| `PUT /configs` | bytes or safe absolute path | No | `force` query controls fixed listeners |
| `PATCH /configs` | JSON patch schema | No | Selective, in-place setters/recreation |
| `POST /restart` | none | Process replacement | Full shutdown/re-exec |

The Rust design must model a parsed immutable configuration separately from a
running generation. Application should construct a new generation, validate
its resources, and publish it atomically where possible. Exact Go partial
update behavior remains a compatibility requirement for the controller API.

## Inbound and metadata flow

There are two inbound configuration families:

- legacy fixed ports managed by `listener/listener.go`: HTTP, SOCKS, mixed,
  redir, TProxy, Shadowsocks, VMess, TUIC, TUN and static tunnels;
- named listeners parsed by `listener.ParseListener`: socks, http, tproxy,
  redir, mixed, tunnel, tun, shadowsocks, snell, vmess, vless, trojan,
  hysteria2, hysteria2-realm, tuic, shadowquic, anytls, mieru, sudoku and
  trusttunnel.

Each listener accepts a stream or packet, performs protocol/authentication
decoding, creates `constant.Metadata`, then calls the `constant.Tunnel`
interface. TCP uses a buffered `ConnContext`; UDP uses `UDPPacket` and
`PacketAdapter` objects with source-aware `WriteBack` behavior.

The first Rust slice only targets the mixed TCP listener. The mixed listener
peeks the first byte and dispatches HTTP or SOCKS parsing. It must preserve
buffered bytes when handing the connection to the tunnel.

## Tunnel data plane

The central singleton `tunnel.Tunnel` implements blocking TCP and nonblocking
UDP entry points.

TCP processing:

1. reject traffic when the tunnel lifecycle state is not eligible;
2. validate and normalize metadata;
3. reverse-map fake/mapped IPs and hosts;
4. optionally sniff buffered traffic and replace the destination;
5. lazily resolve DNS/process metadata as demanded by rules;
6. choose a proxy by special proxy, Direct, Global or ordered rule matching;
7. unwrap groups, handle PASS/REMATCH and reject unsupported UDP choices;
8. dial with retry and the configured timeout;
9. account for early handshake bytes;
10. wrap the connection in the statistics manager and relay both directions.

UDP processing adds a NAT table keyed by source, packet send queues, optional
UDP sniffing, destination mappings, remote packet connections, write-back
address control, timeouts and asynchronous cleanup. UDP compatibility is not
implied by TCP parity.

Global mutable state includes lifecycle status, mode, proxies, providers,
rules, listeners, sniffer, NAT state and process-mode settings. The Rust port
should place these in an owned runtime state behind explicit read/update
interfaces, not reproduce package globals.

## Rules

Rules are ordered. Each rule can request lazy IP resolution or process lookup
through `RuleMatchHelper`. Supported rule kinds include domain exact/suffix/
keyword/regex/wildcard, GEOSITE, GEOIP, ASN, IP CIDR/suffix, source/destination/
inbound port, DSCP, process name/path variants, network, UID, inbound type/user/
name, rematch name, rule set, sub-rule, AND/OR/NOT and MATCH.

Matching can return PASS (continue scanning), REMATCH (mutate metadata and scan
again with cycle protection), a proxy group or a concrete outbound. Rules also
expose provider dependencies and hit/miss statistics. Parser acceptance, error
messages, ordering and lazy side effects all belong in the compatibility
contract.

## DNS

DNS is both a service and a dependency of routing:

```text
UDP/TCP DNS listener or TUN hijack
  -> dns.Service
  -> hosts middleware
  -> fake-IP middleware (when enabled)
  -> IP-to-host mapping middleware
  -> resolver
     -> policy-specific clients or main clients
     -> fallback filters/lazy fallback
     -> cache + singleflight + retry/background refresh
```

Upstream transports include system DNS, UDP/TCP DNS, DoH, DoT, DoQ, DHCP and
Tailscale-aware resolution. Proxy and direct nameserver paths can themselves
route through the tunnel. Fake-IP pools and mapping state interact with
profiles, cache APIs, TUN hijacking and tunnel metadata preprocessing.

DNS parity therefore needs message-level fixtures (including EDNS0, TTL,
truncation and errors), not only hostname lookup tests.

## Outbound adapters and transports

`adapter.ParseProxy` converts untyped configuration maps into concrete outbound
adapters. Current configured outbound types are:

`ss`, `ssr`, `socks5`, `http`, `vmess`, `vless`, `snell`, `trojan`, `hysteria`,
`hysteria2`, `wireguard`, `tuic`, `shadowquic`, `gost-relay`, `direct`, `dns`,
`reject`, `rematch`, `ssh`, `mieru`, `anytls`, `sudoku`, `masque`,
`trusttunnel`, `openvpn`, `tailscale`, and `zerotier`.

Groups add selector, fallback, URL test, load balance and relay behavior.
Providers add loading, health checks, persistence and live updates.

Adapters implement a common stream/packet dial contract, but many compose
several packages from `transport/` and third-party forks. A Rust crate being
available for a protocol does not establish wire parity; each protocol needs
cross-implementation vectors and live interop tests.

The current Rust HTTP adapter keeps those boundaries explicit: runtime owns
the configured `tls`/SNI/verification policy, `tokio-rustls` returns one boxed
proxy stream, and Hyper owns HTTP/1 CONNECT framing and upgrade on either the
plain or TLS stream. DNS, provider downloads and HTTP outbounds share the ring
rustls provider selection but do not share routing or retry policy.

## REST controller

The controller can listen on plain TCP, TLS, Unix sockets and Windows named
pipes. It supports bearer/token authentication, CORS, an external UI, optional
debug routes, WebSockets and an optional DoH mount.

Top-level resources are `/logs`, `/traffic`, `/memory`, `/version`, `/configs`,
`/proxies`, `/group`, `/rules`, `/connections`, `/providers/proxies`,
`/providers/rules`, `/cache`, `/dns`, `/storage`, `/restart`, `/upgrade`, and
the configured UI/DoH paths. Compatibility includes routes, methods, status
codes, JSON shapes, streaming/WebSocket framing, authentication and side
effects—not only successful JSON responses.

## Cargo workspace boundary

Phase 1 introduced the smallest workspace needed by the first vertical slice;
Phase 2 added the test-support helper; Phase 3 added state and controller;
Phase 4A added the classic DNS crate; Phases 4B through 4F2 extended the
existing config, DNS, state, controller and runtime boundaries. Phase 4F3
introduced `rewrite-platform` for system resolver discovery and Phase 4F4
extended that boundary with DHCP interface snapshots, DHCPv4 wire handling and
refresh decisions. The post-Phase 4F15 wire cleanup adds `dhcproto` inside that
same platform boundary without changing resolver ownership. Phase 4F5 stays inside the existing config/DNS crates and
adds no protocol or platform dependency; Phase 4F6 extends those same crates
with per-classic-upstream wrapper state, Phase 4F7 adds resolver-set
composition, Phase 4F8 adds ordered policy matchers, Phase 4F9 adds owned
fallback matcher data and scheduling evidence, and Phase 4F10 adds the shared
dual-stack/ECH lookup boundary plus development-only differential helpers.
Phase 4F11 replaces the development FIFO cache with the configured LRU/ARC,
singleflight, stale-refresh and retry lifecycle without adding a crate. Phase
4F12 extends the existing config/DNS/runtime boundary with host-trie lookup,
portable interface enumeration, native hosts-file refresh and tunnel address
selection; it also adds no crate. Phase 4F13 replaces the reverse mapping's
nominal TTL eviction with the oracle's size-only access-order LRU and extends
its differential coverage across existing local listener types without adding
a crate. Phase 4F14 keeps those crate boundaries and adds the reviewed
`bbolt-rs` persistence dependency to `rewrite-state`: config owns fake-IP
matcher data, DNS owns filter evaluation, state owns pools/profile storage and
controller exposes only the flush operation. Phase 4F15 keeps resolution in
`rewrite-dns` and the HTTP boundary in `rewrite-controller`. After Phase 4F15,
the controller's hand-written HTTP/1 parser, chunk decoder, router and response
writer were replaced by Axum 0.8 over Hyper 1.1. Axum owns route/method
dispatch and Hyper owns HTTP framing, connection reuse and graceful listener
shutdown; controller response helpers still explicitly preserve the oracle's
status, content-type and empty-body classes. One outer middleware evaluates
the runtime-configured DoH mount before Bearer authentication like the oracle,
then applies authentication to every REST route. Streaming traffic/log bodies
observe the same cancellation token as listener shutdown. `hickory-proto` is confined to DNS RR
wire decoding and zone-text rendering for the controller JSON boundary; it is
not used to replace the existing resolver/cache/transport implementation.
`rewrite-platform`
is still not a general TUN/routing implementation.
Crates marked “later phase” remain design boundaries and do not exist yet:

```text
rust/
  Cargo.toml                 workspace policy and shared dependency versions
  crates/
    model/                   metadata, enums, addresses; no I/O
    config/                  YAML/defaults/validation; produces owned specs
    rules/                   parsing and pure matching over model
    net/                     buffered streams, relay, deadlines, cancellation
    inbound/                 HTTP/SOCKS/mixed and later other listeners
    outbound/                DIRECT first, then protocol adapters
    state/                   trackers, DNS mappings and fake-IP pools/profile state
    dns/                     classic/DoT DNS, cache, hosts/fake-IP and policy service
    controller/              REST surface over runtime interfaces
    platform/                socket/TUN/process/routing OS boundaries
    runtime/                 lifecycle, generations, routing orchestration
    cli/                     binary entry point and signals
    test-support/            local servers and fixture helpers; never runtime
```

Intended dependency direction:

```text
model <- config
model <- rules
model <- state
model <- net <- inbound
model <- net <- outbound
config <- dns
platform <- dns
config + dns + state <- controller
config + rules + inbound + outbound + state + controller + dns <- runtime
runtime + config <- cli
test-support ---------------------------------------> tests only
```

Crate/package and binary names are deliberately unresolved until the existing
README naming condition is reviewed. Published crates should not accidentally
claim the restricted project name.

Phase 5C provider lifecycle keeps one immutable `Arc<Config>` generation as the
only data-plane view. Controller requests, HTTP(S) deadlines and coalesced file
notifications send typed refresh commands to the runtime owner; it downloads
or reads bytes, parses the affected provider, rebuilds dependent groups/rules,
persists cache/ETag metadata and only then swaps the generation. A failed step
returns an error without publishing partial config or cache state. Separate
cancellation-owned tasks schedule group health, provider health, remote
refresh and file watching; generation changes re-key their inventories and
shutdown joins each task with a bounded abort fallback.

## Architectural risks to track

1. Upstream drift: the Alpha branch changes frequently and uses many MetaCubeX
   forks with future-dated protocol work.
2. Hidden globals: parse and apply behavior currently depend on package state
   and ordering.
3. Async semantic drift: Go goroutines/channels and Rust tasks/queues differ in
   cancellation, fairness, shutdown and panic behavior.
4. Buffer ownership: sniffing, early data, zero-copy pools and UDP recycling are
   sensitive to duplicated/dropped bytes and use-after-recycle errors.
5. Platform breadth: socket marks, transparent proxying, process discovery,
   TUN routing, named pipes and Android integration are distinct products.
6. Crypto/wire behavior: protocol interoperability is byte-exact and cannot be
   inferred from API similarity.
7. Controller compatibility: dashboards depend on undocumented JSON and
   streaming behavior as well as documented endpoints.
