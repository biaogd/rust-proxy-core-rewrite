# Go/Rust compatibility harness

## Phase 1 network slice

`scripts/phase1.py` builds the Go oracle from the pinned baseline and the Rust
candidate from `rust/`, then runs identical local-only scenarios against each
binary. It compares structured observations for config validation, HTTP
absolute-form proxying, HTTP CONNECT, SOCKS5 IPv4/domain/IPv6, dial failure,
fragmentation, half-close, early disconnect and SIGTERM cleanup.

Run from the repository root:

```sh
python3 compat/scripts/phase1.py
```

`PHASE1_GO_BINARY` and `PHASE1_RUST_BINARY` may point to already-built binaries
for a container or CI job; the baseline `HEAD` check still runs. An isolated
Cargo output directory can be selected with `PHASE1_CARGO_TARGET`.

The harness requires `HEAD` to be the pinned Go baseline. It allocates fresh
loopback ports and temporary homes for every run. The only normalization is for
ephemeral origin ports, temporary paths, shutdown duration and platform socket
close text. On a mismatch or scenario error it writes
`compat/artifacts/phase1-diff.json` with the available observations, rendered
configuration and raw process logs; the directory is ignored by Git. A passing
run removes that known failure artifact. No scenario contacts the public
network.

## Phase 2 configuration and pure rules

`scripts/phase2.py` compares a test-only Go oracle adapter with the Rust
configuration/rule core. Both programs receive the same JSON request batch on
stdin and return normalized observations for accepted/rejected configuration,
effective declared defaults, error classes, selected rule targets and rematch
metadata.

Run from the repository root:

```sh
python3 compat/scripts/phase2.py
```

The suite contains the reviewed cases in `fixtures/phase2/cases.json`, then
adds deterministic generated configuration and rule cases. The default run is
37 fixed cases, 96 generated configuration cases and 256 generated rule cases
with seed `0xc0e43ebe`. Override them with `--generated-configs`,
`--generated-rules` and `--seed`; the reported seed reproduces a failing
generation.

`PHASE2_GO_ORACLE` and `PHASE2_RUST_ORACLE` may point to prebuilt helpers for a
container or CI job. `PHASE2_CARGO_TARGET` selects an isolated Cargo output
directory. The Go adapter lives under `compat/oracle/phase2/`, imports the
pinned implementation directly, and is never a Rust runtime dependency.

The suite uses no public network and needs no platform privileges. A mismatch
writes `compat/artifacts/phase2-diff.json` with the failing index, input, seed,
both observations and stderr. A passing run removes that known artifact.

## Phase 3 local proxy product

`scripts/phase3.py` runs the pinned Go binary and Rust candidate against the
same loopback TCP/UDP servers. It covers the four ordered Phase 3 gates:

- fixed HTTP/SOCKS and mixed listeners, HTTP Basic, SOCKS4/4a/5 authentication,
  DIRECT and immediate REJECT TCP behavior;
- controller Bearer auth, `/version`, `/configs`, `/connections`, `/traffic`
  and `/logs` declared read-only observations;
- controller-independent SIGHUP rule reload, invalid-config rollback and
  listener port migration;
- SOCKS5 UDP ASSOCIATE, IPv4 DIRECT datagrams, write-back source addressing and
  nonzero-FRAG drop behavior.

Run from the repository root:

```sh
python3 compat/scripts/phase3.py
```

The suite binds only ephemeral loopback ports and local echo servers. Dynamic
IDs, timestamps and allocated fixture ports are compared by type or explicit
placeholder; status codes, JSON null/array distinctions, chains, rule names,
wire replies, payloads and close behavior remain semantic. It also runs one
documented Rust-only contract: if a replacement listener port is occupied, the
old generation remains active. The pinned Go implementation closes the old
listener before attempting that bind, so this deliberate transactional safety
property is not presented as Go parity.

Use `PHASE3_GO_BINARY`, `PHASE3_RUST_BINARY` and `PHASE3_CARGO_TARGET` for
prebuilt/container runs. Failures retain `compat/artifacts/phase3-diff.json`;
passing runs remove it.

## Phase 4A classic local DNS

`scripts/phase4.py` starts a deterministic loopback authoritative server with
both UDP and TCP transports, then runs the same rendered DNS configuration
against the pinned Go binary and Rust candidate. It covers the cross-product of
UDP/TCP client transport and UDP/TCP upstream transport, plus valid and empty
nameserver configuration checks.

Run from the repository root:

```sh
python3 compat/scripts/phase4.py
```

The semantic observation includes process/config exit codes, which upstream
transport received each unique question, cache-hit call counts, transaction ID
echo, response flags, question/answer counts, A record type/class/address and
first/cached TTL. Ports and temporary paths are not compared; wire semantics
are. The fixture explicitly disables configured and system hosts, and no
scenario contacts the public network.

`PHASE4_CARGO_TARGET` selects an isolated Cargo output directory. A mismatch
retains `compat/artifacts/phase4-diff.json`; a passing run removes it. The suite
does not claim hosts/fake-IP, EDNS/truncation, resolver policy, encrypted DNS,
DNS REST or TUN hijack behavior.

## Phase 4B hosts and redir-host mapping

`scripts/phase4b.py` uses a local UDP authority and interface-local TCP echo
server to compare the declared hosts and mapping slice. It covers configured A
and AAAA answers, CNAME-only and CNAME-to-upstream responses, cache reuse,
configured cycle rejection and one native non-`localhost` `/etc/hosts` entry
when available.

Run from the repository root:

```sh
python3 compat/scripts/phase4b.py
```

The end-to-end mapping scenario first asks the local DNS listener for
`mapped.phase4.test`, then opens SOCKS5 CONNECT using only the returned native
interface IP. The recovered domain must select `DOMAIN,...,DIRECT` and relay an
exact payload to an echo server bound on that same machine. No public service is
contacted.

The suite compares record owner/type/class/TTL/data, upstream question order,
config and process exit codes, and the final relay payload. A mismatch retains
`compat/artifacts/phase4b-diff.json`; a passing run removes it. Wildcard and
`lan` hosts, fake IP, mapping persistence, broad platform host discovery,
resolver policy and encrypted/intercepted DNS remain outside this gate.

## Phase 4C fake IP

`scripts/phase4c.py` compares the pinned fake-IP pool with the Rust candidate
using only local DNS authorities, an interface-local TCP echo server and fresh
temporary homes.

Run from the repository root:

```sh
python3 compat/scripts/phase4c.py
```

The suite covers IPv4/IPv6 network-address-plus-four allocation, configured
TTL, case-insensitive reuse, exact blacklist/whitelist filtering, filtered
upstream fallthrough, `/29` cyclic overwrite and the 1000-entry nonpersistent
LRU limit. Its end-to-end case asks DNS for a fake A record, connects to that
address through SOCKS5, verifies recovered-domain rule selection, observes both
real configured A and AAAA questions and relays an exact TCP payload.

A two-generation scenario enables `profile.store-fake-ip`, stops each process
cleanly and verifies both mapping reuse and continued allocation after restart.
Only the observable result is compared: Go writes bbolt `cache.db`, while Rust
uses candidate-local JSON sidecars in its isolated home. File-format
interchange, corruption/crash recovery, rule/provider/wildcard filters, UDP
fake-IP routing, REST flush, resolver policy, encrypted DNS and TUN hijack are
outside this gate.

Configuration/process exit codes, DNS records and flags, allocation results,
upstream question names/types/counts, relay payload and restart observations
are semantic. Only the arrival order of Go's concurrent A/AAAA pair is
normalized. A mismatch retains `compat/artifacts/phase4c-diff.json`; a passing
run removes it.

## Phase 4D1 nameserver policy

`scripts/phase4d1.py` starts four deterministic authorities with distinct A
answers and both UDP/TCP transports, then compares the same
`dns.nameserver-policy` configuration against Go and Rust.

Run from the repository root:

```sh
python3 compat/scripts/phase4d1.py
```

The fixture covers main-upstream misses, `+.` matches at the root and arbitrary
subdomain depth, one-label `*` matches, deep wildcard fallback, and an exact
policy overriding an overlapping suffix. Repeating the exact query verifies
the selected-upstream cache hit, restored transaction ID and remaining TTL.
Each authority records transport, name and type, so returning the right-looking
DNS packet from the wrong upstream fails the comparison.

The declared surface is limited to ASCII exact/whole-label-wildcard patterns
and one loopback IP-literal UDP/TCP server per policy. Multiple servers,
same-trie-node overwrite ordering, geosite/rule-set policies, system/domain
upstreams, fallback, proxy/direct DNS, DNS REST and encrypted transports remain
outside 4D1. A mismatch retains `compat/artifacts/phase4d1-diff.json`; a passing
run removes it.

## Phase 4D2 main/fallback selection

`scripts/phase4d2.py` compares one deterministic UDP main upstream, one TCP
fallback upstream and one policy upstream against Go and Rust in both eager
and lazy fallback modes.

Run from the repository root:

```sh
python3 compat/scripts/phase4d2.py
```

The fixture explicitly disables GeoIP filtering and covers a `+.` domain
filter that bypasses main, an accepted main answer, an IPv4-CIDR-filtered main
answer that selects fallback, a cached fallback answer and nameserver-policy
precedence over fallback. Authority observations prove which transport and
server received each question. In eager mode the safe main query also reaches
fallback; in lazy mode it does not. The only normalized field is the exact
cached TTL decrement at a wall-clock second boundary; the TTL must be positive
and lower than the original value.

The declared subset permits one loopback IP-literal UDP/TCP main and fallback
server, explicit `fallback-filter.geoip: false`, IPv4 CIDR and ASCII domain
filters, and `fallback-lazy-query`. Multiple upstreams, GeoIP/GeoSite,
upstream error/retry equivalence, IPv6 answers, system/domain upstreams,
proxy/direct DNS, REST control and encrypted transports are outside 4D2. A
mismatch retains `compat/artifacts/phase4d2-diff.json`; a passing run removes
it.

## Phase 4D3A direct resolver and lazy IP rules

`scripts/phase4d3a.py` drives SOCKS5 domain TCP connections through ordered
domain/IP-CIDR rules while three deterministic local authorities record main,
direct and policy DNS traffic.

Run from the repository root:

```sh
python3 compat/scripts/phase4d3a.py
```

The suite proves that an earlier domain rule and an IP-CIDR `no-resolve` rule
issue no DNS request. A normal destination IP-CIDR first asks main for an
address used only for rule selection, then asks direct for the address used by
the final DIRECT TCP connection. A main-address miss closes without querying
direct. Separate follow-policy runs distinguish direct-authority selection
from two policy-authority lookups. Distinct main/direct answers and an exact
echo payload prevent a syntactically correct but wrongly routed result from
passing.

Both the mixed and DNS listeners are observed ready before scenarios begin;
the existing 100ms Go DNS-publication stabilization window is then applied.
No DNS answer, authority call, relay result or close outcome is normalized.
The gate excludes UDP/IPv6 lazy rules, multiple direct upstreams, failures and
retries, proxy-server nameservers, remote proxies, `respect-rules`, REST and
encrypted DNS. A mismatch retains `compat/artifacts/phase4d3a-diff.json`; a
passing run removes it.

## Phase 4D4 DNS REST query and cache flush

`scripts/phase4d4.py` compares the authenticated `GET /dns/query` and
`POST /cache/dns/flush` subset through a deterministic local UDP authority.

Run from the repository root:

```sh
python3 compat/scripts/phase4d4.py
```

The suite covers default A, explicit A/AAAA/CNAME, exact Go JSON field and
record shapes, content types, Bearer rejection, invalid query type, the
DNS-disabled 500 response and the 204 empty flush response. Repeating a REST
query and then querying the local DNS listener proves both surfaces share the
same positive cache; after flush, the authority must observe a new request.
Because the Go oracle performs cache clearing in a goroutine, the harness waits
100ms before observing the documented eventual side effect. TTL wall-clock
variation is normalized only after proving it remains positive and no greater
than the authority's original 30 seconds.

Only A, AAAA and CNAME REST rendering with one classic loopback upstream is
claimed. Arbitrary RR text rendering, negative/stale/singleflight cache state,
fake-IP flush, complete wrong-method/trailing-slash behavior, encrypted DNS and
storage APIs remain outside 4D4. A mismatch retains
`compat/artifacts/phase4d4-diff.json`; a passing run removes it.

## Phase 4E1 loopback DNS over TLS

`scripts/phase4e1.py` runs the local DNS listener against a loopback TLS
authority using the pinned repository certificate and private key.

Run from the repository root:

```sh
python3 compat/scripts/phase4e1.py
```

The declared configuration is exactly one main nameserver in the form
`tls://127.0.0.1:PORT#skip-cert-verify=true&disable-reuse=true`. UDP and TCP
clients each send one unique A query and one repeat. The suite compares config
and process exit codes, TLS connection/query counts, DNS/TCP framing results,
IDs, flags, question/answer counts, type/class, address and first/cached TTL.
The authority accepts TLS only, so a plaintext upstream implementation cannot
pass.

Certificate-chain and hostname verification are deliberately disabled only
because the reused local fixture certificate is self-signed and expired; TLS
handshake signatures are still verified by rustls/ring. Verified certificates,
connection reuse, SNI/name overrides, TLS failures/retries, encrypted
policy/fallback/direct nameservers, DoH, DoQ and public resolvers remain outside
4E1. A mismatch retains `compat/artifacts/phase4e1-diff.json`; a passing run
removes it.

## Phase 4E2 custom-CA verified DNS over TLS

`scripts/phase4e2.py` uses a deterministic local root and leaf certificate for
`dot.phase4.test`. Both candidates receive the same inline
`tls.custom-certifactes` root and the same loopback main nameserver with
`name-cert-verify=dot.phase4.test&disable-reuse=true`.

Run from the repository root:

```sh
python3 compat/scripts/phase4e2.py
```

The success case compares UDP/TCP client responses, DNS/TCP framing, fresh TLS
connection counts and positive-cache reuse. A second process uses
`wrong.phase4.test`; the authority must receive no accepted TLS connection and
both local client transports must receive the same ID-preserving SERVFAIL as
the Go oracle. The fixture also checks valid configuration and an unsupported
scheme.

This gate covers one inline PEM root and one loopback, no-reuse main DoT
upstream only. Root paths, system trust, multiple roots, connection reuse,
retry/fallback ordering, encrypted policy/fallback/direct nameservers, DoH and
DoQ remain unclaimed. A mismatch retains
`compat/artifacts/phase4e2-diff.json`; a passing run removes it.

## Phase 4E3 multiple inline DoT roots

`scripts/phase4e3.py` extends the verified-DoT fixture with a separate decoy CA.
It runs the issuing root both before and after that decoy, then runs a decoy-only
negative case.

Run from the repository root:

```sh
python3 compat/scripts/phase4e3.py
```

Both trusted orders must produce identical UDP/TCP DNS records, fresh TLS
connection counts and cache hits. With only the decoy root, neither candidate
may accept the authority handshake and both local transports must return the
same ID-preserving SERVFAIL. Configuration and process exit codes are also
compared.

This gate changes only multiple inline `tls.custom-certifactes` entries. The Go
oracle does not interpret this field as certificate file paths, so Rust does not
add path loading. System-root interaction, reuse/retry, encrypted
policy/fallback/direct resolvers, DoH and DoQ remain unclaimed. A mismatch keeps
`compat/artifacts/phase4e3-diff.json`; a pass removes it.

## Phase 4E4 verified DoT connection reuse

`scripts/phase4e4.py` runs one persistent TLS authority and one authority that
closes every connection after a response.

Run from the repository root:

```sh
python3 compat/scripts/phase4e4.py
```

The persistent case sends different names through local UDP and TCP clients,
then repeats one name from cache. Both upstream misses must share one TLS
connection, while the cache hit must not write another framed query. In the
stale case, the second miss first encounters the server-closed pooled stream and
must succeed after exactly one fresh connection, matching Go's retry boundary.

The Rust pool is bounded to eight streams, LIFO, and scoped to the shared local
DNS/controller service. General concurrent pool scheduling, fresh-connection
retries, system trust, encrypted policy/fallback/direct resolvers, DoH and DoQ
remain unclaimed. A mismatch keeps `compat/artifacts/phase4e4-diff.json`; a pass
removes it.

## Phase 4E5 verified HTTPS DoH GET

`scripts/phase4e5.py` runs a deterministic loopback HTTPS authority using the
same custom CA and leaf certificate as Phase 4E2. The authority offers only
HTTP/1.1 and records the request method, path, media header, body length and
decoded DNS message.

Run from the repository root:

```sh
python3 compat/scripts/phase4e5.py
```

The successful case requires an RFC 8484 GET to `/dns-query`, exactly one
unpadded base64url `dns=` parameter, a zero upstream DNS ID,
`Accept: application/dns-message`, no request body and restoration of each
local client's original ID. Repeating the same name through the other local
transport must use the positive cache, so the authority observes one request
and one TLS connection. A wrong verification name must produce ID-preserving
SERVFAIL over local UDP and TCP without an accepted authority connection.

This gate covers one inline PEM root and one loopback HTTP/1.1 main DoH
upstream. It makes only one upstream miss, so connection reuse is not evidence
from this gate; that behavior is isolated in Phase 4E6. System trust, HTTP/2/3,
POST, redirects, general paths, retry behavior, encrypted
policy/fallback/direct resolvers and DoQ remain unclaimed. A mismatch keeps
`compat/artifacts/phase4e5-diff.json`; a pass removes it.

## Phase 4E6 HTTP/1.1 DoH connection reuse

`scripts/phase4e6.py` runs both a persistent HTTP/1.1 TLS authority and an
authority that closes each connection after its first successful response.

Run from the repository root:

```sh
python3 compat/scripts/phase4e6.py
```

The persistent case sends two different cache misses through local UDP and TCP
clients, then repeats the first name. Both misses must use one TLS connection,
while the repeat must remain a resolver-cache hit. The stale case must complete
the second miss using exactly one fresh connection after the server closed the
pooled stream. Every observed request must retain the Phase 4E5 GET, zero-ID,
media-header and empty-body contract without a `Connection` request header.

The Rust pool is bounded to eight streams, LIFO, and keyed by endpoint,
verification name, configured roots and DoH path. Concurrent scheduling,
HTTP/2/3 multiplexing, system trust, general retries, redirects, encrypted
policy/fallback/direct resolvers and DoQ remain unclaimed. A mismatch keeps
`compat/artifacts/phase4e6-diff.json`; a pass removes it.

## Phase 4E7 custom absolute DoH path

`scripts/phase4e7.py` extends the loopback verified-DoH fixture with a custom
request path. Configuration observations cover nested, hyphenated and other
unreserved path segments.

Run from the repository root:

```sh
python3 compat/scripts/phase4e7.py
```

The runtime case requires the authority to receive exactly
`/custom/dns-query?dns=...`, with the path separated from the generated query
parameter. The first local UDP request must reach that target; the repeated TCP
request must use the positive cache while restoring its own client ID.

Phase 4E7 directly accepts only non-root absolute paths with non-empty segments
made from ASCII alphanumeric bytes or `-._~`; Phase 4E8 separately covers
encoded unreserved bytes. URL queries, empty segments, trailing slashes,
userinfo, redirects, non-loopback endpoints and HTTP/2/3 remain outside this
gate. A mismatch keeps
`compat/artifacts/phase4e7-diff.json`; a pass removes it.

## Phase 4E8 encoded unreserved DoH path bytes

`scripts/phase4e8.py` supplies `%2D`, `%7E` and `%41` in otherwise declared DoH
paths and compares configuration acceptance. Its runtime case starts with
`/custom/dns%2Dquery` in YAML.

Run from the repository root:

```sh
python3 compat/scripts/phase4e8.py
```

The Go oracle canonicalizes that configuration to an HTTP target beginning
`/custom/dns-query?dns=...`; Rust must do the same. The first local UDP request
must receive the expected answer and the repeated TCP request must hit cache
with its own restored ID.

Only percent triplets decoding to RFC 3986 unreserved ASCII bytes are accepted.
Encoded separators, percent bytes, reserved/control bytes, malformed triplets,
non-ASCII paths, URL queries, redirects, HTTP/2/3 and non-loopback endpoints
remain outside the gate. A mismatch keeps
`compat/artifacts/phase4e8-diff.json`; a pass removes it.

## Phase 4E9 domain DoT bootstrap and default port

`scripts/phase4e9.py` compares verified DoT domain endpoints with explicit and
implicit ports, an IP-literal implicit port and rejection of a domain-valued
bootstrap resolver. The implicit form normalizes to port 853.

Run from the repository root:

```sh
python3 compat/scripts/phase4e9.py
```

The runtime fixture uses a deterministic loopback UDP bootstrap authority that
answers the endpoint's A query with `127.0.0.1`, followed by the existing local
verified DoT authority on an ephemeral explicit port. It compares the bootstrap
question, TLS authority counts, DNS response and ID restoration, cache hit and
process shutdown. Only one explicit classic loopback `default-nameserver` is
declared; multiple/system bootstrap, AAAA selection, domain DoH, other resolver
roles and proxy routing remain outside the gate. A mismatch keeps
`compat/artifacts/phase4e9-diff.json`; a pass removes it.

## Phase 4E10 DoT trust and verification options

`scripts/phase4e10.py` compares the IP-literal main-DoT verification matrix:
default endpoint-name verification, system/embedded/global trust composition,
`name-cert-verify`, `skip-cert-verify`, their precedence and the
`disable-reuse` toggle.

Run from the repository root:

```sh
python3 compat/scripts/phase4e10.py
```

The deterministic loopback cases prove global-root/name-override success,
default-name mismatch, locally untrusted rejection, skip-verification success,
name-override precedence over skip, and one versus two TLS connections for
reuse versus no reuse. The system/default trust path is exercised without
allowing the local self-signed chain; no public network or host trust-store
mutation is used. Cross-platform positive system-store fixtures, domain DoT
skip verification, proxy/wrapper parameters, broader retry/reset/concurrency,
DoH and DoQ remain outside this gate. A mismatch keeps
`compat/artifacts/phase4e10-diff.json`; a pass removes it.

## Phase 4E11 DoT concurrency, timeout, reset and retry

`scripts/phase4e11.py` compares the reusable IP-literal main-DoT connection
lifecycle using deterministic loopback TLS authorities.

Run from the repository root:

```sh
python3 compat/scripts/phase4e11.py
```

Twelve barrier-synchronized misses prove that network I/O is concurrent and
that only eight idle connections remain pooled; a thirteenth miss must reuse
one of them. Separate cases compare the five-second response timeout, one fresh
attempt after a stale pooled connection, no retry loop after the fresh attempt
fails, and SIGHUP closing the idle connection before the next miss reconnects.
DoH/DoQ scheduling, cancellation races, multiple upstream selection, proxy
routing and wrapper parameters remain outside this gate. A mismatch keeps
`compat/artifacts/phase4e11-diff.json`; a pass removes it.

## Phase 4E12 plaintext HTTP DoH and default URLs

`scripts/phase4e12.py` compares loopback plaintext HTTP/1.1 DoH URLs with an
implicit port 80, explicit ephemeral ports, empty and root paths, and one
custom `/dns-query` path.

Run from the repository root:

```sh
python3 compat/scripts/phase4e12.py
```

Three runtime cases compare the exact normalized request path, RFC 8484 GET
method and Accept header, zero upstream DNS ID, restored response IDs, two
distinct misses on one persistent HTTP connection and a cross-transport cache
hit. URL queries, userinfo, redirects, domain endpoints, HTTPS root forms,
HTTP/2/3, proxy routing and wrapper parameters remain later gates. A mismatch
keeps `compat/artifacts/phase4e12-diff.json`; a pass removes it.
