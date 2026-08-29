# Rust rewrite status

Last updated: 2026-08-28

Go oracle: `c0e43ebecf3be9b223f1015c1fc38689bb073467` (`Alpha`)

## Overall status

| Workstream | State | Evidence / next gate |
| --- | --- | --- |
| Phase 0 baseline and governance | Complete | Six migration documents and root `AGENTS.md` |
| Phase 0B exhaustive Go capability census | Complete | Stable CLI/config/inbound/rule/outbound/DNS/runtime/API/service/platform inventory IDs and planned gates |
| Go reference implementation | Preserved | No existing Go source modified or deleted |
| Phase 1 vertical slice | Complete | Native Darwin arm64 and containerized Linux amd64 differential suites passed |
| Phase 2 config and pure rule core | Complete | 37 fixed + 96 generated config + 256 generated rule Go/Rust observations passed |
| Phase 3 local proxy product | Complete in declared scope | Native TCP/auth/controller/reload/SOCKS UDP differential suite passed; controller tracking waits for a confirmed tunnel payload round-trip |
| Inbound HTTP parser refactor | Complete in the existing Phase 1/3 scope | HTTP/1 syntax parsing uses `httparse`; Phase 1 and Phase 3 Go/Rust differentials re-pass with proxy behavior unchanged |
| Phase 4A classic local DNS | Complete in declared scope | Native UDP/TCP client × UDP/TCP upstream differential suite passed |
| Common DNS wire codec refactor | Complete in the existing 4A/4F1/4F15 scope | Query construction and question/name decoding use `hickory-proto`; all three focused Go/Rust differentials re-pass |
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
| Phase 5E shared services | Partial in declared scope | Direct SNTP adjusted-clock contract; all controller client-auth modes; UI auto/manual archive update; current DNS GeoIP/GeoSite/MMDB scheduling and REST rollback. ECH, NTP proxy/system clock, ASN/general Geo rules and clock propagation to every TLS consumer remain open |
| Phase 4E6 HTTP/1.1 DoH reuse | Complete in declared scope | Persistent cross-client reuse, cache separation and stale pooled-connection recovery differential suite passed |
| Phase 4E7 custom DoH path | Complete in declared scope | Safe custom-path config acceptance, exact GET target and cache differential suite passed |
| Phase 4E8 encoded DoH path bytes | Complete in declared scope | Encoded-unreserved config acceptance, canonical GET target and cache differential suite passed |
| Phase 4E9 domain DoT bootstrap | Complete in declared scope | `DNS-06`; domain endpoint, implicit port 853, classic bootstrap A query and verified DoT/cache differential suite passed |
| Phase 4E10 DoT trust/verification matrix | Complete in declared scope | `DNS-06`; default system/embedded/global roots, verification precedence and reuse-toggle differential suite passed with jointly reserved distinct mixed/DNS fixture ports |
| Phase 4E11 DoT lifecycle | Complete in declared scope | `DNS-06`; concurrent pool cap, five-second timeout, reload reset and bounded-retry differential suite passed |
| Phase 4E12 plaintext HTTP DoH | Complete in declared scope | `DNS-07`; default URL forms, RFC 8484 GET, cache and sequential-reuse differential suite passed |
| Phase 4E13 HTTPS URL semantics | Complete in declared scope | `DNS-07`; root/default-port, discarded configured query, ASCII Basic userinfo and persistent same-origin relative redirect differential suite passed |
| Phase 4E14 domain HTTPS bootstrap/trust | Complete in declared scope | `DNS-07`; one loopback UDP bootstrap, URL-domain Host/SNI and default/name-override/skip verification-precedence differential suite passed |
| Phase 4E15 DoH HTTP/2 | Complete in declared scope | `DNS-08`; ALPN `h2`, RFC 8484 GET, sequential stream reuse and HTTP/1.1 fallback differential suite passed |
| DoH HTTP/1 Hyper refactor | Complete in the existing Phase 4E scope | Hand-written HTTP/1 serialization/parsing removed; 4E5–4E8 and 4E12–4E15 Go/Rust differentials re-pass |
| Phase 4E16 DoH HTTP/3 | Complete in declared scope | `DNS-08`; forced/preferred H3, H2 fallback, RFC 8484 GET, sequential QUIC reuse, reconnect and oracle-compatible no-accepted-0RTT differential suite passed |
| Phase 4E17 verified DoQ framing | Complete in declared scope | `DNS-09`; verified loopback QUIC, ALPN `doq`, one-stream two-octet framing, zero ID/FIN, restoration and failure differential suite passed |
| Phase 4E18 DoQ lifecycle | Complete in declared scope | `DNS-09`; shared sequential/concurrent streams, bounded `NO_ERROR` reconnects, SIGHUP reset and full-handshake observations passed |
| Phase 4E19 encrypted DNS wrappers | Complete in declared scope | `DNS-10`; verified-DoQ ECS inject/preserve/override, disabled request types and one disabled response-RR filter differential suite passed |
| Phase 4F1 local DNS semantics | Complete in declared scope | `DNS-01`; UDP/TCP validation, RR/RCODE, EDNS echo/preservation and UDP-size truncation differential suite passed |
| Phase 4F2 classic DNS upstreams | Complete in declared scope | `DNS-02`; domain bootstrap, concurrent selection, connection/RCODE failover, five-second timeout and UDP-TC retry differential suite passed |
| Phase 4F3 system resolver | Partial, native gates pending | `DNS-03`; config/runtime path and POSIX/Windows/Android-CMFA contracts implemented, but deterministic native port-53 wire parity is not claimed |
| Phase 4F4 DHCP resolver | Partial, privileged native gates pending | `DNS-04`; `dhcproto` now owns packet/options codecs; config/runtime, exact DHCPv4 wire and interface/invalidation contracts re-pass; native UDP 67/68 parity remains pending |
| Phase 4F5 RCODE/Tailscale DNS boundary | Complete in declared scope; DNS-05 partial | Six synthetic RCODE wire paths and the named Tailscale resolver registration lifecycle pass; actual tsnet transport remains Phase 7K |
| Phase 4F6 classic DNS wrappers | Complete in declared scope; DNS-10 partial | Per-upstream ECS/disable wrappers pass on UDP/TCP, including invalid/false values, multi-section filtering and wrapper identity; proxy/rule routing remains |
| Phase 4F7 resolver-set core | Complete in declared core; DNS-11 partial | Default/main/fallback/direct/proxy-server sets, multi-client selection and direct-follow-policy pass; complete bootstrap/proxy consumers remain |
| Phase 4F8 resolver policies | Complete in declared core; DNS-12 partial | Ordered main/proxy multi-resolver domain/GeoSite/inline-rule-set policies pass; external providers, attributes and adapter consumers remain |
| Phase 4F9 fallback decision core | Complete in declared core; DNS-13 partial | GeoIP.dat/GeoSite/domain/IPv4/IPv6 filters, multiple fallback clients and eager/lazy failure/timeout ordering pass; MMDB and broader integration remain |
| Phase 4F10 dual-stack/ECH/lazy tunnel | Complete in declared scope; DNS-14 parity | Concurrent A/AAAA with A-first ordering and configurable wait, primary IPv4, IP literals, HTTPS ECH extraction and tunnel lazy rule resolution pass |
| Phase 4F11 DNS cache lifecycle | Complete in declared core; DNS-15 parity | LRU/ARC size eviction, positive/negative/stale TTL, concurrent singleflight, background retry and reload cache/reset behavior pass |
| Phase 4F12 complete hosts core | Complete in declared portable core; DNS-16 platform gates remain | Wildcard/suffix priority, `lan`, IP/domain/multi-value aliases, DNS query pass-through, system hosts and randomized tunnel routing pass on Darwin |
| Phase 4F13 redir-host local-inbound core | Complete in declared local core; DNS-17 inbound gates remain | HTTP/SOCKS/mixed TCP, SOCKS/mixed UDP, CNAME identity, reload preservation and baseline size-only LRU retention pass |
| Phase 4F14 fake-IP lifecycle core | Complete in declared local core; DNS-18 provider/inbound/platform gates remain | All filter rule kinds, GeoSite/inline providers, v4/v6 bbolt interchange, reload/range lifecycle, TCP/UDP reverse routing, persistent flush/restart and malformed-cache recovery pass |
| Phase 4F15 DNS control surface | Complete in declared loopback TCP core; DNS-19 exhaustive legacy-RDATA gate remains | All oracle RR type names, representative RR JSON, shared cache controls and public external DoH GET/fixed/chunked POST plus errors pass |
| Phase 5A1 configuration input | Complete in declared scope | `CLI-01`/`CLI-02`; 25-case Go/Rust home, path, environment, creation, base64/stdin/file/default precedence, empty-source fallthrough, frozen reload and error differential passed |
| Phase 5A2a default version output | Complete in declared scope; tagged profiles remain | `CLI-04`; default `-v` banner and configuration short-circuit differential pass while Rust truthfully identifies rustc |
| Phase 5A2b geodata-mode CLI default | Complete in declared scope | `CLI-05`; default, `-m` and explicit YAML precedence pass through live `/configs` observations |
| Phase 5A3a controller/secret overrides | Complete in declared scope; CLI-06 remains partial | CLI/environment/explicit-empty precedence, listener selection, Bearer auth and SIGHUP reapplication pass |
| Phase 5A4a X25519 encrypted configuration | Complete in declared single-identity scope; CLI-07 remains partial | File/base64, CLI/environment precedence, wrong/empty key and plaintext warning behavior pass using the Rust `age` library |
| Phase 5A4b X25519 age convert | Complete in declared scope; CLI-10 remains partial | Exact public recipient, trailing argument and invalid/missing identity exit behavior pass |
| Phase 5A4c X25519 age encrypt/decrypt | Complete in declared scope; CLI-10 remains partial | Binary file/stream round trips, plaintext pass-through, errors and bidirectional Go/Rust armor interchange pass |
| Phase 5A4d X25519 age keygen | Complete in declared scope; CLI-10 remains partial | Structured timestamp/public/secret output, startup short-circuit and cross-implementation conversion pass |
| Phase 5A5a IP-CIDR MRS to text | Complete in declared scope; CLI-08 remains partial | Go-produced zstd MRS v1, merged IPv4/IPv6 minimal CIDRs and basic command/error lifecycle differential pass |
| Phase 5A5b IP-CIDR text/YAML to MRS | Complete in declared scope; CLI-08 remains partial | Valid text/YAML, merged IPv4/IPv6 records, empty input and bidirectional Go/Rust MRS frame interoperability pass |
| Phase 5A5c domain MRS to text | Complete in declared scope; CLI-08 remains partial | Go-produced succinct domain set, exact/`*`/`+.` normalization, sorted output and malformed-frame differential pass |
| Phase 5A5d domain text/YAML to MRS | Complete in declared scope; CLI-08 remains partial | Valid text/YAML, exact/`*`/`+.`/dot-wildcard normalization, empty input and bidirectional Go/Rust MRS frame interoperability pass |
| Phase 5A5e classical rejection | Complete in declared pinned-baseline scope; CLI-08 remains partial | Classical text/YAML/empty-format/MRS exit and empty-target side effects match the oracle's unsupported behavior |
| Phase 5A5f streaming YAML rulesets | Complete in declared scope; CLI-08 remains partial | Preamble/header discovery, malformed-entry recovery, later domain/IP records and no-newline failure differential pass |
| Phase 5A6a UUID generation | Complete in declared scope; CLI-09 remains partial | Canonical lowercase UUID v4 structure, startup short-circuit, trailing/unknown/missing command lifecycle differential pass |
| Phase 5A6b Reality keypair generation | Complete in declared scope; CLI-09 remains partial | Raw URL-safe Base64 key shape, X25519 private clamp/public relation, trailing argument and startup short-circuit differential pass |
| Phase 5A6c WireGuard keypair generation | Complete in declared scope; CLI-09 remains partial | Padded standard-Base64 key shape, X25519 private clamp/public relation, trailing argument and startup short-circuit differential pass |
| Phase 5A6d VLESS X25519 generation | Complete in declared scope; CLI-09 remains partial | Fixed-key byte-exact private/password/Hash32/lazy config, invalid length and startup lifecycle differential pass |
| Phase 5A6e ECH keypair generation | Complete in declared scope; CLI-09 remains partial | Parsed ECHConfigList/PEM fields, public name/cipher suites, independent X25519 relation and missing-name lifecycle differential pass |
| Phase 5A6f VLESS ML-KEM-768 generation | Complete in declared scope; CLI-09 remains partial | Fixed-seed byte-exact encapsulation key/Hash32/lazy config, invalid length and startup lifecycle differential pass |
| Phase 5A6g Sudoku keypair generation | Complete; closes pinned-baseline CLI-09 | Canonical split scalars, independent Edwards25519 public recovery, lowercase hex output and startup lifecycle differential pass |
| Phase 5A7a invalid SIGHUP recovery | Complete in declared scope; CLI-11 remains partial | Malformed YAML preserves live routing and the same signal loop applies a following valid generation |
| Phase 5A7b local-resource shutdown | Complete in declared scope; CLI-11 remains partial | SIGINT/SIGTERM close an idle tunnel and release current mixed/controller/DNS TCP and DNS UDP resources before zero exit |
| Phase 5A8a Unix lifecycle hooks | Complete in declared Unix/local-resource scope; CLI-12 remains partial | CLI/environment precedence, shell execution, bounded startup readiness, stable post-down invocation/completion and failure asymmetry pass; shutdown listener state is diagnostic because the Go oracle races closure |
| Phase 5B1a domain regex routing | Complete in declared syntax/local-TCP scope; RULE-03 remains partial | Ignore-case lookahead and comma-bearing quantifier parsing, invalid syntax, mixed HTTP CONNECT DIRECT hit and REJECT fallback pass |
| Phase 5B1b domain wildcard routing | Complete in declared byte-wildcard/local-TCP scope; RULE-03 remains partial | Exact Go byte-level `*`/`?` matching, empty/non-ASCII unit boundaries, mixed HTTP CONNECT DIRECT hit and REJECT fallback pass |
| Phase 5B2a destination IPv4 suffix routing | Complete in declared literal/local-TCP scope; RULE-05 remains partial | Host-bit-preserving suffix parsing/matching, adaptive byte widths, invalid width, mixed HTTP CONNECT DIRECT hit and REJECT fallback pass |
| Phase 5B2b source IPv4 suffix routing | Complete in declared loopback-source/local-TCP scope; RULE-05 remains partial | `SRC-IP-SUFFIX` and `IP-SUFFIX,...,src` aliases, source hit/miss, mixed HTTP CONNECT DIRECT/REJECT outcomes pass |
| Phase 5B2c default DSCP routing | Complete in declared local-mixed-TCP/default-metadata scope; RULE-06 remains partial | DSCP zero/nonzero, slash and reversed ranges, wildcard, invalid 64, and DIRECT/REJECT outcomes pass |
| Phase 5B2d live TCP port/network routing | Complete in declared mixed-TCP scope; RULE-06 remains partial | Real destination/inbound port and TCP network metadata produce matching DIRECT and nonmatching REJECT outcomes |
| Phase 5B2e live source-port routing | Complete in declared mixed-TCP scope; RULE-06 remains partial | Pre-bound client sockets prove real source-port hit and miss after an independent provider-readiness barrier |
| Phase 5B3a inbound-type routing | Complete in declared current-local-TCP scope; RULE-08 remains partial | HTTP absolute-form vs HTTPS CONNECT, SOCKS4/5, slash lists and `SOCKS` alias route through distinct DIRECT/REJECT outcomes |
| Phase 5B3b inbound-user routing | Complete in declared authenticated-local-TCP scope; RULE-08 remains partial | HTTP Basic, SOCKS5 username/password and SOCKS4 USERID populate case-sensitive metadata and drive exact/slash-list DIRECT/REJECT routes |
| Phase 5B3c inbound-name routing | Complete in declared fixed-local-TCP scope; RULE-08 remains partial | `DEFAULT-HTTP`, `DEFAULT-SOCKS` and `DEFAULT-MIXED` metadata plus slash-list matching drive distinct DIRECT/REJECT outcomes |
| Phase 5B3d live logical routing | Complete in declared basic-local-TCP scope; RULE-11 remains partial | AND/OR/NOT combine domain and inbound-type metadata and drive distinct DIRECT/REJECT network outcomes |
| Phase 5B3e live PASS routing | Complete in declared local-TCP scope; RULE-12 remains partial | A matched PASS continues ordered scanning into later DIRECT and REJECT results instead of becoming an outbound |
| Phase 5B3f live sub-rule routing | Complete in declared local-TCP scope; RULE-11/12 remain partial | SUB-RULE enters a named branch; PASS-RULE continues within it and returns to the main scan when exhausted |
| Phase 5B3g live REMATCH routing | Complete in declared mutation/rescan scope; RULE-12 remains partial | REMATCH updates `rematch-name` or switches `special-rules`, then rescans into distinct DIRECT/REJECT outcomes |
| Phase 5B current SOCKS5 UDP metadata | Complete across the fixed SOCKS/mixed UDP scope; RULE-06/08 retain future-inbound gaps | One live rule chain proves UDP SRC/DST/IN ports, network, DSCP, SOCKS5 type, oracle-compatible name and empty user behavior |
| Phase 5B aggregate core domain/IP rules | Complete in declared current-local scope; RULE-02/04/05 retain contextual/native-IPv6 gaps | Three domain families, source/destination CIDR, no-resolve, partial suffix bits, mapped IPv4 and IPv6 pure/error cases pass |
| Phase 5D controller completion boundary | Complete for every currently executable Rust service; API-04/API-11/API-12 retain only explicit 5E/5F service/platform dependencies | TCP/TLS/Unix and native-pipe CI, streams, safe config paths, current proxy/rule/provider surfaces, persistent Go-compatible storage, restart and public UI/DoH/debug are covered |
| Phase 5F1 local TCP/socket completion | Implementation complete in declared local/current-adapter scope; privileged Linux evidence pending | Fixed HTTP/SOCKS/mixed use TFO, Linux MPTCP fallback and keepalive; interface/mark/concurrent dialing reaches DIRECT plus current HTTP/SOCKS5 adapters, while LAN/rebind/native-address differential passes |
| Phase 5F2 UDP NAT completion | Implementation complete in declared local scope; exact-timeout Linux CI result pending | IPv4/IPv6 reuse, fan-out, multi-response, control-close, generation retention and bounded-pressure recovery pass locally; CI enables the real 60-second expiry comparison |
| Phase 5F3 release/platform gate | Configured; native CI result pending | Default quality CI builds the all-feature release binary; a root-only Linux job writes and reads back nonzero `SO_MARK` through the production socket helper |
| Phase 6A1 built-ins and GLOBAL | Implementation complete in declared fast mixed-TCP/control scope; exact expiry evidence pending | COMPATIBLE/PASS/REJECT/REJECT-DROP behavior, dynamic/default and custom GLOBAL data-plane selection, controller views and name-collision validation pass the Go/Rust differential |
| Phase 6A2 configured simple adapters | Implementation complete in declared current-listener TCP/UDP scope | Configured DIRECT/REJECT/DNS/REMATCH, inline-provider DIRECT, group-contained REMATCH, GLOBAL order, controller views, framed DNS TCP and SOCKS5 DNS/direct/reject UDP pass the Go/Rust differential |
| Phase 6B1 HTTP outbound | Complete for the native adapter boundary | Plain/TLS CONNECT, SNI versus verification identity, roots, pinning, client certificates, credential shapes, headers, exact status and malformed/delayed response behavior pass |
| Phase 5C1a configured selector | Complete in declared flat/process-local TCP scope; GRP-01 remains partial | Default and controller-selected REJECT/HTTP members drive new mixed TCP connections; exact detail views and invalid selection pass |
| Phase 5C1b selector reload lifecycle | Complete in declared SIGHUP scope; GRP-01/PROV-03 remain partial | Valid choices survive, malformed config rolls back, and removed choices fall back to the first new member exactly like Go |
| Phase 5C2a local file proxy provider | Complete in declared initial-load HTTP/SOCKS5 TCP scope; PROV-01/GRP-03 remain partial | YAML members, `use` composition, exact File/Compatible provider REST views and selected HTTP routing pass |
| Phase 5C2b manual file-provider refresh | Complete in declared serial transaction scope; PROV-01/PROV-03 remain partial | PUT atomically replaces members/dependent groups; malformed YAML returns 503 and retains controller/data-plane state |
| Phase 5C2c initial HTTP proxy provider | Complete in declared plaintext/direct-fetch/explicit-cache scope; CFG-05/PROV-01 remain partial | Hyper bounded GET, validate-before-publish, atomic cache, HTTP REST views, selected group consumption and authenticated TCP routing pass |
| Phase 5C2d HTTP provider refresh lifecycle | Complete in declared serial plaintext/manual/interval scope; CFG-05/PROV-01/PROV-03 remain partial | Remote PUT and one-second scheduler atomically replace cache/config/group members; malformed YAML and HTTP status failure return 503 and preserve the prior data plane |
| Phase 5C2e HTTP provider request contract | Complete in declared plaintext/process-local ETag scope; CFG-05/PROV-01 remain partial | Repeated custom headers, global ETag enable/disable, If-None-Match/304 cache reuse, changed-ETag publication and configured size-limit rollback pass |
| Phase 5C2f HTTP provider default cache/restart | Complete in declared CLI-home/plaintext scope; CFG-05/PROV-01 remain partial | URL-MD5 default path, first atomic write, network-free cache startup, post-restart PUT replacement/routing and malformed-payload rollback pass |
| Phase 5C2g HTTP provider cache age/recovery | Complete in declared plaintext/serial lifecycle scope; CFG-05/PROV-01/PROV-03 remain partial | Stale-start immediate refresh, corrupt-cache remote repair and failed-refresh old-cache/provider/selection/TCP retention pass |
| Phase 5C2h HTTP provider SIGHUP scheduling | Complete in declared serial plaintext lifecycle scope; CFG-05/PROV-01/PROV-03 remain partial | Long-to-short interval mutation plus stale URL/path/cache replacement re-key pending deadlines and publish the new provider/data plane |
| Phase 5C1c group filter/include-all composition | Complete in declared flat select scope; CFG-04/GRP-03 remain partial | Ordered multi-regex provider filters, exclusion, all include-all forms, empty fallback and selected HTTP routing pass |
| Phase 5C1d nested selectors | Complete in declared select-DAG TCP scope; CFG-04/GRP-01 remain partial | Forward references, recursive HTTP/REJECT/DIRECT selection, UDP capability projection, compatible views and cycle rejection pass |
| Phase 5C1e group type exclusion | Complete in current adapter-type scope; CFG-04/GRP-03 remain partial | Case-insensitive built-in, HTTP, SOCKS5 and nested-selector exclusion plus empty fallback and compatible-view separation pass |
| Phase 5C1f selector persistence | Complete in declared restart/interchange scope; GRP-01 remains partial | Default-enabled and explicitly disabled restart behavior plus Go→Rust→Go bbolt `selected` bucket interchange and live routing pass |
| Phase 5C1g fallback recovery | Complete in declared explicit-healthcheck TCP scope; GRP-02/03 remain partial | Exact Fallback metadata, authenticated HTTP initial route, compatible-provider health transition and DIRECT recovery pass |
| Phase 5C1h fallback fixed control | Complete in declared current-member TCP/persistence scope; GRP-02 remains partial | Valid/invalid PUT, HTTP versus DIRECT routing, restart restoration and Go↔Rust bbolt interchange pass |
| Phase 5C1i fallback group-delay | Complete in declared built-in-member scope; API-05/GRP-02 remain partial | Concurrent DIRECT/REJECT delay, 400/504 errors, pre-validation unfix ordering and durable empty choice pass |
| Phase 5C1j URL-test group | Complete in declared explicit-healthcheck HTTP/TCP scope; GRP-02/03 remain partial | Real two-proxy delay ranking, tolerance, fixed/restart control, group-delay unfix and selected wire routing pass |
| Phase 5C1k round-robin load-balance | Complete in declared explicit-healthcheck HTTP/TCP scope; GRP-02 remains partial | Exact non-selector REST/control, A/B alternation, unhealthy skip/failover, remote group-delay and wire routing pass |
| Phase 5C1l hashing load-balance | Complete in declared explicit-healthcheck HTTP/TCP scope; GRP-02 remains partial | Default/explicit consistent hashing and bounded sticky sessions prove same-key stability, unhealthy replacement, REST/control and wire routing |
| Phase 5C1m automatic group health schedule | Complete in declared local HTTP/TCP scope; GRP-02/03 remain partial | Startup plus eager/lazy interval checks, per-member timeout, touch activation, health failover and lifecycle cancellation pass |
| Phase 5C1n group dial-failure activation | Complete in declared grouped-HTTP/TCP scope; GRP-02/03 remain partial | Default/explicit failure threshold parsing, bounded group retry, below/at-threshold behavior, refused-connection immediate health activation and survivor routing pass |
| Phase 5C1o SOCKS5 fallback health | Complete in declared authenticated SOCKS5/fallback TCP scope; GRP-02/03 remain partial | Real startup/manual/eager health probes, high-threshold refused activation, unhealthy failover and survivor routing pass |
| Phase 5C3 provider completion | Complete for current HTTP/SOCKS5 adapters; PROV-01 retains later-protocol/dialer/override-expression gaps | Inline/file/HTTP/HTTPS, filters/name transforms, provider health, trusted roots and durable digest-bound ETag restart pass |
| Phase 5C4 rule providers | Complete in declared current rule/runtime scope; PROV-02 retains later-consumer/dialer gaps | Inline/file/HTTP/HTTPS, YAML/text/MRS, domain/IP/classical RULE-SET, REST, interval/file-watch refresh, cache and rollback pass |
| Phase 5C5 provider transactions/lifecycle | Complete in declared process/runtime scope; PROV-03 retains native-platform stress gates | Concurrent valid/invalid PUT bursts serialize transactionally; SIGHUP removal clears API/health/schedules and watcher tasks cancel cleanly |
| Phase 5C aggregate | Complete for the pre-Phase-6 adapter surface | All 27 `phase5c*.py` Go/Rust differential gates pass consecutively; later protocols must add their own provider evidence |
| Phase 6B2 SOCKS5 outbound | Complete for the native adapter boundary | Plain/TLS CONNECT, auth and overlength wire shapes, address/reply lifecycle, UDP ASSOCIATE reuse and exact UDP/UoT view pass |
| Phase 6B aggregate | Complete for native HTTP/SOCKS5 on the current mixed data plane | Four original plus two completion differentials cover TCP, TLS identity/client auth, HTTP errors and SOCKS5 UDP; cross-cutting dialer chains remain OUT-21/Phase 7T |
| Phase 6C-A Shadowsocks outbound | Complete in declared AES-128-GCM TCP-only scope | Required SS YAML fields, mixed/rule dispatch, domain-target SIP004 AEAD TCP relay and exact controller type/UDP/UoT view pass one native Go/Rust differential; every other SS mode remains open |
| Phase 6C-B Shadowsocks AEAD TCP matrix | Complete in declared SIP004 AEAD TCP scope | AES-128-GCM, AES-256-GCM and ChaCha20-IETF-Poly1305 each pass domain/IPv4 relay, 128 KiB framing, half-close and process-survival comparison; UDP/UoT/plugins/2022 remain open |
| Phase 6C-C Shadowsocks AEAD UDP | Complete in declared SIP004 AEAD UDP scope | All three accepted ciphers pass mixed/SOCKS5 UDP ingress, IPv4/domain relay, one-client association reuse, controller capability and process-survival comparison; UoT/plugins/2022/IPv6 UDP remain open |
| Phase 6C-D Shadowsocks local providers/groups | Complete in declared inline/file selector scope | Inline and file SS members expose provider/controller identity, switch through a selector and pass real domain TCP plus IPv4 UDP forwarding; HTTP-provider lifecycle/health and later SS options remain open |
| Phase 6C-E Shadowsocks HTTP provider/health | Complete in declared lifecycle scope | Initial HTTP download, A→B manual refresh, TCP/UDP replacement, fresh-cache restart and a real HEAD health probe through SS TCP pass one Go/Rust differential; scheduled/ETag/rollback stress and later SS options remain open |
| Phase 6C-F Shadowsocks UDP-over-TCP | Complete in declared SIP004 UoT scope | Go-compatible default/0/v1/v2 validation, v1/v2 magic destinations and framing, resolved IPv4/domain-originated relay, same-session reuse and exact controller capability pass one native differential; plugins/2022/UoT connect mode remain open |
| Phase 6C-G Shadowsocks legacy stream ciphers | Complete in declared shared-library scope | AES-CTR×3, AES-CFB×3, RC4-MD5 and ChaCha20-IETF each pass config plus domain/large/half-close TCP and IPv4/domain native UDP wire comparison; Go-only extra methods remain rejected |
| Phase 6C-H Shadowsocks extra AEAD ciphers | Complete in declared shared-library scope | XChaCha20-Poly1305, AES-128/256-CCM and AES-128/256-GCM-SIV each pass config plus domain/large/half-close TCP and IPv4/domain native UDP wire comparison; remaining Go-only methods stay explicit gaps |
| Phase 6C-I Shadowsocks 2022 TCP | Complete in declared standard single-PSK TCP scope | Three standard methods pass exact base64 key validation plus domain/large/half-close TCP wire comparison; 2022 UDP remains disabled after the pinned Go client panicked on an official Rust authority response |
| Phase 6C-J Shadowsocks 2022 EIH | Complete in declared AES single-hop TCP scope | AES-128/256 accept exactly `iPSK:uPSK`, reject malformed keys and unsupported ChaCha EIH, and pass domain/large/half-close TCP wire comparison; multi-hop and UDP remain open |
| Outbound module refactor | Complete; behavior-neutral | The 924-line facade is reduced to module declarations/re-exports; DIRECT, HTTP, TLS and SOCKS5 TCP/UDP/auth live in focused files and all seven Phase 6B differentials re-pass |
| Controller/runtime module refactor | Complete; behavior-neutral | The controller and runtime crate roots are reduced to 77 lines (including tests) and 9 lines; `context`/`types` own shared state and production modules use direct external and `crate::module` imports with no `use super`; Phase 3 differential, workspace clippy and tests pass |
| CI portability/fixture hardening | Implemented; Windows storage revalidation pending | Windows uses the pinned cross-platform `biaogd/bbolt-rs` backend instead of storage no-ops; Phase 4 readiness uses a bounded 11-second startup window, Phase 4F13 reload writes atomically and Phase 5F refreshes the fixed UDP session immediately before reload; native Windows product persistence still needs its own gate |
| Controller Axum/Hyper refactor | Complete in the existing declared controller scope | Hand-written HTTP parsing/routing/framing removed; Phase 3, 4D4, 4F14 and 4F15 differentials re-pass without adding routes or compatibility claims |
| Cargo workspace | Implemented | Fourteen focused crates under `rust/crates/`; `Cargo.lock` is present with the workspace |
| Differential harness | Implemented | Phase 1–6C-J Python gates are assigned to fail-independent GitHub Actions matrix shards; local default Cargo targets resolve from Cargo metadata instead of creating repository-local `target/compat`, while CI retains explicit per-job targets |
| First mixed-to-DIRECT slice | Parity in declared scope | Minimal YAML -> mixed HTTP/SOCKS5 TCP -> `MATCH,DIRECT` -> DIRECT relay |
| Phase 2 declared spec/rule subset | Parity in declared scope | Normalized general config plus pure domain/IP/port/network/logic/sub-rule/rematch behavior |
| Broader Mihomo functionality | Not started | Exhaustively planned in `go-capability-inventory.md`; behavior outside the declared slices and partial Phase 4F3–4F15 boundaries remains unimplemented |

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

After Phase 4F15, the inbound HTTP parser was migrated from manual request-line
and header splitting to `httparse` 1.10.1. Mixed HTTP/SOCKS detection,
CONNECT/absolute-form proxy semantics, Basic authentication, header filtering
and unread payload forwarding remain owned by `rewrite-inbound`. The Phase 1
and Phase 3 differential suites re-pass locally on 2026-08-26; this
infrastructure cleanup adds no inbound protocol or compatibility claim.

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

`rewrite-state` owns a 4096-entry IP-to-domain map. Classic DNS
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

CI follow-up on 2026-08-26 hardens only fixture startup: if the first local UDP
query times out, the case is retried once with a new product process and a new
HTTP authority. A second timeout remains a failure; no response, wire or
connection observation is normalized.

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
ping/idle lifecycle, DoQ, proxy routing and encrypted-upstream wrapper
parameters remain unclaimed by Phase 4E15. Phase 4E16 claims only its declared
HTTP/3 selection/reconnect subset; broader QUIC lifecycle and accepted 0-RTT
remain unclaimed.

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

## Phase 4E16 deliverables and evidence

Phase 4E16 adds the declared HTTPS DoH HTTP/3 selection and reconnect slice.
The Rust configuration accepts `#h3=true` as forced H3 and
`dns.prefer-h3: true` as a raced preference for H3. Ordinary HTTPS DoH retains
the previously accepted HTTP/2/HTTP/1.1 path. The preference race probes QUIC
and TLS/TCP, selects the first usable transport and retains that choice for the
transport identity; an H2-only authority therefore remains a deterministic
fallback instead of a startup failure.

The selected H3 path sends the same bodyless RFC 8484 GET contract: HTTPS URI,
configured authority and path, exactly one `dns` query parameter,
`accept: application/dns-message`, zero upstream DNS ID and restored client ID.
One pooled QUIC/H3 sender carries sequential cache misses. If the authority
closes the pooled connection, the client discards it and reconnects within the
bounded retry path.

`compat/scripts/phase4e16.py` runs the pinned Go oracle and Rust candidate
against `compat/helpers/h3-authority`, a deterministic local Go HTTP/3 fixture.
The suite covers configuration acceptance, forced H3, H3 winning over a delayed
H2 endpoint, H2-only fallback, connection reuse and a server-closed first QUIC
connection. It compares exit status, DNS result and exact authority
observations including protocol, method, target, headers, request body, DNS ID,
connection count and `Used0RTT`.

The pinned Go path marks DNS GET requests as eligible for 0-RTT, but its TLS
configuration has no client session cache. The exact authority observation is
therefore `Used0RTT=false` on reconnect. Rust session resumption is deliberately
disabled in this slice to preserve that behavior; this is not a claim of
accepted 0-RTT compatibility.

Observed Phase 4E16 result on 2026-08-26:

| Platform | Result | Environment |
| --- | --- | --- |
| Darwin arm64 | Passed | Native `python3 compat/scripts/phase4e16.py`; Go 1.26.5, Rust 1.95.0 and deterministic loopback H3/H2 authorities |
| Linux amd64 | Pending | The default GitHub Actions full regression includes Phase 4E16; no result is recorded before that run completes |

Dependency review for this gate:

| Dependency | Resolved version | Purpose and coverage | Declared license | Evidence boundary |
| --- | --- | --- | --- | --- |
| `h3` | 0.0.8 | HTTP/3 request/response state machine | MIT | Sequential RFC 8484 GET and bounded reconnect only |
| `h3-quinn` | 0.0.10 | Adapter between the H3 client and Quinn QUIC streams | MIT | Client-side H3 transport integration only |
| `quinn` | 0.11.11 | QUIC endpoint, connection establishment and stream transport | MIT OR Apache-2.0 | Local forced/preferred/reconnect fixtures; no broader token, migration or congestion claim |

The versions and checksums are locked in `rust/Cargo.lock`. Their licenses are
recorded as compatible candidates for this GPL-3.0-only workspace; final
distribution/legal review remains a Phase 9 gate.

QUIC token and rejection matrices, accepted session resumption/0-RTT,
concurrent H3 streams, flow-control and GOAWAY stress, non-200/retry matrices,
DoQ, proxy routing and encrypted-upstream wrapper parameters remain unclaimed.

### Phase 4E16 local exit gate

Per the Phase 4E16 execution instruction, only the new phase suite was run
locally:

```sh
python3 compat/scripts/phase4e16.py
```

It passed on Darwin arm64. The complete Phase 1–4E16 differential regression,
workspace `fmt`/`clippy`/`test`, and Go/with-gVisor baseline gates are configured
in `.github/workflows/rust-rewrite.yml`; their result is intentionally left to
GitHub Actions and is not pre-claimed here.

## Phase 4E17 deliverables and evidence

Phase 4E17 adds the declared verified DNS-over-QUIC framing slice. The Rust
configuration accepts exactly one explicit-port loopback `quic://` main
upstream with an explicit `name-cert-verify` value. It uses the existing inline
custom-root trust path and opens a QUIC connection with ALPN `doq`.

For one query, Rust opens one bidirectional stream, copies and clears the DNS
message ID, writes a two-octet big-endian length followed by the DNS message,
and finishes the sending direction before reading. It rejects a zero response
length, reads exactly the declared response payload and restores the original
client ID. The connection is deliberately one-shot in this phase so no reuse,
retry or token behavior is implied.

`compat/scripts/phase4e17.py` runs the pinned Go oracle and Rust candidate
against `compat/helpers/doq-authority`, a deterministic local QUIC authority.
The authority records established connections, streams, negotiated ALPN, SNI,
declared/payload/trailing lengths, zero DNS ID and observed FIN. The suite
compares configuration validation, a verified answer, wrong certificate-name
SERVFAIL and zero-length-response SERVFAIL, including process exit status and
response-ID restoration.

Observed Phase 4E17 result on 2026-08-26:

| Platform | Result | Environment |
| --- | --- | --- |
| Darwin arm64 | Passed | Native `python3 compat/scripts/phase4e17.py`; Go 1.26.5, Rust 1.95.0 and deterministic loopback DoQ authority |
| Linux amd64 | Pending | The default GitHub Actions full regression includes Phase 4E17; no result is recorded before that run completes |

No new Rust dependency was introduced for this gate. It reuses locked
`quinn` 0.11.11 (MIT OR Apache-2.0) and the existing rustls trust path. The Go
authority reuses the oracle module's already-pinned `metacubex/quic-go` and
`metacubex/tls` dependencies as a development-only fixture.

Default-port and domain/bootstrap DoQ, IP-name/default/system/skip trust
matrices, connection reuse, multiple/concurrent streams, stale-connection
retry, token and 0-RTT behavior, reload reset, cancellation stress, proxy
routing and encrypted-upstream wrapper parameters remain unclaimed by Phase
4E17. Phase 4E18 claims only the lifecycle subset described below.

### Phase 4E17 local exit gates

```sh
cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings

cd ..
python3 compat/scripts/phase4e17.py
```

The format check, complete workspace Clippy gate and Phase 4E17 differential
suite passed locally. The complete Phase 1–4E17 differential regression,
workspace tests and Go/with-gVisor baseline gates remain delegated to the
default GitHub Actions workflow; their result is not pre-claimed here.

## Phase 4E18 deliverables and evidence

Phase 4E18 adds the declared DoQ reuse, stream concurrency, bounded reconnect
and reload-reset slice. The Rust TLS pool now retains a Quinn endpoint and one
verified DoQ connection per transport identity. Connection establishment is
serialized, but the pool lock is released before exchange so cloned connection
handles can open independent bidirectional streams concurrently.

The retry state machine records whether a connection existed before the
exchange. A fresh first exchange receives one attempt. An exchange that began
with a cached connection receives the initial attempt plus at most two
reconnect attempts, matching the pinned Go loop. An exchange failure closes
only the still-current failed connection with application code 1; a concurrent
replacement is not discarded. Same-config SIGHUP closes the active connection
while retaining the endpoint, and a changed transport identity closes both the
connection and endpoint before rebuilding them.

`compat/scripts/phase4e18.py` runs the pinned Go oracle and Rust candidate
against the extended deterministic DoQ authority. Its scenarios prove:

- two sequential and eight overlapping cache misses use ten streams on one
  connection, with an observed concurrent-stream overlap;
- after one successful priming query, two server `NO_ERROR` connection closes
  cause exactly two reconnect attempts before the repeated query succeeds;
- same-config SIGHUP closes the first active connection and the next query
  establishes a second one;
- all authority-observed handshakes negotiate `doq` with
  `DidResume=false` and `Used0RTT=false`.

Observed Phase 4E18 result on 2026-08-26:

| Platform | Result | Environment |
| --- | --- | --- |
| Darwin arm64 | Passed | Native `python3 compat/scripts/phase4e18.py`; Go 1.26.5, Rust 1.95.0 and deterministic reuse/concurrency/retry/reset DoQ authority |
| Linux amd64 | Pending | The default GitHub Actions full regression includes Phase 4E18; no result is recorded before that run completes |

No new dependency was introduced. Rust reuses locked `quinn` 0.11.11 and the
existing rustls trust path. Its endpoint retains Quinn's address-validation
token store across ordinary reconnect and same-config connection reset, while
TLS resumption is disabled to match the oracle's missing client session cache.
Packet-level token reuse, token rejection, stateless reset and idle-timeout
classification are not claimed by the current evidence.

Default-port/domain/bootstrap DoQ, broader trust options, fresh-connect failure
matrices beyond Phase 4E17, timeout/cancellation stress, connection migration,
proxy routing and encrypted-upstream wrapper parameters remain unclaimed by
Phase 4E18. Phase 4E19 claims only the wrapper subset described below.

### Phase 4E18 local exit gates

```sh
cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings

cd ..
python3 compat/scripts/phase4e18.py
```

The format check, complete workspace Clippy gate and Phase 4E18 differential
suite passed locally. The complete Phase 1–4E18 differential regression,
workspace tests and Go/with-gVisor baseline gates remain delegated to the
default GitHub Actions workflow; their result is not pre-claimed here.

## Phase 4E19 deliverables and evidence

Phase 4E19 adds the declared encrypted-upstream query-wrapper subset on the
verified DoQ path. Configuration parsing records one optional ECS prefix and a
deduplicated set of disabled qtypes from `disable-ipv4`, `disable-ipv6` and
`disable-qtype-N`. The resolver applies the Go wrapper order: disabled request
types are answered locally before transport; otherwise ECS is injected or
preserved/overridden before exchange, and disabled RR types are removed from
the received Answer, Authority and Additional sections before validation and
positive caching. Cache identities include the wrapper configuration.

`compat/scripts/phase4e19.py` runs the pinned Go oracle and Rust candidate
against the deterministic DoQ authority. Its scenarios compare exact stable
observations and prove:

- IPv4 and IPv6 ECS prefixes are injected with host bits masked;
- an incoming ECS option is preserved by default and replaced when
  `ecs-override=true`;
- disabled A, AAAA and numeric qtype 65 requests receive the same local
  authoritative empty response without contacting the authority;
- an A answer returned for a CNAME question is filtered from the response;
- valid wrapper fragments are accepted and a wrapper on an unsupported scheme
  is rejected consistently.

Observed Phase 4E19 result on 2026-08-26:

| Platform | Result | Environment |
| --- | --- | --- |
| Darwin arm64 | Passed | Native `python3 compat/scripts/phase4e19.py`; Go 1.26.5, Rust 1.95.0 and deterministic loopback DoQ authority |
| Linux amd64 | Pending | The default GitHub Actions full regression includes Phase 4E19; no result is recorded before that run completes |

No new dependency was introduced. The Rust implementation reuses the existing
DNS wire parser and verified DoQ transport.

Classic-upstream wrappers, the broader invalid/false fragment matrix,
arbitrary compressed and multi-record RR filtering, multiple-upstream
scheduling, `proxy-name` and `respect-rules` remain unclaimed. Classic wrapper
coverage remains Phase 4F6, while proxy/rule routing remains Phase 4D3B.

### Phase 4E19 local exit gates

```sh
cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings

cd ..
python3 compat/scripts/phase4e19.py
```

The format check, complete workspace Clippy gate and Phase 4E19 differential
suite passed locally. The complete Phase 1–4E19 differential regression,
workspace tests and Go/with-gVisor baseline gates remain delegated to the
default GitHub Actions workflow; their result is not pre-claimed here.

## Phase 4F1 deliverables and evidence

Phase 4F1 completes the declared `DNS-01` local-listener boundary. Before a
request reaches the resolver, Rust now applies the Go DNS server's header
acceptance rules: response packets and short headers are silently ignored,
unsupported opcodes receive NOTIMP, invalid section counts and malformed wire
receive FORMERR, and ignored TCP frames leave the connection open. Rejected
messages never reach the configured upstream.

Successful responses preserve generic RR boundaries and non-error RCODEs.
Classic upstream SERVFAIL and REFUSED responses enter the same local SERVFAIL
path as the oracle instead of being returned with an authoritative bit. At the
service convergence point, a request OPT causes a missing response OPT to be
generated with payload size 1232 and the request DO bit; an existing upstream
OPT is preserved. UDP output is limited by the request OPT size, treating
values below 512 as 512, dropping complete RRs in answer/authority/additional
order and setting TC. TCP output is not truncated.

`compat/scripts/phase4f1.py` runs both candidates against one deterministic
TCP authority and proves:

- FORMERR over UDP/TCP for zero/two questions, excessive answer/authority/
  additional counts and a truncated question;
- NOTIMP for an unsupported opcode and silent timeout for QR/short-header
  inputs without closing the TCP connection;
- semantic relay of CNAME, MX, TXT, private/unknown, SOA and A records across
  all three response sections;
- NXDOMAIN, empty NOERROR and NOTIMP preservation, plus local SERVFAIL for
  upstream SERVFAIL/REFUSED;
- 1232-byte OPT echo with DO preservation and an existing 4096-byte upstream
  OPT left intact;
- implicit 512, advertised 256-as-512 and advertised 900 UDP truncation, while
  TCP retains all ten large TXT answers.

Observed Phase 4F1 result on 2026-08-26:

| Platform | Result | Environment |
| --- | --- | --- |
| Darwin arm64 | Passed | Native `python3 compat/scripts/phase4f1.py`; Go 1.26.5, Rust 1.95.0 and deterministic loopback TCP authority |
| Linux amd64 | Pending | The default GitHub Actions full regression includes Phase 4F1; no result is recorded before that run completes |

No new dependency was introduced. DNS request acceptance, EDNS handling and
RR-boundary truncation remain inside `rewrite-dns`.

Phase 4F1 does not claim upstream UDP truncation retry, domain upstream targets,
multiple-upstream scheduling or timeout/failure ordering; those remain Phase
4F2. Negative/stale caching and resolver retry behavior remain Phase 4F11, and
TUN/intercepted DNS remains Phase 8.

### Phase 4F1 local exit gates

```sh
cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings

cd ..
python3 compat/scripts/phase4f1.py
```

The format check, complete workspace Clippy gate and Phase 4F1 differential
suite passed locally. The complete Phase 1–4F1 differential regression,
workspace tests and Go/with-gVisor baseline gates remain delegated to the
default GitHub Actions workflow; their result is not pre-claimed here.

## Phase 4F2 deliverables and evidence

Phase 4F2 completes the declared `DNS-02` classic main-upstream boundary.
Configuration now accepts an ordered list of UDP/TCP nameservers, removes exact
duplicates and permits nonzero non-loopback IP sockets. A domain endpoint keeps
its host and port plus one explicit IP-based `dns.default-nameserver`; the
bootstrap A result supplies the target socket without using the host system
resolver.

For a cache miss, Rust starts every classic main exchange concurrently under a
shared five-second deadline. The first response with a matching ID and QR bit
whose RCODE is neither SERVFAIL nor REFUSED wins; connection failures and those
two RCODEs leave other candidates eligible. Remaining tasks are cancelled when
a winner is selected. A UDP response carrying TC is discarded and the original
query is retried over TCP against the same socket, matching the oracle client.
The cache key includes transport and endpoint/bootstrap identity for the full
main list.

`compat/scripts/phase4f2.py` runs both candidates against deterministic local
UDP/TCP authorities and proves:

- two UDP authorities are contacted concurrently and the delayed response
  loses to the faster valid answer;
- a refused TCP connection and a UDP SERVFAIL can each be bypassed by a healthy
  concurrent resolver;
- a UDP TC response causes exactly one UDP request and one TCP retry, while a
  configured TCP resolver uses TCP directly;
- UDP and TCP domain endpoints each perform one A lookup through the explicit
  UDP bootstrap before contacting the target transport;
- one UDP blackhole produces local SERVFAIL in the shared five-second timeout
  class;
- multiple classic, domain/bootstrap and non-loopback configurations are
  accepted, while an explicitly empty nameserver list is rejected.

Observed Phase 4F2 result on 2026-08-26:

| Platform | Result | Environment |
| --- | --- | --- |
| Darwin arm64 | Passed | Native `python3 compat/scripts/phase4f2.py`; Go 1.26.5, Rust 1.95.0 and deterministic loopback UDP/TCP/bootstrap authorities |
| Linux amd64 | Pending | The default GitHub Actions full regression includes Phase 4F2; no result is recorded before that run completes |

No new dependency was introduced. The classic endpoint model lives in
`rewrite-config`; bootstrap, scheduling and transport fallback live in
`rewrite-dns`.

System and DHCP discovery remain Phases 4F3–4F4, synthetic RCODE/Tailscale
clients remain 4F5, classic wrapper parameters remain 4F6, and combining full
resolver sets/policies remains 4F7–4F9. Phase 4F2 does not claim negative,
stale, singleflight or background retry/cache behavior reserved for 4F11.

### Phase 4F2 local exit gates

```sh
cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings

cd ..
python3 compat/scripts/phase4f2.py
```

The format check, complete workspace Clippy gate and Phase 4F2 differential
suite passed locally. The complete Phase 1–4F2 differential regression,
workspace tests and Go/with-gVisor baseline gates remain delegated to the
default GitHub Actions workflow; their result is not pre-claimed here.

## Phase 4F3 deliverables and evidence

Phase 4F3 introduces the isolated `rewrite-platform` crate and connects a
single `system` or `system://` main nameserver to `rewrite-dns`. POSIX reads
`/etc/resolv.conf` with the oracle's nameserver token rules. Windows uses the
safe `ipconfig` adapter API and accepts only adapters that are up and have a
gateway, filters the oracle's legacy `fec0` resolver prefix and preserves the
first occurrence of each server. The `android-cmfa` feature exposes a replace
or clear injection boundary without introducing Android code into DNS policy.

The runtime refreshes discovery after five minutes, disables missing servers,
restores a reappearing server and deletes an entry only after the same
`disableTimes > 12` check used by Go. Active servers use the Phase 4F2
concurrent UDP client and UDP-TC retry path. `compat/scripts/phase4f3.py`
compares both accepted system nameserver spellings through the real Go and Rust
configuration-test processes. `rewrite-platform` tests the POSIX parser,
Windows adapter filter, Android replace/clear behavior, refresh lifecycle and
native host discovery.

This remains a **partial** `DNS-03` result. The Darwin sandbox cannot bind a
deterministic UDP/TCP authority to port 53, so the local test does not compare
system-resolver wire traffic. Windows native contract execution is delegated
to Actions, and Android-CMFA has no native runner yet. Windows scoped-IPv6 zone
preservation, Android reset callbacks and the system-DNS blacklist API also
remain unverified. None is normalized away or described as parity.

Observed Phase 4F3 result on 2026-08-26:

| Platform | Result | Environment |
| --- | --- | --- |
| Darwin arm64 | Partial contracts passed | Native `compat/scripts/phase4f3.py` plus `cargo test -p rewrite-platform`; deterministic port-53 wire fixture unavailable |
| Linux amd64 | Pending | Default full differential and native platform-contract jobs are configured; no result is recorded before completion |
| Windows amd64 | Cross-check passed; native pending | `cargo +1.95.0 check -p rewrite-platform --target x86_64-pc-windows-gnu --all-features`; native contract job is configured but no runtime result is pre-claimed |
| Android-CMFA | Contract only | Host-side injection contract passed; native execution remains pending |

Phase 4F3 adds target-specific `ipconfig` 0.3.4 for the Windows safe adapter
boundary. Its upstream manifest declares MIT/Apache-2.0; final dependency and
distribution review remains part of the release gate.

### Phase 4F3 local exit gates

```sh
cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p rewrite-platform --all-features

cd ..
python3 compat/scripts/phase4f3.py
```

The complete Phase 1–4F3 regression, workspace tests, Go/with-gVisor baseline
and Windows native contracts remain delegated to the default GitHub Actions
workflow; their result is not pre-claimed here.

The local format check, complete workspace Clippy gate, Phase 4F3 config
differential, five `rewrite-platform` tests and Windows GNU target check passed.

## Phase 4F4 deliverables and evidence

Phase 4F4 accepts a single `dhcp://<interface>` main nameserver and preserves
the Go compatibility alias `dhcp://system`. `rewrite-platform` enumerates the
named interface, selects the first non-link-local IPv4 address and parses its
six-byte hardware address. It builds the same 300-byte broadcast DHCPDISCOVER
as the Go DHCP library, requests the oracle's default option set, binds the
client socket to the interface where the platform API permits it and accepts
only a matching DHCPOFFER with DNS option 6. Discovered addresses enter the
existing Phase 4F2 UDP/TC-retry upstream path on port 53.

The DHCP cache checks interface metadata at most every 20 seconds, retains DNS
discovery for one hour while the IPv4 address is unchanged and triggers a new
discovery after an observed address change. Discovery executes on a blocking
worker with one serialized cache decision, so it does not block the async DNS
executor. A matching offer without DNS, socket failure or the one-minute
deadline becomes the cached oracle-style DHCP error.

`compat/scripts/phase4f4.py` uses the real Go configuration-test process and a
Go helper built against the pinned DHCP library. It compares named-interface
and system-alias acceptance, exact DHCPDISCOVER bytes, and valid/missing-DNS,
malformed-DNS, wrong-message-type and wrong-transaction DHCPOFFER
classifications. Nine
`rewrite-platform` tests cover those packet contracts plus interface selection,
20-second/one-hour invalidation and IPv4-address changes.

After Phase 4F15, DHCPv4 BOOTP fields and options are encoded with
`dhcproto` 0.15.0. Its borrowed message/option decoder replaces the local
offset/length loop while preserving the oracle's malformed-DNS classification.
The exact 300-byte discovery and all five offer classifications re-pass. The
crate is MIT licensed, requires Rust 1.87 (below the workspace Rust 1.95), and
is confined to `rewrite-platform`; it reuses `hickory-proto`, `ipnet`, `rand`
and `thiserror` versions already present in the workspace dependency graph.

This remains a **partial** `DNS-04` result. The local Darwin environment cannot
bind privileged UDP ports 67/68 or safely replace the host network interface,
so no native DHCP server exchange is claimed. Native Linux, Windows and Android
socket behavior, hardware/interface changes during a live exchange, same-name
configuration reload reset behavior and multi-resolver-set interaction remain
pending platform or Phase 4F7 gates.

Observed Phase 4F4 result on 2026-08-26:

| Platform | Result | Environment |
| --- | --- | --- |
| Darwin arm64 | Partial contracts passed | Native `compat/scripts/phase4f4.py`; exact Go/Rust DHCP wire/config observations and nine platform tests, without privileged exchange |
| Linux amd64 | Pending | Default full differential and platform-contract jobs include Phase 4F4; no result is recorded before completion |
| Windows amd64 | Cross-check passed; native pending | Rust 1.95 GNU target check compiles interface, packet and socket code; native contract job is configured |
| Android | Contract only | Portable packet/invalidation contracts pass; native interface/socket/package execution remains pending |

Phase 4F4 adds `network-interface` 2.0.5 (MIT OR Apache-2.0) and makes the
existing `socket2` 0.6 dependency direct with its safe extended socket API.
The interface crate documents its API as subject to change, so it is isolated
inside `rewrite-platform`; final maintenance, license and platform review
remains a release gate.

### Phase 4F4 local exit gates

```sh
cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p rewrite-platform --all-features

cd ..
python3 compat/scripts/phase4f4.py
```

The local format check, complete workspace Clippy gate, Phase 4F4 config/wire
differential, nine `rewrite-platform` tests and Windows GNU target check passed.
The complete Phase 1–4F4 regression, workspace tests, Go/with-gVisor baseline
and privileged native DHCP exchanges remain delegated to GitHub Actions or
later platform runners; no result is pre-claimed.

## Phase 4F5 deliverables and evidence

Phase 4F5 accepts the six Go RCODE names (`success`, `format_error`,
`server_failure`, `name_error`, `not_implemented` and `refused`) as one main
DNS client. It converts the original query to an authoritative response,
preserves the question and request flags, and returns SERVFAIL/REFUSED directly
instead of treating them as retryable upstream failures. Empty synthetic
answers never enter the positive cache.

The same slice accepts `tailscale://<proxy>` and its `ts://<proxy>` alias and
adds an async named-resolver registry in `rewrite-dns`. Registrations carry a
monotonic identity: a replacement becomes visible immediately, dropping the
old guard leaves the replacement intact, and dropping the active guard restores
the missing-resolver error. No Tailscale library or platform transport is linked
into the Rust product in this phase.

`compat/scripts/phase4f5.py` compares real Go and Rust processes for valid and
invalid configuration, all six RCODE responses over local UDP and TCP, exact
flags/counts/question preservation, and missing Tailscale registrations falling
back to SERVFAIL. It also runs matching focused Go and Rust registry contracts.
The Go addition is test-only; no existing oracle implementation file changes.

Observed Phase 4F5 result on 2026-08-26:

| Platform | Result | Environment |
| --- | --- | --- |
| Darwin arm64 | Declared contracts passed; DNS-05 partial | Native `compat/scripts/phase4f5.py`; product-level UDP/TCP RCODE parity plus focused Go/Rust registry lifecycle tests |
| Linux amd64 | Pending | Default full differential includes Phase 4F5; no result is recorded before completion |
| Tailscale/tsnet integration | Not started | Actual adapter startup, `LocalClient.QueryDNS`, shutdown and tailnet behavior remain Phase 7K |

### Phase 4F5 local exit gates

```sh
cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings

cd ..
python3 compat/scripts/phase4f5.py
```

The focused registry contracts and Phase 4F5 process/wire differential passed
locally. The complete Phase 1–4F5 regression, workspace tests and
Go/with-gVisor baseline remain delegated to GitHub Actions; no result is
pre-claimed.

## Phase 4F6 deliverables and evidence

Phase 4F6 attaches `DnsQueryOptions` to each classic `DnsClassicUpstream`.
Exact endpoint/transport/options duplicates are removed, but different wrappers
on the same endpoint remain independently runnable, matching Go's separation of
wrapped-client identity from reusable raw-transport identity. Cache identity
includes each upstream's wrapper configuration.

The resolver preserves Go's wrapper order: a disabled question returns a local
authoritative empty response without network I/O; otherwise ECS is injected,
preserved or overridden before UDP/TCP exchange, and configured RR types are
removed from Answer, Authority and Additional before response selection and
caching. Invalid ECS prefixes, false disable switches and unsupported numeric
qtypes are accepted but ignored like the oracle. Proxy-name fragments are still
rejected because Phase 4D3B routing is not implemented.

`compat/scripts/phase4f6.py` runs the real Go and Rust products against one
deterministic dual UDP/TCP authority. For both upstream transports it covers
IPv4/IPv6 ECS, existing ECS preserve/override, disabled A and TYPE65 requests,
compressed multi-record filtering across all three RR sections, ignored
false/invalid values, exact deduplication and two distinct wrappers sharing one
raw endpoint. A focused Go contract verifies `Equal` versus `transportEqual`;
matching Rust config tests verify the represented identities. The added Go file
is test-only and no oracle implementation file changes.

CI follow-up on 2026-08-26 normalizes only `-SIGTERM` produced by the harness's
own cleanup signal after all DNS assertions. DNS readiness can precede Go's
main signal-handler registration on a loaded runner; all other exit codes and
every semantic observation remain exact.

Observed Phase 4F6 result on 2026-08-26:

| Platform | Result | Environment |
| --- | --- | --- |
| Darwin arm64 | Passed | Native `compat/scripts/phase4f6.py`; deterministic UDP/TCP authority plus Go/Rust identity contracts |
| Linux amd64 | Pending | Default full differential includes Phase 4F6; no result is recorded before completion |

### Phase 4F6 local exit gates

```sh
cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings

cd ..
python3 compat/scripts/phase4f6.py
```

The focused Phase 4F6 differential and identity contracts passed locally. The
complete Phase 1–4F6 regression, workspace tests and Go/with-gVisor baseline
remain delegated to GitHub Actions; no result is pre-claimed.

## Phase 4F7 deliverables and evidence

Phase 4F7 adds `DnsResolverClient` and stores independent default, main,
fallback, direct and proxy-server resolver sets. Exact clients are deduplicated;
different clients race under the existing fastest-valid selection behavior.
Fallback now accepts multiple clients, direct accepts a set and still applies
`direct-nameserver-follow-policy`, and wrapper state remains attached to each
client. Cache identity includes the main and fallback client sets.

All previously accepted URL/special transport forms pass product configuration
validation in every applicable set. The runtime differential deliberately uses
deterministic UDP/TCP clients because the DoT/DoH/DoQ wire contracts were
already accepted in Phase 4E; Phase 4F7 tests composition rather than repeating
handshakes. A development-only Rust helper and Go oracle helper invoke default
and proxy resolver boundaries directly, since the Rust product does not yet
contain a remote outbound that can consume proxy-server DNS.

`compat/scripts/phase4f7.py` proves two-client fastest-valid selection for
default, main, direct and proxy sets; main-answer rejection into a two-client
fallback set; and nameserver-policy selection by a direct resolver with
follow-policy enabled. It compares addresses, process exits and exact authority
contact/transport counts.

This remains a **partial** `DNS-11` result. Domain bootstrap paths still retain
their earlier single bootstrap endpoint internally, and actual proxy outbound
resolution remains a later adapter consumer gate. Neither is claimed by direct
testing of the common resolver-set service.

Observed Phase 4F7 result on 2026-08-26:

| Platform | Result | Environment |
| --- | --- | --- |
| Darwin arm64 | Declared core passed; DNS-11 partial | Native `compat/scripts/phase4f7.py`; deterministic dual UDP/TCP resolver sets and Go/Rust lookup helpers |
| Linux amd64 | Pending | Default full differential includes Phase 4F7; no result is recorded before completion |

### Phase 4F7 local exit gates

```sh
cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings

cd ..
python3 compat/scripts/phase4f7.py
```

The Phase 4F7 resolver-set differential, format check and strict workspace
Clippy gate passed locally. Complete Phase 1–4F7 regression, workspace tests and
Go/with-gVisor baseline remain delegated to GitHub Actions; no result is
pre-claimed.

## Phase 4F8 deliverables and evidence

Phase 4F8 changes both `dns.nameserver-policy` and
`dns.proxy-server-nameserver-policy` into ordered streams of resolver sets.
YAML insertion order is retained. Contiguous domain entries behave as one Go
trie group, including exact-over-wildcard priority and later overwrite of an
equal node; GeoSite and rule-set matchers terminate a domain group and are
checked in their declared order. Direct-follow-policy reuses the expanded main
policy stream, while proxy lookups use an independent proxy policy stream.

File-backed Rust configurations decode a local `GeoSite.dat` and support its
Plain, Regex, Domain and Full domain matcher types. Inline rule providers with
`domain` behavior and domain-bearing `classical` rules are accepted solely as
DNS matcher data. `prost` 0.14 is used only for the stable GeoSite protobuf wire
format and `regex` 1.x only for the corresponding regex matcher. Both are
maintained pure-Rust crates under MIT/Apache-2.0-compatible licensing and add no
platform API or runtime network dependency.

`compat/scripts/phase4f8.py` creates the GeoSite protobuf fixture locally and
starts distinct loopback authorities. It compares product configuration exits,
selected addresses and authority contacts for: a domain group before a matcher,
a matcher before a later domain group, same-node overwrite, comma expansion,
all four GeoSite types, inline domain/classical rule sets, main multi-client
selection and proxy-policy multi-client selection. Protocol-specific handshakes
are retained from Phase 4E; the composition gate uses deterministic UDP/TCP.
Product validation additionally places every previously accepted resolver
transport and special client in a policy value without re-claiming its wire
handshake.

This remains a **partial** `DNS-12` result. File/HTTP/MRS rule-provider vehicles,
GeoSite attributes, dynamic provider refresh, `respect-rules`, and use by a real
remote proxy outbound remain separate provider/adapter integration gates.

Observed Phase 4F8 result on 2026-08-26:

| Platform | Result | Environment |
| --- | --- | --- |
| Darwin arm64 | Declared core passed; DNS-12 partial | Native `compat/scripts/phase4f8.py`; generated GeoSite data and deterministic main/proxy UDP/TCP policy sets |
| Linux amd64 | Pending | Default full differential includes Phase 4F8; no result is recorded before completion |

### Phase 4F8 local exit gates

```sh
cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings

cd ..
python3 compat/scripts/phase4f8.py
```

The Phase 4F8 differential, format check and strict workspace Clippy gate passed
locally. Complete Phase 1–4F8 regression, workspace tests and Go/with-gVisor
baseline remain delegated to GitHub Actions; no result is pre-claimed.

## Phase 4F9 deliverables and evidence

Phase 4F9 extends the fallback decision boundary without entering Phase 4F10
lookup ordering. File-backed `geodata-mode: true` configurations decode
`GeoIP.dat` CIDR lists and `GeoSite.dat` domain lists beside the YAML. GeoIP
selection preserves the Go fallback inversion rule and the private/loopback/
link-local/multicast exception; `!CODE` inversion is also represented. Domain,
GeoSite and IPv4/IPv6 CIDR filters compose with the resolver-set model from
Phase 4F7.

The scheduler continues to start eager fallback queries alongside main, but it
waits for the main result before selecting fallback. Lazy fallback starts only
after a rejected or failed main response and shares the Go oracle's single
five-second budget. Consequently, a main query that consumes the entire budget
returns an error without contacting fallback; eager mode can return an already
completed fallback response at that boundary.

`compat/scripts/phase4f9.py` generates deterministic GeoIP/GeoSite protobuf
fixtures and compares product validation, selected addresses, authority
contacts, prompt/five-second duration classes, and eager/lazy start ordering.
It covers domain and GeoSite-only routing, IPv4 and IPv6 answer filters, GeoIP
hit/miss/private/`lan`/inverted decisions, a blackholed plus healthy fallback set,
delayed SERVFAIL, and main timeout behavior.

This remains a **partial** `DNS-13` result. The Rust path intentionally requires
`geodata-mode: true` for GeoIP fallback; Go's default MMDB database mode,
broader encrypted/special transport runtime combinations, cache/retry
interaction and non-loopback integration are not claimed.

Observed Phase 4F9 result on 2026-08-26:

| Platform | Result | Environment |
| --- | --- | --- |
| Darwin arm64 | Declared core passed; DNS-13 partial | Native `compat/scripts/phase4f9.py`; generated GeoIP/GeoSite data and deterministic UDP authorities |
| Linux amd64 | Pending | Default full differential includes Phase 4F9; no result is recorded before completion |

### Phase 4F9 local exit gates

```sh
cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings

cd ..
python3 compat/scripts/phase4f9.py
```

The Phase 4F9 differential, format check and strict workspace Clippy gate
passed locally. Complete Phase 1–4F9 regression, workspace tests and
Go/with-gVisor baseline remain delegated to GitHub Actions; no result is
pre-claimed.

## Phase 4F10 deliverables and evidence

Phase 4F10 replaces the earlier sequential development lookup path with the Go
resolver's dual-stack contract. A and AAAA queries start concurrently. The
lookup waits for A first, then waits only the configured `dns.ipv6-timeout`
for AAAA; returned address lists keep IPv4 entries before IPv6. A zero timeout
uses the Go-compatible 100 ms fallback. The primary-IPv4 operation returns a
successful A result without waiting for AAAA, but waits for AAAA when A fails.
IPv4 and IPv6 literals are resolved locally without contacting an upstream.

The DNS wire parser now recognizes HTTPS (type 65) answer records and returns
the first ECH service parameter (key 5), preserving its bytes exactly. A valid
HTTPS answer without ECH produces the same observable failure class at the
helper boundary. This does not add outbound TLS ECH negotiation; adapter-level
ECH consumption remains with the relevant remote protocol gate.

The tunnel portion re-proves lazy rule resolution through the product boundary.
A domain rule preceding an IP rule reaches DIRECT without contacting the main
resolver, while an IP-CIDR rule causes concurrent main A/AAAA resolution before
selection. Both paths then use the configured direct resolver and complete a
mixed SOCKS5 TCP echo relay.

`compat/scripts/phase4f10.py` compares config exits, ordered address lists,
upstream query families and concurrent start times, configurable wait-window
inclusion/exclusion, primary-A early return, A-failure AAAA fallback, literal
short-circuiting, ECH bytes/errors, tunnel resolver contacts and relay results.

Observed Phase 4F10 result on 2026-08-26:

| Platform | Result | Environment |
| --- | --- | --- |
| Darwin arm64 | Declared scope passed; DNS-14 parity | Native `compat/scripts/phase4f10.py`; deterministic UDP authorities and mixed SOCKS tunnel |
| Linux amd64 | Pending | Default full differential includes Phase 4F10; no result is recorded before completion |

### Phase 4F10 local exit gates

```sh
cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings

cd ..
python3 compat/scripts/phase4f10.py
```

The Phase 4F10 differential, format check and strict workspace Clippy gate
passed locally. Complete Phase 1–4F10 regression, workspace tests and
Go/with-gVisor baseline remain delegated to GitHub Actions; no result is
pre-claimed.

## Phase 4F11 deliverables and evidence

Phase 4F11 replaces the fixed-size FIFO development cache with the configured
Go cache lifecycle. `dns.cache-algorithm` selects LRU or ARC and
`dns.cache-max-size` controls the live capacity (zero uses the Go default of
4096). LRU reads update recency. ARC keeps separate recent/frequent and ghost
lists, preserving the oracle's scan-resistant behavior.

The cache now derives its lifetime from every non-OPT resource-record section,
so positive answers and SOA-bearing NXDOMAIN responses share the same minimum
TTL rule. OPT records are not stored when they form the normal trailing OPT
suffix. Expired entries remain visible with all semantic TTLs set to one while
one background refresh replaces them. Fresh hits restore the caller ID and age
record TTLs without returning zero.

Concurrent misses for the same resolver/cache identity share one upstream
exchange and restore each waiting caller's transaction ID. SERVFAIL/REFUSED and
transport failures remain uncached; the first failed unshared exchange returns
SERVFAIL to the local client and starts the same immediately observable
background retry as the pinned Go implementation. A validated SIGHUP generation
clears the resolver cache and invokes the already shared encrypted/HTTP/QUIC
connection reset path; the earlier Phase 4E11 and 4E18 suites remain the wire
evidence for pooled transport teardown.

`compat/scripts/phase4f11.py` runs both products against deterministic local UDP
authorities and compares transaction IDs, RCODE/address/TTL classes and upstream
request counts. It distinguishes LRU eviction from ARC scan resistance at
capacity two, verifies positive stale-while-refresh, negative caching,
eight-client singleflight, SERVFAIL background retry and same-config reload
invalidation.

Observed Phase 4F11 result on 2026-08-26:

| Platform | Result | Environment |
| --- | --- | --- |
| Darwin arm64 | Declared core passed; DNS-15 parity | Native `compat/scripts/phase4f11.py`; deterministic UDP authorities and product SIGHUP |
| Linux amd64 | Pending | Default full differential includes Phase 4F11 and the prior transport-reset suites; no result is recorded before completion |

### Phase 4F11 local exit gates

```sh
cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings

cd ..
python3 compat/scripts/phase4f11.py
```

The focused Phase 4F11 differential, format check and strict workspace Clippy
gate passed locally. Complete Phase 1–4F11 regression, workspace tests and
Go/with-gVisor baseline remain delegated to GitHub Actions; no result is
pre-claimed.

## Phase 4F12 deliverables and evidence

Phase 4F12 replaces the exact-name development map with an owned host table
that follows the Go domain-trie priority. It accepts exact names, whole-label
`*` at any position, root-inclusive `+.` suffixes and subdomain-only `.`
suffixes. Keys and lookup names are case-insensitive. Invalid host patterns are
skipped like the oracle, while mixed address/domain lists, short domain targets
and alias cycles remain configuration errors.

Values now cover scalar IPv4/IPv6, domain aliases, multi-address lists and
`lan` expansion from eligible local interfaces. DNS A/AAAA resolution follows
configured alias chains, external aliases prepend CNAME before upstream
answers, CNAME queries against address entries pass through, and unrelated
query types or classes remain upstream traffic. `dns.use-hosts: false` bypasses
the DNS middleware without disabling tunnel host mapping.

System-host lookup is no longer a startup snapshot. The DNS service reads the
native Unix or Windows hosts-file path through a process-wide cache with the
oracle's five-second metadata check and honors Go-style true forms of
`DISABLE_SYSTEM_HOSTS`. Tunnel routing applies configured aliases and address
values before rules, then randomly selects one configured address; it uses
system hosts only when enabled by DNS configuration.

`compat/scripts/phase4f12.py` compares configuration acceptance, DNS wire
records and upstream-call observations, disabled-host behavior, available
`lan` addresses, native system-host resolution and 48 mixed SOCKS domain
connections across two loopback marker servers. The Go and Rust observations
match exactly on the local Darwin host.

Observed Phase 4F12 result on 2026-08-26:

| Platform | Result | Environment |
| --- | --- | --- |
| Darwin arm64 | Declared portable core passed; DNS-16 platform gates remain | Native `compat/scripts/phase4f12.py`; deterministic UDP authority, local interfaces, native hosts and loopback tunnel targets |
| Linux amd64 | Pending | Default full differential now includes Phase 4F12; no result is recorded before completion |
| Windows amd64 | Pending | Path and cache code are compiled by the workspace gate, but no native editable-hosts fixture is claimed |

### Phase 4F12 local exit gates

```sh
cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings

cd ..
python3 compat/scripts/phase4f12.py
```

The focused Phase 4F12 differential, format check and strict workspace Clippy
gate passed locally. Complete Phase 1–4F12 regression, workspace tests and
Go/with-gVisor baseline remain delegated to GitHub Actions; no result is
pre-claimed.

## Phase 4F13 deliverables and evidence

Phase 4F13 completes the redir-host core for every local inbound currently
implemented in Rust. One DNS A mapping is consumed through the dedicated HTTP
listener, dedicated SOCKS listener and both protocol branches of a mixed
listener over TCP. The same mapping is consumed by SOCKS and mixed UDP
datagrams. In every case the inbound supplies only the destination IP, the
runtime restores the mapped domain before rule evaluation, and
`DOMAIN,...,DIRECT` reaches an interface-local deterministic echo service.

The mapping identity follows middleware position. An ordinary upstream answer
containing CNAME plus terminal A records maps the address to the original query
name. A configured external hosts alias rewrites the question before the
mapping middleware, so its terminal address maps to the configured target
name. Separate rule gates prove both identities rather than comparing DNS wire
records alone.

Mapping state remains runtime-owned across a validated SIGHUP. The reload gate
starts with a rejecting domain rule, publishes a DNS mapping, changes that rule
to DIRECT and succeeds only when both the new rule generation and old mapping
are visible together. The cache now matches Go's access-order capacity of 4096
instead of evicting the earliest nominal expiry.

The pinned Go baseline passes a DNS-derived timestamp to `SetWithExpire`, but
constructs the mapping LRU with `WithSize(4096)` and no `WithAge`. Its `Get`
therefore never evaluates that timestamp. The differential deliberately waits
beyond a one-second DNS TTL and observes that the mapping remains usable in
both products. This is recorded as baseline-compatible TTL-past retention, not
as a claim that redir-host entries expire by TTL.

`compat/scripts/phase4f13.py` compares all of the paths above on a native
non-loopback IPv4 interface. Exact same-name cache refresh counts are excluded
from this gate because Phase 4F11 owns them; the queried-name set remains exact.
Redir-port, TProxy, TUN and future inbound families remain outside the current
Rust runtime and keep `DNS-17` partial at the full-product level.

Observed Phase 4F13 result on 2026-08-26:

| Platform | Result | Environment |
| --- | --- | --- |
| Darwin arm64 | Declared local-inbound core passed; DNS-17 broader inbound gates remain | Native `compat/scripts/phase4f13.py`; local UDP authority plus interface-bound TCP/UDP echo services |
| Linux amd64 | Pending | Default full differential now includes Phase 4F13; no result is recorded before completion |

### Phase 4F13 local exit gates

```sh
cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p rewrite-state redir_host_mapping_uses_the_go_size_only_lru_contract

cd ..
python3 compat/scripts/phase4f13.py
```

The focused Phase 4F13 differential, state LRU contract, format check and
strict workspace Clippy gate passed locally. Complete Phase 1–4F13 regression,
workspace tests and Go/with-gVisor baseline remain delegated to GitHub Actions;
no result is pre-claimed.

## Phase 4F14 deliverables and evidence

Phase 4F14 completes the fake-IP lifecycle on the currently implemented local
DNS, mixed TCP and mixed UDP surface. Blacklist and whitelist mode now accept
the Go domain trie syntax, GeoSite entries and inline domain/classical
rule-set providers. Rule mode evaluates the first matching DOMAIN,
DOMAIN-SUFFIX, DOMAIN-KEYWORD, DOMAIN-REGEX, DOMAIN-WILDCARD, GEOSITE,
RULE-SET or MATCH entry and applies its ordered `fake-ip`/`real-ip` action.
IP-CIDR providers and non-domain rule kinds are rejected like the oracle.

Persistent pools now use the Go profile's bbolt `cache.db` rather than the
Phase 4C Rust JSON sidecars. IPv4 and IPv6 retain separate `fakeip` and
`fakeip6` buckets with the same bidirectional keys and allocation state keys.
The gate starts Go, continues both families in Rust, then continues Rust's
new mappings in Go. It also replaces a malformed cache file through the same
observable recovery path. The backend is pinned to revision
`83d3900849e5c41273798e0951b110d6375c925f` of `biaogd/bbolt-rs`; its MIT
license is compatible with this GPL-3.0-only workspace, and no database type
escapes `rewrite-state`.

On SIGHUP, nonpersistent pools clone their mappings into the replacement
family even when the prefix changes, preserving the pinned Go pool's
observable old-address reverse entry while allocating fresh names from the new
prefix. Persistent pools instead restore the shared file and clear a family
when its saved offset is outside the new prefix. Both paths are differential
tested. `POST /cache/fakeip/flush` resets allocation and deletes both current
family buckets; a persistent restart proves that the side effect reached disk.
Mixed SOCKS TCP and UDP requests addressed only by a fake IPv4 recover the
domain before rule evaluation and reach deterministic interface-local echo
services.

`compat/scripts/phase4f14.py` covers these paths plus IPv4/IPv6 allocation,
REST status/body, process exit and direct Go/Rust file interchange. File/HTTP/
MRS provider loading remains owned by later provider phases. Redir-port,
TProxy, TUN and future inbound families remain their own integration gates, so
the full-product `DNS-18` inventory row stays partial outside the declared
local surface.

The interchange fixture binds both `HOME` and `XDG_CONFIG_HOME` to the same
temporary tree. This prevents the Go oracle's conditional XDG fallback from
using a runner-shared cache while Rust reads the temporary legacy path. It
prefills multiple IPv4 mappings before Go-to-Rust handoff, so equal first
addresses cannot mask a missing database transfer, and it never uses SIGHUP as
a shutdown-readiness probe because the oracle persists the pool offset only
during normal shutdown.

Observed Phase 4F14 result on 2026-08-26:

| Platform | Result | Environment |
| --- | --- | --- |
| Darwin arm64 | Declared fake-IP lifecycle core passed; DNS-18 external-provider/inbound/platform gates remain | Native `compat/scripts/phase4f14.py`; local DNS/echo services, temporary homes and bidirectional Go/Rust bbolt files |
| Linux amd64 | Pending | Default full differential now includes Phase 4F14; no result is recorded before completion |

### Phase 4F14 local exit gates

```sh
python3 compat/scripts/phase4f14.py

cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p rewrite-config -p rewrite-state -p rewrite-dns -p rewrite-controller -p rewrite-runtime
```

The focused Phase 4F14 differential/interchange and affected-crate tests pass
locally. Format and strict workspace Clippy are run locally before handoff.
Complete Phase 1–4F14 regression, all workspace tests and Go/with-gVisor
baseline remain delegated to GitHub Actions; no result is pre-claimed.

## Phase 4F15 deliverables and evidence

Phase 4F15 delivers the declared `DNS-19` controller core and completes
`API-09` on loopback TCP. `external-doh-server` is now executable configuration. Its mount
is outside Bearer authentication like the Go router, accepts exact and child
paths, RFC 8484 raw-URL GET plus fixed-length or chunked POST bodies, limits
decoded DNS input to 65,535 bytes and returns `application/dns-message`.
Malformed base64/DNS, disabled DNS, wrong content type and unsupported methods
retain the oracle status and text/empty body classes.

`/dns/query` accepts every symbolic name in the pinned miekg/dns
`StringToType` table with the same case sensitivity and empty-type default.
The DNS crate decodes address, domain-name, character-string and structured RR
data into the Go controller's zone-text JSON shape; unknown wire types retain
RFC 3597 hex form. `hickory-proto` 0.26.1 is used only for bounded RR wire
decoding/rendering; its Rust 1.88 floor is below the workspace's pinned 1.95,
its maintained upstream supports the declared portable core, and its
MIT-or-Apache-2.0 license is compatible with this GPL-3.0-only workspace.
`POST /cache/dns/flush` and
`POST /cache/fakeip/flush` keep Bearer authentication, no-content success and
method behavior. The ordinary cache gate proves a cached repeat followed by a
post-flush upstream refetch; Phases 4F11 and 4F14 retain the deeper
negative/stale and persistent fake-IP lifecycle evidence.

`compat/scripts/phase4f15.py` compares Go and Rust REST status, headers and
JSON for SOA, MX, TXT, SRV, CAA, HTTPS, ANY and default A queries; cache
authentication/method/side effects; and external DoH GET, fixed/chunked POST,
mount-prefix and error paths. External UI/static serving, debug/GC and
TLS/Unix/pipe controller transports remain later API/platform gates.
Exhaustive Go/Rust zone-text vectors for every legacy or obsolete Go-known
RDATA structure remain a documented `DNS-19` gap; no full-product DNS REST
parity is claimed from the representative corpus alone.

Observed Phase 4F15 result on 2026-08-26:

| Platform | Result | Environment |
| --- | --- | --- |
| Darwin arm64 | Declared DNS control surface passed | Native `compat/scripts/phase4f15.py`; local UDP authority, loopback controller and deterministic wire queries |
| Linux amd64 | Pending | Default full differential now includes Phase 4F15; no result is recorded before completion |

### Phase 4F15 local exit gates

```sh
python3 compat/scripts/phase4f15.py

cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test -p rewrite-config -p rewrite-controller -p rewrite-dns
```

The focused Phase 4F15 differential and affected-crate tests pass locally.
Format and strict workspace Clippy are run locally before handoff. Complete
Phase 1–4F15 regression, all workspace tests and Go/with-gVisor baseline remain
delegated to GitHub Actions; no result is pre-claimed.

## Phase 5A1 deliverables and evidence

Phase 5A1 delivers inventory rows `CLI-01` and `CLI-02`. The executable accepts
the oracle's `-d`, `-f` and single- or double-dash `config` forms, with CLI
values overriding `CLASH_HOME_DIR`, `CLASH_CONFIG_FILE` and
`CLASH_CONFIG_STRING`. Relative explicit paths are resolved from the startup
working directory. Without a home override, an existing
`$HOME/.config/mihomo` wins; otherwise a present `XDG_CONFIG_HOME` supplies the
fallback, including the oracle's relative-XDG behavior.

Configuration bytes follow the pinned Go order: non-empty base64 config,
`-f -` stdin, explicit/environment file, then `<home>/config.yaml`. File mode
creates the home directory and writes the exact `mixed-port: 7890` initial file
when the selected path is absent. It does not invent a missing explicit parent.
File-backed SIGHUP reloads retain the resolved path; inline/stdin sources retain
their original YAML instead of reading another source.

The `home` 0.5.12 crate supplies the cross-platform user-home lookup instead of
duplicating Unix and Windows environment/platform rules. It is maintained in
the Rust Cargo repository, supports Rust 1.88 and later (below this workspace's
Rust 1.95 floor), and is MIT-or-Apache-2.0 licensed. Mihomo-specific XDG
existence precedence, path resolution and initial-file behavior remain explicit
and differentially tested in `rewrite-cli`.

`compat/scripts/phase5a1.py` compares 25 Go/Rust cases covering absolute and
relative CLI/environment paths, CLI-over-environment behavior, legacy/XDG
selection, initial-file content and side effects, all four input tiers, an
explicit empty inline override, the oracle's empty decoded/stdin fallthrough to
an uninitialized working-directory `config.yaml`, invalid base64/YAML and
missing-parent errors.
Inline and stdin runtime cases use two local DNS authorities to prove that a
processed SIGHUP resets cache state through the frozen source rather than a
lower-priority shadow file. The gate compares exit acceptance, normalized
successful path output, semantic error class and relevant filesystem/network
side effects without normalizing source choices.

Observed Phase 5A1 result on 2026-08-26:

| Platform | Result | Environment |
| --- | --- | --- |
| Darwin arm64 | Declared `CLI-01`/`CLI-02` scope passed | Native Go 1.26.5 and Rust 1.95.0; temporary homes, working directories and stdin |
| Linux amd64 | Pending | Default full differential includes Phase 5A1; no result is recorded before completion |

### Phase 5A1 local exit gates

```sh
PHASE5A1_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5a1.py

cargo fmt --manifest-path rust/Cargo.toml --all --check
cargo clippy --manifest-path rust/Cargo.toml --workspace --all-targets --all-features -- -D warnings
cargo test --manifest-path rust/Cargo.toml -p rewrite-cli --all-features
```

The focused differential and CLI crate tests pass locally. The full regression
and workspace test suite remain delegated to GitHub Actions. Phase 5A1 makes no
claim about `CLI-03` onward, expanded configuration validation, overrides,
subcommands, hooks or transactional application.

## Phase 5B1a deliverables and evidence

Phase 5B1a advances inventory row `RULE-03` with `DOMAIN-REGEX`. The rule
parser preserves comma-bearing payloads by taking the final field as the
target, compiles expressions once with case-insensitive matching, and delegates
advanced matching to `fancy-regex` 0.19.0 rather than maintaining a regex
engine. Invalid expressions remain configuration errors and match-time engine
errors are non-matches, matching the pinned oracle's observable rule boundary.

`compat/scripts/phase5b1a.py` starts both products with the same mixed listener,
routes lowercase and uppercase `localhost` through an expression containing a
lookahead and `{1,2}` quantifier to a local TCP echo server, and proves an IP
authority falls through to REJECT. Unit tests also pin the matched rule kind and
invalid-expression class. This is not exhaustive `regexp2` syntax parity;
timeouts, Unicode categories and less common .NET constructs remain unclaimed.
`DOMAIN-WILDCARD` is handled by the following independent Phase 5B1b slice.

Local evidence on 2026-08-26:

```sh
PHASE5B1A_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5b1a.py
cargo test --manifest-path rust/Cargo.toml -p rewrite-rules --all-features
cargo fmt --manifest-path rust/Cargo.toml --all --check
cargo clippy --manifest-path rust/Cargo.toml --workspace --all-targets --all-features -- -D warnings
```

The focused tests pass locally. Full regression and Linux evidence remain
delegated to GitHub Actions and are not pre-claimed.

## Phase 5B1b deliverables and evidence

Phase 5B1b adds `DOMAIN-WILDCARD` without treating it as a filesystem glob.
The pinned Go matcher compares bytes: `*` consumes zero or more bytes and `?`
exactly one byte. Rust keeps that small compatibility algorithm at the rule
boundary, lowercases the configured pattern like Go, and compiles no regex for
this rule kind. Unit tests include empty patterns and a non-ASCII value to
prevent an accidental future switch to Unicode-scalar matching.

`compat/scripts/phase5b1b.py` reuses the Phase 5B1 mixed-listener harness and
compares a `local?o*` DIRECT route plus IP-authority REJECT fallback against the
Go oracle. This closes implementation of the two named RULE-03 kinds in the
declared local TCP corpus, but RULE-03 remains partial until the broader
regexp2 syntax, Unicode, sub-rule and intercepted-host matrix is exercised.

Local evidence on 2026-08-26:

```sh
PHASE5B1B_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5b1b.py
cargo test --manifest-path rust/Cargo.toml -p rewrite-rules --all-features
cargo fmt --manifest-path rust/Cargo.toml --all --check
cargo clippy --manifest-path rust/Cargo.toml --workspace --all-targets --all-features -- -D warnings
```

The focused tests pass locally. Full regression and Linux evidence remain
delegated to GitHub Actions and are not pre-claimed.

## Phase 5B2a deliverables and evidence

Phase 5B2a starts `RULE-05` with literal destination IPv4 `IP-SUFFIX`. Unlike
CIDR containment, the oracle preserves the address bits in the prefix text and
compares the requested number of bits from the end of the address. Rust parses
the address and width separately rather than using `ipnet`, which would risk
normalizing away the host bits that are the rule's payload.

`compat/scripts/phase5b2a.py` selects a native non-loopback IPv4 address, finds
the shortest whole-byte suffix that distinguishes it from `127.0.0.1`, and
runs one all-interface local echo server. The suffix route reaches DIRECT while
the loopback literal falls through to REJECT; an over-wide `/33` rule is
rejected by both products. Hosts without a non-loopback IPv4 interface report
an explicit skip rather than using a public network.

Local evidence on 2026-08-26:

```sh
PHASE5B2A_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5b2a.py
cargo test --manifest-path rust/Cargo.toml -p rewrite-rules --all-features
cargo fmt --manifest-path rust/Cargo.toml --all --check
cargo clippy --manifest-path rust/Cargo.toml --workspace --all-targets --all-features -- -D warnings
```

Destination IPv6, non-byte widths, IPv4-mapped IPv6, `src` and
`SRC-IP-SUFFIX`, and observable lazy/no-resolve resolver calls remain pending;
this phase does not claim them.

## Phase 5B2b deliverables and evidence

Phase 5B2b adds the source forms of the IPv4 suffix matcher. Both
`SRC-IP-SUFFIX,prefix,target` and `IP-SUFFIX,prefix,target,src` compile to the
same source matcher, never request destination resolution and expose the
oracle's `SrcIPSuffix` matched kind. The implementation reuses the suffix-bit
core from Phase 5B2a rather than duplicating source-specific matching code.

`compat/scripts/phase5b2b.py` uses the mixed listener's deterministic
`127.0.0.1` client source. Each source spelling routes a connection to a local
echo through DIRECT, while a suffix ending in `.2` falls through to REJECT.
Destination address and echo behavior are held constant, so only the source
rule can account for the different outcome.

Local evidence on 2026-08-26:

```sh
PHASE5B2B_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5b2b.py
cargo test --manifest-path rust/Cargo.toml -p rewrite-rules --all-features
cargo fmt --manifest-path rust/Cargo.toml --all --check
cargo clippy --manifest-path rust/Cargo.toml --workspace --all-targets --all-features -- -D warnings
```

IPv6, partial-byte suffixes, mapped-address family behavior and observable
resolver invocation remain pending before RULE-05 can be called complete.

## Phase 5B2c deliverables and evidence

Phase 5B2c adds the `DSCP` matcher and makes the metadata value explicit across
the runtime and controller snapshot boundary. The current ordinary mixed TCP
listener does not recover a packet DSCP value, so its honest value is `0`; the
implementation does not synthesize nonzero metadata to widen this claim.

The matcher accepts slash-separated values and inclusive ranges, normalizes a
reversed range like the oracle, treats `*` as a wildcard, and rejects values
above the six-bit DSCP limit. `compat/scripts/phase5b2c.py` proves `0` reaches
DIRECT, `1` falls through to REJECT, `1/2-0` and `*` reach DIRECT, and `64` is a
configuration error in both products.

Local evidence on 2026-08-26:

```sh
PHASE5B2C_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5b2c.py
cargo test --manifest-path rust/Cargo.toml -p rewrite-model -p rewrite-rules -p rewrite-state --all-features
cargo fmt --manifest-path rust/Cargo.toml --all --check
cargo clippy --manifest-path rust/Cargo.toml --workspace --all-targets --all-features -- -D warnings
```

The focused differential and checks pass locally. Capturing nonzero DSCP from
transparent proxy, TUN or UDP paths remains pending, so RULE-06 remains partial.

## Phase 5B2d deliverables and evidence

Phase 5B2d promotes destination port, inbound port and network matching from
the pure policy oracle to a live mixed TCP path. Each rule is rendered only
after the fixture has reserved the listener and echo ports, avoiding fixed-port
collisions and making the compared metadata the real socket values.

`compat/scripts/phase5b2d.py` proves destination-port and inbound-port exact
hits plus adjacent-port misses. It also proves the same connection reports
`NETWORK,TCP` and does not report `NETWORK,UDP`. Every pair yields an observable
DIRECT echo or REJECT close in both products.

Local evidence on 2026-08-27:

```sh
PHASE5B2D_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5b2d.py
cargo clippy --manifest-path rust/Cargo.toml --workspace --all-targets --all-features -- -D warnings
```

Live `SRC-PORT`, UDP ingress metadata and nonzero DSCP capture remain pending,
so aggregate RULE-06 remains partial.

## Phase 5B2e deliverables and evidence

Phase 5B2e completes live port metadata for the current TCP inbound by proving
`SRC-PORT`. The fixture binds two client sockets before proxy startup, retaining
their exact ephemeral ports without a reserve/close race. A separate localhost
DIRECT probe waits for Go's provider publication before either source socket is
connected, so the rule result cannot be confused with startup defaults.

`compat/scripts/phase5b2e.py` places one bound port in the rule. That client
receives a DIRECT echo, while the other simultaneously reserved source port
falls through to REJECT. Both outcomes match the pinned Go oracle.

Local evidence on 2026-08-27:

```sh
PHASE5B2E_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5b2e.py
cargo clippy --manifest-path rust/Cargo.toml --workspace --all-targets --all-features -- -D warnings
```

UDP ingress metadata and capture of nonzero DSCP remain pending, so aggregate
RULE-06 remains partial.

## Phase 5B3a deliverables and evidence

Phase 5B3a begins `RULE-08` with `IN-TYPE` on the currently implemented local
TCP inbounds. It also corrects the metadata boundary exposed by the oracle:
HTTP absolute-form requests are type `HTTP`, while HTTP CONNECT tunnels are
type `HTTPS`. SOCKS4 and SOCKS5 remain distinct, and the Go `SOCKS` payload
alias expands to both. Slash-separated type lists are parsed once into the rule
matcher; unsupported future inbound kinds remain rejected in this partial gate.

`compat/scripts/phase5b3a.py` sends all four wire inputs through one mixed
listener. One configuration routes HTTP/SOCKS4 to DIRECT and HTTPS/SOCKS5 to
REJECT; a second proves that `SOCKS` selects both SOCKS versions but neither
HTTP form. The fixture waits for a DIRECT echo before collecting outcomes,
closing the oracle's listener-open/provider-publication startup window.

Local evidence on 2026-08-26:

```sh
PHASE5B3A_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5b3a.py
cargo test --manifest-path rust/Cargo.toml -p rewrite-model -p rewrite-inbound -p rewrite-rules -p rewrite-state --all-features
cargo fmt --manifest-path rust/Cargo.toml --all --check
cargo clippy --manifest-path rust/Cargo.toml --workspace --all-targets --all-features -- -D warnings
```

The focused differential passed twice consecutively after the readiness
barrier. `IN-USER`, `IN-NAME`, UDP metadata and future inbound protocol kinds
remain separate phases.

## Phase 5B3b deliverables and evidence

Phase 5B3b adds `IN-USER` and carries the authenticated identity into shared
metadata. HTTP Basic returns the configured username after credential
validation, SOCKS5 records the RFC 1929 username, and SOCKS4 records USERID.
The connection/controller metadata snapshot now exposes the same value instead
of an unconditional empty string. With authentication disabled, the field
remains empty.

The rule parser accepts one exact case-sensitive username or a slash-separated
list, rejecting empty members. `compat/scripts/phase5b3b.py` authenticates the
same `alice` identity through HTTP and SOCKS5, a passwordless `socks4` USERID
through SOCKS4, and a distinct valid `Alice` identity to prove case sensitivity.
Exact and list configurations produce separate DIRECT echo and REJECT-close
observations in both products after the same readiness barrier as Phase 5B3a.

Local evidence on 2026-08-26:

```sh
PHASE5B3B_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5b3b.py
cargo test --manifest-path rust/Cargo.toml -p rewrite-inbound -p rewrite-rules -p rewrite-state --all-features
cargo fmt --manifest-path rust/Cargo.toml --all --check
cargo clippy --manifest-path rust/Cargo.toml --workspace --all-targets --all-features -- -D warnings
```

Invalid UTF-8 protocol usernames, UDP-association user propagation, remote
inbound protocols and `IN-NAME` remain outside this phase.

## Phase 5B3c deliverables and evidence

Phase 5B3c completes the current fixed local TCP subset of `RULE-08` by adding
`IN-NAME`. Runtime listener identity is attached after protocol decoding:
`port` is `DEFAULT-HTTP`, `socks-port` is `DEFAULT-SOCKS`, and `mixed-port` is
`DEFAULT-MIXED`, exactly matching the pinned listener additions. Connection
snapshots now carry the same metadata value.

The matcher is case-sensitive and accepts slash-separated names.
`compat/scripts/phase5b3c.py` starts all three fixed listeners together, sends
HTTP through the HTTP and mixed ports and SOCKS5 through the SOCKS port, and
compares DIRECT echo for the HTTP/mixed name list with REJECT for the SOCKS
name. DIRECT probes form the provider-readiness barrier before the rejection
observation.

Local evidence on 2026-08-26:

```sh
PHASE5B3C_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5b3c.py
cargo test --manifest-path rust/Cargo.toml -p rewrite-model -p rewrite-rules -p rewrite-runtime -p rewrite-state --all-features
cargo fmt --manifest-path rust/Cargo.toml --all --check
cargo clippy --manifest-path rust/Cargo.toml --workspace --all-targets --all-features -- -D warnings
```

SOCKS UDP listener-name propagation, YAML named listeners and future inbound
protocol names remain pending, so aggregate RULE-08 remains partial.

## Phase 5B3d deliverables and evidence

Phase 5B3d promotes the existing pure `AND`, `OR` and `NOT` matcher subset to a
live routing claim. The gate combines `DOMAIN` and `IN-TYPE` conditions on an
HTTP CONNECT request, so the result crosses configuration parsing, inbound
metadata, ordered rule evaluation, adapter selection and the TCP relay.

`compat/scripts/phase5b3d.py` runs three isolated configurations. AND requires
both the `localhost` host and HTTPS CONNECT type, OR accepts either condition,
and NOT reverses the host result. Each case proves both a DIRECT echo and a
REJECT close against the pinned Go oracle.

Local evidence on 2026-08-26:

```sh
PHASE5B3D_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5b3d.py
cargo clippy --manifest-path rust/Cargo.toml --workspace --all-targets --all-features -- -D warnings
```

Live `SUB-RULE`, lazy DNS/process-helper behavior and the larger nested/error
corpus remain pending, so aggregate RULE-11 remains partial.

## Phase 5B3e deliverables and evidence

Phase 5B3e promotes `PASS` from a pure evaluator observation to a live mixed
TCP routing contract. A matched PASS is a scan-control action: it must skip
adapter selection and continue with the following rule.

`compat/scripts/phase5b3e.py` proves both continuations. One configuration
passes a `localhost` match into a later `DOMAIN,...,DIRECT` while a literal IP
falls through to REJECT; another passes the same host into `MATCH,REJECT`.
The resulting echo and connection-close observations match the pinned Go
oracle.

Local evidence on 2026-08-26:

```sh
PHASE5B3E_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5b3e.py
cargo clippy --manifest-path rust/Cargo.toml --workspace --all-targets --all-features -- -D warnings
```

Live `PASS-RULE`, sub-rule escape and rematch mutation/rescan remain pending,
so aggregate RULE-12 remains partial.

## Phase 5B3f deliverables and evidence

Phase 5B3f adds live `SUB-RULE` entry and `PASS-RULE` continuation. A TCP
condition selects a named branch; PASS-RULE skips only the matching child and
does not select an outbound. When the child list is exhausted without a final
target, evaluation resumes at the next main rule.

`compat/scripts/phase5b3f.py` proves both control-flow paths. In the first,
`localhost` passes one child and reaches a later branch DIRECT while the IP
literal reaches the branch REJECT. In the second, the only child returns
PASS-RULE and the main MATCH selects DIRECT. The prior Phase 5B3e script is
rerun because its live fixture is now shared with this phase.

Local evidence on 2026-08-26:

```sh
PHASE5B3E_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5b3e.py
PHASE5B3F_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5b3f.py
cargo clippy --manifest-path rust/Cargo.toml --workspace --all-targets --all-features -- -D warnings
```

Lazy DNS/process helpers and broader nested/cycle live behavior remain pending
for RULE-11; live REMATCH remains pending for RULE-12.

## Phase 5B3g deliverables and evidence

Phase 5B3g makes the already parsed REMATCH proxies executable in the Rust
runtime. They remain rule-engine scan actions rather than network outbounds.
Runtime admission now accepts a rule target backed by a REMATCH action while
continuing to reject unrelated unsupported proxy targets.

`compat/scripts/phase5b3g.py` proves both mutation forms. `target-rematch-name`
sets `after` and rescans the main rules, where host metadata produces separate
DIRECT and REJECT results. `target-sub-rule` switches the next scan to a named
branch with the same two observable network outcomes. A config unit test pins
runtime admission so this support cannot silently regress to parse-only.

Local evidence on 2026-08-27:

```sh
PHASE5B3G_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5b3g.py
cargo test --manifest-path rust/Cargo.toml -p rewrite-rules -p rewrite-config --all-features
cargo fmt --manifest-path rust/Cargo.toml --all --check
cargo clippy --manifest-path rust/Cargo.toml --workspace --all-targets --all-features -- -D warnings
```

The focused differential and checks pass locally. REMATCH cycle termination
and mutation-failure paths remain pending, so aggregate RULE-12 stays partial.

## Phase 5B current SOCKS5 UDP metadata deliverables and evidence

This aggregate phase closes the rule-metadata loop for the currently available
SOCKS5 UDP ingress instead of splitting every field into a separate migration.
One AND rule consumes the real UDP source, destination and inbound ports,
`NETWORK,UDP`, default `DSCP,0`, `IN-TYPE,SOCKS5` and the listener name before
the packet can reach a local echo server.

The pinned Go default mixed UDP socket is implemented by its SOCKS UDP listener,
so both `socks-port` and `mixed-port` expose `DEFAULT-SOCKS`; Rust now preserves
that non-obvious behavior. UDP packets also do not inherit the TCP SOCKS auth
identity in the oracle. The differential enables authentication and places an
`IN-USER,alice,REJECT` rule first, proving the raw UDP metadata remains empty
rather than fabricating an association user.

`compat/scripts/phase5b_udp.py` sends bound UDP clients through both fixed
listeners and compares complete SOCKS5 UDP echo/timeout outcomes. A third
unlisted source port proves the composite matcher falls through to REJECT.

Local evidence on 2026-08-27:

```sh
PHASE5BUDP_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5b_udp.py
cargo test --manifest-path rust/Cargo.toml -p rewrite-inbound -p rewrite-runtime --all-features
cargo fmt --manifest-path rust/Cargo.toml --all --check
cargo clippy --manifest-path rust/Cargo.toml --workspace --all-targets --all-features -- -D warnings
```

The aggregate differential passes locally. Nonzero DSCP extraction,
transparent/TUN metadata, YAML named listeners and future inbound protocols
remain attached to their platform or protocol phases.

## Phase 5B aggregate core domain/IP deliverables and evidence

This aggregate phase advances three related core destination-rule rows in one
gate. `DOMAIN`, `DOMAIN-SUFFIX` and `DOMAIN-KEYWORD` route hosts-backed names
through the real mixed TCP path. Destination/source CIDR rules consume real
socket metadata, while a reserved `.invalid` name proves `no-resolve` falls
through without relying on the machine's special localhost hosts entry.

IP suffix coverage now includes non-byte-aligned IPv4 hit/miss and a live
IPv4-mapped IPv6 destination. Rust normalizes mapped addresses at the shared
metadata boundary, as the Go tunnel does, so rule matching and the final DIRECT
dial both use IPv4. Fixed Phase 2 cases add IPv6 destination hit/miss, IPv6
source matching and invalid `/129` validation without depending on native IPv6
availability in local development.

`compat/scripts/phase5b_core.py` contains the complete live matrix; the pinned
Phase 2 fixture now contains 41 fixed cases.

Local evidence on 2026-08-27:

```sh
PHASE5BCORE_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5b_core.py
PHASE2_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase2.py --generated-configs 0 --generated-rules 0
cargo test --manifest-path rust/Cargo.toml -p rewrite-model -p rewrite-inbound -p rewrite-runtime --all-features
cargo fmt --manifest-path rust/Cargo.toml --all --check
cargo clippy --manifest-path rust/Cargo.toml --workspace --all-targets --all-features -- -D warnings
```

Both aggregate and fixed differentials pass locally. Native IPv6 network
routing, exhaustive IDNA/sniffer contexts and remaining resolver-call variants
retain their explicit matrix gaps.

## Phase 5D aggregate controller core deliverables and evidence

The controller now uses Axum's WebSocket implementation for the four existing
read-only observability surfaces. `/traffic` and `/memory` emit one JSON text
frame per second, `/logs` delivers filtered runtime events, and
`/connections` sends an immediate snapshot followed by the requested
millisecond interval. Socket receive branches observe peer close/error while
the runtime cancellation token stops every stream during shutdown.

Authentication preserves the pinned oracle boundary: ordinary HTTP and
WebSockets may use `Authorization: Bearer`; only an actual WebSocket upgrade
may replace it with a nonempty `token` query parameter. A wrong nonempty query
token does not fall back to the header. `/memory` preserves the zero-valued
first frame expected by the controller UI. Current Rust memory remains zero,
so real process-memory accounting is not claimed.

`compat/scripts/phase5d_streams.py` starts complete Go and Rust products and
compares wrong-token rejection, both successful authorization forms,
handshake headers, HTTP memory and WebSocket memory/traffic/connections first
frames, interval parsing and a live mixed-TCP log event. It passed locally on
Darwin arm64 on 2026-08-27.

The connections resource is also complete for the current local TCP runtime.
Each tracked connection owns a cancellation token shared with its relay task.
`DELETE /connections/{id}` removes and cancels exactly the selected tracker,
including an idempotent missing-ID response; `DELETE /connections` drains and
cancels the current tracker set. `compat/scripts/phase5d_connections.py` holds
two real DIRECT tunnels, identifies one through returned metadata, proves the
other remains usable after single deletion, then proves collection deletion
closes the survivor and returns a null connection list. All three mutations
match the oracle's empty 204 response.

Controller authentication and CORS are now complete on the current TCP
surface. Rust parses the Go defaults (`allow-origins: ["*"]` and Private
Network enabled), nested partial overrides and the oracle's empty-list
allow-all behavior. `tower-http` 0.7.0 supplies CORS framing and preflight
handling; a small compatibility wrapper retains the fixed Go method/header
allowlist, single-wildcard origin matching and exact ordinary/preflight `Vary`
headers. Because the layer reads the shared watched configuration per request,
same-address SIGHUP reload changes the policy without a listener gap.

`compat/scripts/phase5d_cors.py` compares default allowed and unauthorized
actual requests, allowed Private Network preflight, denied method/header,
configured exact/wildcard/denied origins, disabled Private Network and two hot
reloads including an explicit empty origin list. Preflight succeeds without a
Bearer token, matching the oracle's CORS-before-auth middleware order.

The current executable `API-04` configuration subset now uses a bounded
controller-to-runtime request channel with an explicit completion response.
The runtime first parses the requested generation and binds every new local
socket, publishes the watched configuration only after preparation succeeds,
then retires obsolete listeners. Inline `PUT /configs` preserves the serving
controller's address, secret, DoH mount and CORS configuration, matching the
oracle's exclusion of the external controller during `ApplyConfig`. `PATCH`
updates the currently executable HTTP, SOCKS and mixed ports, log level and
IPv6 fields; unknown JSON fields remain ignored.

`compat/scripts/phase5d_configs.py` compares the live GET subset, malformed and
unknown PATCH inputs, mixed-listener migration with closure of the old port,
inline YAML switching `MATCH` between DIRECT and REJECT, `force=true`, payload
precedence over a relative path, and malformed-YAML rollback of both routing
and the visible generation. Safe-root/default path loading, the other Go PATCH
fields and `/configs/geo` are deliberately still unclaimed.

The current top-level rule program now carries shared atomic wrapper state.
Every evaluation records the selected rule's hit or each preceding miss, while
a disabled rule is skipped without changing its counters. `GET /rules` exposes
ordered index/type/payload/proxy/size fields and wrapper state; cloned runtime
configuration handles share those counters. `PATCH /rules/disable` applies
valid nonnegative indexes in place and ignores out-of-range indexes like the
oracle.

`compat/scripts/phase5d_rules.py` waits for the oracle's provider-readiness
boundary, takes a counter baseline, then compares exact counter deltas and
timestamp advancement for one DomainSuffix DIRECT hit and one MATCH REJECT
fallback. It proves disable changes the live route to REJECT without counting
the skipped rule, enable restores DIRECT, malformed JSON returns the oracle
error, and negative/out-of-range indexes are no-ops. Exhaustive payload
rendering, GeoIP/GeoSite sizes and reload-state lifecycle remain unclaimed.

The controller also implements the complete process-local JSON storage
lifecycle. Runtime state owns an isolated key/value map; Axum decodes escaped
path keys and frames bodies, while `serde_json` validates writes before an
atomic replacement. Values retain their original JSON whitespace and bytes.
Missing reads return literal `null`, deletion is idempotent, invalid JSON is a
400, and a valid value over 1 MiB is a 413 without changing the prior value.

`compat/scripts/phase5d_storage.py` compares all of those statuses, bodies,
content types and rollback effects using an escaped Unicode/path key. This gate
does not claim storage across process restart or interchange with the oracle's
cache database; that persistence boundary remains separate from the accepted
HTTP contract.

The current built-in proxy registry and implicit GLOBAL selector are now
visible through `/proxies` and `/group`. The JSON view preserves the seven
built-in names and types, adapter UUID conventions (including zero IDs for
PASS/PASS-RULE and no selector ID), initial alive state, capability flags,
GLOBAL members/current choice and exact not-found/non-selector/invalid-choice
errors. GLOBAL selection is shared by the controller's runtime state and can
switch between DIRECT and REJECT.

Proxy delay uses Hyper's maintained HTTP/1 client connection and sends the
oracle's HEAD request through the current local DIRECT/COMPATIBLE boundary.
Successful tests update the ten-entry adapter history and per-URL `extra`
health state; GLOBAL group delay tests its current built-in member set and
returns the successful DIRECT result. `compat/scripts/phase5d_proxies.py`
compares list/detail/group shapes, mutations, validation, positive local delay,
history side effects and group results. Remote adapters/groups, HTTPS,
exhaustive failure/timeout behavior and selection reload/persistence remain
unclaimed.

Rule, Direct and Global modes are now executable on every current mixed TCP
and SOCKS UDP path. Direct bypasses rule evaluation, while Global resolves the
runtime's current GLOBAL DIRECT/REJECT selection for each new connection or
UDP association. Controller PATCH and inline-YAML PUT publish the mode through
the existing transactional generation channel, and invalid mode input leaves
the prior generation active.

`compat/scripts/phase5d_modes.py` begins with a rejecting MATCH rule, switches
through Direct and Global, changes GLOBAL from DIRECT to REJECT and back,
restores Rule mode, verifies invalid-input rollback, then applies Direct via
inline YAML. Every state is observed through `/configs` plus real TCP and UDP
echo behavior. Fresh UDP source sockets model the oracle's association cache;
existing-association retention and configured remote GLOBAL members remain
outside this gate.

The controller now also exposes the pinned oracle's implicit provider boundary.
`/providers/proxies` lists the `default` compatible provider with DIRECT and
REJECT, including the zero-time `updatedAt` value; provider detail and member
views reuse the built-in adapter state. The default update and health-check
operations return 204 because this compatible provider has no external vehicle.
`/providers/rules` returns the oracle's empty map, while unknown providers and
members preserve its 404 JSON error.

`compat/scripts/phase5d_providers.py` compares proxy-provider list/detail/member,
no-op update/health, missing proxy resources, the empty rule-provider list and
missing rule-provider update. This is deliberately partial `API-08`: file/HTTP
providers, refresh timers, real health transitions, configured rule providers
and persistence are not implemented or claimed.

Local focused evidence:

```sh
PHASE5DSTREAMS_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5d_streams.py
PHASE5DCONNECTIONS_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5d_connections.py
PHASE5DCORS_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5d_cors.py
PHASE5DCONFIGS_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5d_configs.py
PHASE5DRULES_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5d_rules.py
PHASE5DSTORAGE_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5d_storage.py
PHASE5DPROXIES_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5d_proxies.py
PHASE5DMODES_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5d_modes.py
PHASE5DPROVIDERS_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5d_providers.py
cargo test --manifest-path rust/Cargo.toml -p rewrite-config -p rewrite-state -p rewrite-controller -p rewrite-runtime --all-features
cargo fmt --manifest-path rust/Cargo.toml --all --check
cargo clippy --manifest-path rust/Cargo.toml --workspace --all-targets --all-features -- -D warnings
```

TLS/Unix/pipe listeners, real process memory, structured logs, exhaustive
filters/cadence/backpressure, the remaining configuration mutations and
mutations outside the now-complete current-local connections resource remain
explicit Phase 5D gaps.

## Controller HTTP infrastructure refactor

The post-Phase 4F15 controller now uses Axum 0.8.9 over Hyper 1.11.0 instead of
maintaining a local HTTP/1 request parser, chunk decoder, route switch and
socket response writer. Static REST routes use typed Axum handlers; an outer
middleware retains the runtime-configured external DoH mount before Bearer
authentication. Hyper handles fixed-length/chunked request framing and
connection lifecycle, while explicit response helpers retain the oracle's
JSON, DNS-message, text and empty-body content classes. Traffic and log streams
remain streaming bodies tied to the runtime cancellation token.

This was intentionally a behavior-neutral infrastructure change. At that
refactor boundary it did not claim TLS/Unix/pipe listeners, WebSockets, CORS,
mutation APIs, external UI or
any additional DNS/proxy protocol. `axum` is MIT licensed, has a Rust 1.80
minimum below the workspace Rust 1.95 toolchain, is maintained in the Tokio
project, and supports the existing portable Tokio TCP boundary. The initial
feature set was HTTP/1, JSON and Tokio integration; the later Phase 5D gate
additionally enables Axum's maintained WebSocket stack.

Local evidence on 2026-08-26:

```sh
PHASE3_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase3.py
PHASE4_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase4d4.py
PHASE4_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase4f14.py
PHASE4_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase4f15.py
cargo test -p rewrite-controller -p rewrite-runtime -p rewrite-dns --all-features
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

The four focused Go/Rust differential suites and affected-crate tests pass.
Format and strict workspace Clippy are required before handoff; the full
Phase 1–4F15 regression remains delegated to GitHub Actions.

## CI portability and Phase 4F14 signal barrier

GitHub Actions run `32954739951` exposed two independent CI-only failures.
The Windows native `rewrite-platform` job linked that crate in isolation, so
`dhcproto`'s no-default-features `hickory-proto` edge did not inherit the
`std` feature enabled elsewhere by `rewrite-dns`. `rewrite-platform` now
declares `hickory-proto/std` directly; the standalone dependency graph and all
nine platform tests pass locally. The Windows-native rerun remains the
acceptance authority.

Phase 4F14 also no longer assumes that a listening Go DNS socket means
`signal.Notify` is installed. Its reload polling re-sends SIGHUP at a bounded
interval until the changed fake-IP filter is observable, and each bbolt
interchange generation crosses the same observable reload barrier before
SIGTERM asks the product to persist its allocation offset. This preserves the
exact v4/v6 mapping assertions while removing the startup race that could
terminate the Go oracle before `StoreState`. A native Linux arm64 Docker run
proved Go→Rust→Go v4/v6 mapping interchange and three zero exit codes. On a
future mismatch the script now writes the three mapping snapshots to the
existing Phase 4F14 failure artifact instead of losing the evidence.

## DoH HTTP/1 client infrastructure refactor

The plaintext and TLS HTTP/1 DoH paths now use Hyper 1.11's client-connection
API instead of serializing request lines and parsing status/header/body framing
inside `rewrite-dns`. Hyper connection drivers own each TCP/TLS stream; the
resolver pools bounded request senders and still owns transport identity,
reload invalidation, one fresh retry after a stale pooled connection and the
separate H2/H3/DoQ paths. The compatibility layer continues to require an
explicit `Content-Length`, bounds the DNS body, enforces same-origin relative
redirects and the ten-request limit, verifies zero upstream DNS IDs and
restores the client ID.

`compat/scripts/phase4e5.py` through `phase4e8.py` and `phase4e12.py` through
`phase4e15.py` all re-pass locally on 2026-08-26. This infrastructure change
does not expand supported DoH URL forms, transports, concurrency or retry
behavior.

## Common DNS wire codec refactor

Ordinary DNS query construction and question/compressed-name decoding now use
the existing `hickory-proto` 0.26.1 dependency. This removes local label-length,
pointer-loop and query field codecs from those generic paths. Explicit raw-wire
logic remains where it encodes observable Mihomo behavior: request flag echo,
local authoritative answers, EDNS preservation, UDP truncation, cache identity
and hosts/fake-IP responses.

Phase 4A, Phase 4F1 and Phase 4F15 Go/Rust differential suites re-pass locally
on 2026-08-26. No new RR type, malformed-message acceptance or resolver role is
claimed by the codec migration.

## Differential fixture timing stability

The shared DNS fixture cleanup normalizes `-SIGTERM` only when that exact
signal was sent by the harness to a still-running product. A process that exits
before cleanup, any other signal, timeout or forced `SIGKILL` remains an exact
observable failure. Common 30-second authority answers are compared as one
narrow 27–30 second freshness window so independent wall-clock rounding cannot
create a false Go/Rust mismatch; values outside that window fail immediately,
and Phase 4F11 continues to compare the semantic TTL=1 stale boundary and cache
lifecycle separately.

The Phase 4E17 empty-response case retains and validates the first DoQ framing
exchange but excludes whether the Phase 4F11 background retry starts before or
after the authority snapshot. Its retry count and bound remain covered by the
Phase 4F11 differential instead of being sampled concurrently by two phases.
The previously fluctuating Phase 4E1, 4E17, 4F6 and 4F11 focused suites pass
locally with these scope-specific normalizations.

The shared product launcher now binds `HOME`, `XDG_CONFIG_HOME` and
`CLASH_HOME_DIR` to each scenario's scratch tree. This prevents the Go
oracle's selector `cache.db` from escaping through a runner-provided XDG path
and changing the next scenario's initial `default-selected` observation. The
Phase 5C reload and initial-selector fixtures pass consecutively in CI order;
the change normalizes no product output and only isolates process state.

The plaintext HTTP outbound fixture now uses the same bounded data-plane
readiness gate as the authenticated SOCKS5 fixture before clearing setup
observations and collecting its one comparable CONNECT exchange. A transient
first connection during Go listener startup can therefore no longer abort the
aggregate run, while a route that never carries the exact echo bytes still
fails within the common I/O deadline.

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

The Phase 6B1a HTTP outbound gate accepts only plaintext TCP CONNECT. The
configuration model carries a named HTTP server, port and optional Basic
credentials into the runtime; rule parsing recognizes that name as an
executable target. Hyper owns the HTTP/1 CONNECT exchange and upgrade, and the
existing bounded runtime cancellation/tracking path owns the resulting relay.
The differential fixture observes CONNECT method, normalized ephemeral
authority/Host, Proxy-Authorization, successful echo and an independent
REJECT result.

Local focused evidence:

```sh
PHASE6BHTTP_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase6b_http.py
cargo test --manifest-path rust/Cargo.toml -p rewrite-config -p rewrite-rules -p rewrite-outbound -p rewrite-runtime --all-features
cargo fmt --manifest-path rust/Cargo.toml --all --check
cargo clippy --manifest-path rust/Cargo.toml --workspace --all-targets --all-features -- -D warnings
```

TLS, partial credentials, full failure behavior, controller rendering, proxy
groups/providers and UDP were explicitly outside this first gate; the native
HTTP items are closed by the Phase 6B completion gate below.

The Phase 5C1a selector gate adds flat configured selectors without claiming
the automatic group families. Runtime state retains each valid selection while
the configuration generation remains active; the controller exposes exact
configured HTTP/Selector detail JSON and validates PUT choices. The selected
member is resolved only when opening a new TCP connection, and its UDP support
field changes with the member just as in the oracle. Both configured objects
also join the implicit `default` compatible provider and its member lookup.

Local focused evidence:

```sh
PHASE5CSELECTOR_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5c_selector.py
cargo test --manifest-path rust/Cargo.toml -p rewrite-config -p rewrite-state -p rewrite-controller -p rewrite-runtime --all-features
```

Nested groups, providers, reload/persistence and URL-test/fallback/load-balance
remain outside this selector gate.

The Phase 6B2a SOCKS5 gate reuses the same configured outbound and boxed async
stream boundaries as HTTP. `fast-socks5` 1.0.0 supplies Tokio target-address
encoding, CONNECT processing and stream I/O under the MIT license. Its default
password client also advertises no-auth, whereas the pinned Go oracle advertises
only password when credentials exist; the local compatibility adapter therefore
emits the oracle greeting before handing the remaining standardized fields to
the library boundary. Phase 6B2b records that the oracle nevertheless accepts
a server-selected no-auth method.

Local focused evidence:

```sh
PHASE6BSOCKS_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase6b_socks5.py
cargo test --manifest-path rust/Cargo.toml -p rewrite-config -p rewrite-outbound -p rewrite-controller -p rewrite-runtime --all-features
```

No-auth, resolution-policy permutations, TLS, complete failures and SOCKS5 UDP
were outside this first gate and are closed by later Phase 6B gates. Native UoT
is false; dialer chains remain OUT-21.

Phase 6B2b closes the current plaintext SOCKS5 TCP handshake contract. The
pinned Go adapter enables RFC 1929 only when the username is nonempty, permits
an empty or absent password, ignores a password-only configuration, accepts a
server-selected no-auth downgrade, and retries terminal method/version failures
ten times. It also sends domain, IPv4 and IPv6 targets without local conversion.
The oracle accepts a CONNECT response with a nonzero reply status when its bind
address is structurally valid; Rust preserves that observable behavior rather
than silently adopting the library's stricter status policy.

`fast-socks5` still owns target-address encoding and response-address parsing.
The custom boundary is limited to the method exchange, RFC 1929 bytes, the
oracle's CONNECT status policy and the five-second handshake deadline.

Local focused evidence:

```sh
PHASE6BSOCKSCONTRACT_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase6b_socks5_contract.py
cargo test --manifest-path rust/Cargo.toml -p rewrite-config -p rewrite-outbound -p rewrite-controller -p rewrite-runtime --all-features
```

TLS, UDP ASSOCIATE and credential lengths above 255 bytes are closed by Phase
6B3. Native UoT is false; dialer chains remain the separate OUT-21 gate.

Phase 5C1b adds selector reconciliation to the transactional generation publish
barrier. It distinguishes initial `default-selected` from reload recovery: an
existing valid choice wins, an invalid generation changes nothing, and a choice
removed by a valid generation falls back to the first new member. The fixture
also observes the resulting HTTP/DIRECT data-plane behavior.

```sh
PHASE5CSELECTORRELOAD_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5c_selector_reload.py
```

Phase 5C2a adds synchronous local YAML file providers to configuration
validation. Provider proxies share the existing typed HTTP/SOCKS5 model and
outbound implementations, while groups keep separate expanded members and
explicit compatible-provider members. The controller reports deterministic
file modification time, File vehicle metadata, provider-name on member
adapters and the oracle's implicit group-compatible provider.

```sh
PHASE5CFILEPROVIDER_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5c_file_provider.py
cargo test --manifest-path rust/Cargo.toml -p rewrite-config -p rewrite-controller -p rewrite-runtime --all-features
```

Manual refresh, file-watch/interval scheduling, HTTP vehicles, filters,
overrides, health state and persistence are outside this initial-load gate.

Phase 5C2b promotes file reload into the existing controller-to-runtime
configuration transaction. Parsing, duplicate checks, provider replacement and
dependent group expansion happen on a clone before publication. Successful PUT
switches member APIs and live routing together; malformed YAML never reaches
the active generation and produces the oracle's 503 class.

```sh
PHASE5CPROVIDERREFRESH_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5c_provider_refresh.py
cargo test --manifest-path rust/Cargo.toml -p rewrite-config -p rewrite-controller -p rewrite-runtime --all-features
```

Concurrent refresh/coalescing, old live-connection cleanup, intervals/file
watching, HTTP remote updates and health scheduling remain unclaimed by 5C2b.

Phase 5C2c adds the first remote provider vehicle without adding a second HTTP
implementation. Configuration declares a plaintext URL and explicit cache
path but does not perform I/O in `-t` mode. Runtime startup uses Hyper HTTP/1
with a four-MiB bound, parses and duplicate-checks the complete response,
rebuilds dependent groups, then atomically publishes the cache and generation.
The differential gives the Go download its own exact-port DIRECT rule, because
the oracle routes provider fetches through its rule engine, and compares the
GET target, cache bytes, HTTP vehicle views, selected provider member and
authenticated mixed-TCP forwarding.

```sh
PHASE5CHTTPPROVIDER_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5c_http_provider.py
cargo test --manifest-path rust/Cargo.toml -p rewrite-config -p rewrite-controller -p rewrite-runtime --all-features
```

At the 5C2c boundary, stale-cache refresh, intervals and remote PUT were still
unclaimed; 5C2d below closes their declared serial plaintext subset. HTTPS,
hashed default cache paths, custom headers/size limits, proxy/rule-routed
downloads, ETag and concurrent failure lifecycle remain unclaimed.

Phase 5C2d moves remote refresh into the controller-to-runtime configuration
transaction instead of duplicating fetch behavior in the REST handler. Manual
PUT and a runtime-owned interval scheduler both perform the same bounded
plaintext HTTP GET, parse and duplicate validation, temporary cache write and
generation publication. The scheduler retains one deadline per configured
provider and starts the interval after the initial hydration completes.
Malformed payloads and non-success HTTP responses fail before cache or active
configuration mutation, so the previously selected provider member continues
to carry new TCP tunnels.

```sh
PHASE5CHTTPPROVIDERREFRESH_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5c_http_provider_refresh.py
cargo test --manifest-path rust/Cargo.toml -p rewrite-config -p rewrite-controller -p rewrite-runtime --all-features
```

At the 5C2d boundary, ETag, headers and size controls were still unclaimed;
5C2e below closes their declared process-local plaintext subset. HTTPS,
optional hashed cache paths, provider-aware routing, concurrent/coalesced
refresh, SIGHUP interval mutation and shutdown-race evidence remain unclaimed.

Phase 5C2e extends that single Hyper request path rather than adding another
client. Provider declarations retain ordered repeated headers and an optional
byte limit, while executable configuration now carries the existing global
`etag-support` switch. Successful 200 responses retain their ETag in the active
generation; later refreshes send `If-None-Match`, treat 304 as a successful
same-byte freshness update, and leave members unchanged. A changed ETag
validates and publishes new members, while an over-limit body returns 503 before
cache or configuration mutation. The disabled-switch scenario proves repeated
custom headers remain present while conditional requests remain absent.

```sh
PHASE5CHTTPPROVIDERCONTRACT_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5c_http_provider_contract.py
cargo test --manifest-path rust/Cargo.toml -p rewrite-config -p rewrite-controller -p rewrite-runtime --all-features
```

At the 5C2e boundary, hashed default paths were still unclaimed; 5C2f below
closes the CLI-home/restart-cache subset. HTTPS, redirects, provider-aware
download routing, global User-Agent behavior, durable ETag database
interchange, concurrent refresh and override expressions remain unclaimed.

Phase 5C2f separates provider-home resolution from configuration-file resource
resolution. The CLI carries its already resolved Mihomo home into both ordinary
file and frozen YAML parsing, so the config crate remains deterministic and
does not read process environment variables. Relative explicit provider paths
use that home; omitted HTTP paths use the Go-compatible lowercase MD5 of the
URL under `proxies/`, implemented by the RustCrypto `md-5` crate. The restart
differential proves a fresh valid cache starts provider views and TCP routing
without another network request, then remains fully replaceable through PUT
with malformed-response cache/config rollback.

```sh
PHASE5CHTTPPROVIDERCACHE_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5c_http_provider_cache.py
cargo test --manifest-path rust/Cargo.toml -p rewrite-config -p rewrite-cli -p rewrite-runtime --all-features
```

HTTPS, durable ETag metadata, stale-cache startup refresh, permission and
corruption matrices, provider-aware routing, concurrent refresh and overrides
remain unclaimed.

Phase 5C2g gives the HTTP provider scheduler cache-age input without teaching
the configuration layer to read process environment. Only successfully parsed
cache files contribute a modification timestamp. Fresh caches retain their
remaining interval; caches older than the configured interval enter the
existing controller-owned refresh transaction immediately. The differential
proves that successful stale refresh replaces members/cache and routes through
the new authenticated proxy, HTTP failure preserves the old provider and data
plane, and malformed cache YAML is repaired from valid remote bytes.

```sh
PHASE5CHTTPPROVIDERSTALE_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5c_http_provider_stale.py
cargo test --manifest-path rust/Cargo.toml -p rewrite-config -p rewrite-runtime --all-features
```

Permission/platform error classes, durable ETag metadata, retry-backoff timing,
concurrent refresh, HTTPS, provider-aware routing and overrides remain
unclaimed.

Phase 5C2h makes provider deadlines generation-aware. A deadline is retained
only while the provider's interval, URL, cache path and cache timestamp remain
the same. The differential proves that a fresh cache configured for 600 seconds
does not fetch, a SIGHUP change to one second refreshes and routes through the
new member, and a later URL/path change with a stale valid cache immediately
fetches, persists and publishes the replacement source.

```sh
PHASE5CHTTPPROVIDERRELOAD_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5c_http_provider_reload.py
cargo test --manifest-path rust/Cargo.toml -p rewrite-runtime --all-features
```

Zero-interval retirement races are deliberately not claimed: the oracle may
allow one already-retiring provider request to update shared cache bytes.
Retry-backoff timing, concurrent refresh, HTTPS, provider-aware routing,
durable ETag metadata and overrides also remain unclaimed.

Phase 5C1c composes flat selectors from explicit proxies, named file providers,
all top-level proxies, all providers or both. Provider filters use the oracle's
backtick-separated regular-expression order, exclusions run over the combined
result, and an empty dynamic set exposes the configured fallback. Compatible
provider views retain only the explicit/include-all-proxy portion.

```sh
PHASE5CGROUPFILTERS_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5c_group_filters.py
cargo test --manifest-path rust/Cargo.toml -p rewrite-config -p rewrite-controller -p rewrite-runtime --all-features
```

Include/exclude proxy types, automatic group strategies, lazy health checks,
expected-status policies and cross-process selection persistence remain
separate gates.

Phase 5C1d admits select groups as explicit members of other select groups.
Configuration validates the complete dependency graph before publication and
rejects self or multi-node cycles while allowing forward references. Runtime
resolution follows the current selection at every level, and controller UDP
capability plus compatible-provider member views project the nested selection.

```sh
PHASE5CNESTED_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5c_nested_selector.py
cargo test --manifest-path rust/Cargo.toml -p rewrite-config -p rewrite-controller -p rewrite-runtime --all-features
```

Automatic group types, restart-persisted choices, provider-driven nested
membership changes and exhaustive invalid-DAG diagnostics remain unclaimed.

Phase 5C1e applies `exclude-type` after name filtering over explicit, nested and
provider-derived members. Type matching is case-insensitive and recognizes the
current built-ins, HTTP, SOCKS5 and Selector adapters. If every candidate is
removed, the configured empty fallback becomes the sole runtime member, while
the compatible provider continues to expose its unfiltered explicit inventory.

```sh
PHASE5CEXCLUDETYPE_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5c_exclude_type.py
cargo test --manifest-path rust/Cargo.toml -p rewrite-config -p rewrite-controller -p rewrite-runtime --all-features
```

Future adapter types join this filter only with their owning protocol slice;
automatic-group health policy remains separate.

Phase 5C1f moves configured selector choices from process-only state into the
profile's existing bbolt `cache.db`. `profile.store-selected` defaults to true,
matching Go, and false suppresses both writes and restart restoration. State is
loaded before selector membership reconciliation so stale or removed choices
cannot escape the active configuration. The differential first proves isolated
Go and Rust restart/reset sequences, then has Go select the HTTP member, Rust
restore and replace it with REJECT, and Go restore that Rust-written value.

```sh
PHASE5CSELECTORPERSIST_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5c_selector_persistence.py
cargo test --manifest-path rust/Cargo.toml -p rewrite-config -p rewrite-state -p rewrite-controller -p rewrite-runtime --all-features
```

Malformed-database recovery, simultaneous profile writers and persistence of
future automatic-group health state remain unclaimed.

Phase 5C1g introduces the first non-selector group kind without claiming the
whole automatic-group scheduler. A fallback group carries the current common
metadata, reports the selected member and UDP override exactly, and resolves
each new TCP connection against per-URL health. Its compatible-provider
healthcheck covers the accepted failure shape: an authenticated HTTP member is
initially usable, becomes unavailable, then the healthcheck marks it down while
DIRECT remains healthy and receives the next connection.

```sh
PHASE5CFALLBACK_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5c_fallback.py
cargo test --manifest-path rust/Cargo.toml -p rewrite-config -p rewrite-state -p rewrite-controller -p rewrite-runtime --all-features
```

Scheduled/`lazy` checks, interval/timeout/max-failure policy, general remote
health measurement, UDP routing, URL-test and load-balance remain unclaimed.

Phase 5C1h adds fallback's manual fixed-member lifecycle. Controller PUT shares
the validated member and bbolt persistence path with selectors while retaining
fallback's empty string as the dynamic state. The differential distinguishes
HTTP-proxied from DIRECT TCP, checks invalid-choice rollback and process
restart, then exchanges both fixed values through Go and Rust.

```sh
PHASE5CFALLBACKCONTROL_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5c_fallback_control.py
```

Phase 5C1i adds fallback group-delay over the currently accepted built-in
health-test members. Tests run concurrently under the request timeout and
record per-URL health. The controller deliberately clears and persists the
fixed choice before parsing the query, preserving Go's otherwise surprising
side effect for malformed and zero-timeout requests.

```sh
PHASE5CFALLBACKDELAY_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5c_fallback_delay.py
cargo test --manifest-path rust/Cargo.toml -p rewrite-state -p rewrite-controller -p rewrite-runtime --all-features
```

Automatic scheduling, exhaustive remote-member status/error cases, SOCKS5
health evidence, selector delay, UDP routing and load-balance remain unclaimed.

Phase 5C1j adds URL-test on the same typed group boundary. Controller health
measurement now connects through configured HTTP/SOCKS5 implementations rather
than treating every remote member as failed; the accepted differential proves
the HTTP path with authenticated slow and fast CONNECT fixtures. Per-URL delay
state selects the minimum healthy member, tolerance retains an acceptable
current member, and fixed PUT uses the same restart-persistent selected bucket.
Group-delay measures both remote members concurrently, clears fixed before the
test and returns routing to the faster member.

```sh
PHASE5CURLTEST_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5c_url_test.py
cargo test --manifest-path rust/Cargo.toml -p rewrite-config -p rewrite-state -p rewrite-controller -p rewrite-runtime --all-features
```

Periodic/`lazy` scheduling, interval/timeout/max-failure policy, complete
failure/status handling, SOCKS5 health evidence and UDP remain unclaimed.

Phase 5C1k adds the first load-balance strategy. Round-robin position advances
only for data-plane selection, scans forward over members whose per-URL health
is false and returns the first member if none are healthy, matching the pinned
Go algorithm. Unlike selectable automatic groups it owns no fixed choice, so
its REST view omits `now`/`fixed` and PUT returns `Must be a Selector`. The
differential observes alternating authenticated HTTP proxy connections, closes
the first proxy, refreshes health and proves every later connection and the
group-delay result use only the survivor.

```sh
PHASE5CLOADBALANCE_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5c_load_balance.py
cargo test --manifest-path rust/Cargo.toml -p rewrite-config -p rewrite-state -p rewrite-controller -p rewrite-runtime --all-features
```

Phase 5C1l completes the currently configured TCP load-balance strategy set.
Default and explicit `consistent-hashing` use a process-random hash of the
registrable destination domain or destination IP. `sticky-sessions` adds the
source IP and retains the selected index in a 1000-entry LRU for ten minutes.
Because the Go oracle intentionally seeds its hash per process and initially
salts sticky choices with wall-clock nanoseconds, the black-box gate compares
properties rather than literal A/B identity: each implementation must keep
four same-key connections together, then move every connection to the other
member once the first member fails health checking. REST shape and PUT failure
remain exact differentials.

```sh
PHASE5CLOADBALANCEHASH_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5c_load_balance_hashing.py
cargo test --manifest-path rust/Cargo.toml -p rewrite-config -p rewrite-state -p rewrite-runtime --all-features
```

Phase 5C1m adds the automatic health lifecycle shared by fallback, URL-test and
load-balance groups. The scheduler performs an initial concurrent check,
honors the configured second interval and member timeout, skips idle ticks in
the default lazy mode, and resumes after the data plane touches a group. It
observes committed config generations and is cancellation-owned by the
runtime. The differential closes the first authenticated HTTP proxy and
proves eager groups discover it without traffic, lazy groups preserve their
previous health while idle and discover it after a route attempt, and both
subsequently use only the surviving proxy.

```sh
PHASE5CHEALTHSCHEDULE_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5c_health_schedule.py
cargo test --manifest-path rust/Cargo.toml -p rewrite-config -p rewrite-state -p rewrite-controller -p rewrite-runtime --all-features
```

Phase 5C1n adds dial-failure-triggered health activation for the current
grouped HTTP/TCP path. Configuration preserves the oracle's default threshold
of five and explicit `max-failed-times`. A bounded ten-attempt group retry
records ordinary failures against that threshold; TCP connection refusal
activates health immediately. Trigger delivery is owned by the runtime health
scheduler, coalesces with scheduled work and resets its counter after the
check. The differential proves threshold two versus below-threshold 99,
refused-connection bypass, eventual unhealthy state and subsequent routing
through the surviving HTTP proxy. The initiating tunnel outcome is retained as
diagnostic rather than compatibility evidence because Go combines asynchronous
health work with jittered retry backoff.

```sh
PHASE5CDIALFAILURE_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5c_dial_failure.py
cargo test --manifest-path rust/Cargo.toml -p rewrite-config -p rewrite-state -p rewrite-controller -p rewrite-runtime --all-features
```

Phase 5C1o proves that the library-backed authenticated SOCKS5 outbound joins
the same automatic health boundary without protocol-specific hand-written
logic. The fallback gate records successful startup and explicit HEAD probes,
detects a closed member through the eager interval, and routes subsequent TCP
through the survivor. Its separate lazy/high-threshold case proves a refused
SOCKS5 server activates the coalesced health check immediately. As in Phase
5C1n, the initiating connection is diagnostic rather than parity evidence.

```sh
PHASE5CSOCKSHEALTH_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5c_socks5_health.py
cargo test --manifest-path rust/Cargo.toml -p rewrite-config -p rewrite-state -p rewrite-controller -p rewrite-runtime --all-features
```

## Phase 5C aggregate closeout

Phase 5C3 replaces the provider-only handwritten Hyper client with a shared
`reqwest`/rustls client. It accepts HTTP and HTTPS, follows configured trust
roots and host mappings, streams into configured/hard size bounds, and
preserves repeated headers and conditional requests. Inline proxy providers,
current-adapter filters/type exclusion and structured name transforms use the
same parser as file/remote bytes. Provider health uses the real delay engine
for startup, manual, eager and lazy interval checks. ETag sidecars bind URL,
payload digest and ETag, preventing stale metadata after cache changes.

Phase 5C4 compiles domain, IP-CIDR and classical payloads into ordered
`RULE-SET` matchers. Inline, YAML, text and MRS inputs share one transactional
replacement path; file notifications, manual PUT and HTTP(S) interval refresh
validate the rebuilt rule program before publication. REST snapshots, status,
live TCP routing and cache bytes are differential evidence.

Phase 5C5 retains mutable configuration ownership in the runtime loop.
Eight-way valid/invalid PUT bursts prove serialized convergence and rollback;
SIGHUP removal proves the provider API disappears, routing changes generation,
stale health is removed, and file/interval tasks rebind or cancel. All 27 Phase
5C scripts passed consecutively, followed by workspace fmt, warnings-denied
clippy and tests.

This closes Phase 5C only for adapters already implemented before Phase 6.
Named provider download proxies, the general override-expression language,
encrypted subscription bytes, later protocols and native release stress remain
assigned to their owning later slices.

## Phase 6B1b deliverables and evidence

HTTP proxy configuration now carries `tls`, `sni` and `skip-cert-verify` into
both the data-plane and controller health dial path. `tokio-rustls` wraps the
direct proxy TCP stream with a five-second handshake bound; Hyper then reuses
the Phase 6B1a CONNECT request/upgrade implementation without custom HTTP
framing. The focused differential proves authenticated TLS relay, exact SNI,
untrusted-certificate rejection, server-side SNI rejection, CONNECT 502
failure and continued process availability.

The Phase 5C reqwest client now selects its `rustls-no-provider` feature so the
workspace's existing ring provider remains unambiguous. This fixes the Linux
Phase 4E19 panic introduced when AWS-LC and ring were both enabled. The 4E19
fixture also reserves a port usable by both DNS TCP and UDP, retries only
pre-readiness UDP packets, and writes product/authority diagnostics on an
exception; its full Go/Rust differential re-passes locally.

Local accepted gates:

```sh
PHASE6BHTTPTLS_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase6b_http_tls.py
PHASE6BHTTP_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase6b_http.py
PHASE4_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase4e19.py
```

Positive custom-root verification, `name-cert-verify`, client
certificate/fingerprint behavior and malformed/delayed response boundaries are
closed by Phase 6B3. HTTP has no UDP path; dialer chains remain OUT-21.

## Phase 6B1c deliverables and evidence

HTTP proxy configuration now carries string-valued custom `headers` through
the same runtime and controller-health dial boundary. Hyper emits the oracle's
default Host, User-Agent and Proxy-Connection fields, custom fields replace
those defaults, and configured Basic credentials replace any custom
Proxy-Authorization value last. The no-credential form omits authorization.

The response gate now accepts exactly CONNECT status 200. The previous Rust
`is_success()` check incorrectly admitted 204; the focused differential proves
204, 301, 400, 405, 407 and 500 all close the attempted tunnel without
terminating the process, while both default unauthenticated and overridden
authenticated 200 paths relay TCP bytes.

The prior Linux provider failure was also corrected at its source: reqwest
keeps `rustls-no-provider`, and the runtime explicitly installs the workspace's
ring provider before constructing a provider client. The focused Phase 5C2c
provider differential re-passes locally.

Local accepted gates:

```sh
PHASE6BHTTPCONTRACT_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase6b_http_contract.py
PHASE5CHTTPPROVIDER_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5c_http_provider.py
PHASE6BHTTP_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase6b_http.py
PHASE6BHTTPTLS_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase6b_http_tls.py
```

Positive trust-store verification, `name-cert-verify`, client certificates,
fingerprints and malformed/delayed response boundaries are closed by Phase
6B3. HTTP has no UDP path; dialer chains remain OUT-21.

The pinned HTTP adapter does not own a separate CONNECT-response timeout; its
deadline comes from the caller context. Exact outer timeout windows,
concurrent reload stress and later group/provider/platform combinations remain
cross-cutting gates rather than native Phase 6B protocol gaps.

## Phase 5D completion deliverables and evidence

The controller now binds simultaneous plain TCP, TLS and Unix-domain listeners
from one runtime generation. Linux/Android controller sockets apply a
configured routing mark before bind; Unix sockets use mode `0666`, remove stale
paths and bypass the controller secret like Go. The same Hyper/Axum application
serves HTTP/1 or HTTP/2, and TLS is delegated to `tokio-rustls`. Native Windows
named-pipe serving is compiled behind `cfg(windows)` and has a dedicated
GitHub Actions differential rather than a host-only claim.

Controller-visible configuration now retains source/home context and supports
inline YAML, the current default config, or an absolute path under home. Unsafe
and relative paths preserve the oracle error classes, and every replacement is
validated and bound before publication. UI path changes recreate controller
applications so static service roots do not remain stale after SIGHUP.

Observability uses real process RSS after the oracle's initial zero frame.
Traffic and memory HTTP/WebSocket streams sustain their cadence, totals remain
monotonic, and log streams support both plain and structured records. The
fixture reads the WebSocket handshake byte-precisely so the first frame cannot
be lost to TCP coalescing.

`/storage/{key}` is no longer process-local. `rewrite-state` reads and writes
the Go `storage` bbolt bucket in `cache.db`, preserves the MessagePack `Data`
and timestamp fields, enforces the 64-byte key/1 MiB total bounds, and evicts
deterministically by timestamp and key. The differential performs restart,
deletion persistence, LRU pressure and Go→Rust→Go interchange. `/restart`
returns the Go response before re-exec; Unix retains the PID and restores
controller readiness.

Focused local acceptance on Darwin arm64, 2026-08-28:

```sh
PHASE5DTRANSPORT_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5d_transports.py
PHASE5DSTREAMS_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5d_streams.py
PHASE5DCONFIGPATH_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5d_config_paths.py
PHASE5DSTORAGEPERSIST_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5d_storage_persistence.py
PHASE5DRESTART_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5d_restart.py
PHASE5DHTTPSHEALTH_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5d_https_health.py
```

The pre-existing Phase 5D provider, mode, proxy, storage, rules, configs, CORS
and connections differentials also re-pass after these changes. Local
formatting, workspace Clippy with `-D warnings`, and all-feature workspace tests
pass. The full Linux regression and Windows pipe differential run in GitHub
Actions and are not claimed before their results arrive.

Phase 5D is therefore closed at the controller boundary for currently
executable Rust services. Its acceptance did not itself claim update services,
global TLS/ECH, Go pprof/expvar data, privileged nonzero Linux `SO_MARK`, or
stress/backpressure; those remain coupled to Phase 5E and Phase 5F evidence.

Phase 5E now accepts its first broad service slice. `rewrite-services` owns a
bounded SNTP exchange and adjusted clock, safe library-backed UI archive
updates, and validated atomic geodata updates. Runtime managers follow config
reload for NTP, UI auto-download and scheduled Geo updates. The controller
exposes `/upgrade/ui`, `/upgrade/geo` and `/configs/geo`; all four Go client
certificate modes are implemented at a narrow rustls boundary. Existing
Go-compatible fake-IP/group/storage bbolt persistence remains the 5E3 format.

Focused local acceptance on Darwin arm64, 2026-08-28:

```sh
cargo test -p rewrite-services -p rewrite-config --all-features
PHASE5ESERVICES_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5e_services.py
PHASE5ETLSAUTH_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5e_tls_client_auth.py
PHASE5EGEORULES_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5e_geo_rules.py
```

The UI/Geo differential covers automatic and manual success, both Geo route
aliases, exact success status/body, invalid archive/data rejection and file
rollback. The TLS differential generates independent trusted and untrusted
client credentials and matches request/require/verify behavior for every
mode. Direct local SNTP offset calculation is a deterministic contract test.

The 5E4 general-rule slice additionally loads protobuf `GeoSite.dat` and
`GeoIP.dat` resources from the configured home and compiles `GEOSITE`, `GEOIP`
and `SRC-GEOIP` into the existing lazy rule engine. Its differential proves
real mixed HTTP TCP routing plus the Go-compatible `/rules` type, payload and
record-size fields. These rule consumers also participate in scheduled and
manual geodata update selection.

Phase 5E remains partial: NTP through a named UDP proxy, writing the platform
clock, server ECH, adjusted-clock propagation through every DNS/client TLS
stack, ASN updates, MMDB-mode general GEOIP and exhaustive loader/matcher
variants are not claimed. The default Linux differential shard includes all
three Phase 5E scripts, but its result remains pending.

Phase 5F2 now has its first complete vertical runtime slice. The local SOCKS
UDP path owns a bounded 64-packet session per client socket address, reuses one
DIRECT outbound socket, accepts multiple upstream responses, resets the
60-second idle deadline on traffic and closes on listener/controller
cancellation. A session retains the configuration generation that selected
its route, matching the Go NAT table rather than silently switching an active
flow during SIGHUP.

Focused local acceptance on Darwin arm64, 2026-08-28:

```sh
PHASE5FUDPNAT_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5f_udp_nat.py
PHASE3_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase3.py
```

The differential observes stable upstream source-port reuse for sequential
packets, multiple SOCKS write-backs, destination fan-out, continued DIRECT
traffic on an existing session after a REJECT reload and rejection for a fresh
client. IPv4 and IPv6, control-association closure and bounded-pressure recovery
are covered. A dedicated Linux CI shard runs the real 60-second expiry gate;
its result remains pending and remote UDP adapters/UoT remain protocol gates.

Phase 5F2b broadens the same deterministic differential without changing the
60-second production timeout. One IPv4 client now proves that two destination
authorities share the stable outbound socket, and that closing a SOCKS5 UDP
ASSOCIATE control connection does not own or tear down the source-keyed NAT
entry, matching the fixed Go listener. A dual-stack mixed listener additionally
proves IPv6 request decoding, DIRECT forwarding, response encoding and source
port reuse. Phase 5F2c sends 256 packets through the bounded 64-entry session
queue and requires a later marker response, then enables exact idle-expiry
source-port recreation under `PHASE5F_TIMEOUT_TEST=1` in Linux CI. The fast
Darwin pressure gate passes; the wall-clock CI result and remote UDP
adapters/UoT remain explicitly separate evidence/protocol claims.

Phase 5F1a also accepts the fixed-listener IPv4 LAN-policy boundary. Runtime
configuration now retains `allow-lan`, `bind-address`, allowed/disallowed
prefixes and skip-auth prefixes; fixed HTTP, SOCKS and mixed TCP use those
values for bind and per-peer admission before protocol authentication. The
controller returns the active values instead of hard-coded defaults.

Focused local acceptance on Darwin arm64, 2026-08-28:

```sh
PHASE5FLANPOLICY_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5f_lan_policy.py
```

The differential proves unauthenticated loopback access through all three
listener kinds when explicitly skipped, allowed-list miss, disallowed-list
precedence, and `allow-lan: false` forcing loopback even with a nonlocal bind
address. Its current expansion also covers IPv4/IPv6 wildcard behavior, a real
native non-loopback address and same-port bind-address hot replacement.

Phase 5F1b extends that accepted boundary through the platform socket adapter.
`bind-address: '*'` now creates the oracle's dual-stack wildcard socket,
bracketed IPv6 literals are accepted, IPv4-mapped peers are normalized before
LAN policy checks, and fixed listener identity includes the bound address.
Controller PATCH can therefore replace a bind address on the same port while
also updating the three validated prefix lists. The expanded
`phase5f_lan_policy.py` differential proves IPv4 and IPv6 wildcard relay,
IPv4-to-IPv6 same-port replacement with old-address retirement, a live auth
bypass update and invalid-prefix rollback.

Phase 5F1c completes the remaining executable socket policy. Fixed TCP
listeners retain `inbound-tfo`/`inbound-mptcp` in live configuration, use
`tokio-tfo` for accepted TFO streams, request Linux MPTCP with ordinary TCP
fallback, and apply keepalive through `socket2`. DIRECT TCP/UDP and current
HTTP/SOCKS5 proxy and health-check sockets apply interface/routing-mark policy;
domain DIRECT dials honor `tcp-concurrent`. The Darwin differential passes
TFO/MPTCP-enabled relay, non-loopback wildcard access, the `lo0` dial path,
invalid-interface failure, domain concurrency and an exact nonzero-mark
controller snapshot. Mark application on global-unicast Linux/Android sockets
is implemented and has a root-only write/read-back CI gate; its result is not
claimed before Actions completes.

Phase 5F3 adds the all-feature release build to the default quality workflow.
Portable logs, memory/traffic streams and connection lifecycle were already
accepted in Phase 5D and remain the Rust diagnostics boundary. Go-runtime
`pprof`/`expvar` payloads and process lookup are still visible in the inventory:
the former are non-portable API gaps, while the latter requires future PROCESS
rules/original-flow metadata. Neither is relabeled as compatible merely to
close the local listener/data-plane phase.

Focused Phase 5F local commands now are:

```sh
PHASE5FLANPOLICY_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5f_lan_policy.py
PHASE5FUDPNAT_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase5f_udp_nat.py
```

Both fast Darwin differentials pass on 2026-08-28. Linux CI additionally sets
`PHASE5F_TIMEOUT_TEST=1` and separately runs the ignored root-only routing-mark
contract; neither Linux result is claimed until Actions reports it.

Phase 6A1 now implements the reserved built-in and implicit GLOBAL vertical
slice for current mixed TCP. COMPATIBLE enters the existing DIRECT dial path;
PASS continues ordered evaluation; REJECT closes immediately; REJECT-DROP owns
the client until its 60-second drop interval or runtime cancellation. The
default GLOBAL member order is DIRECT, REJECT, configured top-level proxies
and configured groups, while an explicit group named GLOBAL replaces that
default. Controller selection and live mode-global routing read the same
runtime state.

Focused local acceptance on Darwin arm64, 2026-08-28:

```sh
PHASE6ABUILTINS_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase6a_builtins.py
```

The fast differential compares built-in list/detail fields, PASS→COMPATIBLE,
immediate REJECT, REJECT-DROP retention with and without payload, default GLOBAL
selection of DIRECT/REJECT/a configured authenticated HTTP adapter, custom
GLOBAL group replacement and delay paths, dynamic UDP capability, and
duplicate/reserved/collision validation. The
dedicated Linux `builtins` shard sets `PHASE6A_DROP_TIMEOUT_TEST=1` and compares
closure around the oracle's 60-second timeout; that native result remains
pending.

Phase 6A2 completes the configured simple-adapter boundary. Top-level DIRECT,
REJECT, DNS and REMATCH records now share validation, GLOBAL/group membership,
controller rendering and live selection. DIRECT carries TCP and UDP, REJECT
closes TCP and silently drops UDP, DNS carries framed TCP or message UDP through
the runtime-owned `DnsService`, and REMATCH restarts rule evaluation directly
or through a selected group. Inline providers accept DIRECT records in the same
declared scope.

Focused local acceptance on Darwin arm64, 2026-08-28:

```sh
PHASE6ASIMPLE_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase6a_simple_adapters.py
```

The differential compares accepted and rejected configuration, exact default
GLOBAL ordering, adapter/group/controller views, deterministic TCP direct,
reject, DNS and rematch outcomes, and SOCKS5 UDP direct, reject, REJECT-DROP,
DNS and rematch outcomes. Both Phase 6A scripts pass locally. Rich per-adapter
socket/dialer options remain OUT-01 or protocol-composition work; the Linux
60-second REJECT-DROP result remains pending CI evidence rather than a Phase 6A
implementation gap.

## Phase 6B completion deliverables and evidence

Phase 6B is complete for the native HTTP and SOCKS5 adapters on the current
mixed data plane. The shared rustls boundary now supports the oracle's global
custom trust roots, separate SNI and verification identities, SHA-256 leaf or
chain pinning, skip verification and file/inline client certificate/key
loading. The TLS identity differential proves successful mutual TLS and
pinning plus missing-client-certificate and bad-pin rejection for both
protocols. It also records that SOCKS5 uses its IP server identity and therefore
does not emit an SNI name in this fixture.

The HTTP contract additionally proves that Basic auth is active only when both
credential fields are nonempty, configured credentials retain precedence over
a custom authorization header, delayed valid framing succeeds, and EOF,
malformed responses plus 204/301/400/405/407/500 fail without killing the
process. The SOCKS5 contract preserves the pinned uint8 credential-length wrap
and full-byte write for credentials above 255 bytes. Its UDP association keeps
the authenticated TCP control stream alive, handles plaintext and TLS control
channels, replaces `0.0.0.0` relay replies with the proxy address, resolves and
relays multiple destinations through one source session, and exposes the
oracle's `udp: true`, `uot: false` controller fields.

Focused local acceptance on Darwin arm64, 2026-08-28:

```sh
PHASE6BHTTP_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase6b_http.py
PHASE6BHTTPTLS_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase6b_http_tls.py
PHASE6BHTTPCONTRACT_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase6b_http_contract.py
PHASE6BSOCKS_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase6b_socks5.py
PHASE6BSOCKSCONTRACT_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase6b_socks5_contract.py
PHASE6BSOCKSUDP_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase6b_socks5_udp.py
PHASE6BTLSIDENTITY_CARGO_TARGET=/Users/ren/data/rust-target/mihomo python3 compat/scripts/phase6b_tls_identity.py
```

The two new completion scripts and both expanded contract scripts pass locally;
the original HTTP/TLS/SOCKS5 gates are rerun in the final focused gate below.
GitHub Actions assigns all seven scripts to the parallel
`controller-services-outbound` shard. Linux results remain pending until that
run completes. Common `dialer-proxy` chaining belongs to OUT-21/Phase 7T, and
later protocol/provider override combinations must provide their own evidence;
neither is an unfinished native Phase 6B behavior.

## Outbound module refactor

The behavior-neutral post-6B refactor replaces the monolithic outbound
`lib.rs` with a 20-line public facade. DIRECT dialing lives in `direct.rs`,
Hyper CONNECT in `http.rs`, rustls policy in `tls.rs`, and SOCKS5 is split into
`socks5/{mod,tcp,udp,auth}.rs`. Existing public names and signatures remain
re-exported from the crate root, so controller/runtime callers do not depend on
the internal file layout. Workspace warnings-denied clippy and all seven Phase
6B Go/Rust differentials pass after the move. No compatibility row changes and
no new protocol behavior are claimed.

## Controller and runtime module refactor

The behavior-neutral post-6B structure pass replaces the 3,033-line controller
crate root with 77 lines including focused tests and nine focused modules:
shared context, server lifecycle, TLS material, dynamic CORS, route/auth/DoH
handling, proxy/provider APIs,
configuration mutation, observability streams and response serialization. The
public serving, TLS preparation and provider-health entry points remain
re-exported with their existing names and signatures.

The 3,077-line runtime crate root is likewise reduced to a 9-line facade.
Shared task and controller-key types live in `types`. Process and reload
orchestration, background provider/service scheduling, transactional
generation replacement, listener/UDP sessions and TCP routing/relay now live
in separate modules with explicit imports. Every production module imports
external crates directly and names sibling dependencies through `crate::...`;
there are no `use super` imports in controller/runtime production code. No
protocol, configuration or REST support row changes as a result of the move.

Focused local acceptance on Darwin arm64, 2026-08-28:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
python3 compat/scripts/phase3.py
python3 compat/scripts/phase4f13.py
python3 compat/scripts/phase5f_udp_nat.py
```

All commands above pass after the dependency cleanup. The two focused fixture
scripts also reproduce and resolve the completed Actions failures: Phase 4F13
uses atomic reload input and a bounded two-window startup/reload allowance;
Phase 5F refreshes the fixed UDP NAT entry immediately before generation
replacement. The later storage migration removes the Windows-only persistence
no-ops; native Windows product restart/interchange evidence is still required
before durable profile compatibility is claimed there.

## Configuration module refactor

The behavior-neutral post-6B structure pass replaces the 7,001-line
configuration crate root with a 14-line public facade. Public normalized types,
the crate-private raw YAML schema, load/default/reload policy, DNS/geodata/host
parsing, proxy/group/provider parsing, public errors and unit fixtures now live
in separate physical modules. Existing public names and signatures remain
re-exported from the crate root. Production code contains no `use super`
imports; sibling dependencies use explicit `crate::...` paths. The 57 config
unit tests, workspace fmt/clippy/test, the Phase 2 generated config/rule oracle
suite and the Phase 6A simple-adapter differential pass after the move. This
changes no compatibility-matrix support claim.

## State module refactor

The behavior-neutral post-6B structure pass replaces the 1,968-line state
crate root with an 87-line facade. Controller snapshot models, connection and
traffic lifecycle, proxy/group health and selection, DNS/redir-host/fake-IP
state, bbolt-backed storage/profile persistence, and unit fixtures now live in
focused modules. Existing public types and `RuntimeState` methods remain
available from the same crate-root API. Production modules use explicit
`crate::...` paths and contain no `use super` imports; test-only fake-IP
inspection is exposed through narrow test-only methods instead of widening the
production data structure.

Focused local acceptance on Darwin arm64, 2026-08-28:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
python3 compat/scripts/phase3.py
python3 compat/scripts/phase4f13.py
python3 compat/scripts/phase4f14.py
python3 compat/scripts/phase5c_selector_persistence.py
python3 compat/scripts/phase5d_storage_persistence.py
```

All gates pass. The connection/controller lifecycle, redir-host, fake-IP
database interchange, selector persistence and controller storage interchange
matrix evidence remains unchanged; this refactor adds no feature or platform
compatibility claim.

## DNS module refactor

The behavior-neutral post-6B structure pass replaces the 4,784-line DNS crate
root with a 238-line facade. Cache/TTL/singleflight behavior lives in `cache`;
hosts, ECS, fake-IP and answer enhancement in `enhancer`; UDP/TCP listener
framing in `server`; shared resolver/controller state and public lookup APIs in
`service`; classic DNS, DoT, DoH and DoQ clients in `transport`; and wire,
policy, resolver-set, fallback, platform resolver and REST rendering logic in
`wire`. Unit fixtures move to `tests`. Existing public names and signatures are
re-exported unchanged from the crate root.

Every production and test module uses explicit imports; the DNS source tree
contains no `use super` or wildcard module imports. The public API inventory is
identical before and after the move. Focused local acceptance on Darwin arm64,
2026-08-28:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
python3 compat/scripts/phase4.py
python3 compat/scripts/phase4f1.py
python3 compat/scripts/phase4e15.py
python3 compat/scripts/phase4e18.py
python3 compat/scripts/phase4f11.py
python3 compat/scripts/phase4f14.py
```

All gates pass. These cover the basic UDP/TCP listener, full local wire/EDNS
boundary, HTTP/2 DoH, DoQ connection lifecycle, cache lifecycle and fake-IP
bbolt interchange across the new module seams. Existing Phase 4A, 4D1–4D4,
4E1–4E19, 4F1–4F14 and cache/DNS REST matrix claims remain unchanged; no DNS
feature or platform support is added by this refactor.

## Rules module refactor

The behavior-neutral post-6B structure pass replaces the 1,782-line rules
crate root with a 12-line facade. Public rule/provider/result models live in
`model`; ordered scans, sub-rule traversal and rematch transitions in `engine`;
pure metadata matchers and lazy destination resolution in `matcher`; and
parsing, provider references and graph validation in `parser`. Unit fixtures
move to `tests`. Existing public names, methods and signatures remain available
from the same crate-root API.

Every production and test module uses explicit imports; the rules source tree
contains no `use super` or wildcard module imports. The public API inventory is
identical before and after the move. Focused local acceptance on Darwin arm64,
2026-08-28:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
python3 compat/scripts/phase2.py
python3 compat/scripts/phase5b_core.py
python3 compat/scripts/phase5d_rules.py
```

All gates pass. These cover generated configuration and rule observations,
ordered routing decisions, rule families, sub-rules, provider-backed rules,
lazy resolution/`no-resolve`, rematch behavior, and the `/rules` inventory and
enable/disable controller boundary. Existing Phase 2, Phase 4D3A, Phase 5A2,
Phase 5A3, Phase 5B and Phase 5D rule/routing matrix claims remain unchanged;
this refactor adds no feature or platform compatibility claim.

## Ruleset conversion module refactor

The behavior-neutral post-6B structure pass replaces the 700-line ruleset
crate root with a 12-line facade. Public errors and source formats live in
`model`; text and streaming-YAML input extraction in `source`; IP range and
succinct-domain-set construction in `encode`; MRS validation, trie traversal
and canonical text rendering in `decode`; and unit fixtures in `tests`. The two
public types and four conversion functions remain available under the same
crate-root names and signatures.

Every module uses explicit imports; the ruleset source tree contains no
`use super` or wildcard module imports. Focused local acceptance on Darwin
arm64, 2026-08-28:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
python3 compat/scripts/phase5a5a.py
python3 compat/scripts/phase5a5b.py
python3 compat/scripts/phase5a5c.py
python3 compat/scripts/phase5a5d.py
python3 compat/scripts/phase5a5e.py
python3 compat/scripts/phase5a5f.py
```

The workspace gates and all six differential assertion sets pass. The local
differential run reused one external Cargo target and raised only its in-memory
per-process deadline from 5 to 30 seconds: immediately after a complete cold
build, the unchanged five-second harness twice timed out starting the Rust CLI,
while direct pre/post-split conversion of the same Go-produced frame completed
in 0.01–0.05 seconds with identical bytes. No fixture deadline was changed in
the repository; the unmodified Actions jobs remain the default-timeout gate.
Existing Phase 5A5a–5A5f and CLI-08 matrix claims remain unchanged; this
refactor adds no ruleset behavior or platform support claim.

## Native Windows and Apple Silicon build gates

The default Rust workflow now has a separate native build matrix for
`windows-latest` X64 and `macos-latest` ARM64. Each leg verifies the Actions
runner architecture and the host architecture before building the locked Cargo
workspace with all targets and all features. The target directory is explicitly
placed under `runner.temp`, overriding the developer-machine Cargo target path.
macOS additionally requires `uname -m=arm64`, so an Intel runner cannot satisfy
the Apple Silicon build gate. Both native build legs passed in Actions run
`33158824630`; compilation alone does not claim platform runtime parity.

The first matrix run exposed a separate Linux reload race: runtime sockets
could become externally reachable before the CLI task had registered SIGHUP.
The CLI now waits for successful signal-handler registration before starting
the runtime, so port readiness also implies reload-signal readiness. This is a
product lifecycle ordering fix rather than an added fixture delay.

That run also showed the Windows oracle logging a live named pipe while the
PowerShell readiness client timed out. The client now passes the pipe name and
request through explicit environment variables instead of PowerShell
`-Command` positional argument parsing, uses bounded one-second connection
attempts inside the overall readiness window and preserves the last exception
as the timeout cause.

Actions run `33159534696` verified both native build legs, the named-pipe
differential and every non-DNS-general gate. Its sole failure was a Phase 4F9
fixture setup mismatch: the Go product validation received the temporary home
directory through `-d`, while the Rust product validation did not and therefore
looked for `GeoIP.dat` under the runner's default home. The fixture now supplies
the same `-d` input to both products and guarantees its released mixed/DNS port
numbers are distinct. The complete Phase 4F9 differential passes locally after
the correction; a subsequent Actions run remains the acceptance authority.

## Cross-platform bbolt backend migration

The state crate now uses the `bbolt` package from `biaogd/bbolt-rs`, pinned to
revision `83d3900849e5c41273798e0951b110d6375c925f`. The dependency's native
Windows `cargo test` passed in upstream Actions run `33158755650`. Its database
API is contained inside `rewrite-state`; fake-IP mappings/allocation state,
selector choices and controller storage all use the same implementation on
Windows, Darwin and Linux. The previous Windows restore/persist/store no-ops
and target-specific dependency exclusion have been removed. `USERPROFILE` is
used as the Windows home fallback when `HOME` is absent.

Focused Darwin arm64 acceptance after the migration:

```sh
cargo test -p rewrite-state --all-features
python3 compat/scripts/phase4f14.py
python3 compat/scripts/phase5c_selector_persistence.py
python3 compat/scripts/phase5d_storage_persistence.py
```

All four gates pass, including bidirectional Go/Rust `cache.db` interchange.
This does not yet establish native Windows product restart compatibility. The
dependency repository is public, so the public product repository's Actions
can fetch the pinned revision without an additional credential.

## Phase 6C-A Shadowsocks AES-128-GCM TCP evidence

The first SS client slice uses the official `shadowsocks` crate at an exact
`1.25.0` pin with default DNS/service features disabled and only its legacy
AEAD cipher feature enabled. The product first opens the server socket through
the existing platform-aware direct connector, then gives that established
Tokio stream to `ProxyClientStream`. This keeps interface, routing-mark,
keepalive, concurrency and product DNS policy on the rewrite side of a narrow
adapter while avoiding a hand-written SIP004 cipher/framing implementation.
The lower-level `shadowsocks-crypto` crate was not selected because it would
leave record framing, nonce and lifecycle code in the product. The full service
crate surface is also not enabled.

Dependency review: `shadowsocks` 1.25.0 is the MIT-licensed core library from
the actively maintained
[`shadowsocks/shadowsocks-rust`](https://github.com/shadowsocks/shadowsocks-rust)
project, requires Rust 1.91 (below this workspace's pinned 1.95 CI toolchain),
and its upstream releases publish Linux, Windows and Apple arm64 artifacts. Its
legacy AEAD feature currently brings the C-backed `aws-lc` implementation; the
existing native Windows x86_64 and macOS arm64 workspace build jobs therefore
remain mandatory before either platform gains a Phase 6C build claim. The exact
crate pin prevents an unreviewed protocol/dependency expansion.

Configuration intentionally accepts only required nonempty server, port and
password fields with `cipher: aes-128-gcm`; UDP, plugins, TLS fields and all
other ciphers fail validation in this gate. The controller reports
`type: Shadowsocks`, `udp: false` and `uot: false`. The deterministic
`rewrite-shadowsocks-authority` test binary uses the same official core in
server mode and relays the decoded target to a local echo server.

Focused Darwin arm64 evidence on 2026-08-29:

```sh
cargo test -p rewrite-config -p rewrite-outbound -p rewrite-test-support --all-features --target-dir /Users/ren/data/rust-target/mihomo/phase6c-shadowsocks
PHASE6CSS_CARGO_TARGET=/Users/ren/data/rust-target/mihomo/phase6c-shadowsocks python3 compat/scripts/phase6c_shadowsocks.py
```

Both gates pass. The default controller/outbound Actions shard now includes the
new differential, but Linux compatibility is pending that native run. Other
ciphers, 2022, UDP, UoT, plugins, group/provider use, inbound/server direction
and cross-adapter dialer composition remain explicit Phase 6C gaps.

## Phase 6C-B SIP004 AEAD TCP matrix evidence

Configuration now accepts the complete standard SIP004 AEAD set exposed by the
selected library feature: `aes-128-gcm`, `aes-256-gcm` and
`chacha20-ietf-poly1305`. No new crypto or framing implementation was added;
all three methods retain the Phase 6C-A established-stream adapter boundary.
Extra AEAD, stream and 2022 methods remain rejected.

The new local authority differential creates independent Go and Rust product
generations for every cipher. Each generation relays both domain and IPv4
targets, echoes a 128 KiB deterministic payload across multiple encrypted
records, delivers the response after client half-close and remains alive.
Focused Darwin arm64 evidence on 2026-08-29:

```sh
cargo test -p rewrite-config parses_phase6c_shadowsocks_sip004_aead_scope --all-features --target-dir /Users/ren/data/rust-target/mihomo/phase6c-shadowsocks
PHASE6CSSCIPHERS_CARGO_TARGET=/Users/ren/data/rust-target/mihomo/phase6c-shadowsocks python3 compat/scripts/phase6c_shadowsocks_ciphers.py
```

Both checks pass. The differential is assigned to the default
controller/outbound Actions shard; Linux and native dependency build evidence
remain pending CI. UDP, UoT, plugins, provider/group use, inbound/server mode,
2022 and cross-adapter composition remain open.

## Phase 6C-C SIP004 AEAD UDP evidence

Configuration accepts `udp: true` for the three Phase 6C-B ciphers and exposes
that capability through direct adapter and selector controller views while
continuing to report `uot: false`. The runtime adds a Shadowsocks branch to its
existing per-client mixed/SOCKS5 UDP session table. It keeps the established
64-packet bounded queue, explicit cancellation and one-minute idle timeout and
tracks uploaded/downloaded payload bytes through the normal connection state.

The outbound adapter resolves only the Shadowsocks server locally, asks
`rewrite-platform` to bind the nonblocking UDP socket with interface and
routing-mark policy, connects that socket, and passes it into the official
crate's `ProxySocket`. Destination domain bytes therefore remain intact on the
wire rather than being pre-resolved by product code. The test authority was
extended with the same official crate's server-side UDP decoder and a bounded
local UDP relay; it remains test support and creates no inbound/server product
claim.

Focused Darwin arm64 evidence on 2026-08-29:

```sh
cargo test --manifest-path rust/Cargo.toml -p rewrite-config parses_phase6c_shadowsocks_sip004_aead_scope --all-features --target-dir /Users/ren/data/rust-target/mihomo/phase6c-shadowsocks-udp
PHASE6CSSUDP_CARGO_TARGET=/Users/ren/data/rust-target/mihomo/phase6c-shadowsocks-udp python3 compat/scripts/phase6c_shadowsocks_udp.py
```

Both checks pass. The differential covers AES-128-GCM, AES-256-GCM and
ChaCha20-IETF-Poly1305 independently; each listener uses one inbound client for
IPv4, domain and a subsequent 4 KiB IPv4 exchange, then compares controller
fields and process survival. It is included in the default controller/outbound
Actions shard. Native Linux CI evidence remains pending. UoT, plugins,
stream/extra/2022 ciphers, IPv6 UDP, HTTP-provider lifecycle/health,
inbound/server direction and shared dialer/transport composition remain open.

## Phase 6C-D Shadowsocks local provider/group evidence

The generic proxy-provider parser now has direct compatibility evidence for
Shadowsocks records in both inline payloads and local files. Their provider
member controller views retain `type: Shadowsocks`, provider ownership,
`udp: true` and `uot: false`; a `select` group expands both provider member
lists in configured order and reports the selected member's UDP capability.
No SS-specific provider branch or new dependency was required.

The deterministic differential starts two independent official-library SS
authorities with different ports and passwords. It selects the inline member,
proves domain TCP and IPv4 UDP echo, then stops that authority before selecting
the file member and repeating both transfers. This makes a stale or ignored
selector choice observable instead of allowing two equivalent authorities to
hide it. Provider/member and group summaries plus process survival are also
compared.

Focused Darwin arm64 evidence on 2026-08-29:

```sh
PHASE6CSSPROVIDER_CARGO_TARGET=/Users/ren/data/rust-target/mihomo/phase6c-shadowsocks-provider python3 compat/scripts/phase6c_shadowsocks_provider.py
```

The Go/Rust differential passes and is included in the default
controller/outbound Actions shard. Linux evidence remains pending that run.
HTTP-provider download/refresh/cache and automatic health behavior for SS,
UoT, plugins, stream/extra/2022 ciphers, IPv6 UDP, inbound/server direction and
shared dialer/transport composition remain open.

## Phase 6C-E Shadowsocks HTTP-provider lifecycle and health evidence

The generic HTTP provider can now be cited for its Shadowsocks consumer path.
Initial download parses an SS member and persists the exact payload; manual
refresh transactionally replaces the same member name with new server
credentials; a clean restart uses the fresh cache while the HTTP endpoint
returns 500. Selector state, provider ownership and `udp: true`/`uot: false`
remain visible across those generations.

The differential uses independent A and B official-library authorities with
different ports and passwords. It proves A TCP/UDP, refreshes the provider to B,
stops A and proves B TCP/UDP, then restarts the product and proves B again from
cache without another successful provider response. The provider healthcheck
performs a real HEAD request through B to a deterministic local 204 server and
must populate both member history and per-URL health state.

Focused Darwin arm64 evidence on 2026-08-29:

```sh
PHASE6CSSHTTPPROVIDER_CARGO_TARGET=/Users/ren/data/rust-target/mihomo/phase6c-shadowsocks-provider python3 compat/scripts/phase6c_shadowsocks_http_provider.py
```

The Go/Rust differential passes and is included in the default
controller/outbound Actions shard. Linux evidence remains pending that run.
The generic scheduled refresh, ETag, malformed/oversized rollback, transform
and concurrent reload corpus is not repeated with SS payloads. UoT, plugins,
stream/extra/2022 ciphers, IPv6 UDP, inbound/server direction and shared
dialer/transport composition remain open.

## Phase 6C-F Shadowsocks UDP-over-TCP evidence

Configuration now models `udp-over-tcp` and `udp-over-tcp-version` explicitly.
Omitted/zero and explicit v1 select the legacy magic destination; v2 adds its
request prefix and selects the v2 magic destination; other versions fail
validation. The controller reports `uot: true` only for a configured
Shadowsocks member with the option enabled. Non-Shadowsocks adapters continue
to reject these fields.

The official Shadowsocks crate still owns the encrypted TCP stream. A narrow
local adapter implements only sing UoT v1/v2 non-connect framing because the
selected Shadowsocks library has no UoT surface and reviewed alternatives are
bound to AnyTLS or a different UDP-over-TCP protocol. The runtime resolves the
requested UDP target before writing the UoT frame, retains the existing
per-client bounded session lifecycle, and uses the same tracker/cancellation/
one-minute idle rules as native Shadowsocks UDP.

Focused Darwin arm64 evidence on 2026-08-29:

```sh
cargo test --manifest-path rust/Cargo.toml -p rewrite-config parses_phase6c_shadowsocks_sip004_aead_scope --all-features --target-dir /Users/ren/data/rust-target/mihomo/phase6c-shadowsocks-uot
PHASE6CSSUOT_CARGO_TARGET=/Users/ren/data/rust-target/mihomo/phase6c-shadowsocks-uot python3 compat/scripts/phase6c_shadowsocks_uot.py
```

Both checks pass. The differential proves Go/Rust agreement for accepted
versions 0/1/2 and rejected version 3, real v1 and v2 encrypted TCP relay,
IPv4 and domain-originated requests, repeated datagrams on one client session,
controller capability and process survival. The authority independently logs
the magic destination version, preventing native SS UDP from satisfying the
gate accidentally. The script is in the default controller/outbound Actions
shard; native Linux evidence remains pending. Plugins, stream/extra/2022
ciphers, IPv6 UDP, inbound/server direction, UoT connect mode and shared
dialer/transport composition remain open.

## Phase 6C-G Shadowsocks legacy stream-cipher evidence

The workspace enables the official Shadowsocks library's stream-cipher feature
and configuration accepts exactly the eight additional methods shared with the
Go oracle: three AES-CTR widths, three AES-CFB widths, RC4-MD5 and
ChaCha20-IETF. The existing outbound stream and datagram adapters require no
hand-written cipher logic. `chacha20`, `xchacha20`, `aes-192-gcm` and the Go
implementation's broader extra AEAD set remain rejected because the selected
Rust library does not implement compatible methods for them.

Focused Darwin arm64 evidence on 2026-08-29:

```sh
cargo test --manifest-path rust/Cargo.toml -p rewrite-config parses_phase6c_shadowsocks_legacy_stream_scope --all-features --target-dir /Users/ren/data/rust-target/mihomo/phase6c-shadowsocks-legacy
PHASE6CSSLEGACY_CARGO_TARGET=/Users/ren/data/rust-target/mihomo/phase6c-shadowsocks-legacy python3 compat/scripts/phase6c_shadowsocks_legacy.py
```

The differential passes all eight methods independently. Every method proves a
domain TCP exchange, a 128 KiB IPv4 TCP exchange, half-close response delivery,
IPv4 and domain-originated native UDP relay, and product survival against the
same official-library authority. The script is included in the default
controller/outbound Actions shard; native Linux evidence remains pending.
Plugins, Shadowsocks 2022, Go-only extra methods, IPv6 UDP, inbound/server mode
and shared dialer/transport composition remain open.

## Phase 6C-H Shadowsocks extra AEAD evidence

The workspace enables the official library's extra SIP004 AEAD feature and the
config parser accepts the five methods shared with Go: XChaCha20-IETF-Poly1305,
AES-128/256-CCM and AES-128/256-GCM-SIV. The same outbound TCP/native-UDP
adapters own routing and lifecycle; the product contains no new cipher code.

Focused Darwin arm64 evidence on 2026-08-29:

```sh
cargo test --manifest-path rust/Cargo.toml -p rewrite-config parses_phase6c_shadowsocks_extra_aead_scope --all-features --target-dir /Users/ren/data/rust-target/mihomo/phase6c-shadowsocks-extra-aead
PHASE6CSSEXTRAAEAD_CARGO_TARGET=/Users/ren/data/rust-target/mihomo/phase6c-shadowsocks-extra-aead python3 compat/scripts/phase6c_shadowsocks_extra_aead.py
```

The five-method Go/Rust differential passes. Each method proves domain TCP,
128 KiB IPv4 TCP, half-close delivery, IPv4/domain native UDP and process
survival with an independent official-library authority. The script is in the
default controller/outbound Actions shard; Linux evidence remains pending.
Go-only AES-192-CCM, reduced-round ChaCha, AEGIS/AEZ/Deoxys/LEA/Ascon and other
extra methods remain rejected, while 2022 and plugins remain later gates.

## Phase 6C-I Shadowsocks 2022 TCP evidence

The workspace enables the official library's Shadowsocks 2022 feature. The
parser accepts the three standard shared methods and validates their single
base64 PSK at configuration time: 16 decoded bytes for AES-128 and 32 for
AES-256/ChaCha20. Invalid base64, wrong key lengths and `udp: true` are rejected
instead of deferring failure or exposing an unverified path.

Focused Darwin arm64 evidence on 2026-08-29:

```sh
cargo test --manifest-path rust/Cargo.toml -p rewrite-config parses_phase6c_shadowsocks_2022_scope --all-features --target-dir /Users/ren/data/rust-target/mihomo/phase6c-shadowsocks-2022
PHASE6CSS2022_CARGO_TARGET=/Users/ren/data/rust-target/mihomo/phase6c-shadowsocks-2022 python3 compat/scripts/phase6c_shadowsocks_2022.py
```

The differential passes key validation and all three independent TCP methods,
including domain relay, 128 KiB IPv4 relay, half-close delivery and process
survival. It is included in the default controller/outbound Actions shard;
native Linux evidence remains pending.

The UDP gate was attempted but is not claimed: the pinned Go
`sing-shadowsocks2` AES-2022 client dereferenced a nil `remoteCipher` in
`clientPacketConn.readPacket` on the first response from the official Rust
authority. Rust rejects 2022 UDP until this cross-implementation boundary can
be verified without weakening the oracle. EIH, 2022-extra, plugins, IPv6 UDP
and server direction remain open.

## Phase 6C-J Shadowsocks 2022 single-hop EIH evidence

AES-128-GCM and AES-256-GCM 2022 configurations now accept one EIH identity
key followed by one user PSK as `iPSK:uPSK`. Both components must be standard
base64 and decode to the method's exact key length. ChaCha20-2022 EIH and AES
chains longer than one identity hop remain rejected, so this slice does not
silently claim the broader EIH chain protocol.

Focused Darwin arm64 evidence on 2026-08-29:

```sh
cargo test --manifest-path rust/Cargo.toml -p rewrite-config parses_phase6c_shadowsocks_2022_single_hop_eih_scope --all-features --target-dir /Users/ren/data/rust-target/mihomo/phase6c-shadowsocks-2022-eih
PHASE6CSS2022EIH_CARGO_TARGET=/Users/ren/data/rust-target/mihomo/phase6c-shadowsocks-2022-eih python3 compat/scripts/phase6c_shadowsocks_2022_eih.py
```

The fixed Go oracle and Rust agree on valid AES-128/256 chains, malformed
identity keys and unsupported ChaCha EIH. Each AES method then passes domain
TCP, 128 KiB IPv4 TCP, half-close delivery and process-survival comparison
against an official-library multi-user authority. The gate is included in the
default controller/outbound Actions shard; Linux evidence remains pending.

Multi-hop EIH, native 2022 UDP, 2022-extra ciphers, plugins, IPv6 UDP and server
direction remain open.

Other workstreams stop at their latest independently accepted rows above.
`DNS-03`–`DNS-05` retain the platform/integration gaps documented above, while
`DNS-10`–`DNS-13` and `DNS-16`–`DNS-18` retain the platform/database/adapter/
provider/inbound integration gaps above.
Phase 4D3B, Phase 5A3b or another implementation gate must not begin without a
separate instruction and the exact inventory IDs/matrix rows. Accepted 0-RTT and broader
HTTP/3/HTTP/2 lifecycle, general encrypted-DNS pool/retry behavior, concurrent
DoH scheduling, broader DoQ endpoint/trust/token/error behavior, upstream
selection and broader REST control, `respect-rules`, intercepted DNS, TUN, remote proxy
protocols, external providers and broader REST/platform
compatibility are planned but not implied by this status.
