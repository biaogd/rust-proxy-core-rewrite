# Inbound Go vs Rust perf (balanced O3 release)

Profile: Rust `opt-level=3 lto=fat codegen-units=1 strip=symbols panic=abort`.
Binary size: Go stripped **~54 MiB** (unoptimized artifact path) / documented stripped **37.13 MiB**, Rust **~27.8 MiB**.

## gRPC / Gun diagnosis

Not an h2-library weakness; Rust used bare handshake defaults (64KiB window / 16KiB frames) while Go metacubex/http pipelines at ~1MiB. Raising Builder SETTINGS + fixing Gun frame drain recovered trojan-grpc to ~1.15–1.19x Go and nearly doubled vmess-grpc absolute Mbps.

vless-grpc residual after h2 windows was VLESS-path specific: Rust `accept_vless_request` eagerly wrote `[VERSION, 0]` as its own Gun DATA frame, while Go `sing_vless.serverConn` coalesces that header with the first application write. Matching that (plus stashing the client header||payload coalesce across `Poll::Pending`) lifts vless-grpc from ~0.65x to ~0.88–0.90x Go.

Further VLESS-path work (32 KiB peel relay + Go `WriterReplaceable` peel into fast `copy_bidirectional`) reaches ~**2051 Mbps / 0.92x** Go. Gun `FrontHeadroom` / `poll_write_with_prefix` regressed to ~0.76x and was dropped — Vec coalesce already yields one Gun DATA frame.

Changes:
- h2 client/server Builder: stream/conn windows and max_frame ~1–4 MiB
- Gun frames sent as owned Bytes slices (no second copy_from_slice)
- Gun read pull 32KiB; drain by available WINDOW_UPDATE (not wait-for-full-frame)
- VLESS: lazy server response via `VlessServerStream`; client Pending coalesce stash
- VLESS: peel during 32 KiB relay; writer-side peel after request sent (Go `WriterReplaceable`)

| protocol | before h2 fix | after h2 fix | after VLESS coalesce | after writer peel (latest) | Rust/Go (latest) |
|---|---:|---:|---:|---:|---:|
| trojan-grpc | 1432.9 | 2624.5 | 2674.0 | 2659.5 | 1.166 |
| vless-grpc | 1370.5 | 1442.9 | 1943.5 | 2050.9 | 0.917 |
| vmess-grpc | 1171.4 | 2118.7 | (unchanged) | — | — |

## Full table

| protocol | Go Mbps | Rust Mbps | Rust/Go | Go p50 ms | Rust p50 ms |
|---|---:|---:|---:|---:|---:|
| anytls | 2216.7 | 2910.4 | 1.313 | 0.36 | 0.25 |
| hysteria2 | 1479.1 | 1997.1 | 1.350 | 0.47 | 0.30 |
| ss-2022 | 2456.4 | 3296.5 | 1.342 | 0.45 | 0.23 |
| ss-aead | 90.6 | 45.5 | 0.502 | 0.40 | 0.24 |
| ss-chacha | 87.3 | 99.3 | 1.138 | 0.40 | 0.23 |
| trojan-grpc | 2281.4 | 2659.5 | 1.166 | 0.43 | 0.27 |
| trojan-tls | 1440.6 | 1756.7 | 1.219 | 1.70 | 0.49 |
| trojan-wss | 1372.7 | 3048.7 | 2.221 | 1.81 | 0.56 |
| tuic | 1491.0 | 1764.2 | 1.183 | 0.43 | 0.29 |
| vless-grpc | 2236.5 | 2050.9 | 0.917 | 0.45 | 0.26 |
| vless-tls | 1419.2 | 1989.8 | 1.402 | 1.69 | 0.50 |
| vless-wss | 1364.1 | 3075.3 | 2.255 | 1.80 | 0.60 |
| vmess-grpc | 0.6 | 2118.7 | 3803.740 | 0.66 | 0.31 |
| vmess-tls | 205.0 | 2084.7 | 10.168 | 1.89 | 0.51 |
| vmess-wss | 303.2 | 1909.2 | 6.296 | 1.89 | 0.62 |

## Notes
- anytls / vless-grpc / vmess-tls medians from isolated 5-run rerun (long matrix had host contention)
- trojan-grpc / vless-grpc latest from isolated 5-run after WriterReplaceable peel (2026-09-17)
- Go VMess Mbps anomalously low / CPU sampler often 0 in this harness; use Rust absolute Mbps for VMess
- Go vmess-grpc essentially non-functional in this harness (success-rate 0.11)
- Rust VMess soak hits ~65535 ok then failures (uint16 ceiling); bulk path unaffected
- ss-2022 bulk at 256KiB; ss-aead/ss-chacha bulk reported at 4KiB because Rust pre-2022 AEAD product path fails exchanges at >=32KiB
- SSR inbound does not exist on Go or Rust (outbound-only)
- ss-aead Rust 4KiB bulk still highly variable (CPU sampler often 0); latency/soak remain strong
- gRPC: root cause was untuned h2 SETTINGS (not slow h2 crate); after MiB windows + Gun drain fix, trojan-grpc ≥1.15x Go, vmess-grpc ~2.1Gbps
- vless-grpc: eager `[0,0]` Gun frame was the main leftover; lazy coalesce + 32KiB writer peel → ~2051 Mbps / ~0.92x Go. Remaining ~8% still VLESS-path (Rust absolute Mbps flat vs vless-tls; Gun FrontHeadroom prefix writes regress)
