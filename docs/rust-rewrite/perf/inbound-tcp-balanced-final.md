# Inbound Go vs Rust perf (balanced O3 release)

Profile: Rust `opt-level=3 lto=fat codegen-units=1 strip=symbols panic=abort`.
Binary size: Go stripped **37.13 MiB**, Rust **27.64 MiB**.

## gRPC / Gun diagnosis

Not an h2-library weakness; Rust used bare handshake defaults (64KiB window / 16KiB frames) while Go metacubex/http pipelines at ~1MiB. Raising Builder SETTINGS + fixing Gun frame drain recovered trojan-grpc to 1.15x Go and nearly doubled vmess-grpc absolute Mbps. vless-grpc remains ~0.65x — residual looks VLESS-path specific, not generic Gun/h2.

Changes:
- h2 client/server Builder: stream/conn windows and max_frame ~1–4 MiB
- Gun frames sent as owned Bytes slices (no second copy_from_slice)
- Gun read pull 32KiB; drain by available WINDOW_UPDATE (not wait-for-full-frame)

| protocol | before Rust Mbps | after Rust Mbps | after Rust/Go |
|---|---:|---:|---:|
| trojan-grpc | 1432.9 | 2624.5 | 1.149 |
| vless-grpc | 1370.5 | 1442.9 | 0.651 |
| vmess-grpc | 1171.4 | 2118.7 | 3803.740 |

## Full table

| protocol | Go Mbps | Rust Mbps | Rust/Go | Go p50 ms | Rust p50 ms |
|---|---:|---:|---:|---:|---:|
| anytls | 2216.7 | 2910.4 | 1.313 | 0.36 | 0.25 |
| hysteria2 | 1479.1 | 1997.1 | 1.350 | 0.47 | 0.30 |
| ss-2022 | 2456.4 | 3296.5 | 1.342 | 0.45 | 0.23 |
| ss-aead | 90.6 | 45.5 | 0.502 | 0.40 | 0.24 |
| ss-chacha | 87.3 | 99.3 | 1.138 | 0.40 | 0.23 |
| trojan-grpc | 2283.3 | 2624.5 | 1.149 | 0.50 | 0.26 |
| trojan-tls | 1440.6 | 1756.7 | 1.219 | 1.70 | 0.49 |
| trojan-wss | 1372.7 | 3048.7 | 2.221 | 1.81 | 0.56 |
| tuic | 1491.0 | 1764.2 | 1.183 | 0.43 | 0.29 |
| vless-grpc | 2216.8 | 1442.9 | 0.651 | 0.50 | 0.25 |
| vless-tls | 1419.2 | 1989.8 | 1.402 | 1.69 | 0.50 |
| vless-wss | 1364.1 | 3075.3 | 2.255 | 1.80 | 0.60 |
| vmess-grpc | 0.6 | 2118.7 | 3803.740 | 0.66 | 0.31 |
| vmess-tls | 205.0 | 2084.7 | 10.168 | 1.89 | 0.51 |
| vmess-wss | 303.2 | 1909.2 | 6.296 | 1.89 | 0.62 |

## Notes
- anytls / vless-grpc / vmess-tls medians from isolated 5-run rerun (long matrix had host contention)
- Go VMess Mbps anomalously low / CPU sampler often 0 in this harness; use Rust absolute Mbps for VMess
- Go vmess-grpc essentially non-functional in this harness (success-rate 0.11)
- Rust VMess soak hits ~65535 ok then failures (uint16 ceiling); bulk path unaffected
- ss-2022 bulk at 256KiB; ss-aead/ss-chacha bulk reported at 4KiB because Rust pre-2022 AEAD product path fails exchanges at >=32KiB
- SSR inbound does not exist on Go or Rust (outbound-only)
- ss-aead Rust 4KiB bulk still highly variable (CPU sampler often 0); latency/soak remain strong
- gRPC: root cause was untuned h2 SETTINGS (not slow h2 crate); after MiB windows + Gun drain fix, trojan-grpc 1.15x Go, vmess-grpc ~2.1Gbps; vless-grpc still ~0.65x
