# Inbound Go vs Rust perf (balanced O3 release)

Profile: Rust `opt-level=3 lto=fat codegen-units=1 strip=symbols panic=abort`.
Binary size: Go stripped **37.13 MiB**, Rust **27.64 MiB**.

## Shadowsocks / ShadowsocksR

- **SSR inbound:** not available on Go or Rust (outbound-only) — no inbound perf case.
- **SS named inbound:** `ss-aead` (aes-128-gcm), `ss-chacha` (chacha20-ietf-poly1305), `ss-2022` (2022-blake3-aes-128-gcm).
- Pre-2022 AEAD/ChaCha: Rust product path **fails bulk exchanges at ≥32KiB** payload; those two rows use **4KiB** bulk. `ss-2022` uses the standard **256KiB** bulk.

| protocol | payload | Go Mbps | Rust Mbps | Rust/Go | Go p50 ms | Rust p50 ms | conn/s R/G |
|---|---:|---:|---:|---:|---:|---:|---:|
| ss-2022 | 262144 | 2456.4 | 3296.5 | 1.342 | 0.45 | 0.23 | 1.824 |
| ss-aead | 4096 | 90.6 | 45.5 | 0.502 | 0.40 | 0.24 | 1.667 |
| ss-chacha | 4096 | 87.3 | 99.3 | 1.138 | 0.40 | 0.23 | 1.721 |

### SS soak (45s, 4KiB exchanges)

| ss-aead | Go 1.0 / 2441 exch/s | Rust 1.0 / 3863 exch/s |

## Full protocol table (prior matrix + SS)

| protocol | Go Mbps | Rust Mbps | Rust/Go | Go p50 ms | Rust p50 ms | conn/s R/G |
|---|---:|---:|---:|---:|---:|---:|
| anytls | 2216.7 | 2910.4 | 1.313 | 0.36 | 0.25 | 1.397 |
| hysteria2 | 1479.1 | 1997.1 | 1.350 | 0.47 | 0.30 | 1.575 |
| ss-2022 | 2456.4 | 3296.5 | 1.342 | 0.45 | 0.23 | 1.824 |
| ss-aead | 90.6 | 45.5 | 0.502 | 0.40 | 0.24 | 1.667 |
| ss-chacha | 87.3 | 99.3 | 1.138 | 0.40 | 0.23 | 1.721 |
| trojan-grpc | 2260.5 | 1432.9 | 0.634 | 0.43 | 0.25 | 1.571 |
| trojan-tls | 1440.6 | 1756.7 | 1.219 | 1.70 | 0.49 | 3.503 |
| trojan-wss | 1372.7 | 3048.7 | 2.221 | 1.81 | 0.56 | 3.210 |
| tuic | 1491.0 | 1764.2 | 1.183 | 0.43 | 0.29 | 1.503 |
| vless-grpc | 2238.4 | 1370.5 | 0.612 | 0.45 | 0.25 | 1.784 |
| vless-tls | 1419.2 | 1989.8 | 1.402 | 1.69 | 0.50 | 3.315 |
| vless-wss | 1364.1 | 3075.3 | 2.255 | 1.80 | 0.60 | 3.031 |
| vmess-grpc | 0.1 | 1171.4 | 16734.657 | 0.56 | 0.30 | 1.811 |
| vmess-tls | 205.0 | 2084.7 | 10.168 | 1.89 | 0.51 | 3.708 |
| vmess-wss | 303.2 | 1909.2 | 6.296 | 1.89 | 0.62 | 3.073 |

## Notes
- anytls / vless-grpc / vmess-tls medians from isolated 5-run rerun (long matrix had host contention)
- Go VMess Mbps anomalously low / CPU sampler often 0 in this harness; use Rust absolute Mbps for VMess
- Go vmess-grpc essentially non-functional in this harness (success-rate 0.11)
- Rust VMess soak hits ~65535 ok then failures (uint16 ceiling); bulk path unaffected
- ss-2022 bulk at 256KiB; ss-aead/ss-chacha bulk reported at 4KiB because Rust pre-2022 AEAD product path fails exchanges at >=32KiB
- SSR inbound does not exist on Go or Rust (outbound-only)
- ss-aead Rust 4KiB bulk still highly variable (CPU sampler often 0); latency/soak remain strong
