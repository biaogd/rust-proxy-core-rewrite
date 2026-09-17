# Inbound Go vs Rust perf (balanced O3 release)

Profile: Rust `opt-level=3 lto=fat codegen-units=1 strip=symbols panic=abort`.
Binary size: Go stripped **37.13 MiB**, Rust **27.64 MiB**.

Conditions: 12s × 8 workers × 256KiB payload; median of 3 runs (5 for anytls/vless-grpc/vmess-tls); latency 60 samples; soak 45s.

| protocol | Go Mbps | Rust Mbps | Rust/Go | Go p50 ms | Rust p50 ms | conn/s Rust/Go | Go RSS KiB | Rust RSS KiB |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| anytls | 2216.7 | 2910.4 | 1.313 | 0.36 | 0.25 | 1.397 | 45116 | 24452 |
| hysteria2 | 1479.1 | 1997.1 | 1.350 | 0.47 | 0.30 | 1.575 | 47720 | 34796 |
| trojan-grpc | 2260.5 | 1432.9 | 0.634 | 0.43 | 0.25 | 1.571 | 45892 | 27652 |
| trojan-tls | 1440.6 | 1756.7 | 1.219 | 1.70 | 0.49 | 3.503 | 44504 | 23752 |
| trojan-wss | 1372.7 | 3048.7 | 2.221 | 1.81 | 0.56 | 3.210 | 45028 | 28052 |
| tuic | 1491.0 | 1764.2 | 1.183 | 0.43 | 0.29 | 1.503 | 57780 | 80588 |
| vless-grpc | 2238.4 | 1370.5 | 0.612 | 0.45 | 0.25 | 1.784 | 46440 | 27296 |
| vless-tls | 1419.2 | 1989.8 | 1.402 | 1.69 | 0.50 | 3.315 | 44164 | 23240 |
| vless-wss | 1364.1 | 3075.3 | 2.255 | 1.80 | 0.60 | 3.031 | 45176 | 27016 |
| vmess-grpc | 0.1 | 1171.4 | 16734.657 | 0.56 | 0.30 | 1.811 | 35844 | 27216 |
| vmess-tls | 205.0 | 2084.7 | 10.168 | 1.89 | 0.51 | 3.708 | 47436 | 25412 |
| vmess-wss | 303.2 | 1909.2 | 6.296 | 1.89 | 0.62 | 3.073 | 48328 | 28928 |

## Soak

| protocol | Go ok rate | Rust ok rate | Go exch/s | Rust exch/s |
|---|---:|---:|---:|---:|
| anytls | 1.0 | 1.0 | 2765.0 | 3796.7 |
| trojan-tls | 1.0 | 1.0 | 593.7 | 1964.1 |
| vmess-tls | 1.0 | 0.6445 | 557.4 | 2259.6 |

## Notes
- anytls / vless-grpc / vmess-tls medians from isolated 5-run rerun (long matrix had host contention)
- Go VMess Mbps anomalously low / CPU sampler often 0 in this harness; use Rust absolute Mbps for VMess
- Go vmess-grpc essentially non-functional in this harness (success-rate 0.11)
- Rust VMess soak hits ~65535 ok then failures (uint16 ceiling); bulk path unaffected
