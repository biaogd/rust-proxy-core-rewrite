//! Brutal congestion controller — a quinn port of Hysteria2's signature
//! fixed-rate, loss-tolerant controller (Go: core/internal/congestion/brutal).
//!
//! HY2-A / HY2-B: stock Quinn [`BbrConfig`] remains the default when Clash
//! `up`/`down` are unset (Go default). Brutal is installed only when an upload
//! bandwidth is configured; [`SwitchableController`] can flip to BBR after
//! handshake when the server advertises `CC-RX: auto`.
//!
//! Brutal sends at a configured constant bitrate and never backs off on loss.
//! Instead it tracks the recent ACK success rate and *speeds up* to compensate
//! for losses (sending `rate / ackRate`, so 20% loss → ~25% faster).
//!
//! ## Quinn mapping (not a claim of Go pacer identity)
//!
//! Go Brutal owns an **independent token-bucket pacer** at `bps / ackRate` and
//! separately sizes the congestion window for in-flight
//! (`~2 * bps * RTT / ackRate`). Quinn's [`Controller`] trait only exposes
//! `window()`; Quinn's internal pacer always refills at
//! `~1.25 * window / RTT` and ignores `ControllerMetrics::pacing_rate`.
//!
//! To approximate the Go send-rate under that constraint we set:
//! `window = (bps / ackRate) * RTT / 1.25`, so Quinn's pacer emits at
//! `~bps / ackRate`. The previous `≥10 KiB` floor is removed — it made low
//! bandwidth / low RTT configs send far above the configured rate.
//! Echo success alone must not be treated as Brutal parity; see the Brutal
//! rate differential.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss
)]

use std::{
    any::Any,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use quinn_proto::RttEstimator;
use quinn_proto::congestion::{BbrConfig, Controller, ControllerFactory, ControllerMetrics};

const SLOT_COUNT: usize = 5; // seconds of ACK/loss history
const MIN_SAMPLE_COUNT: u64 = 50;
const MIN_ACK_RATE: f64 = 0.8;
/// Quinn's internal pacer refills at ~1.25×window/RTT (draft recovery §7.7).
const QUINN_PACING_GAIN: f64 = 1.25;
/// Assumed RTT used only before the first sample (matches Go's early 10 KiB
/// behaviour order-of-magnitude without locking a huge floor forever).
const INITIAL_RTT_HINT: Duration = Duration::from_millis(100);

/// Shared Brutal rate (bytes/sec) plus the flag that hands the window to BBR.
pub(crate) type BrutalControl = (Arc<AtomicU64>, Arc<AtomicBool>);

#[derive(Clone, Copy, Default)]
struct Slot {
    ts: i64, // seconds since `base`
    ack: u64,
    loss: u64,
}

#[derive(Clone)]
struct Brutal {
    /// Shared target send rate in bytes/sec. Read live on every `window()` so
    /// it can be clamped to the server's advertised Rx after the handshake
    /// (quinn cannot swap the controller itself, but it can read a new rate).
    rate: Arc<AtomicU64>,
    mtu: u64,
    base: Instant,
    srtt: Duration,
    ack_rate: f64,
    slots: [Slot; SLOT_COUNT],
}

impl Brutal {
    fn new(rate: Arc<AtomicU64>, mtu: u16) -> Self {
        Self {
            rate,
            mtu: u64::from(mtu),
            base: Instant::now(),
            srtt: Duration::ZERO,
            ack_rate: 1.0,
            slots: [Slot::default(); SLOT_COUNT],
        }
    }

    fn secs(&self, now: Instant) -> i64 {
        now.saturating_duration_since(self.base).as_secs() as i64
    }

    fn record(&mut self, now: Instant, ack: u64, loss: u64) {
        let ts = self.secs(now);
        let slot = &mut self.slots[(ts as usize) % SLOT_COUNT];
        if slot.ts == ts {
            slot.ack += ack;
            slot.loss += loss;
        } else {
            slot.ts = ts;
            slot.ack = ack;
            slot.loss = loss;
        }
        self.update_ack_rate(ts);
    }

    fn update_ack_rate(&mut self, now_ts: i64) {
        let min_ts = now_ts - SLOT_COUNT as i64;
        let (mut acks, mut losses) = (0u64, 0u64);
        for s in &self.slots {
            if s.ts < min_ts {
                continue;
            }
            acks += s.ack;
            losses += s.loss;
        }
        if acks + losses < MIN_SAMPLE_COUNT {
            self.ack_rate = 1.0;
            return;
        }
        let rate = acks as f64 / (acks + losses) as f64;
        self.ack_rate = rate.max(MIN_ACK_RATE);
    }

    /// Target application send rate after ACK-rate compensation (bytes/sec).
    fn target_bps(&self) -> f64 {
        let bps = self.rate.load(Ordering::Relaxed) as f64;
        if bps <= 0.0 {
            return 0.0;
        }
        bps / self.ack_rate.max(MIN_ACK_RATE)
    }

    /// Window that makes Quinn's 1.25×window/RTT pacer emit ≈ `target_bps`.
    fn window_for_rate(&self, rtt: Duration) -> u64 {
        // Floor at one MTU so QUIC can still emit a packet. Accurate rate
        // capping therefore requires `bps * RTT / 1.25 >= MTU` (low bandwidth
        // on sub-millisecond localhost RTT cannot be capped by window alone —
        // that case is excluded from the Brutal rate differential via injected
        // delay). The old fixed 10 KiB floor is gone.
        let floor = self.mtu.max(1);
        let target = self.target_bps();
        if target <= 0.0 {
            return floor;
        }
        let rtt = if rtt.is_zero() { INITIAL_RTT_HINT } else { rtt };
        let cwnd = target * rtt.as_secs_f64() / QUINN_PACING_GAIN;
        (cwnd as u64).max(floor)
    }
}

impl Controller for Brutal {
    fn on_ack(
        &mut self,
        now: Instant,
        _sent: Instant,
        _bytes: u64,
        _app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.srtt = rtt.get();
        self.record(now, 1, 0);
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        // Record loss for the ACK-rate estimate, but never shrink the window.
        let lost_pkts = (lost_bytes / self.mtu.max(1)).max(1);
        self.record(now, 0, lost_pkts);
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.mtu = u64::from(new_mtu);
    }

    fn window(&self) -> u64 {
        self.window_for_rate(self.srtt)
    }

    fn metrics(&self) -> ControllerMetrics {
        // Documented for qlog only — Quinn's pacer does not consume this.
        // ControllerMetrics is non_exhaustive; mutate a default instance.
        let mut metrics = ControllerMetrics::default();
        metrics.congestion_window = self.window();
        metrics.pacing_rate = Some((self.target_bps() * 8.0) as u64);
        metrics
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        self.window_for_rate(INITIAL_RTT_HINT)
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

/// Factory that builds a fresh [`Brutal`] controller per connection, all
/// sharing the same live rate handle.
#[allow(dead_code)] // SwitchableFactory covers the live Brutal path today.
pub(crate) struct BrutalFactory {
    /// Shared target send rate in bytes/sec.
    pub rate: Arc<AtomicU64>,
}

impl ControllerFactory for BrutalFactory {
    fn build(self: Arc<Self>, _now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(Brutal::new(self.rate.clone(), current_mtu))
    }
}

/// A controller that runs both Brutal and BBR in parallel and lets either one
/// govern the send window via a shared flag. This is how the client honours the
/// server's post-handshake `CC-RX: auto` (switch Brutal → BBR) despite quinn
/// fixing the controller at connect time: quinn only ever sees this one
/// wrapper, while we flip which inner controller's `window()` is authoritative.
///
/// Both inner controllers are fed every path event so the inactive one stays
/// warm and the switch is seamless.
struct SwitchableController {
    brutal: Brutal,
    bbr: Box<dyn Controller>,
    use_bbr: Arc<AtomicBool>,
}

impl SwitchableController {
    fn bbr_active(&self) -> bool {
        self.use_bbr.load(Ordering::Relaxed)
    }
}

impl Controller for SwitchableController {
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        self.brutal.on_sent(now, bytes, last_packet_number);
        self.bbr.on_sent(now, bytes, last_packet_number);
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.brutal.on_ack(now, sent, bytes, app_limited, rtt);
        self.bbr.on_ack(now, sent, bytes, app_limited, rtt);
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        self.brutal
            .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
        self.bbr
            .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        self.brutal
            .on_congestion_event(now, sent, is_persistent_congestion, lost_bytes);
        self.bbr
            .on_congestion_event(now, sent, is_persistent_congestion, lost_bytes);
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.brutal.on_mtu_update(new_mtu);
        self.bbr.on_mtu_update(new_mtu);
    }

    fn window(&self) -> u64 {
        if self.bbr_active() {
            self.bbr.window()
        } else {
            self.brutal.window()
        }
    }

    fn metrics(&self) -> ControllerMetrics {
        if self.bbr_active() {
            self.bbr.metrics()
        } else {
            self.brutal.metrics()
        }
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(Self {
            brutal: self.brutal.clone(),
            bbr: self.bbr.clone_box(),
            use_bbr: self.use_bbr.clone(),
        })
    }

    fn initial_window(&self) -> u64 {
        if self.bbr_active() {
            self.bbr.initial_window()
        } else {
            self.brutal.initial_window()
        }
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

/// Factory for [`SwitchableController`]. `rate` drives Brutal; flipping
/// `use_bbr` hands the window over to BBR.
pub(crate) struct SwitchableFactory {
    pub rate: Arc<AtomicU64>,
    pub use_bbr: Arc<AtomicBool>,
}

impl ControllerFactory for SwitchableFactory {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        let brutal = Brutal::new(self.rate.clone(), current_mtu);
        let bbr = Arc::new(BbrConfig::default()).build(now, current_mtu);
        Box::new(SwitchableController {
            brutal,
            bbr,
            use_bbr: self.use_bbr.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_tracks_configured_rate_without_10kib_floor() {
        let rate = Arc::new(AtomicU64::new(100_000)); // 100 KB/s
        let mut brutal = Brutal::new(rate, 1200);
        brutal.srtt = Duration::from_millis(50);
        brutal.ack_rate = 1.0;
        // window = 100_000 * 0.05 / 1.25 = 4_000 (above MTU, below old 10 KiB)
        assert_eq!(brutal.window(), 4_000);
        assert!(brutal.window() < 10_240);
    }

    #[test]
    fn window_floors_to_mtu_when_rate_rtt_product_is_tiny() {
        let rate = Arc::new(AtomicU64::new(100_000));
        let mut brutal = Brutal::new(rate, 1200);
        brutal.srtt = Duration::from_millis(1);
        brutal.ack_rate = 1.0;
        // 100_000 * 0.001 / 1.25 = 80 → floored to MTU
        assert_eq!(brutal.window(), 1200);
    }

    #[test]
    fn window_scales_with_ack_rate_compensation() {
        let rate = Arc::new(AtomicU64::new(1_000_000));
        let mut brutal = Brutal::new(rate, 1200);
        brutal.srtt = Duration::from_millis(40);
        brutal.ack_rate = 0.8;
        // target = 1e6/0.8 = 1.25e6; window = 1.25e6 * 0.04 / 1.25 = 40_000
        assert_eq!(brutal.window(), 40_000);
    }

    #[test]
    fn initial_window_uses_rate_hint_not_fixed_10kib() {
        let rate = Arc::new(AtomicU64::new(50_000));
        let brutal = Brutal::new(rate, 1200);
        // 50_000 * 0.1 / 1.25 = 4_000
        assert_eq!(brutal.initial_window(), 4_000);
    }
}
