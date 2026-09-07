//! Congestion-control selection for Hysteria2.
//!
//! HY2-A gate: stock Quinn [`quinn::congestion::BbrConfig`] is installed when
//! Clash `up`/`down` are unset (Go default). Brutal bandwidth control and BBR
//! profile knobs are deferred to HY2-B.

#![allow(dead_code)]

/// Documents the HY2-A congestion choice for status/compat reporting.
pub(crate) const HY2A_CONGESTION: &str = "quinn::congestion::BbrConfig (stock)";
