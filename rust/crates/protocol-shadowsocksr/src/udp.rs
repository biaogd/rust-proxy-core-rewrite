//! UDP association stub — SSR-A is TCP-only.

use crate::ShadowsocksRProtocolError;

/// SSR UDP is out of scope for SSR-A.
///
/// # Errors
///
/// Always returns a configuration error so callers cannot silently fall back.
pub fn associate_udp() -> Result<(), ShadowsocksRProtocolError> {
    Err(ShadowsocksRProtocolError::Configuration(
        "ShadowsocksR UDP is not implemented in SSR-A".to_owned(),
    ))
}
