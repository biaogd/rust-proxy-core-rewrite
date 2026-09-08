//! SSR protocol plugins (SSR-A: `origin` only).

mod origin;

use rewrite_io::BoxedStream;

use crate::ShadowsocksRProtocolError;

pub(crate) fn wrap(
    name: &str,
    stream: BoxedStream,
    _write_iv: &[u8],
    protocol_param: &str,
) -> Result<BoxedStream, ShadowsocksRProtocolError> {
    if !protocol_param.is_empty() {
        return Err(ShadowsocksRProtocolError::Configuration(format!(
            "protocol-param is not accepted for SSR-A protocol `{name}`"
        )));
    }
    match name {
        "origin" => Ok(origin::wrap(stream)),
        other => Err(ShadowsocksRProtocolError::ProtocolPlugin(format!(
            "{other} (SSR-A implements origin only)"
        ))),
    }
}
