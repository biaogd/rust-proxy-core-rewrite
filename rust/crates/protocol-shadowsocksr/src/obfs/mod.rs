//! SSR obfs plugins (SSR-A: `plain` only).

mod plain;

use rewrite_io::BoxedStream;

use crate::ShadowsocksRProtocolError;

pub(crate) fn wrap(
    name: &str,
    stream: BoxedStream,
    obfs_param: &str,
) -> Result<BoxedStream, ShadowsocksRProtocolError> {
    if !obfs_param.is_empty() {
        return Err(ShadowsocksRProtocolError::Configuration(format!(
            "obfs-param is not accepted for SSR-A obfs `{name}`"
        )));
    }
    match name {
        "plain" => Ok(plain::wrap(stream)),
        other => Err(ShadowsocksRProtocolError::Obfs(format!(
            "{other} (SSR-A implements plain only)"
        ))),
    }
}
