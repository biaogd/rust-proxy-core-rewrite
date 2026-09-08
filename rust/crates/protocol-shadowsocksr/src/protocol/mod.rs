//! SSR protocol plugins (SSR-A: `origin`; SSR-B: `auth_aes128_*`).

mod auth_aes128;
mod origin;

use rewrite_io::BoxedStream;

use crate::ShadowsocksRProtocolError;

pub(crate) use auth_aes128::{AUTH_AES128_MD5, AUTH_AES128_SHA1, AuthAes128Conn};

pub(crate) struct ProtocolContext<'a> {
    pub write_iv: &'a [u8],
    pub stream_key: &'a [u8],
    pub protocol_param: &'a str,
    pub obfs_overhead: usize,
}

pub(crate) fn wrap(
    name: &str,
    stream: BoxedStream,
    ctx: &ProtocolContext<'_>,
) -> Result<BoxedStream, ShadowsocksRProtocolError> {
    match name {
        "origin" => {
            if !ctx.protocol_param.is_empty() {
                return Err(ShadowsocksRProtocolError::Configuration(
                    "protocol-param is not accepted for SSR protocol `origin`".into(),
                ));
            }
            Ok(origin::wrap(stream))
        }
        "auth_aes128_md5" => Ok(Box::new(AuthAes128Conn::new(
            stream,
            AUTH_AES128_MD5,
            ctx.stream_key.to_vec(),
            ctx.write_iv.to_vec(),
            ctx.protocol_param,
            ctx.obfs_overhead,
        ))),
        "auth_aes128_sha1" => Ok(Box::new(AuthAes128Conn::new(
            stream,
            AUTH_AES128_SHA1,
            ctx.stream_key.to_vec(),
            ctx.write_iv.to_vec(),
            ctx.protocol_param,
            ctx.obfs_overhead,
        ))),
        other => Err(ShadowsocksRProtocolError::ProtocolPlugin(format!(
            "{other} (SSR-B implements origin / auth_aes128_md5 / auth_aes128_sha1 only)"
        ))),
    }
}

pub(crate) fn overhead(name: &str) -> Result<usize, ShadowsocksRProtocolError> {
    match name {
        "origin" => Ok(0),
        "auth_aes128_md5" | "auth_aes128_sha1" => Ok(9),
        other => Err(ShadowsocksRProtocolError::ProtocolPlugin(format!(
            "{other} (SSR-B implements origin / auth_aes128_md5 / auth_aes128_sha1 only)"
        ))),
    }
}
