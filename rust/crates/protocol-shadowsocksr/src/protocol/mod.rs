//! SSR protocol plugins (SSR-A: `origin`; SSR-B: `auth_aes128_*`; SSR-C: `auth_sha1_v4` / `auth_chain_*`).

mod auth_aes128;
mod auth_chain;
mod auth_sha1_v4;
mod origin;

use rewrite_io::BoxedStream;

use crate::ShadowsocksRProtocolError;

pub(crate) use auth_aes128::{AUTH_AES128_MD5, AUTH_AES128_SHA1, AuthAes128Conn, AuthAes128Udp};
pub(crate) use auth_chain::{AuthChainConn, AuthChainKind, AuthChainUdp};
pub(crate) use auth_sha1_v4::AuthSha1V4Conn;

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
        "auth_sha1_v4" => Ok(Box::new(AuthSha1V4Conn::new(
            stream,
            ctx.stream_key.to_vec(),
            ctx.write_iv.to_vec(),
            ctx.obfs_overhead,
        ))),
        "auth_chain_a" => Ok(Box::new(AuthChainConn::new(
            stream,
            AuthChainKind::A,
            ctx.stream_key.to_vec(),
            ctx.write_iv.to_vec(),
            ctx.protocol_param,
            ctx.obfs_overhead,
        ))),
        "auth_chain_b" => Ok(Box::new(AuthChainConn::new(
            stream,
            AuthChainKind::B,
            ctx.stream_key.to_vec(),
            ctx.write_iv.to_vec(),
            ctx.protocol_param,
            ctx.obfs_overhead,
        ))),
        other => Err(ShadowsocksRProtocolError::ProtocolPlugin(format!(
            "{other} (SSR-C implements origin / auth_aes128_md5 / auth_aes128_sha1 / auth_sha1_v4 / auth_chain_a / auth_chain_b)"
        ))),
    }
}

pub(crate) fn overhead(name: &str) -> Result<usize, ShadowsocksRProtocolError> {
    match name {
        "origin" => Ok(0),
        "auth_aes128_md5" | "auth_aes128_sha1" => Ok(9),
        "auth_sha1_v4" => Ok(7),
        "auth_chain_a" | "auth_chain_b" => Ok(4),
        other => Err(ShadowsocksRProtocolError::ProtocolPlugin(format!(
            "{other} (SSR-C implements origin / auth_aes128_md5 / auth_aes128_sha1 / auth_sha1_v4 / auth_chain_a / auth_chain_b)"
        ))),
    }
}
