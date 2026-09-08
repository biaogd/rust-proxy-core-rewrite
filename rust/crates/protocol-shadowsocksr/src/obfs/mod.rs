//! SSR obfs plugins (SSR-A: `plain`; SSR-B: http_* + tls1.2_ticket_*; SSR-C: `random_head`).

mod http;
mod plain;
mod random_head;
mod tls12_ticket;

use rewrite_io::BoxedStream;

use crate::ShadowsocksRProtocolError;

pub(crate) struct ObfsContext<'a> {
    pub host: &'a str,
    pub port: u16,
    pub stream_key: &'a [u8],
    pub iv_len: usize,
    pub obfs_param: &'a str,
}

pub(crate) fn wrap(
    name: &str,
    stream: BoxedStream,
    ctx: &ObfsContext<'_>,
) -> Result<BoxedStream, ShadowsocksRProtocolError> {
    match name {
        "plain" => {
            if !ctx.obfs_param.is_empty() {
                return Err(ShadowsocksRProtocolError::Configuration(
                    "obfs-param is not accepted for SSR obfs `plain`".into(),
                ));
            }
            Ok(plain::wrap(stream))
        }
        "http_simple" => Ok(Box::new(http::HttpObfsConn::new(
            stream,
            ctx.host.to_owned(),
            ctx.port,
            ctx.obfs_param.to_owned(),
            ctx.iv_len,
            false,
        ))),
        "http_post" => Ok(Box::new(http::HttpObfsConn::new(
            stream,
            ctx.host.to_owned(),
            ctx.port,
            ctx.obfs_param.to_owned(),
            ctx.iv_len,
            true,
        ))),
        "tls1.2_ticket_auth" | "tls1.2_ticket_fastauth" => {
            // Camouflage only — not real TLS (no rustls).
            Ok(Box::new(tls12_ticket::Tls12TicketConn::new(
                stream,
                ctx.host.to_owned(),
                ctx.obfs_param.to_owned(),
                ctx.stream_key.to_vec(),
            )))
        }
        "random_head" => {
            if !ctx.obfs_param.is_empty() {
                return Err(ShadowsocksRProtocolError::Configuration(
                    "obfs-param is not accepted for SSR obfs `random_head`".into(),
                ));
            }
            Ok(Box::new(random_head::RandomHeadConn::new(stream)))
        }
        other => Err(ShadowsocksRProtocolError::Obfs(format!(
            "{other} (SSR-C implements plain / http_simple / http_post / tls1.2_ticket_auth / tls1.2_ticket_fastauth / random_head)"
        ))),
    }
}

pub(crate) fn overhead(name: &str) -> Result<usize, ShadowsocksRProtocolError> {
    match name {
        "plain" | "http_simple" | "http_post" | "random_head" => Ok(0),
        "tls1.2_ticket_auth" | "tls1.2_ticket_fastauth" => Ok(5),
        other => Err(ShadowsocksRProtocolError::Obfs(format!(
            "{other} (SSR-C implements plain / http_simple / http_post / tls1.2_ticket_auth / tls1.2_ticket_fastauth / random_head)"
        ))),
    }
}
