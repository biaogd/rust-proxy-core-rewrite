//! SSR TCP client session: obfs → stream cipher → protocol → SOCKS address.

use std::net::IpAddr;

use bytes::BufMut as _;
use rewrite_io::BoxedStream;
use rewrite_model::{Destination, Host};
use tokio::io::AsyncWriteExt as _;

use crate::cipher::{StreamCipherConn, derive_key, parse_stream_cipher};
use crate::{ShadowsocksRProtocolError, obfs, protocol};

/// Options accepted by the SSR-A/B/C TCP dial.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SsrClientOptions {
    pub password: String,
    pub cipher: String,
    pub protocol: String,
    pub protocol_param: String,
    pub obfs: String,
    pub obfs_param: String,
    /// SSR server hostname (for http Host / tls camouflage SNI).
    pub server_host: String,
    pub server_port: u16,
}

/// Wraps an established TCP carrier in an SSR client session and writes the
/// SOCKS destination header.
/// This convenience function creates a one-shot identity. Repeated adapter
/// dials must use [`connect_tcp_on_stream_with_state`] with persistent state.
///
/// Layer order matches Go `ShadowSocksR.StreamConnContext`:
/// `obfs → stream cipher → protocol → SOCKS addr`.
///
/// # Errors
///
/// Returns when cipher/protocol/obfs are unimplemented or the SOCKS header
/// cannot be written.
pub async fn connect_tcp_on_stream(
    stream: BoxedStream,
    destination: &Destination,
    options: &SsrClientOptions,
) -> Result<BoxedStream, ShadowsocksRProtocolError> {
    connect_tcp_on_stream_with_state(
        stream,
        destination,
        options,
        &crate::SsrClientState::default(),
    )
    .await
}

/// Opens a session using the adapter's persistent authentication identity.
///
/// # Errors
/// Returns configuration, framing or underlying I/O errors.
pub async fn connect_tcp_on_stream_with_state(
    stream: BoxedStream,
    destination: &Destination,
    options: &SsrClientOptions,
    state: &crate::SsrClientState,
) -> Result<BoxedStream, ShadowsocksRProtocolError> {
    reject_non_ssr_stream(options)?;
    let cipher = parse_stream_cipher(&options.cipher)?;
    let key = derive_key(&options.password, cipher);
    let obfs_overhead = obfs::overhead(&options.obfs)?;
    let _ = protocol::overhead(&options.protocol)?;

    let stream = obfs::wrap(
        &options.obfs,
        stream,
        &obfs::ObfsContext {
            host: &options.server_host,
            port: options.server_port,
            stream_key: &key,
            iv_len: cipher.iv_len(),
            obfs_param: &options.obfs_param,
        },
    )?;
    let mut cipher_conn = StreamCipherConn::new(stream, cipher, key.clone())?;
    // Generate write IV before protocol wrap (Go ObtainWriteIV).
    let write_iv = cipher_conn.obtain_write_iv().to_vec();
    let stream: BoxedStream = Box::new(cipher_conn);
    let mut stream = protocol::wrap(
        &options.protocol,
        stream,
        &protocol::ProtocolContext {
            state,
            write_iv: &write_iv,
            stream_key: &key,
            protocol_param: &options.protocol_param,
            obfs_overhead,
        },
    )?;

    let header = encode_socks_addr(destination)?;
    stream.write_all(&header).await?;
    stream.flush().await?;
    Ok(stream)
}

fn reject_non_ssr_stream(options: &SsrClientOptions) -> Result<(), ShadowsocksRProtocolError> {
    // AEAD / SS2022 names must never be treated as SSR stream ciphers.
    let lower = options.cipher.to_ascii_lowercase();
    if lower.contains("gcm")
        || lower.contains("poly1305")
        || lower.contains("2022")
        || lower.contains("blake3")
        || lower.starts_with("aead_")
    {
        return Err(ShadowsocksRProtocolError::Configuration(format!(
            "cipher `{}` is AEAD/SS2022, not ShadowsocksR",
            options.cipher
        )));
    }
    Ok(())
}

fn encode_socks_addr(destination: &Destination) -> Result<Vec<u8>, ShadowsocksRProtocolError> {
    let mut buffer = Vec::with_capacity(32);
    match &destination.host {
        Host::Ip(IpAddr::V4(address)) => {
            buffer.put_u8(0x01);
            buffer.extend_from_slice(&address.octets());
        }
        Host::Ip(IpAddr::V6(address)) => {
            buffer.put_u8(0x04);
            buffer.extend_from_slice(&address.octets());
        }
        Host::Domain(domain) => {
            let length = u8::try_from(domain.len()).map_err(|_| {
                ShadowsocksRProtocolError::Protocol("SOCKS domain exceeds 255 bytes".to_owned())
            })?;
            buffer.put_u8(0x03);
            buffer.put_u8(length);
            buffer.extend_from_slice(domain.as_bytes());
        }
    }
    buffer.put_u16(destination.port);
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};

    use shadowsocks_crypto::CipherKind;
    use shadowsocks_crypto::v1::Cipher;
    use shadowsocks_crypto::v1::openssl_bytes_to_key;
    use tokio::io::{AsyncReadExt as _, duplex};
    use tokio::net::TcpListener;

    fn base_options() -> SsrClientOptions {
        SsrClientOptions {
            password: "ssr-a-password".into(),
            cipher: "aes-128-cfb".into(),
            protocol: "origin".into(),
            protocol_param: String::new(),
            obfs: "plain".into(),
            obfs_param: String::new(),
            server_host: "127.0.0.1".into(),
            server_port: 8388,
        }
    }

    #[tokio::test]
    async fn origin_plain_roundtrip_echo() {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            let (mut inbound, _) = listener.accept().await.expect("accept");
            let mut key = vec![0_u8; 16];
            openssl_bytes_to_key(b"ssr-a-password", &mut key);
            let mut iv = [0_u8; 16];
            inbound.read_exact(&mut iv).await.expect("iv");
            let mut dec = Cipher::new(CipherKind::AES_128_CFB128, &key, &iv);
            let mut header = [0_u8; 1 + 4 + 2];
            inbound.read_exact(&mut header).await.expect("hdr");
            let _ = dec.decrypt_packet(&mut header);
            assert_eq!(header[0], 0x01);
            let mut payload = vec![0_u8; 11];
            inbound.read_exact(&mut payload).await.expect("payload");
            let _ = dec.decrypt_packet(&mut payload);
            assert_eq!(&payload, b"hello-ssr-a");

            let mut reply_iv = [7_u8; 16];
            rand::fill(&mut reply_iv);
            let mut enc = Cipher::new(CipherKind::AES_128_CFB128, &key, &reply_iv);
            let mut body = payload.clone();
            enc.encrypt_packet(&mut body);
            inbound.write_all(&reply_iv).await.expect("riv");
            inbound.write_all(&body).await.expect("body");
        });

        let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let mut options = base_options();
        options.server_port = addr.port();
        let dest = Destination {
            host: Host::Ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
            port: 9,
        };
        let mut stream = connect_tcp_on_stream(Box::new(tcp), &dest, &options)
            .await
            .expect("ssr connect");
        stream.write_all(b"hello-ssr-a").await.expect("write");
        let mut got = [0_u8; 11];
        stream.read_exact(&mut got).await.expect("read");
        assert_eq!(&got, b"hello-ssr-a");
        server.await.expect("server");
    }

    #[test]
    fn rejects_unimplemented_protocol_loudly() {
        let (_a, b) = duplex(64);
        let mut options = base_options();
        options.protocol = "auth_chain_c".into();
        let dest = Destination {
            host: Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            port: 1,
        };
        let result = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(connect_tcp_on_stream(Box::new(b), &dest, &options));
        let Err(err) = result else {
            panic!("must reject");
        };
        assert!(err.to_string().contains("auth_chain_c"));
        assert!(err.to_string().contains("SSR-C implements"));
    }
}
