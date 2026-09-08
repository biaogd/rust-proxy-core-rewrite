//! SSR UDP association: SOCKS addr (no RSV/FRAG) → protocol EncodePacket → stream Pack.
//!
//! Matches Go `ShadowSocksR.ListenPacketContext` layering (`cipher.PacketConn` then
//! `protocol.PacketConn`). Obfs plugins are TCP-only.

use std::net::IpAddr;

use bytes::{Buf as _, BufMut as _};
use rewrite_model::{Destination, Host};
use tokio::net::UdpSocket;

use crate::ShadowsocksRProtocolError;
use crate::cipher::{SsrStreamCipher, derive_key, pack_udp, parse_stream_cipher, unpack_udp};
use crate::client::SsrClientOptions;
use crate::protocol::{AUTH_AES128_MD5, AUTH_AES128_SHA1, AuthAes128Udp, AuthChainUdp};

enum ProtocolUdp {
    Identity,
    AuthAes128(AuthAes128Udp),
    AuthChain(AuthChainUdp),
}

impl ProtocolUdp {
    fn new(
        protocol: &str,
        protocol_param: &str,
        stream_key: &[u8],
    ) -> Result<Self, ShadowsocksRProtocolError> {
        match protocol {
            "origin" | "auth_sha1_v4" => {
                if protocol == "origin" && !protocol_param.is_empty() {
                    return Err(ShadowsocksRProtocolError::Configuration(
                        "protocol-param is not accepted for SSR protocol `origin`".into(),
                    ));
                }
                Ok(Self::Identity)
            }
            "auth_aes128_md5" => Ok(Self::AuthAes128(AuthAes128Udp::new(
                AUTH_AES128_MD5,
                stream_key.to_vec(),
                protocol_param,
            ))),
            "auth_aes128_sha1" => Ok(Self::AuthAes128(AuthAes128Udp::new(
                AUTH_AES128_SHA1,
                stream_key.to_vec(),
                protocol_param,
            ))),
            "auth_chain_a" | "auth_chain_b" => Ok(Self::AuthChain(AuthChainUdp::new(
                stream_key.to_vec(),
                protocol_param,
            ))),
            other => Err(ShadowsocksRProtocolError::ProtocolPlugin(format!(
                "{other} (SSR-C UDP implements origin / auth_aes128_* / auth_sha1_v4 / auth_chain_a / auth_chain_b)"
            ))),
        }
    }

    fn encode(&mut self, plaintext: &[u8]) -> Vec<u8> {
        match self {
            Self::Identity => plaintext.to_vec(),
            Self::AuthAes128(p) => p.encode_packet(plaintext),
            Self::AuthChain(p) => p.encode_packet(plaintext),
        }
    }

    fn decode(&mut self, packet: &[u8]) -> Result<Vec<u8>, ShadowsocksRProtocolError> {
        match self {
            Self::Identity => Ok(packet.to_vec()),
            Self::AuthAes128(p) => p.decode_packet(packet),
            Self::AuthChain(p) => p.decode_packet(packet),
        }
    }
}

/// Connected SSR UDP association (client → SSR server).
pub struct SsrUdpAssociation {
    socket: UdpSocket,
    cipher: SsrStreamCipher,
    key: Vec<u8>,
    protocol: ProtocolUdp,
}

impl SsrUdpAssociation {
    /// Builds an association over an already-connected UDP socket.
    ///
    /// # Errors
    ///
    /// Returns when cipher/protocol options are unsupported.
    pub fn from_connected_socket(
        socket: UdpSocket,
        options: &SsrClientOptions,
    ) -> Result<Self, ShadowsocksRProtocolError> {
        reject_non_ssr_udp(options)?;
        let cipher = parse_stream_cipher(&options.cipher)?;
        let key = derive_key(&options.password, cipher);
        // Obfs is TCP-only; refuse non-plain so callers cannot assume UDP camouflage.
        match options.obfs.as_str() {
            "plain" => {
                if !options.obfs_param.is_empty() {
                    return Err(ShadowsocksRProtocolError::Configuration(
                        "obfs-param is not accepted for SSR obfs `plain`".into(),
                    ));
                }
            }
            other => {
                return Err(ShadowsocksRProtocolError::Configuration(format!(
                    "SSR UDP does not apply TCP obfs `{other}` (use plain)"
                )));
            }
        }
        let protocol = ProtocolUdp::new(&options.protocol, &options.protocol_param, &key)?;
        Ok(Self {
            socket,
            cipher,
            key,
            protocol,
        })
    }

    /// Sends one SSR UDP datagram (SOCKS addr without RSV/FRAG + payload).
    ///
    /// # Errors
    ///
    /// Returns framing, protocol, or socket errors.
    pub async fn send(
        &mut self,
        destination: &Destination,
        payload: &[u8],
    ) -> Result<(), ShadowsocksRProtocolError> {
        let mut plain = encode_socks_addr(destination)?;
        plain.extend_from_slice(payload);
        let framed = self.protocol.encode(&plain);
        let packed = pack_udp(self.cipher, &self.key, &framed);
        self.socket
            .send(&packed)
            .await
            .map_err(ShadowsocksRProtocolError::Io)?;
        Ok(())
    }

    /// Receives one SSR UDP datagram.
    ///
    /// # Errors
    ///
    /// Returns framing, protocol, or socket errors.
    pub async fn recv(&mut self) -> Result<(Destination, Vec<u8>), ShadowsocksRProtocolError> {
        let mut buffer = vec![0_u8; 65_536];
        let length = self
            .socket
            .recv(&mut buffer)
            .await
            .map_err(ShadowsocksRProtocolError::Io)?;
        buffer.truncate(length);
        let unpacked = unpack_udp(self.cipher, &self.key, &buffer)?;
        let decoded = self.protocol.decode(&unpacked)?;
        split_socks_payload(&decoded)
    }
}

fn reject_non_ssr_udp(options: &SsrClientOptions) -> Result<(), ShadowsocksRProtocolError> {
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

fn split_socks_payload(packet: &[u8]) -> Result<(Destination, Vec<u8>), ShadowsocksRProtocolError> {
    if packet.is_empty() {
        return Err(ShadowsocksRProtocolError::Protocol(
            "SSR UDP packet missing SOCKS address".into(),
        ));
    }
    let mut cursor = std::io::Cursor::new(packet);
    let atyp = cursor.get_u8();
    let host = match atyp {
        0x01 => {
            if cursor.remaining() < 4 + 2 {
                return Err(ShadowsocksRProtocolError::Protocol(
                    "SSR UDP IPv4 address truncated".into(),
                ));
            }
            let mut octets = [0_u8; 4];
            cursor.copy_to_slice(&mut octets);
            Host::Ip(IpAddr::V4(octets.into()))
        }
        0x04 => {
            if cursor.remaining() < 16 + 2 {
                return Err(ShadowsocksRProtocolError::Protocol(
                    "SSR UDP IPv6 address truncated".into(),
                ));
            }
            let mut octets = [0_u8; 16];
            cursor.copy_to_slice(&mut octets);
            Host::Ip(IpAddr::V6(octets.into()))
        }
        0x03 => {
            if cursor.remaining() < 1 {
                return Err(ShadowsocksRProtocolError::Protocol(
                    "SSR UDP domain length truncated".into(),
                ));
            }
            let len = usize::from(cursor.get_u8());
            if cursor.remaining() < len + 2 {
                return Err(ShadowsocksRProtocolError::Protocol(
                    "SSR UDP domain address truncated".into(),
                ));
            }
            let mut name = vec![0_u8; len];
            cursor.copy_to_slice(&mut name);
            let domain = String::from_utf8(name).map_err(|_| {
                ShadowsocksRProtocolError::Protocol("SSR UDP domain is not UTF-8".into())
            })?;
            Host::Domain(domain)
        }
        other => {
            return Err(ShadowsocksRProtocolError::Protocol(format!(
                "SSR UDP unknown SOCKS atyp {other}"
            )));
        }
    };
    let port = cursor.get_u16();
    let start = usize::try_from(cursor.position()).map_err(|_| {
        ShadowsocksRProtocolError::Protocol("SSR UDP address position overflow".into())
    })?;
    Ok((Destination { host, port }, packet[start..].to_vec()))
}

/// Legacy stub name kept for callers; prefer [`SsrUdpAssociation`].
///
/// # Errors
///
/// Always returns a configuration error pointing at the association API.
pub fn associate_udp() -> Result<(), ShadowsocksRProtocolError> {
    Err(ShadowsocksRProtocolError::Configuration(
        "use SsrUdpAssociation::from_connected_socket for ShadowsocksR UDP".to_owned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn socks_roundtrip_ipv4() {
        let dest = Destination {
            host: Host::Ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
            port: 53,
        };
        let mut encoded = encode_socks_addr(&dest).unwrap();
        encoded.extend_from_slice(b"dns");
        let (got, payload) = split_socks_payload(&encoded).unwrap();
        assert_eq!(got, dest);
        assert_eq!(payload, b"dns");
    }

    #[test]
    fn auth_aes128_udp_encode_appends_uid_and_mac() {
        let key = vec![0x22_u8; 16];
        let udp = AuthAes128Udp::new(AUTH_AES128_MD5, key, "9:pass");
        let encoded = udp.encode_packet(b"abc");
        assert_eq!(encoded.len(), 3 + 4 + 4);
        assert_eq!(&encoded[..3], b"abc");
        assert_eq!(&encoded[3..7], &9_u32.to_le_bytes());
    }
}
