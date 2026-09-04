use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rewrite_io::BoxedStream;
use rewrite_model::{Destination, Host};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use crate::{COMMAND_UDP, TrojanProtocolError, append_socks_address, request_header_with_command};

const MAX_PACKET: usize = 8192;

pub struct TrojanUdpAssociation {
    remote: BoxedStream,
    password: String,
    initial_destination: Destination,
    request_sent: bool,
}

impl TrojanUdpAssociation {
    /// Sends one UDP datagram using the Go oracle's 8192-byte frame splitting.
    ///
    /// # Errors
    ///
    /// Returns an I/O or address-framing error.
    pub async fn send(
        &mut self,
        destination: &Destination,
        payload: &[u8],
    ) -> Result<(), TrojanProtocolError> {
        if !self.request_sent {
            let header = request_header_with_command(
                &self.initial_destination,
                &self.password,
                COMMAND_UDP,
            )?;
            self.remote.write_all(&header).await?;
            self.request_sent = true;
        }
        for chunk in payload
            .chunks(MAX_PACKET)
            .chain(payload.is_empty().then_some(&[][..]))
        {
            let mut frame = Vec::with_capacity(23 + chunk.len());
            append_socks_address(&mut frame, destination)?;
            let length = u16::try_from(chunk.len()).map_err(|_| {
                TrojanProtocolError::Protocol("Trojan UDP frame length overflow".to_owned())
            })?;
            frame.extend_from_slice(&length.to_be_bytes());
            frame.extend_from_slice(b"\r\n");
            frame.extend_from_slice(chunk);
            self.remote.write_all(&frame).await?;
        }
        Ok(())
    }

    /// Receives one Trojan UDP frame.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed addresses, oversized lengths, a bad
    /// delimiter or truncated payloads.
    pub async fn recv(&mut self) -> Result<(Destination, Vec<u8>), TrojanProtocolError> {
        let destination = read_socks_address(&mut self.remote).await?;
        let length = usize::from(self.remote.read_u16().await?);
        if length > MAX_PACKET {
            return Err(TrojanProtocolError::Protocol(
                "Trojan UDP packet exceeds 8192 bytes".to_owned(),
            ));
        }
        let mut delimiter = [0_u8; 2];
        self.remote.read_exact(&mut delimiter).await?;
        let mut payload = vec![0_u8; length];
        self.remote.read_exact(&mut payload).await?;
        Ok((destination, payload))
    }
}

/// Creates a Trojan UDP association over an established TLS carrier.
#[must_use]
pub fn associate_trojan_udp_on_stream(
    remote: BoxedStream,
    destination: &Destination,
    password: &str,
) -> TrojanUdpAssociation {
    TrojanUdpAssociation {
        remote,
        password: password.to_owned(),
        initial_destination: destination.clone(),
        request_sent: false,
    }
}

async fn read_socks_address(remote: &mut BoxedStream) -> Result<Destination, TrojanProtocolError> {
    let host = match remote.read_u8().await? {
        1 => Host::Ip(IpAddr::V4(Ipv4Addr::from(remote.read_u32().await?))),
        4 => {
            let mut bytes = [0_u8; 16];
            remote.read_exact(&mut bytes).await?;
            Host::Ip(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        3 => {
            let length = usize::from(remote.read_u8().await?);
            let mut bytes = vec![0_u8; length];
            remote.read_exact(&mut bytes).await?;
            Host::Domain(String::from_utf8(bytes).map_err(|_| {
                TrojanProtocolError::Protocol("invalid Trojan UDP domain".to_owned())
            })?)
        }
        value => {
            return Err(TrojanProtocolError::Protocol(format!(
                "invalid Trojan UDP address type {value}"
            )));
        }
    };
    Ok(Destination {
        host,
        port: remote.read_u16().await?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn receives_address_payload_and_rejects_oversize() {
        let (client, mut authority) = tokio::io::duplex(128);
        authority
            .write_all(b"\x03\x0budp.example\x00\x35\x00\x04\r\npong")
            .await
            .expect("response");
        let destination = Destination {
            host: Host::Domain("initial.example".to_owned()),
            port: 53,
        };
        let mut association =
            associate_trojan_udp_on_stream(Box::new(client), &destination, "password");
        let (remote, payload) = association.recv().await.expect("packet");
        assert_eq!(remote.host, Host::Domain("udp.example".to_owned()));
        assert_eq!(remote.port, 53);
        assert_eq!(payload, b"pong");
    }

    #[tokio::test]
    async fn sends_zero_length_and_splits_at_oracle_boundary() {
        let destination = Destination {
            host: Host::Ip("192.0.2.1".parse().expect("IP")),
            port: 53,
        };
        let (client, mut authority) = tokio::io::duplex(32 * 1024);
        let expected_destination = destination.clone();
        let task = tokio::spawn(async move {
            let header =
                request_header_with_command(&expected_destination, "password", COMMAND_UDP)
                    .expect("header");
            let mut actual = vec![0; header.len()];
            authority
                .read_exact(&mut actual)
                .await
                .expect("header bytes");
            assert_eq!(actual, header);
            for length in [0_usize, MAX_PACKET, 1] {
                let mut address = Vec::new();
                append_socks_address(&mut address, &expected_destination).expect("address");
                let mut actual = vec![0; address.len()];
                authority
                    .read_exact(&mut actual)
                    .await
                    .expect("address bytes");
                assert_eq!(actual, address);
                assert_eq!(
                    usize::from(authority.read_u16().await.expect("length")),
                    length
                );
                let mut delimiter = [0; 2];
                authority
                    .read_exact(&mut delimiter)
                    .await
                    .expect("delimiter");
                assert_eq!(&delimiter, b"\r\n");
                let mut payload = vec![0; length];
                authority.read_exact(&mut payload).await.expect("payload");
            }
        });
        let mut association =
            associate_trojan_udp_on_stream(Box::new(client), &destination, "password");
        association.send(&destination, &[]).await.expect("empty");
        association
            .send(&destination, &vec![0; MAX_PACKET + 1])
            .await
            .expect("split");
        task.await.expect("authority task");
    }
}
