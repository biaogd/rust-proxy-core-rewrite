use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rand::RngExt as _;
use rewrite_io::BoxedStream;
use rewrite_model::{Destination, Host};
use tokio::io::{ReadHalf, WriteHalf};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::header::VmessCommand;
use super::header::read_response_header;
use super::{ConnectedVmess, VmessClientOptions, VmessProtocolError, connect_protocol_on_stream};

const VMESS_MAX_PACKET_FRAME: usize = 15_000;
const XUDP_STATUS_NEW: u8 = 1;
const XUDP_STATUS_KEEP: u8 = 2;
const XUDP_STATUS_END: u8 = 3;
const XUDP_STATUS_KEEPALIVE: u8 = 4;
const XUDP_OPTION_DATA: u8 = 1;
const XUDP_OPTION_ERROR: u8 = 2;
const XUDP_NETWORK_UDP: u8 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VmessPacketMode {
    Standard,
    PacketAddr,
    Xudp,
}

pub struct VmessUdpAssociation {
    remote: WriteHalf<BoxedStream>,
    body_writer: super::body::BodyWriter,
    mode: VmessPacketMode,
    fixed_destination: Destination,
    xudp_global_id: [u8; 8],
    xudp_request_written: bool,
    responses: mpsc::Receiver<Result<(Destination, Vec<u8>), VmessProtocolError>>,
    cancellation: CancellationToken,
}

struct VmessPacketReader {
    remote: ReadHalf<BoxedStream>,
    body_reader: super::body::BodyReader,
    response_key: [u8; 16],
    response_iv: [u8; 16],
    response_verification: u8,
    legacy_header: bool,
    response_header_read: bool,
    mode: VmessPacketMode,
    fixed_destination: Destination,
    xudp_read_buffer: Vec<u8>,
}

impl Drop for VmessUdpAssociation {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

impl VmessUdpAssociation {
    /// Sends one UDP datagram through the `VMess` association.
    ///
    /// # Errors
    ///
    /// Returns a protocol error for an unsupported destination or oversized
    /// datagram, and an I/O error when the `VMess` stream fails.
    pub async fn send(
        &mut self,
        destination: &Destination,
        payload: &[u8],
    ) -> Result<(), VmessProtocolError> {
        let frame = match self.mode {
            VmessPacketMode::Standard => {
                if destination != &self.fixed_destination {
                    return Err(VmessProtocolError::Protocol(
                        "VMess UDP association destination changed".to_owned(),
                    ));
                }
                payload.to_vec()
            }
            VmessPacketMode::PacketAddr => {
                let mut frame = Vec::with_capacity(payload.len() + 19);
                encode_packet_address(&mut frame, destination)?;
                frame.extend_from_slice(payload);
                frame
            }
            VmessPacketMode::Xudp => self.encode_xudp_frame(destination, payload)?,
        };
        if frame.len() > VMESS_MAX_PACKET_FRAME {
            return Err(VmessProtocolError::Protocol(
                "VMess UDP frame exceeds 15000 bytes".to_owned(),
            ));
        }
        self.body_writer
            .write_record(&mut self.remote, &frame)
            .await?;
        Ok(())
    }

    /// Receives one UDP datagram and its logical source destination.
    ///
    /// # Errors
    ///
    /// Returns a protocol or I/O error for malformed `VMess` packet framing.
    pub async fn recv(&mut self) -> Result<(Destination, Vec<u8>), VmessProtocolError> {
        self.responses.recv().await.unwrap_or_else(|| {
            Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "VMess UDP response loop ended",
            )
            .into())
        })
    }

    fn encode_xudp_frame(
        &mut self,
        destination: &Destination,
        payload: &[u8],
    ) -> Result<Vec<u8>, VmessProtocolError> {
        let payload_length = u16::try_from(payload.len()).map_err(|_| {
            VmessProtocolError::Protocol("XUDP payload exceeds 65535 bytes".to_owned())
        })?;
        let mut address = Vec::with_capacity(20);
        encode_vmess_address(&mut address, destination)?;
        let first = !self.xudp_request_written;
        let extension_length = if first { self.xudp_global_id.len() } else { 0 };
        let frame_header_length = 5_usize
            .checked_add(address.len())
            .and_then(|length| length.checked_add(extension_length))
            .ok_or_else(|| VmessProtocolError::Protocol("XUDP frame is too large".to_owned()))?;
        let frame_header_length = u16::try_from(frame_header_length)
            .map_err(|_| VmessProtocolError::Protocol("XUDP frame is too large".to_owned()))?;
        let mut frame =
            Vec::with_capacity(2 + usize::from(frame_header_length) + 2 + payload.len());
        frame.extend_from_slice(&frame_header_length.to_be_bytes());
        frame.extend_from_slice(&0_u16.to_be_bytes());
        frame.push(if first {
            XUDP_STATUS_NEW
        } else {
            XUDP_STATUS_KEEP
        });
        frame.push(XUDP_OPTION_DATA);
        frame.push(XUDP_NETWORK_UDP);
        frame.extend_from_slice(&address);
        if first {
            frame.extend_from_slice(&self.xudp_global_id);
            self.xudp_request_written = true;
        }
        frame.extend_from_slice(&payload_length.to_be_bytes());
        frame.extend_from_slice(payload);
        Ok(frame)
    }
}

impl VmessPacketReader {
    async fn recv(&mut self) -> Result<(Destination, Vec<u8>), VmessProtocolError> {
        self.ensure_response_header().await?;
        match self.mode {
            VmessPacketMode::Standard => {
                let payload = self.read_body_record().await?;
                Ok((self.fixed_destination.clone(), payload))
            }
            VmessPacketMode::PacketAddr => {
                let frame = self.read_body_record().await?;
                let (destination, consumed) = decode_packet_address(&frame)?;
                Ok((destination, frame[consumed..].to_vec()))
            }
            VmessPacketMode::Xudp => self.recv_xudp().await,
        }
    }

    async fn ensure_response_header(&mut self) -> Result<(), VmessProtocolError> {
        if self.response_header_read {
            return Ok(());
        }
        if self.legacy_header {
            self.body_reader
                .read_legacy_response_header(
                    &mut self.remote,
                    &self.response_key,
                    &self.response_iv,
                    self.response_verification,
                )
                .await?;
        } else {
            read_response_header(
                &mut self.remote,
                &self.response_key,
                &self.response_iv,
                self.response_verification,
            )
            .await?;
        }
        self.response_header_read = true;
        Ok(())
    }

    async fn read_body_record(&mut self) -> Result<Vec<u8>, VmessProtocolError> {
        self.body_reader
            .read_record(&mut self.remote)
            .await
            .map_err(VmessProtocolError::from)
    }

    async fn recv_xudp(&mut self) -> Result<(Destination, Vec<u8>), VmessProtocolError> {
        loop {
            let length = {
                let bytes = self.take_xudp_bytes(2).await?;
                usize::from(u16::from_be_bytes([bytes[0], bytes[1]]))
            };
            if length < 4 {
                return Err(VmessProtocolError::Protocol(
                    "invalid XUDP frame header length".to_owned(),
                ));
            }
            let header = self.take_xudp_bytes(length).await?;
            let status = header[2];
            let option = header[3];
            if option & XUDP_OPTION_ERROR != 0 {
                return Err(VmessProtocolError::Protocol(
                    "remote closed XUDP association".to_owned(),
                ));
            }
            match status {
                XUDP_STATUS_NEW => {
                    return Err(VmessProtocolError::Protocol(
                        "unexpected XUDP new response frame".to_owned(),
                    ));
                }
                XUDP_STATUS_END => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "XUDP association ended",
                    )
                    .into());
                }
                XUDP_STATUS_KEEP | XUDP_STATUS_KEEPALIVE => {}
                _ => {
                    return Err(VmessProtocolError::Protocol(
                        "invalid XUDP response status".to_owned(),
                    ));
                }
            }
            let destination = if length == 4 {
                self.fixed_destination.clone()
            } else {
                if header[4] != XUDP_NETWORK_UDP {
                    return Err(VmessProtocolError::Protocol(
                        "invalid XUDP response network".to_owned(),
                    ));
                }
                let (destination, consumed) = decode_vmess_address(&header[5..])?;
                if 5 + consumed != header.len() {
                    return Err(VmessProtocolError::Protocol(
                        "invalid XUDP response address length".to_owned(),
                    ));
                }
                destination
            };
            if option & XUDP_OPTION_DATA == 0 {
                continue;
            }
            let payload_length = {
                let bytes = self.take_xudp_bytes(2).await?;
                usize::from(u16::from_be_bytes([bytes[0], bytes[1]]))
            };
            let payload = self.take_xudp_bytes(payload_length).await?;
            return Ok((destination, payload));
        }
    }

    async fn take_xudp_bytes(&mut self, length: usize) -> Result<Vec<u8>, VmessProtocolError> {
        while self.xudp_read_buffer.len() < length {
            let record = self.read_body_record().await?;
            if record.is_empty() {
                return Err(VmessProtocolError::Protocol(
                    "empty VMess body record in XUDP stream".to_owned(),
                ));
            }
            self.xudp_read_buffer.extend_from_slice(&record);
        }
        Ok(self.xudp_read_buffer.drain(..length).collect())
    }
}

/// Opens a `VMess` UDP association over an established outer transport.
///
/// # Errors
///
/// Returns an error when the `VMess` handshake or packet framing fails.
pub async fn associate_vmess_udp_on_stream(
    remote: BoxedStream,
    destination: &Destination,
    options: VmessClientOptions,
    mode: VmessPacketMode,
) -> Result<VmessUdpAssociation, VmessProtocolError> {
    let (command, header_destination, chunked_none) = match mode {
        VmessPacketMode::Standard => (VmessCommand::Udp, destination.clone(), true),
        VmessPacketMode::PacketAddr => (
            VmessCommand::Udp,
            Destination {
                host: Host::Domain("sp.packet-addr.v2fly.arpa".to_owned()),
                port: 443,
            },
            true,
        ),
        VmessPacketMode::Xudp => (
            VmessCommand::Mux,
            Destination {
                host: Host::Domain("v1.mux.cool".to_owned()),
                port: 666,
            },
            false,
        ),
    };
    let transport =
        connect_protocol_on_stream(remote, &header_destination, options, command, chunked_none)
            .await?;
    let mut xudp_global_id = [0_u8; 8];
    rand::rng().fill(&mut xudp_global_id);
    let ConnectedVmess {
        remote,
        body_reader,
        body_writer,
        response_key,
        response_iv,
        response_verification,
        legacy_header,
        response_header_read,
    } = transport;
    let (remote_read, remote_write) = tokio::io::split(remote);
    let mut reader = VmessPacketReader {
        remote: remote_read,
        body_reader,
        response_key,
        response_iv,
        response_verification,
        legacy_header,
        response_header_read,
        mode,
        fixed_destination: destination.clone(),
        xudp_read_buffer: Vec::new(),
    };
    let (response_sender, responses) = mpsc::channel(32);
    let cancellation = CancellationToken::new();
    let read_cancellation = cancellation.clone();
    tokio::spawn(async move {
        loop {
            let response = tokio::select! {
                () = read_cancellation.cancelled() => break,
                response = reader.recv() => response,
            };
            let failed = response.is_err();
            if response_sender.send(response).await.is_err() || failed {
                break;
            }
        }
    });
    Ok(VmessUdpAssociation {
        remote: remote_write,
        body_writer,
        mode,
        fixed_destination: destination.clone(),
        xudp_global_id,
        xudp_request_written: false,
        responses,
        cancellation,
    })
}

fn encode_packet_address(
    output: &mut Vec<u8>,
    destination: &Destination,
) -> Result<(), VmessProtocolError> {
    match destination.host {
        Host::Ip(IpAddr::V4(address)) => {
            output.push(1);
            output.extend_from_slice(&address.octets());
        }
        Host::Ip(IpAddr::V6(address)) => {
            output.push(2);
            output.extend_from_slice(&address.octets());
        }
        Host::Domain(_) => {
            return Err(VmessProtocolError::Protocol(
                "packet-address mode requires a resolved IP destination".to_owned(),
            ));
        }
    }
    output.extend_from_slice(&destination.port.to_be_bytes());
    Ok(())
}

fn decode_packet_address(input: &[u8]) -> Result<(Destination, usize), VmessProtocolError> {
    let (host, address_length) = decode_ip_address(input, 1, 2)?;
    let port_offset = 1 + address_length;
    let port = read_u16(input, port_offset)?;
    Ok((Destination { host, port }, port_offset + 2))
}

fn encode_vmess_address(
    output: &mut Vec<u8>,
    destination: &Destination,
) -> Result<(), VmessProtocolError> {
    output.extend_from_slice(&destination.port.to_be_bytes());
    match &destination.host {
        Host::Ip(IpAddr::V4(address)) => {
            output.push(1);
            output.extend_from_slice(&address.octets());
        }
        Host::Domain(domain) => {
            let length = u8::try_from(domain.len()).map_err(|_| {
                VmessProtocolError::Protocol("XUDP domain exceeds 255 bytes".to_owned())
            })?;
            if length == 0 {
                return Err(VmessProtocolError::Protocol(
                    "XUDP destination domain is empty".to_owned(),
                ));
            }
            output.push(2);
            output.push(length);
            output.extend_from_slice(domain.as_bytes());
        }
        Host::Ip(IpAddr::V6(address)) => {
            output.push(3);
            output.extend_from_slice(&address.octets());
        }
    }
    Ok(())
}

fn decode_vmess_address(input: &[u8]) -> Result<(Destination, usize), VmessProtocolError> {
    let port = read_u16(input, 0)?;
    let address_type = *input
        .get(2)
        .ok_or_else(|| VmessProtocolError::Protocol("truncated XUDP address".to_owned()))?;
    let (host, consumed) = match address_type {
        1 => {
            let octets: [u8; 4] = input
                .get(3..7)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| VmessProtocolError::Protocol("truncated XUDP IPv4".to_owned()))?;
            (Host::Ip(Ipv4Addr::from(octets).into()), 7)
        }
        2 => {
            let length =
                usize::from(*input.get(3).ok_or_else(|| {
                    VmessProtocolError::Protocol("truncated XUDP domain".to_owned())
                })?);
            let end = 4 + length;
            let domain = input
                .get(4..end)
                .and_then(|bytes| std::str::from_utf8(bytes).ok())
                .filter(|domain| !domain.is_empty())
                .ok_or_else(|| VmessProtocolError::Protocol("invalid XUDP domain".to_owned()))?;
            (Host::Domain(domain.to_owned()), end)
        }
        3 => {
            let octets: [u8; 16] = input
                .get(3..19)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| VmessProtocolError::Protocol("truncated XUDP IPv6".to_owned()))?;
            (Host::Ip(Ipv6Addr::from(octets).into()), 19)
        }
        _ => {
            return Err(VmessProtocolError::Protocol(
                "invalid XUDP address type".to_owned(),
            ));
        }
    };
    Ok((Destination { host, port }, consumed))
}

fn decode_ip_address(
    input: &[u8],
    ipv4_type: u8,
    ipv6_type: u8,
) -> Result<(Host, usize), VmessProtocolError> {
    match input.first().copied() {
        Some(value) if value == ipv4_type => {
            let octets: [u8; 4] = input
                .get(1..5)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| {
                    VmessProtocolError::Protocol("truncated packet-address IPv4".to_owned())
                })?;
            Ok((Host::Ip(Ipv4Addr::from(octets).into()), 4))
        }
        Some(value) if value == ipv6_type => {
            let octets: [u8; 16] = input
                .get(1..17)
                .and_then(|bytes| bytes.try_into().ok())
                .ok_or_else(|| {
                    VmessProtocolError::Protocol("truncated packet-address IPv6".to_owned())
                })?;
            Ok((Host::Ip(Ipv6Addr::from(octets).into()), 16))
        }
        _ => Err(VmessProtocolError::Protocol(
            "invalid packet-address family".to_owned(),
        )),
    }
}

fn read_u16(input: &[u8], offset: usize) -> Result<u16, VmessProtocolError> {
    input
        .get(offset..offset + 2)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u16::from_be_bytes)
        .ok_or_else(|| VmessProtocolError::Protocol("truncated VMess packet frame".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_address_round_trips_ipv4_and_ipv6() {
        for destination in [
            Destination {
                host: Host::Ip("192.0.2.90".parse().unwrap()),
                port: 53,
            },
            Destination {
                host: Host::Ip("2001:db8::90".parse().unwrap()),
                port: 5353,
            },
        ] {
            let mut frame = Vec::new();
            encode_packet_address(&mut frame, &destination).unwrap();
            let (decoded, consumed) = decode_packet_address(&frame).unwrap();
            assert_eq!(decoded, destination);
            assert_eq!(consumed, frame.len());
        }
    }

    #[test]
    fn xudp_address_round_trips_all_families() {
        for destination in [
            Destination {
                host: Host::Ip("192.0.2.91".parse().unwrap()),
                port: 1001,
            },
            Destination {
                host: Host::Domain("xudp.phase6d".to_owned()),
                port: 1002,
            },
            Destination {
                host: Host::Ip("2001:db8::91".parse().unwrap()),
                port: 1003,
            },
        ] {
            let mut frame = Vec::new();
            encode_vmess_address(&mut frame, &destination).unwrap();
            let (decoded, consumed) = decode_vmess_address(&frame).unwrap();
            assert_eq!(decoded, destination);
            assert_eq!(consumed, frame.len());
        }
    }
}
