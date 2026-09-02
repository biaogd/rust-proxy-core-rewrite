use std::{
    io,
    net::IpAddr,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const SESSION_NEW: u8 = 0x01;
const SESSION_KEEP: u8 = 0x02;
const SESSION_END: u8 = 0x03;
const SESSION_KEEP_ALIVE: u8 = 0x04;

const OPTION_NONE: u8 = 0x00;
const OPTION_DATA: u8 = 0x01;

const MAX_METADATA_LEN: usize = 512;
const MAX_DATA_LEN: usize = u16::MAX as usize;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum V2rayMuxNetwork {
    #[default]
    Tcp,
    Udp,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct V2rayMuxOptions {
    pub id: [u8; 2],
    pub host: String,
    pub port: u16,
    pub network: V2rayMuxNetwork,
}

enum ReadState {
    MetadataLength { bytes: [u8; 2], filled: usize },
    Metadata { bytes: [u8; 4], filled: usize },
    DataLength { bytes: [u8; 2], filled: usize },
    Data { remaining: usize },
}

impl Default for ReadState {
    fn default() -> Self {
        Self::MetadataLength {
            bytes: [0; 2],
            filled: 0,
        }
    }
}

struct PendingWrite {
    frame: Vec<u8>,
    written: usize,
    accepted: usize,
}

/// A single-session v2ray-plugin mux stream.
///
/// This intentionally implements the limited framing used by Mihomo's Go
/// `transport/v2ray-plugin/mux.go`, rather than a general-purpose mux protocol.
/// The Go writer truncates a payload length to `u16` while still appending all
/// bytes when one `Write` exceeds 65,535 bytes, which corrupts the following
/// frame boundary. This implementation preserves valid wire behavior by
/// splitting such writes into multiple `Keep + Data` frames.
pub struct V2rayMux<S> {
    inner: S,
    id: [u8; 2],
    opening: Option<Vec<u8>>,
    read_state: ReadState,
    pending_write: Option<PendingWrite>,
    shutdown_frame: Option<PendingWrite>,
    end_sent: bool,
}

impl<S> V2rayMux<S> {
    /// Creates a mux wrapper and buffers its `New` frame until the first write.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] when the destination metadata
    /// cannot fit in the protocol's unsigned 16-bit metadata length.
    pub fn new(inner: S, options: &V2rayMuxOptions) -> io::Result<Self> {
        let opening = encode_opening(options)?;
        Ok(Self {
            inner,
            id: options.id,
            opening: Some(opening),
            read_state: ReadState::default(),
            pending_write: None,
            shutdown_frame: None,
            end_sent: false,
        })
    }

    #[must_use]
    pub fn into_inner(self) -> S {
        self.inner
    }
}

fn encode_opening(options: &V2rayMuxOptions) -> io::Result<Vec<u8>> {
    let mut frame = Vec::with_capacity(32 + options.host.len());
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&options.id);
    frame.extend_from_slice(&[SESSION_NEW, OPTION_NONE]);
    frame.push(match options.network {
        V2rayMuxNetwork::Tcp => 0x01,
        V2rayMuxNetwork::Udp => 0x02,
    });
    frame.extend_from_slice(&options.port.to_be_bytes());

    match options.host.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => {
            frame.push(0x01);
            frame.extend_from_slice(&address.octets());
        }
        Ok(IpAddr::V6(address)) => {
            frame.push(0x03);
            frame.extend_from_slice(&address.octets());
        }
        Err(_) => {
            frame.push(0x02);
            frame.extend_from_slice(options.host.as_bytes());
        }
    }

    let metadata_len = frame.len() - 2;
    let metadata_len = u16::try_from(metadata_len).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "v2ray mux opening metadata exceeds 65535 bytes",
        )
    })?;
    frame[..2].copy_from_slice(&metadata_len.to_be_bytes());
    Ok(frame)
}

fn append_data_frames(frame: &mut Vec<u8>, id: [u8; 2], payload: &[u8]) {
    for chunk in payload.chunks(MAX_DATA_LEN) {
        frame.extend_from_slice(&4_u16.to_be_bytes());
        frame.extend_from_slice(&id);
        frame.extend_from_slice(&[SESSION_KEEP, OPTION_DATA]);
        let chunk_len = u16::try_from(chunk.len()).expect("data chunks are limited to u16::MAX");
        frame.extend_from_slice(&chunk_len.to_be_bytes());
        frame.extend_from_slice(chunk);
    }
}

fn poll_fill<S: AsyncRead + Unpin>(
    inner: &mut S,
    cx: &mut Context<'_>,
    bytes: &mut [u8],
    filled: &mut usize,
) -> Poll<io::Result<()>> {
    while *filled < bytes.len() {
        let mut read_buf = ReadBuf::new(&mut bytes[*filled..]);
        match Pin::new(&mut *inner).poll_read(cx, &mut read_buf) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) if read_buf.filled().is_empty() => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "v2ray mux frame ended early",
                )));
            }
            Poll::Ready(Ok(())) => *filled += read_buf.filled().len(),
        }
    }
    Poll::Ready(Ok(()))
}

fn poll_pending_write<S: AsyncWrite + Unpin>(
    inner: &mut S,
    cx: &mut Context<'_>,
    pending: &mut PendingWrite,
) -> Poll<io::Result<usize>> {
    while pending.written < pending.frame.len() {
        match Pin::new(&mut *inner).poll_write(cx, &pending.frame[pending.written..]) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(0)) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write v2ray mux frame",
                )));
            }
            Poll::Ready(Ok(written)) => pending.written += written,
        }
    }
    Poll::Ready(Ok(pending.accepted))
}

impl<S: AsyncRead + Unpin> AsyncRead for V2rayMux<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        loop {
            let this = &mut *self;
            match &mut this.read_state {
                ReadState::MetadataLength { bytes, filled } => {
                    match poll_fill(&mut this.inner, cx, bytes, filled) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) => {}
                    }
                    let length = u16::from_be_bytes(*bytes) as usize;
                    if length > MAX_METADATA_LEN {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "invalid metalen",
                        )));
                    }
                    this.read_state = ReadState::Metadata {
                        // The Go oracle uses the length only as a 512-byte
                        // guard and then consumes the fixed ID/status fields.
                        bytes: [0; 4],
                        filled: 0,
                    };
                }
                ReadState::Metadata { bytes, filled } => {
                    match poll_fill(&mut this.inner, cx, bytes, filled) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) => {}
                    }
                    let opcode = bytes[2];
                    let option = bytes[3];
                    this.read_state = if opcode == SESSION_KEEP_ALIVE || option != OPTION_DATA {
                        ReadState::default()
                    } else {
                        ReadState::DataLength {
                            bytes: [0; 2],
                            filled: 0,
                        }
                    };
                }
                ReadState::DataLength { bytes, filled } => {
                    match poll_fill(&mut this.inner, cx, bytes, filled) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) => {}
                    }
                    let remaining = u16::from_be_bytes(*bytes) as usize;
                    this.read_state = if remaining == 0 {
                        ReadState::default()
                    } else {
                        ReadState::Data { remaining }
                    };
                }
                ReadState::Data { remaining } => {
                    let wanted = (*remaining).min(output.remaining());
                    let mut temporary = vec![0; wanted];
                    let mut input = ReadBuf::new(&mut temporary);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut input) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) if input.filled().is_empty() => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "v2ray mux data ended early",
                            )));
                        }
                        Poll::Ready(Ok(())) => {
                            let read = input.filled().len();
                            output.put_slice(input.filled());
                            *remaining -= read;
                            if *remaining == 0 {
                                this.read_state = ReadState::default();
                            }
                            return Poll::Ready(Ok(()));
                        }
                    }
                }
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for V2rayMux<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if this.pending_write.is_none() {
            if input.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let mut frame = this.opening.take().unwrap_or_default();
            append_data_frames(&mut frame, this.id, input);
            this.pending_write = Some(PendingWrite {
                frame,
                written: 0,
                accepted: input.len(),
            });
        }

        let result = poll_pending_write(
            &mut this.inner,
            cx,
            this.pending_write.as_mut().expect("pending write exists"),
        );
        if result.is_ready() {
            this.pending_write = None;
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if let Some(pending) = &mut this.pending_write {
            match poll_pending_write(&mut this.inner, cx, pending) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(_)) => this.pending_write = None,
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if let Some(pending) = &mut this.pending_write {
            match poll_pending_write(&mut this.inner, cx, pending) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(_)) => this.pending_write = None,
            }
        }

        if this.shutdown_frame.is_none() && !this.end_sent {
            this.shutdown_frame = Some(PendingWrite {
                frame: vec![0, 4, this.id[0], this.id[1], SESSION_END, OPTION_NONE],
                written: 0,
                accepted: 0,
            });
        }
        if let Some(shutdown_frame) = &mut this.shutdown_frame {
            match poll_pending_write(&mut this.inner, cx, shutdown_frame) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(_)) => {
                    this.shutdown_frame = None;
                    this.end_sent = true;
                }
            }
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    fn options(host: &str) -> V2rayMuxOptions {
        V2rayMuxOptions {
            id: [0x12, 0x34],
            host: host.to_owned(),
            port: 443,
            network: V2rayMuxNetwork::Tcp,
        }
    }

    #[test]
    fn opening_encodes_ip_families_and_udp_network() {
        let ipv4 = encode_opening(&options("192.0.2.1")).unwrap();
        assert_eq!(&ipv4[6..], &[0x01, 0x01, 0xbb, 0x01, 192, 0, 2, 1]);

        let mut ipv6_options = options("2001:db8::1");
        ipv6_options.network = V2rayMuxNetwork::Udp;
        let ipv6 = encode_opening(&ipv6_options).unwrap();
        assert_eq!(&ipv6[6..10], &[0x02, 0x01, 0xbb, 0x03]);
        assert_eq!(
            &ipv6[10..],
            &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );
    }

    #[test]
    fn opening_rejects_metadata_that_cannot_be_framed() {
        let error = encode_opening(&options(&"a".repeat(65_528))).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn first_write_combines_new_metadata_and_data() {
        let (client, mut peer) = tokio::io::duplex(256);
        let mut mux = V2rayMux::new(client, &options("example.com")).unwrap();

        mux.write_all(b"hello").await.unwrap();
        mux.flush().await.unwrap();

        let mut wire = vec![0; 2 + 2 + 2 + 1 + 2 + 1 + 11 + 2 + 2 + 2 + 2 + 5];
        peer.read_exact(&mut wire).await.unwrap();
        assert_eq!(u16::from_be_bytes([wire[0], wire[1]]) as usize, 19);
        assert_eq!(&wire[2..6], &[0x12, 0x34, SESSION_NEW, OPTION_NONE]);
        assert_eq!(&wire[6..10], &[0x01, 0x01, 0xbb, 0x02]);
        assert_eq!(&wire[10..21], b"example.com");
        assert_eq!(
            &wire[21..],
            &[
                0,
                4,
                0x12,
                0x34,
                SESSION_KEEP,
                OPTION_DATA,
                0,
                5,
                b'h',
                b'e',
                b'l',
                b'l',
                b'o'
            ]
        );
    }

    #[tokio::test]
    async fn reads_past_keepalive_and_non_data_frames() {
        let (client, mut peer) = tokio::io::duplex(256);
        let mut mux = V2rayMux::new(client, &options("127.0.0.1")).unwrap();
        peer.write_all(&[0, 4, 0x12, 0x34, SESSION_KEEP_ALIVE, OPTION_NONE])
            .await
            .unwrap();
        peer.write_all(&[0, 4, 0x12, 0x34, SESSION_END, OPTION_NONE])
            .await
            .unwrap();
        peer.write_all(&[
            0,
            4,
            0x12,
            0x34,
            SESSION_KEEP,
            OPTION_DATA,
            0,
            6,
            b'a',
            b'b',
            b'c',
            b'd',
            b'e',
            b'f',
        ])
        .await
        .unwrap();

        let mut first = [0; 2];
        mux.read_exact(&mut first).await.unwrap();
        let mut second = [0; 4];
        mux.read_exact(&mut second).await.unwrap();
        assert_eq!(&first, b"ab");
        assert_eq!(&second, b"cdef");
    }

    #[tokio::test]
    async fn rejects_metadata_larger_than_go_limit() {
        let (client, mut peer) = tokio::io::duplex(16);
        let mut mux = V2rayMux::new(client, &options("::1")).unwrap();
        peer.write_all(&513_u16.to_be_bytes()).await.unwrap();

        let error = mux.read_u8().await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(error.to_string(), "invalid metalen");
    }

    #[tokio::test]
    async fn splits_payloads_at_u16_boundary() {
        let (client, mut peer) = tokio::io::duplex(140_000);
        let mut mux = V2rayMux::new(client, &options("127.0.0.1")).unwrap();
        let payload = vec![0x5a; MAX_DATA_LEN + 7];
        mux.write_all(&payload).await.unwrap();
        mux.flush().await.unwrap();

        let opening_len = 2 + 2 + 2 + 1 + 2 + 1 + 4;
        let total_len = opening_len + 8 + MAX_DATA_LEN + 8 + 7;
        let mut wire = vec![0; total_len];
        peer.read_exact(&mut wire).await.unwrap();
        let first = opening_len;
        assert_eq!(
            &wire[first..first + 8],
            &[0, 4, 0x12, 0x34, 2, 1, 0xff, 0xff]
        );
        let second = first + 8 + MAX_DATA_LEN;
        assert_eq!(&wire[second..second + 8], &[0, 4, 0x12, 0x34, 2, 1, 0, 7]);
        assert!(wire[first + 8..second].iter().all(|byte| *byte == 0x5a));
        assert_eq!(&wire[second + 8..], &[0x5a; 7]);
    }

    #[tokio::test]
    async fn shutdown_sends_end_frame() {
        let (client, mut peer) = tokio::io::duplex(32);
        let mut mux = V2rayMux::new(client, &options("127.0.0.1")).unwrap();
        mux.shutdown().await.unwrap();

        let mut end = [0; 6];
        peer.read_exact(&mut end).await.unwrap();
        assert_eq!(end, [0, 4, 0x12, 0x34, SESSION_END, OPTION_NONE]);
        assert_eq!(
            peer.read_u8().await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }
}
