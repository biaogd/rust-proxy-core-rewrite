//! Hysteria2 TCP stream framing over a QUIC bidirectional stream.
//!
//! Fast-open (Go / rsteria2 default): write `TCPRequest` and return immediately.
//! Parse `TCPResponse` lazily on the first `poll_read`. Eager await of the
//! response before any application I/O deadlocks against some Go authorities.

use std::pin::Pin;
use std::task::{Context, Poll};

use rewrite_model::Destination;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::auth::random_padding;
use crate::varint;
use crate::{FRAME_TYPE_TCP_REQUEST, Hysteria2ProtocolError};

const MAX_MESSAGE_LENGTH: u64 = 2048;
const MAX_PADDING_LENGTH: u64 = 4096;

#[derive(Debug)]
enum TcpResponseParse {
    NeedMore,
    Done { ok: bool, consumed: usize },
    Invalid,
}

fn parse_tcp_response(buf: &[u8]) -> TcpResponseParse {
    let mut pos = 0_usize;
    let Some(&status) = buf.get(pos) else {
        return TcpResponseParse::NeedMore;
    };
    pos += 1;

    let Some((msg_len, n)) = varint::read_from(buf.get(pos..).unwrap_or_default()) else {
        return TcpResponseParse::NeedMore;
    };
    if msg_len > MAX_MESSAGE_LENGTH {
        return TcpResponseParse::Invalid;
    }
    pos += n;
    let msg_len = usize::try_from(msg_len).unwrap_or(usize::MAX);
    if buf.len() < pos.saturating_add(msg_len) {
        return TcpResponseParse::NeedMore;
    }
    pos += msg_len;

    let Some((pad_len, n)) = varint::read_from(buf.get(pos..).unwrap_or_default()) else {
        return TcpResponseParse::NeedMore;
    };
    if pad_len > MAX_PADDING_LENGTH {
        return TcpResponseParse::Invalid;
    }
    pos += n;
    let pad_len = usize::try_from(pad_len).unwrap_or(usize::MAX);
    if buf.len() < pos.saturating_add(pad_len) {
        return TcpResponseParse::NeedMore;
    }
    pos += pad_len;

    TcpResponseParse::Done {
        ok: status == 0,
        consumed: pos,
    }
}

/// Multiplexed TCP proxy stream after the Hysteria2 TCP request is written.
pub struct Hysteria2Stream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    write_closed: bool,
    response_done: bool,
    scratch: Vec<u8>,
    leftover: Vec<u8>,
    leftover_pos: usize,
}

impl Hysteria2Stream {
    /// Opens a QUIC bidi stream and writes the TCP request (fast-open).
    ///
    /// The server's TCP response is validated on the first read.
    pub(crate) async fn open(
        connection: &quinn::Connection,
        destination: &Destination,
    ) -> Result<Self, Hysteria2ProtocolError> {
        let (mut send, recv) = connection.open_bi().await?;
        let address = destination.authority();
        let padding = random_padding(64, 512);
        let mut frame = Vec::new();
        varint::write_into(&mut frame, FRAME_TYPE_TCP_REQUEST)?;
        varint::write_into(&mut frame, address.len() as u64)?;
        frame.extend_from_slice(address.as_bytes());
        varint::write_into(&mut frame, padding.len() as u64)?;
        frame.extend_from_slice(padding.as_bytes());
        send.write_all(&frame).await.map_err(|error| {
            Hysteria2ProtocolError::Io(std::io::Error::other(error.to_string()))
        })?;
        send.flush().await.map_err(|error| {
            Hysteria2ProtocolError::Io(std::io::Error::other(error.to_string()))
        })?;

        Ok(Self {
            send,
            recv,
            write_closed: false,
            response_done: false,
            scratch: Vec::new(),
            leftover: Vec::new(),
            leftover_pos: 0,
        })
    }

    fn poll_establish(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let me = &mut *self;
        while !me.response_done {
            match parse_tcp_response(&me.scratch) {
                TcpResponseParse::Done { ok, consumed } => {
                    if !ok {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::ConnectionRefused,
                            "hysteria2: server rejected tcp connect",
                        )));
                    }
                    me.leftover = me.scratch.split_off(consumed);
                    me.scratch.clear();
                    me.response_done = true;
                    break;
                }
                TcpResponseParse::Invalid => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "hysteria2: malformed TCPResponse",
                    )));
                }
                TcpResponseParse::NeedMore => {
                    let mut tmp = [0_u8; 512];
                    let mut rb = ReadBuf::new(&mut tmp);
                    match Pin::new(&mut me.recv).poll_read(cx, &mut rb) {
                        Poll::Ready(Ok(())) => {
                            let filled = rb.filled();
                            if filled.is_empty() {
                                return Poll::Ready(Err(std::io::Error::new(
                                    std::io::ErrorKind::UnexpectedEof,
                                    "hysteria2: stream closed before TCPResponse",
                                )));
                            }
                            me.scratch.extend_from_slice(filled);
                        }
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for Hysteria2Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if !self.response_done {
            match self.as_mut().poll_establish(context) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        let me = &mut *self;
        if me.leftover_pos < me.leftover.len() {
            let rest = &me.leftover[me.leftover_pos..];
            let n = rest.len().min(buffer.remaining());
            buffer.put_slice(&rest[..n]);
            me.leftover_pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut me.recv).poll_read(context, buffer)
    }
}

impl AsyncWrite for Hysteria2Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.write_closed {
            return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        }
        <quinn::SendStream as tokio::io::AsyncWrite>::poll_write(
            Pin::new(&mut self.send),
            context,
            buffer,
        )
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        <quinn::SendStream as tokio::io::AsyncWrite>::poll_flush(Pin::new(&mut self.send), context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.write_closed {
            return Poll::Ready(Ok(()));
        }
        match <quinn::SendStream as tokio::io::AsyncWrite>::poll_shutdown(
            Pin::new(&mut self.send),
            context,
        ) {
            Poll::Ready(Ok(())) => {
                self.write_closed = true;
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_ok_response() {
        // status=0, msg_len=0, pad_len=0
        let buf = [0_u8, 0, 0];
        match parse_tcp_response(&buf) {
            TcpResponseParse::Done {
                ok: true,
                consumed: 3,
            } => {}
            other => panic!("unexpected parse: {other:?}"),
        }
    }

    #[test]
    fn needs_more_when_truncated() {
        assert!(matches!(
            parse_tcp_response(&[0_u8]),
            TcpResponseParse::NeedMore
        ));
    }
}
