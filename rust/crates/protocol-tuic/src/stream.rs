//! TUIC v5 TCP relay over a QUIC bidirectional stream.

use std::pin::Pin;
use std::task::{Context, Poll};

use rewrite_model::Destination;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::TuicProtocolError;
use crate::protocol::encode_connect;

/// Proxied TCP byte stream after the Connect command is written.
pub struct TuicStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    write_closed: bool,
}

impl TuicStream {
    pub(crate) async fn open(
        connection: &quinn::Connection,
        destination: &Destination,
    ) -> Result<Self, TuicProtocolError> {
        let (mut send, recv) = connection.open_bi().await?;
        let header = encode_connect(destination)?;
        send.write_all(&header)
            .await
            .map_err(|error| TuicProtocolError::Io(std::io::Error::other(error.to_string())))?;
        send.flush()
            .await
            .map_err(|error| TuicProtocolError::Io(std::io::Error::other(error.to_string())))?;
        Ok(Self {
            send,
            recv,
            write_closed: false,
        })
    }
}

impl AsyncRead for TuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(context, buf)
    }
}

impl AsyncWrite for TuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        if self.write_closed {
            return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        }
        <quinn::SendStream as AsyncWrite>::poll_write(Pin::new(&mut self.send), context, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        <quinn::SendStream as AsyncWrite>::poll_flush(Pin::new(&mut self.send), context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.write_closed {
            return Poll::Ready(Ok(()));
        }
        match <quinn::SendStream as AsyncWrite>::poll_shutdown(Pin::new(&mut self.send), context) {
            Poll::Ready(Ok(())) => {
                self.write_closed = true;
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}
