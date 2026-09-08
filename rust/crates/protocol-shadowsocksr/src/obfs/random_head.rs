//! `random_head` obfs (SSR-C).

#![allow(clippy::cast_possible_truncation)]

use std::pin::Pin;
use std::task::{Context, Poll};

use rewrite_io::BoxedStream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::crypto_util::{append_rand, crc32_ieee, random_u32_bounded};

/// Random leading bytes + inverted CRC32, then raw passthrough after first read.
pub(crate) struct RandomHeadConn {
    inner: BoxedStream,
    has_sent_header: bool,
    raw_trans_sent: bool,
    raw_trans_recv: bool,
    buf: Vec<u8>,
    pending_write: Vec<u8>,
    pending_offset: usize,
}

impl RandomHeadConn {
    pub(crate) fn new(inner: BoxedStream) -> Self {
        Self {
            inner,
            has_sent_header: false,
            raw_trans_sent: false,
            raw_trans_recv: false,
            buf: Vec::new(),
            pending_write: Vec::new(),
            pending_offset: 0,
        }
    }

    fn build_header() -> Vec<u8> {
        let data_length = random_u32_bounded(96) as usize + 4;
        let mut buf = Vec::with_capacity(data_length + 4);
        append_rand(&mut buf, data_length);
        let crc = 0xffff_ffff_u32.wrapping_sub(crc32_ieee(&buf));
        buf.extend_from_slice(&crc.to_le_bytes());
        buf
    }

    fn poll_flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        while self.pending_offset < self.pending_write.len() {
            let slice = &self.pending_write[self.pending_offset..];
            match Pin::new(&mut self.inner).poll_write(cx, slice) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "random_head write returned 0",
                    )));
                }
                Poll::Ready(Ok(n)) => self.pending_offset += n,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.pending_write.clear();
        self.pending_offset = 0;
        Poll::Ready(Ok(()))
    }

    fn queue_buffered_payload(&mut self) {
        if !self.buf.is_empty() {
            self.pending_write = std::mem::take(&mut self.buf);
            self.pending_offset = 0;
        }
        self.raw_trans_sent = true;
    }
}

impl AsyncRead for RandomHeadConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.as_mut().get_mut();
        if !this.raw_trans_recv {
            let mut scratch = [0_u8; 16 * 1024];
            let mut tmp = ReadBuf::new(&mut scratch);
            match Pin::new(&mut this.inner).poll_read(cx, &mut tmp) {
                Poll::Ready(Ok(())) => {
                    // Discard the server's first response (Go returns n=0 after one Read).
                    let _ = tmp.filled();
                    this.raw_trans_recv = true;
                    this.queue_buffered_payload();
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }

        match this.poll_flush_pending(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }

        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for RandomHeadConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let this = self.as_mut().get_mut();
        match this.poll_flush_pending(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }

        if this.raw_trans_sent {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }

        this.buf.extend_from_slice(buf);

        if !this.has_sent_header {
            this.has_sent_header = true;
            this.pending_write = Self::build_header();
            this.pending_offset = 0;
            match this.poll_flush_pending(cx) {
                Poll::Ready(Ok(())) | Poll::Pending => return Poll::Ready(Ok(buf.len())),
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            }
        }

        if this.raw_trans_recv {
            this.queue_buffered_payload();
            match this.poll_flush_pending(cx) {
                Poll::Ready(Ok(())) | Poll::Pending => Poll::Ready(Ok(buf.len())),
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            }
        } else {
            Poll::Ready(Ok(buf.len()))
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let this = self.as_mut().get_mut();
        match this.poll_flush_pending(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let this = self.as_mut().get_mut();
        match this.poll_flush_pending(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_shutdown(cx),
            other => other,
        }
    }
}
