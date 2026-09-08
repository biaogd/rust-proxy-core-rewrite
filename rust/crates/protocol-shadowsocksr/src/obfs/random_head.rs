//! `random_head` obfs (SSR-C).

#![allow(clippy::cast_possible_truncation)]

use std::pin::Pin;
use std::task::{Context, Poll};

use rewrite_io::BoxedStream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::crypto_util::{append_rand, crc32_ieee, random_u32_bounded};
use crate::obfs::limits::{
    HandshakeDeadlineSlot, PRE_HANDSHAKE_BUF_MAX, arm_handshake_deadline, buffer_cap_error,
    clear_handshake_deadline, drop_on_shutdown_error, poll_handshake_deadline,
};

/// Random leading bytes + inverted CRC32, then raw passthrough after first read.
pub(crate) struct RandomHeadConn {
    inner: BoxedStream,
    has_sent_header: bool,
    raw_trans_sent: bool,
    raw_trans_recv: bool,
    buf: Vec<u8>,
    pending_write: Vec<u8>,
    pending_offset: usize,
    handshake_deadline: HandshakeDeadlineSlot,
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
            handshake_deadline: None,
        }
    }

    fn handshake_complete(&self) -> bool {
        self.raw_trans_recv && self.raw_trans_sent && self.buf.is_empty()
    }

    fn check_deadline(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        let complete = self.handshake_complete();
        poll_handshake_deadline(&mut self.handshake_deadline, complete, cx, "random_head")
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
        match this.check_deadline(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }

        if !this.raw_trans_recv {
            let mut scratch = [0_u8; 16 * 1024];
            let mut tmp = ReadBuf::new(&mut scratch);
            match Pin::new(&mut this.inner).poll_read(cx, &mut tmp) {
                Poll::Ready(Ok(())) => {
                    // Discard the server's first response (Go returns n=0 after one Read).
                    let _ = tmp.filled();
                    this.raw_trans_recv = true;
                    this.queue_buffered_payload();
                    clear_handshake_deadline(&mut this.handshake_deadline);
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
        match this.check_deadline(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        match this.poll_flush_pending(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }

        if this.raw_trans_sent {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }

        arm_handshake_deadline(&mut this.handshake_deadline);
        if this.buf.len() >= PRE_HANDSHAKE_BUF_MAX {
            // Backpressure without self-wake (deadline Sleep wakes mute peers).
            return Poll::Pending;
        }
        let accept = buf.len().min(PRE_HANDSHAKE_BUF_MAX - this.buf.len());
        if accept == 0 {
            return Poll::Ready(Err(buffer_cap_error("random_head")));
        }
        this.buf.extend_from_slice(&buf[..accept]);

        if !this.has_sent_header {
            this.has_sent_header = true;
            this.pending_write = Self::build_header();
            this.pending_offset = 0;
            match this.poll_flush_pending(cx) {
                Poll::Ready(Ok(())) | Poll::Pending => return Poll::Ready(Ok(accept)),
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            }
        }

        if this.raw_trans_recv {
            this.queue_buffered_payload();
            match this.poll_flush_pending(cx) {
                Poll::Ready(Ok(())) | Poll::Pending => Poll::Ready(Ok(accept)),
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            }
        } else {
            Poll::Ready(Ok(accept))
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let this = self.as_mut().get_mut();
        match this.check_deadline(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
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
            Poll::Ready(Ok(())) => {
                if !this.buf.is_empty() {
                    return Poll::Ready(Err(drop_on_shutdown_error("random_head")));
                }
                Pin::new(&mut this.inner).poll_shutdown(cx)
            }
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::poll_fn;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, duplex};

    #[tokio::test]
    async fn shutdown_before_handshake_errors_instead_of_dropping_payload() {
        let (client, mut server) = duplex(4096);
        let mut conn = RandomHeadConn::new(Box::new(client));
        let payload = vec![0x5a_u8; 2048];
        conn.write_all(&payload).await.unwrap();
        // Header reached the peer; application payload is still buffered.
        let mut header = vec![0_u8; 256];
        let n = server.read(&mut header).await.unwrap();
        assert!(n > 0);
        let err = conn.shutdown().await.expect_err("must not silent-drop");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("drop pre-handshake payload"));
    }

    #[tokio::test]
    async fn handshake_then_payload_reaches_server_before_shutdown() {
        let (client, mut server) = duplex(8192);
        let mut conn = RandomHeadConn::new(Box::new(client));
        let payload = b"post-handshake-payload".to_vec();
        conn.write_all(&payload).await.unwrap();
        let mut header = vec![0_u8; 256];
        assert!(server.read(&mut header).await.unwrap() > 0);
        // Complete camouflage, then drive client until buffered payload flushes.
        server.write_all(&[0x00]).await.unwrap();
        let mut sink = [0_u8; 32];
        tokio::time::timeout(
            Duration::from_secs(1),
            poll_fn(|cx| {
                if conn.raw_trans_recv && conn.buf.is_empty() && conn.pending_write.is_empty() {
                    return Poll::Ready(());
                }
                let mut buf = ReadBuf::new(&mut sink);
                match Pin::new(&mut conn).poll_read(cx, &mut buf) {
                    Poll::Pending => {
                        if conn.raw_trans_recv
                            && conn.buf.is_empty()
                            && conn.pending_write.is_empty()
                        {
                            Poll::Ready(())
                        } else {
                            Poll::Pending
                        }
                    }
                    Poll::Ready(Ok(())) => {
                        if conn.raw_trans_recv
                            && conn.buf.is_empty()
                            && conn.pending_write.is_empty()
                        {
                            Poll::Ready(())
                        } else {
                            cx.waker().wake_by_ref();
                            Poll::Pending
                        }
                    }
                    Poll::Ready(Err(error)) => panic!("{error}"),
                }
            }),
        )
        .await
        .expect("drive handshake + flush");
        let mut got = vec![0_u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(1), server.read(&mut got))
            .await
            .expect("payload read")
            .unwrap();
        got.truncate(n);
        assert_eq!(got, payload);
        conn.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn pre_handshake_buffer_applies_backpressure_then_times_out() {
        // Large duplex so the camouflage header can flush; otherwise writes Pending
        // until the handshake Sleep fires.
        let (client, _server) = duplex(PRE_HANDSHAKE_BUF_MAX + 1024);
        let mut conn = RandomHeadConn::new(Box::new(client));
        let chunk = vec![0x11_u8; 16 * 1024];
        let mut accepted = 0_usize;
        loop {
            let step = poll_fn(|cx| match Pin::new(&mut conn).poll_write(cx, &chunk) {
                Poll::Pending => Poll::Ready(None),
                Poll::Ready(outcome) => Poll::Ready(Some(outcome)),
            })
            .await;
            match step {
                None => break,
                Some(Ok(n)) => {
                    accepted += n;
                    if accepted >= PRE_HANDSHAKE_BUF_MAX {
                        break;
                    }
                }
                Some(Err(error)) => panic!("unexpected write error before cap: {error}"),
            }
        }
        assert!(accepted > 0);
        assert!(conn.buf.len() <= PRE_HANDSHAKE_BUF_MAX);
        assert!(
            poll_fn(|cx| {
                let ready = Pin::new(&mut conn).poll_write(cx, &chunk);
                Poll::Ready(matches!(ready, Poll::Pending))
            })
            .await
        );

        crate::obfs::limits::force_deadline_elapsed(&mut conn.handshake_deadline);
        let err = poll_fn(|cx| Pin::new(&mut conn).poll_write(cx, &chunk))
            .await
            .expect_err("deadline");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    }
}
