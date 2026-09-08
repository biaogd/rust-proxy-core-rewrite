//! `http_simple` / `http_post` obfs (SSR-B). Camouflage HTTP request wrapping only.

#![allow(clippy::cast_possible_truncation)]

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf as _, BytesMut};
use rewrite_io::BoxedStream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::crypto_util::random_u32_bounded;

const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.162 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 7.0; Moto C Build/NRD90M.059) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36",
];
const BOUNDARY_SET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

pub(crate) struct HttpObfsConn {
    inner: BoxedStream,
    host: String,
    port: u16,
    param: String,
    iv_size: usize,
    use_post: bool,
    has_sent_header: bool,
    has_recv_header: bool,
    recv_buf: BytesMut,
    pending_write: Vec<u8>,
    pending_offset: usize,
}

impl HttpObfsConn {
    pub(crate) fn new(
        inner: BoxedStream,
        host: String,
        port: u16,
        param: String,
        iv_size: usize,
        use_post: bool,
    ) -> Self {
        Self {
            inner,
            host,
            port,
            param,
            iv_size,
            use_post,
            has_sent_header: false,
            has_recv_header: false,
            recv_buf: BytesMut::new(),
            pending_write: Vec::new(),
            pending_offset: 0,
        }
    }

    fn pick_host(&self) -> (String, String) {
        let mut custom_body = String::new();
        let mut host = self.host.clone();
        if !self.param.is_empty() {
            if let Some((hosts, body)) = self.param.split_once('#') {
                host.clear();
                host.push_str(hosts);
                custom_body = body.replace("\\n", "\r\n").replace('\n', "\r\n");
            } else {
                host.clear();
                host.push_str(&self.param);
            }
        }
        let hosts: Vec<&str> = host.split(',').filter(|part| !part.is_empty()).collect();
        let chosen = if hosts.is_empty() {
            self.host.clone()
        } else {
            hosts[random_u32_bounded(hosts.len() as u32) as usize].to_owned()
        };
        (chosen, custom_body)
    }

    fn build_request(&self, first: &[u8]) -> Vec<u8> {
        let head_length = self.iv_size + 30;
        let mut head_data_length = first.len();
        if first.len().saturating_sub(head_length) > 64 {
            head_data_length = head_length + random_u32_bounded(65) as usize;
        }
        head_data_length = head_data_length.min(first.len());
        let head_data = &first[..head_data_length];
        let rest = &first[head_data_length..];

        let (host, custom_body) = self.pick_host();
        let mut buf = Vec::with_capacity(512 + first.len() * 3);
        if self.use_post {
            buf.extend_from_slice(b"POST /");
        } else {
            buf.extend_from_slice(b"GET /");
        }
        for byte in head_data {
            buf.push(b'%');
            let hex = format!("{byte:02x}");
            buf.extend_from_slice(hex.as_bytes());
        }
        buf.extend_from_slice(b" HTTP/1.1\r\nHost: ");
        buf.extend_from_slice(host.as_bytes());
        if self.port != 80 {
            buf.extend_from_slice(format!(":{}", self.port).as_bytes());
        }
        buf.extend_from_slice(b"\r\n");
        if custom_body.is_empty() {
            let ua = USER_AGENTS[random_u32_bounded(USER_AGENTS.len() as u32) as usize];
            buf.extend_from_slice(b"User-Agent: ");
            buf.extend_from_slice(ua.as_bytes());
            buf.extend_from_slice(
                b"\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.8\r\nAccept-Encoding: gzip, deflate\r\n",
            );
            if self.use_post {
                buf.extend_from_slice(b"Content-Type: multipart/form-data; boundary=");
                for _ in 0..32 {
                    buf.push(BOUNDARY_SET[random_u32_bounded(62) as usize]);
                }
                buf.extend_from_slice(b"\r\n");
            }
            buf.extend_from_slice(b"DNT: 1\r\nConnection: keep-alive\r\n\r\n");
        } else {
            buf.extend_from_slice(custom_body.as_bytes());
            buf.extend_from_slice(b"\r\n\r\n");
        }
        buf.extend_from_slice(rest);
        buf
    }

    fn poll_flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        while self.pending_offset < self.pending_write.len() {
            let slice = &self.pending_write[self.pending_offset..];
            match Pin::new(&mut self.inner).poll_write(cx, slice) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "http obfs write returned 0",
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
}

impl AsyncRead for HttpObfsConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Do not map header-only reads to AsyncRead EOF (Ready + 0 filled). Go's
        // `(0, nil)` after headers is "wait for body"; Tokio treats 0 as EOF.
        loop {
            if self.has_recv_header {
                if !self.recv_buf.is_empty() {
                    let n = buf.remaining().min(self.recv_buf.len());
                    buf.put_slice(&self.recv_buf[..n]);
                    self.recv_buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                return Pin::new(&mut self.inner).poll_read(cx, buf);
            }

            if let Some(pos) = self
                .recv_buf
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
            {
                self.has_recv_header = true;
                self.recv_buf.advance(pos + 4);
                // Headers alone: keep reading for encrypted payload instead of
                // returning Ready(Ok) with an empty ReadBuf.
                continue;
            }

            let mut scratch = [0_u8; 16 * 1024];
            let mut tmp = ReadBuf::new(&mut scratch);
            match Pin::new(&mut self.inner).poll_read(cx, &mut tmp) {
                Poll::Ready(Ok(())) => {
                    let filled = tmp.filled();
                    if filled.is_empty() {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "EOF before HTTP obfs response headers",
                        )));
                    }
                    if self.recv_buf.len() + filled.len() > 64 * 1024 {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "HTTP obfs response headers exceed 64KiB",
                        )));
                    }
                    self.recv_buf.extend_from_slice(filled);
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for HttpObfsConn {
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
        if this.has_sent_header {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        this.pending_write = this.build_request(buf);
        this.pending_offset = 0;
        this.has_sent_header = true;
        match this.poll_flush_pending(cx) {
            Poll::Ready(Ok(())) | Poll::Pending => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::poll_fn;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, duplex};

    #[tokio::test]
    async fn header_only_read_waits_for_payload_not_eof() {
        let (client, mut server) = duplex(4096);
        let mut conn = HttpObfsConn::new(
            Box::new(client),
            "example.com".into(),
            443,
            String::new(),
            16,
            false,
        );

        // Headers arrive first; encrypted payload arrives on a later read.
        server
            .write_all(b"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\n\r\n")
            .await
            .unwrap();
        server.flush().await.unwrap();

        let mut out = [0_u8; 16];
        let pending = poll_fn(|cx| {
            let mut buf = ReadBuf::new(&mut out);
            match Pin::new(&mut conn).poll_read(cx, &mut buf) {
                Poll::Ready(Ok(())) => {
                    // Must not report a 0-byte Ready (AsyncRead EOF).
                    assert!(
                        !buf.filled().is_empty(),
                        "header-only read must not return Ready with empty buffer"
                    );
                    Poll::Ready(Ok::<usize, ()>(buf.filled().len()))
                }
                Poll::Ready(Err(_)) => Poll::Ready(Err(())),
                Poll::Pending => Poll::Pending,
            }
        });
        // With only headers available, poll_read should Pending (or later yield
        // payload) — never Ready(Ok) with zero filled bytes.
        let first = tokio::time::timeout(std::time::Duration::from_millis(50), pending).await;
        assert!(
            first.is_err() || matches!(first, Ok(Ok(n)) if n > 0),
            "unexpected Ready empty success before payload"
        );

        server.write_all(b"ciphertext-iv-body").await.unwrap();
        server.flush().await.unwrap();
        let n = conn.read(&mut out).await.unwrap();
        assert!(n > 0);
        assert_eq!(&out[..n], &b"ciphertext-iv-body"[..n]);
    }

    #[tokio::test]
    async fn headers_then_payload_in_separate_reads() {
        let (client, mut server) = duplex(4096);
        let mut conn = HttpObfsConn::new(
            Box::new(client),
            "example.com".into(),
            80,
            String::new(),
            16,
            true,
        );
        server.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
        let read = tokio::spawn(async move {
            let mut buf = vec![0_u8; 32];
            let n = conn.read(&mut buf).await.unwrap();
            buf.truncate(n);
            buf
        });
        tokio::task::yield_now().await;
        server.write_all(b"payload-bytes").await.unwrap();
        let got = read.await.unwrap();
        assert_eq!(got, b"payload-bytes");
    }
}
