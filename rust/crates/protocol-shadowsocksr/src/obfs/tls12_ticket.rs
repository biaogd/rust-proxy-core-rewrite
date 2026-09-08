//! `tls1.2_ticket_auth` / `tls1.2_ticket_fastauth` obfs (SSR-B).
//!
//! TLS **camouflage / appearance only** — forged ClientHello / CCS / application_data
//! records. This is not real TLS and does not use rustls.

#![allow(clippy::cast_possible_truncation)]

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf as _, BytesMut};
use rewrite_io::BoxedStream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::crypto_util::{append_rand, hmac_sha1, random_u32_bounded, unix_timestamp};

pub(crate) struct Tls12TicketConn {
    inner: BoxedStream,
    host: String,
    param: String,
    key: Vec<u8>,
    client_id: [u8; 32],
    handshake_status: u8,
    decoded: BytesMut,
    under_decoded: BytesMut,
    send_buf: Vec<u8>,
    pending_write: Vec<u8>,
    pending_offset: usize,
}

impl Tls12TicketConn {
    pub(crate) fn new(inner: BoxedStream, host: String, param: String, key: Vec<u8>) -> Self {
        let mut client_id = [0_u8; 32];
        rand::fill(&mut client_id);
        Self {
            inner,
            host,
            param,
            key,
            client_id,
            handshake_status: 0,
            decoded: BytesMut::new(),
            under_decoded: BytesMut::new(),
            send_buf: Vec::new(),
            pending_write: Vec::new(),
            pending_offset: 0,
        }
    }

    fn hmac(&self, data: &[u8]) -> [u8; 10] {
        let mut key = self.key.clone();
        key.extend_from_slice(&self.client_id);
        let full = hmac_sha1(&key, data);
        let mut out = [0_u8; 10];
        out.copy_from_slice(&full[..10]);
        out
    }

    fn get_host(&self) -> String {
        let mut host = if self.param.is_empty() {
            self.host.clone()
        } else {
            self.param.clone()
        };
        if let Some(last) = host.chars().last()
            && last.is_ascii_digit()
        {
            host.clear();
        }
        let hosts: Vec<&str> = host.split(',').collect();
        if hosts.is_empty() || (hosts.len() == 1 && hosts[0].is_empty()) {
            return String::new();
        }
        hosts[random_u32_bounded(hosts.len() as u32) as usize].to_owned()
    }

    fn pack_data(buf: &mut Vec<u8>, data: &[u8]) {
        buf.extend_from_slice(&[0x17, 0x03, 0x03]);
        buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
        buf.extend_from_slice(data);
    }

    fn pack_auth_data(&self, buf: &mut Vec<u8>) {
        let start = buf.len();
        buf.extend_from_slice(&unix_timestamp().to_be_bytes());
        append_rand(buf, 18);
        let mac = self.hmac(&buf[start..]);
        buf.extend_from_slice(&mac);
    }

    fn pack_sni(buf: &mut Vec<u8>, host: &str) {
        let len = host.len() as u16;
        buf.extend_from_slice(&[0, 0]);
        buf.extend_from_slice(&(len + 5).to_be_bytes());
        buf.extend_from_slice(&(len + 3).to_be_bytes());
        buf.push(0);
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(host.as_bytes());
    }

    fn pack_ticket(buf: &mut Vec<u8>) {
        let length = 16 * (random_u32_bounded(17) as usize + 8);
        buf.extend_from_slice(&[0, 0x23]);
        buf.extend_from_slice(&(length as u16).to_be_bytes());
        append_rand(buf, length);
    }

    fn build_client_hello(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(512);
        data.extend_from_slice(&[0x03, 0x03]);
        self.pack_auth_data(&mut data);
        data.push(0x20);
        data.extend_from_slice(&self.client_id);
        data.extend_from_slice(&[
            0x00, 0x1c, 0xc0, 0x2b, 0xc0, 0x2f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0x14, 0xcc, 0x13,
            0xc0, 0x0a, 0xc0, 0x14, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x9c, 0x00, 0x35, 0x00, 0x2f,
            0x00, 0x0a,
        ]);
        data.extend_from_slice(&[0x01, 0x00]);

        let mut ext = Vec::new();
        let host = self.get_host();
        ext.extend_from_slice(&[0xff, 0x01, 0x00, 0x01, 0x00]);
        Self::pack_sni(&mut ext, &host);
        ext.extend_from_slice(&[0, 0x17, 0, 0]);
        Self::pack_ticket(&mut ext);
        ext.extend_from_slice(&[
            0x00, 0x0d, 0x00, 0x16, 0x00, 0x14, 0x06, 0x01, 0x06, 0x03, 0x05, 0x01, 0x05, 0x03,
            0x04, 0x01, 0x04, 0x03, 0x03, 0x01, 0x03, 0x03, 0x02, 0x01, 0x02, 0x03,
        ]);
        ext.extend_from_slice(&[0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00]);
        ext.extend_from_slice(&[0x00, 0x12, 0x00, 0x00]);
        ext.extend_from_slice(&[0x75, 0x50, 0x00, 0x00]);
        ext.extend_from_slice(&[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]);
        ext.extend_from_slice(&[0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x17, 0x00, 0x18]);

        data.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        data.extend_from_slice(&ext);

        let mut ret = Vec::with_capacity(data.len() + 9);
        ret.extend_from_slice(&[0x16, 0x03, 0x01]);
        ret.extend_from_slice(&((data.len() + 4) as u16).to_be_bytes());
        ret.extend_from_slice(&[0x01, 0x00]);
        ret.extend_from_slice(&(data.len() as u16).to_be_bytes());
        ret.extend_from_slice(&data);
        ret
    }

    fn build_finish_flight(&mut self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[
            0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0x16, 0x03, 0x03, 0x00, 0x20,
        ]);
        append_rand(&mut buf, 22);
        let mac = self.hmac(&buf);
        buf.extend_from_slice(&mac);
        buf.append(&mut self.send_buf);
        self.handshake_status = 8;
        buf
    }

    fn frame_app_data(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len() + 16);
        let mut rest = data;
        while rest.len() > 2048 {
            let mut size = random_u32_bounded(4096) as usize + 100;
            if rest.len() < size {
                size = rest.len();
            }
            Self::pack_data(&mut out, &rest[..size]);
            rest = &rest[size..];
        }
        if !rest.is_empty() {
            Self::pack_data(&mut out, rest);
        }
        out
    }

    fn poll_flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        while self.pending_offset < self.pending_write.len() {
            let slice = &self.pending_write[self.pending_offset..];
            match Pin::new(&mut self.inner).poll_write(cx, slice) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "tls1.2_ticket camouflage write returned 0",
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

    fn decode_records(&mut self) {
        while self.under_decoded.len() > 5 {
            if self.under_decoded[..3] != [0x17, 0x03, 0x03] {
                self.under_decoded.clear();
                return;
            }
            let size = u16::from_be_bytes([self.under_decoded[3], self.under_decoded[4]]) as usize;
            if self.under_decoded.len() < 5 + size {
                break;
            }
            self.under_decoded.advance(5);
            let payload = self.under_decoded.split_to(size);
            self.decoded.extend_from_slice(&payload);
        }
    }
}

impl AsyncRead for Tls12TicketConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if !self.decoded.is_empty() {
            let n = buf.remaining().min(self.decoded.len());
            buf.put_slice(&self.decoded[..n]);
            self.decoded.advance(n);
            return Poll::Ready(Ok(()));
        }

        let mut scratch = [0_u8; 16 * 1024];
        let mut tmp = ReadBuf::new(&mut scratch);
        match Pin::new(&mut self.inner).poll_read(cx, &mut tmp) {
            Poll::Ready(Ok(())) => {
                let filled = tmp.filled();
                if filled.is_empty() {
                    return Poll::Ready(Ok(()));
                }
                if self.handshake_status == 8 {
                    self.under_decoded.extend_from_slice(filled);
                    self.decode_records();
                    if self.decoded.is_empty() {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    let n = buf.remaining().min(self.decoded.len());
                    buf.put_slice(&self.decoded[..n]);
                    self.decoded.advance(n);
                    return Poll::Ready(Ok(()));
                }

                if filled.len() < 11 + 32 + 1 + 32 {
                    return Poll::Ready(Err(std::io::Error::other(
                        "tls1.2_ticket camouflage handshake too short",
                    )));
                }
                let mac1 = self.hmac(&filled[11..33]);
                let mac2 = self.hmac(&filled[..filled.len() - 10]);
                if mac1 != filled[33..43] || mac2.as_slice() != &filled[filled.len() - 10..] {
                    return Poll::Ready(Err(std::io::Error::other(
                        "tls1.2_ticket camouflage HMAC mismatch",
                    )));
                }
                // Finish handshake (CCS + Finished + queued app data).
                match self.poll_flush_pending(cx) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                }
                self.pending_write = self.build_finish_flight();
                self.pending_offset = 0;
                match self.poll_flush_pending(cx) {
                    Poll::Ready(Ok(())) | Poll::Pending => {
                        // No application data yet from this handshake reply.
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                }
            }
            other => other,
        }
    }
}

impl AsyncWrite for Tls12TicketConn {
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

        if this.handshake_status == 8 {
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            this.pending_write = Self::frame_app_data(buf);
            this.pending_offset = 0;
            return match this.poll_flush_pending(cx) {
                Poll::Ready(Ok(())) | Poll::Pending => Poll::Ready(Ok(buf.len())),
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            };
        }

        if !buf.is_empty() {
            // TLS record length is u16 — never pack a single record over 65535.
            // Bidirectional copy may Write large payloads before the server
            // handshake reply is Read (status still 1); queue framed chunks.
            this.send_buf.extend_from_slice(&Self::frame_app_data(buf));
        }

        if this.handshake_status == 0 {
            this.handshake_status = 1;
            this.pending_write = this.build_client_hello();
            this.pending_offset = 0;
            return match this.poll_flush_pending(cx) {
                Poll::Ready(Ok(())) | Poll::Pending => Poll::Ready(Ok(buf.len())),
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            };
        }

        Poll::Ready(Ok(buf.len()))
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
