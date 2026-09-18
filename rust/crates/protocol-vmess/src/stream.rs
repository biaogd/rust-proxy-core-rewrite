//! In-place `VMess` TCP body stream (no duplex + spawn relay).

use std::pin::Pin;
use std::task::{Context, Poll};

use aes_gcm::aead::{Aead as _, KeyInit as _};
use aes_gcm::{Aes128Gcm, Nonce};
use cfb_mode::cipher::KeyIvInit as _;
use rewrite_io::BoxedStream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::body::{BodyReader, BodyWriter, PendingRecordRead};
use crate::header::seal_response_header;
use crate::kdf::{derive_12, derive_16};

/// Plaintext `VMess` TCP session over an encrypted body carrier.
pub struct VmessTcpStream {
    remote: BoxedStream,
    body_reader: BodyReader,
    body_writer: BodyWriter,
    read_pending: PendingRecordRead,
    plaintext: Vec<u8>,
    plaintext_offset: usize,
    write_buf: Vec<u8>,
    write_offset: usize,
    /// Bytes of plaintext already encoded into `write_buf` awaiting flush completion.
    accepted_plain: Option<usize>,
    /// Server: AEAD response header written before the first body record.
    write_prelude: Option<Vec<u8>>,
    response_header: ResponseHeaderRead,
}

enum ResponseHeaderRead {
    NotNeeded,
    Done,
    AeadLength {
        buf: [u8; 18],
        filled: usize,
        response_key: [u8; 16],
        response_iv: [u8; 16],
        response_verification: u8,
    },
    AeadHeader {
        buf: Vec<u8>,
        filled: usize,
        response_key: [u8; 16],
        response_iv: [u8; 16],
        response_verification: u8,
    },
    LegacyHeader {
        buf: [u8; 4],
        filled: usize,
        response_key: [u8; 16],
        response_iv: [u8; 16],
        response_verification: u8,
    },
    LegacyCommand {
        buf: Vec<u8>,
        filled: usize,
    },
}

impl VmessTcpStream {
    /// Client TCP body stream after the request header has been written.
    #[must_use]
    pub(crate) fn client(
        remote: BoxedStream,
        body_reader: BodyReader,
        body_writer: BodyWriter,
        response_key: [u8; 16],
        response_iv: [u8; 16],
        response_verification: u8,
        legacy_header: bool,
    ) -> Self {
        let response_header = if legacy_header {
            ResponseHeaderRead::LegacyHeader {
                buf: [0; 4],
                filled: 0,
                response_key,
                response_iv,
                response_verification,
            }
        } else {
            ResponseHeaderRead::AeadLength {
                buf: [0; 18],
                filled: 0,
                response_key,
                response_iv,
                response_verification,
            }
        };
        Self {
            remote,
            body_reader,
            body_writer,
            read_pending: PendingRecordRead::Idle,
            plaintext: Vec::new(),
            plaintext_offset: 0,
            write_buf: Vec::new(),
            write_offset: 0,
            accepted_plain: None,
            write_prelude: None,
            response_header,
        }
    }

    /// Server TCP body stream; seals the response header on first write.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn server(
        remote: BoxedStream,
        body_reader: BodyReader,
        body_writer: BodyWriter,
        response_key: [u8; 16],
        response_iv: [u8; 16],
        response_verification: u8,
        request_options: u8,
        response_header_written: bool,
    ) -> Self {
        let write_prelude = if response_header_written {
            None
        } else {
            Some(
                seal_response_header(
                    &response_key,
                    &response_iv,
                    response_verification,
                    request_options,
                )
                .expect("VMess AEAD response header seal"),
            )
        };
        Self {
            remote,
            body_reader,
            body_writer,
            read_pending: PendingRecordRead::Idle,
            plaintext: Vec::new(),
            plaintext_offset: 0,
            write_buf: Vec::new(),
            write_offset: 0,
            accepted_plain: None,
            write_prelude,
            response_header: ResponseHeaderRead::NotNeeded,
        }
    }

    fn poll_flush_write_buf(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        while self.write_offset < self.write_buf.len() {
            let offset = self.write_offset;
            match Pin::new(&mut self.remote).poll_write(cx, &self.write_buf[offset..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::from(std::io::ErrorKind::WriteZero)));
                }
                Poll::Ready(Ok(written)) => self.write_offset += written,
            }
        }
        self.write_buf.clear();
        self.write_offset = 0;
        Poll::Ready(Ok(()))
    }

    #[allow(clippy::too_many_lines)]
    fn poll_response_header(&mut self, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        loop {
            match &mut self.response_header {
                ResponseHeaderRead::NotNeeded | ResponseHeaderRead::Done => {
                    return Poll::Ready(Ok(()));
                }
                ResponseHeaderRead::AeadLength {
                    buf,
                    filled,
                    response_key,
                    response_iv,
                    response_verification,
                } => {
                    match poll_fill_exact(cx, &mut self.remote, buf, filled) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) => {}
                    }
                    let response_key = *response_key;
                    let response_iv = *response_iv;
                    let response_verification = *response_verification;
                    let encrypted_length = *buf;
                    let length_key = derive_16(&response_key, &[b"AEAD Resp Header Len Key"]);
                    let length_iv = derive_12(&response_iv, &[b"AEAD Resp Header Len IV"]);
                    let length = Aes128Gcm::new_from_slice(&length_key)
                        .map_err(std::io::Error::other)?
                        .decrypt(Nonce::from_slice(&length_iv), encrypted_length.as_slice())
                        .map_err(|_| {
                            std::io::Error::other("VMess response length authentication failed")
                        })?;
                    let length = match length.as_slice() {
                        [high, low] => usize::from(u16::from_be_bytes([*high, *low])),
                        _ => {
                            return Poll::Ready(Err(std::io::Error::other(
                                "invalid VMess response header length",
                            )));
                        }
                    };
                    if !(4..=4096).contains(&length) {
                        return Poll::Ready(Err(std::io::Error::other(
                            "invalid VMess response header size",
                        )));
                    }
                    self.response_header = ResponseHeaderRead::AeadHeader {
                        buf: vec![0_u8; length + 16],
                        filled: 0,
                        response_key,
                        response_iv,
                        response_verification,
                    };
                }
                ResponseHeaderRead::AeadHeader {
                    buf,
                    filled,
                    response_key,
                    response_iv,
                    response_verification,
                } => {
                    match poll_fill_exact(cx, &mut self.remote, buf, filled) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) => {}
                    }
                    let response_key = *response_key;
                    let response_iv = *response_iv;
                    let response_verification = *response_verification;
                    let encrypted_header = std::mem::take(buf);
                    let header_key = derive_16(&response_key, &[b"AEAD Resp Header Key"]);
                    let header_iv = derive_12(&response_iv, &[b"AEAD Resp Header IV"]);
                    let header = Aes128Gcm::new_from_slice(&header_key)
                        .map_err(std::io::Error::other)?
                        .decrypt(Nonce::from_slice(&header_iv), encrypted_header.as_slice())
                        .map_err(|_| {
                            std::io::Error::other("VMess response header authentication failed")
                        })?;
                    if header.first() != Some(&response_verification) {
                        return Poll::Ready(Err(std::io::Error::other(
                            "VMess response verification byte mismatch",
                        )));
                    }
                    self.response_header = ResponseHeaderRead::Done;
                    return Poll::Ready(Ok(()));
                }
                ResponseHeaderRead::LegacyHeader {
                    buf,
                    filled,
                    response_key,
                    response_iv,
                    response_verification,
                } => {
                    match poll_fill_exact(cx, &mut self.remote, buf, filled) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) => {}
                    }
                    let mut header = *buf;
                    let response_key = *response_key;
                    let response_iv = *response_iv;
                    let response_verification = *response_verification;
                    let mut cipher = cfb_mode::BufDecryptor::<aes::Aes128>::new(
                        (&response_key).into(),
                        (&response_iv).into(),
                    );
                    cipher.decrypt(&mut header);
                    if header[0] != response_verification {
                        return Poll::Ready(Err(std::io::Error::other(
                            "VMess response verification byte mismatch",
                        )));
                    }
                    if header[2] != 0 {
                        return Poll::Ready(Err(std::io::Error::other(
                            "VMess dynamic port response is unsupported",
                        )));
                    }
                    if header[3] != 0 {
                        self.response_header = ResponseHeaderRead::LegacyCommand {
                            buf: vec![0_u8; usize::from(header[3])],
                            filled: 0,
                        };
                    } else {
                        self.response_header = ResponseHeaderRead::Done;
                        return Poll::Ready(Ok(()));
                    }
                }
                ResponseHeaderRead::LegacyCommand { buf, filled } => {
                    match poll_fill_exact(cx, &mut self.remote, buf, filled) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                        Poll::Ready(Ok(())) => {}
                    }
                    self.response_header = ResponseHeaderRead::Done;
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

fn poll_fill_exact<R: AsyncRead + Unpin>(
    cx: &mut Context<'_>,
    reader: &mut R,
    buf: &mut [u8],
    filled: &mut usize,
) -> Poll<std::io::Result<()>> {
    while *filled < buf.len() {
        let mut read_buf = ReadBuf::new(&mut buf[*filled..]);
        match Pin::new(&mut *reader).poll_read(cx, &mut read_buf) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {
                let read = read_buf.filled().len();
                if read == 0 {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "short VMess response header",
                    )));
                }
                *filled += read;
            }
        }
    }
    Poll::Ready(Ok(()))
}

impl AsyncRead for VmessTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.poll_response_header(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }

        loop {
            if self.plaintext_offset < self.plaintext.len() {
                let available = &self.plaintext[self.plaintext_offset..];
                let take = available.len().min(buf.remaining());
                buf.put_slice(&available[..take]);
                self.plaintext_offset += take;
                if self.plaintext_offset >= self.plaintext.len() {
                    self.plaintext.clear();
                    self.plaintext_offset = 0;
                }
                return Poll::Ready(Ok(()));
            }

            let this = &mut *self;
            match this
                .body_reader
                .poll_read_record(cx, &mut this.remote, &mut this.read_pending)
            {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(plaintext)) => {
                    if plaintext.is_empty() {
                        continue;
                    }
                    this.plaintext = plaintext;
                    this.plaintext_offset = 0;
                }
            }
        }
    }
}

impl AsyncWrite for VmessTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        match self.poll_flush_write_buf(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }

        if let Some(accepted) = self.accepted_plain.take() {
            return Poll::Ready(Ok(accepted));
        }

        if let Some(prelude) = self.write_prelude.take() {
            self.write_buf = prelude;
            self.write_offset = 0;
            match self.poll_flush_write_buf(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {}
            }
        }

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let take = buf.len().min(BodyWriter::maximum_plaintext());
        let wire = match self.body_writer.encode_record(&buf[..take]) {
            Ok(wire) => wire,
            Err(error) => return Poll::Ready(Err(error)),
        };
        self.write_buf = wire;
        self.write_offset = 0;
        match self.poll_flush_write_buf(cx) {
            Poll::Pending => {
                self.accepted_plain = Some(take);
                Poll::Pending
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => Poll::Ready(Ok(take)),
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match self.poll_flush_write_buf(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        if let Some(accepted) = self.accepted_plain.take() {
            // Flush completed the wire write that accepted `accepted` plaintext.
            let _ = accepted;
        }
        Pin::new(&mut self.remote).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        match self.poll_flush_write_buf(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        self.accepted_plain = None;
        Pin::new(&mut self.remote).poll_shutdown(cx)
    }
}
