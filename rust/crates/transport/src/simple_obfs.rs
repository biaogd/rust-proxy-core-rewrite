use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE;
use rand::RngExt;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const MAX_HTTP_HEADER: usize = 16 * 1024;

pub struct HttpObfsClient<S> {
    inner: S,
    host: String,
    port: u16,
    first_request: bool,
    write_buffer: Vec<u8>,
    write_offset: usize,
    pending_input: usize,
    first_response: bool,
    read_buffer: Vec<u8>,
    read_offset: usize,
}

impl<S> HttpObfsClient<S> {
    pub fn new(inner: S, host: String, port: u16) -> Self {
        Self {
            inner,
            host,
            port,
            first_request: true,
            write_buffer: Vec::new(),
            write_offset: 0,
            pending_input: 0,
            first_response: true,
            read_buffer: Vec::new(),
            read_offset: 0,
        }
    }

    fn request(&self, payload: &[u8]) -> Vec<u8> {
        let mut random = [0_u8; 16];
        rand::rng().fill(&mut random);
        let key = URL_SAFE.encode(random);
        let host = if self.port == 80 {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        };
        let mut request = format!(
            "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: curl/7.{}.{}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nContent-Length: {}\r\n\r\n",
            rand::random_range(0..54),
            rand::random_range(0..2),
            payload.len()
        )
        .into_bytes();
        request.extend_from_slice(payload);
        request
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> HttpObfsClient<S> {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.write_offset < self.write_buffer.len() {
            let written = ready!(
                Pin::new(&mut self.inner).poll_write(cx, &self.write_buffer[self.write_offset..])
            )?;
            if written == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.write_offset += written;
        }
        self.write_buffer.clear();
        self.write_offset = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for HttpObfsClient<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.read_offset < this.read_buffer.len() {
            let available = &this.read_buffer[this.read_offset..];
            let length = available.len().min(output.remaining());
            output.put_slice(&available[..length]);
            this.read_offset += length;
            return Poll::Ready(Ok(()));
        }
        if !this.first_response {
            return Pin::new(&mut this.inner).poll_read(cx, output);
        }
        loop {
            let mut temporary = [0_u8; 1024];
            let mut input = ReadBuf::new(&mut temporary);
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut input))?;
            if input.filled().is_empty() {
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            this.read_buffer.extend_from_slice(input.filled());
            if let Some(index) = find_header_end(&this.read_buffer) {
                this.first_response = false;
                this.read_offset = index + 4;
                return Pin::new(this).poll_read(cx, output);
            }
            if this.read_buffer.len() > MAX_HTTP_HEADER {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "simple-obfs HTTP response header exceeds limit",
                )));
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for HttpObfsClient<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if !this.write_buffer.is_empty() {
            ready!(this.poll_drain(cx))?;
            return Poll::Ready(Ok(std::mem::take(&mut this.pending_input)));
        }
        if !this.first_request {
            return Pin::new(&mut this.inner).poll_write(cx, input);
        }
        this.first_request = false;
        this.write_buffer = this.request(input);
        this.pending_input = input.len();
        ready!(this.poll_drain(cx))?;
        Poll::Ready(Ok(std::mem::take(&mut this.pending_input)))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.write_buffer.is_empty() {
            ready!(this.poll_drain(cx))?;
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.write_buffer.is_empty() {
            ready!(this.poll_drain(cx))?;
        }
        // Mihomo's Go HTTPObfs exposes only net.Conn, not CloseWriter. Its relay
        // therefore closes the whole obfuscated connection when the client
        // half-closes instead of preserving the response direction.
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "simple-obfs HTTP does not preserve TCP half-close",
        )))
    }
}

pub struct HttpObfsServer<S> {
    inner: S,
    expected_host: Option<String>,
    first_request: bool,
    read_buffer: Vec<u8>,
    read_offset: usize,
    first_response: bool,
    write_buffer: Vec<u8>,
    write_offset: usize,
    pending_input: usize,
}

impl<S> HttpObfsServer<S> {
    pub fn new(inner: S, expected_host: Option<String>) -> Self {
        Self {
            inner,
            expected_host,
            first_request: true,
            read_buffer: Vec::new(),
            read_offset: 0,
            first_response: true,
            write_buffer: Vec::new(),
            write_offset: 0,
            pending_input: 0,
        }
    }

    pub fn request_host(&self) -> Option<&str> {
        let header_end = find_header_end(&self.read_buffer)?;
        std::str::from_utf8(&self.read_buffer[..header_end])
            .ok()?
            .lines()
            .find_map(|line| line.strip_prefix("Host: "))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> HttpObfsServer<S> {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.write_offset < self.write_buffer.len() {
            let written = ready!(
                Pin::new(&mut self.inner).poll_write(cx, &self.write_buffer[self.write_offset..])
            )?;
            if written == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.write_offset += written;
        }
        self.write_buffer.clear();
        self.write_offset = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for HttpObfsServer<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.first_request {
            if this.read_offset < this.read_buffer.len() {
                let available = &this.read_buffer[this.read_offset..];
                let length = available.len().min(output.remaining());
                output.put_slice(&available[..length]);
                this.read_offset += length;
                return Poll::Ready(Ok(()));
            }
            return Pin::new(&mut this.inner).poll_read(cx, output);
        }
        loop {
            if let Some(header_end) = find_header_end(&this.read_buffer) {
                let header =
                    std::str::from_utf8(&this.read_buffer[..header_end]).map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP obfs header")
                    })?;
                if !header.starts_with("GET / HTTP/1.1\r\n")
                    || !header.lines().any(|line| line == "Connection: Upgrade")
                {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid HTTP obfs request",
                    )));
                }
                if let Some(expected_host) = &this.expected_host
                    && !header
                        .lines()
                        .any(|line| line.strip_prefix("Host: ") == Some(expected_host))
                {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unexpected HTTP obfs host",
                    )));
                }
                let content_length = header
                    .lines()
                    .find_map(|line| line.strip_prefix("Content-Length: "))
                    .and_then(|value| value.parse::<usize>().ok())
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "missing HTTP obfs length")
                    })?;
                let body = header_end + 4;
                if this.read_buffer.len() >= body + content_length {
                    this.first_request = false;
                    this.read_offset = body;
                    return Pin::new(this).poll_read(cx, output);
                }
            }
            if this.read_buffer.len() > MAX_HTTP_HEADER + 65_535 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "simple-obfs HTTP request exceeds limit",
                )));
            }
            let mut temporary = [0_u8; 2048];
            let mut input = ReadBuf::new(&mut temporary);
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut input))?;
            if input.filled().is_empty() {
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            this.read_buffer.extend_from_slice(input.filled());
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for HttpObfsServer<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if !this.write_buffer.is_empty() {
            ready!(this.poll_drain(cx))?;
            return Poll::Ready(Ok(std::mem::take(&mut this.pending_input)));
        }
        if !this.first_response {
            return Pin::new(&mut this.inner).poll_write(cx, input);
        }
        this.first_response = false;
        this.write_buffer = b"HTTP/1.1 101 Switching Protocols\r\nServer: nginx/1.18.0\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: dGVzdA==\r\n\r\n".to_vec();
        this.write_buffer.extend_from_slice(input);
        this.pending_input = input.len();
        ready!(this.poll_drain(cx))?;
        Poll::Ready(Ok(std::mem::take(&mut this.pending_input)))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.write_buffer.is_empty() {
            ready!(this.poll_drain(cx))?;
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.write_buffer.is_empty() {
            ready!(this.poll_drain(cx))?;
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

const TLS_CHUNK_SIZE: usize = 1 << 14;

pub struct TlsObfsClient<S> {
    inner: S,
    server: String,
    first_request: bool,
    write_buffer: Vec<u8>,
    write_offset: usize,
    pending_input: usize,
    first_response: bool,
    wire_buffer: Vec<u8>,
    payload_buffer: Vec<u8>,
    payload_offset: usize,
}

impl<S> TlsObfsClient<S> {
    pub fn new(inner: S, server: String) -> Self {
        Self {
            inner,
            server,
            first_request: true,
            write_buffer: Vec::new(),
            write_offset: 0,
            pending_input: 0,
            first_response: true,
            wire_buffer: Vec::new(),
            payload_buffer: Vec::new(),
            payload_offset: 0,
        }
    }

    fn client_hello(&self, payload: &[u8]) -> io::Result<Vec<u8>> {
        let mut random = [0_u8; 28];
        let mut session_id = [0_u8; 32];
        rand::rng().fill(&mut random);
        rand::rng().fill(&mut session_id);
        let server = self.server.as_bytes();
        let record_length = 212 + payload.len() + server.len();
        let handshake_length = 208 + payload.len() + server.len();
        let extension_length = 79 + payload.len() + server.len();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .to_be_bytes();
        let mut output = Vec::with_capacity(record_length + 5);
        output.extend_from_slice(&[0x16, 0x03, 0x01]);
        push_length(&mut output, record_length)?;
        output.extend_from_slice(&[0x01, 0x00]);
        push_length(&mut output, handshake_length)?;
        output.extend_from_slice(&[0x03, 0x03]);
        output.extend_from_slice(&timestamp[4..]);
        output.extend_from_slice(&random);
        output.push(32);
        output.extend_from_slice(&session_id);
        output.extend_from_slice(&[0x00, 0x38]);
        output.extend_from_slice(&TLS_CIPHER_SUITES);
        output.extend_from_slice(&[0x01, 0x00]);
        push_length(&mut output, extension_length)?;
        output.extend_from_slice(&[0x00, 0x23]);
        push_length(&mut output, payload.len())?;
        output.extend_from_slice(payload);
        output.extend_from_slice(&[0x00, 0x00]);
        push_length(&mut output, server.len() + 5)?;
        push_length(&mut output, server.len() + 3)?;
        output.push(0);
        push_length(&mut output, server.len())?;
        output.extend_from_slice(server);
        output.extend_from_slice(&TLS_FIXED_EXTENSIONS);
        Ok(output)
    }

    fn application_record(payload: &[u8]) -> io::Result<Vec<u8>> {
        let mut output = Vec::with_capacity(payload.len() + 5);
        output.extend_from_slice(&[0x17, 0x03, 0x03]);
        push_length(&mut output, payload.len())?;
        output.extend_from_slice(payload);
        Ok(output)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> TlsObfsClient<S> {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.write_offset < self.write_buffer.len() {
            let written = ready!(
                Pin::new(&mut self.inner).poll_write(cx, &self.write_buffer[self.write_offset..])
            )?;
            if written == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.write_offset += written;
        }
        self.write_buffer.clear();
        self.write_offset = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for TlsObfsClient<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.payload_offset < this.payload_buffer.len() {
            let payload = &this.payload_buffer[this.payload_offset..];
            let length = payload.len().min(output.remaining());
            output.put_slice(&payload[..length]);
            this.payload_offset += length;
            return Poll::Ready(Ok(()));
        }
        this.payload_buffer.clear();
        this.payload_offset = 0;
        loop {
            let prefix = if this.first_response { 105 } else { 3 };
            if this.wire_buffer.len() >= prefix + 2 {
                let length = usize::from(u16::from_be_bytes([
                    this.wire_buffer[prefix],
                    this.wire_buffer[prefix + 1],
                ]));
                let total = prefix + 2 + length;
                if this.wire_buffer.len() >= total {
                    this.payload_buffer = this.wire_buffer[prefix + 2..total].to_vec();
                    this.wire_buffer.drain(..total);
                    this.first_response = false;
                    return Pin::new(this).poll_read(cx, output);
                }
            }
            let mut temporary = [0_u8; 2048];
            let mut input = ReadBuf::new(&mut temporary);
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut input))?;
            if input.filled().is_empty() {
                if this.wire_buffer.is_empty() {
                    return Poll::Ready(Ok(()));
                }
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            this.wire_buffer.extend_from_slice(input.filled());
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TlsObfsClient<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if !this.write_buffer.is_empty() {
            ready!(this.poll_drain(cx))?;
            return Poll::Ready(Ok(std::mem::take(&mut this.pending_input)));
        }
        let length = input.len().min(TLS_CHUNK_SIZE);
        this.write_buffer = if this.first_request {
            this.first_request = false;
            this.client_hello(&input[..length])?
        } else {
            Self::application_record(&input[..length])?
        };
        this.pending_input = length;
        ready!(this.poll_drain(cx))?;
        Poll::Ready(Ok(std::mem::take(&mut this.pending_input)))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.write_buffer.is_empty() {
            ready!(this.poll_drain(cx))?;
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.write_buffer.is_empty() {
            ready!(this.poll_drain(cx))?;
        }
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "simple-obfs TLS does not preserve TCP half-close",
        )))
    }
}

pub struct TlsObfsServer<S> {
    inner: S,
    expected_server: Option<String>,
    first_request: bool,
    wire_buffer: Vec<u8>,
    payload_buffer: Vec<u8>,
    payload_offset: usize,
    first_response: bool,
    write_buffer: Vec<u8>,
    write_offset: usize,
    pending_input: usize,
}

impl<S> TlsObfsServer<S> {
    pub fn new(inner: S, expected_server: Option<String>) -> Self {
        Self {
            inner,
            expected_server,
            first_request: true,
            wire_buffer: Vec::new(),
            payload_buffer: Vec::new(),
            payload_offset: 0,
            first_response: true,
            write_buffer: Vec::new(),
            write_offset: 0,
            pending_input: 0,
        }
    }

    fn response_record(first: bool, payload: &[u8]) -> io::Result<Vec<u8>> {
        let mut output = Vec::with_capacity(payload.len() + if first { 107 } else { 5 });
        if first {
            output.extend_from_slice(&[0x16, 0x03, 0x03, 0x00, 0x5b]);
            output.resize(96, 0);
            output.extend_from_slice(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
        }
        output.extend_from_slice(&[0x17, 0x03, 0x03]);
        push_length(&mut output, payload.len())?;
        output.extend_from_slice(payload);
        Ok(output)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> TlsObfsServer<S> {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.write_offset < self.write_buffer.len() {
            let written = ready!(
                Pin::new(&mut self.inner).poll_write(cx, &self.write_buffer[self.write_offset..])
            )?;
            if written == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.write_offset += written;
        }
        self.write_buffer.clear();
        self.write_offset = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for TlsObfsServer<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.payload_offset < this.payload_buffer.len() {
            let payload = &this.payload_buffer[this.payload_offset..];
            let length = payload.len().min(output.remaining());
            output.put_slice(&payload[..length]);
            this.payload_offset += length;
            return Poll::Ready(Ok(()));
        }
        this.payload_buffer.clear();
        this.payload_offset = 0;
        loop {
            if this.wire_buffer.len() >= 5 {
                let length = usize::from(u16::from_be_bytes([
                    this.wire_buffer[3],
                    this.wire_buffer[4],
                ]));
                let total = 5 + length;
                if this.wire_buffer.len() >= total {
                    let frame = this.wire_buffer[..total].to_vec();
                    this.wire_buffer.drain(..total);
                    this.payload_buffer = if this.first_request {
                        let (payload, server) = parse_client_hello(&frame)?;
                        if this
                            .expected_server
                            .as_deref()
                            .is_some_and(|expected| expected != server)
                        {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "unexpected simple-obfs TLS server name",
                            )));
                        }
                        this.first_request = false;
                        payload
                    } else {
                        if frame[..3] != [0x17, 0x03, 0x03] {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "invalid simple-obfs TLS application record",
                            )));
                        }
                        frame[5..].to_vec()
                    };
                    return Pin::new(this).poll_read(cx, output);
                }
            }
            let mut temporary = [0_u8; 2048];
            let mut input = ReadBuf::new(&mut temporary);
            ready!(Pin::new(&mut this.inner).poll_read(cx, &mut input))?;
            if input.filled().is_empty() {
                if this.wire_buffer.is_empty() {
                    return Poll::Ready(Ok(()));
                }
                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
            }
            this.wire_buffer.extend_from_slice(input.filled());
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TlsObfsServer<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if !this.write_buffer.is_empty() {
            ready!(this.poll_drain(cx))?;
            return Poll::Ready(Ok(std::mem::take(&mut this.pending_input)));
        }
        let length = input.len().min(TLS_CHUNK_SIZE);
        this.write_buffer = Self::response_record(this.first_response, &input[..length])?;
        this.first_response = false;
        this.pending_input = length;
        ready!(this.poll_drain(cx))?;
        Poll::Ready(Ok(std::mem::take(&mut this.pending_input)))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.write_buffer.is_empty() {
            ready!(this.poll_drain(cx))?;
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.write_buffer.is_empty() {
            ready!(this.poll_drain(cx))?;
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

fn push_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn push_length(output: &mut Vec<u8>, value: usize) -> io::Result<()> {
    let value = u16::try_from(value).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "simple-obfs TLS field exceeds 65535 bytes",
        )
    })?;
    push_u16(output, value);
    Ok(())
}

fn parse_client_hello(frame: &[u8]) -> io::Result<(Vec<u8>, &str)> {
    if frame.len() < 138 || frame[..3] != [0x16, 0x03, 0x01] || frame[5] != 0x01 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid simple-obfs TLS client hello",
        ));
    }
    let mut offset = 138;
    let mut ticket = None;
    let mut server = None;
    while offset + 4 <= frame.len() {
        let kind = u16::from_be_bytes([frame[offset], frame[offset + 1]]);
        let length = usize::from(u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]));
        offset += 4;
        let end = offset
            .checked_add(length)
            .filter(|end| *end <= frame.len())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated simple-obfs TLS extension",
                )
            })?;
        let data = &frame[offset..end];
        match kind {
            0x0023 => ticket = Some(data.to_vec()),
            0x0000 if data.len() >= 5 => {
                let name_length = usize::from(u16::from_be_bytes([data[3], data[4]]));
                if 5 + name_length <= data.len() {
                    server = std::str::from_utf8(&data[5..5 + name_length]).ok();
                }
            }
            _ => {}
        }
        offset = end;
    }
    ticket.zip(server).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "simple-obfs TLS client hello lacks ticket or server name",
        )
    })
}

const TLS_CIPHER_SUITES: [u8; 56] = [
    0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f,
    0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a,
    0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d,
    0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff,
];

const TLS_FIXED_EXTENSIONS: [u8; 66] = [
    0x00, 0x0b, 0x00, 0x04, 0x03, 0x01, 0x00, 0x02, 0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d,
    0x00, 0x17, 0x00, 0x19, 0x00, 0x18, 0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x01, 0x06, 0x02,
    0x06, 0x03, 0x05, 0x01, 0x05, 0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x03, 0x01,
    0x03, 0x02, 0x03, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03, 0x00, 0x16, 0x00, 0x00, 0x00, 0x17,
    0x00, 0x00,
];

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}
