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

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}
