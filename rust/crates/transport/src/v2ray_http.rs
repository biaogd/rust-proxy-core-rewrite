use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use rand::RngExt as _;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::BoxedStream;

const MAX_RESPONSE_HEADER: usize = 64 * 1024;

/// Wraps a stream with the pinned oracle's `V2Ray` HTTP/1 first-write transport.
#[must_use]
pub fn connect_v2ray_http(
    stream: BoxedStream,
    server_host: &str,
    method: &str,
    paths: &[String],
    headers: &BTreeMap<String, Vec<String>>,
) -> BoxedStream {
    Box::new(V2rayHttpStream::new(
        stream,
        server_host.to_owned(),
        method.to_owned(),
        paths.to_vec(),
        headers.clone(),
    ))
}

struct V2rayHttpStream {
    inner: BoxedStream,
    server_host: String,
    method: String,
    paths: Vec<String>,
    headers: BTreeMap<String, Vec<String>>,
    first_request: bool,
    write_buffer: Vec<u8>,
    write_offset: usize,
    pending_input: usize,
    first_response: bool,
    read_buffer: Vec<u8>,
    read_offset: usize,
}

impl V2rayHttpStream {
    fn new(
        inner: BoxedStream,
        server_host: String,
        method: String,
        paths: Vec<String>,
        headers: BTreeMap<String, Vec<String>>,
    ) -> Self {
        Self {
            inner,
            server_host,
            method,
            paths,
            headers,
            first_request: true,
            write_buffer: Vec::new(),
            write_offset: 0,
            pending_input: 0,
            first_response: true,
            read_buffer: Vec::new(),
            read_offset: 0,
        }
    }

    fn selected<'a>(values: &'a [String], fallback: &'a str) -> &'a str {
        values
            .get(rand::rng().random_range(0..values.len()))
            .map_or(fallback, String::as_str)
    }

    fn request(&self, payload: &[u8]) -> Vec<u8> {
        let path = oracle_path(Self::selected(&self.paths, "/"));
        let host = self
            .headers
            .iter()
            .find(|(name, values)| name.eq_ignore_ascii_case("host") && !values.is_empty())
            .map_or(self.server_host.as_str(), |(_, values)| {
                Self::selected(values, &self.server_host)
            });
        let mut request = format!("{} {} HTTP/1.1\r\nHost: {}\r\n", self.method, path, host);
        let mut has_user_agent = false;
        for (name, values) in &self.headers {
            if values.is_empty() {
                continue;
            }
            if name.eq_ignore_ascii_case("host") || name.eq_ignore_ascii_case("content-length") {
                continue;
            }
            has_user_agent |= name.eq_ignore_ascii_case("user-agent");
            request.push_str(name);
            request.push_str(": ");
            request.push_str(Self::selected(values, ""));
            request.push_str("\r\n");
        }
        if !has_user_agent {
            request.push_str("User-Agent: Go-http-client/1.1\r\n");
        }
        write!(request, "Content-Length: {}\r\n\r\n", payload.len())
            .expect("writing to a String cannot fail");
        let mut request = request.into_bytes();
        request.extend_from_slice(payload);
        request
    }

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

fn oracle_path(path: &str) -> String {
    let mut url = url::Url::parse("http://vmess.invalid/").expect("static V2Ray HTTP base URL");
    url.set_path(path);
    url.path().to_owned()
}

impl AsyncRead for V2rayHttpStream {
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
            if let Some(end) = this
                .read_buffer
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
            {
                this.first_response = false;
                this.read_offset = end + 4;
                return Pin::new(this).poll_read(cx, output);
            }
            if this.read_buffer.len() > MAX_RESPONSE_HEADER {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "V2Ray HTTP response header exceeds limit",
                )));
            }
        }
    }
}

impl AsyncWrite for V2rayHttpStream {
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
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::connect_v2ray_http;
    use crate::BoxedStream;

    #[tokio::test]
    async fn first_write_selects_configured_members_and_strips_response_header() {
        let (client, mut server) = tokio::io::duplex(4096);
        let mut client = connect_v2ray_http(
            Box::new(client) as BoxedStream,
            "origin.test",
            "POST",
            &["/a?x=1".to_owned(), "/b space".to_owned()],
            &BTreeMap::from([
                (
                    "Host".to_owned(),
                    vec!["front-a.test".to_owned(), "front-b.test".to_owned()],
                ),
                (
                    "X-Test".to_owned(),
                    vec!["one".to_owned(), "two".to_owned()],
                ),
            ]),
        );
        let server_task = tokio::spawn(async move {
            let mut request = Vec::new();
            loop {
                let mut chunk = [0_u8; 512];
                let length = server.read(&mut chunk).await.expect("read request");
                request.extend_from_slice(&chunk[..length]);
                if request.windows(4).any(|window| window == b"\r\n\r\n")
                    && request.ends_with(b"vmess-header")
                {
                    break;
                }
            }
            server
                .write_all(b"HTTP/1.1 200 OK\r\nX-Test: response\r\n\r\nvmess-response")
                .await
                .expect("write response");
            request
        });
        client
            .write_all(b"vmess-header")
            .await
            .expect("write VMess header");
        let mut response = vec![0_u8; "vmess-response".len()];
        client
            .read_exact(&mut response)
            .await
            .expect("read stripped response");
        assert_eq!(response, b"vmess-response");
        let request = String::from_utf8(server_task.await.expect("server task")).expect("HTTP");
        assert!(
            request.starts_with("POST /a%3Fx=1 HTTP/1.1\r\n")
                || request.starts_with("POST /b%20space HTTP/1.1\r\n")
        );
        assert!(
            request.contains("Host: front-a.test\r\n")
                || request.contains("Host: front-b.test\r\n")
        );
        assert!(request.contains("X-Test: one\r\n") || request.contains("X-Test: two\r\n"));
        assert!(request.contains("Content-Length: 12\r\n\r\nvmess-header"));
    }
}
