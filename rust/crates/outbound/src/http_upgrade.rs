use std::collections::{BTreeMap, btree_map::Entry};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use url::Url;

use crate::BoxedOutboundStream;

const MAX_HEADER_BYTES: usize = 8192;

/// Opens the v2ray-plugin raw HTTP Upgrade transport. Unlike WebSocket mode,
/// bytes after the 101 response are not framed.
///
/// # Errors
///
/// Returns an error when the request is invalid, transport I/O fails, or the
/// peer returns an invalid HTTP Upgrade response.
pub async fn connect_v2ray_http_upgrade(
    mut stream: BoxedOutboundStream,
    host: &str,
    path: &str,
    headers: &BTreeMap<String, String>,
    fast_open: bool,
) -> io::Result<BoxedOutboundStream> {
    let (path, early_data_limit) = split_early_data_path(path);
    if early_data_limit > 0 {
        return Ok(Box::new(LazyHttpUpgradeIo::new(
            stream,
            host.to_owned(),
            path,
            headers.clone(),
            early_data_limit,
            fast_open,
        )?));
    }
    let request = build_request(host, &path, headers, None)?;
    stream.write_all(&request).await?;
    if fast_open {
        Ok(Box::new(PendingResponseIo::new(stream)))
    } else {
        let prefix = read_response(&mut stream).await?;
        Ok(Box::new(PrefixedIo::new(stream, prefix)))
    }
}

fn build_request(
    host: &str,
    path: &str,
    headers: &BTreeMap<String, String>,
    early_data: Option<&[u8]>,
) -> io::Result<Vec<u8>> {
    validate_request_target(path)?;
    let effective_host = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("host"))
        .map_or(host, |(_, value)| value.as_str());
    validate_header("Host", effective_host)?;
    let mut request = format!("GET {path} HTTP/1.1\r\nHost: {effective_host}\r\n");
    for (name, value) in headers {
        validate_header(name, value)?;
        if name.eq_ignore_ascii_case("host")
            || name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("upgrade")
            || early_data.is_some() && name.eq_ignore_ascii_case("sec-websocket-protocol")
        {
            continue;
        }
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("Connection: Upgrade\r\nUpgrade: websocket\r\n");
    if let Some(early_data) = early_data {
        request.push_str("Sec-WebSocket-Protocol: ");
        request.push_str(&URL_SAFE_NO_PAD.encode(early_data));
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    Ok(request.into_bytes())
}

fn validate_request_target(path: &str) -> io::Result<()> {
    if !path.starts_with('/') || path.bytes().any(|byte| byte <= b' ' || byte == 0x7f) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid v2ray-plugin HTTP Upgrade path",
        ));
    }
    Ok(())
}

fn validate_header(name: &str, value: &str) -> io::Result<()> {
    let valid_name = !name.is_empty()
        && name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        });
    if !valid_name || value.bytes().any(|byte| matches!(byte, b'\r' | b'\n' | 0)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid v2ray-plugin HTTP header {name:?}"),
        ));
    }
    Ok(())
}

async fn read_response(stream: &mut BoxedOutboundStream) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(512);
    let mut chunk = [0_u8; 1024];
    loop {
        let count = stream.read(&mut chunk).await?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "v2ray-plugin HTTP Upgrade closed before response",
            ));
        }
        bytes.extend_from_slice(&chunk[..count]);
        if let Some(end) = find_header_end(&bytes) {
            validate_response(&bytes[..end])?;
            return Ok(bytes.split_off(end));
        }
        if bytes.len() > MAX_HEADER_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "v2ray-plugin HTTP Upgrade response headers exceeded 8192 bytes",
            ));
        }
    }
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|offset| offset + 4)
}

fn validate_response(bytes: &[u8]) -> io::Result<()> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut headers);
    response
        .parse(bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let connection = response
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("connection"))
        .and_then(|header| std::str::from_utf8(header.value).ok());
    let upgrade = response
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("upgrade"))
        .and_then(|header| std::str::from_utf8(header.value).ok());
    if response.code != Some(101)
        || !connection.is_some_and(|value| value.eq_ignore_ascii_case("upgrade"))
        || !upgrade.is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "unexpected v2ray-plugin HTTP Upgrade response: {}",
                response.code.unwrap_or_default()
            ),
        ));
    }
    Ok(())
}

fn split_early_data_path(path: &str) -> (String, usize) {
    let Ok(url) = Url::parse(&format!("ws://v2ray.invalid{path}")) else {
        return (path.to_owned(), 0);
    };
    let Some(value) = url
        .query_pairs()
        .find_map(|(key, value)| (key == "ed").then_some(value.into_owned()))
    else {
        return (path.to_owned(), 0);
    };
    let Ok(parsed) = value.parse::<i64>() else {
        return (path.to_owned(), 0);
    };
    let mut parameters: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (key, value) in url.query_pairs().filter(|(key, _)| key != "ed") {
        match parameters.entry(key.into_owned()) {
            Entry::Vacant(entry) => {
                entry.insert(vec![value.into_owned()]);
            }
            Entry::Occupied(mut entry) => entry.get_mut().push(value.into_owned()),
        }
    }
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (key, values) in parameters {
        for value in values {
            serializer.append_pair(&key, &value);
        }
    }
    let query = serializer.finish();
    let normalized = if query.is_empty() {
        url.path().to_owned()
    } else {
        format!("{}?{query}", url.path())
    };
    (
        normalized,
        usize::try_from(parsed.max(0)).unwrap_or(usize::MAX),
    )
}

struct PrefixedIo {
    stream: BoxedOutboundStream,
    prefix: Bytes,
    offset: usize,
}

impl PrefixedIo {
    fn new(stream: BoxedOutboundStream, prefix: Vec<u8>) -> Self {
        Self {
            stream,
            prefix: Bytes::from(prefix),
            offset: 0,
        }
    }
}

impl AsyncRead for PrefixedIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.offset < this.prefix.len() {
            let remaining = &this.prefix[this.offset..];
            let count = remaining.len().min(output.remaining());
            output.put_slice(&remaining[..count]);
            this.offset += count;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.stream).poll_read(cx, output)
    }
}

impl AsyncWrite for PrefixedIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, input)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

struct PendingResponseIo {
    stream: BoxedOutboundStream,
    response: Vec<u8>,
    prefix: Bytes,
    prefix_offset: usize,
    validated: bool,
}

impl PendingResponseIo {
    fn new(stream: BoxedOutboundStream) -> Self {
        Self {
            stream,
            response: Vec::with_capacity(512),
            prefix: Bytes::new(),
            prefix_offset: 0,
            validated: false,
        }
    }
}

impl AsyncRead for PendingResponseIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while !this.validated {
            let mut chunk = [0_u8; 1024];
            let mut buffer = ReadBuf::new(&mut chunk);
            ready!(Pin::new(&mut this.stream).poll_read(cx, &mut buffer))?;
            if buffer.filled().is_empty() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "v2ray-plugin HTTP Upgrade closed before response",
                )));
            }
            this.response.extend_from_slice(buffer.filled());
            if let Some(end) = find_header_end(&this.response) {
                validate_response(&this.response[..end])?;
                this.prefix = Bytes::copy_from_slice(&this.response[end..]);
                this.response.clear();
                this.validated = true;
            } else if this.response.len() > MAX_HEADER_BYTES {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "v2ray-plugin HTTP Upgrade response headers exceeded 8192 bytes",
                )));
            }
        }
        if this.prefix_offset < this.prefix.len() {
            let remaining = &this.prefix[this.prefix_offset..];
            let count = remaining.len().min(output.remaining());
            output.put_slice(&remaining[..count]);
            this.prefix_offset += count;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.stream).poll_read(cx, output)
    }
}

impl AsyncWrite for PendingResponseIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, input)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

type LazyFuture = Pin<Box<dyn Future<Output = io::Result<(BoxedOutboundStream, usize)>> + Send>>;

enum LazyState {
    Pending {
        stream: Option<BoxedOutboundStream>,
        host: String,
        path: String,
        headers: BTreeMap<String, String>,
        early_data_limit: usize,
        fast_open: bool,
    },
    Connecting(LazyFuture),
    Connected(BoxedOutboundStream),
    Failed,
}

struct LazyHttpUpgradeIo {
    state: LazyState,
}

impl LazyHttpUpgradeIo {
    fn new(
        stream: BoxedOutboundStream,
        host: String,
        path: String,
        headers: BTreeMap<String, String>,
        early_data_limit: usize,
        fast_open: bool,
    ) -> io::Result<Self> {
        build_request(&host, &path, &headers, Some(&[]))?;
        Ok(Self {
            state: LazyState::Pending {
                stream: Some(stream),
                host,
                path,
                headers,
                early_data_limit,
                fast_open,
            },
        })
    }

    fn begin(&mut self, input: &[u8]) {
        let LazyState::Pending {
            stream,
            host,
            path,
            headers,
            early_data_limit,
            fast_open,
        } = &mut self.state
        else {
            return;
        };
        let mut stream = stream.take().expect("lazy HTTP Upgrade stream taken once");
        let request_host = host.clone();
        let request_path = path.clone();
        let request_headers = headers.clone();
        let early_length = input.len().min(*early_data_limit);
        let input = Bytes::copy_from_slice(input);
        let fast_open = *fast_open;
        self.state = LazyState::Connecting(Box::pin(async move {
            let request = build_request(
                &request_host,
                &request_path,
                &request_headers,
                Some(&input[..early_length]),
            )?;
            stream.write_all(&request).await?;
            let mut stream: BoxedOutboundStream = if fast_open {
                Box::new(PendingResponseIo::new(stream))
            } else {
                let prefix = read_response(&mut stream).await?;
                Box::new(PrefixedIo::new(stream, prefix))
            };
            if early_length < input.len() {
                stream.write_all(&input[early_length..]).await?;
            }
            Ok((stream, input.len()))
        }));
    }
}

impl AsyncRead for LazyHttpUpgradeIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            match &mut this.state {
                LazyState::Pending { .. } => return Poll::Pending,
                LazyState::Connecting(future) => match ready!(future.as_mut().poll(cx)) {
                    Ok((stream, _)) => this.state = LazyState::Connected(stream),
                    Err(error) => {
                        this.state = LazyState::Failed;
                        return Poll::Ready(Err(error));
                    }
                },
                LazyState::Connected(stream) => return Pin::new(stream).poll_read(cx, output),
                LazyState::Failed => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            }
        }
    }
}

impl AsyncWrite for LazyHttpUpgradeIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if matches!(this.state, LazyState::Pending { .. }) {
            this.begin(input);
        }
        match &mut this.state {
            LazyState::Connecting(future) => match ready!(future.as_mut().poll(cx)) {
                Ok((stream, accepted)) => {
                    this.state = LazyState::Connected(stream);
                    Poll::Ready(Ok(accepted))
                }
                Err(error) => {
                    this.state = LazyState::Failed;
                    Poll::Ready(Err(error))
                }
            },
            LazyState::Connected(stream) => Pin::new(stream).poll_write(cx, input),
            LazyState::Pending { .. } => unreachable!("lazy HTTP Upgrade started above"),
            LazyState::Failed => Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            match &mut this.state {
                LazyState::Pending { .. } => return Poll::Ready(Ok(())),
                LazyState::Connecting(future) => match ready!(future.as_mut().poll(cx)) {
                    Ok((stream, _)) => this.state = LazyState::Connected(stream),
                    Err(error) => {
                        this.state = LazyState::Failed;
                        return Poll::Ready(Err(error));
                    }
                },
                LazyState::Connected(stream) => return Pin::new(stream).poll_flush(cx),
                LazyState::Failed => {
                    return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
                }
            }
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            match &mut this.state {
                LazyState::Pending { stream, .. } => {
                    return Pin::new(
                        stream
                            .as_mut()
                            .expect("pending lazy HTTP Upgrade retains stream"),
                    )
                    .poll_shutdown(cx);
                }
                LazyState::Connecting(future) => match ready!(future.as_mut().poll(cx)) {
                    Ok((stream, _)) => this.state = LazyState::Connected(stream),
                    Err(error) => {
                        this.state = LazyState::Failed;
                        return Poll::Ready(Err(error));
                    }
                },
                LazyState::Connected(stream) => return Pin::new(stream).poll_shutdown(cx),
                LazyState::Failed => return Poll::Ready(Ok(())),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn early_data_query_is_removed_and_remaining_query_is_sorted() {
        assert_eq!(
            split_early_data_path("/ws?z=2&ed=64&a=1"),
            ("/ws?a=1&z=2".to_owned(), 64)
        );
        assert_eq!(
            split_early_data_path("/ws?ed=bad&z=2"),
            ("/ws?ed=bad&z=2".to_owned(), 0)
        );
    }

    #[test]
    fn raw_upgrade_has_no_rfc6455_headers() {
        let request = build_request("example.test", "/raw", &BTreeMap::new(), None).unwrap();
        let request = String::from_utf8(request).unwrap();
        assert!(request.contains("Upgrade: websocket\r\n"));
        assert!(!request.contains("Sec-WebSocket-Key"));
        assert!(!request.contains("Sec-WebSocket-Version"));
    }
}
