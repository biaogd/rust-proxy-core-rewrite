use std::collections::{BTreeMap, btree_map::Entry};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use futures_util::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::http::header::{
    CONNECTION, HOST, SEC_WEBSOCKET_KEY, SEC_WEBSOCKET_PROTOCOL, SEC_WEBSOCKET_VERSION, UPGRADE,
};
use tokio_tungstenite::tungstenite::http::{HeaderName, HeaderValue, Request};
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::tungstenite::{Error, Message};
use url::Url;

use crate::BoxedOutboundStream;

pub struct WebSocketIo<S> {
    stream: WebSocketStream<S>,
    read_buffer: Bytes,
    read_offset: usize,
    pending_write: usize,
}

impl<S> WebSocketIo<S> {
    pub fn new(stream: WebSocketStream<S>) -> Self {
        Self {
            stream,
            read_buffer: Bytes::new(),
            read_offset: 0,
            pending_write: 0,
        }
    }
}

/// Upgrades an already-connected transport to a binary WebSocket byte stream.
///
/// # Errors
///
/// Returns a Tungstenite error when the request cannot be constructed or the
/// peer rejects or violates the WebSocket handshake.
pub async fn connect_websocket<S>(
    stream: S,
    host: &str,
    port: u16,
    path: &str,
) -> Result<WebSocketIo<S>, Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let uri = format!("ws://{host}:{port}{path}");
    let mut request = uri.into_client_request()?;
    request
        .headers_mut()
        .insert(HOST, HeaderValue::from_str(host)?);
    let (stream, _) = tokio_tungstenite::client_async(request, stream).await?;
    Ok(WebSocketIo::new(stream))
}

/// Upgrades an established transport using an explicit WebSocket request
/// path and header set.
///
/// # Errors
///
/// Returns an error when a configured header is invalid or the peer rejects
/// the RFC 6455 handshake.
pub async fn connect_websocket_with_headers(
    stream: BoxedOutboundStream,
    host: &str,
    port: u16,
    path: &str,
    headers: &BTreeMap<String, String>,
) -> Result<BoxedOutboundStream, Error> {
    connect_websocket_with_early_data(stream, host, port, path, headers, 0, None).await
}

/// Upgrades an established transport and defers the handshake until the first
/// `VMess` bytes are available when early data is enabled.
///
/// An absent header name appends the encoded bytes to the URL path, matching
/// Mihomo's `VMess` WebSocket transport. A present name places them in that
/// request header.
///
/// # Errors
///
/// Returns an error when the request or early-data header is invalid, or the
/// peer rejects the RFC 6455 handshake.
#[allow(clippy::too_many_arguments)]
pub async fn connect_websocket_with_early_data(
    stream: BoxedOutboundStream,
    host: &str,
    port: u16,
    path: &str,
    headers: &BTreeMap<String, String>,
    max_early_data: usize,
    early_data_header_name: Option<&str>,
) -> Result<BoxedOutboundStream, Error> {
    let (path, path_early_data) = split_early_data_path(path);
    let (max_early_data, early_data_header_name) = if path_early_data > 0 {
        (path_early_data, Some(SEC_WEBSOCKET_PROTOCOL.as_str()))
    } else {
        (max_early_data, early_data_header_name)
    };
    let request = websocket_request(host, port, &path, headers, None)?;
    if max_early_data > 0 {
        let placement = match early_data_header_name {
            Some(name) => EarlyDataPlacement::Header(HeaderName::from_bytes(name.as_bytes())?),
            None => EarlyDataPlacement::Path,
        };
        return Ok(Box::new(LazyWebSocketIo::new(
            stream,
            request,
            max_early_data,
            placement,
        )));
    }
    let (stream, _) = tokio_tungstenite::client_async(request, stream).await?;
    Ok(Box::new(WebSocketIo::new(stream)))
}

/// Opens the Go-compatible v2ray-plugin WebSocket transport, including custom
/// headers and the `path?ed=N` lazy early-data convention.
///
/// # Errors
///
/// Returns an error when request headers are invalid or the peer rejects or
/// violates the WebSocket handshake.
pub async fn connect_v2ray_websocket(
    stream: BoxedOutboundStream,
    host: &str,
    port: u16,
    path: &str,
    headers: &BTreeMap<String, String>,
) -> Result<BoxedOutboundStream, Error> {
    let (path, early_data) = split_early_data_path(path);
    connect_websocket_with_early_data(
        stream,
        host,
        port,
        &path,
        headers,
        early_data,
        Some(SEC_WEBSOCKET_PROTOCOL.as_str()),
    )
    .await
}

fn websocket_request(
    host: &str,
    port: u16,
    path: &str,
    headers: &BTreeMap<String, String>,
    early_data: Option<&[u8]>,
) -> Result<Request<()>, Error> {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let uri = format!("ws://{host}:{port}{path}");
    let mut request = uri.into_client_request()?;
    request
        .headers_mut()
        .insert(HOST, HeaderValue::from_str(host)?);
    for (name, value) in headers {
        let name = HeaderName::from_bytes(name.as_bytes())?;
        let value = HeaderValue::from_str(value)?;
        request.headers_mut().insert(name, value);
    }
    request
        .headers_mut()
        .insert(CONNECTION, HeaderValue::from_static("Upgrade"));
    request
        .headers_mut()
        .insert(UPGRADE, HeaderValue::from_static("websocket"));
    request
        .headers_mut()
        .insert(SEC_WEBSOCKET_VERSION, HeaderValue::from_static("13"));
    request.headers_mut().insert(
        SEC_WEBSOCKET_KEY,
        HeaderValue::from_str(&tokio_tungstenite::tungstenite::handshake::client::generate_key())?,
    );
    if let Some(early_data) = early_data {
        request.headers_mut().insert(
            SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_str(&URL_SAFE_NO_PAD.encode(early_data))?,
        );
    }
    Ok(request)
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

type UpgradeFuture = Pin<
    Box<
        dyn Future<Output = io::Result<(WebSocketIo<BoxedOutboundStream>, usize)>> + Send + 'static,
    >,
>;

enum LazyState {
    Pending {
        stream: Option<BoxedOutboundStream>,
        request: Option<Request<()>>,
        early_data_limit: usize,
        placement: Option<EarlyDataPlacement>,
    },
    Upgrading(UpgradeFuture),
    Connected(WebSocketIo<BoxedOutboundStream>),
    Failed,
}

struct LazyWebSocketIo {
    state: LazyState,
}

enum EarlyDataPlacement {
    Header(HeaderName),
    Path,
}

impl LazyWebSocketIo {
    fn new(
        stream: BoxedOutboundStream,
        request: Request<()>,
        early_data_limit: usize,
        placement: EarlyDataPlacement,
    ) -> Self {
        Self {
            state: LazyState::Pending {
                stream: Some(stream),
                request: Some(request),
                early_data_limit,
                placement: Some(placement),
            },
        }
    }

    fn begin(&mut self, input: &[u8]) {
        let LazyState::Pending {
            stream,
            request,
            early_data_limit,
            placement,
        } = &mut self.state
        else {
            return;
        };
        let stream = stream.take().expect("lazy WebSocket stream taken once");
        let mut request = request.take().expect("lazy WebSocket request taken once");
        let placement = placement
            .take()
            .expect("lazy WebSocket early-data placement taken once");
        let input = Bytes::copy_from_slice(input);
        let early_length = input.len().min(*early_data_limit);
        let early = URL_SAFE_NO_PAD.encode(&input[..early_length]);
        self.state = LazyState::Upgrading(Box::pin(async move {
            apply_early_data(&mut request, placement, &early)?;
            let stream = early_websocket_handshake(stream, request).await?;
            let mut stream = WebSocketIo::new(stream);
            if early_length < input.len() {
                stream.write_all(&input[early_length..]).await?;
            }
            Ok((stream, input.len()))
        }));
    }
}

fn apply_early_data(
    request: &mut Request<()>,
    placement: EarlyDataPlacement,
    encoded: &str,
) -> io::Result<()> {
    match placement {
        EarlyDataPlacement::Header(name) => {
            let value = HeaderValue::from_str(encoded)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
            request.headers_mut().insert(name, value);
        }
        EarlyDataPlacement::Path => {
            let current = request.uri().clone();
            let mut parts = current.into_parts();
            let target = parts
                .path_and_query
                .as_ref()
                .map_or("/", |value| value.as_str());
            let (path, query) = target
                .split_once('?')
                .map_or((target, None), |(path, query)| (path, Some(query)));
            let target = query.map_or_else(
                || format!("{path}{encoded}"),
                |query| format!("{path}{encoded}?{query}"),
            );
            parts.path_and_query = Some(
                target
                    .parse()
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?,
            );
            *request.uri_mut() = tokio_tungstenite::tungstenite::http::Uri::from_parts(parts)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        }
    }
    Ok(())
}

async fn early_websocket_handshake(
    mut stream: BoxedOutboundStream,
    request: Request<()>,
) -> io::Result<WebSocketStream<BoxedOutboundStream>> {
    let target = request
        .uri()
        .path_and_query()
        .map_or("/", |value| value.as_str());
    let mut encoded = format!("GET {target} HTTP/1.1\r\n");
    for (name, value) in request.headers() {
        encoded.push_str(name.as_str());
        encoded.push_str(": ");
        encoded.push_str(
            value
                .to_str()
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?,
        );
        encoded.push_str("\r\n");
    }
    encoded.push_str("\r\n");
    let key = request
        .headers()
        .get(SEC_WEBSOCKET_KEY)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing WebSocket key"))?;
    let expected_accept = derive_accept_key(key.as_bytes());
    stream.write_all(encoded.as_bytes()).await?;

    let mut response_bytes = Vec::with_capacity(512);
    let mut chunk = [0_u8; 1024];
    let header_end = loop {
        let count = stream.read(&mut chunk).await?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "WebSocket peer closed before the upgrade response",
            ));
        }
        response_bytes.extend_from_slice(&chunk[..count]);
        if let Some(offset) = response_bytes
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
        {
            break offset + 4;
        }
        if response_bytes.len() > 8192 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "WebSocket upgrade response headers exceeded 8192 bytes",
            ));
        }
    };
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut headers);
    response
        .parse(&response_bytes[..header_end])
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let header = |name: &str| {
        response
            .headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case(name))
            .and_then(|header| std::str::from_utf8(header.value).ok())
    };
    if response.code != Some(101)
        || !header("connection").is_some_and(|value| value.eq_ignore_ascii_case("upgrade"))
        || !header("upgrade").is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
        || header("sec-websocket-accept") != Some(expected_accept.as_str())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid WebSocket upgrade response",
        ));
    }
    let prefix = response_bytes.split_off(header_end);
    Ok(WebSocketStream::from_partially_read(stream, prefix, Role::Client, None).await)
}

impl AsyncRead for LazyWebSocketIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            match &mut this.state {
                LazyState::Pending { .. } => return Poll::Pending,
                LazyState::Upgrading(future) => match ready!(future.as_mut().poll(cx)) {
                    Ok((stream, _)) => this.state = LazyState::Connected(stream),
                    Err(error) => {
                        this.state = LazyState::Failed;
                        return Poll::Ready(Err(error));
                    }
                },
                LazyState::Connected(stream) => return Pin::new(stream).poll_read(cx, output),
                LazyState::Failed => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "v2ray-plugin WebSocket upgrade failed",
                    )));
                }
            }
        }
    }
}

impl AsyncWrite for LazyWebSocketIo {
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
            LazyState::Upgrading(future) => match ready!(future.as_mut().poll(cx)) {
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
            LazyState::Pending { .. } => unreachable!("lazy upgrade started above"),
            LazyState::Failed => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "v2ray-plugin WebSocket upgrade failed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            match &mut this.state {
                LazyState::Pending { .. } => return Poll::Ready(Ok(())),
                LazyState::Upgrading(future) => match ready!(future.as_mut().poll(cx)) {
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
                            .expect("pending lazy WebSocket retains stream"),
                    )
                    .poll_shutdown(cx);
                }
                LazyState::Upgrading(future) => match ready!(future.as_mut().poll(cx)) {
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

impl<S> AsyncRead for WebSocketIo<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.read_offset < this.read_buffer.len() {
                let available = &this.read_buffer[this.read_offset..];
                let length = available.len().min(output.remaining());
                output.put_slice(&available[..length]);
                this.read_offset += length;
                return Poll::Ready(Ok(()));
            }
            this.read_buffer = Bytes::new();
            this.read_offset = 0;
            match ready!(Pin::new(&mut this.stream).poll_next(cx)) {
                Some(Ok(Message::Binary(payload))) => this.read_buffer = payload,
                Some(Ok(Message::Text(payload))) => {
                    this.read_buffer = Bytes::copy_from_slice(payload.as_bytes());
                }
                Some(Ok(Message::Close(_))) | None => return Poll::Ready(Ok(())),
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                Some(Ok(Message::Frame(_))) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "v2ray-plugin WebSocket received a non-binary data message",
                    )));
                }
                Some(Err(error)) => return Poll::Ready(Err(io::Error::other(error))),
            }
        }
    }
}

impl<S> AsyncWrite for WebSocketIo<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.pending_write != 0 {
            ready!(Pin::new(&mut this.stream).poll_flush(cx)).map_err(io::Error::other)?;
            return Poll::Ready(Ok(std::mem::take(&mut this.pending_write)));
        }
        ready!(Pin::new(&mut this.stream).poll_ready(cx)).map_err(io::Error::other)?;
        Pin::new(&mut this.stream)
            .start_send(Message::Binary(Bytes::copy_from_slice(input)))
            .map_err(io::Error::other)?;
        this.pending_write = input.len();
        ready!(Pin::new(&mut this.stream).poll_flush(cx)).map_err(io::Error::other)?;
        Poll::Ready(Ok(std::mem::take(&mut this.pending_write)))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream)
            .poll_flush(cx)
            .map_err(io::Error::other)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream)
            .poll_close(cx)
            .map_err(io::Error::other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vmess_early_data_uses_named_header_or_path_before_query() {
        let mut header_request =
            websocket_request("example.test", 80, "/header", &BTreeMap::new(), None).unwrap();
        apply_early_data(
            &mut header_request,
            EarlyDataPlacement::Header(HeaderName::from_static("x-vmess-early")),
            "AQID",
        )
        .unwrap();
        assert_eq!(header_request.headers()["x-vmess-early"], "AQID");
        assert_eq!(header_request.uri().path_and_query().unwrap(), "/header");

        let mut path_request = websocket_request(
            "example.test",
            80,
            "/append?token=1",
            &BTreeMap::new(),
            None,
        )
        .unwrap();
        apply_early_data(&mut path_request, EarlyDataPlacement::Path, "AQID").unwrap();
        assert_eq!(
            path_request.uri().path_and_query().unwrap(),
            "/appendAQID?token=1"
        );
    }

    #[test]
    fn xray_early_data_query_is_removed_and_remaining_query_is_sorted() {
        assert_eq!(
            split_early_data_path("/ws?z=2&ed=64&a=1"),
            ("/ws?a=1&z=2".to_owned(), 64)
        );
    }
}
