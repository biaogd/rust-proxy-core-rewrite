//! Client session and multiplexed streams for `AnyTLS`.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context, Poll};

use bytes::{Buf, Bytes, BytesMut};
use rewrite_io::BoxedStream;
use rewrite_model::Destination;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{Mutex, mpsc, oneshot};

use crate::frame::{
    CMD_ALERT, CMD_FIN, CMD_HEART_REQUEST, CMD_HEART_RESPONSE, CMD_PSH, CMD_SERVER_SETTINGS,
    CMD_SETTINGS, CMD_SYN, CMD_SYNACK, CMD_UPDATE_PADDING_SCHEME, CMD_WASTE, Frame,
    HEADER_OVERHEAD, MAX_FRAME_DATA_LEN, encode_settings, encode_socks_address,
};
use crate::padding::{CHECK_MARK, PaddingFactory};
use crate::{AnyTlsConnectOptions, AnyTlsProtocolError};

struct StreamInbox {
    sender: mpsc::UnboundedSender<Bytes>,
}

struct SessionInner {
    write: Mutex<WriteState>,
    streams: StdMutex<HashMap<u32, StreamInbox>>,
    padding: StdMutex<Arc<PaddingFactory>>,
    closed: AtomicBool,
    peer_version: AtomicU32,
    stream_id: AtomicU32,
    pkt_counter: AtomicU32,
    send_padding: AtomicBool,
    seq: u64,
    close_hook: StdMutex<Option<SessionCloseHook>>,
}

struct WriteState {
    remote: BoxedStream,
    buffering: bool,
    buffer: Vec<u8>,
}

type WriteFuture = Pin<Box<dyn Future<Output = Result<usize, std::io::Error>> + Send>>;

/// Callback invoked once when a stream fully closes (FIN sent / dropped).
pub type StreamCloseHook = Box<dyn FnOnce() + Send + Sync>;

/// Callback invoked once when the session closes.
pub type SessionCloseHook = Box<dyn FnOnce() + Send + Sync>;

/// Handle to a live `AnyTLS` session over one TLS carrier.
#[derive(Clone)]
pub struct Session {
    inner: Arc<SessionInner>,
}

/// Logical `AnyTLS` stream over a multiplexed session.
pub struct AnyTlsStream {
    session: Arc<SessionInner>,
    sid: u32,
    receiver: mpsc::UnboundedReceiver<Bytes>,
    pending: BytesMut,
    write_closed: bool,
    read_closed: bool,
    pending_write: Option<WriteFuture>,
    pending_shutdown: Option<WriteFuture>,
    close_hook: Option<StreamCloseHook>,
    reader_done: Option<oneshot::Receiver<()>>,
}

impl Session {
    /// Starts a client session on an authenticated TLS carrier.
    ///
    /// # Errors
    ///
    /// Returns I/O errors when the initial settings frame cannot be written.
    pub async fn start(
        remote: BoxedStream,
        client_metadata: &str,
        padding: Arc<PaddingFactory>,
        seq: u64,
    ) -> Result<Self, AnyTlsProtocolError> {
        let (read_half, write_half) = split_stream(remote);
        let inner = Arc::new(SessionInner {
            write: Mutex::new(WriteState {
                remote: write_half,
                buffering: true,
                buffer: Vec::new(),
            }),
            streams: StdMutex::new(HashMap::new()),
            padding: StdMutex::new(Arc::clone(&padding)),
            closed: AtomicBool::new(false),
            peer_version: AtomicU32::new(0),
            stream_id: AtomicU32::new(0),
            pkt_counter: AtomicU32::new(0),
            send_padding: AtomicBool::new(true),
            seq,
            close_hook: StdMutex::new(None),
        });

        let (done_tx, _done_rx) = oneshot::channel();
        let reader_session = Arc::clone(&inner);
        tokio::spawn(async move {
            recv_loop(reader_session, read_half).await;
            let _ = done_tx.send(());
        });

        let mut settings = Frame::new(CMD_SETTINGS, 0);
        settings.data = encode_settings(client_metadata, padding.md5());
        inner.write_control_frame(settings).await?;

        Ok(Self { inner })
    }

    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::Acquire)
    }

    #[must_use]
    pub fn seq(&self) -> u64 {
        self.inner.seq
    }

    pub fn set_close_hook(&self, hook: SessionCloseHook) {
        *self
            .inner
            .close_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(hook);
    }

    /// Opens a new multiplexed stream and writes the proxy destination.
    ///
    /// # Errors
    ///
    /// Returns protocol or I/O errors when the stream cannot be opened.
    pub async fn open_proxy(
        &self,
        destination: &Destination,
        close_hook: Option<StreamCloseHook>,
    ) -> Result<AnyTlsStream, AnyTlsProtocolError> {
        let mut stream = self.open_stream(close_hook).await?;
        let address = encode_socks_address(destination)?;
        // First proxy write flushes the session buffer (settings+SYN).
        {
            let mut guard = self.inner.write.lock().await;
            guard.buffering = false;
        }
        self.inner.write_data_frame(stream.sid, &address).await?;
        // Keep ownership of reader_done only on the first stream of a session when
        // created via open_proxy_stream; pooled sessions already have a reader.
        stream.reader_done = None;
        Ok(stream)
    }

    /// Opens a multiplexed stream without writing a destination yet.
    ///
    /// # Errors
    ///
    /// Returns protocol or I/O errors when SYN cannot be sent.
    pub async fn open_stream(
        &self,
        close_hook: Option<StreamCloseHook>,
    ) -> Result<AnyTlsStream, AnyTlsProtocolError> {
        if self.is_closed() {
            return Err(AnyTlsProtocolError::Protocol(
                "AnyTLS session is closed".to_owned(),
            ));
        }
        let sid = self.inner.stream_id.fetch_add(1, Ordering::AcqRel) + 1;
        let (sender, receiver) = mpsc::unbounded_channel();
        self.inner
            .streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(sid, StreamInbox { sender });
        self.inner
            .write_control_frame(Frame::new(CMD_SYN, sid))
            .await?;
        Ok(AnyTlsStream {
            session: Arc::clone(&self.inner),
            sid,
            receiver,
            pending: BytesMut::new(),
            write_closed: false,
            read_closed: false,
            pending_write: None,
            pending_shutdown: None,
            close_hook,
            reader_done: None,
        })
    }

    /// Closes the underlying TLS session.
    pub async fn close(&self) {
        mark_session_closed(&self.inner).await;
    }
}

async fn mark_session_closed(inner: &Arc<SessionInner>) {
    if inner
        .closed
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    let hook = inner
        .close_hook
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    {
        let mut guard = inner.write.lock().await;
        let _ = guard.remote.shutdown().await;
    }
    let inboxes: Vec<_> = inner
        .streams
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .drain()
        .map(|(_, inbox)| inbox)
        .collect();
    for inbox in inboxes {
        let _ = inbox.sender.send(Bytes::new());
    }
    if let Some(hook) = hook {
        hook();
    }
}

impl Drop for AnyTlsStream {
    fn drop(&mut self) {
        let hook = self.close_hook.take();
        let session = Arc::clone(&self.session);
        let sid = self.sid;
        let need_fin = !self.write_closed;
        self.write_closed = true;
        tokio::spawn(async move {
            if need_fin {
                let _ = session.write_control_frame(Frame::new(CMD_FIN, sid)).await;
            }
            session
                .streams
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&sid);
        });
        if let Some(hook) = hook {
            hook();
        }
    }
}

impl AsyncRead for AnyTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.read_closed {
            return Poll::Ready(Ok(()));
        }
        if !self.pending.is_empty() {
            let amount = buffer.remaining().min(self.pending.len());
            buffer.put_slice(&self.pending[..amount]);
            self.pending.advance(amount);
            return Poll::Ready(Ok(()));
        }
        match self.receiver.poll_recv(context) {
            Poll::Ready(Some(chunk)) => {
                if chunk.is_empty() {
                    self.read_closed = true;
                    return Poll::Ready(Ok(()));
                }
                let amount = buffer.remaining().min(chunk.len());
                buffer.put_slice(&chunk[..amount]);
                if amount < chunk.len() {
                    self.pending.extend_from_slice(&chunk[amount..]);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => {
                self.read_closed = true;
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for AnyTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.write_closed {
            return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        }
        if self.pending_write.is_none() {
            let session = Arc::clone(&self.session);
            let sid = self.sid;
            let payload = buffer.to_vec();
            let accepted = buffer.len();
            self.pending_write = Some(Box::pin(async move {
                session
                    .write_data_frame(sid, &payload)
                    .await
                    .map_err(|error| std::io::Error::other(error.to_string()))?;
                Ok(accepted)
            }));
        }
        match self
            .pending_write
            .as_mut()
            .expect("pending write installed")
            .as_mut()
            .poll(context)
        {
            Poll::Ready(result) => {
                self.pending_write = None;
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.write_closed {
            return Poll::Ready(Ok(()));
        }
        if self.pending_shutdown.is_none() {
            let session = Arc::clone(&self.session);
            let sid = self.sid;
            // CloseWrite semantics: send FIN, keep reading until peer FIN/EOF.
            self.pending_shutdown = Some(Box::pin(async move {
                session
                    .write_control_frame(Frame::new(CMD_FIN, sid))
                    .await
                    .map_err(|error| std::io::Error::other(error.to_string()))?;
                Ok(0)
            }));
        }
        match self
            .pending_shutdown
            .as_mut()
            .expect("pending shutdown installed")
            .as_mut()
            .poll(context)
        {
            Poll::Ready(Ok(_)) => {
                self.pending_shutdown = None;
                self.write_closed = true;
                // Half-close only: keep the stream mapped and do not run the
                // pool dieHook until the stream is fully dropped (Go has no
                // CloseWrite; pool return is on full Close).
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => {
                self.pending_shutdown = None;
                Poll::Ready(Err(error))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl SessionInner {
    async fn write_control_frame(&self, frame: Frame) -> Result<(), AnyTlsProtocolError> {
        let encoded = frame.encode();
        self.write_conn(&encoded).await
    }

    async fn write_data_frame(&self, sid: u32, data: &[u8]) -> Result<(), AnyTlsProtocolError> {
        if data.is_empty() {
            return Ok(());
        }
        if data.len() <= MAX_FRAME_DATA_LEN {
            let mut frame = Frame::new(CMD_PSH, sid);
            frame.data = data.to_vec();
            return self.write_conn(&frame.encode()).await;
        }
        let mut encoded = Vec::with_capacity(data.len() + HEADER_OVERHEAD * 4);
        let mut offset = 0;
        while offset < data.len() {
            let end = (offset + MAX_FRAME_DATA_LEN).min(data.len());
            let mut frame = Frame::new(CMD_PSH, sid);
            frame.data = data[offset..end].to_vec();
            encoded.extend_from_slice(&frame.encode());
            offset = end;
        }
        self.write_conn(&encoded).await
    }

    async fn write_conn(&self, payload: &[u8]) -> Result<(), AnyTlsProtocolError> {
        let mut guard = self.write.lock().await;
        if guard.buffering {
            guard.buffer.extend_from_slice(payload);
            return Ok(());
        }
        if !guard.buffer.is_empty() {
            let mut combined = std::mem::take(&mut guard.buffer);
            combined.extend_from_slice(payload);
            return write_conn_locked(self, &mut guard, &combined).await;
        }
        write_conn_locked(self, &mut guard, payload).await
    }
}

async fn write_conn_locked(
    session: &SessionInner,
    guard: &mut WriteState,
    mut payload: &[u8],
) -> Result<(), AnyTlsProtocolError> {
    if session.send_padding.load(Ordering::Acquire) {
        let pkt = session.pkt_counter.fetch_add(1, Ordering::AcqRel) + 1;
        let padding = session
            .padding
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if pkt < padding.stop() {
            for size in padding.generate_record_payload_sizes(pkt) {
                let remain = payload.len();
                if size == CHECK_MARK {
                    if remain == 0 {
                        break;
                    }
                    continue;
                }
                let size = usize::try_from(size).unwrap_or(0);
                if remain > size {
                    guard.remote.write_all(&payload[..size]).await?;
                    payload = &payload[size..];
                } else if remain > 0 {
                    let padding_len = size.saturating_sub(remain + HEADER_OVERHEAD);
                    let mut packet = payload.to_vec();
                    if padding_len > 0 {
                        let mut waste = vec![0_u8; HEADER_OVERHEAD + padding_len];
                        waste[0] = CMD_WASTE;
                        waste[5..7].copy_from_slice(
                            &u16::try_from(padding_len).unwrap_or(u16::MAX).to_be_bytes(),
                        );
                        packet.extend_from_slice(&waste);
                    }
                    guard.remote.write_all(&packet).await?;
                    payload = &[];
                } else {
                    let mut waste = vec![0_u8; HEADER_OVERHEAD + size];
                    waste[0] = CMD_WASTE;
                    waste[5..7]
                        .copy_from_slice(&u16::try_from(size).unwrap_or(u16::MAX).to_be_bytes());
                    guard.remote.write_all(&waste).await?;
                }
            }
            if payload.is_empty() {
                return Ok(());
            }
            guard.remote.write_all(payload).await?;
            return Ok(());
        }
        session.send_padding.store(false, Ordering::Release);
    }
    guard.remote.write_all(payload).await?;
    Ok(())
}

async fn recv_loop(session: Arc<SessionInner>, mut remote_read: BoxedStream) {
    let mut header = [0_u8; HEADER_OVERHEAD];
    loop {
        if session.closed.load(Ordering::Acquire) {
            break;
        }
        if let Err(error) = remote_read.read_exact(&mut header).await {
            let _ = error;
            break;
        }
        let cmd = header[0];
        let sid = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
        let length = usize::from(u16::from_be_bytes([header[5], header[6]]));
        let mut data = vec![0_u8; length];
        if length > 0
            && let Err(error) = remote_read.read_exact(&mut data).await
        {
            let _ = error;
            break;
        }
        match cmd {
            CMD_PSH if !data.is_empty() => {
                let sender = session
                    .streams
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get(&sid)
                    .map(|inbox| inbox.sender.clone());
                if let Some(sender) = sender {
                    let _ = sender.send(Bytes::from(data));
                }
            }
            CMD_FIN => {
                if let Some(inbox) = session
                    .streams
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&sid)
                {
                    let _ = inbox.sender.send(Bytes::new());
                }
            }
            CMD_SYNACK => {
                if !data.is_empty()
                    && let Some(inbox) = session
                        .streams
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .remove(&sid)
                {
                    let _ = inbox.sender.send(Bytes::new());
                }
            }
            CMD_ALERT => break,
            CMD_UPDATE_PADDING_SCHEME => {
                if let Some(factory) = PaddingFactory::new(&data) {
                    *session
                        .padding
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(factory);
                }
            }
            CMD_HEART_REQUEST => {
                let _ = session
                    .write_control_frame(Frame::new(CMD_HEART_RESPONSE, sid))
                    .await;
            }
            CMD_SERVER_SETTINGS => {
                if let Some(version) = parse_settings_version(&data) {
                    session.peer_version.store(version, Ordering::Release);
                }
            }
            _ => {}
        }
    }
    mark_session_closed(&session).await;
}

fn parse_settings_version(data: &[u8]) -> Option<u32> {
    for line in String::from_utf8_lossy(data).lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key == "v" {
            return value.parse().ok();
        }
    }
    None
}

fn split_stream(remote: BoxedStream) -> (BoxedStream, BoxedStream) {
    let (read, write) = tokio::io::split(remote);
    (
        Box::new(ReadHalfStream(read)),
        Box::new(WriteHalfStream(write)),
    )
}

struct ReadHalfStream(tokio::io::ReadHalf<BoxedStream>);
struct WriteHalfStream(tokio::io::WriteHalf<BoxedStream>);

impl AsyncRead for ReadHalfStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(context, buffer)
    }
}

impl AsyncWrite for ReadHalfStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        _buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Ready(Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "read half does not support write",
        )))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for WriteHalfStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        _buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "write half does not support read",
        )))
    }
}

impl AsyncWrite for WriteHalfStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(context)
    }
}

/// Opens a one-shot `AnyTLS` proxy stream on an established TLS carrier.
pub async fn open_proxy_stream(
    remote: BoxedStream,
    destination: &Destination,
    options: &AnyTlsConnectOptions<'_>,
) -> Result<BoxedStream, AnyTlsProtocolError> {
    let padding = options
        .padding
        .clone()
        .unwrap_or_else(PaddingFactory::default_factory);
    let session = Session::start(remote, options.client_metadata, padding, 1).await?;
    let session_for_hook = session.clone();
    let close_hook: StreamCloseHook = Box::new(move || {
        tokio::spawn(async move {
            session_for_hook.close().await;
        });
    });
    let stream = session.open_proxy(destination, Some(close_hook)).await?;
    Ok(Box::new(stream))
}
