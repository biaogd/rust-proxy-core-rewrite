//! Client session and multiplexed streams for `AnyTLS`.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use rewrite_io::BoxedStream;
use rewrite_model::Destination;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{Mutex, Notify, mpsc, oneshot};
use tokio::task::AbortHandle;

use crate::frame::{
    CMD_ALERT, CMD_FIN, CMD_HEART_REQUEST, CMD_HEART_RESPONSE, CMD_PSH, CMD_SERVER_SETTINGS,
    CMD_SETTINGS, CMD_SYN, CMD_SYNACK, CMD_UPDATE_PADDING_SCHEME, CMD_WASTE, Frame,
    HEADER_OVERHEAD, MAX_FRAME_DATA_LEN, encode_settings, encode_socks_address,
};
use crate::padding::{CHECK_MARK, PaddingFactory, SharedPadding};
use crate::{AnyTlsConnectOptions, AnyTlsProtocolError};

/// Cap matching Go's synchronous pipe: one in-flight payload stalls `recvLoop`.
const STREAM_RECV_CAPACITY: usize = 1;

/// Matches Go `writeControlFrame` write deadline (`time.Second * 5`).
const WRITE_DEADLINE: Duration = Duration::from_secs(5);

/// Bound for acquiring the write lock / dropping the carrier during `Close`.
const CLOSE_DEADLINE: Duration = Duration::from_secs(5);

/// Matches Go `util.NewDeadlineWatcher(time.Second*3, ...)` for SYNACK.
const SYNACK_WATCHDOG: Duration = Duration::from_secs(3);

enum StreamEvent {
    Data(Bytes),
    Error(String),
}

struct StreamInbox {
    sender: mpsc::Sender<StreamEvent>,
}

struct SessionInner {
    write: Mutex<WriteState>,
    streams: StdMutex<HashMap<u32, StreamInbox>>,
    padding: SharedPadding,
    closed: AtomicBool,
    peer_version: AtomicU32,
    stream_id: AtomicU32,
    pkt_counter: AtomicU32,
    send_padding: AtomicBool,
    seq: u64,
    close_hook: StdMutex<Option<SessionCloseHook>>,
    close_notify: Notify,
    reader_abort: StdMutex<Option<AbortHandle>>,
    syn_done: StdMutex<Option<AbortHandle>>,
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
    receiver: mpsc::Receiver<StreamEvent>,
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
        padding: SharedPadding,
        seq: u64,
    ) -> Result<Self, AnyTlsProtocolError> {
        let padding_md5 = padding
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .md5()
            .to_owned();
        let (read_half, write_half) = split_stream(remote);
        let inner = Arc::new(SessionInner {
            write: Mutex::new(WriteState {
                remote: write_half,
                buffering: true,
                buffer: Vec::new(),
            }),
            streams: StdMutex::new(HashMap::new()),
            padding,
            closed: AtomicBool::new(false),
            peer_version: AtomicU32::new(0),
            stream_id: AtomicU32::new(0),
            pkt_counter: AtomicU32::new(0),
            send_padding: AtomicBool::new(true),
            seq,
            close_hook: StdMutex::new(None),
            close_notify: Notify::new(),
            reader_abort: StdMutex::new(None),
            syn_done: StdMutex::new(None),
        });

        let (done_tx, _done_rx) = oneshot::channel();
        let reader_session = Arc::clone(&inner);
        let join = tokio::spawn(async move {
            recv_loop(reader_session, read_half).await;
            let _ = done_tx.send(());
        });
        *inner
            .reader_abort
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(join.abort_handle());

        let mut settings = Frame::new(CMD_SETTINGS, 0);
        settings.data = encode_settings(client_metadata, &padding_md5);
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
        let (sender, receiver) = mpsc::channel(STREAM_RECV_CAPACITY);
        self.inner
            .streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(sid, StreamInbox { sender });

        let peer_version = self.inner.peer_version.load(Ordering::Acquire);
        if sid >= 2 && peer_version >= 2 {
            arm_synack_watchdog(&self.inner);
        }

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

fn arm_synack_watchdog(inner: &Arc<SessionInner>) {
    let mut guard = inner
        .syn_done
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(previous) = guard.take() {
        previous.abort();
    }
    let session = Arc::clone(inner);
    let join = tokio::spawn(async move {
        tokio::time::sleep(SYNACK_WATCHDOG).await;
        mark_session_closed(&session).await;
    });
    *guard = Some(join.abort_handle());
}

fn cancel_synack_watchdog(inner: &SessionInner) {
    if let Some(handle) = inner
        .syn_done
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
    {
        handle.abort();
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
    // Wake any write stalled on a non-reading peer (Go `SetDeadline(now)`).
    inner.close_notify.notify_waiters();
    cancel_synack_watchdog(inner);
    if let Some(handle) = inner
        .reader_abort
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
    {
        handle.abort();
    }
    let hook = inner
        .close_hook
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    // Drop stream senders so readers observe EOF/error without waiting on a
    // blocked write half.
    {
        let _inboxes: Vec<_> = inner
            .streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .drain()
            .map(|(_, inbox)| inbox)
            .collect();
    }
    if let Ok(mut guard) = tokio::time::timeout(CLOSE_DEADLINE, inner.write.lock()).await {
        // Prefer dropping the write half over awaiting shutdown forever.
        guard.remote = Box::new(ClosedStream);
        guard.buffer.clear();
        guard.buffering = false;
    } else {
        // Write lock stuck past deadline; close_notify should have woken the
        // writer. Remaining cleanup is best-effort via closed flag.
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
            Poll::Ready(Some(StreamEvent::Data(chunk))) => {
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
            Poll::Ready(Some(StreamEvent::Error(message))) => {
                self.read_closed = true;
                Poll::Ready(Err(std::io::Error::other(message)))
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
        if self.closed.load(Ordering::Acquire) {
            return Err(AnyTlsProtocolError::Protocol(
                "AnyTLS session is closed".to_owned(),
            ));
        }
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
                    write_all_cancellable(session, &mut guard.remote, &payload[..size]).await?;
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
                    write_all_cancellable(session, &mut guard.remote, &packet).await?;
                    payload = &[];
                } else {
                    let mut waste = vec![0_u8; HEADER_OVERHEAD + size];
                    waste[0] = CMD_WASTE;
                    waste[5..7]
                        .copy_from_slice(&u16::try_from(size).unwrap_or(u16::MAX).to_be_bytes());
                    write_all_cancellable(session, &mut guard.remote, &waste).await?;
                }
            }
            if payload.is_empty() {
                return Ok(());
            }
            write_all_cancellable(session, &mut guard.remote, payload).await?;
            return Ok(());
        }
        session.send_padding.store(false, Ordering::Release);
    }
    write_all_cancellable(session, &mut guard.remote, payload).await
}

async fn write_all_cancellable(
    session: &SessionInner,
    remote: &mut BoxedStream,
    payload: &[u8],
) -> Result<(), AnyTlsProtocolError> {
    if session.closed.load(Ordering::Acquire) {
        return Err(AnyTlsProtocolError::Protocol(
            "AnyTLS session is closed".to_owned(),
        ));
    }
    // Arm notify before racing so a concurrent close cannot be missed.
    let notified = session.close_notify.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();
    tokio::select! {
        result = tokio::time::timeout(WRITE_DEADLINE, remote.write_all(payload)) => {
            match result {
                Ok(Ok(())) => Ok(()),
                Ok(Err(error)) => Err(AnyTlsProtocolError::Io(error)),
                Err(_) => Err(AnyTlsProtocolError::Protocol(
                    "AnyTLS write deadline exceeded".to_owned(),
                )),
            }
        }
        () = notified => Err(AnyTlsProtocolError::Protocol(
            "AnyTLS session is closed".to_owned(),
        )),
    }
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
                    // Awaitable send provides Go pipe backpressure.
                    if sender
                        .send(StreamEvent::Data(Bytes::from(data)))
                        .await
                        .is_err()
                    {
                        // Stream gone; drop payload.
                    }
                }
            }
            CMD_FIN => {
                let _ = session
                    .streams
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&sid);
            }
            CMD_SYNACK => {
                cancel_synack_watchdog(&session);
                if !data.is_empty() {
                    let reason = format!("remote: {}", String::from_utf8_lossy(&data));
                    if let Some(inbox) = session
                        .streams
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .remove(&sid)
                    {
                        let _ = inbox.sender.try_send(StreamEvent::Error(reason));
                    }
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
struct ClosedStream;

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
            "write half does not support write",
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

impl AsyncRead for ClosedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        _buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ClosedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        _buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
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

/// Opens a one-shot `AnyTLS` proxy stream on an established TLS carrier.
pub async fn open_proxy_stream(
    remote: BoxedStream,
    destination: &Destination,
    options: &AnyTlsConnectOptions<'_>,
) -> Result<BoxedStream, AnyTlsProtocolError> {
    let padding = options
        .padding
        .clone()
        .unwrap_or_else(crate::padding::default_shared_padding);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{
        CMD_PSH, CMD_SERVER_SETTINGS, CMD_SYNACK, CMD_UPDATE_PADDING_SCHEME, HEADER_OVERHEAD,
    };
    use rewrite_model::Host;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    fn frame(cmd: u8, sid: u32, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_OVERHEAD + data.len());
        out.push(cmd);
        out.extend_from_slice(&sid.to_be_bytes());
        out.extend_from_slice(&(u16::try_from(data.len()).unwrap()).to_be_bytes());
        out.extend_from_slice(data);
        out
    }

    async fn drain_settings(server: &mut tokio::io::DuplexStream) {
        let mut header = [0_u8; HEADER_OVERHEAD];
        let _ = server.read_exact(&mut header).await;
        let length = usize::from(u16::from_be_bytes([header[5], header[6]]));
        if length > 0 {
            let mut body = vec![0_u8; length];
            let _ = server.read_exact(&mut body).await;
        }
    }

    async fn flush_buffered(session: &Session) {
        let mut guard = session.inner.write.lock().await;
        guard.buffering = false;
        if !guard.buffer.is_empty() {
            let buffered = std::mem::take(&mut guard.buffer);
            write_conn_locked(&session.inner, &mut guard, &buffered)
                .await
                .expect("flush");
        }
    }

    #[tokio::test]
    async fn slow_consumer_applies_recv_backpressure() {
        let (client, mut server) = duplex(64 * 1024);
        let padding = Arc::new(StdMutex::new(PaddingFactory::default_factory()));
        let session = Session::start(Box::new(client), "test", Arc::clone(&padding), 1)
            .await
            .expect("session");
        flush_buffered(&session).await;
        let peer = tokio::spawn(async move {
            drain_settings(&mut server).await;
            let _ = server
                .write_all(&frame(CMD_SERVER_SETTINGS, 0, b"v=2"))
                .await;
            // Wait for SYN (stream 1).
            let mut header = [0_u8; HEADER_OVERHEAD];
            let _ = server.read_exact(&mut header).await;
            let length = usize::from(u16::from_be_bytes([header[5], header[6]]));
            if length > 0 {
                let mut body = vec![0_u8; length];
                let _ = server.read_exact(&mut body).await;
            }
            // Flood two PSH payloads; capacity is 1 so the second send awaits.
            for payload in [b"one".as_slice(), b"two".as_slice(), b"three".as_slice()] {
                let _ = server.write_all(&frame(CMD_PSH, 1, payload)).await;
            }
            // Keep the carrier open until the test finishes.
            let mut sink = vec![0_u8; 64];
            let _ = server.read(&mut sink).await;
        });

        let mut stream = session.open_stream(None).await.expect("stream");
        flush_buffered(&session).await;
        // Give recv_loop time to enqueue the first PSH and block on the second.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut first = [0_u8; 8];
        let n = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut first))
            .await
            .expect("read1 timeout")
            .expect("read1");
        assert_eq!(&first[..n], b"one");
        let n = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut first))
            .await
            .expect("read2 timeout")
            .expect("read2");
        assert_eq!(&first[..n], b"two");
        let n = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut first))
            .await
            .expect("read3 timeout")
            .expect("read3");
        assert_eq!(&first[..n], b"three");
        drop(stream);
        session.close().await;
        let _ = peer.await;
    }

    #[tokio::test]
    async fn close_completes_when_peer_neither_reads_nor_closes() {
        // Tiny duplex buffer so writes block once the peer stops reading.
        let (client, server) = duplex(8);
        let padding = Arc::new(StdMutex::new(PaddingFactory::default_factory()));
        let session = Session::start(Box::new(client), "hang", Arc::clone(&padding), 1)
            .await
            .expect("session");
        // Consume initial buffered SETTINGS from the client write buffer flush
        // path by opening a stream (disables buffering) then flooding writes.
        let peer = tokio::spawn(async move {
            // Never read; never close.
            std::future::pending::<()>().await;
            drop(server);
        });

        {
            let mut guard = session.inner.write.lock().await;
            guard.buffering = false;
        }
        let session_write = session.clone();
        let writer = tokio::spawn(async move {
            // Attempt a large write that will stall on the tiny duplex.
            let payload = vec![0x61_u8; 64 * 1024];
            let mut frame = Frame::new(CMD_PSH, 1);
            frame.data = payload;
            let _ = session_write.inner.write_control_frame(frame).await;
        });

        tokio::time::sleep(Duration::from_millis(20)).await;
        tokio::time::timeout(Duration::from_secs(2), session.close())
            .await
            .expect("close must finish while peer is stuck");
        assert!(session.is_closed());
        writer.abort();
        peer.abort();
    }

    #[tokio::test]
    async fn synack_reject_surfaces_remote_reason() {
        let (client, mut server) = duplex(64 * 1024);
        let padding = Arc::new(StdMutex::new(PaddingFactory::default_factory()));
        let session = Session::start(Box::new(client), "reject", Arc::clone(&padding), 1)
            .await
            .expect("session");
        flush_buffered(&session).await;
        let peer = tokio::spawn(async move {
            drain_settings(&mut server).await;
            let _ = server
                .write_all(&frame(CMD_SERVER_SETTINGS, 0, b"v=2"))
                .await;
            let mut header = [0_u8; HEADER_OVERHEAD];
            let _ = server.read_exact(&mut header).await;
            let length = usize::from(u16::from_be_bytes([header[5], header[6]]));
            if length > 0 {
                let mut body = vec![0_u8; length];
                let _ = server.read_exact(&mut body).await;
            }
            let _ = server
                .write_all(&frame(CMD_SYNACK, 1, b"destination refused"))
                .await;
            let mut sink = vec![0_u8; 32];
            let _ = server.read(&mut sink).await;
        });

        let mut stream = session.open_stream(None).await.expect("stream");
        flush_buffered(&session).await;
        let mut buffer = [0_u8; 8];
        let error = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buffer))
            .await
            .expect("timeout")
            .expect_err("reject must surface as read error");
        assert!(
            error.to_string().contains("remote: destination refused"),
            "unexpected error: {error}"
        );
        drop(stream);
        session.close().await;
        let _ = peer.await;
    }

    #[tokio::test]
    async fn missing_synack_closes_session_for_v2_reuse() {
        let (client, mut server) = duplex(64 * 1024);
        let padding = Arc::new(StdMutex::new(PaddingFactory::default_factory()));
        let session = Session::start(Box::new(client), "watchdog", Arc::clone(&padding), 1)
            .await
            .expect("session");
        flush_buffered(&session).await;
        let peer = tokio::spawn(async move {
            drain_settings(&mut server).await;
            let _ = server
                .write_all(&frame(CMD_SERVER_SETTINGS, 0, b"v=2"))
                .await;
            // Consume SYN frames but never send SYNACK.
            let mut sink = vec![0_u8; 4096];
            loop {
                match server.read(&mut sink).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        });

        // Stream 1 has no watchdog; stream 2 arms the 3s timer.
        let stream1 = session.open_stream(None).await.expect("s1");
        flush_buffered(&session).await;
        drop(stream1);
        tokio::task::yield_now().await;
        // Ensure peer_version is visible before opening stream 2.
        for _ in 0..50 {
            if session.inner.peer_version.load(Ordering::Acquire) >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            session.inner.peer_version.load(Ordering::Acquire) >= 2,
            "peer version must be recorded before stream 2"
        );
        let _stream2 = session.open_stream(None).await.expect("s2");
        flush_buffered(&session).await;
        tokio::time::timeout(Duration::from_secs(5), async {
            while !session.is_closed() {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("missing SYNACK must close session");
        session.close().await;
        let _ = peer.await;
    }

    #[tokio::test]
    async fn padding_update_is_shared_with_client_for_new_auth() {
        let shared = Arc::new(StdMutex::new(PaddingFactory::default_factory()));
        let before = shared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .md5()
            .to_owned();
        let scheme = b"stop=1\n0=16-16";
        let updated = PaddingFactory::new(scheme).expect("scheme");
        *shared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(updated);
        let after = shared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .md5()
            .to_owned();
        assert_ne!(before, after);
        let blob = crate::authentication_blob("pw", &shared.lock().unwrap().clone());
        // 32 hash + 2 len + 16 padding
        assert_eq!(blob.len(), 32 + 2 + 16);
    }

    #[tokio::test]
    async fn padding_update_frame_mutates_shared_factory() {
        let (client, mut server) = duplex(64 * 1024);
        let shared = Arc::new(StdMutex::new(PaddingFactory::default_factory()));
        let before = shared.lock().unwrap().md5().to_owned();
        let session = Session::start(Box::new(client), "pad", Arc::clone(&shared), 1)
            .await
            .expect("session");
        flush_buffered(&session).await;
        let scheme = b"stop=1\n0=16-16";
        let peer = tokio::spawn(async move {
            drain_settings(&mut server).await;
            let _ = server
                .write_all(&frame(CMD_UPDATE_PADDING_SCHEME, 0, scheme))
                .await;
            let mut sink = vec![0_u8; 32];
            let _ = server.read(&mut sink).await;
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let current = shared.lock().unwrap().md5().to_owned();
                if current != before {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("padding update must land on shared factory");
        session.close().await;
        let _ = peer.await;
    }

    #[tokio::test]
    async fn open_proxy_destination_smoke() {
        let (client, mut server) = duplex(64 * 1024);
        let padding = Arc::new(StdMutex::new(PaddingFactory::default_factory()));
        let session = Session::start(Box::new(client), "proxy", Arc::clone(&padding), 1)
            .await
            .expect("session");
        // open_proxy flushes SETTINGS+SYN+addr; peer waits for that traffic.
        let peer = tokio::spawn(async move {
            drain_settings(&mut server).await;
            let mut sink = vec![0_u8; 4096];
            let _ = server.read(&mut sink).await;
        });
        let destination = Destination {
            host: Host::Domain("example.com".to_owned()),
            port: 443,
        };
        let stream = session.open_proxy(&destination, None).await.expect("proxy");
        drop(stream);
        session.close().await;
        let _ = peer.await;
    }
}
