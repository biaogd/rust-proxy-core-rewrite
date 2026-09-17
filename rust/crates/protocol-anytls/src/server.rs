//! Server-side `AnyTLS` authentication and multiplexed session handling.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::hash::BuildHasher;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex as StdMutex, Weak};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use rewrite_io::BoxedStream;
use rewrite_model::Destination;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{Mutex, Notify, mpsc, oneshot};
use tokio::task::AbortHandle;

use crate::AnyTlsProtocolError;
use crate::frame::{
    CMD_ALERT, CMD_FIN, CMD_HEART_REQUEST, CMD_HEART_RESPONSE, CMD_PSH, CMD_SERVER_SETTINGS,
    CMD_SETTINGS, CMD_SYN, CMD_SYNACK, CMD_UPDATE_PADDING_SCHEME, Frame, HEADER_OVERHEAD,
    MAX_FRAME_DATA_LEN, encode_psh_payload,
};
use crate::padding::SharedPadding;

/// Cap matching Go's synchronous pipe: one in-flight payload stalls `recvLoop`.
const STREAM_RECV_CAPACITY: usize = 1;

/// Bound pending streams waiting for the runtime accept loop (backpressure).
const STREAM_DISPATCH_CAPACITY: usize = 16;

/// Hard cap on concurrent logical streams per authenticated session.
const MAX_SERVER_STREAMS: usize = 256;

/// Matches Go `writeControlFrame` write deadline (`time.Second * 5`).
const WRITE_DEADLINE: Duration = Duration::from_secs(5);

/// Bound for acquiring the write lock / dropping the carrier during `Close`.
const CLOSE_DEADLINE: Duration = Duration::from_secs(5);

enum StreamEvent {
    Data(Bytes),
}

/// Shared remote-termination state for a stream (Go `Stream.dieErr`).
struct StreamTerminus {
    die_err: StdMutex<Option<(std::io::ErrorKind, String)>>,
}

impl StreamTerminus {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            die_err: StdMutex::new(None),
        })
    }

    fn fail(&self, kind: std::io::ErrorKind, message: impl Into<String>) {
        let mut guard = self
            .die_err
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.is_none() {
            *guard = Some((kind, message.into()));
        }
    }

    fn error(&self) -> Option<std::io::Error> {
        self.die_err
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(|(kind, message)| std::io::Error::new(*kind, message.clone()))
    }
}

struct StreamInbox {
    sender: mpsc::Sender<StreamEvent>,
    terminus: Arc<StreamTerminus>,
}

struct ServerSessionInner {
    weak_self: StdMutex<Weak<ServerSessionInner>>,
    write: Mutex<WriteState>,
    streams: StdMutex<HashMap<u32, StreamInbox>>,
    padding: SharedPadding,
    closed: AtomicBool,
    close_complete: AtomicBool,
    peer_version: AtomicU32,
    /// Dropped on session close so the runtime `stream_rx` observes `None`.
    stream_tx: StdMutex<Option<mpsc::Sender<ServerStream>>>,
    close_notify: Notify,
    close_wait: Notify,
    reader_abort: StdMutex<Option<AbortHandle>>,
    write_deadline: Duration,
}

struct WriteState {
    remote: BoxedStream,
}

type WriteFuture = Pin<Box<dyn Future<Output = Result<usize, std::io::Error>> + Send>>;

/// Builds a password-digest lookup table keyed by SHA-256 of each password.
#[must_use]
pub fn password_digest_table(
    users: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
) -> HashMap<[u8; 32], String> {
    users
        .into_iter()
        .map(|(username, password)| {
            let digest = Sha256::digest(password.into().as_bytes());
            let mut key = [0_u8; 32];
            key.copy_from_slice(&digest);
            (key, username.into())
        })
        .collect()
}

/// Reads the post-TLS authentication blob and resolves the username.
///
/// Returns `Ok(None)` when the password digest is unknown (caller should drop
/// the connection). Returns `Ok(Some(username))` on success.
///
/// # Errors
///
/// Returns I/O or protocol errors when the authentication blob is malformed.
pub async fn authenticate_connection<S>(
    stream: &mut (impl AsyncRead + Unpin),
    users: &HashMap<[u8; 32], String, S>,
) -> Result<Option<String>, AnyTlsProtocolError>
where
    S: BuildHasher,
{
    let mut digest = [0_u8; 32];
    stream.read_exact(&mut digest).await?;
    let username = match users.get(&digest) {
        Some(name) => name.clone(),
        None => return Ok(None),
    };
    let mut len_bytes = [0_u8; 2];
    stream.read_exact(&mut len_bytes).await?;
    let padding_len = usize::from(u16::from_be_bytes(len_bytes));
    if padding_len > 0 {
        let mut padding = vec![0_u8; padding_len];
        stream.read_exact(&mut padding).await?;
    }
    Ok(Some(username))
}

/// Decodes a SOCKS-style destination address from `buf`.
///
/// # Errors
///
/// Returns protocol errors when the buffer is truncated or malformed.
pub fn decode_socks_address(buf: &[u8]) -> Result<(Destination, usize), AnyTlsProtocolError> {
    crate::frame::decode_socks_address(buf)
}

/// Handle to a live server-side `AnyTLS` session over one TLS carrier.
pub struct ServerSession {
    inner: Arc<ServerSessionInner>,
    close_wait: oneshot::Receiver<()>,
}

/// Logical inbound `AnyTLS` stream over a multiplexed server session.
pub struct ServerStream {
    session: Arc<ServerSessionInner>,
    sid: u32,
    receiver: mpsc::Receiver<StreamEvent>,
    terminus: Arc<StreamTerminus>,
    pending: BytesMut,
    write_closed: bool,
    read_closed: bool,
    pending_write: Option<WriteFuture>,
    pending_shutdown: Option<WriteFuture>,
    handshake_reported: bool,
}

impl ServerSession {
    /// Starts the server recv loop and returns a receiver for inbound streams.
    #[must_use]
    pub fn start(
        remote: BoxedStream,
        padding: SharedPadding,
    ) -> (Self, mpsc::Receiver<ServerStream>) {
        let (stream_tx, stream_rx) = mpsc::channel(STREAM_DISPATCH_CAPACITY);
        let (close_tx, close_wait) = oneshot::channel();
        let (read_half, write_half) = split_stream(remote);
        let inner = Arc::new(ServerSessionInner {
            weak_self: StdMutex::new(Weak::new()),
            write: Mutex::new(WriteState { remote: write_half }),
            streams: StdMutex::new(HashMap::new()),
            padding,
            closed: AtomicBool::new(false),
            close_complete: AtomicBool::new(false),
            peer_version: AtomicU32::new(0),
            stream_tx: StdMutex::new(Some(stream_tx)),
            close_notify: Notify::new(),
            close_wait: Notify::new(),
            reader_abort: StdMutex::new(None),
            write_deadline: WRITE_DEADLINE,
        });
        *inner
            .weak_self
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::downgrade(&inner);

        let reader_session = Arc::clone(&inner);
        let join = tokio::spawn(async move {
            recv_loop(reader_session, read_half).await;
            let _ = close_tx.send(());
        });
        *inner
            .reader_abort
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(join.abort_handle());

        (Self { inner, close_wait }, stream_rx)
    }

    /// Waits until the recv loop has finished and carrier teardown completed.
    pub async fn closed(&mut self) {
        let _ = (&mut self.close_wait).await;
        wait_for_close_complete(&self.inner).await;
    }

    /// Waits until session teardown has completed (does not require `&mut self`).
    ///
    /// Unlike [`Self::closed`], this does not time out — suitable for `select!`
    /// loops that must observe peer disconnect without a false-positive wake.
    pub async fn wait_closed(&self) {
        if self.inner.close_complete.load(Ordering::Acquire) {
            return;
        }
        let notified = self.inner.close_wait.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if self.inner.close_complete.load(Ordering::Acquire) {
            return;
        }
        notified.await;
    }

    /// Closes the underlying TLS session.
    pub fn close(&self) {
        request_session_close(Arc::clone(&self.inner));
    }
}

impl Drop for ServerSession {
    fn drop(&mut self) {
        // Abort paths and early returns must still tear down the recv loop and
        // carrier; finalize runs on a detached task so abort cannot cancel it.
        request_session_close(Arc::clone(&self.inner));
    }
}

impl ServerStream {
    /// Reports successful proxy setup to the client (empty SYNACK when v>=2).
    ///
    /// # Errors
    ///
    /// Returns protocol or I/O errors when the SYNACK frame cannot be written.
    pub async fn handshake_success(&mut self) -> Result<(), AnyTlsProtocolError> {
        if self.handshake_reported {
            return Ok(());
        }
        self.handshake_reported = true;
        if self.session.peer_version.load(Ordering::Acquire) >= 2 {
            self.session
                .write_control_frame(Frame::new(CMD_SYNACK, self.sid))
                .await?;
        }
        Ok(())
    }
}

impl AsyncRead for ServerStream {
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
                    if let Some(error) = self.terminus.error() {
                        return Poll::Ready(Err(error));
                    }
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
                if let Some(error) = self.terminus.error() {
                    Poll::Ready(Err(error))
                } else {
                    Poll::Ready(Ok(()))
                }
            }
            Poll::Pending => {
                if let Some(error) = self.terminus.error() {
                    self.read_closed = true;
                    Poll::Ready(Err(error))
                } else {
                    Poll::Pending
                }
            }
        }
    }
}

impl AsyncWrite for ServerStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.write_closed {
            return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        }
        if self.pending_write.is_none() {
            if let Some(error) = self.terminus.error() {
                self.write_closed = true;
                return Poll::Ready(Err(error));
            }
            let session = Arc::clone(&self.session);
            // Encode once in poll_write so the async path only does write_conn.
            let encoded = encode_psh_payload(self.sid, buffer);
            let accepted = buffer.len();
            self.pending_write = Some(Box::pin(async move {
                session
                    .write_encoded(encoded)
                    .await
                    .map_err(|error| std::io::Error::other(error.to_string()))?;
                Ok(accepted)
            }));
        } else if self.terminus.error().is_some() {
            schedule_close_from_inner(&self.session);
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

impl Drop for ServerStream {
    fn drop(&mut self) {
        let abandoned_write = self.pending_write.take().is_some();
        let abandoned_shutdown = self.pending_shutdown.take().is_some();
        if abandoned_write || abandoned_shutdown {
            schedule_close_from_inner(&self.session);
        }
        let session = Arc::clone(&self.session);
        let sid = self.sid;
        let need_fin = !self.write_closed && !abandoned_shutdown;
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
    }
}

impl ServerSessionInner {
    async fn write_control_frame(&self, frame: Frame) -> Result<(), AnyTlsProtocolError> {
        self.write_conn(&frame.encode()).await
    }

    async fn write_encoded(&self, encoded: Vec<u8>) -> Result<(), AnyTlsProtocolError> {
        if encoded.is_empty() {
            return Ok(());
        }
        self.write_conn(&encoded).await
    }

    async fn write_conn(&self, payload: &[u8]) -> Result<(), AnyTlsProtocolError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(AnyTlsProtocolError::Protocol(
                "AnyTLS session is closed".to_owned(),
            ));
        }
        let result = {
            let mut guard = self.write.lock().await;
            if self.closed.load(Ordering::Acquire) {
                Err(AnyTlsProtocolError::Protocol(
                    "AnyTLS session is closed".to_owned(),
                ))
            } else {
                write_all_cancellable(self, &mut guard.remote, payload).await
            }
        };
        if result.is_err() {
            schedule_close_from_inner(self);
        }
        result
    }
}

fn request_session_close(inner: Arc<ServerSessionInner>) {
    if inner
        .closed
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    inner.close_notify.notify_waiters();
    tokio::spawn(async move {
        finalize_session_close(inner).await;
    });
}

async fn finalize_session_close(inner: Arc<ServerSessionInner>) {
    if let Some(handle) = inner
        .reader_abort
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
    {
        handle.abort();
    }
    // Drop the dispatch sender so runtime `stream_rx.recv()` returns `None` and
    // connection tasks can exit (freeing inbound connection slots).
    {
        let _ = inner
            .stream_tx
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
    }
    {
        let inboxes: Vec<_> = inner
            .streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .drain()
            .map(|(_, inbox)| inbox)
            .collect();
        for inbox in inboxes {
            inbox
                .terminus
                .fail(std::io::ErrorKind::ConnectionReset, "AnyTLS session closed");
        }
    }
    if let Ok(mut guard) = tokio::time::timeout(CLOSE_DEADLINE, inner.write.lock()).await {
        guard.remote = Box::new(ClosedStream);
    }
    inner.close_complete.store(true, Ordering::Release);
    inner.close_wait.notify_waiters();
}

async fn wait_for_close_complete(inner: &ServerSessionInner) {
    if inner.close_complete.load(Ordering::Acquire) {
        return;
    }
    let notified = inner.close_wait.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();
    if inner.close_complete.load(Ordering::Acquire) {
        return;
    }
    let _ = tokio::time::timeout(CLOSE_DEADLINE + Duration::from_secs(1), notified).await;
}

fn schedule_close_from_inner(inner: &ServerSessionInner) {
    let Some(arc) = inner
        .weak_self
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .upgrade()
    else {
        return;
    };
    request_session_close(arc);
}

async fn write_all_cancellable(
    session: &ServerSessionInner,
    remote: &mut BoxedStream,
    payload: &[u8],
) -> Result<(), AnyTlsProtocolError> {
    if session.closed.load(Ordering::Acquire) {
        return Err(AnyTlsProtocolError::Protocol(
            "AnyTLS session is closed".to_owned(),
        ));
    }
    let notified = session.close_notify.notified();
    tokio::pin!(notified);
    notified.as_mut().enable();
    tokio::select! {
        result = tokio::time::timeout(session.write_deadline, remote.write_all(payload)) => {
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

enum RecvAction {
    Continue,
    Stop,
}

async fn recv_loop(session: Arc<ServerSessionInner>, mut remote_read: BoxedStream) {
    let mut header = [0_u8; HEADER_OVERHEAD];
    let mut received_settings = false;
    loop {
        if session.closed.load(Ordering::Acquire) {
            break;
        }
        if remote_read.read_exact(&mut header).await.is_err() {
            break;
        }
        let cmd = header[0];
        let sid = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
        let length = usize::from(u16::from_be_bytes([header[5], header[6]]));
        if length > MAX_FRAME_DATA_LEN {
            break;
        }
        let mut data = vec![0_u8; length];
        if length > 0 && remote_read.read_exact(&mut data).await.is_err() {
            break;
        }
        let action = match cmd {
            CMD_SETTINGS => {
                received_settings = true;
                handle_settings_frame(&session, &data).await
            }
            CMD_SYN => handle_syn_frame(&session, sid, received_settings).await,
            CMD_PSH if !data.is_empty() => {
                handle_psh_frame(&session, sid, data).await;
                RecvAction::Continue
            }
            CMD_FIN => {
                handle_fin_frame(&session, sid);
                RecvAction::Continue
            }
            CMD_HEART_REQUEST => {
                let _ = session
                    .write_control_frame(Frame::new(CMD_HEART_RESPONSE, sid))
                    .await;
                RecvAction::Continue
            }
            CMD_ALERT => RecvAction::Stop,
            _ => RecvAction::Continue,
        };
        if matches!(action, RecvAction::Stop) {
            break;
        }
    }
    request_session_close(session);
}

async fn handle_settings_frame(session: &ServerSessionInner, data: &[u8]) -> RecvAction {
    if data.is_empty() {
        return RecvAction::Continue;
    }
    let settings = string_map_from_bytes(data);
    let local_md5 = session
        .padding
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .md5()
        .to_owned();
    if settings.get("padding-md5").map(String::as_str) != Some(local_md5.as_str()) {
        let raw_scheme = session
            .padding
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .raw_scheme()
            .to_vec();
        let mut frame = Frame::new(CMD_UPDATE_PADDING_SCHEME, 0);
        frame.data = raw_scheme;
        if session.write_control_frame(frame).await.is_err() {
            return RecvAction::Stop;
        }
    }
    if let Some(version) = settings
        .get("v")
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|version| *version >= 2)
    {
        session.peer_version.store(version, Ordering::Release);
        let mut frame = Frame::new(CMD_SERVER_SETTINGS, 0);
        frame.data = b"v=2".to_vec();
        if session.write_control_frame(frame).await.is_err() {
            return RecvAction::Stop;
        }
    }
    RecvAction::Continue
}

async fn handle_syn_frame(
    session: &Arc<ServerSessionInner>,
    sid: u32,
    received_settings: bool,
) -> RecvAction {
    if !received_settings {
        let mut frame = Frame::new(CMD_ALERT, 0);
        frame.data = b"client did not send its settings".to_vec();
        let _ = session.write_control_frame(frame).await;
        return RecvAction::Stop;
    }
    let (sender, receiver) = mpsc::channel(STREAM_RECV_CAPACITY);
    let terminus = StreamTerminus::new();
    let insert_result = {
        let mut streams = session
            .streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if streams.contains_key(&sid) {
            InsertSyn::Duplicate
        } else if streams.len() >= MAX_SERVER_STREAMS {
            InsertSyn::AtCapacity
        } else {
            streams.insert(
                sid,
                StreamInbox {
                    sender,
                    terminus: Arc::clone(&terminus),
                },
            );
            InsertSyn::Inserted
        }
    };
    match insert_result {
        InsertSyn::Duplicate => return RecvAction::Continue,
        InsertSyn::AtCapacity => {
            let mut frame = Frame::new(CMD_ALERT, 0);
            frame.data = b"too many streams".to_vec();
            let _ = session.write_control_frame(frame).await;
            return RecvAction::Stop;
        }
        InsertSyn::Inserted => {}
    }
    let stream = ServerStream {
        session: Arc::clone(session),
        sid,
        receiver,
        terminus,
        pending: BytesMut::new(),
        write_closed: false,
        read_closed: false,
        pending_write: None,
        pending_shutdown: None,
        handshake_reported: false,
    };
    // Await in the recv loop (no spawn) so channel capacity back-pressures SYN
    // intake instead of unbounded dispatch tasks.
    let tx = session
        .stream_tx
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    if let Some(tx) = tx {
        let _ = tx.send(stream).await;
    }
    RecvAction::Continue
}

enum InsertSyn {
    Duplicate,
    AtCapacity,
    Inserted,
}

async fn handle_psh_frame(session: &ServerSessionInner, sid: u32, data: Vec<u8>) {
    let sender = session
        .streams
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(&sid)
        .map(|inbox| inbox.sender.clone());
    if let Some(sender) = sender {
        let _ = sender.send(StreamEvent::Data(Bytes::from(data))).await;
    }
}

fn handle_fin_frame(session: &ServerSessionInner, sid: u32) {
    if let Some(inbox) = session
        .streams
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(&sid)
    {
        inbox.terminus.fail(
            std::io::ErrorKind::ConnectionReset,
            "AnyTLS stream closed by peer",
        );
    }
}

fn string_map_from_bytes(raw: &[u8]) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for line in String::from_utf8_lossy(raw).lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        map.insert(key.to_owned(), value.to_owned());
    }
    map
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{
        CMD_PSH, CMD_SERVER_SETTINGS, CMD_SETTINGS, CMD_SYN, CMD_SYNACK, HEADER_OVERHEAD,
        encode_settings, encode_socks_address,
    };
    use crate::padding::PaddingFactory;
    use rewrite_model::Host;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    fn frame(cmd: u8, sid: u32, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_OVERHEAD + data.len());
        out.push(cmd);
        out.extend_from_slice(&sid.to_be_bytes());
        out.extend_from_slice(&(u16::try_from(data.len()).unwrap()).to_be_bytes());
        out.extend_from_slice(data);
        out
    }

    #[test]
    fn password_digest_table_maps_sha256_keys() {
        let table = password_digest_table([("alice", "secret"), ("bob", "other")]);
        let alice_digest = Sha256::digest(b"secret");
        let mut key = [0_u8; 32];
        key.copy_from_slice(&alice_digest);
        assert_eq!(table.get(&key), Some(&"alice".to_owned()));
        assert_eq!(table.len(), 2);
    }

    #[tokio::test]
    async fn authenticate_connection_round_trip() {
        let table = password_digest_table([("user1", "pass1")]);
        let padding = PaddingFactory::default_factory();
        let auth = crate::authentication_blob("pass1", &padding);
        let (mut client, mut server) = duplex(4096);
        client.write_all(&auth).await.expect("write auth");
        let username = authenticate_connection(&mut server, &table)
            .await
            .expect("auth")
            .expect("known user");
        assert_eq!(username, "user1");
    }

    #[tokio::test]
    async fn authenticate_connection_unknown_password_returns_none() {
        let table = password_digest_table([("user1", "pass1")]);
        let padding = PaddingFactory::default_factory();
        let auth = crate::authentication_blob("wrong", &padding);
        let (mut client, mut server) = duplex(4096);
        client.write_all(&auth).await.expect("write auth");
        let username = authenticate_connection(&mut server, &table)
            .await
            .expect("auth");
        assert!(username.is_none());
    }

    #[test]
    fn decode_socks_address_round_trip() {
        let destinations = [
            Destination {
                host: Host::Domain("example.com".to_owned()),
                port: 443,
            },
            Destination {
                host: Host::Ip("127.0.0.1".parse().expect("ipv4")),
                port: 8080,
            },
            Destination {
                host: Host::Ip("::1".parse().expect("ipv6")),
                port: 53,
            },
        ];
        for destination in destinations {
            let encoded = encode_socks_address(&destination).expect("encode");
            let (decoded, consumed) = decode_socks_address(&encoded).expect("decode");
            assert_eq!(consumed, encoded.len());
            assert_eq!(decoded, destination);
        }
    }

    #[tokio::test]
    async fn minimal_server_session_delivers_stream_and_payload() {
        let padding = Arc::new(std::sync::Mutex::new(PaddingFactory::default_factory()));
        let padding_md5 = padding.lock().unwrap().md5().to_owned();
        let (client, server) = duplex(64 * 1024);
        let (session, mut stream_rx) = ServerSession::start(Box::new(server), Arc::clone(&padding));

        let client_task = tokio::spawn(async move {
            let mut client = client;
            let settings = encode_settings("test-client", &padding_md5);
            client
                .write_all(&frame(CMD_SETTINGS, 0, &settings))
                .await
                .expect("settings");
            let mut header = [0_u8; HEADER_OVERHEAD];
            client
                .read_exact(&mut header)
                .await
                .expect("server settings hdr");
            assert_eq!(header[0], CMD_SERVER_SETTINGS);
            let length = usize::from(u16::from_be_bytes([header[5], header[6]]));
            if length > 0 {
                let mut body = vec![0_u8; length];
                client
                    .read_exact(&mut body)
                    .await
                    .expect("server settings body");
            }
            client
                .write_all(&frame(CMD_SYN, 1, &[]))
                .await
                .expect("syn");
            let destination = Destination {
                host: Host::Domain("example.com".to_owned()),
                port: 443,
            };
            let addr = encode_socks_address(&destination).expect("addr");
            client
                .write_all(&frame(CMD_PSH, 1, &addr))
                .await
                .expect("addr");
            client
                .write_all(&frame(CMD_PSH, 1, b"hello"))
                .await
                .expect("payload");
            client.read_exact(&mut header).await.expect("synack hdr");
            assert_eq!(header[0], CMD_SYNACK);
            let length = usize::from(u16::from_be_bytes([header[5], header[6]]));
            assert_eq!(length, 0);
            client.read_exact(&mut header).await.expect("psh hdr");
            assert_eq!(header[0], CMD_PSH);
            let length = usize::from(u16::from_be_bytes([header[5], header[6]]));
            let mut payload = vec![0_u8; length];
            client.read_exact(&mut payload).await.expect("psh body");
            assert_eq!(&payload, b"world");
        });

        let mut stream = stream_rx.recv().await.expect("stream delivered");
        let mut addr_buf = [0_u8; 256];
        let n = stream.read(&mut addr_buf).await.expect("read addr");
        let (destination, _) = decode_socks_address(&addr_buf[..n]).expect("decode addr");
        assert_eq!(destination.port, 443);
        stream.handshake_success().await.expect("handshake");
        let mut payload = [0_u8; 8];
        let n = stream.read(&mut payload).await.expect("read payload");
        assert_eq!(&payload[..n], b"hello");
        stream.write_all(b"world").await.expect("write response");
        client_task.await.expect("client task");
        session.close();
    }

    #[tokio::test]
    async fn session_close_unblocks_stream_receiver() {
        let padding = Arc::new(std::sync::Mutex::new(PaddingFactory::default_factory()));
        let (client, server) = duplex(4096);
        let (mut session, mut stream_rx) =
            ServerSession::start(Box::new(server), Arc::clone(&padding));
        drop(client);
        tokio::time::timeout(Duration::from_secs(2), session.closed())
            .await
            .expect("session closed");
        let next = tokio::time::timeout(Duration::from_secs(2), stream_rx.recv())
            .await
            .expect("stream receiver must unblock after session close");
        assert!(
            next.is_none(),
            "dispatch channel must close on session teardown"
        );
    }

    #[tokio::test]
    async fn dropping_server_session_closes_peer() {
        let padding = Arc::new(std::sync::Mutex::new(PaddingFactory::default_factory()));
        let (mut client, server) = duplex(4096);
        let (session, stream_rx) = ServerSession::start(Box::new(server), Arc::clone(&padding));
        drop(stream_rx);
        drop(session);
        let mut buf = [0_u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf))
            .await
            .expect("peer must observe EOF after session drop");
        assert_eq!(read.expect("read"), 0);
    }

    #[tokio::test]
    async fn syn_beyond_stream_cap_stops_session() {
        let padding = Arc::new(std::sync::Mutex::new(PaddingFactory::default_factory()));
        let padding_md5 = padding.lock().unwrap().md5().to_owned();
        let (mut client, server) = duplex(64 * 1024);
        let (mut session, mut stream_rx) =
            ServerSession::start(Box::new(server), Arc::clone(&padding));

        let settings = encode_settings("test-client", &padding_md5);
        client
            .write_all(&frame(CMD_SETTINGS, 0, &settings))
            .await
            .expect("settings");
        let mut header = [0_u8; HEADER_OVERHEAD];
        client
            .read_exact(&mut header)
            .await
            .expect("server settings hdr");
        assert_eq!(header[0], CMD_SERVER_SETTINGS);
        let length = usize::from(u16::from_be_bytes([header[5], header[6]]));
        if length > 0 {
            let mut body = vec![0_u8; length];
            client
                .read_exact(&mut body)
                .await
                .expect("server settings body");
        }

        // Hold delivered streams so map entries stay alive up to the cap.
        let mut held = Vec::new();
        for sid in 1..=u32::try_from(MAX_SERVER_STREAMS).expect("sid") {
            client
                .write_all(&frame(CMD_SYN, sid, &[]))
                .await
                .expect("syn");
            let stream = tokio::time::timeout(Duration::from_secs(2), stream_rx.recv())
                .await
                .expect("dispatch")
                .expect("stream");
            held.push(stream);
        }
        client
            .write_all(&frame(
                CMD_SYN,
                u32::try_from(MAX_SERVER_STREAMS + 1).expect("sid"),
                &[],
            ))
            .await
            .expect("overflow syn");
        client.read_exact(&mut header).await.expect("alert hdr");
        assert_eq!(header[0], crate::frame::CMD_ALERT);
        tokio::time::timeout(Duration::from_secs(2), session.closed())
            .await
            .expect("session closed after stream cap");
        drop(held);
    }
}
