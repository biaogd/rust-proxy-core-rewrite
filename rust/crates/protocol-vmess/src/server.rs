//! IN-E VMess AEAD server-side request Accept (`alterId = 0` only).
//!
//! Authenticates AuthID + AEAD request headers, validates the sing-vmess
//! ±120s timestamp window, and optionally rejects replayed AuthIDs.
//!
//! Note: the Go product listener calls `ServiceWithDisableHeaderProtection()`,
//! so product differentials may not exercise AuthID replay rejection even when
//! this optional cache is enabled.

use std::collections::{HashMap, VecDeque};
use std::hash::BuildHasher;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rewrite_io::BoxedStream;
use rewrite_model::Destination;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::body::{self, BodyOptions, BodyReader, BodyWriter};
use crate::header::{
    DEFAULT_TIMESTAMP_SKEW_SECS, VmessCommand, command_key, matches_legacy_alter_id_auth,
    read_aead_request_after_auth_id, seal_response_header, timestamp_within_skew,
    try_decode_auth_id,
};
use crate::{VmessProtocolError, VmessSecurity};

/// Default AuthID replay cache capacity (decoded AuthID plaintexts).
pub const DEFAULT_AUTH_ID_REPLAY_CAPACITY: usize = 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VmessUserEntry {
    pub username: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VmessServerRequest {
    pub command: VmessCommand,
    pub destination: Destination,
    pub username: String,
    pub uuid: [u8; 16],
    pub security: VmessSecurity,
    pub global_padding: bool,
    pub authenticated_length: bool,
}

/// Options for [`accept_vmess_request`].
///
/// The Go mihomo VMess inbound disables header protection, so enabling the
/// optional AuthID replay cache here may exceed what product differentials
/// cover today.
#[derive(Debug, Default)]
pub struct VmessAcceptOptions<'a> {
    /// Maximum accepted `|client_unix - server_unix|` in seconds (default 120).
    pub timestamp_skew_secs: Option<u64>,
    /// Optional bounded AuthID replay filter (TTL matches the timestamp window).
    pub replay_cache: Option<&'a mut AuthIdReplayCache>,
}

/// Bounded AuthID replay filter matching sing-vmess's simple 120s window.
///
/// Inserts decoded AuthID plaintexts; a duplicate within the TTL is rejected.
#[derive(Debug)]
pub struct AuthIdReplayCache {
    ttl: Duration,
    capacity: usize,
    order: VecDeque<([u8; 16], Instant)>,
    seen: HashMap<[u8; 16], Instant>,
}

impl AuthIdReplayCache {
    /// Creates a cache with `capacity` entries and a 120-second TTL.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self::with_ttl(capacity, Duration::from_secs(DEFAULT_TIMESTAMP_SKEW_SECS))
    }

    /// Creates a cache with an explicit TTL (primarily for tests).
    #[must_use]
    pub fn with_ttl(capacity: usize, ttl: Duration) -> Self {
        Self {
            ttl,
            capacity: capacity.max(1),
            order: VecDeque::new(),
            seen: HashMap::new(),
        }
    }

    /// Returns `true` when `decoded_auth_id` is new (and records it); `false` on replay.
    pub fn check_and_insert(&mut self, decoded_auth_id: [u8; 16]) -> bool {
        let now = Instant::now();
        self.reap(now);
        if self.seen.contains_key(&decoded_auth_id) {
            return false;
        }
        while self.seen.len() >= self.capacity {
            if let Some((oldest, _)) = self.order.pop_front() {
                self.seen.remove(&oldest);
            } else {
                break;
            }
        }
        self.seen.insert(decoded_auth_id, now);
        self.order.push_back((decoded_auth_id, now));
        true
    }

    fn reap(&mut self, now: Instant) {
        while let Some((id, inserted)) = self.order.front().copied() {
            if now.saturating_duration_since(inserted) < self.ttl {
                break;
            }
            self.order.pop_front();
            if self.seen.get(&id).copied() == Some(inserted) {
                self.seen.remove(&id);
            }
        }
    }
}

/// Maps a configured `uuid` field to the 16-byte VMess identifier.
///
/// Matches VLESS / sing-vmess: a valid UUID string is used as-is, otherwise the
/// text is folded into a stable v5 UUID (namespace nil).
#[must_use]
pub fn map_uuid(text: &str) -> [u8; 16] {
    Uuid::parse_str(text)
        .unwrap_or_else(|_| Uuid::new_v5(&Uuid::nil(), text.as_bytes()))
        .into_bytes()
}

/// Builds a lookup table from configured users to their 16-byte VMess UUIDs.
#[must_use]
pub fn uuid_table<'a>(
    users: impl IntoIterator<Item = (&'a str, VmessUserEntry)>,
) -> HashMap<[u8; 16], VmessUserEntry> {
    users
        .into_iter()
        .map(|(uuid, entry)| (map_uuid(uuid), entry))
        .collect()
}

/// Server session after a successful AEAD Accept.
///
/// Body directions are inverted relative to the client connector: reads decrypt
/// the client request stream; writes seal the server response stream (after the
/// AEAD response header).
pub struct VmessServerSession {
    body_reader: BodyReader,
    body_writer: BodyWriter,
    response_key: [u8; 16],
    response_iv: [u8; 16],
    response_verification: u8,
    request_options: u8,
    response_header_written: bool,
}

impl VmessServerSession {
    /// Writes the AEAD response header if it has not been written yet.
    ///
    /// # Errors
    ///
    /// Returns protocol or I/O errors when sealing/writing the header fails.
    pub async fn ensure_response_header<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
    ) -> Result<(), VmessProtocolError> {
        if self.response_header_written {
            return Ok(());
        }
        let wire = seal_response_header(
            &self.response_key,
            &self.response_iv,
            self.response_verification,
            self.request_options,
        )?;
        writer.write_all(&wire).await?;
        self.response_header_written = true;
        Ok(())
    }

    /// Reads and decrypts one request-direction body record.
    ///
    /// # Errors
    ///
    /// Returns I/O errors from the body reader.
    pub async fn read_body<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
    ) -> Result<Vec<u8>, VmessProtocolError> {
        Ok(self.body_reader.read_record(reader).await?)
    }

    /// Seals and writes one response-direction body record, writing the response
    /// header first when needed.
    ///
    /// # Errors
    ///
    /// Returns protocol or I/O errors from the response header or body writer.
    pub async fn write_body<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        plaintext: &[u8],
    ) -> Result<(), VmessProtocolError> {
        self.ensure_response_header(writer).await?;
        Ok(self.body_writer.write_record(writer, plaintext).await?)
    }

    /// Spawns an inverted TCP relay that presents a plaintext duplex to the
    /// caller, matching [`crate::connect_vmess_on_stream`] but with server body
    /// directions.
    #[must_use]
    pub fn into_tcp_relay(self, remote: BoxedStream) -> BoxedStream {
        let cancellation = CancellationToken::new();
        let (application, relay) = tokio::io::duplex(64 * 1024);
        let task_cancellation = cancellation.clone();
        let Self {
            body_reader,
            body_writer,
            response_key,
            response_iv,
            response_verification,
            request_options,
            response_header_written,
        } = self;
        tokio::spawn(async move {
            run_server_relay(
                remote,
                relay,
                body_reader,
                body_writer,
                response_key,
                response_iv,
                response_verification,
                request_options,
                response_header_written,
                task_cancellation,
            )
            .await;
        });
        Box::new(VmessServerRelayStream {
            inner: application,
            cancellation,
        })
    }
}

struct VmessServerRelayStream {
    inner: tokio::io::DuplexStream,
    cancellation: CancellationToken,
}

impl Drop for VmessServerRelayStream {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

impl AsyncRead for VmessServerRelayStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for VmessServerRelayStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_server_relay(
    remote: BoxedStream,
    relay: tokio::io::DuplexStream,
    mut body_reader: BodyReader,
    mut body_writer: BodyWriter,
    response_key: [u8; 16],
    response_iv: [u8; 16],
    response_verification: u8,
    request_options: u8,
    mut response_header_written: bool,
    cancellation: CancellationToken,
) {
    let (mut remote_read, mut remote_write) = tokio::io::split(remote);
    let (mut plain_read, mut plain_write) = tokio::io::split(relay);
    let read_cancellation = cancellation.clone();
    let write_cancellation = cancellation.clone();

    let read_loop = async {
        loop {
            let plaintext = tokio::select! {
                () = read_cancellation.cancelled() => break,
                result = body_reader.read_record(&mut remote_read) => match result {
                    Ok(plaintext) => plaintext,
                    Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => break,
                    Err(error) => return Err(error),
                },
            };
            plain_write.write_all(&plaintext).await?;
        }
        plain_write.shutdown().await
    };

    let write_loop = async {
        let mut buffer = vec![0_u8; BodyWriter::maximum_plaintext()];
        loop {
            let size = tokio::select! {
                () = write_cancellation.cancelled() => return Ok::<(), std::io::Error>(()),
                result = plain_read.read(&mut buffer) => result?,
            };
            if !response_header_written {
                let wire = seal_response_header(
                    &response_key,
                    &response_iv,
                    response_verification,
                    request_options,
                )
                .map_err(|error| std::io::Error::other(error.to_string()))?;
                remote_write.write_all(&wire).await?;
                response_header_written = true;
            }
            if size == 0 {
                remote_write.shutdown().await?;
                return Ok(());
            }
            body_writer
                .write_record(&mut remote_write, &buffer[..size])
                .await?;
        }
    };

    tokio::pin!(read_loop);
    tokio::pin!(write_loop);
    tokio::select! {
        () = cancellation.cancelled() => {}
        _ = &mut read_loop => cancellation.cancel(),
        write_result = &mut write_loop => {
            if write_result.is_err() {
                cancellation.cancel();
            } else {
                tokio::select! {
                    () = cancellation.cancelled() => {}
                    _ = &mut read_loop => {}
                }
            }
        }
    }
}

/// Reads and authenticates one VMess AEAD request header (`alterId = 0`).
///
/// Legacy `alterId > 0` headers are rejected with a clear protocol error when
/// detected. Timestamp skew defaults to ±120 seconds (sing-vmess).
///
/// # Errors
///
/// Returns [`VmessProtocolError::Protocol`] for unknown UUIDs, stale AuthIDs,
/// replays, legacy alterId, or malformed headers; [`VmessProtocolError::Io`]
/// for transport failures.
pub async fn accept_vmess_request<S, H>(
    stream: &mut S,
    users: &HashMap<[u8; 16], VmessUserEntry, H>,
    mut options: VmessAcceptOptions<'_>,
) -> Result<(VmessServerRequest, VmessServerSession), VmessProtocolError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    H: BuildHasher,
{
    let skew = options
        .timestamp_skew_secs
        .unwrap_or(DEFAULT_TIMESTAMP_SKEW_SECS);
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());

    let mut auth_id = [0_u8; 16];
    stream.read_exact(&mut auth_id).await?;

    let mut matched: Option<([u8; 16], VmessUserEntry, [u8; 16], [u8; 16])> = None;
    for (uuid, entry) in users {
        let key = command_key(uuid);
        if let Some(decoded) = try_decode_auth_id(&key, &auth_id)? {
            let timestamp = u64::from_be_bytes(
                decoded[..8]
                    .try_into()
                    .expect("AuthID timestamp is eight bytes"),
            );
            if !timestamp_within_skew(timestamp, now_secs, skew) {
                return Err(VmessProtocolError::Protocol(
                    "VMess AuthID timestamp outside allowed window".to_owned(),
                ));
            }
            if let Some(cache) = options.replay_cache.as_mut() {
                if !cache.check_and_insert(decoded) {
                    return Err(VmessProtocolError::Protocol(
                        "VMess AuthID replay detected".to_owned(),
                    ));
                }
            }
            matched = Some((*uuid, entry.clone(), key, decoded));
            break;
        }
    }

    let Some((uuid, user, key, decoded_auth_id)) = matched else {
        for uuid in users.keys() {
            if matches_legacy_alter_id_auth(uuid, &auth_id, now_secs, skew)? {
                return Err(VmessProtocolError::Protocol(
                    "VMess legacy alterId is not supported".to_owned(),
                ));
            }
        }
        return Err(VmessProtocolError::Protocol(
            "unknown VMess uuid".to_owned(),
        ));
    };

    let opened = read_aead_request_after_auth_id(stream, &key, auth_id, decoded_auth_id).await?;
    let chunked_none =
        opened.security == VmessSecurity::None && opened.command == VmessCommand::Udp;
    let (body_reader, body_writer, response_key, response_iv) = body::server_pair(
        opened.security,
        &opened.request_key,
        &opened.request_iv,
        BodyOptions {
            legacy_header: false,
            chunked_none,
            global_padding: opened.global_padding,
            authenticated_length: opened.authenticated_length,
        },
    );

    let request = VmessServerRequest {
        command: opened.command,
        destination: opened.destination,
        username: user.username,
        uuid,
        security: opened.security,
        global_padding: opened.global_padding,
        authenticated_length: opened.authenticated_length,
    };
    let session = VmessServerSession {
        body_reader,
        body_writer,
        response_key,
        response_iv,
        response_verification: opened.response_verification,
        request_options: opened.request_options,
        response_header_written: false,
    };
    Ok((request, session))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::{SealRequestOptions, seal_request_header, seal_request_header_at};
    use crate::{VmessClientOptions, connect_vmess_on_stream};
    use rewrite_model::Host;

    const UUID_TEXT: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    fn users() -> HashMap<[u8; 16], VmessUserEntry> {
        uuid_table([(
            UUID_TEXT,
            VmessUserEntry {
                username: "alice".to_owned(),
            },
        )])
    }

    #[test]
    fn map_uuid_parses_valid_uuid() {
        let mapped = map_uuid(UUID_TEXT);
        assert_eq!(mapped, Uuid::parse_str(UUID_TEXT).unwrap().into_bytes());
    }

    #[test]
    fn map_uuid_folds_non_uuid_text_deterministically() {
        assert_eq!(map_uuid("not-a-uuid"), map_uuid("not-a-uuid"));
        assert_ne!(map_uuid("not-a-uuid"), map_uuid("also-not-a-uuid"));
    }

    #[test]
    fn auth_id_replay_cache_rejects_duplicates_within_ttl() {
        let mut cache = AuthIdReplayCache::with_ttl(4, Duration::from_secs(60));
        let id = [0x11; 16];
        assert!(cache.check_and_insert(id));
        assert!(!cache.check_and_insert(id));
        assert!(cache.check_and_insert([0x22; 16]));
    }

    #[test]
    fn auth_id_replay_cache_is_capacity_bounded() {
        let mut cache = AuthIdReplayCache::with_ttl(2, Duration::from_secs(60));
        assert!(cache.check_and_insert([1; 16]));
        assert!(cache.check_and_insert([2; 16]));
        assert!(cache.check_and_insert([3; 16]));
        // Oldest entry was evicted by capacity.
        assert!(cache.check_and_insert([1; 16]));
    }

    #[tokio::test]
    async fn aead_roundtrip_client_seal_server_open_response() {
        let uuid = map_uuid(UUID_TEXT);
        let destination = Destination {
            host: Host::Domain("vmess-inbound.example".to_owned()),
            port: 443,
        };
        let expected_destination = destination.clone();
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        let client_task = tokio::spawn(async move {
            let options = VmessClientOptions {
                uuid,
                alter_id: 0,
                security: VmessSecurity::Aes128Gcm,
                global_padding: true,
                authenticated_length: true,
            };
            let mut stream = connect_vmess_on_stream(Box::new(client), &destination, options)
                .await
                .expect("client connect");
            stream.write_all(b"hello-from-client").await.unwrap();
            stream.flush().await.unwrap();
            let mut reply = vec![0_u8; 17];
            stream.read_exact(&mut reply).await.unwrap();
            reply
        });

        let (request, mut session) =
            accept_vmess_request(&mut server, &users(), VmessAcceptOptions::default())
                .await
                .expect("accept");
        assert_eq!(request.username, "alice");
        assert_eq!(request.uuid, uuid);
        assert_eq!(request.command, VmessCommand::Tcp);
        assert_eq!(request.destination, expected_destination);
        assert_eq!(request.security, VmessSecurity::Aes128Gcm);
        assert!(request.global_padding);
        assert!(request.authenticated_length);

        let plaintext = session.read_body(&mut server).await.expect("body");
        assert_eq!(plaintext, b"hello-from-client");
        session
            .write_body(&mut server, b"hello-from-server")
            .await
            .expect("response body");

        let reply = client_task.await.unwrap();
        assert_eq!(reply, b"hello-from-server");
    }

    #[tokio::test]
    async fn rejects_unknown_uuid() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let destination = Destination {
            host: Host::Ip("192.0.2.10".parse().unwrap()),
            port: 80,
        };
        tokio::spawn(async move {
            let sealed = seal_request_header(
                &[0xff; 16],
                &command_key(&[0xff; 16]),
                &destination,
                SealRequestOptions {
                    alter_id: 0,
                    security: VmessSecurity::Aes128Gcm,
                    command: VmessCommand::Tcp,
                    global_padding: false,
                    authenticated_length: false,
                },
            )
            .unwrap();
            let _ = client.write_all(&sealed.wire).await;
        });
        let error = accept_vmess_request(&mut server, &users(), VmessAcceptOptions::default())
            .await
            .err()
            .expect("unknown uuid");
        assert!(
            matches!(error, VmessProtocolError::Protocol(message) if message.contains("unknown"))
        );
    }

    #[tokio::test]
    async fn rejects_stale_timestamp() {
        let uuid = map_uuid(UUID_TEXT);
        let destination = Destination {
            host: Host::Ip("192.0.2.11".parse().unwrap()),
            port: 80,
        };
        let (mut client, mut server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let sealed = seal_request_header_at(
                &uuid,
                &command_key(&uuid),
                &destination,
                SealRequestOptions {
                    alter_id: 0,
                    security: VmessSecurity::ChaCha20Poly1305,
                    command: VmessCommand::Tcp,
                    global_padding: false,
                    authenticated_length: false,
                },
                now.saturating_sub(DEFAULT_TIMESTAMP_SKEW_SECS + 30),
            )
            .unwrap();
            let _ = client.write_all(&sealed.wire).await;
        });
        let error = accept_vmess_request(&mut server, &users(), VmessAcceptOptions::default())
            .await
            .err()
            .expect("stale timestamp");
        assert!(
            matches!(error, VmessProtocolError::Protocol(message) if message.contains("timestamp"))
        );
    }

    #[tokio::test]
    async fn rejects_replayed_auth_id_when_cache_enabled() {
        let uuid = map_uuid(UUID_TEXT);
        let destination = Destination {
            host: Host::Ip("192.0.2.12".parse().unwrap()),
            port: 80,
        };
        let sealed = seal_request_header(
            &uuid,
            &command_key(&uuid),
            &destination,
            SealRequestOptions {
                alter_id: 0,
                security: VmessSecurity::Aes128Gcm,
                command: VmessCommand::Tcp,
                global_padding: false,
                authenticated_length: false,
            },
        )
        .unwrap();

        let mut cache = AuthIdReplayCache::new(DEFAULT_AUTH_ID_REPLAY_CAPACITY);
        let (mut client1, mut server1) = tokio::io::duplex(4096);
        client1.write_all(&sealed.wire).await.unwrap();
        accept_vmess_request(
            &mut server1,
            &users(),
            VmessAcceptOptions {
                replay_cache: Some(&mut cache),
                ..VmessAcceptOptions::default()
            },
        )
        .await
        .expect("first accept");

        let (mut client2, mut server2) = tokio::io::duplex(4096);
        client2.write_all(&sealed.wire).await.unwrap();
        let error = accept_vmess_request(
            &mut server2,
            &users(),
            VmessAcceptOptions {
                replay_cache: Some(&mut cache),
                ..VmessAcceptOptions::default()
            },
        )
        .await
        .err()
        .expect("replay");
        assert!(
            matches!(error, VmessProtocolError::Protocol(message) if message.contains("replay"))
        );
    }

    #[tokio::test]
    async fn rejects_legacy_alter_id_with_clear_protocol_error() {
        let uuid = map_uuid(UUID_TEXT);
        let destination = Destination {
            host: Host::Domain("legacy.example".to_owned()),
            port: 9443,
        };
        let (mut client, mut server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            let sealed = seal_request_header(
                &uuid,
                &command_key(&uuid),
                &destination,
                SealRequestOptions {
                    alter_id: 64,
                    security: VmessSecurity::Aes128Gcm,
                    command: VmessCommand::Tcp,
                    global_padding: false,
                    authenticated_length: false,
                },
            )
            .unwrap();
            let _ = client.write_all(&sealed.wire).await;
        });
        let error = accept_vmess_request(&mut server, &users(), VmessAcceptOptions::default())
            .await
            .err()
            .expect("legacy alterId");
        assert!(
            matches!(error, VmessProtocolError::Protocol(message) if message.contains("alterId"))
        );
    }
}
