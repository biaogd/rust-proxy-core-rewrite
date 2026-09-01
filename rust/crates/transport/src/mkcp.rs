//! `V2Ray` mKCP byte-stream transport.
//!
//! This is intentionally not backed by a generic KCP crate: `V2Ray` mKCP has a
//! different segment format, authentication envelope and camouflage headers.

#![allow(clippy::cast_possible_truncation, clippy::struct_excessive_bools)]

use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use rand::RngExt as _;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::BoxedStream;

const DATA_OVERHEAD: usize = 18;
const COMMAND_ACK: u8 = 0;
const COMMAND_DATA: u8 = 1;
const COMMAND_TERMINATE: u8 = 2;
const COMMAND_PING: u8 = 3;
const MAX_ACKS: usize = 128;

static NEXT_CONVERSATION: AtomicU32 = AtomicU32::new(1);

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MkcpConfig {
    pub mtu: u32,
    pub tti: u32,
    pub uplink_capacity: u32,
    pub downlink_capacity: u32,
    pub congestion: bool,
    pub write_buffer: u32,
    pub read_buffer: u32,
    pub seed: String,
    pub header: String,
}

impl MkcpConfig {
    fn mtu(&self) -> u32 {
        if self.mtu == 0 { 1350 } else { self.mtu }
    }

    fn tti(&self) -> u32 {
        if self.tti == 0 { 50 } else { self.tti }
    }

    fn uplink_capacity(&self) -> u32 {
        if self.uplink_capacity == 0 {
            5
        } else {
            self.uplink_capacity
        }
    }

    fn downlink_capacity(&self) -> u32 {
        if self.downlink_capacity == 0 {
            20
        } else {
            self.downlink_capacity
        }
    }

    fn write_buffer(&self) -> u32 {
        if self.write_buffer == 0 {
            2 * 1024 * 1024
        } else {
            self.write_buffer
        }
    }

    fn read_buffer(&self) -> u32 {
        if self.read_buffer == 0 {
            2 * 1024 * 1024
        } else {
            self.read_buffer
        }
    }

    fn flight_size(capacity: u32, mtu: u32, tti: u32) -> u32 {
        let intervals = (1000 / tti.max(1)).max(1);
        (capacity.saturating_mul(1024 * 1024) / mtu.max(1) / intervals).max(8)
    }

    fn sending_flight_size(&self) -> u32 {
        Self::flight_size(self.uplink_capacity(), self.mtu(), self.tti())
    }

    fn receiving_flight_size(&self) -> u32 {
        Self::flight_size(self.downlink_capacity(), self.mtu(), self.tti())
    }

    fn sending_buffer_size(&self) -> usize {
        (self.write_buffer() / self.mtu().max(1)).max(1) as usize
    }
}

pub(crate) type PacketFuture<'a, T> = Pin<Box<dyn Future<Output = io::Result<T>> + Send + 'a>>;

pub(crate) trait PacketEndpoint: Send + Sync + 'static {
    fn send<'a>(&'a self, packet: &'a [u8]) -> PacketFuture<'a, usize>;
    fn recv<'a>(&'a self, packet: &'a mut [u8]) -> PacketFuture<'a, usize>;
}

struct UdpEndpoint(UdpSocket);

impl PacketEndpoint for UdpEndpoint {
    fn send<'a>(&'a self, packet: &'a [u8]) -> PacketFuture<'a, usize> {
        Box::pin(self.0.send(packet))
    }

    fn recv<'a>(&'a self, packet: &'a mut [u8]) -> PacketFuture<'a, usize> {
        Box::pin(self.0.recv(packet))
    }
}

/// Turns a connected UDP socket into a V2Ray-compatible mKCP byte stream.
///
/// # Errors
///
/// Returns an error when the configured seed cannot initialize AES-GCM.
pub fn connect_mkcp(socket: UdpSocket, config: MkcpConfig) -> io::Result<BoxedStream> {
    connect_mkcp_endpoint(Arc::new(UdpEndpoint(socket)), config)
}

pub(crate) fn connect_mkcp_endpoint(
    endpoint: Arc<dyn PacketEndpoint>,
    config: MkcpConfig,
) -> io::Result<BoxedStream> {
    let conversation = NEXT_CONVERSATION.fetch_add(1, Ordering::Relaxed) as u16;
    connect_with_conversation(endpoint, config, conversation)
}

fn connect_with_conversation(
    endpoint: Arc<dyn PacketEndpoint>,
    config: MkcpConfig,
    conversation: u16,
) -> io::Result<BoxedStream> {
    let codec = PacketCodec::new(&config)?;
    let capacity = usize::try_from(config.write_buffer().max(config.read_buffer()))
        .unwrap_or(2 * 1024 * 1024)
        .clamp(64 * 1024, 8 * 1024 * 1024);
    let (application, engine_stream) = tokio::io::duplex(capacity);
    let (mut application_reader, mut application_writer) = tokio::io::split(engine_stream);
    let (outgoing_tx, outgoing_rx) = mpsc::channel::<ApplicationEvent>(256);
    let (incoming_tx, mut incoming_rx) = mpsc::channel::<Vec<u8>>(256);

    let reader_tx = outgoing_tx;
    tokio::spawn(async move {
        let mut buffer = vec![0_u8; 64 * 1024];
        loop {
            match application_reader.read(&mut buffer).await {
                Ok(0) | Err(_) => {
                    let _ = reader_tx.send(ApplicationEvent::Closed).await;
                    break;
                }
                Ok(length) => {
                    if reader_tx
                        .send(ApplicationEvent::Data(buffer[..length].to_vec()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    });
    tokio::spawn(async move {
        while let Some(payload) = incoming_rx.recv().await {
            if application_writer.write_all(&payload).await.is_err() {
                return;
            }
        }
        let _ = application_writer.shutdown().await;
    });
    tokio::spawn(run_engine(
        endpoint,
        config,
        conversation,
        codec,
        outgoing_rx,
        incoming_tx,
    ));
    Ok(Box::new(application))
}

enum ApplicationEvent {
    Data(Vec<u8>),
    Closed,
}

#[derive(Clone)]
struct DataSegment {
    number: u32,
    payload: Vec<u8>,
    timeout: u32,
    transmit: u32,
}

struct AckItem {
    number: u32,
    timestamp: u32,
    next_flush: u32,
}

enum Segment {
    Data {
        option: u8,
        timestamp: u32,
        number: u32,
        sending_next: u32,
        payload: Vec<u8>,
    },
    Ack {
        option: u8,
        receiving_window: u32,
        receiving_next: u32,
        timestamp: u32,
        numbers: Vec<u32>,
    },
    Command {
        command: u8,
        option: u8,
        sending_next: u32,
        receiving_next: u32,
        peer_rto: u32,
    },
}

struct Engine {
    config: MkcpConfig,
    conversation: u16,
    started: Instant,
    mss: usize,
    rto: u32,
    last_ping: u32,
    send_next: u32,
    recv_next: u32,
    remote_recv_window: u32,
    send_window: VecDeque<DataSegment>,
    pending_application: VecDeque<Vec<u8>>,
    pending_offset: usize,
    recv_cache: BTreeMap<u32, Vec<u8>>,
    acknowledgements: Vec<AckItem>,
    app_closed: bool,
    close_started: Option<u32>,
    peer_terminating: bool,
}

impl Engine {
    fn new(config: MkcpConfig, conversation: u16, codec: &PacketCodec) -> Self {
        let computed = config.mtu() as usize;
        let mss = computed
            .saturating_sub(codec.overhead())
            .saturating_sub(DATA_OVERHEAD)
            .max(576);
        Self {
            config,
            conversation,
            started: Instant::now(),
            mss,
            rto: 100,
            last_ping: 0,
            send_next: 0,
            recv_next: 0,
            remote_recv_window: 32,
            send_window: VecDeque::new(),
            pending_application: VecDeque::new(),
            pending_offset: 0,
            recv_cache: BTreeMap::new(),
            acknowledgements: Vec::new(),
            app_closed: false,
            close_started: None,
            peer_terminating: false,
        }
    }

    fn elapsed(&self) -> u32 {
        self.started.elapsed().as_millis() as u32
    }

    fn enqueue(&mut self, payload: &[u8]) {
        self.pending_application.push_back(payload.to_vec());
        self.fill_send_window();
    }

    fn fill_send_window(&mut self) {
        while self.send_window.len() < self.config.sending_buffer_size() {
            let Some(payload) = self.pending_application.front() else {
                break;
            };
            let end = (self.pending_offset + self.mss).min(payload.len());
            self.send_window.push_back(DataSegment {
                number: self.send_next,
                payload: payload[self.pending_offset..end].to_vec(),
                timeout: 0,
                transmit: 0,
            });
            self.send_next = self.send_next.wrapping_add(1);
            self.pending_offset = end;
            if self.pending_offset == payload.len() {
                self.pending_application.pop_front();
                self.pending_offset = 0;
            }
        }
    }

    fn input(&mut self, segments: Vec<(u16, Segment)>) -> Vec<Vec<u8>> {
        let now = self.elapsed();
        for (conversation, segment) in segments {
            if conversation != self.conversation {
                break;
            }
            match segment {
                Segment::Data {
                    option: _,
                    timestamp,
                    number,
                    sending_next,
                    payload,
                } => {
                    self.remove_before(sending_next);
                    self.acknowledgements
                        .retain(|ack| ack.number >= sending_next);
                    if number.wrapping_sub(self.recv_next) < self.config.receiving_flight_size() {
                        self.acknowledgements.push(AckItem {
                            number,
                            timestamp,
                            next_flush: 0,
                        });
                        self.recv_cache.entry(number).or_insert(payload);
                    }
                }
                Segment::Ack {
                    option: _,
                    receiving_window,
                    receiving_next,
                    timestamp,
                    numbers,
                } => {
                    self.remote_recv_window = self.remote_recv_window.max(receiving_window);
                    self.remove_before(receiving_next);
                    for number in numbers {
                        self.remove_number(number);
                    }
                    let sample = now.wrapping_sub(timestamp);
                    if sample < 10_000 {
                        self.rto = (sample.max(self.config.tti()).saturating_mul(5) / 4)
                            .clamp(100, 10_000);
                    }
                }
                Segment::Command {
                    command,
                    option: _,
                    sending_next,
                    receiving_next,
                    peer_rto,
                } => {
                    self.remove_before(receiving_next);
                    self.acknowledgements
                        .retain(|ack| ack.number >= sending_next);
                    if peer_rto != 0 {
                        self.rto = peer_rto.min(10_000);
                    }
                    if command == COMMAND_TERMINATE {
                        self.peer_terminating = true;
                    }
                }
            }
        }
        let mut delivered = Vec::new();
        while let Some(payload) = self.recv_cache.remove(&self.recv_next) {
            self.recv_next = self.recv_next.wrapping_add(1);
            delivered.push(payload);
        }
        delivered
    }

    fn remove_before(&mut self, next: u32) {
        while self
            .send_window
            .front()
            .is_some_and(|segment| segment.number < next)
        {
            self.send_window.pop_front();
        }
    }

    fn remove_number(&mut self, number: u32) {
        if let Some(index) = self
            .send_window
            .iter()
            .position(|segment| segment.number == number)
        {
            self.send_window.remove(index);
        }
    }

    fn flush_segments(&mut self) -> Vec<Segment> {
        self.fill_send_window();
        let now = self.elapsed();
        if self.app_closed && self.close_started.is_none() {
            self.close_started = Some(now);
        }
        let mut output = Vec::new();
        if !self.acknowledgements.is_empty() {
            let mut numbers = Vec::with_capacity(MAX_ACKS);
            let mut timestamp = 0;
            for item in &mut self.acknowledgements {
                if item.next_flush > now && !numbers.is_empty() {
                    continue;
                }
                numbers.push(item.number);
                timestamp = timestamp.max(item.timestamp);
                item.next_flush = now + (self.rto / 2).max(20);
                if numbers.len() == MAX_ACKS {
                    break;
                }
            }
            output.push(Segment::Ack {
                option: u8::from(self.app_closed),
                receiving_window: self
                    .recv_next
                    .wrapping_add(self.config.receiving_flight_size()),
                receiving_next: self.recv_next,
                timestamp,
                numbers,
            });
        }

        let permitted = self
            .remote_recv_window
            .wrapping_sub(
                self.send_window
                    .front()
                    .map_or(self.send_next, |s| s.number),
            )
            .min(self.config.sending_flight_size())
            .saturating_mul(20)
            .max(1) as usize;
        let sending_next = self
            .send_window
            .front()
            .map_or(self.send_next, |segment| segment.number);
        for segment in self.send_window.iter_mut().take(permitted) {
            if segment.transmit != 0 && now.wrapping_sub(segment.timeout) > 0x7fff_ffff {
                continue;
            }
            segment.transmit = segment.transmit.saturating_add(1);
            segment.timeout = now.wrapping_add(self.rto.max(self.config.tti()));
            output.push(Segment::Data {
                option: u8::from(self.app_closed),
                timestamp: now,
                number: segment.number,
                sending_next,
                payload: segment.payload.clone(),
            });
        }
        if self.app_closed && self.send_window.is_empty() {
            output.push(self.command(COMMAND_TERMINATE));
        } else if now.wrapping_sub(self.last_ping) >= 3000 {
            output.push(self.command(COMMAND_PING));
            self.last_ping = now;
        }
        output
    }

    fn command(&self, command: u8) -> Segment {
        Segment::Command {
            command,
            option: u8::from(self.app_closed),
            sending_next: self
                .send_window
                .front()
                .map_or(self.send_next, |s| s.number),
            receiving_next: self.recv_next,
            peer_rto: self.rto,
        }
    }

    fn finished(&self) -> bool {
        self.peer_terminating
            || self
                .close_started
                .is_some_and(|started| self.elapsed().wrapping_sub(started) >= 8000)
    }
}

async fn run_engine(
    endpoint: Arc<dyn PacketEndpoint>,
    config: MkcpConfig,
    conversation: u16,
    mut codec: PacketCodec,
    mut outgoing: mpsc::Receiver<ApplicationEvent>,
    incoming: mpsc::Sender<Vec<u8>>,
) {
    let interval = Duration::from_millis(u64::from(config.tti().max(1)));
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut engine = Engine::new(config, conversation, &codec);
    let mut datagram = vec![0_u8; 64 * 1024];
    loop {
        tokio::select! {
            event = outgoing.recv() => match event {
                Some(ApplicationEvent::Data(payload)) => engine.enqueue(&payload),
                Some(ApplicationEvent::Closed) | None => engine.app_closed = true,
            },
            received = endpoint.recv(&mut datagram) => match received {
                Ok(length) => {
                    let segments = codec.decode(&datagram[..length]);
                    for payload in engine.input(segments) {
                        if incoming.send(payload).await.is_err() {
                            engine.app_closed = true;
                        }
                    }
                }
                Err(_) => break,
            },
            _ = ticker.tick() => {}
        }
        for segment in engine.flush_segments() {
            let packet = codec.encode(conversation, &segment);
            if endpoint.send(&packet).await.is_err() {
                return;
            }
        }
        if engine.finished() {
            break;
        }
    }
}

enum PacketSecurity {
    Simple,
    Seeded(Box<Aes128Gcm>),
}

struct PacketCodec {
    security: PacketSecurity,
    header: PacketHeader,
}

impl PacketCodec {
    fn new(config: &MkcpConfig) -> io::Result<Self> {
        let security = if config.seed.is_empty() {
            PacketSecurity::Simple
        } else {
            let digest = Sha256::digest(config.seed.as_bytes());
            PacketSecurity::Seeded(Box::new(Aes128Gcm::new_from_slice(&digest[..16]).map_err(
                |error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()),
            )?))
        };
        Ok(Self {
            security,
            header: PacketHeader::new(&config.header),
        })
    }

    fn overhead(&self) -> usize {
        self.header.size()
            + match self.security {
                PacketSecurity::Simple => 6,
                PacketSecurity::Seeded(_) => 28,
            }
    }

    fn encode(&mut self, conversation: u16, segment: &Segment) -> Vec<u8> {
        let plain = serialize_segment(conversation, segment);
        let encrypted = match &self.security {
            PacketSecurity::Simple => simple_seal(&plain),
            PacketSecurity::Seeded(cipher) => {
                let mut nonce = [0_u8; 12];
                rand::rng().fill(&mut nonce);
                let mut output = nonce.to_vec();
                output.extend_from_slice(
                    &cipher
                        .encrypt(Nonce::from_slice(&nonce), plain.as_slice())
                        .expect("AES-GCM encryption cannot fail for an in-memory payload"),
                );
                output
            }
        };
        let mut output = self.header.serialize();
        output.extend_from_slice(&encrypted);
        output
    }

    fn decode(&self, packet: &[u8]) -> Vec<(u16, Segment)> {
        let Some(payload) = packet.get(self.header.size()..) else {
            return Vec::new();
        };
        let plain = match &self.security {
            PacketSecurity::Simple => simple_open(payload),
            PacketSecurity::Seeded(cipher) => {
                let Some((nonce, encrypted)) = payload.split_at_checked(12) else {
                    return Vec::new();
                };
                cipher.decrypt(Nonce::from_slice(nonce), encrypted).ok()
            }
        };
        let Some(plain) = plain else {
            return Vec::new();
        };
        parse_segments(&plain)
    }
}

enum PacketHeader {
    None,
    Srtp {
        number: u16,
    },
    Utp {
        connection_id: u16,
    },
    Wechat {
        sequence: u32,
    },
    Dtls {
        epoch: u16,
        length: u16,
        sequence: u32,
    },
    Wireguard,
}

impl PacketHeader {
    fn new(name: &str) -> Self {
        match name.to_ascii_lowercase().as_str() {
            "srtp" => Self::Srtp {
                number: rand::random(),
            },
            "utp" => Self::Utp {
                connection_id: rand::random(),
            },
            "wechat-video" | "wechat" => Self::Wechat {
                sequence: u32::from(rand::random::<u16>()),
            },
            "dtls" => Self::Dtls {
                epoch: rand::random(),
                length: 17,
                sequence: 0,
            },
            "wireguard" => Self::Wireguard,
            _ => Self::None,
        }
    }

    fn size(&self) -> usize {
        match self {
            Self::None => 0,
            Self::Srtp { .. } | Self::Utp { .. } | Self::Wireguard => 4,
            Self::Wechat { .. } | Self::Dtls { .. } => 13,
        }
    }

    fn serialize(&mut self) -> Vec<u8> {
        let mut output = vec![0_u8; self.size()];
        match self {
            Self::None => {}
            Self::Srtp { number } => {
                *number = number.wrapping_add(1);
                output[..2].copy_from_slice(&0xb5e8_u16.to_be_bytes());
                output[2..].copy_from_slice(&number.to_be_bytes());
            }
            Self::Utp { connection_id } => {
                output[..2].copy_from_slice(&connection_id.to_be_bytes());
                output[2] = 1;
            }
            Self::Wechat { sequence } => {
                *sequence = sequence.wrapping_add(1);
                output.copy_from_slice(&[
                    0xa1, 0x08, 0, 0, 0, 0, 0, 0x10, 0x11, 0x18, 0x30, 0x22, 0x30,
                ]);
                output[2..6].copy_from_slice(&sequence.to_be_bytes());
            }
            Self::Dtls {
                epoch,
                length,
                sequence,
            } => {
                output[0..3].copy_from_slice(&[23, 254, 253]);
                output[3..5].copy_from_slice(&epoch.to_be_bytes());
                output[7..11].copy_from_slice(&sequence.to_be_bytes());
                output[11..13].copy_from_slice(&length.to_be_bytes());
                *sequence = sequence.wrapping_add(1);
                *length += 17;
                if *length > 100 {
                    *length -= 50;
                }
            }
            Self::Wireguard => output[0] = 4,
        }
        output
    }
}

fn serialize_segment(conversation: u16, segment: &Segment) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(&conversation.to_be_bytes());
    match segment {
        Segment::Data {
            option,
            timestamp,
            number,
            sending_next,
            payload,
        } => {
            output.extend_from_slice(&[COMMAND_DATA, *option]);
            output.extend_from_slice(&timestamp.to_be_bytes());
            output.extend_from_slice(&number.to_be_bytes());
            output.extend_from_slice(&sending_next.to_be_bytes());
            output.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            output.extend_from_slice(payload);
        }
        Segment::Ack {
            option,
            receiving_window,
            receiving_next,
            timestamp,
            numbers,
        } => {
            output.extend_from_slice(&[COMMAND_ACK, *option]);
            output.extend_from_slice(&receiving_window.to_be_bytes());
            output.extend_from_slice(&receiving_next.to_be_bytes());
            output.extend_from_slice(&timestamp.to_be_bytes());
            output.push(numbers.len() as u8);
            for number in numbers {
                output.extend_from_slice(&number.to_be_bytes());
            }
        }
        Segment::Command {
            command,
            option,
            sending_next,
            receiving_next,
            peer_rto,
        } => {
            output.extend_from_slice(&[*command, *option]);
            output.extend_from_slice(&sending_next.to_be_bytes());
            output.extend_from_slice(&receiving_next.to_be_bytes());
            output.extend_from_slice(&peer_rto.to_be_bytes());
        }
    }
    output
}

fn parse_segments(mut packet: &[u8]) -> Vec<(u16, Segment)> {
    let mut segments = Vec::new();
    while packet.len() >= 4 {
        let conversation = u16::from_be_bytes([packet[0], packet[1]]);
        let command = packet[2];
        let option = packet[3];
        packet = &packet[4..];
        let segment = match command {
            COMMAND_DATA if packet.len() >= 14 => {
                let length = usize::from(u16::from_be_bytes([packet[12], packet[13]]));
                if packet.len() < 14 + length {
                    break;
                }
                let segment = Segment::Data {
                    option,
                    timestamp: read_u32(packet),
                    number: read_u32(&packet[4..]),
                    sending_next: read_u32(&packet[8..]),
                    payload: packet[14..14 + length].to_vec(),
                };
                packet = &packet[14 + length..];
                segment
            }
            COMMAND_ACK if packet.len() >= 13 => {
                let count = usize::from(packet[12]);
                if packet.len() < 13 + count * 4 {
                    break;
                }
                let mut numbers = Vec::with_capacity(count);
                for chunk in packet[13..13 + count * 4].chunks_exact(4) {
                    numbers.push(read_u32(chunk));
                }
                let segment = Segment::Ack {
                    option,
                    receiving_window: read_u32(packet),
                    receiving_next: read_u32(&packet[4..]),
                    timestamp: read_u32(&packet[8..]),
                    numbers,
                };
                packet = &packet[13 + count * 4..];
                segment
            }
            _ if packet.len() >= 12 => {
                let segment = Segment::Command {
                    command,
                    option,
                    sending_next: read_u32(packet),
                    receiving_next: read_u32(&packet[4..]),
                    peer_rto: read_u32(&packet[8..]),
                };
                packet = &packet[12..];
                segment
            }
            _ => break,
        };
        segments.push((conversation, segment));
    }
    segments
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn simple_seal(plain: &[u8]) -> Vec<u8> {
    let mut output = vec![0_u8; 6];
    output[4..6].copy_from_slice(&(plain.len() as u16).to_be_bytes());
    output.extend_from_slice(plain);
    let hash = fnv1a(&output[4..]);
    output[..4].copy_from_slice(&hash.to_be_bytes());
    let original = output.len();
    let padding = (4 - original % 4) % 4;
    output.resize(original + padding, 0);
    for index in 4..output.len() {
        output[index] ^= output[index - 4];
    }
    output.truncate(original);
    output
}

fn simple_open(ciphertext: &[u8]) -> Option<Vec<u8>> {
    let original = ciphertext.len();
    let padding = (4 - original % 4) % 4;
    let mut plain = ciphertext.to_vec();
    plain.resize(original + padding, 0);
    for index in (4..plain.len()).rev() {
        plain[index] ^= plain[index - 4];
    }
    plain.truncate(original);
    if plain.len() < 6 || read_u32(&plain) != fnv1a(&plain[4..]) {
        return None;
    }
    let length = usize::from(u16::from_be_bytes([plain[4], plain[5]]));
    (plain.len() == 6 + length).then(|| plain[6..].to_vec())
}

fn fnv1a(bytes: &[u8]) -> u32 {
    bytes.iter().fold(2_166_136_261, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(16_777_619)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ChannelEndpoint {
        sender: mpsc::Sender<Vec<u8>>,
        receiver: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    }

    impl PacketEndpoint for ChannelEndpoint {
        fn send<'a>(&'a self, packet: &'a [u8]) -> PacketFuture<'a, usize> {
            Box::pin(async move {
                self.sender
                    .send(packet.to_vec())
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "peer closed"))?;
                Ok(packet.len())
            })
        }

        fn recv<'a>(&'a self, packet: &'a mut [u8]) -> PacketFuture<'a, usize> {
            Box::pin(async move {
                let payload =
                    self.receiver.lock().await.recv().await.ok_or_else(|| {
                        io::Error::new(io::ErrorKind::UnexpectedEof, "peer closed")
                    })?;
                let length = payload.len().min(packet.len());
                packet[..length].copy_from_slice(&payload[..length]);
                Ok(length)
            })
        }
    }

    #[test]
    fn simple_authentication_round_trips_and_rejects_tampering() {
        let payload = b"v2ray-mkcp-packet";
        let mut sealed = simple_seal(payload);
        assert_eq!(simple_open(&sealed).as_deref(), Some(payload.as_slice()));
        sealed[7] ^= 0x80;
        assert!(simple_open(&sealed).is_none());
    }

    #[test]
    fn every_camouflage_header_has_the_go_size() {
        for (name, size) in [
            ("none", 0),
            ("srtp", 4),
            ("utp", 4),
            ("wechat-video", 13),
            ("dtls", 13),
            ("wireguard", 4),
        ] {
            let mut header = PacketHeader::new(name);
            assert_eq!(header.serialize().len(), size, "{name}");
        }
    }

    #[tokio::test]
    async fn full_duplex_stream_round_trips_over_packet_endpoint() {
        let (left_tx, left_rx) = mpsc::channel(256);
        let (right_tx, right_rx) = mpsc::channel(256);
        let left_endpoint = Arc::new(ChannelEndpoint {
            sender: left_tx,
            receiver: tokio::sync::Mutex::new(right_rx),
        });
        let right_endpoint = Arc::new(ChannelEndpoint {
            sender: right_tx,
            receiver: tokio::sync::Mutex::new(left_rx),
        });
        let config = MkcpConfig {
            tti: 10,
            write_buffer: 64 * 1024,
            seed: "phase6d-mkcp".to_owned(),
            header: "srtp".to_owned(),
            ..MkcpConfig::default()
        };
        let mut left = connect_with_conversation(left_endpoint, config.clone(), 42).unwrap();
        let mut right = connect_with_conversation(right_endpoint, config, 42).unwrap();
        let echo = tokio::spawn(async move {
            let mut buffer = vec![0_u8; 16 * 1024];
            loop {
                let length = right.read(&mut buffer).await?;
                if length == 0 {
                    break;
                }
                right.write_all(&buffer[..length]).await?;
            }
            Ok::<(), io::Error>(())
        });
        let payload = vec![0x5a; 128 * 1024];
        left.write_all(&payload).await.unwrap();
        let mut response = vec![0_u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(10), left.read_exact(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response, payload);
        drop(left);
        let _ = tokio::time::timeout(Duration::from_secs(1), echo).await;
    }
}
