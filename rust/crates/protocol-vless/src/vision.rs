use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use rewrite_io::{BoxedStream, VisionDirectControl};

const CMD_PADDING_CONTINUE: u8 = 0x00;
const CMD_PADDING_END: u8 = 0x01;
const CMD_PADDING_DIRECT: u8 = 0x02;

const TLS_APPLICATION_DATA: u8 = 0x17;
const TLS_CLIENT_HANDSHAKE_START: [u8; 2] = [0x16, 0x03];
const TLS_SERVER_HANDSHAKE_START: [u8; 3] = [0x16, 0x03, 0x03];
const TLS13_SUPPORTED_VERSIONS: [u8; 6] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReadState {
    Framed,
    End,
}

impl ReadState {
    fn is_done(self) -> bool {
        matches!(self, ReadState::End)
    }
}

struct TlsFilterState {
    packets_to_filter: i32,
    is_tls: bool,
    is_tls12_or_above: bool,
    enable_xtls: bool,
    cipher: u16,
    remaining_server_hello: usize,
}

impl TlsFilterState {
    fn new() -> Self {
        Self {
            packets_to_filter: 8,
            is_tls: false,
            is_tls12_or_above: false,
            enable_xtls: false,
            cipher: 0,
            remaining_server_hello: 0,
        }
    }

    fn filter(&mut self, buffer: &[u8]) {
        if self.packets_to_filter <= 0 {
            return;
        }
        let length = buffer.len();
        self.packets_to_filter -= 1;

        if let Some(index) = find_subslice(buffer, &TLS_SERVER_HANDSHAKE_START) {
            if length > index + 5 && buffer[0] == 0x16 && buffer[1] == 0x03 && buffer[2] == 0x03 {
                self.is_tls = true;
                if buffer[index + 5] == 0x02 {
                    self.is_tls12_or_above = true;
                    let remaining =
                        usize::from(u16::from_be_bytes([buffer[index + 3], buffer[index + 4]]));
                    self.remaining_server_hello = remaining.saturating_add(5);
                    if length - index >= 79 && self.remaining_server_hello >= 79 {
                        let session_id_len = usize::from(buffer[index + 43]);
                        let cipher_offset = index + 43 + session_id_len + 1;
                        if cipher_offset + 2 <= length {
                            self.cipher = u16::from(buffer[cipher_offset]) << 8
                                | u16::from(buffer[cipher_offset + 1]);
                        }
                    }
                }
            }
        } else if let Some(index) = find_subslice(buffer, &TLS_CLIENT_HANDSHAKE_START)
            && length > index + 5
            && buffer[index + 5] == 0x01
        {
            self.is_tls = true;
        }

        if self.remaining_server_hello > 0 {
            let mut end = self.remaining_server_hello;
            let start = 0;
            if start + end > length {
                end = length;
                self.remaining_server_hello -= end;
            } else {
                self.remaining_server_hello = 0;
            }
            if contains_subslice(&buffer[start..start + end], &TLS13_SUPPORTED_VERSIONS) {
                let cipher_name = tls13_cipher_name(self.cipher);
                if cipher_name != Some("TLS_AES_128_CCM_8_SHA256") {
                    self.enable_xtls = true;
                }
                self.packets_to_filter = 0;
                return;
            }
            if self.remaining_server_hello == 0 {
                self.packets_to_filter = 0;
            }
        }
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    find_subslice(haystack, needle).is_some()
}

fn tls13_cipher_name(cipher: u16) -> Option<&'static str> {
    match cipher {
        0x1301 => Some("TLS_AES_128_GCM_SHA256"),
        0x1302 => Some("TLS_AES_256_GCM_SHA384"),
        0x1303 => Some("TLS_CHACHA20_POLY1305_SHA256"),
        0x1304 => Some("TLS_AES_128_CCM_SHA256"),
        0x1305 => Some("TLS_AES_128_CCM_8_SHA256"),
        _ => None,
    }
}

/// Vision framing for `flow: xtls-rprx-vision`.
pub struct VisionStream {
    inner: BoxedStream,
    write_uuid: Option<[u8; 16]>,
    expected_server_uuid: [u8; 16],
    write_buf: BytesMut,
    pending_input_len: usize,
    write_filter_application_data: bool,
    tls_filter: TlsFilterState,
    server_uuid_consumed: bool,
    decoded: BytesMut,
    raw: BytesMut,
    read_state: ReadState,
    control: Option<VisionDirectControl>,
    pending_write_direct: bool,
}

impl VisionStream {
    pub(crate) fn new(
        inner: BoxedStream,
        uuid: [u8; 16],
        control: Option<VisionDirectControl>,
    ) -> Self {
        Self {
            inner,
            write_uuid: Some(uuid),
            expected_server_uuid: uuid,
            write_buf: BytesMut::new(),
            pending_input_len: 0,
            write_filter_application_data: true,
            tls_filter: TlsFilterState::new(),
            server_uuid_consumed: false,
            decoded: BytesMut::new(),
            raw: BytesMut::new(),
            read_state: ReadState::Framed,
            control,
            pending_write_direct: false,
        }
    }

    fn build_vision_frame(&mut self, data: &[u8], command: u8, padding_tls: bool) {
        let is_first_frame = self.write_uuid.is_some();
        if let Some(uuid) = self.write_uuid.take() {
            self.write_buf.put_slice(&uuid);
        }

        let content_len = u16::try_from(data.len()).expect("Vision frame data is pre-chunked");
        let padding_len: u16 = if data.is_empty() && is_first_frame {
            rand::random::<u16>() % 500 + 400
        } else if usize::from(content_len) < 900 && padding_tls {
            rand::random::<u16>() % 500 + 900 - content_len
        } else if usize::from(content_len) < 900 {
            rand::random::<u16>() % 256
        } else {
            0
        };

        self.write_buf.put_u8(command);
        self.write_buf.put_u16(content_len);
        self.write_buf.put_u16(padding_len);
        self.write_buf.put_slice(data);
        for _ in 0..padding_len {
            self.write_buf.put_u8(rand::random());
        }
    }

    fn choose_write_command(&mut self, data: &[u8]) -> u8 {
        self.tls_filter.filter(data);
        if data.len() > 6 && data.starts_with(&[TLS_APPLICATION_DATA, 0x03, 0x03]) {
            if self.tls_filter.enable_xtls {
                CMD_PADDING_DIRECT
            } else {
                CMD_PADDING_END
            }
        } else if !self.tls_filter.is_tls12_or_above && self.tls_filter.packets_to_filter <= 1 {
            CMD_PADDING_END
        } else {
            CMD_PADDING_CONTINUE
        }
    }
}

impl AsyncRead for VisionStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.decoded.is_empty() {
                let amount = this.decoded.len().min(buf.remaining());
                buf.put_slice(&this.decoded[..amount]);
                this.decoded.advance(amount);
                return Poll::Ready(Ok(()));
            }
            if this.read_state.is_done() {
                return Pin::new(&mut this.inner).poll_read(cx, buf);
            }

            let changed = match decode_vision_frames(
                &mut this.raw,
                &mut this.decoded,
                &mut this.read_state,
                &mut this.server_uuid_consumed,
                &this.expected_server_uuid,
                this.control.as_ref(),
            ) {
                Ok(changed) => changed,
                Err(error) => return Poll::Ready(Err(error)),
            };
            if changed || this.read_state.is_done() {
                continue;
            }

            let mut tmp = [0_u8; 8192];
            let mut tmp_buf = ReadBuf::new(&mut tmp);
            match Pin::new(&mut this.inner).poll_read(cx, &mut tmp_buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {
                    let filled = tmp_buf.filled();
                    if filled.is_empty() {
                        if !this.raw.is_empty() {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "connection closed with incomplete Vision frame",
                            )));
                        }
                        return Poll::Ready(Ok(()));
                    }
                    this.raw.extend_from_slice(filled);
                }
            }
        }
    }
}

fn decode_vision_frames(
    raw: &mut BytesMut,
    decoded: &mut BytesMut,
    read_state: &mut ReadState,
    server_uuid_consumed: &mut bool,
    expected_server_uuid: &[u8; 16],
    control: Option<&VisionDirectControl>,
) -> std::io::Result<bool> {
    let before = decoded.len();
    loop {
        if !*server_uuid_consumed {
            if raw.len() < 16 + 5 {
                break;
            }
            if raw[..16] != expected_server_uuid[..] {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "XTLS Vision server responded with an unknown UUID",
                ));
            }
            raw.advance(16);
            *server_uuid_consumed = true;
        }
        if raw.len() < 5 {
            break;
        }
        let command = raw[0];
        let content_len = u16::from_be_bytes([raw[1], raw[2]]) as usize;
        let padding_len = u16::from_be_bytes([raw[3], raw[4]]) as usize;
        if raw.len() < 5 + content_len + padding_len {
            break;
        }
        raw.advance(5);
        decoded.extend_from_slice(&raw[..content_len]);
        raw.advance(content_len + padding_len);

        match command {
            CMD_PADDING_CONTINUE => {}
            CMD_PADDING_END => {
                *read_state = ReadState::End;
                decoded.extend_from_slice(raw);
                raw.clear();
                break;
            }
            CMD_PADDING_DIRECT => {
                let Some(control) = control else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "XTLS Vision carrier cannot promote to raw TCP",
                    ));
                };
                decoded.extend_from_slice(raw);
                raw.clear();
                control.request_read_direct();
                *read_state = ReadState::End;
                break;
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("XTLS Vision read unknown command: {command}"),
                ));
            }
        }
    }
    Ok(read_state.is_done() || decoded.len() > before)
}

impl AsyncWrite for VisionStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let this = self.get_mut();
        if this.pending_write_direct && this.write_buf.is_empty() {
            match Pin::new(&mut this.inner).poll_flush(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {}
            }
            this.control
                .as_ref()
                .expect("DIRECT promotion was validated")
                .request_write_direct();
            this.pending_write_direct = false;
            return Poll::Ready(Ok(std::mem::take(&mut this.pending_input_len)));
        }
        if this.write_buf.is_empty() {
            if this.write_filter_application_data {
                let accepted = buf.len().min(usize::from(u16::MAX));
                let input = &buf[..accepted];
                if input.is_empty() {
                    this.build_vision_frame(input, CMD_PADDING_CONTINUE, true);
                } else {
                    let command = this.choose_write_command(input);
                    if command == CMD_PADDING_DIRECT {
                        if this.control.is_none() {
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::Unsupported,
                                "XTLS Vision carrier cannot promote to raw TCP",
                            )));
                        }
                        this.pending_write_direct = true;
                    }
                    if command != CMD_PADDING_CONTINUE {
                        this.write_filter_application_data = false;
                    }
                    this.build_vision_frame(input, command, this.tls_filter.is_tls);
                }
                this.pending_input_len = accepted;
            } else {
                return Pin::new(&mut this.inner).poll_write(cx, buf);
            }
        }

        loop {
            if this.write_buf.is_empty() {
                break;
            }
            let pending = &this.write_buf[..];
            match Pin::new(&mut this.inner).poll_write(cx, pending) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "broken pipe",
                    )));
                }
                Poll::Ready(Ok(written)) => this.write_buf.advance(written),
            }
        }

        if this.pending_write_direct {
            match Pin::new(&mut this.inner).poll_flush(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(())) => {}
            }
            this.control
                .as_ref()
                .expect("DIRECT promotion was validated")
                .request_write_direct();
            this.pending_write_direct = false;
        }

        Poll::Ready(Ok(std::mem::take(&mut this.pending_input_len)))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;

    use rewrite_io::VisionDirectControl;

    use super::{CMD_PADDING_CONTINUE, CMD_PADDING_DIRECT, ReadState, decode_vision_frames};

    const UUID: [u8; 16] = [
        0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3, 0x08,
        0x11,
    ];

    fn frame(uuid: [u8; 16], command: u8) -> BytesMut {
        let mut frame = Vec::from(uuid);
        frame.extend_from_slice(&[command, 0, 4, 0, 0]);
        frame.extend_from_slice(b"data");
        BytesMut::from(frame.as_slice())
    }

    #[test]
    fn validates_server_uuid_and_command() {
        let mut raw = frame(UUID, CMD_PADDING_CONTINUE);
        let mut decoded = BytesMut::new();
        let mut state = ReadState::Framed;
        let mut uuid_consumed = false;
        assert!(
            decode_vision_frames(
                &mut raw,
                &mut decoded,
                &mut state,
                &mut uuid_consumed,
                &UUID,
                None,
            )
            .expect("valid frame")
        );
        assert_eq!(decoded, b"data"[..]);

        let mut raw = frame([0; 16], CMD_PADDING_CONTINUE);
        let error = decode_vision_frames(
            &mut raw,
            &mut BytesMut::new(),
            &mut ReadState::Framed,
            &mut false,
            &UUID,
            None,
        )
        .expect_err("wrong UUID");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);

        let mut raw = frame(UUID, 0xff);
        let error = decode_vision_frames(
            &mut raw,
            &mut BytesMut::new(),
            &mut ReadState::Framed,
            &mut false,
            &UUID,
            None,
        )
        .expect_err("unknown command");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn requires_a_direct_capable_carrier() {
        let mut raw = frame(UUID, CMD_PADDING_DIRECT);
        let error = decode_vision_frames(
            &mut raw,
            &mut BytesMut::new(),
            &mut ReadState::Framed,
            &mut false,
            &UUID,
            None,
        )
        .expect_err("direct splice");
        assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);

        let control = VisionDirectControl::default();
        let mut raw = frame(UUID, CMD_PADDING_DIRECT);
        assert!(
            decode_vision_frames(
                &mut raw,
                &mut BytesMut::new(),
                &mut ReadState::Framed,
                &mut false,
                &UUID,
                Some(&control),
            )
            .expect("capable carrier")
        );
        assert!(control.read_is_direct());
    }
}
