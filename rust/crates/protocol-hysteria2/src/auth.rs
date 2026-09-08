//! HTTP/3 authentication for Hysteria2.

use crate::{Hysteria2ProtocolError, STATUS_AUTH_OK};

pub(crate) const AUTH_HOST: &str = "hysteria";
pub(crate) const AUTH_PATH: &str = "/auth";
pub(crate) const HEADER_AUTH: &str = "hysteria-auth";
pub(crate) const HEADER_CC_RX: &str = "hysteria-cc-rx";
pub(crate) const HEADER_PADDING: &str = "hysteria-padding";
pub(crate) const HEADER_UDP: &str = "hysteria-udp";

const PADDING_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

pub(crate) struct AuthResponse {
    pub udp_enabled: bool,
    pub rx_auto: bool,
    #[allow(dead_code)]
    pub rx: u64,
}

pub(crate) fn random_padding(min: usize, max: usize) -> String {
    let n = rand::random_range(min..max);
    (0..n)
        .map(|_| {
            let index = rand::random_range(0..PADDING_CHARS.len());
            PADDING_CHARS[index] as char
        })
        .collect()
}

pub(crate) async fn authenticate(
    connection: quinn::Connection,
    password: &str,
    receive_bps: u64,
) -> Result<AuthResponse, Hysteria2ProtocolError> {
    // Match rsteria2: do not drive `poll_close` (that closes the Quinn conn).
    let (driver, mut sender) = h3::client::new(h3_quinn::Connection::new(connection.clone()))
        .await
        .map_err(|error| Hysteria2ProtocolError::Protocol(error.to_string()))?;

    let uri = format!("https://{AUTH_HOST}{AUTH_PATH}")
        .parse::<http::Uri>()
        .map_err(|error| Hysteria2ProtocolError::Protocol(error.to_string()))?;
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri(uri)
        .header(http::header::HOST, AUTH_HOST)
        .header(HEADER_AUTH, password)
        .header(HEADER_CC_RX, receive_bps.to_string())
        .header(HEADER_PADDING, random_padding(256, 2048))
        .body(())
        .map_err(|error| Hysteria2ProtocolError::Protocol(error.to_string()))?;

    let mut stream = sender
        .send_request(request)
        .await
        .map_err(|error| Hysteria2ProtocolError::Protocol(error.to_string()))?;
    stream
        .finish()
        .await
        .map_err(|error| Hysteria2ProtocolError::Protocol(error.to_string()))?;
    let response = stream
        .recv_response()
        .await
        .map_err(|error| Hysteria2ProtocolError::Protocol(error.to_string()))?;

    // Drop h3 pieces without driving the driver to completion. Keep `stream`
    // alive across the SendRequest drop so the last-request close path does
    // not tear down the Quinn connection (rsteria2 ordering).
    drop(sender);
    drop(driver);

    let status = response.status().as_u16();
    if status != STATUS_AUTH_OK {
        connection.close(0_u32.into(), b"authentication failed");
        return Err(Hysteria2ProtocolError::Protocol(format!(
            "authentication failed, status code: {status}"
        )));
    }

    let udp_enabled = response
        .headers()
        .get(HEADER_UDP)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("true"));
    let rx_header = response
        .headers()
        .get(HEADER_CC_RX)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("0");
    let (rx_auto, rx) = if rx_header.eq_ignore_ascii_case("auto") {
        (true, 0)
    } else {
        (false, rx_header.parse::<u64>().unwrap_or(0))
    };

    // `stream` drops here after headers are copied.
    drop(stream);

    Ok(AuthResponse {
        udp_enabled,
        rx_auto,
        rx,
    })
}
