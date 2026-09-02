//! Capture the first on-wire TLS `ClientHello` via the production `ShadowTLS` v3 path
//! (`connect_shadow_tls` → `connect_with_session_id_generator`).
//!
//! ```text
//! cargo run -p rewrite-transport --example capture_clienthello_chrome
//! ```

use std::io;

use hmac::Mac;
use rewrite_transport::{BoxedStream, ShadowTlsConnectOptions, connect_shadow_tls};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const HOST: &str = "phase6c-shadow-tls.example";
const PASSWORD: &str = "phase6c-shadow-tls-plugin-password";
const SESSION_ID_START: usize = 1 + 3 + 2 + 32 + 1;
const SESSION_ID_SIZE: usize = 32;
const HMAC_SIZE: usize = 4;

#[derive(Debug)]
struct HelloShape {
    cipher_suites: Vec<String>,
    extensions: Vec<String>,
    has_grease: bool,
    session_id_hmac_valid: bool,
}

#[tokio::main]
async fn main() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind listener");
    let addr = listener.local_addr().expect("local addr");

    let capture = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut header = [0_u8; 5];
        stream.read_exact(&mut header).await.expect("header");
        let len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let mut body = vec![0_u8; len];
        stream.read_exact(&mut body).await.expect("body");
        let mut record = header.to_vec();
        record.extend_from_slice(&body);
        let _ = stream.shutdown().await;
        record
    });

    let stream = TcpStream::connect(addr).await.expect("connect");
    let boxed: BoxedStream = Box::new(stream);
    let alpn = vec!["h2".to_owned(), "http/1.1".to_owned()];
    let _ = connect_shadow_tls(
        boxed,
        ShadowTlsConnectOptions {
            host: HOST,
            password: PASSWORD,
            version: 3,
            skip_certificate_verification: true,
            verification_name: None,
            certificate_fingerprint: None,
            certificate: None,
            private_key: None,
            custom_roots: &[],
            alpn: &alpn,
            client_fingerprint: Some("chrome"),
        },
        None,
    )
    .await;

    let raw = capture.await.expect("capture join");
    let shape = shape_from_client_hello(&raw).expect("parse ClientHello");
    print_shape(&shape);
}

fn handshake_message(raw: &[u8]) -> Option<&[u8]> {
    if raw.len() < 5 || raw[0] != 0x16 {
        return None;
    }
    let rec_len = u16::from_be_bytes([raw[3], raw[4]]) as usize;
    let hello = &raw[5..5 + rec_len.min(raw.len().saturating_sub(5))];
    (hello.first() == Some(&0x01)).then_some(hello)
}

fn print_shape(shape: &HelloShape) {
    println!("{{");
    println!("  \"cipher_suites\": [{}],", shape.cipher_suites.join(", "));
    println!("  \"extensions\": [{}],", shape.extensions.join(", "));
    println!("  \"has_grease\": {},", shape.has_grease);
    println!(
        "  \"session_id_hmac_valid\": {}",
        shape.session_id_hmac_valid
    );
    println!("}}");
}

fn shape_from_client_hello(raw: &[u8]) -> io::Result<HelloShape> {
    let (ciphers, extensions) = parse_client_hello(raw)?;
    Ok(HelloShape {
        has_grease: ciphers.iter().any(|v| is_grease(*v)),
        session_id_hmac_valid: verify_session_id_hmac(raw, PASSWORD),
        cipher_suites: ciphers.iter().map(|v| format!("\"0x{v:04x}\"")).collect(),
        extensions: extensions
            .iter()
            .map(|v| format!("\"0x{v:04x}\""))
            .collect(),
    })
}

fn is_grease(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a
}

fn normalize_grease(v: u16) -> u16 {
    if is_grease(v) { 0x0a0a } else { v }
}

fn parse_client_hello(raw: &[u8]) -> io::Result<(Vec<u16>, Vec<u16>)> {
    if raw.len() < 5 || raw[0] != 0x16 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a handshake record",
        ));
    }
    let rec_len = u16::from_be_bytes([raw[3], raw[4]]) as usize;
    let hs = &raw[5..5 + rec_len.min(raw.len().saturating_sub(5))];
    if hs.first() != Some(&0x01) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not ClientHello",
        ));
    }
    let body_len = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | hs[3] as usize;
    let mut p = &hs[4..4 + body_len.min(hs.len().saturating_sub(4))];
    if p.len() < 34 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "short body"));
    }
    p = &p[34..];
    let sid_len = p[0] as usize;
    p = &p[1 + sid_len..];
    let cs_len = u16::from_be_bytes([p[0], p[1]]) as usize;
    p = &p[2..];
    let mut ciphers = Vec::new();
    for i in (0..cs_len).step_by(2) {
        ciphers.push(normalize_grease(u16::from_be_bytes([p[i], p[i + 1]])));
    }
    p = &p[cs_len..];
    let comp_len = p[0] as usize;
    p = &p[1 + comp_len..];
    if p.len() < 2 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "no extensions"));
    }
    let ext_len = u16::from_be_bytes([p[0], p[1]]) as usize;
    p = &p[2..2 + ext_len.min(p.len().saturating_sub(2))];
    let mut extensions = Vec::new();
    let mut q = p;
    while q.len() >= 4 {
        let typ = u16::from_be_bytes([q[0], q[1]]);
        let len = u16::from_be_bytes([q[2], q[3]]) as usize;
        extensions.push(normalize_grease(typ));
        if q.len() < 4 + len {
            break;
        }
        q = &q[4 + len..];
    }
    Ok((ciphers, extensions))
}

fn verify_session_id_hmac(raw: &[u8], password: &str) -> bool {
    let Some(hello) = handshake_message(raw) else {
        return false;
    };
    if hello.len() < SESSION_ID_START + SESSION_ID_SIZE {
        return false;
    }
    let session_id = &hello[SESSION_ID_START..SESSION_ID_START + SESSION_ID_SIZE];
    if session_id[..SESSION_ID_SIZE - HMAC_SIZE] == [0_u8; SESSION_ID_SIZE - HMAC_SIZE] {
        return false;
    }
    let Ok(mut mac) = hmac::Hmac::<sha1::Sha1>::new_from_slice(password.as_bytes()) else {
        return false;
    };
    mac.update(&hello[..SESSION_ID_START]);
    let mut prefix = [0_u8; SESSION_ID_SIZE];
    prefix[..SESSION_ID_SIZE - HMAC_SIZE]
        .copy_from_slice(&session_id[..SESSION_ID_SIZE - HMAC_SIZE]);
    mac.update(&prefix);
    mac.update(&hello[SESSION_ID_START + SESSION_ID_SIZE..]);
    let expected = mac.finalize().into_bytes();
    session_id[SESSION_ID_SIZE - HMAC_SIZE..] == expected[..HMAC_SIZE]
}
