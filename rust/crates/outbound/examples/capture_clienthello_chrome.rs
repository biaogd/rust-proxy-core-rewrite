//! Capture rustls Chrome-shaped `ClientHello` for differential vs Go uTLS.
//!
//! ```text
//! cargo run -p rewrite-outbound --example capture_clienthello_chrome
//! ```

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::rustls::ClientHelloFingerprint;
use tokio_rustls::rustls::crypto::CryptoProvider;
use tokio_rustls::rustls::crypto::aws_lc_rs::default_provider;
use tokio_rustls::rustls::pki_types::ServerName;

fn main() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let capture = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        stream
            .set_read_timeout(Some(Duration::from_millis(800)))
            .ok();
        let mut header = [0u8; 5];
        stream.read_exact(&mut header).expect("header");
        let len = u16::from_be_bytes([header[3], header[4]]) as usize;
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).expect("body");
        let mut record = header.to_vec();
        record.extend_from_slice(&body);
        record
    });

    let provider = default_provider();
    let _ = CryptoProvider::install_default(provider.clone());

    let mut config = ClientConfig::builder_with_provider(provider.into())
        .with_safe_default_protocol_versions()
        .expect("versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    config.client_hello_fingerprint = Some(ClientHelloFingerprint::Chrome);
    config.client_hello_fingerprint_mlkem = true;
    config.enable_sni = true;

    let server_name = ServerName::try_from("phase6c-shadow-tls.example").expect("sni");
    let mut conn =
        tokio_rustls::rustls::ClientConnection::new(Arc::new(config), server_name).expect("conn");
    let mut sock = TcpStream::connect(addr).expect("connect");
    {
        let mut tls = tokio_rustls::rustls::Stream::new(&mut conn, &mut sock);
        let _ = tls.write(b"x");
    }
    let _ = sock.shutdown(Shutdown::Both);
    let raw = capture.join().expect("join");

    let (ciphers, extensions) = parse_client_hello(&raw).expect("parse ClientHello");
    println!("{{");
    println!("  \"cipher_suites\": [{}],", join_hex_u16(&ciphers));
    println!("  \"extensions\": [{}],", join_hex_u16(&extensions));
    println!(
        "  \"has_grease\": {}",
        ciphers.iter().any(|v| is_grease(*v))
    );
    println!("}}");
}

fn is_grease(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a
}

fn normalize_grease(v: u16) -> u16 {
    if is_grease(v) { 0x0a0a } else { v }
}

fn join_hex_u16(vals: &[u16]) -> String {
    vals.iter()
        .map(|v| format!("\"0x{v:04x}\""))
        .collect::<Vec<_>>()
        .join(", ")
}

fn parse_client_hello(raw: &[u8]) -> Result<(Vec<u16>, Vec<u16>), String> {
    if raw.len() < 5 || raw[0] != 0x16 {
        return Err(format!("not handshake record (len={})", raw.len()));
    }
    let rec_len = u16::from_be_bytes([raw[3], raw[4]]) as usize;
    let hs = &raw[5..5 + rec_len.min(raw.len() - 5)];
    if hs.is_empty() || hs[0] != 0x01 {
        return Err("not ClientHello".into());
    }
    let body_len = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | hs[3] as usize;
    let mut p = &hs[4..4 + body_len.min(hs.len() - 4)];
    if p.len() < 34 {
        return Err("short body".into());
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
        return Err("no extensions".into());
    }
    let ext_len = u16::from_be_bytes([p[0], p[1]]) as usize;
    p = &p[2..2 + ext_len.min(p.len() - 2)];
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

#[derive(Debug)]
struct NoVerify;

impl tokio_rustls::rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[tokio_rustls::rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: tokio_rustls::rustls::pki_types::UnixTime,
    ) -> Result<tokio_rustls::rustls::client::danger::ServerCertVerified, tokio_rustls::rustls::Error>
    {
        Ok(tokio_rustls::rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
        default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
