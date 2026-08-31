//! TLS client configuration for `ShadowTLS` only (via the `shadow-rustls` fork).

use std::io::Cursor;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use sha2::{Digest, Sha256};
use shadow_rustls::client::WebPkiServerVerifier;
use shadow_rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use shadow_rustls::crypto::{
    WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature,
};
use shadow_rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use shadow_rustls::{
    ClientConfig, ClientHelloFingerprint, DigitallySignedStruct, Error as TlsError, RootCertStore,
    SignatureScheme,
};

use crate::http::HttpProxyError;
use crate::tls::HttpProxyTls;

#[derive(Debug)]
struct ShadowTimeProvider {
    clock: Arc<rewrite_services::AdjustedClock>,
}

impl shadow_rustls::time_provider::TimeProvider for ShadowTimeProvider {
    fn current_time(&self) -> Option<UnixTime> {
        let offset = self.clock.offset_micros();
        let now = if offset >= 0 {
            SystemTime::now() + Duration::from_micros(offset.unsigned_abs())
        } else {
            SystemTime::now() - Duration::from_micros(offset.unsigned_abs())
        };
        now.duration_since(SystemTime::UNIX_EPOCH)
            .ok()
            .map(UnixTime::since_unix_epoch)
    }
}

#[derive(Debug)]
struct NoCertificateVerification {
    algorithms: WebPkiSupportedAlgorithms,
}

impl NoCertificateVerification {
    fn new() -> Self {
        Self {
            algorithms: shadow_rustls::crypto::ring::default_provider()
                .signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(message, certificate, signature, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(message, certificate, signature, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

#[derive(Debug)]
struct NameOverrideVerification {
    verifier: Arc<WebPkiServerVerifier>,
    verification_name: ServerName<'static>,
}

impl ServerCertVerifier for NameOverrideVerification {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        self.verifier.verify_server_cert(
            end_entity,
            intermediates,
            &self.verification_name,
            ocsp_response,
            now,
        )
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.verifier
            .verify_tls12_signature(message, certificate, signature)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.verifier
            .verify_tls13_signature(message, certificate, signature)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.verifier.supported_verify_schemes()
    }
}

#[derive(Debug)]
struct FingerprintVerification {
    fingerprint: [u8; 32],
    verification_name: Option<ServerName<'static>>,
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for FingerprintVerification {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        if Sha256::digest(end_entity.as_ref()).as_slice() == self.fingerprint {
            return Ok(ServerCertVerified::assertion());
        }
        for (index, certificate) in intermediates.iter().enumerate() {
            if Sha256::digest(certificate.as_ref()).as_slice() != self.fingerprint {
                continue;
            }
            let mut roots = RootCertStore::empty();
            roots
                .add(certificate.clone())
                .map_err(|error| TlsError::General(error.to_string()))?;
            let verifier = WebPkiServerVerifier::builder(Arc::new(roots))
                .build()
                .map_err(|error| TlsError::General(error.to_string()))?;
            return verifier.verify_server_cert(
                end_entity,
                &intermediates[..index],
                self.verification_name.as_ref().unwrap_or(server_name),
                ocsp_response,
                now,
            );
        }
        Err(TlsError::General(
            "certificate fingerprint does not match".to_owned(),
        ))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(message, certificate, signature, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(message, certificate, signature, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

fn load_root_store(custom_roots: &[String]) -> Result<RootCertStore, HttpProxyError> {
    let mut roots = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for certificate in native.certs {
        roots
            .add(certificate)
            .map_err(|error| HttpProxyError::TlsConfiguration(error.to_string()))?;
    }
    let embedded = rustls_pemfile::certs(&mut Cursor::new(include_bytes!(
        "../../../../component/ca/ca-certificates.crt"
    )))
    .collect::<Result<Vec<_>, _>>()
    .map_err(|error| HttpProxyError::TlsConfiguration(error.to_string()))?;
    for certificate in embedded {
        roots
            .add(certificate)
            .map_err(|error| HttpProxyError::TlsConfiguration(error.to_string()))?;
    }
    for pem in custom_roots {
        let certificates = rustls_pemfile::certs(&mut Cursor::new(pem.as_bytes()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| HttpProxyError::TlsConfiguration(error.to_string()))?;
        for certificate in certificates {
            roots
                .add(certificate)
                .map_err(|error| HttpProxyError::TlsConfiguration(error.to_string()))?;
        }
    }
    Ok(roots)
}

fn load_pem_or_path(value: &str) -> Result<Vec<u8>, HttpProxyError> {
    if value.contains("-----BEGIN") {
        Ok(value.as_bytes().to_vec())
    } else {
        std::fs::read(value).map_err(|error| HttpProxyError::TlsConfiguration(error.to_string()))
    }
}

fn load_certificates(value: &str) -> Result<Vec<CertificateDer<'static>>, HttpProxyError> {
    let bytes = load_pem_or_path(value)?;
    let certificates = rustls_pemfile::certs(&mut Cursor::new(bytes))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| HttpProxyError::TlsConfiguration(error.to_string()))?;
    if certificates.is_empty() {
        return Err(HttpProxyError::TlsConfiguration(
            "client certificate contains no certificate".to_owned(),
        ));
    }
    Ok(certificates)
}

fn load_private_key(value: &str) -> Result<PrivateKeyDer<'static>, HttpProxyError> {
    let bytes = load_pem_or_path(value)?;
    rustls_pemfile::private_key(&mut Cursor::new(bytes))
        .map_err(|error| HttpProxyError::TlsConfiguration(error.to_string()))?
        .ok_or_else(|| HttpProxyError::TlsConfiguration("client private key is missing".to_owned()))
}

pub(crate) fn shadow_client_config(
    tls: HttpProxyTls<'_>,
    client_hello_fingerprint: Option<&str>,
    client_hello_fingerprint_mlkem: bool,
    clock: Option<Arc<rewrite_services::AdjustedClock>>,
) -> Result<ClientConfig, HttpProxyError> {
    let time_provider = Arc::new(ShadowTimeProvider {
        clock: clock.unwrap_or_else(|| Arc::new(rewrite_services::AdjustedClock::default())),
    });
    let roots = load_root_store(tls.custom_roots)?;
    // Chrome fingerprint needs aws-lc so X25519MLKEM768 key shares can be offered.
    let provider = Arc::new(shadow_rustls::crypto::aws_lc_rs::default_provider());
    let builder = if tls.tls12_only {
        ClientConfig::builder_with_details(provider, time_provider)
            .with_protocol_versions(&[&shadow_rustls::version::TLS12])
            .map_err(|error| HttpProxyError::TlsConfiguration(error.to_string()))?
    } else if tls.tls13_only {
        ClientConfig::builder_with_details(provider, time_provider)
            .with_protocol_versions(&[&shadow_rustls::version::TLS13])
            .map_err(|error| HttpProxyError::TlsConfiguration(error.to_string()))?
    } else {
        ClientConfig::builder_with_details(provider, time_provider)
            .with_safe_default_protocol_versions()
            .map_err(|error| HttpProxyError::TlsConfiguration(error.to_string()))?
    };
    let builder = if let Some(fingerprint) = tls.fingerprint {
        let normalized = fingerprint.trim().replace(':', "");
        let fingerprint = hex::decode(normalized)
            .map_err(|error| HttpProxyError::TlsConfiguration(error.to_string()))?;
        let fingerprint: [u8; 32] = fingerprint.try_into().map_err(|_| {
            HttpProxyError::TlsConfiguration(
                "certificate fingerprint must contain 32 bytes".to_owned(),
            )
        })?;
        let verification_name = tls
            .verification_name
            .map(str::to_owned)
            .map(ServerName::try_from)
            .transpose()
            .map_err(|error| HttpProxyError::TlsConfiguration(error.to_string()))?;
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(FingerprintVerification {
                fingerprint,
                verification_name,
                algorithms: shadow_rustls::crypto::ring::default_provider()
                    .signature_verification_algorithms,
            }))
    } else if let Some(verification_name) = tls.verification_name {
        let verification_name = ServerName::try_from(verification_name.to_owned())
            .map_err(|error| HttpProxyError::TlsConfiguration(error.to_string()))?;
        let verifier = WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|error| HttpProxyError::TlsConfiguration(error.to_string()))?;
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NameOverrideVerification {
                verifier,
                verification_name,
            }))
    } else if tls.skip_certificate_verification {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification::new()))
    } else {
        builder.with_root_certificates(roots)
    };
    let mut config = match (tls.certificate, tls.private_key) {
        (Some(certificate), Some(private_key)) => {
            let certificates = load_certificates(certificate)?;
            let private_key = load_private_key(private_key)?;
            builder
                .with_client_auth_cert(certificates, private_key)
                .map_err(|error| HttpProxyError::TlsConfiguration(error.to_string()))
        }
        (None, None) => Ok(builder.with_no_client_auth()),
        _ => Err(HttpProxyError::TlsConfiguration(
            "client certificate and private key must be configured together".to_owned(),
        )),
    }?;
    config.alpn_protocols = tls
        .alpn_protocols
        .iter()
        .map(|value| value.to_vec())
        .collect();
    match client_hello_fingerprint {
        None | Some("") => {}
        Some(value) if value.eq_ignore_ascii_case("none") => {}
        Some(value) if value.eq_ignore_ascii_case("chrome") => {
            config.client_hello_fingerprint = Some(ClientHelloFingerprint::Chrome);
            config.client_hello_fingerprint_mlkem = client_hello_fingerprint_mlkem;
        }
        Some(value) => {
            return Err(HttpProxyError::TlsConfiguration(format!(
                "unsupported ShadowTLS client-fingerprint: {value}"
            )));
        }
    }
    Ok(config)
}

#[cfg(test)]
mod chrome_fingerprint_tests {
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    use shadow_rustls::pki_types::ServerName;
    use shadow_rustls::{ClientConnection, Stream};

    use super::*;
    use crate::tls::HttpProxyTls;

    const CHROME_CIPHERS_PARTIAL: &[u16] = &[
        0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
    ];

    const CHROME_EXT_TYPES: &[u16] = &[
        0x0000, 0x0005, 0x000a, 0x000b, 0x000d, 0x0010, 0x0012, 0x0017, 0x001b, 0x0023, 0x002b,
        0x002d, 0x0033, 0x44cd, 0xfe0d, 0xff01,
    ];

    fn is_grease(v: u16) -> bool {
        v & 0x0f0f == 0x0a0a
    }

    fn normalize_grease(v: u16) -> u16 {
        if is_grease(v) { 0x0a0a } else { v }
    }

    fn capture_client_hello(fingerprint: Option<&str>) -> Vec<u8> {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let capture = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            stream
                .set_read_timeout(Some(Duration::from_millis(800)))
                .ok();
            let mut header = [0_u8; 5];
            stream.read_exact(&mut header).expect("header");
            let len = u16::from_be_bytes([header[3], header[4]]) as usize;
            let mut body = vec![0_u8; len];
            stream.read_exact(&mut body).expect("body");
            let mut record = header.to_vec();
            record.extend_from_slice(&body);
            record
        });

        let config = Arc::new(
            shadow_client_config(
                HttpProxyTls {
                    server_name: "phase6c-shadow-tls.example",
                    verification_name: None,
                    skip_certificate_verification: true,
                    fingerprint: None,
                    certificate: None,
                    private_key: None,
                    custom_roots: &[],
                    ech_config: None,
                    alpn_protocols: &[b"h2", b"http/1.1"],
                    tls12_only: false,
                    tls13_only: false,
                },
                fingerprint,
                true,
                None,
            )
            .expect("config"),
        );
        let server_name = ServerName::try_from("phase6c-shadow-tls.example").expect("sni");
        let mut conn = ClientConnection::new(config, server_name).expect("conn");
        let mut sock = TcpStream::connect(addr).expect("connect");
        {
            let mut tls = Stream::new(&mut conn, &mut sock);
            let _ = tls.write(b"x");
        }
        let _ = sock.shutdown(Shutdown::Both);
        capture.join().expect("join")
    }

    fn parse_client_hello(raw: &[u8]) -> (Vec<u16>, Vec<u16>, Option<Vec<u8>>) {
        assert_eq!(raw[0], 0x16);
        let rec_len = u16::from_be_bytes([raw[3], raw[4]]) as usize;
        let hs = &raw[5..5 + rec_len];
        assert_eq!(hs[0], 0x01);
        let body_len = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | hs[3] as usize;
        let mut p = &hs[4..4 + body_len];
        p = &p[34..];
        let sid_len = p[0] as usize;
        p = &p[1 + sid_len..];
        let cs_len = u16::from_be_bytes([p[0], p[1]]) as usize;
        p = &p[2..];
        let mut ciphers = Vec::new();
        for i in (0..cs_len).step_by(2) {
            ciphers.push(u16::from_be_bytes([p[i], p[i + 1]]));
        }
        p = &p[cs_len..];
        let comp_len = p[0] as usize;
        p = &p[1 + comp_len..];
        let ext_len = u16::from_be_bytes([p[0], p[1]]) as usize;
        p = &p[2..2 + ext_len];
        let mut extensions = Vec::new();
        let mut ech_body = None;
        let mut q = p;
        while q.len() >= 4 {
            let typ = u16::from_be_bytes([q[0], q[1]]);
            let len = u16::from_be_bytes([q[2], q[3]]) as usize;
            if typ == 0xfe0d {
                ech_body = Some(q[4..4 + len].to_vec());
            }
            extensions.push(typ);
            q = &q[4 + len..];
        }
        (ciphers, extensions, ech_body)
    }

    #[test]
    fn chrome_partial_fingerprint_cipher_and_extension_set() {
        let raw = capture_client_hello(Some("chrome"));
        let (ciphers_raw, extensions_raw, ech_body) = parse_client_hello(&raw);

        assert!(is_grease(ciphers_raw[0]), "leading GREASE cipher");
        let ciphers: Vec<u16> = ciphers_raw.iter().copied().map(normalize_grease).collect();
        assert_eq!(ciphers, CHROME_CIPHERS_PARTIAL, "cipher suite list");

        assert!(is_grease(extensions_raw[0]), "leading GREASE extension");
        assert!(
            is_grease(*extensions_raw.last().expect("exts")),
            "trailing GREASE extension"
        );
        let grease_exts: Vec<u16> = extensions_raw
            .iter()
            .copied()
            .filter(|t| is_grease(*t))
            .collect();
        assert_eq!(grease_exts.len(), 2);
        assert_ne!(grease_exts[0], grease_exts[1]);

        let ech = ech_body.expect("missing GREASE ECH");
        assert_eq!(ech[0], 0x00, "ECH outer type");
        assert_eq!(
            &ech[1..5],
            &[0x00, 0x01, 0x00, 0x01],
            "HKDF-SHA256 + AES-128-GCM"
        );
        let enc_len = u16::from_be_bytes([ech[6], ech[7]]) as usize;
        assert_eq!(enc_len, 32, "X25519 encapsulated key length");
        let payload_len = u16::from_be_bytes([ech[8 + enc_len], ech[9 + enc_len]]) as usize;
        assert!(
            [144_usize, 176, 208, 240].contains(&payload_len),
            "BoringGREASEECH payload len {payload_len}"
        );

        let mut have: Vec<u16> = extensions_raw
            .iter()
            .copied()
            .filter(|t| !is_grease(*t))
            .map(normalize_grease)
            .collect();
        have.sort_unstable();
        have.dedup();
        let mut want: Vec<u16> = CHROME_EXT_TYPES.to_vec();
        want.sort_unstable();
        assert_eq!(have, want, "extension type set");
    }

    #[test]
    fn chrome_middle_extension_order_shuffles_across_dials() {
        let mut orders = std::collections::BTreeSet::new();
        for _ in 0..12 {
            let raw = capture_client_hello(Some("chrome"));
            let (_, extensions, _) = parse_client_hello(&raw);
            let middle: Vec<u16> = extensions[1..extensions.len() - 1].to_vec();
            orders.insert(middle);
        }
        assert!(
            orders.len() > 1,
            "expected ShuffleChromeTLSExtensions-style middle variance"
        );
    }

    #[test]
    fn default_fingerprint_is_not_chrome_shaped() {
        let raw = capture_client_hello(None);
        let (ciphers, _, _) = parse_client_hello(&raw);
        assert!(!ciphers.iter().any(|c| is_grease(*c)));
        let normalized: Vec<u16> = ciphers.iter().copied().map(normalize_grease).collect();
        assert_ne!(normalized, CHROME_CIPHERS_PARTIAL);
    }

    #[test]
    fn unsupported_fingerprint_names_are_rejected() {
        for name in [
            "firefox",
            "safari",
            "ios",
            "android",
            "edge",
            "360",
            "qq",
            "chrome120",
            "random",
        ] {
            let error = shadow_client_config(
                HttpProxyTls {
                    server_name: "phase6c-shadow-tls.example",
                    verification_name: None,
                    skip_certificate_verification: true,
                    fingerprint: None,
                    certificate: None,
                    private_key: None,
                    custom_roots: &[],
                    ech_config: None,
                    alpn_protocols: &[b"h2", b"http/1.1"],
                    tls12_only: false,
                    tls13_only: false,
                },
                Some(name),
                true,
                None,
            )
            .expect_err(name);
            assert!(
                error
                    .to_string()
                    .contains("unsupported ShadowTLS client-fingerprint"),
                "{name}: {error}"
            );
        }
    }
}
