use std::io::Cursor;
use std::sync::Arc;

use sha2::{Digest, Sha256};
use tokio_rustls::rustls::client::WebPkiServerVerifier;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::client::{EchConfig, EchMode};
use tokio_rustls::rustls::crypto::aws_lc_rs::hpke::ALL_SUPPORTED_SUITES;
use tokio_rustls::rustls::crypto::{
    WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature,
};
use tokio_rustls::rustls::pki_types::{
    CertificateDer, EchConfigListBytes, PrivateKeyDer, ServerName, UnixTime,
};
use tokio_rustls::rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, RootCertStore, SignatureScheme,
};

use crate::http::HttpProxyError;

#[derive(Clone, Copy, Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct HttpProxyTls<'a> {
    pub server_name: &'a str,
    pub verification_name: Option<&'a str>,
    pub skip_certificate_verification: bool,
    pub fingerprint: Option<&'a str>,
    pub certificate: Option<&'a str>,
    pub private_key: Option<&'a str>,
    pub custom_roots: &'a [String],
    pub ech_config: Option<&'a [u8]>,
    pub alpn_protocols: &'a [&'a [u8]],
    pub tls12_only: bool,
    pub tls13_only: bool,
    /// Optional `ClientHello` fingerprint (`chrome`, …) for `ShadowTLS` camouflage.
    pub client_hello_fingerprint: Option<&'a str>,
    /// Include X25519MLKEM768 when fingerprinting Chrome (false for `ShadowTLS` v2).
    pub client_hello_fingerprint_mlkem: bool,
}

#[derive(Debug)]
struct NoCertificateVerification {
    algorithms: WebPkiSupportedAlgorithms,
}

impl NoCertificateVerification {
    fn new() -> Self {
        Self {
            algorithms: tokio_rustls::rustls::crypto::ring::default_provider()
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

pub(crate) fn client_config(
    tls: HttpProxyTls<'_>,
    clock: Option<Arc<rewrite_services::AdjustedClock>>,
) -> Result<ClientConfig, HttpProxyError> {
    let clock = clock.unwrap_or_else(|| Arc::new(rewrite_services::AdjustedClock::default()));
    let roots = load_root_store(tls.custom_roots)?;
    let chrome = tls
        .client_hello_fingerprint
        .is_some_and(|value| value.eq_ignore_ascii_case("chrome"));
    let builder = if let Some(ech_config) = tls.ech_config {
        let provider = Arc::new(tokio_rustls::rustls::crypto::aws_lc_rs::default_provider());
        let ech_config = EchConfig::new(EchConfigListBytes::from(ech_config), ALL_SUPPORTED_SUITES)
            .map_err(|error| HttpProxyError::TlsConfiguration(error.to_string()))?;
        ClientConfig::builder_with_details(provider, clock)
            .with_ech(EchMode::Enable(ech_config))
            .map_err(|error| HttpProxyError::TlsConfiguration(error.to_string()))?
    } else {
        // Chrome fingerprint needs aws-lc so X25519MLKEM768 key shares can be offered.
        let provider = if chrome {
            Arc::new(tokio_rustls::rustls::crypto::aws_lc_rs::default_provider())
        } else {
            Arc::new(tokio_rustls::rustls::crypto::ring::default_provider())
        };
        if tls.tls12_only {
            ClientConfig::builder_with_details(provider, clock)
                .with_protocol_versions(&[&tokio_rustls::rustls::version::TLS12])
                .map_err(|error| HttpProxyError::TlsConfiguration(error.to_string()))?
        } else if tls.tls13_only {
            ClientConfig::builder_with_details(provider, clock)
                .with_protocol_versions(&[&tokio_rustls::rustls::version::TLS13])
                .map_err(|error| HttpProxyError::TlsConfiguration(error.to_string()))?
        } else {
            ClientConfig::builder_with_details(provider, clock)
                .with_safe_default_protocol_versions()
                .map_err(|error| HttpProxyError::TlsConfiguration(error.to_string()))?
        }
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
                algorithms: tokio_rustls::rustls::crypto::ring::default_provider()
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
    apply_alpn(&mut config, tls.alpn_protocols);
    if chrome {
        apply_chrome_client_hello(&mut config, tls.client_hello_fingerprint_mlkem);
    }
    Ok(config)
}

fn apply_chrome_client_hello(config: &mut ClientConfig, include_mlkem: bool) {
    config.client_hello_fingerprint = Some(tokio_rustls::rustls::ClientHelloFingerprint::Chrome);
    config.client_hello_fingerprint_mlkem = include_mlkem;
    // BoringGREASEECH is emitted inside apply_chrome_fingerprint as an
    // extra_extension (do not also enable rustls EchMode::Grease).
}

fn apply_alpn(config: &mut ClientConfig, protocols: &[&[u8]]) {
    config.alpn_protocols = protocols.iter().map(|value| value.to_vec()).collect();
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

#[cfg(test)]
mod chrome_fingerprint_tests {
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    use tokio_rustls::rustls::pki_types::ServerName;
    use tokio_rustls::rustls::{ClientConnection, Stream};

    use super::*;

    /// Partial Chrome fingerprint cipher list (rustls aws-lc supported suites only).
    /// Full uTLS HelloChrome_133 advertises 16 suites including RSA/CBC (`c013`,
    /// `c014`, `009c`, `009d`, `002f`, `0035`); those are intentionally omitted.
    const CHROME_CIPHERS_PARTIAL: &[u16] = &[
        0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
    ];

    /// Extension types Chrome 133 offers (GREASE normalized; order not asserted).
    const CHROME_EXT_TYPES: &[u16] = &[
        0x0000, // server_name
        0x0005, // status_request
        0x000a, // supported_groups
        0x000b, // ec_point_formats
        0x000d, // signature_algorithms
        0x0010, // alpn
        0x0012, // sct
        0x0017, // extended_master_secret
        0x001b, // compress_certificate
        0x0023, // session_ticket
        0x002b, // supported_versions
        0x002d, // psk_key_exchange_modes
        0x0033, // key_share
        0x44cd, // alps new
        0xfe0d, // encrypted_client_hello (GREASE)
        0xff01, // renegotiation_info
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
            client_config(
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
                    client_hello_fingerprint: fingerprint,
                    client_hello_fingerprint_mlkem: true,
                },
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
        p = &p[34..]; // version + random
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
        // Self-check of the partial rustls Chrome shape — not a Go/Rust differential.
        // Go/uTLS HelloChrome_133 still advertises six extra cipher suites that rustls
        // aws-lc cannot negotiate; see CHROME_CIPHERS_PARTIAL above.
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
        // Two distinct GREASE extension codepoints (BoringSSL / uTLS rule).
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
    fn non_chrome_fingerprint_names_stay_rustls_default() {
        // Go maps these via uTLS parrots; we accept the labels without shaping
        // (Clash still dials; ClientHello stays rustls-default).
        for name in [
            "firefox",
            "safari",
            "ios",
            "android",
            "edge",
            "360",
            "qq",
            "chrome120",
        ] {
            let raw = capture_client_hello(Some(name));
            let (ciphers, _, _) = parse_client_hello(&raw);
            assert!(
                !ciphers.iter().any(|c| is_grease(*c)),
                "{name} should not get chrome GREASE shaping"
            );
        }
    }
}
