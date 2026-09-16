use std::collections::HashMap;
use std::io::Cursor;
use std::sync::{Arc, Mutex, OnceLock};

use sha2::{Digest, Sha256};
use tokio_rustls::rustls::client::WebPkiServerVerifier;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::client::{EchConfig, EchMode, Resumption};
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

#[derive(Debug, thiserror::Error)]
pub enum TlsClientError {
    #[error("HTTP proxy TLS configuration is invalid: {0}")]
    Configuration(String),
    #[error("HTTP proxy TLS handshake timed out")]
    Timeout,
    #[error("HTTP proxy TLS handshake failed: {0}")]
    Handshake(std::io::Error),
}

#[derive(Clone, Copy, Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct ClientTlsOptions<'a> {
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
}

#[derive(Debug)]
struct NoCertificateVerification {
    algorithms: WebPkiSupportedAlgorithms,
}

impl NoCertificateVerification {
    fn new() -> Self {
        Self {
            algorithms: tokio_rustls::rustls::crypto::aws_lc_rs::default_provider()
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

fn load_root_store(custom_roots: &[String]) -> Result<RootCertStore, TlsClientError> {
    // System + embedded roots are expensive to parse; share across dials when no
    // per-proxy PEMs are attached (Go caches via GetCertPool).
    if custom_roots.is_empty() {
        return shared_native_root_store().map(|roots| (*roots).clone());
    }
    let mut roots = (*shared_native_root_store()?).clone();
    for pem in custom_roots {
        let certificates = rustls_pemfile::certs(&mut Cursor::new(pem.as_bytes()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| TlsClientError::Configuration(error.to_string()))?;
        for certificate in certificates {
            roots
                .add(certificate)
                .map_err(|error| TlsClientError::Configuration(error.to_string()))?;
        }
    }
    Ok(roots)
}

fn shared_native_root_store() -> Result<Arc<RootCertStore>, TlsClientError> {
    static ROOTS: OnceLock<Result<Arc<RootCertStore>, String>> = OnceLock::new();
    match ROOTS.get_or_init(|| {
        let mut roots = RootCertStore::empty();
        let native = rustls_native_certs::load_native_certs();
        for certificate in native.certs {
            roots
                .add(certificate)
                .map_err(|error| error.to_string())?;
        }
        let embedded = rustls_pemfile::certs(&mut Cursor::new(include_bytes!(
            "../../../../component/ca/ca-certificates.crt"
        )))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
        for certificate in embedded {
            roots
                .add(certificate)
                .map_err(|error| error.to_string())?;
        }
        Ok(Arc::new(roots))
    }) {
        Ok(roots) => Ok(Arc::clone(roots)),
        Err(error) => Err(TlsClientError::Configuration(error.clone())),
    }
}

#[derive(Clone, Eq, Hash, PartialEq)]
struct SkipVerifyCacheKey {
    alpn: Vec<Vec<u8>>,
    tls12_only: bool,
    tls13_only: bool,
}

fn skip_verify_config_cache() -> &'static Mutex<HashMap<SkipVerifyCacheKey, Arc<ClientConfig>>> {
    static CACHE: OnceLock<Mutex<HashMap<SkipVerifyCacheKey, Arc<ClientConfig>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Builds a shared rustls client config, caching the common skip-verify path so
/// repeated Trojan/VLESS dials do not re-parse CA material or rebuild crypto.
///
/// # Errors
///
/// Returns configuration failures from [`client_config`].
pub fn client_config_arc(
    tls: ClientTlsOptions<'_>,
    clock: Option<Arc<rewrite_services::AdjustedClock>>,
) -> Result<Arc<ClientConfig>, TlsClientError> {
    let cacheable = tls.skip_certificate_verification
        && tls.fingerprint.is_none()
        && tls.verification_name.is_none()
        && tls.certificate.is_none()
        && tls.private_key.is_none()
        && tls.custom_roots.is_empty()
        && tls.ech_config.is_none();
    if cacheable {
        let key = SkipVerifyCacheKey {
            alpn: tls
                .alpn_protocols
                .iter()
                .map(|value| value.to_vec())
                .collect(),
            tls12_only: tls.tls12_only,
            tls13_only: tls.tls13_only,
        };
        if let Ok(guard) = skip_verify_config_cache().lock()
            && let Some(config) = guard.get(&key)
        {
            return Ok(Arc::clone(config));
        }
        // Skip-verify ignores AdjustedClock; share one Arc so tickets resume.
        let mut config = client_config(tls, None)?;
        config.resumption = Resumption::in_memory_sessions(256);
        let config = Arc::new(config);
        if let Ok(mut guard) = skip_verify_config_cache().lock() {
            guard.insert(key, Arc::clone(&config));
        }
        return Ok(config);
    }
    Ok(Arc::new(client_config(tls, clock)?))
}

/// Builds the shared rustls client configuration for an outer transport.
///
/// # Errors
///
/// Returns an error for invalid roots, client identity, fingerprint, ECH or
/// protocol-version constraints.
pub fn client_config(
    tls: ClientTlsOptions<'_>,
    clock: Option<Arc<rewrite_services::AdjustedClock>>,
) -> Result<ClientConfig, TlsClientError> {
    let clock = clock.unwrap_or_else(|| Arc::new(rewrite_services::AdjustedClock::default()));
    // Skip-verify never consults the root store — avoid parsing CA bundles.
    let roots = if tls.skip_certificate_verification
        && tls.fingerprint.is_none()
        && tls.verification_name.is_none()
    {
        RootCertStore::empty()
    } else {
        load_root_store(tls.custom_roots)?
    };
    let builder = if let Some(ech_config) = tls.ech_config {
        let provider = Arc::new(tokio_rustls::rustls::crypto::aws_lc_rs::default_provider());
        let ech_config = EchConfig::new(EchConfigListBytes::from(ech_config), ALL_SUPPORTED_SUITES)
            .map_err(|error| TlsClientError::Configuration(error.to_string()))?;
        ClientConfig::builder_with_details(provider, clock)
            .with_ech(EchMode::Enable(ech_config))
            .map_err(|error| TlsClientError::Configuration(error.to_string()))?
    } else {
        let provider = Arc::new(tokio_rustls::rustls::crypto::aws_lc_rs::default_provider());
        if tls.tls12_only {
            ClientConfig::builder_with_details(provider, clock)
                .with_protocol_versions(&[&tokio_rustls::rustls::version::TLS12])
                .map_err(|error| TlsClientError::Configuration(error.to_string()))?
        } else if tls.tls13_only {
            ClientConfig::builder_with_details(provider, clock)
                .with_protocol_versions(&[&tokio_rustls::rustls::version::TLS13])
                .map_err(|error| TlsClientError::Configuration(error.to_string()))?
        } else {
            ClientConfig::builder_with_details(provider, clock)
                .with_safe_default_protocol_versions()
                .map_err(|error| TlsClientError::Configuration(error.to_string()))?
        }
    };
    let builder = if let Some(fingerprint) = tls.fingerprint {
        let normalized = fingerprint.trim().replace(':', "");
        let fingerprint = hex::decode(normalized)
            .map_err(|error| TlsClientError::Configuration(error.to_string()))?;
        let fingerprint: [u8; 32] = fingerprint.try_into().map_err(|_| {
            TlsClientError::Configuration(
                "certificate fingerprint must contain 32 bytes".to_owned(),
            )
        })?;
        let verification_name = tls
            .verification_name
            .map(str::to_owned)
            .map(ServerName::try_from)
            .transpose()
            .map_err(|error| TlsClientError::Configuration(error.to_string()))?;
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(FingerprintVerification {
                fingerprint,
                verification_name,
                algorithms: tokio_rustls::rustls::crypto::aws_lc_rs::default_provider()
                    .signature_verification_algorithms,
            }))
    } else if let Some(verification_name) = tls.verification_name {
        let verification_name = ServerName::try_from(verification_name.to_owned())
            .map_err(|error| TlsClientError::Configuration(error.to_string()))?;
        let verifier = WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .map_err(|error| TlsClientError::Configuration(error.to_string()))?;
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
                .map_err(|error| TlsClientError::Configuration(error.to_string()))
        }
        (None, None) => Ok(builder.with_no_client_auth()),
        _ => Err(TlsClientError::Configuration(
            "client certificate and private key must be configured together".to_owned(),
        )),
    }?;
    apply_alpn(&mut config, tls.alpn_protocols);
    Ok(config)
}

fn apply_alpn(config: &mut ClientConfig, protocols: &[&[u8]]) {
    config.alpn_protocols = protocols.iter().map(|value| value.to_vec()).collect();
}

fn load_pem_or_path(value: &str) -> Result<Vec<u8>, TlsClientError> {
    if value.contains("-----BEGIN") {
        Ok(value.as_bytes().to_vec())
    } else {
        std::fs::read(value).map_err(|error| TlsClientError::Configuration(error.to_string()))
    }
}

fn load_certificates(value: &str) -> Result<Vec<CertificateDer<'static>>, TlsClientError> {
    let bytes = load_pem_or_path(value)?;
    let certificates = rustls_pemfile::certs(&mut Cursor::new(bytes))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| TlsClientError::Configuration(error.to_string()))?;
    if certificates.is_empty() {
        return Err(TlsClientError::Configuration(
            "client certificate contains no certificate".to_owned(),
        ));
    }
    Ok(certificates)
}

fn load_private_key(value: &str) -> Result<PrivateKeyDer<'static>, TlsClientError> {
    let bytes = load_pem_or_path(value)?;
    rustls_pemfile::private_key(&mut Cursor::new(bytes))
        .map_err(|error| TlsClientError::Configuration(error.to_string()))?
        .ok_or_else(|| TlsClientError::Configuration("client private key is missing".to_owned()))
}
