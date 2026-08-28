use super::{Arc, BufReader, Cursor, FsPath};

#[derive(Debug)]
pub(super) struct AcceptAnyClientCertificate {
    mandatory: bool,
    signatures: Arc<dyn tokio_rustls::rustls::server::danger::ClientCertVerifier>,
    hints: Vec<tokio_rustls::rustls::DistinguishedName>,
}

impl tokio_rustls::rustls::server::danger::ClientCertVerifier for AcceptAnyClientCertificate {
    fn client_auth_mandatory(&self) -> bool {
        self.mandatory
    }

    fn root_hint_subjects(&self) -> &[tokio_rustls::rustls::DistinguishedName] {
        &self.hints
    }

    fn verify_client_cert(
        &self,
        _end_entity: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[tokio_rustls::rustls::pki_types::CertificateDer<'_>],
        _now: tokio_rustls::rustls::pki_types::UnixTime,
    ) -> Result<tokio_rustls::rustls::server::danger::ClientCertVerified, tokio_rustls::rustls::Error>
    {
        Ok(tokio_rustls::rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        signature: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        self.signatures
            .verify_tls12_signature(message, cert, signature)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        signature: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        self.signatures
            .verify_tls13_signature(message, cert, signature)
    }

    fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
        self.signatures.supported_verify_schemes()
    }
}
/// Validates controller TLS material before a runtime generation is published.
///
/// # Errors
///
/// Returns an I/O error for unreadable or invalid PEM material and ECH, whose
/// server-side support is not exposed by the selected TLS library.
pub fn prepare_tls_config(
    config: &rewrite_config::ControllerTls,
    clock: Arc<rewrite_services::AdjustedClock>,
) -> std::io::Result<tokio_rustls::rustls::ServerConfig> {
    if !config.ech_key.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "controller TLS ECH awaits Phase 5E2",
        ));
    }
    let certificate = load_pem_or_path(&config.certificate)?;
    let private_key = load_pem_or_path(&config.private_key)?;
    let certificates = rustls_pemfile::certs(&mut BufReader::new(Cursor::new(certificate)))
        .collect::<Result<Vec<_>, _>>()?;
    let private_key = rustls_pemfile::private_key(&mut BufReader::new(Cursor::new(private_key)))?
        .ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "private key not found")
    })?;
    let client_auth: Option<Arc<dyn tokio_rustls::rustls::server::danger::ClientCertVerifier>> = if matches!(
        config.client_auth_type.as_str(),
        "verify-if-given" | "require-and-verify"
    ) {
        let client_ca = load_pem_or_path(&config.client_auth_cert)?;
        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        let client_certificates =
            rustls_pemfile::certs(&mut BufReader::new(Cursor::new(client_ca)))
                .collect::<Result<Vec<_>, _>>()?;
        let (accepted, _) = roots.add_parsable_certificates(client_certificates);
        if accepted == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "client CA certificate not found",
            ));
        }
        let mut verifier =
            tokio_rustls::rustls::server::WebPkiClientVerifier::builder(roots.into());
        if config.client_auth_type == "verify-if-given" {
            verifier = verifier.allow_unauthenticated();
        }
        Some(verifier.build().map_err(std::io::Error::other)?)
    } else if matches!(config.client_auth_type.as_str(), "request" | "require-any") {
        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        let signature_roots = if config.client_auth_cert.is_empty() {
            certificates.clone()
        } else {
            let client_ca = load_pem_or_path(&config.client_auth_cert)?;
            rustls_pemfile::certs(&mut BufReader::new(Cursor::new(client_ca)))
                .collect::<Result<Vec<_>, _>>()?
        };
        let (accepted, _) = roots.add_parsable_certificates(signature_roots);
        if accepted == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "client signature verifier roots are empty",
            ));
        }
        let signatures = tokio_rustls::rustls::server::WebPkiClientVerifier::builder(roots.into())
            .allow_unauthenticated()
            .build()
            .map_err(std::io::Error::other)?;
        Some(Arc::new(AcceptAnyClientCertificate {
            mandatory: config.client_auth_type == "require-any",
            signatures,
            hints: Vec::new(),
        }))
    } else {
        None
    };
    let builder = tokio_rustls::rustls::ServerConfig::builder_with_details(
        Arc::new(tokio_rustls::rustls::crypto::ring::default_provider()),
        clock,
    )
    .with_safe_default_protocol_versions()
    .map_err(std::io::Error::other)?;
    let mut server = match client_auth {
        Some(verifier) => builder.with_client_cert_verifier(verifier),
        None => builder.with_no_client_auth(),
    }
    .with_single_cert(certificates, private_key)
    .map_err(std::io::Error::other)?;
    server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(server)
}

pub(super) fn load_pem_or_path(value: &str) -> std::io::Result<Vec<u8>> {
    if value.contains("-----BEGIN") {
        Ok(value.as_bytes().to_vec())
    } else if value.is_empty() {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "TLS PEM value is empty",
        ))
    } else {
        std::fs::read(FsPath::new(value))
    }
}
