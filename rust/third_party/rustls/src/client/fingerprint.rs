//! ClientHello fingerprint profiles for camouflage (ShadowTLS / uTLS parity).
//!
//! These profiles only reshape the *offered* ClientHello. Negotiation still
//! requires a suite/group the configured [`CryptoProvider`] can actually use.
//!
//! Chrome shape targets metacubex/utls `HelloChrome_Auto` (= `HelloChrome_133`):
//! cipher suite list, GREASE, extension set, and a stable contiguous extension
//! order. Go still runs `ShuffleChromeTLSExtensions` on the middle extensions;
//! we keep a fixed order so differentials are stable (documented mismatch).

use alloc::vec;
use alloc::vec::Vec;

use crate::enums::{
    CertificateCompressionAlgorithm, CipherSuite, ProtocolVersion, SignatureScheme,
};
use crate::msgs::base::PayloadU8;
use crate::msgs::enums::{ExtensionType, NamedGroup};
use crate::msgs::handshake::{
    ClientExtensions, ClientSessionTicket, KeyShareEntry, ProtocolName, SupportedProtocolVersions,
};

/// Browser-like ClientHello shape applied during handshake construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ClientHelloFingerprint {
    /// Google Chrome (uTLS `HelloChrome_Auto` / Chrome 133) shape.
    Chrome,
}

const GREASE_CIPHER: CipherSuite = CipherSuite::Unknown(0x0a0a);
const GREASE_GROUP: NamedGroup = NamedGroup::Unknown(0x0a0a);
const GREASE_VERSION: ProtocolVersion = ProtocolVersion::Unknown(0x0a0a);
const GREASE_EXT_A: ExtensionType = ExtensionType::Unknown(0x0a0a);
const GREASE_EXT_B: ExtensionType = ExtensionType::Unknown(0x1a1a);
/// ALPS "new" codepoint used by Chrome (`utls` `ApplicationSettingsExtensionNew`).
const ALPS_NEW: ExtensionType = ExtensionType::Unknown(17613);

/// Chrome 133 cipher suite order from metacubex/utls `HelloChrome_133`.
pub(super) fn chrome_cipher_suites() -> Vec<CipherSuite> {
    vec![
        GREASE_CIPHER,
        CipherSuite::TLS13_AES_128_GCM_SHA256,
        CipherSuite::TLS13_AES_256_GCM_SHA384,
        CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        CipherSuite::TLS_RSA_WITH_AES_128_GCM_SHA256,
        CipherSuite::TLS_RSA_WITH_AES_256_GCM_SHA384,
        CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
        CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA,
    ]
}

fn chrome_signature_schemes() -> Vec<SignatureScheme> {
    vec![
        SignatureScheme::ECDSA_NISTP256_SHA256,
        SignatureScheme::RSA_PSS_SHA256,
        SignatureScheme::RSA_PKCS1_SHA256,
        SignatureScheme::ECDSA_NISTP384_SHA384,
        SignatureScheme::RSA_PSS_SHA384,
        SignatureScheme::RSA_PKCS1_SHA384,
        SignatureScheme::RSA_PSS_SHA512,
        SignatureScheme::RSA_PKCS1_SHA512,
    ]
}

fn encode_alpn_list(protocols: &[&str]) -> Vec<u8> {
    let mut body = Vec::new();
    for protocol in protocols {
        let bytes = protocol.as_bytes();
        body.push(u8::try_from(bytes.len()).expect("alpn proto length"));
        body.extend_from_slice(bytes);
    }
    let mut out = Vec::with_capacity(2 + body.len());
    let len = u16::try_from(body.len()).expect("alpn list length");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&body);
    out
}

/// Apply Chrome ClientHello shaping to extensions + cipher list.
///
/// `include_mlkem` mirrors Go: v3 keeps X25519MLKEM768; v2 strips it.
pub(super) fn apply_chrome_fingerprint(
    exts: &mut ClientExtensions<'_>,
    cipher_suites: &mut Vec<CipherSuite>,
    include_mlkem: bool,
) {
    *cipher_suites = chrome_cipher_suites();

    let mut groups = vec![GREASE_GROUP];
    if include_mlkem {
        groups.push(NamedGroup::X25519MLKEM768);
    }
    groups.extend([
        NamedGroup::X25519,
        NamedGroup::secp256r1,
        NamedGroup::secp384r1,
    ]);
    exts.named_groups = Some(groups);

    exts.signature_schemes = Some(chrome_signature_schemes());
    exts.supported_versions = Some(SupportedProtocolVersions {
        tls13: true,
        tls12: true,
        grease: Some(GREASE_VERSION),
    });
    exts.session_ticket = Some(ClientSessionTicket::Request);
    exts.renegotiation_info = Some(PayloadU8::new(Vec::new()));
    exts.extended_master_secret_request = Some(());
    exts.certificate_status_request =
        Some(crate::msgs::handshake::CertificateStatusRequest::build_ocsp());
    exts.ec_point_formats = Some(crate::msgs::handshake::SupportedEcPointFormats::default());
    exts.preshared_key_modes = Some(crate::msgs::handshake::PskKeyExchangeModes {
        psk: false,
        psk_dhe: true,
    });
    exts.certificate_compression_algorithms =
        Some(vec![CertificateCompressionAlgorithm::Brotli]);

    // Chrome parrot ALPN when the caller did not configure any.
    if exts.protocols.is_none() {
        exts.protocols = Some(vec![
            ProtocolName::from(b"h2".to_vec()),
            ProtocolName::from(b"http/1.1".to_vec()),
        ]);
    }

    // Not part of the Chrome ClientHello parrot.
    exts.certificate_authority_names = None;
    exts.ticket_request = None;
    exts.early_data_request = None;
    exts.client_certificate_types = None;
    exts.server_certificate_types = None;

    // Prepend GREASE key share (one zero byte, matching uTLS Chrome parrot).
    let mut shares = vec![KeyShareEntry::new(GREASE_GROUP, vec![0])];
    if let Some(existing) = exts.key_shares.take() {
        for share in existing {
            if !include_mlkem && share.group == NamedGroup::X25519MLKEM768 {
                continue;
            }
            shares.push(share);
        }
    }
    exts.key_shares = Some(shares);

    // Extra extensions Chrome offers that rustls does not model as first-class fields.
    // First GREASE body empty; last GREASE body a single zero (BoringSSL / uTLS).
    exts.extra_extensions = vec![
        (GREASE_EXT_A, Vec::new()),
        (ExtensionType::SCT, Vec::new()),
        (ALPS_NEW, encode_alpn_list(&["h2"])),
        (GREASE_EXT_B, vec![0x00]),
    ];

    // Contiguous order for known + extra types. ECH GREASE (when enabled on the
    // ClientConfig) slots before the trailing GREASE, matching Chrome 133.
    // Middle extensions are not shuffled here (Go's ShuffleChromeTLSExtensions does).
    exts.contiguous_extensions = vec![
        GREASE_EXT_A,
        ExtensionType::ServerName,
        ExtensionType::ExtendedMasterSecret,
        ExtensionType::RenegotiationInfo,
        ExtensionType::EllipticCurves,
        ExtensionType::ECPointFormats,
        ExtensionType::SessionTicket,
        ExtensionType::ALProtocolNegotiation,
        ExtensionType::StatusRequest,
        ExtensionType::SignatureAlgorithms,
        ExtensionType::SCT,
        ExtensionType::KeyShare,
        ExtensionType::PSKKeyExchangeModes,
        ExtensionType::SupportedVersions,
        ExtensionType::CompressCertificate,
        ALPS_NEW,
        ExtensionType::EncryptedClientHello,
        GREASE_EXT_B,
    ];
    // Disable random bucket so contiguous order wins.
    exts.order_seed = 0;
}
