//! ClientHello fingerprint profiles for camouflage (ShadowTLS / uTLS parity).
//!
//! Chrome shape targets metacubex/utls `HelloChrome_Auto` (= `HelloChrome_133`):
//! cipher suite list, BoringSSL GREASE, extension set, middle-extension shuffle
//! (GREASE bookends fixed), and BoringGREASEECH payload shape.

use alloc::vec;
use alloc::vec::Vec;

use crate::crypto::SecureRandom;
use crate::crypto::aws_lc_rs::hpke::DH_KEM_X25519_HKDF_SHA256_AES_128;
use crate::crypto::hpke::{Hpke, HpkePublicKey};
use crate::enums::{
    CertificateCompressionAlgorithm, CipherSuite, ProtocolVersion, SignatureScheme,
};
use crate::error::Error;
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

/// BoringSSL GREASE seed indices (metacubex/utls `ssl_grease_*`).
const GREASE_CIPHER_IDX: usize = 0;
const GREASE_GROUP_IDX: usize = 1;
const GREASE_EXT1_IDX: usize = 2;
const GREASE_EXT2_IDX: usize = 3;
const GREASE_VERSION_IDX: usize = 4;
const GREASE_SEED_LEN: usize = 5;

/// ALPS "new" codepoint used by Chrome (`utls` `ApplicationSettingsExtensionNew`).
const ALPS_NEW: ExtensionType = ExtensionType::Unknown(17613);

/// BoringGREASEECH candidate plaintext lengths (ciphertext = len + 16 for AES-GCM).
const ECH_GREASE_PAYLOAD_PLAIN_LENS: [u16; 4] = [128, 160, 192, 224];

/// Fixed dummy X25519 public key used by uTLS/cloudflare-go GREASE ECH (`dummyX25519PublicKey`).
const DUMMY_X25519_PUBLIC_KEY: [u8; 32] = [
    143, 38, 37, 36, 12, 6, 229, 30, 140, 27, 167, 73, 26, 100, 203, 107, 216, 81, 163, 222, 52,
    211, 54, 210, 46, 37, 78, 216, 157, 97, 241, 244,
];

/// Chrome 133 cipher suite order from metacubex/utls `HelloChrome_133` (GREASE slot first).
fn chrome_cipher_suites(grease_cipher: CipherSuite) -> Vec<CipherSuite> {
    vec![
        grease_cipher,
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

/// BoringSSL GREASE: `0xωaωa` from a per-index seed (utls `GetBoringGREASEValue`).
pub(super) fn boring_grease_value(seed: u16) -> u16 {
    let mut ret = seed;
    ret = (ret & 0xf0) | 0x0a;
    ret | (ret << 8)
}

fn fill_grease_seeds(rng: &dyn SecureRandom) -> Result<[u16; GREASE_SEED_LEN], Error> {
    let mut bytes = [0_u8; GREASE_SEED_LEN * 2];
    rng.fill(&mut bytes)?;
    let mut seeds = [0_u16; GREASE_SEED_LEN];
    for (i, seed) in seeds.iter_mut().enumerate() {
        *seed = u16::from_le_bytes([bytes[2 * i], bytes[2 * i + 1]]);
    }
    // Extension GREASE values must differ (utls ApplyPreset).
    if boring_grease_value(seeds[GREASE_EXT1_IDX]) == boring_grease_value(seeds[GREASE_EXT2_IDX]) {
        seeds[GREASE_EXT2_IDX] ^= 0x1010;
    }
    Ok(seeds)
}

/// Shuffle middle extensions; keep GREASE / padding / PSK bookends fixed
/// (utls `ShuffleChromeTLSExtensions`).
pub(super) fn shuffle_chrome_extensions(
    exts: &mut [ExtensionType],
    rng: &dyn SecureRandom,
) -> Result<(), Error> {
    if exts.len() < 3 {
        return Ok(());
    }
    let skip = |typ: ExtensionType| match typ {
        ExtensionType::PreSharedKey => true,
        ExtensionType::Unknown(v) if is_grease_u16(v) => true,
        _ => false,
    };
    // Fisher–Yates over indices, skipping invariant positions like Go's Shuffle.
    for i in (1..exts.len()).rev() {
        let mut buf = [0_u8; 8];
        rng.fill(&mut buf)?;
        let j = (u64::from_le_bytes(buf) as usize) % (i + 1);
        if skip(exts[i]) || skip(exts[j]) {
            continue;
        }
        exts.swap(i, j);
    }
    Ok(())
}

fn is_grease_u16(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a
}

/// BoringGREASEECH extension body (type/length added by encoder).
///
/// Matches metacubex/utls `BoringGREASEECH`: HKDF-SHA256 + AES-128-GCM, X25519-sized
/// encapsulated key (32 bytes), payload length from `{128,160,192,224}+16`.
fn build_boring_grease_ech(rng: &dyn SecureRandom) -> Result<Vec<u8>, Error> {
    let mut config_id = [0_u8; 1];
    rng.fill(&mut config_id)?;
    let mut pick = [0_u8; 1];
    rng.fill(&mut pick)?;
    let plain = ECH_GREASE_PAYLOAD_PLAIN_LENS[pick[0] as usize % ECH_GREASE_PAYLOAD_PLAIN_LENS.len()];
    let payload_len = usize::from(plain) + 16;

    let pub_key = HpkePublicKey(DUMMY_X25519_PUBLIC_KEY.to_vec());
    let (enc, _sealer) = DH_KEM_X25519_HKDF_SHA256_AES_128.setup_sealer(&[], &pub_key)?;
    let enc = enc.0;
    let mut payload = vec![0_u8; payload_len];
    rng.fill(&mut payload)?;

    let mut out = Vec::with_capacity(1 + 4 + 1 + 2 + enc.len() + 2 + payload.len());
    out.push(0x00); // Outer ClientHello
    out.extend_from_slice(&0x0001_u16.to_be_bytes()); // HKDF_SHA256
    out.extend_from_slice(&0x0001_u16.to_be_bytes()); // AES_128_GCM
    out.push(config_id[0]);
    out.extend_from_slice(&(enc.len() as u16).to_be_bytes());
    out.extend_from_slice(&enc);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

/// Apply Chrome ClientHello shaping to extensions + cipher list.
///
/// `include_mlkem` mirrors Go: v3 keeps X25519MLKEM768; v2 strips it.
pub(super) fn apply_chrome_fingerprint(
    exts: &mut ClientExtensions<'_>,
    cipher_suites: &mut Vec<CipherSuite>,
    include_mlkem: bool,
    secure_random: &'static dyn SecureRandom,
) -> Result<(), Error> {
    let seeds = fill_grease_seeds(secure_random)?;
    let grease_cipher = CipherSuite::Unknown(boring_grease_value(seeds[GREASE_CIPHER_IDX]));
    let grease_group = NamedGroup::Unknown(boring_grease_value(seeds[GREASE_GROUP_IDX]));
    let grease_version = ProtocolVersion::Unknown(boring_grease_value(seeds[GREASE_VERSION_IDX]));
    let grease_ext_a = ExtensionType::Unknown(boring_grease_value(seeds[GREASE_EXT1_IDX]));
    let grease_ext_b = ExtensionType::Unknown(boring_grease_value(seeds[GREASE_EXT2_IDX]));

    *cipher_suites = chrome_cipher_suites(grease_cipher);

    let mut groups = vec![grease_group];
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
        grease: Some(grease_version),
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

    if exts.protocols.is_none() {
        exts.protocols = Some(vec![
            ProtocolName::from(b"h2".to_vec()),
            ProtocolName::from(b"http/1.1".to_vec()),
        ]);
    }

    exts.certificate_authority_names = None;
    exts.ticket_request = None;
    exts.early_data_request = None;
    exts.client_certificate_types = None;
    exts.server_certificate_types = None;
    // Chrome GREASE ECH is an extra_extension; do not also set typed ECH / EchMode.
    exts.encrypted_client_hello = None;
    exts.encrypted_client_hello_outer = None;

    let mut shares = vec![KeyShareEntry::new(grease_group, vec![0])];
    if let Some(existing) = exts.key_shares.take() {
        for share in existing {
            if !include_mlkem && share.group == NamedGroup::X25519MLKEM768 {
                continue;
            }
            shares.push(share);
        }
    }
    exts.key_shares = Some(shares);

    let ech_body = build_boring_grease_ech(secure_random)?;
    exts.extra_extensions = vec![
        (grease_ext_a, Vec::new()),
        (ExtensionType::SCT, Vec::new()),
        (ALPS_NEW, encode_alpn_list(&["h2"])),
        (ExtensionType::EncryptedClientHello, ech_body),
        (grease_ext_b, vec![0x00]),
    ];

    let mut order = vec![
        grease_ext_a,
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
        grease_ext_b,
    ];
    shuffle_chrome_extensions(&mut order, secure_random)?;
    exts.contiguous_extensions = order;
    exts.order_seed = 0;
    Ok(())
}
