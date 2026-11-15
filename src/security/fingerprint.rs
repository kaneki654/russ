use rustls::pki_types::CertificateDer;
use sha2::{Digest, Sha256};

pub fn certificate_fingerprint(certificate: &CertificateDer<'_>) -> String {
    sha256_fingerprint(certificate.as_ref())
}

pub fn sha256_fingerprint(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// Accept either a plain 64-character hex digest or a digest formatted with
/// spaces/colons.  Returning `None` for malformed input prevents a UI field
/// from becoming an implicit trust decision.
pub fn normalize_fingerprint(value: &str) -> Option<String> {
    let mut normalized = String::with_capacity(64);
    for character in value.chars() {
        if character.is_ascii_hexdigit() {
            normalized.extend(character.to_lowercase());
        } else if character == ':' || character.is_ascii_whitespace() {
            continue;
        } else {
            return None;
        }
    }
    (normalized.len() == 64
        && normalized
            .chars()
            .all(|character| character.is_ascii_hexdigit()))
    .then_some(normalized)
}
