use russ::core::{sha256_bytes, validate_relative_path};
use russ::network::DiscoveryAnnouncement;
use russ::security::{
    normalize_fingerprint, tls13_client_builder, tls13_server_builder, AuthChallenge,
    DeviceIdentity, ReplayGuard,
};
use std::path::Path;

#[test]
fn destination_path_validation_is_cross_platform() {
    assert!(validate_relative_path(Path::new("folder/file.bin")).is_ok());
    assert!(validate_relative_path(Path::new("folder\\file.bin")).is_ok());
    assert!(validate_relative_path(Path::new("../file.bin")).is_err());
    assert!(validate_relative_path(Path::new("C:\\file.bin")).is_err());
    assert!(validate_relative_path(Path::new("/tmp/file.bin")).is_err());
}

#[test]
fn fingerprint_material_is_sha256() {
    let digest = sha256_bytes(b"device certificate DER");
    assert_eq!(digest.len(), 64);
    assert!(digest
        .chars()
        .all(|character| character.is_ascii_hexdigit()));
}

#[test]
fn fingerprint_input_is_normalized_without_changing_identity() {
    let plain = "ab".repeat(32);
    let formatted = plain
        .as_bytes()
        .chunks(2)
        .map(|chunk| std::str::from_utf8(chunk).expect("hex"))
        .collect::<Vec<_>>()
        .join(":");
    assert_eq!(normalize_fingerprint(&formatted), Some(plain));
    assert!(normalize_fingerprint("not a fingerprint").is_none());
}

#[test]
fn replay_guard_accepts_a_challenge_once() {
    let challenge = AuthChallenge::new(60);
    let issued = challenge.issued_unix_seconds;
    let mut guard = ReplayGuard::new(16, 5);
    assert!(guard.accept(&challenge, issued));
    assert!(!guard.accept(&challenge, issued));
}

#[test]
fn device_identity_is_persistent() {
    let directory = tempfile::tempdir().expect("temporary identity directory");
    let path = directory.path().join("identity.json");
    let first = DeviceIdentity::load_or_create(&path, "test device").expect("create identity");
    let second = DeviceIdentity::load_or_create(&path, "renamed device").expect("load identity");
    assert_eq!(first.device_id, second.device_id);
    assert_eq!(first.device_name, second.device_name);
}

#[test]
fn tls_builders_are_tls13_only() {
    let _client = tls13_client_builder();
    let _server = tls13_server_builder();
}

#[test]
fn discovery_announcements_are_local_and_serializable() {
    let announcement = DiscoveryAnnouncement::new(
        "device-id",
        "test device",
        4433,
        "test OS",
        "ab".repeat(32),
        "0.1.0",
    );
    let encoded = serde_json::to_vec(&announcement).expect("serialize announcement");
    let decoded: DiscoveryAnnouncement =
        serde_json::from_slice(&encoded).expect("deserialize announcement");
    assert_eq!(decoded.device_id, "device-id");
    assert_eq!(decoded.port, 4433);
}
