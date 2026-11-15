use russ::core::{sha256_bytes, sha256_file, verify_file_sha256};
use std::io::Write;

#[test]
fn sha256_bytes_is_stable() {
    assert_eq!(
        sha256_bytes(b"russ"),
        "4950abf9d70f734e001983519a90a43fb1be4ba3a54e03717e540b0fd5b3f507"
    );
}

#[tokio::test]
async fn file_hash_is_streamed_and_verifiable() {
    let mut file = tempfile::NamedTempFile::new().expect("temporary file");
    file.write_all(b"bounded hashing").expect("write test data");
    file.flush().expect("flush test data");

    let digest = sha256_file(file.path()).await.expect("hash file");
    assert!(verify_file_sha256(file.path(), &digest)
        .await
        .expect("verify file"));
    assert!(!verify_file_sha256(file.path(), &"00".repeat(32))
        .await
        .expect("verify mismatch"));
}
