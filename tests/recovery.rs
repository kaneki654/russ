use russ::core::recovery::{load_checkpoint, save_checkpoint, ResumeCheckpoint};

#[tokio::test]
async fn checkpoint_round_trip_is_atomic_and_validated() {
    let root = tempfile::tempdir().expect("temporary checkpoint directory");
    let checkpoint = ResumeCheckpoint::new(
        "transfer-1",
        "folder/file.bin",
        128,
        1024,
        Some("a".repeat(64)),
    )
    .expect("valid checkpoint");

    save_checkpoint(root.path(), &checkpoint)
        .await
        .expect("save checkpoint");
    let loaded = load_checkpoint(root.path(), "transfer-1")
        .await
        .expect("load checkpoint")
        .expect("checkpoint exists");
    assert_eq!(loaded.completed_bytes, 128);
    assert_eq!(loaded.relative_path.to_string_lossy(), "folder/file.bin");
}

#[test]
fn checkpoint_rejects_traversal() {
    assert!(ResumeCheckpoint::new("transfer-1", "../escape", 0, 1, None).is_err());
    assert!(ResumeCheckpoint::new("transfer/1", "file.bin", 0, 1, None).is_err());
}
