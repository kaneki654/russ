use russ::updater::{
    artifact_sha256, current_target, save_manifest_atomic, UpdateEvent, UpdateManifest,
    UpdateWatcher,
};
use std::{thread, time::Duration};

#[test]
fn update_watcher_reports_a_verified_staged_artifact() {
    let directory = tempfile::tempdir().expect("update directory");
    let artifact = directory.path().join("staged-russ");
    let manifest_path = directory.path().join("manifest.json");
    std::fs::write(&artifact, b"new staged binary contents").expect("write artifact");
    let digest = artifact_sha256(&artifact).expect("hash artifact");
    let manifest = UpdateManifest::new(
        "0.1.1-dev",
        current_target(),
        artifact.clone(),
        digest,
        "test-build",
    );
    save_manifest_atomic(&manifest_path, &manifest).expect("write manifest");

    let current = directory.path().join("current-russ");
    std::fs::write(&current, b"previously installed version").unwrap();
    let (events, mut event_rx) = tokio::sync::mpsc::unbounded_channel();
    let _watcher = UpdateWatcher::start(&manifest_path, current, events).expect("start watcher");
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let event = loop {
        if let Ok(event) = event_rx.try_recv() {
            break event;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "update watcher did not report a candidate"
        );
        thread::sleep(Duration::from_millis(20));
    };

    match event {
        UpdateEvent::Available(candidate) => {
            assert_eq!(candidate.manifest.build_id, "test-build");
            assert_eq!(
                candidate.artifact_path,
                artifact.canonicalize().expect("artifact path")
            );
        }
        UpdateEvent::Failed(error) => panic!("unexpected updater error: {error}"),
        UpdateEvent::InstalledDigest(_) => panic!("unexpected installed digest event"),
        UpdateEvent::InternetStatus(_) => panic!("unexpected internet status event"),
    }
}

#[test]
fn update_manifest_rejects_invalid_digest() {
    let manifest = UpdateManifest::new(
        "0.1.1",
        current_target(),
        "staged-russ",
        "not-a-digest",
        "build",
    );
    assert!(manifest.validate().is_err());
}

#[test]
fn watcher_recognizes_an_update_after_cargo_replaces_the_executable_path() {
    let directory = tempfile::tempdir().unwrap();
    let current = directory.path().join("current");
    let artifact = directory.path().join("candidate");
    let manifest_path = directory.path().join("manifest.json");
    std::fs::write(&current, b"running old build").unwrap();
    std::fs::write(&artifact, b"first new build").unwrap();
    let manifest = UpdateManifest::new(
        "0.2.1",
        current_target(),
        &artifact,
        artifact_sha256(&artifact).unwrap(),
        "first",
    );
    save_manifest_atomic(&manifest_path, &manifest).unwrap();
    let (events, mut receiver) = tokio::sync::mpsc::unbounded_channel();
    let _watcher = UpdateWatcher::start(&manifest_path, &current, events).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while receiver.try_recv().is_err() {
        assert!(std::time::Instant::now() < deadline);
        thread::sleep(Duration::from_millis(10));
    }
    std::fs::write(&current, b"second new build").unwrap();
    std::fs::write(&artifact, b"second new build").unwrap();
    let digest = artifact_sha256(&artifact).unwrap();
    let manifest = UpdateManifest::new("0.2.1", current_target(), &artifact, &digest, "second");
    save_manifest_atomic(&manifest_path, &manifest).unwrap();
    loop {
        if let Ok(UpdateEvent::Available(candidate)) = receiver.try_recv() {
            if candidate.manifest.sha256 == digest {
                break;
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "running version must be cached, not re-read from the replaced path"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

#[tokio::test]
async fn lan_update_download_pins_publisher_and_verifies_artifact() {
    use russ::{security::DeviceIdentity, updater::distribution::*};
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("new-build");
    let current = root.path().join("current");
    tokio::fs::write(&source, b"new executable bytes")
        .await
        .unwrap();
    tokio::fs::write(&current, b"old executable bytes")
        .await
        .unwrap();
    let releases = root.path().join("releases");
    let manifest = publish_release(
        &releases,
        &source,
        "0.2.2",
        &current_target(),
        "test release",
    )
    .unwrap();
    let publisher = DeviceIdentity::new("publisher").unwrap();
    let client = DeviceIdentity::new("client").unwrap();
    let server =
        start_server("127.0.0.1:0".parse().unwrap(), &publisher, releases.clone()).unwrap();
    let release = available_releases(&releases).pop().unwrap();
    let downloaded = root.path().join("downloaded");
    let candidate = download_release(
        server.address,
        publisher.certificate_fingerprint.as_deref().unwrap(),
        &release,
        &client,
        &downloaded,
        &current,
    )
    .await
    .unwrap();
    assert_eq!(candidate.manifest.sha256, manifest.sha256);
    assert_eq!(
        tokio::fs::read(candidate.artifact_path).await.unwrap(),
        b"new executable bytes"
    );
    assert!(downloaded.join("manifest.json").is_file());

    let rejected = root.path().join("rejected");
    assert!(download_release(
        server.address,
        &"00".repeat(32),
        &release,
        &client,
        &rejected,
        &current
    )
    .await
    .is_err());
    assert!(!rejected.join("manifest.json").exists());
}

#[tokio::test]
async fn corrupt_network_update_never_publishes_a_manifest() {
    use russ::{security::DeviceIdentity, updater::distribution::*};
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("new-build");
    let current = root.path().join("current");
    tokio::fs::write(&source, b"verified build").await.unwrap();
    tokio::fs::write(&current, b"old build").await.unwrap();
    let releases = root.path().join("releases");
    let manifest = publish_release(&releases, &source, "0.2.2", &current_target(), "test").unwrap();
    tokio::fs::write(&manifest.artifact, b"corrupted build")
        .await
        .unwrap();
    let publisher = DeviceIdentity::new("publisher").unwrap();
    let client = DeviceIdentity::new("client").unwrap();
    let server =
        start_server("127.0.0.1:0".parse().unwrap(), &publisher, releases.clone()).unwrap();
    let release = available_releases(&releases).pop().unwrap();
    let destination = root.path().join("download");
    let error = download_release(
        server.address,
        publisher.certificate_fingerprint.as_deref().unwrap(),
        &release,
        &client,
        &destination,
        &current,
    )
    .await
    .unwrap_err();
    assert!(format!("{error:#}").contains("SHA-256 mismatch"));
    assert!(!destination.join("manifest.json").exists());
    assert_eq!(std::fs::read_dir(destination).unwrap().count(), 0);
    assert!(publish_release(&releases, &source, "0.2.2", "../../outside", "test").is_err());
}
