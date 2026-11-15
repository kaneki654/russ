use ring::{
    rand::SystemRandom,
    signature::{Ed25519KeyPair, KeyPair},
};
use russ::updater::{
    artifact_sha256, current_target,
    internet::{self, FeedState, InternetRelease, InternetUpdateConfig, ReleaseFeed},
};
use std::{
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn keypair() -> Ed25519KeyPair {
    let bytes = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    Ed25519KeyPair::from_pkcs8(bytes.as_ref()).unwrap()
}

fn public_key(key: &Ed25519KeyPair) -> String {
    key.public_key()
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn feed(now: u64) -> ReleaseFeed {
    ReleaseFeed {
        protocol_version: 1,
        sequence: now,
        expires_unix_seconds: now + 3600,
        releases: vec![InternetRelease {
            version: "9.0.0".into(),
            target: current_target(),
            url: "https://releases.example.com/russ.bin".into(),
            sha256: "ab".repeat(32),
            size: 42,
            built_unix_seconds: now,
            release_notes: Some("test update".into()),
        }],
    }
}

#[test]
fn only_the_pinned_signing_key_can_authorize_an_update() {
    let key = keypair();
    let bytes = internet::sign_feed(&feed(1000), &key).unwrap();
    assert!(internet::verify_feed(&bytes, &public_key(&key), &FeedState::default(), 1001).is_ok());
    assert!(
        internet::verify_feed(&bytes, &public_key(&keypair()), &FeedState::default(), 1001)
            .is_err()
    );
    let mut envelope: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    envelope["payload"] = envelope["payload"]
        .as_str()
        .unwrap()
        .replace("9.0.0", "9.0.1")
        .into();
    assert!(internet::verify_feed(
        &serde_json::to_vec(&envelope).unwrap(),
        &public_key(&key),
        &FeedState::default(),
        1001
    )
    .is_err());
}

#[test]
fn replayed_conflicting_expired_and_insecure_feeds_are_rejected() {
    let key = keypair();
    let key_hex = public_key(&key);
    let original = internet::sign_feed(&feed(1000), &key).unwrap();
    let (_, state) =
        internet::verify_feed(&original, &key_hex, &FeedState::default(), 1001).unwrap();
    assert!(internet::verify_feed(&original, &key_hex, &state, 1001).is_ok());
    assert!(internet::verify_feed(
        &internet::sign_feed(&feed(999), &key).unwrap(),
        &key_hex,
        &state,
        1001
    )
    .is_err());
    let mut conflicting = feed(1000);
    conflicting.releases[0].sha256 = "cd".repeat(32);
    assert!(internet::verify_feed(
        &internet::sign_feed(&conflicting, &key).unwrap(),
        &key_hex,
        &state,
        1001
    )
    .is_err());
    assert!(internet::verify_feed(&original, &key_hex, &state, 5000).is_err());
    let mut insecure = feed(1002);
    insecure.releases[0].url = "http://releases.example.com/russ.bin".into();
    assert!(internet::verify_feed(
        &internet::sign_feed(&insecure, &key).unwrap(),
        &key_hex,
        &state,
        1002
    )
    .is_err());
    assert!(internet::https_url("https://user:password@example.com/latest.json").is_err());
}

#[test]
fn signing_key_is_persistent_and_private() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("publisher.pk8");
    let first = internet::init_signing_key(&path).unwrap();
    assert_eq!(first.len(), 64);
    assert_eq!(first, internet::init_signing_key(&path).unwrap());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

struct HttpsFixture {
    root: tempfile::TempDir,
    current: PathBuf,
    config: InternetUpdateConfig,
    client: reqwest::Client,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for HttpsFixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn https_fixture(corrupt: bool) -> HttpsFixture {
    let root = tempfile::tempdir().unwrap();
    let current = root.path().join("current");
    std::fs::write(&current, b"old executable").unwrap();
    let artifact = root.path().join("new");
    let payload = vec![42_u8; 256 * 1024];
    std::fs::write(&artifact, &payload).unwrap();
    let key = keypair();
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![certificate.cert.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der()).into(),
    )
    .unwrap();
    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .https_only(true)
        .min_tls_version(reqwest::tls::Version::TLS_1_3)
        .add_root_certificate(reqwest::Certificate::from_der(certificate.cert.der()).unwrap())
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!(
        "https://localhost:{}/",
        listener.local_addr().unwrap().port()
    );
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut release_feed = feed(now);
    release_feed.releases[0].url = format!("{base}russ.bin");
    release_feed.releases[0].sha256 = artifact_sha256(&artifact).unwrap();
    release_feed.releases[0].size = payload.len() as u64;
    let signed = internet::sign_feed(&release_feed, &key).unwrap();
    let config = InternetUpdateConfig {
        manifest_url: format!("{base}latest.json"),
        public_key: public_key(&key),
    };
    let task = tokio::spawn(async move {
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        while let Ok((tcp, _)) = listener.accept().await {
            let mut stream = acceptor.accept(tcp).await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(stream.read_u8().await.unwrap());
                assert!(request.len() < 8192);
            }
            let request = String::from_utf8(request).unwrap();
            let mut body = if request.starts_with("GET /latest.json ") {
                signed.clone()
            } else {
                payload.clone()
            };
            if corrupt && request.starts_with("GET /russ.bin ") {
                body[0] ^= 1;
            }
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            stream.write_all(&body).await.unwrap();
            stream.shutdown().await.unwrap();
        }
    });
    HttpsFixture {
        root,
        current,
        config,
        client,
        task,
    }
}

#[tokio::test]
async fn https_feed_downloads_and_stages_a_verified_update() {
    let fixture = https_fixture(false).await;
    let directory = fixture.root.path().join("updates");
    let candidate = internet::check_once(
        &fixture.client,
        &fixture.config,
        &directory,
        &fixture.current,
        None,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(candidate.manifest.version, "9.0.0");
    assert_eq!(
        std::fs::read(&candidate.artifact_path).unwrap(),
        vec![42_u8; 256 * 1024]
    );
    assert!(directory.join("manifest.json").exists());
    assert!(internet::check_once(
        &fixture.client,
        &fixture.config,
        &directory,
        &fixture.current,
        Some(&candidate.manifest.sha256)
    )
    .await
    .unwrap()
    .is_none());
}

#[tokio::test]
async fn corrupted_https_download_cannot_be_installed() {
    let fixture = https_fixture(true).await;
    let directory = fixture.root.path().join("updates");
    let error = internet::check_once(
        &fixture.client,
        &fixture.config,
        &directory,
        &fixture.current,
        None,
    )
    .await
    .unwrap_err();
    assert!(format!("{error:#}").contains("SHA-256"));
    assert!(!directory.join("manifest.json").exists());
    assert!(!std::fs::read_dir(directory).unwrap().any(|entry| entry
        .unwrap()
        .path()
        .extension()
        .is_some_and(|extension| extension == "part")));
}
