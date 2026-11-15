//! Signed HTTPS release feeds for machines outside the publisher's LAN.
use super::{
    artifact_sha256, candidate_from_manifest, save_manifest_atomic, UpdateCandidate, UpdateEvent,
    UpdateManifest,
};
use anyhow::{anyhow, bail, Context, Result};
use reqwest::{Client, Url};
use ring::{
    rand::SystemRandom,
    signature::{self, Ed25519KeyPair, KeyPair},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::AsyncWriteExt,
    sync::{mpsc::UnboundedSender, watch},
    task::JoinHandle,
};

const MAX_FEED_BYTES: usize = 128 * 1024;
const MAX_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;
const CHECK_INTERVAL: Duration = Duration::from_secs(300);

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct InternetUpdateConfig {
    pub manifest_url: String,
    pub public_key: String,
}

impl Default for InternetUpdateConfig {
    fn default() -> Self {
        let mut config: Self =
            serde_json::from_str(include_str!("../../release/update-source.json"))
                .expect("embedded update source must be valid JSON");
        if let Some(url) = option_env!("RUSS_UPDATE_URL") {
            config.manifest_url = url.to_owned();
        }
        if let Some(key) = option_env!("RUSS_UPDATE_PUBLIC_KEY") {
            config.public_key = key.to_owned();
        }
        config
    }
}

impl InternetUpdateConfig {
    pub fn validate(&self) -> Result<()> {
        https_url(&self.manifest_url)?;
        decode_hex::<32>(&self.public_key).context("invalid update public key")?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InternetRelease {
    pub version: String,
    pub target: String,
    pub url: String,
    pub sha256: String,
    pub size: u64,
    pub built_unix_seconds: u64,
    pub release_notes: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReleaseFeed {
    pub protocol_version: u16,
    pub sequence: u64,
    pub expires_unix_seconds: u64,
    pub releases: Vec<InternetRelease>,
}

#[derive(Serialize, Deserialize)]
struct SignedFeed {
    payload: String,
    signature: String,
}

#[derive(Default, Serialize, Deserialize)]
pub struct FeedState {
    pub sequence: u64,
    pub payload_sha256: String,
}

pub fn https_url(value: &str) -> Result<Url> {
    let url = Url::parse(value).context("invalid update URL")?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        bail!("updates require an HTTPS URL without credentials or fragments");
    }
    Ok(url)
}

pub fn sign_feed(feed: &ReleaseFeed, key: &Ed25519KeyPair) -> Result<Vec<u8>> {
    let payload = serde_json::to_string(feed)?;
    Ok(serde_json::to_vec_pretty(&SignedFeed {
        signature: encode_hex(key.sign(payload.as_bytes()).as_ref()),
        payload,
    })?)
}

pub fn verify_feed(
    bytes: &[u8],
    public_key: &str,
    previous: &FeedState,
    now: u64,
) -> Result<(ReleaseFeed, FeedState)> {
    if bytes.len() > MAX_FEED_BYTES {
        bail!("update feed exceeds size limit")
    }
    let signed: SignedFeed = serde_json::from_slice(bytes).context("invalid signed update feed")?;
    let key = decode_hex::<32>(public_key)?;
    let signature = decode_hex::<64>(&signed.signature)?;
    signature::UnparsedPublicKey::new(&signature::ED25519, key)
        .verify(signed.payload.as_bytes(), &signature)
        .map_err(|_| anyhow!("update signature verification failed"))?;
    let feed: ReleaseFeed = serde_json::from_str(&signed.payload)?;
    let payload_sha256 = format!("{:x}", Sha256::digest(signed.payload.as_bytes()));
    if feed.protocol_version != 1
        || feed.sequence == 0
        || feed.sequence > now.saturating_add(600)
        || feed.expires_unix_seconds <= now
        || feed.expires_unix_seconds <= feed.sequence
    {
        bail!("update feed is expired, not yet valid, or uses an unsupported protocol");
    }
    if feed.sequence < previous.sequence
        || (feed.sequence == previous.sequence
            && !previous.payload_sha256.is_empty()
            && previous.payload_sha256 != payload_sha256)
    {
        bail!("update feed rollback or conflicting sequence rejected");
    }
    let mut targets = HashSet::new();
    if feed.releases.is_empty() || feed.releases.len() > 8 {
        bail!("invalid number of update artifacts")
    }
    for release in &feed.releases {
        if !targets.insert(&release.target)
            || release.size == 0
            || release.size > MAX_ARTIFACT_BYTES
        {
            bail!("duplicate target or invalid update artifact size");
        }
        semver::Version::parse(&release.version)?;
        decode_hex::<32>(&release.sha256)?;
        https_url(&release.url)?;
    }
    let state = FeedState {
        sequence: feed.sequence,
        payload_sha256,
    };
    Ok((feed, state))
}

pub fn http_client() -> Result<Client> {
    Ok(Client::builder()
        .use_rustls_tls()
        .https_only(true)
        .min_tls_version(reqwest::tls::Version::TLS_1_3)
        .connect_timeout(Duration::from_secs(10))
        .read_timeout(Duration::from_secs(20))
        .timeout(Duration::from_secs(600))
        .redirect(reqwest::redirect::Policy::limited(5))
        .user_agent(concat!("RUSS/", env!("CARGO_PKG_VERSION")))
        .build()?)
}

pub struct InternetUpdater {
    configuration: watch::Sender<InternetUpdateConfig>,
    task: JoinHandle<()>,
}

impl InternetUpdater {
    pub fn start(
        config: InternetUpdateConfig,
        directory: PathBuf,
        events: UnboundedSender<UpdateEvent>,
    ) -> Self {
        let (configuration, mut changes) = watch::channel(config);
        let task = tokio::spawn(async move {
            let client = match http_client() {
                Ok(client) => client,
                Err(error) => {
                    let _ = events.send(UpdateEvent::InternetStatus(format!(
                        "Unavailable: {error:#}"
                    )));
                    return;
                }
            };
            let mut timer = tokio::time::interval(CHECK_INTERVAL);
            timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut offered: Option<String> = None;
            loop {
                let config = changes.borrow_and_update().clone();
                if config.manifest_url.trim().is_empty() {
                    let _ = events.send(UpdateEvent::InternetStatus(
                        "Public release feed is not configured".into(),
                    ));
                } else {
                    let _ = events.send(UpdateEvent::InternetStatus(
                        "Checking public release feed…".into(),
                    ));
                    match check_once(
                        &client,
                        &config,
                        &directory,
                        &super::running_image_path().unwrap_or_default(),
                        offered.as_deref(),
                    )
                    .await
                    {
                        Ok(Some(candidate)) => {
                            offered = Some(candidate.manifest.sha256.clone());
                            let _ = events.send(UpdateEvent::InternetStatus(format!(
                                "Verified update {} is ready",
                                candidate.manifest.version
                            )));
                            let _ = events.send(UpdateEvent::Available(candidate));
                        }
                        Ok(None) => {
                            let _ = events.send(UpdateEvent::InternetStatus(
                                "Public release feed checked".into(),
                            ));
                        }
                        Err(error) => {
                            tracing::warn!(error = %format!("{error:#}"), "internet update check failed; will retry");
                            let _ = events.send(UpdateEvent::InternetStatus(format!(
                                "Check failed; retrying automatically: {error:#}"
                            )));
                        }
                    }
                }
                timer.reset();
                tokio::select! {
                    _ = timer.tick() => {},
                    result = changes.changed() => { if result.is_err() { return; } offered = None; },
                }
            }
        });
        Self {
            configuration,
            task,
        }
    }

    pub fn configure(&self, config: InternetUpdateConfig) {
        let _ = self.configuration.send(config);
    }
}

impl Drop for InternetUpdater {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub async fn check_once(
    client: &Client,
    config: &InternetUpdateConfig,
    directory: &Path,
    current_executable: &Path,
    offered: Option<&str>,
) -> Result<Option<UpdateCandidate>> {
    config.validate()?;
    let mut response = client
        .get(https_url(&config.manifest_url)?)
        .timeout(Duration::from_secs(20))
        .send()
        .await?
        .error_for_status()?;
    if response
        .content_length()
        .is_some_and(|size| size > MAX_FEED_BYTES as u64)
    {
        bail!("update feed exceeds size limit")
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if bytes.len().saturating_add(chunk.len()) > MAX_FEED_BYTES {
            bail!("update feed exceeds size limit")
        }
        bytes.extend_from_slice(&chunk);
    }
    fs::create_dir_all(directory)?;
    let source_id = format!(
        "{:x}",
        Sha256::digest(format!("{}\n{}", config.manifest_url, config.public_key))
    );
    let state_path = directory.join(format!("feed-state-{source_id}.json"));
    let state: FeedState = match fs::read(&state_path) {
        Ok(bytes) => {
            serde_json::from_slice(&bytes).context("invalid persisted update-feed state")?
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => FeedState::default(),
        Err(error) => return Err(error.into()),
    };
    let (feed, new_state) = verify_feed(&bytes, &config.public_key, &state, now()?)?;
    crate::storage::database::save_json_atomic(&state_path, &new_state)?;
    let local_version = semver::Version::parse(env!("CARGO_PKG_VERSION"))?;
    let local_build = env!("RUSS_BUILD_UNIX_SECONDS").parse::<u64>()?;
    let Some(release) = feed.releases.iter().find(|release| {
        release.target == super::current_target()
            && semver::Version::parse(&release.version).is_ok_and(|version| {
                version > local_version
                    || (version == local_version && release.built_unix_seconds > local_build)
            })
            && offered != Some(release.sha256.as_str())
    }) else {
        return Ok(None);
    };
    let current = current_executable.to_path_buf();
    let digest = tokio::task::spawn_blocking(move || artifact_sha256(current)).await??;
    if digest == release.sha256.to_ascii_lowercase() {
        return Ok(None);
    }
    download(client, release, directory, current_executable)
        .await
        .map(Some)
}

struct PartialFile(PathBuf);
impl Drop for PartialFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

async fn download(
    client: &Client,
    release: &InternetRelease,
    directory: &Path,
    current: &Path,
) -> Result<UpdateCandidate> {
    let mut response = client
        .get(https_url(&release.url)?)
        .send()
        .await?
        .error_for_status()?;
    if response
        .content_length()
        .is_some_and(|size| size != release.size)
    {
        bail!("update download size does not match signed feed")
    }
    let temporary = PartialFile(directory.join(format!("internet-{}.part", uuid::Uuid::new_v4())));
    let mut file = tokio::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary.0)
        .await?;
    let mut received = 0_u64;
    let mut hasher = Sha256::new();
    while let Some(chunk) = response.chunk().await? {
        received = received
            .checked_add(chunk.len() as u64)
            .context("update size overflow")?;
        if received > release.size {
            bail!("update download exceeds signed size")
        }
        file.write_all(&chunk).await?;
        hasher.update(&chunk);
    }
    if received != release.size
        || format!("{:x}", hasher.finalize()) != release.sha256.to_ascii_lowercase()
    {
        bail!("update download failed SHA-256 or size verification");
    }
    file.sync_all().await?;
    drop(file);
    // Use our own canonical digest as the filename, never a network-supplied path.
    let artifact = directory.join(format!(
        "internet-{}.{}",
        release.sha256.to_ascii_lowercase(),
        if cfg!(windows) { "exe" } else { "bin" }
    ));
    tokio::fs::rename(&temporary.0, &artifact).await?;
    let mut manifest = UpdateManifest::new(
        &release.version,
        &release.target,
        artifact.canonicalize()?,
        &release.sha256,
        &release.sha256,
    );
    manifest.built_unix_seconds = release.built_unix_seconds;
    manifest.release_notes = release.release_notes.clone();
    let path = directory.join("manifest.json");
    let current = current.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let candidate = candidate_from_manifest(&path, &manifest, &current)?;
        save_manifest_atomic(path, &manifest)?;
        Ok(candidate)
    })
    .await?
}

pub fn init_signing_key(path: &Path) -> Result<String> {
    if !path.exists() {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .map_err(|_| anyhow!("could not generate update signing key"))?;
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        file.write_all(key.as_ref())?;
        file.sync_all()?;
    }
    let key = load_key(path)?;
    Ok(encode_hex(key.public_key().as_ref()))
}

fn load_key(path: &Path) -> Result<Ed25519KeyPair> {
    let bytes = if let Ok(encoded) = std::env::var("RUSS_UPDATE_SIGNING_KEY_PKCS8") {
        let value = encoded.trim();
        if value.len() % 2 != 0 || value.len() > 1024 {
            bail!("invalid signing key encoding")
        }
        value
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair)?, 16).map_err(anyhow::Error::from)
            })
            .collect::<Result<Vec<_>>>()?
    } else {
        fs::read(path)?
    };
    Ed25519KeyPair::from_pkcs8(&bytes).map_err(|_| anyhow!("invalid update signing key"))
}

pub fn cli(arguments: &[String]) -> Option<Result<String>> {
    let command = arguments.get(1)?.as_str();
    if command != "--init-update-signing" && command != "--export-internet-release" {
        return None;
    }
    Some((|| {
        let option = |flag: &str| {
            arguments
                .windows(2)
                .find(|pair| pair[0] == flag)
                .map(|pair| pair[1].as_str())
        };
        let key = option("--key").map(PathBuf::from).unwrap_or_else(|| {
            crate::storage::database::updates_directory().join("publisher-signing.pk8")
        });
        if command == "--init-update-signing" {
            let public_key = init_signing_key(&key)?;
            return Ok(format!(
                "Signing key stored privately at {}\nPublic key: {public_key}",
                key.display()
            ));
        }
        let base = option("--base-url").context("--export-internet-release requires --base-url with the public HTTPS artifact directory")?;
        let output = option("--output")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("target/internet-release"));
        let catalog = option("--catalog")
            .map(PathBuf::from)
            .unwrap_or_else(|| crate::storage::database::updates_directory().join("releases"));
        let feed = export_release(&catalog, &key, base, &output)?;
        Ok(format!("Signed feed exported to {}. Publish it and its adjacent artifacts at the configured HTTPS location.", feed.display()))
    })())
}

pub fn export_release(
    catalog: &Path,
    key_path: &Path,
    base_url: &str,
    output: &Path,
) -> Result<PathBuf> {
    let key = load_key(key_path)?;
    if encode_hex(key.public_key().as_ref()) != InternetUpdateConfig::default().public_key {
        bail!("signing key does not match the public key embedded in this release");
    }
    let base = https_url(base_url)?;
    if !base.path().ends_with('/') || base.query().is_some() {
        bail!("asset base URL must end in / and contain no query")
    }
    fs::create_dir_all(output)?;
    let mut releases = Vec::new();
    for info in super::distribution::available_releases(catalog) {
        let manifest: UpdateManifest =
            serde_json::from_slice(&fs::read(catalog.join(&info.target).join("manifest.json"))?)?;
        if artifact_sha256(&manifest.artifact)? != info.sha256 {
            bail!("published artifact failed verification")
        }
        let filename = format!(
            "russ-{}-{}.{}",
            info.target,
            info.sha256,
            if info.target.contains("windows") {
                "exe"
            } else {
                "bin"
            }
        );
        let destination = output.join(&filename);
        fs::copy(&manifest.artifact, &destination)?;
        releases.push(InternetRelease {
            version: info.version,
            target: info.target,
            url: base.join(&filename)?.to_string(),
            sha256: info.sha256,
            size: fs::metadata(destination)?.len(),
            built_unix_seconds: info.built_unix_seconds,
            release_notes: manifest.release_notes,
        });
    }
    if releases.is_empty() {
        bail!("no published artifacts; run --publish-updates first")
    }
    let sequence = now()?;
    let bytes = sign_feed(
        &ReleaseFeed {
            protocol_version: 1,
            sequence,
            expires_unix_seconds: sequence + 90 * 24 * 60 * 60,
            releases,
        },
        &key,
    )?;
    let destination = output.join("latest.json");
    let temporary = output.join(format!("{}.tmp", uuid::Uuid::new_v4()));
    fs::write(&temporary, bytes)?;
    fs::rename(temporary, &destination)?;
    Ok(destination)
}

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N]> {
    if value.len() != N * 2 {
        bail!("invalid hexadecimal key or digest length")
    }
    let mut bytes = [0_u8; N];
    for (output, pair) in bytes
        .iter_mut()
        .zip(value.as_bytes().as_chunks::<2>().0.iter())
    {
        let text = std::str::from_utf8(pair)?;
        *output = u8::from_str_radix(text, 16).context("invalid hexadecimal key or digest")?;
    }
    Ok(bytes)
}
