//! Authenticated, bounded LAN release delivery. UDP notices are advisory;
//! artifact downloads pin the explicitly approved publisher certificate.
use super::{
    artifact_sha256, candidate_from_manifest, save_manifest_atomic, UpdateCandidate, UpdateManifest,
};
use crate::{
    network::bind_tcp_listener,
    security::{self, DeviceIdentity},
};
use anyhow::{anyhow, Context, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    fs,
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::Semaphore,
    task::JoinHandle,
    time::timeout,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub const UPDATE_PORT: u16 = 45_890;
const MAX_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;
const STEP_TIMEOUT: Duration = Duration::from_secs(5);
const TARGETS: &[&str] = &[
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-pc-windows-msvc",
    "aarch64-pc-windows-msvc",
];

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReleaseInfo {
    pub target: String,
    pub version: String,
    pub sha256: String,
    #[serde(default)]
    pub built_unix_seconds: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpdateAnnouncement {
    pub protocol: String,
    pub device_id: String,
    pub device_name: String,
    pub certificate_fingerprint: String,
    pub port: u16,
    pub releases: Vec<ReleaseInfo>,
}

impl UpdateAnnouncement {
    pub fn valid(&self) -> bool {
        self.protocol == "russ-update/1"
            && self.port != 0
            && !self.device_id.is_empty()
            && self.device_name.len() <= 256
            && security::normalize_fingerprint(&self.certificate_fingerprint).is_some()
            && self.releases.len() <= TARGETS.len()
            && self.releases.iter().all(|release| {
                TARGETS.contains(&release.target.as_str())
                    && semver::Version::parse(&release.version).is_ok()
                    && security::normalize_fingerprint(&release.sha256).is_some()
            })
    }
}

#[derive(Serialize, Deserialize)]
struct Request {
    target: String,
    sha256: String,
}

#[derive(Serialize, Deserialize)]
struct Response {
    manifest: UpdateManifest,
    size: u64,
}

pub struct ReleaseServer {
    pub address: SocketAddr,
    task: JoinHandle<()>,
}

impl Drop for ReleaseServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub fn start_server(
    address: SocketAddr,
    identity: &DeviceIdentity,
    directory: PathBuf,
) -> Result<ReleaseServer> {
    let listener = bind_tcp_listener(address)?;
    let address = listener.local_addr()?;
    let acceptor = TlsAcceptor::from(Arc::new(security::tls::server_config(identity)?));
    let task = tokio::spawn(async move {
        let slots = Arc::new(Semaphore::new(4));
        while let Ok((stream, peer)) = listener.accept().await {
            let Ok(permit) = slots.clone().try_acquire_owned() else {
                continue;
            };
            let acceptor = acceptor.clone();
            let directory = directory.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let result = timeout(Duration::from_secs(180), async {
                    let mut stream = timeout(STEP_TIMEOUT, acceptor.accept(stream)).await??;
                    let request: Request = read_packet(&mut stream).await?;
                    if !TARGETS.contains(&request.target.as_str()) {
                        return Err(anyhow!("unsupported release target"));
                    }
                    let manifest_path = directory.join(&request.target).join("manifest.json");
                    let manifest: UpdateManifest =
                        serde_json::from_slice(&fs::read(manifest_path).await?)?;
                    manifest.validate()?;
                    if manifest.target != request.target || manifest.sha256 != request.sha256 {
                        return Err(anyhow!("release changed; refresh announcement"));
                    }
                    // Publishers create these manifests locally; clients never supply a path.
                    let mut artifact = fs::File::open(&manifest.artifact).await?;
                    let size = artifact.metadata().await?.len();
                    if size == 0 || size > MAX_ARTIFACT_BYTES {
                        return Err(anyhow!("invalid artifact size"));
                    }
                    write_packet(&mut stream, &Response { manifest, size }).await?;
                    let copied = tokio::io::copy(&mut artifact, &mut stream).await?;
                    if copied != size {
                        return Err(anyhow!("release changed during download"));
                    }
                    stream.flush().await?;
                    Ok::<_, anyhow::Error>(())
                })
                .await;
                if !matches!(result, Ok(Ok(()))) {
                    tracing::debug!(%peer, "release download ended before completion");
                }
            });
        }
    });
    Ok(ReleaseServer { address, task })
}

/// Copy an immutable artifact into the publisher's release catalog, then
/// atomically make it visible. This also supports publishing another OS target.
pub fn publish_release(
    directory: &Path,
    artifact: &Path,
    version: &str,
    target: &str,
    notes: &str,
) -> Result<UpdateManifest> {
    if !TARGETS.contains(&target) {
        return Err(anyhow!("unsupported release target"));
    }
    semver::Version::parse(version)?;
    let digest = artifact_sha256(artifact)?;
    let target_dir = directory.join(target);
    std::fs::create_dir_all(&target_dir)?;
    let destination = target_dir.join(format!(
        "{digest}.{}",
        if target.contains("windows") {
            "exe"
        } else {
            "bin"
        }
    ));
    if !destination.exists() {
        let temporary = target_dir.join(format!("{}.part", uuid::Uuid::new_v4()));
        std::fs::copy(artifact, &temporary)?;
        if artifact_sha256(&temporary)? != digest {
            return Err(anyhow!("artifact changed during publication"));
        }
        std::fs::rename(temporary, &destination)?;
    }
    let mut manifest = UpdateManifest::new(
        version,
        target,
        destination.canonicalize()?,
        &digest,
        &digest,
    );
    manifest.built_unix_seconds = std::fs::metadata(artifact)?
        .modified()?
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    manifest.release_notes = Some(notes.to_owned());
    save_manifest_atomic(target_dir.join("manifest.json"), &manifest)?;
    Ok(manifest)
}

pub fn available_releases(directory: &Path) -> Vec<ReleaseInfo> {
    TARGETS
        .iter()
        .filter_map(|target| {
            let manifest: UpdateManifest = serde_json::from_slice(
                &std::fs::read(directory.join(target).join("manifest.json")).ok()?,
            )
            .ok()?;
            manifest.validate().ok()?;
            if manifest.target != *target {
                return None;
            }
            Some(ReleaseInfo {
                target: manifest.target,
                version: manifest.version,
                sha256: manifest.sha256,
                built_unix_seconds: manifest.built_unix_seconds,
            })
        })
        .collect()
}

/// The caller approves the publisher fingerprint before invoking this function.
/// No artifact paths or digest values from the network are used as local paths.
pub async fn download_release(
    address: SocketAddr,
    publisher_fingerprint: &str,
    release: &ReleaseInfo,
    identity: &DeviceIdentity,
    directory: &Path,
    current_executable: &Path,
) -> Result<UpdateCandidate> {
    let current_executable = current_executable.to_path_buf();
    let result = timeout(Duration::from_secs(180), async {
        if release.target != super::current_target() {
            return Err(anyhow!("update is for another platform"));
        }
        let config = security::tls::client_config(identity, Some(publisher_fingerprint))?;
        let connector = TlsConnector::from(Arc::new(config));
        let tcp = timeout(STEP_TIMEOUT, TcpStream::connect(address)).await??;
        let server_name = rustls::pki_types::ServerName::try_from("russ".to_owned())?;
        let mut stream = timeout(STEP_TIMEOUT, connector.connect(server_name, tcp)).await??;
        write_packet(
            &mut stream,
            &Request {
                target: release.target.clone(),
                sha256: release.sha256.clone(),
            },
        )
        .await?;
        let response: Response = read_packet(&mut stream).await?;
        response.manifest.validate()?;
        if response.manifest.target != release.target
            || response.manifest.version != release.version
            || response.manifest.sha256 != release.sha256
            || response.manifest.built_unix_seconds != release.built_unix_seconds
            || response.size == 0
            || response.size > MAX_ARTIFACT_BYTES
        {
            return Err(anyhow!(
                "publisher response does not match approved release"
            ));
        }
        fs::create_dir_all(directory).await?;
        let temporary = directory.join(format!("{}.part", uuid::Uuid::new_v4()));
        let mut output = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .await?;
        let transfer = async {
            let mut remaining = response.size;
            let mut buffer = vec![0_u8; 64 * 1024];
            let mut hasher = Sha256::new();
            while remaining > 0 {
                let limit = remaining.min(buffer.len() as u64) as usize;
                let count = timeout(STEP_TIMEOUT, stream.read(&mut buffer[..limit])).await??;
                if count == 0 {
                    return Err(anyhow!("incomplete update download"));
                }
                output.write_all(&buffer[..count]).await?;
                hasher.update(&buffer[..count]);
                remaining -= count as u64;
            }
            if format!("{:x}", hasher.finalize()) != release.sha256.to_ascii_lowercase() {
                return Err(anyhow!("update SHA-256 mismatch"));
            }
            output.sync_all().await?;
            Ok::<_, anyhow::Error>(())
        }
        .await;
        drop(output);
        if let Err(error) = transfer {
            let _ = fs::remove_file(&temporary).await;
            return Err(error);
        }
        let artifact = directory.join(format!(
            "{}.{}",
            release.sha256,
            if cfg!(windows) { "exe" } else { "bin" }
        ));
        fs::rename(&temporary, &artifact).await?;
        let mut manifest = response.manifest;
        manifest.artifact = artifact.canonicalize()?;
        let manifest_path = directory.join("manifest.json");
        let current = current_executable.clone();
        tokio::task::spawn_blocking(move || {
            let candidate = candidate_from_manifest(&manifest_path, &manifest, &current)?;
            save_manifest_atomic(&manifest_path, &manifest)?;
            Ok::<_, anyhow::Error>(candidate)
        })
        .await?
    })
    .await
    .context("update download timed out")?;
    result
}

async fn write_packet<W: AsyncWrite + Unpin, T: Serialize>(
    stream: &mut W,
    value: &T,
) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > 64 * 1024 {
        return Err(anyhow!("update metadata is too large"));
    }
    timeout(STEP_TIMEOUT, async {
        stream.write_u32(bytes.len() as u32).await?;
        stream.write_all(&bytes).await?;
        stream.flush().await
    })
    .await??;
    Ok(())
}

async fn read_packet<R: AsyncRead + Unpin, T: DeserializeOwned>(stream: &mut R) -> Result<T> {
    timeout(STEP_TIMEOUT, async {
        let length = stream.read_u32().await? as usize;
        if length == 0 || length > 64 * 1024 {
            return Err(anyhow!("invalid update metadata length"));
        }
        let mut bytes = vec![0_u8; length];
        stream.read_exact(&mut bytes).await?;
        Ok(serde_json::from_slice(&bytes)?)
    })
    .await
    .context("update metadata timed out")?
}
