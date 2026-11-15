use anyhow::{anyhow, Context, Result};
use notify::{Event, EventKind, RecursiveMode, Watcher};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{self, Read},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc as std_mpsc, Arc,
    },
    thread,
    time::Duration,
};
use tokio::sync::mpsc::UnboundedSender;

pub mod distribution;
pub mod internet;

pub const UPDATE_PROTOCOL_VERSION: u16 = 1;

/// Linux keeps the mapped image accessible even if Cargo replaces its filename.
pub fn running_image_path() -> io::Result<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        Ok(PathBuf::from("/proc/self/exe"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::env::current_exe()
    }
}

pub fn installation_path() -> io::Result<PathBuf> {
    let executable = std::env::current_exe()?;
    #[cfg(target_os = "linux")]
    if let Some(name) = executable
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_suffix(" (deleted)"))
    {
        return Ok(executable.with_file_name(name));
    }
    Ok(executable)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpdateManifest {
    pub protocol_version: u16,
    pub version: String,
    pub target: String,
    pub artifact: PathBuf,
    pub sha256: String,
    #[serde(default)]
    pub build_id: String,
    #[serde(default)]
    pub release_notes: Option<String>,
    #[serde(default)]
    pub built_unix_seconds: u64,
}

#[derive(Clone, Debug)]
pub struct UpdateCandidate {
    pub manifest: UpdateManifest,
    pub manifest_path: PathBuf,
    pub artifact_path: PathBuf,
    pub artifact_size: u64,
}

pub enum UpdateEvent {
    InternetStatus(String),
    InstalledDigest(String),
    Available(UpdateCandidate),
    Failed(String),
}

pub struct UpdateWatcher {
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct UpdateRequest {
    parent_pid: u32,
    current_executable: PathBuf,
    staged_executable: PathBuf,
    expected_sha256: String,
    restart_args: Vec<String>,
}

impl UpdateManifest {
    pub fn new(
        version: impl Into<String>,
        target: impl Into<String>,
        artifact: impl Into<PathBuf>,
        sha256: impl Into<String>,
        build_id: impl Into<String>,
    ) -> Self {
        Self {
            protocol_version: UPDATE_PROTOCOL_VERSION,
            version: version.into(),
            target: target.into(),
            artifact: artifact.into(),
            sha256: sha256.into(),
            build_id: build_id.into(),
            release_notes: None,
            built_unix_seconds: env!("RUSS_BUILD_UNIX_SECONDS").parse().unwrap_or_default(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != UPDATE_PROTOCOL_VERSION {
            return Err(anyhow!("unsupported update manifest protocol"));
        }
        if self.version.trim().is_empty() || self.target.trim().is_empty() {
            return Err(anyhow!("update manifest is missing version or target"));
        }
        if normalize_sha256(&self.sha256).is_none() {
            return Err(anyhow!(
                "update manifest contains an invalid SHA-256 digest"
            ));
        }
        if self.artifact.as_os_str().is_empty() {
            return Err(anyhow!("update manifest has no artifact path"));
        }
        Ok(())
    }
}

impl UpdateWatcher {
    pub fn start(
        manifest_path: impl Into<PathBuf>,
        current_executable: impl Into<PathBuf>,
        events: UnboundedSender<UpdateEvent>,
    ) -> Result<Self> {
        let manifest_path = manifest_path.into();
        let current_executable = current_executable.into();
        let parent = manifest_path
            .parent()
            .ok_or_else(|| anyhow!("update manifest has no parent directory"))?
            .to_path_buf();
        fs::create_dir_all(&parent)
            .with_context(|| format!("create update directory {}", parent.display()))?;
        let workspace = discover_workspace();

        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread = thread::Builder::new()
            .name("russ-update-watcher".to_owned())
            .spawn(move || {
                watch_manifest(
                    manifest_path,
                    current_executable,
                    parent,
                    workspace,
                    events,
                    thread_stop,
                );
            })
            .context("start update watcher")?;
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }
}

impl Drop for UpdateWatcher {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

pub fn current_target() -> String {
    if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
        "x86_64-pc-windows-msvc".to_owned()
    } else if cfg!(all(target_os = "windows", target_arch = "aarch64")) {
        "aarch64-pc-windows-msvc".to_owned()
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        "x86_64-unknown-linux-gnu".to_owned()
    } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        "aarch64-unknown-linux-gnu".to_owned()
    } else {
        format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS)
    }
}

pub fn artifact_sha256(path: impl AsRef<Path>) -> Result<String> {
    let mut file = File::open(path.as_ref())
        .with_context(|| format!("open artifact {}", path.as_ref().display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn save_manifest_atomic(path: impl AsRef<Path>, manifest: &UpdateManifest) -> Result<()> {
    manifest.validate()?;
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create manifest directory {}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(manifest).context("serialize update manifest")?;
    let temporary = path.with_extension(format!("tmp.{}", std::process::id()));
    fs::write(&temporary, bytes)
        .with_context(|| format!("write temporary manifest {}", temporary.display()))?;
    fs::rename(&temporary, path)
        .with_context(|| format!("replace update manifest {}", path.display()))
}

pub fn launch_update(
    candidate: &UpdateCandidate,
    current_executable: impl AsRef<Path>,
    restart_args: Vec<String>,
) -> Result<()> {
    let current_executable = current_executable.as_ref();
    let current_executable = current_executable.canonicalize().with_context(|| {
        format!(
            "resolve current executable {}",
            current_executable.display()
        )
    })?;
    let verified = verify_candidate(&candidate.manifest_path, &candidate.manifest)?;
    if verified.artifact_path != candidate.artifact_path
        || verified.manifest.sha256 != candidate.manifest.sha256
    {
        return Err(anyhow!("update candidate changed before installation"));
    }

    let update_directory = candidate
        .manifest_path
        .parent()
        .ok_or_else(|| anyhow!("update manifest has no parent directory"))?;
    fs::create_dir_all(update_directory)?;
    let process_id = std::process::id();
    let request_path = update_directory.join(format!("request-{process_id}.json"));
    let helper_path =
        update_directory.join(format!("russ-updater-{process_id}{}", executable_suffix()));
    let request = UpdateRequest {
        parent_pid: process_id,
        current_executable,
        staged_executable: candidate.artifact_path.clone(),
        expected_sha256: normalize_sha256(&candidate.manifest.sha256)
            .ok_or_else(|| anyhow!("invalid update digest"))?,
        restart_args,
    };
    let request_bytes = serde_json::to_vec_pretty(&request).context("serialize update request")?;
    fs::write(&request_path, request_bytes)
        .with_context(|| format!("write update request {}", request_path.display()))?;
    fs::copy(running_image_path()?, &helper_path)
        .with_context(|| format!("copy updater helper to {}", helper_path.display()))?;
    make_executable(&helper_path)?;

    Command::new(&helper_path)
        .arg("--russ-update-helper")
        .arg("--request")
        .arg(&request_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("start updater helper {}", helper_path.display()))?;
    Ok(())
}

pub fn run_helper_from_args(args: &[String]) -> Result<()> {
    let request_path = args
        .windows(2)
        .find(|pair| pair[0] == "--request")
        .map(|pair| PathBuf::from(&pair[1]))
        .ok_or_else(|| anyhow!("update helper requires --request"))?;
    let bytes = fs::read(&request_path)
        .with_context(|| format!("read update request {}", request_path.display()))?;
    let request: UpdateRequest = serde_json::from_slice(&bytes).context("parse update request")?;
    install_update(&request)
}

fn install_update(request: &UpdateRequest) -> Result<()> {
    let staged_digest = artifact_sha256(&request.staged_executable)?;
    if staged_digest != request.expected_sha256 {
        return Err(anyhow!(
            "staged update digest mismatch: expected {}, got {}",
            request.expected_sha256,
            staged_digest
        ));
    }

    let current = &request.current_executable;
    let parent = current
        .parent()
        .ok_or_else(|| anyhow!("current executable has no parent"))?;
    let process_id = std::process::id();
    let temporary = parent.join(format!(".russ-update-{process_id}{}", executable_suffix()));
    let backup = parent.join(format!(".russ-backup-{process_id}{}", executable_suffix()));
    fs::copy(&request.staged_executable, &temporary).with_context(|| {
        format!(
            "stage update beside current executable: {}",
            temporary.display()
        )
    })?;
    if artifact_sha256(&temporary)? != request.expected_sha256 {
        let _ = fs::remove_file(&temporary);
        return Err(anyhow!("staged temporary update failed verification"));
    }

    let mut last_error = None;
    for _ in 0..120 {
        match fs::rename(current, &backup) {
            Ok(()) => {
                last_error = None;
                break;
            }
            Err(error) => {
                last_error = Some(error);
                thread::sleep(Duration::from_millis(250));
            }
        }
    }
    if let Some(error) = last_error {
        let _ = fs::remove_file(&temporary);
        return Err(anyhow!(
            "could not replace running executable after waiting for process {}: {}",
            request.parent_pid,
            error
        ));
    }

    if let Err(error) = fs::rename(&temporary, current) {
        let _ = fs::rename(&backup, current);
        return Err(anyhow!("install new executable: {error}"));
    }

    let spawn_result = Command::new(current)
        .args(&request.restart_args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    match spawn_result {
        Ok(_) => {
            let _ = fs::remove_file(&backup);
            Ok(())
        }
        Err(error) => {
            let _ = fs::remove_file(current);
            let _ = fs::rename(&backup, current);
            Err(anyhow!("restart updated application: {error}"))
        }
    }
}

fn watch_manifest(
    manifest_path: PathBuf,
    current_executable: PathBuf,
    parent: PathBuf,
    workspace: Option<PathBuf>,
    events: UnboundedSender<UpdateEvent>,
    stop: Arc<AtomicBool>,
) {
    // Cache the running build once. Cargo may replace the file at the same
    // pathname while this process still executes the old mapped image.
    let installed_digest = match artifact_sha256(&current_executable) {
        Ok(digest) => digest,
        Err(error) => {
            let _ = events.send(UpdateEvent::Failed(format!("{error:#}")));
            return;
        }
    };
    let (notify_tx, notify_rx) = std_mpsc::channel();
    let mut watcher = match notify::recommended_watcher(move |result| {
        let _ = notify_tx.send(result);
    }) {
        Ok(watcher) => watcher,
        Err(error) => {
            let _ = events.send(UpdateEvent::Failed(format!(
                "create update watcher: {error}"
            )));
            return;
        }
    };
    if let Err(error) = watcher.watch(&parent, RecursiveMode::NonRecursive) {
        let _ = events.send(UpdateEvent::Failed(format!(
            "watch update directory {}: {error}",
            parent.display()
        )));
        return;
    }
    if let Some(workspace) = &workspace {
        if workspace.join("assets").is_dir() {
            if let Err(error) = watcher.watch(&workspace.join("assets"), RecursiveMode::Recursive) {
                let _ = events.send(UpdateEvent::Failed(format!(
                    "watch application assets: {error}"
                )));
            }
        }
        if let Err(error) = watcher.watch(&workspace.join("src"), RecursiveMode::Recursive) {
            let _ = events.send(UpdateEvent::Failed(format!(
                "watch source directory {}: {error}",
                workspace.join("src").display()
            )));
        }
        if let Err(error) = watcher.watch(workspace, RecursiveMode::NonRecursive) {
            let _ = events.send(UpdateEvent::Failed(format!(
                "watch workspace {}: {error}",
                workspace.display()
            )));
        }
    }

    if let Err(error) = scan_manifest(&manifest_path, &installed_digest, &events) {
        if error.to_string() != "update artifact is already installed" {
            let _ = events.send(UpdateEvent::Failed(error.to_string()));
        }
    }
    while !stop.load(Ordering::Acquire) {
        match notify_rx.recv_timeout(Duration::from_millis(500)) {
            Ok(Ok(event)) => {
                if relevant_event(&event, &manifest_path) {
                    if let Err(error) = scan_manifest(&manifest_path, &installed_digest, &events) {
                        if error.to_string() != "update artifact is already installed" {
                            let _ = events.send(UpdateEvent::Failed(error.to_string()));
                        }
                    }
                } else if workspace
                    .as_ref()
                    .is_some_and(|workspace| relevant_source_event(&event, workspace))
                {
                    while notify_rx.recv_timeout(Duration::from_millis(250)).is_ok() {}
                    if let Some(workspace) = &workspace {
                        if let Err(error) = build_staged_and_publish(workspace, &manifest_path) {
                            let _ = events.send(UpdateEvent::Failed(format!(
                                "automatic staged rebuild failed: {error:#}"
                            )));
                        }
                    }
                }
            }
            Ok(Err(error)) => {
                let _ = events.send(UpdateEvent::Failed(format!(
                    "watch update directory: {error}"
                )));
            }
            Err(std_mpsc::RecvTimeoutError::Timeout) => {}
            Err(std_mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
}

fn relevant_event(event: &Event, manifest_path: &Path) -> bool {
    !matches!(event.kind, EventKind::Access(_))
        && event.paths.iter().any(|path| path == manifest_path)
}

fn relevant_source_event(event: &Event, workspace: &Path) -> bool {
    !matches!(event.kind, EventKind::Access(_))
        && event.paths.iter().any(|path| {
            path.starts_with(workspace.join("src"))
                || path.starts_with(workspace.join("assets"))
                || matches!(
                    path.file_name().and_then(|name| name.to_str()),
                    Some("Cargo.toml")
                        | Some("Cargo.lock")
                        | Some("rust-toolchain.toml")
                        | Some("build.rs")
                )
        })
}

fn discover_workspace() -> Option<PathBuf> {
    let current = std::env::current_dir().ok()?;
    current
        .ancestors()
        .find(|candidate| candidate.join("Cargo.toml").is_file() && candidate.join("src").is_dir())
        .map(Path::to_path_buf)
}

fn build_staged_and_publish(workspace: &Path, manifest_path: &Path) -> Result<()> {
    let target_dir = workspace.join("target").join("russ-staged");
    let status = Command::new("cargo")
        .current_dir(workspace)
        .args(["build", "--release", "--bin", "russ", "--target-dir"])
        .arg(&target_dir)
        .status()
        .context("run automatic staged Cargo build")?;
    if !status.success() {
        return Err(anyhow!("automatic Cargo build exited with {status}"));
    }

    let artifact_name = if current_target().contains("windows") {
        "russ.exe"
    } else {
        "russ"
    };
    let artifact = target_dir.join("release").join(artifact_name);
    if !artifact.is_file() {
        return Err(anyhow!(
            "staged artifact was not produced: {}",
            artifact.display()
        ));
    }
    let version = workspace_version(workspace)?;
    let releases = manifest_path
        .parent()
        .context("update directory")?
        .join("releases");
    let manifest = distribution::publish_release(
        &releases,
        &artifact,
        &version,
        &current_target(),
        "Automatically rebuilt after a source change",
    )?;
    save_manifest_atomic(manifest_path, &manifest)?;
    // Developers with cargo-xwin installed publish both OS builds from the
    // same source revision. A failed Windows build leaves its last release intact.
    if cfg!(target_os = "linux")
        && Command::new("cargo")
            .args(["xwin", "--version"])
            .output()
            .is_ok_and(|output| output.status.success())
    {
        let status = Command::new("cargo")
            .current_dir(workspace)
            .args([
                "xwin",
                "build",
                "--release",
                "--bin",
                "russ",
                "--target",
                "x86_64-pc-windows-msvc",
                "--target-dir",
            ])
            .arg(&target_dir)
            .status()
            .context("build Windows update")?;
        if !status.success() {
            return Err(anyhow!("Windows update build failed: {status}"));
        }
        distribution::publish_release(
            &releases,
            &target_dir.join("x86_64-pc-windows-msvc/release/russ.exe"),
            &version,
            "x86_64-pc-windows-msvc",
            "Connection reliability and LAN update delivery",
        )?;
    }
    Ok(())
}

fn workspace_version(workspace: &Path) -> Result<String> {
    let output = Command::new("cargo")
        .current_dir(workspace)
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .output()?;
    if !output.status.success() {
        return Err(anyhow!("could not read workspace version"));
    }
    let metadata: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    metadata["packages"]
        .as_array()
        .and_then(|packages| packages.iter().find(|package| package["name"] == "russ"))
        .and_then(|package| package["version"].as_str())
        .map(str::to_owned)
        .context("workspace has no RUSS package")
}

/// Publish already-built native and Windows artifacts. This runs as a mode of
/// the single russ executable; no second updater executable is distributed.
pub fn publish_workspace_updates(workspace: &Path) -> Result<()> {
    let version = workspace_version(workspace)?;
    let directory = crate::storage::database::updates_directory();
    let releases = directory.join("releases");
    let native =
        workspace
            .join("target/release")
            .join(if cfg!(windows) { "russ.exe" } else { "russ" });
    let manifest = distribution::publish_release(&releases, &native, &version, &current_target(),
        "Connection reliability: bounded setup, TLS retry, non-blocking receiver and queued approvals; LAN update delivery")?;
    save_manifest_atomic(directory.join("manifest.json"), &manifest)?;
    if cfg!(target_os = "linux") {
        let windows = workspace.join("target/x86_64-pc-windows-msvc/release/russ.exe");
        if windows.is_file() {
            distribution::publish_release(
                &releases,
                &windows,
                &version,
                "x86_64-pc-windows-msvc",
                "Connection reliability and LAN update delivery",
            )?;
        }
    }
    Ok(())
}

fn scan_manifest(
    manifest_path: &Path,
    installed_digest: &str,
    events: &UnboundedSender<UpdateEvent>,
) -> Result<()> {
    let bytes = match fs::read(manifest_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let manifest: UpdateManifest =
        serde_json::from_slice(&bytes).context("parse update manifest")?;
    let candidate = verify_candidate(manifest_path, &manifest)?;
    if candidate
        .manifest
        .sha256
        .eq_ignore_ascii_case(installed_digest)
    {
        return Err(anyhow!("update artifact is already installed"));
    }
    let _ = events.send(UpdateEvent::Available(candidate));
    Ok(())
}

pub(crate) fn candidate_from_manifest(
    manifest_path: &Path,
    manifest: &UpdateManifest,
    current_executable: &Path,
) -> Result<UpdateCandidate> {
    let candidate = verify_candidate(manifest_path, manifest)?;
    if artifact_sha256(current_executable)? == candidate.manifest.sha256.to_ascii_lowercase() {
        return Err(anyhow!("update artifact is already installed"));
    }
    Ok(candidate)
}

fn verify_candidate(manifest_path: &Path, manifest: &UpdateManifest) -> Result<UpdateCandidate> {
    manifest.validate()?;
    if manifest.target != current_target() {
        return Err(anyhow!(
            "update target {} does not match this application target {}",
            manifest.target,
            current_target()
        ));
    }
    let artifact_path = if manifest.artifact.is_absolute() {
        manifest.artifact.clone()
    } else {
        manifest_path
            .parent()
            .ok_or_else(|| anyhow!("update manifest has no parent"))?
            .join(&manifest.artifact)
    };
    let artifact_path = artifact_path
        .canonicalize()
        .with_context(|| format!("resolve update artifact {}", artifact_path.display()))?;
    let metadata = fs::metadata(&artifact_path)?;
    if !metadata.is_file() {
        return Err(anyhow!("update artifact is not a regular file"));
    }
    let expected = normalize_sha256(&manifest.sha256)
        .ok_or_else(|| anyhow!("invalid update SHA-256 digest"))?;
    let actual = artifact_sha256(&artifact_path)?;
    if actual != expected {
        return Err(anyhow!(
            "update artifact digest mismatch: expected {expected}, got {actual}"
        ));
    }
    Ok(UpdateCandidate {
        manifest: manifest.clone(),
        manifest_path: manifest_path.to_path_buf(),
        artifact_path,
        artifact_size: metadata.len(),
    })
}

fn normalize_sha256(value: &str) -> Option<String> {
    let normalized = value
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace() && *byte != b':')
        .map(|byte| byte.to_ascii_lowercase() as char)
        .collect::<String>();
    (normalized.len() == 64 && normalized.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then_some(normalized)
}

fn executable_suffix() -> &'static str {
    if cfg!(target_os = "windows") {
        ".exe"
    } else {
        ""
    }
}

fn make_executable(_path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(_path)?.permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(_path, permissions)?;
    }
    Ok(())
}
