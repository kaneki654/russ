use serde::{Deserialize, Serialize};
use std::{
    io,
    path::{Component, Path, PathBuf},
    time::UNIX_EPOCH,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub relative_path: PathBuf,
    pub size_bytes: u64,
    pub modified_unix_seconds: Option<u64>,
    #[serde(default)]
    pub is_directory: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TransferManifest {
    pub entries: Vec<ManifestEntry>,
    pub total_bytes: u64,
}

impl TransferManifest {
    pub fn new(mut entries: Vec<ManifestEntry>) -> io::Result<Self> {
        for entry in &mut entries {
            entry.relative_path = validate_relative_path(&entry.relative_path)?;
        }
        entries.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
        let total_bytes = entries
            .iter()
            .filter(|entry| !entry.is_directory)
            .map(|entry| entry.size_bytes)
            .sum::<u64>();
        Ok(Self {
            entries,
            total_bytes,
        })
    }

    pub fn from_file(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        let metadata = std::fs::metadata(path)?;
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "manifest source is not a file",
            ));
        }
        let relative_path = path
            .file_name()
            .map(PathBuf::from)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "file has no name"))?;
        Self::new(vec![ManifestEntry {
            relative_path,
            size_bytes: metadata.len(),
            modified_unix_seconds: modified_unix_seconds(&metadata),
            is_directory: false,
        }])
    }

    /// Build a deterministic manifest for a file or directory.  Directory
    /// entries are retained so empty folders survive a transfer. Symlinks are
    /// rejected rather than followed, preventing a selected folder from
    /// unexpectedly sending data outside its tree.
    pub fn from_path(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref();
        let metadata = std::fs::symlink_metadata(path)?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        let mut entries = Vec::new();
        collect_manifest_entries(path, base, &mut entries, metadata.is_dir())?;
        Self::new(entries)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileInspection {
    pub path: PathBuf,
    pub size_bytes: u64,
    pub modified_unix_seconds: Option<u64>,
    pub sha256: Option<String>,
}

pub fn inspect_file(path: impl AsRef<Path>) -> io::Result<FileInspection> {
    let path = path.as_ref();
    let metadata = std::fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "selected path is not a regular file",
        ));
    }
    Ok(FileInspection {
        path: path.to_path_buf(),
        size_bytes: metadata.len(),
        modified_unix_seconds: modified_unix_seconds(&metadata),
        sha256: None,
    })
}

fn collect_manifest_entries(
    path: &Path,
    base: &Path,
    entries: &mut Vec<ManifestEntry>,
    is_directory: bool,
) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("symlinks are not supported: {}", path.display()),
        ));
    }

    let relative_path = path.strip_prefix(base).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("could not create relative path: {error}"),
        )
    })?;
    validate_relative_path(relative_path)?;
    entries.push(ManifestEntry {
        relative_path: relative_path.to_path_buf(),
        size_bytes: if is_directory { 0 } else { metadata.len() },
        modified_unix_seconds: modified_unix_seconds(&metadata),
        is_directory,
    });

    if is_directory {
        let mut children = std::fs::read_dir(path)?.collect::<Result<Vec<_>, std::io::Error>>()?;
        children.sort_by_key(|entry| entry.file_name());
        for child in children {
            let child_path = child.path();
            let child_metadata = std::fs::symlink_metadata(&child_path)?;
            collect_manifest_entries(&child_path, base, entries, child_metadata.is_dir())?;
        }
    }
    Ok(())
}

/// Normalize a receiver-relative path and reject absolute paths, parent
/// traversal, drive prefixes, and NUL bytes.  Both slash styles are checked
/// because manifests can be exchanged between Windows and Linux.
pub fn validate_relative_path(path: &Path) -> io::Result<PathBuf> {
    let raw = path.to_string_lossy();
    if raw.is_empty() || raw.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "empty or NUL-containing path",
        ));
    }
    if raw.starts_with('/') || raw.starts_with('\\') || raw.as_bytes().get(1) == Some(&b':') {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "absolute destination path is not allowed",
        ));
    }

    let mut normalized = PathBuf::new();
    for segment in raw.split(['/', '\\']) {
        if segment.is_empty() || segment == "." {
            continue;
        }
        if segment == ".." || segment.contains(':') {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "path traversal component is not allowed",
            ));
        }
        normalized.push(segment);
    }

    if normalized.as_os_str().is_empty()
        || normalized.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid relative destination path",
        ));
    }
    Ok(normalized)
}

fn modified_unix_seconds(metadata: &std::fs::Metadata) -> Option<u64> {
    metadata
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}
