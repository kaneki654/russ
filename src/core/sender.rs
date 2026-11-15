use super::manifest::{validate_relative_path, TransferManifest};
use std::{io, path::PathBuf};

/// Protocol-neutral sender request consumed by the TCP/TLS sender without
/// changing GUI or hardware-planning code.
#[derive(Clone, Debug)]
pub struct SendRequest {
    pub source: PathBuf,
    pub manifest: TransferManifest,
}

impl SendRequest {
    pub fn for_file(source: impl Into<PathBuf>) -> io::Result<Self> {
        let source = source.into();
        let manifest = TransferManifest::from_file(&source)?;
        for entry in &manifest.entries {
            validate_relative_path(&entry.relative_path)?;
        }
        Ok(Self { source, manifest })
    }

    pub fn for_path(source: impl Into<PathBuf>) -> io::Result<Self> {
        let source = source.into();
        let metadata = std::fs::symlink_metadata(&source)?;
        if metadata.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "symbolic links are not supported as transfer roots",
            ));
        }
        if !metadata.is_file() && !metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "transfer source is not a file or directory",
            ));
        }
        let manifest = TransferManifest::from_path(&source)?;
        Ok(Self { source, manifest })
    }

    pub fn source_root(&self) -> PathBuf {
        self.source
            .parent()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))
    }
}
