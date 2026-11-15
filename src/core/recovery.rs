use super::manifest::validate_relative_path;
use serde::{Deserialize, Serialize};
use std::{
    io,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResumeCheckpoint {
    pub transfer_id: String,
    pub relative_path: PathBuf,
    pub completed_bytes: u64,
    pub total_bytes: u64,
    pub source_sha256: Option<String>,
    pub updated_unix_seconds: u64,
}

impl ResumeCheckpoint {
    pub fn new(
        transfer_id: impl Into<String>,
        relative_path: impl Into<PathBuf>,
        completed_bytes: u64,
        total_bytes: u64,
        source_sha256: Option<String>,
    ) -> io::Result<Self> {
        let relative_path = relative_path.into();
        let checkpoint = Self {
            transfer_id: transfer_id.into(),
            relative_path: validate_relative_path(&relative_path)?,
            completed_bytes,
            total_bytes,
            source_sha256,
            updated_unix_seconds: now_unix_seconds(),
        };
        checkpoint.validate()?;
        Ok(checkpoint)
    }

    pub fn validate(&self) -> io::Result<()> {
        if self.transfer_id.is_empty()
            || !self
                .transfer_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid transfer id",
            ));
        }
        validate_relative_path(&self.relative_path)?;
        if self.completed_bytes > self.total_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "checkpoint exceeds file size",
            ));
        }
        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        self.completed_bytes == self.total_bytes
    }
}

pub fn checkpoint_path(root: impl AsRef<Path>, transfer_id: &str) -> io::Result<PathBuf> {
    if transfer_id.is_empty()
        || !transfer_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid transfer id",
        ));
    }
    Ok(root.as_ref().join(format!("{transfer_id}.json")))
}

pub async fn save_checkpoint(
    root: impl AsRef<Path>,
    checkpoint: &ResumeCheckpoint,
) -> io::Result<()> {
    checkpoint.validate()?;
    let root = root.as_ref();
    tokio::fs::create_dir_all(root).await?;
    let path = checkpoint_path(root, &checkpoint.transfer_id)?;
    let temporary = path.with_extension(format!("json.tmp.{}", std::process::id()));
    let json = serde_json::to_vec_pretty(checkpoint)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    tokio::fs::write(&temporary, json).await?;
    tokio::fs::rename(temporary, path).await
}

pub async fn load_checkpoint(
    root: impl AsRef<Path>,
    transfer_id: &str,
) -> io::Result<Option<ResumeCheckpoint>> {
    let path = checkpoint_path(root, transfer_id)?;
    match tokio::fs::read(path).await {
        Ok(bytes) => {
            let checkpoint: ResumeCheckpoint = serde_json::from_slice(&bytes)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            checkpoint.validate()?;
            Ok(Some(checkpoint))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

pub async fn remove_checkpoint(root: impl AsRef<Path>, transfer_id: &str) -> io::Result<()> {
    let path = checkpoint_path(root, transfer_id)?;
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}
