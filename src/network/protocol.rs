use crate::core::ManifestEntry;
use serde::{Deserialize, Serialize};
use std::{io, path::Path};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_CONTROL_FRAME_BYTES: usize = 8 * 1024 * 1024;
pub const MANIFEST_BATCH_SIZE: usize = 64;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "message", rename_all = "snake_case")]
pub enum WireMessage {
    ServerHello {
        protocol_version: u16,
        device_id: String,
        device_name: String,
        operating_system: String,
        certificate_fingerprint: String,
    },
    Hello {
        protocol_version: u16,
        device_id: String,
        device_name: String,
        operating_system: String,
        certificate_fingerprint: String,
        transfer_id: String,
    },
    OfferStart {
        transfer_id: String,
        file_count: u64,
        total_bytes: u64,
    },
    ManifestBatch {
        transfer_id: String,
        entries: Vec<WireManifestEntry>,
    },
    OfferEnd {
        transfer_id: String,
    },
    Accept {
        transfer_id: String,
        resume: Vec<WireResumeEntry>,
    },
    Reject {
        transfer_id: String,
        reason: String,
    },
    FileStart {
        transfer_id: String,
        relative_path: String,
        size_bytes: u64,
        offset_bytes: u64,
    },
    FileComplete {
        transfer_id: String,
        relative_path: String,
        sha256: String,
    },
    FileAck {
        transfer_id: String,
        relative_path: String,
    },
    TransferComplete {
        transfer_id: String,
        total_bytes: u64,
    },
    TransferAck {
        transfer_id: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireManifestEntry {
    pub relative_path: String,
    pub size_bytes: u64,
    pub modified_unix_seconds: Option<u64>,
    pub is_directory: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WireResumeEntry {
    pub relative_path: String,
    pub offset_bytes: u64,
}

impl WireManifestEntry {
    pub fn from_manifest_entry(entry: &ManifestEntry) -> io::Result<Self> {
        let relative_path = path_to_wire_string(&entry.relative_path)?;
        Ok(Self {
            relative_path,
            size_bytes: entry.size_bytes,
            modified_unix_seconds: entry.modified_unix_seconds,
            is_directory: entry.is_directory,
        })
    }

    pub fn to_manifest_entry(&self) -> io::Result<ManifestEntry> {
        Ok(ManifestEntry {
            relative_path: crate::core::validate_relative_path(Path::new(&self.relative_path))?,
            size_bytes: self.size_bytes,
            modified_unix_seconds: self.modified_unix_seconds,
            is_directory: self.is_directory,
        })
    }
}

pub async fn write_message<W>(writer: &mut W, message: &WireMessage) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let payload = serde_json::to_vec(message)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if payload.len() > MAX_CONTROL_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "control frame exceeds configured limit",
        ));
    }
    let length = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "control frame length overflow"))?;
    writer.write_all(&length.to_be_bytes()).await?;
    writer.write_all(&payload).await?;
    writer.flush().await
}

pub async fn read_message<R>(reader: &mut R) -> io::Result<WireMessage>
where
    R: AsyncRead + Unpin,
{
    let mut length_bytes = [0_u8; 4];
    reader.read_exact(&mut length_bytes).await?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    if length == 0 || length > MAX_CONTROL_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid control frame length",
        ));
    }
    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload).await?;
    serde_json::from_slice(&payload)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn path_to_wire_string(path: &Path) -> io::Result<String> {
    let validated = crate::core::validate_relative_path(path)?;
    let value = validated.to_string_lossy().replace('\\', "/");
    if value.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "empty wire path",
        ));
    }
    Ok(value)
}
