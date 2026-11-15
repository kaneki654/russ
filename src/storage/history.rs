use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TransferHistoryEntry {
    pub transfer_id: String,
    pub direction: String,
    pub peer_device_name: String,
    pub bytes: u64,
    pub sha256: Option<String>,
    pub completed_at_unix_seconds: u64,
    pub succeeded: bool,
}
