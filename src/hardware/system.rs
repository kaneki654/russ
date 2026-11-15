use super::{cpu, memory, network, CpuSnapshot, MemorySnapshot, NetworkSnapshot};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use sysinfo::{Disks, System};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StorageSnapshot {
    pub mount_point: String,
    pub total_bytes: u64,
    pub available_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HardwareSnapshot {
    pub captured_at_unix_seconds: u64,
    pub hostname: String,
    pub operating_system: String,
    pub os_version: String,
    pub kernel_version: String,
    pub cpu: CpuSnapshot,
    pub memory: MemorySnapshot,
    pub storage: Vec<StorageSnapshot>,
    pub network: NetworkSnapshot,
}

impl Default for HardwareSnapshot {
    fn default() -> Self {
        Self {
            captured_at_unix_seconds: 0,
            hostname: "unknown".to_owned(),
            operating_system: std::env::consts::OS.to_owned(),
            os_version: String::new(),
            kernel_version: String::new(),
            cpu: CpuSnapshot::default(),
            memory: MemorySnapshot::default(),
            storage: Vec::new(),
            network: NetworkSnapshot::default(),
        }
    }
}

impl HardwareSnapshot {
    pub fn detect() -> Self {
        let mut system = System::new_all();
        system.refresh_all();

        let disks = Disks::new_with_refreshed_list();
        let storage = disks
            .list()
            .iter()
            .map(|disk| StorageSnapshot {
                mount_point: disk.mount_point().display().to_string(),
                total_bytes: disk.total_space(),
                available_bytes: disk.available_space(),
            })
            .collect();

        let captured_at_unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or_default();

        Self {
            captured_at_unix_seconds,
            hostname: System::host_name().unwrap_or_else(|| "unknown".to_owned()),
            operating_system: System::name().unwrap_or_else(|| std::env::consts::OS.to_owned()),
            os_version: System::os_version().unwrap_or_default(),
            kernel_version: System::kernel_version().unwrap_or_default(),
            cpu: cpu::detect(),
            memory: memory::detect(),
            storage,
            network: network::detect(),
        }
    }

    pub fn total_storage_bytes(&self) -> u64 {
        self.storage.iter().map(|disk| disk.total_bytes).sum()
    }

    pub fn available_storage_bytes(&self) -> u64 {
        self.storage.iter().map(|disk| disk.available_bytes).sum()
    }

    pub fn preferred_interface(&self) -> Option<&super::NetworkInterfaceSnapshot> {
        self.network
            .interfaces
            .iter()
            .find(|interface| interface.usable_by_default)
            .or_else(|| {
                self.network
                    .interfaces
                    .iter()
                    .find(|interface| interface.is_up)
            })
    }
}
