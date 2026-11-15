use serde::{Deserialize, Serialize};
use sysinfo::System;

/// RAM information in bytes.  The transfer engine uses available RAM only as
/// an input to a conservative budget; it never treats all RAM as a buffer.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MemorySnapshot {
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub used_bytes: u64,
}

pub fn detect() -> MemorySnapshot {
    let mut system = System::new_all();
    system.refresh_memory();

    let total_bytes = system.total_memory();
    let available_bytes = system.available_memory();
    MemorySnapshot {
        total_bytes,
        available_bytes,
        used_bytes: total_bytes.saturating_sub(available_bytes),
    }
}
