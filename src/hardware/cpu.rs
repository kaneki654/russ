use serde::{Deserialize, Serialize};
use sysinfo::System;

/// CPU information captured at application start or on an explicit refresh.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CpuSnapshot {
    pub logical_cores: usize,
    pub physical_cores: usize,
    pub architecture: String,
    pub model: String,
    pub average_frequency_mhz: u64,
}

pub fn detect() -> CpuSnapshot {
    let mut system = System::new_all();
    system.refresh_cpu_all();

    let logical_cores = system.cpus().len().max(1);
    let physical_cores = system.physical_core_count().unwrap_or(logical_cores).max(1);
    let average_frequency_mhz = if system.cpus().is_empty() {
        0
    } else {
        let total: u64 = system.cpus().iter().map(|cpu| cpu.frequency()).sum();
        total / system.cpus().len() as u64
    };

    CpuSnapshot {
        logical_cores,
        physical_cores,
        architecture: std::env::consts::ARCH.to_owned(),
        model: system
            .cpus()
            .first()
            .map(|cpu| cpu.brand().trim().to_owned())
            .unwrap_or_else(|| "Unknown CPU".to_owned()),
        average_frequency_mhz,
    }
}
