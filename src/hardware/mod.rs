//! Hardware and local-resource discovery used by the transfer planner.
//!
//! Detection is deliberately kept separate from the transfer engine.  The
//! engine consumes a snapshot, so later protocol work can refresh hardware
//! information without changing the sender or receiver APIs.

pub mod cpu;
pub mod memory;
pub mod network;
pub mod system;

pub use cpu::CpuSnapshot;
pub use memory::MemorySnapshot;
pub use network::{NetworkInterfaceSnapshot, NetworkSnapshot};
pub use system::{HardwareSnapshot, StorageSnapshot};

/// Format a byte count for compact display in the desktop UI.
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];

    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }

    if unit == 0 {
        format!("{bytes} {}", UNITS[unit])
    } else if value >= 100.0 {
        format!("{value:.0} {}", UNITS[unit])
    } else if value >= 10.0 {
        format!("{value:.1} {}", UNITS[unit])
    } else {
        format!("{value:.2} {}", UNITS[unit])
    }
}
