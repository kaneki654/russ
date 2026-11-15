use crate::hardware::{HardwareSnapshot, NetworkInterfaceSnapshot};

pub fn usable_interfaces(snapshot: &HardwareSnapshot) -> Vec<&NetworkInterfaceSnapshot> {
    snapshot
        .network
        .interfaces
        .iter()
        .filter(|interface| interface.usable_by_default)
        .collect()
}
