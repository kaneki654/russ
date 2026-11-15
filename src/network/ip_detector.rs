use crate::hardware::HardwareSnapshot;
use std::net::IpAddr;

pub fn local_addresses(snapshot: &HardwareSnapshot) -> Vec<IpAddr> {
    snapshot
        .network
        .interfaces
        .iter()
        .filter(|interface| interface.usable_by_default)
        .flat_map(|interface| interface.addresses())
        .filter_map(|address| address.parse().ok())
        .collect()
}
