use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, net::IpAddr};
use sysinfo::Networks;

#[cfg(target_os = "linux")]
use std::{fs, path::Path};

/// A network interface and the addresses currently assigned to it.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NetworkInterfaceSnapshot {
    pub name: String,
    pub ipv4_addresses: Vec<String>,
    pub ipv6_addresses: Vec<String>,
    pub is_up: bool,
    pub is_loopback: bool,
    pub is_virtual: bool,
    pub usable_by_default: bool,
    pub link_speed_mbps: Option<u64>,
    pub received_bytes: u64,
    pub transmitted_bytes: u64,
}

impl NetworkInterfaceSnapshot {
    pub fn addresses(&self) -> impl Iterator<Item = &str> {
        self.ipv4_addresses
            .iter()
            .chain(self.ipv6_addresses.iter())
            .map(String::as_str)
    }

    pub fn primary_address(&self) -> Option<&str> {
        self.ipv4_addresses
            .first()
            .or_else(|| self.ipv6_addresses.first())
            .map(String::as_str)
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NetworkSnapshot {
    pub interfaces: Vec<NetworkInterfaceSnapshot>,
}

/// Discover local addresses without relying on an internet service.  The
/// interface list is merged with sysinfo counters when those counters are
/// available.  Loopback and commonly virtual/container-only interfaces stay
/// visible for diagnostics but are not selected by default.
pub fn detect() -> NetworkSnapshot {
    let mut interfaces: BTreeMap<String, NetworkInterfaceSnapshot> = BTreeMap::new();

    if let Ok(addrs) = if_addrs::get_if_addrs() {
        for interface in addrs {
            let name = interface.name;
            let ip = match &interface.addr {
                if_addrs::IfAddr::V4(address) => IpAddr::V4(address.ip),
                if_addrs::IfAddr::V6(address) => IpAddr::V6(address.ip),
            };
            let is_loopback = ip.is_loopback() || name == "lo" || name == "lo0";
            let is_virtual = likely_virtual_interface(&name);
            let is_usable_address = !is_loopback && !ip.is_unspecified() && !ip.is_multicast();

            let entry =
                interfaces
                    .entry(name.clone())
                    .or_insert_with(|| NetworkInterfaceSnapshot {
                        name: name.clone(),
                        is_loopback,
                        is_virtual,
                        ..Default::default()
                    });
            entry.is_loopback |= is_loopback;
            entry.is_virtual |= is_virtual;
            entry.is_up |= is_usable_address;

            match ip {
                IpAddr::V4(address) => entry.ipv4_addresses.push(address.to_string()),
                IpAddr::V6(address) => entry.ipv6_addresses.push(address.to_string()),
            }
        }
    }

    // sysinfo provides portable byte counters.  Link speed is intentionally
    // best-effort because the OS does not expose it uniformly.
    let networks = Networks::new_with_refreshed_list();
    for (name, data) in &networks {
        let entry = interfaces
            .entry(name.clone())
            .or_insert_with(|| NetworkInterfaceSnapshot {
                name: name.clone(),
                is_virtual: likely_virtual_interface(name),
                ..Default::default()
            });
        entry.received_bytes = data.received();
        entry.transmitted_bytes = data.transmitted();
    }

    for entry in interfaces.values_mut() {
        entry.link_speed_mbps = read_link_speed_mbps(&entry.name);
        entry.usable_by_default = entry.is_up && !entry.is_loopback && !entry.is_virtual;
    }

    NetworkSnapshot {
        interfaces: interfaces.into_values().collect(),
    }
}

fn likely_virtual_interface(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        "docker",
        "br-",
        "veth",
        "virbr",
        "vmnet",
        "virtual",
        "tun",
        "tap",
        "wg",
        "tailscale",
        "zt",
    ]
    .iter()
    .any(|prefix| lower.starts_with(prefix) || lower.contains(prefix))
}

#[cfg(target_os = "linux")]
fn read_link_speed_mbps(name: &str) -> Option<u64> {
    let path = Path::new("/sys/class/net").join(name).join("speed");
    let value = fs::read_to_string(path).ok()?.trim().parse::<i64>().ok()?;
    (value > 0).then_some(value as u64)
}

#[cfg(not(target_os = "linux"))]
fn read_link_speed_mbps(_name: &str) -> Option<u64> {
    None
}
