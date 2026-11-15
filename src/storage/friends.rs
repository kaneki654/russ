use serde::{Deserialize, Serialize};

/// A trusted peer record. The identity fingerprint, rather than an IP address,
/// is the stable security handle used by TLS trust checks.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SavedFriend {
    pub device_name: String,
    pub device_id: String,
    pub last_known_ip: Option<String>,
    pub port: u16,
    pub operating_system: String,
    pub certificate_fingerprint: String,
    pub last_connection_unix_seconds: Option<u64>,
    pub trusted: bool,
}

impl SavedFriend {
    pub fn display_address(&self) -> String {
        self.last_known_ip
            .as_deref()
            .map(|ip| {
                if ip.contains(':') {
                    format!("[{ip}]:{}", self.port)
                } else {
                    format!("{ip}:{}", self.port)
                }
            })
            .unwrap_or_else(|| format!("port {}", self.port))
    }
}
