use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use std::{
    fs, io,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceIdentity {
    pub device_id: String,
    pub device_name: String,
    pub created_unix_seconds: u64,
    pub certificate_fingerprint: Option<String>,
    #[serde(default)]
    pub certificate_der: Vec<u8>,
    #[serde(default)]
    pub private_key_der: Vec<u8>,
}

impl DeviceIdentity {
    pub fn new(device_name: impl Into<String>) -> io::Result<Self> {
        let mut identity = Self {
            device_id: Uuid::new_v4().to_string(),
            device_name: device_name.into(),
            created_unix_seconds: now_unix_seconds(),
            certificate_fingerprint: None,
            certificate_der: Vec::new(),
            private_key_der: Vec::new(),
        };
        identity.regenerate_certificate()?;
        Ok(identity)
    }

    /// Load a persistent identity or create it once.  The file is local-only;
    /// The private key is kept in the local identity file for this desktop
    /// foundation. Production packaging should move it to the platform
    /// credential store before broad deployment.
    pub fn load_or_create(
        path: impl AsRef<Path>,
        device_name: impl Into<String>,
    ) -> io::Result<Self> {
        let path = path.as_ref();
        if path.exists() {
            let bytes = fs::read(path)?;
            let mut identity: Self = serde_json::from_slice(&bytes)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            identity.ensure_certificate()?;
            if identity.certificate_fingerprint.is_none() {
                identity.certificate_fingerprint = Some(
                    crate::security::fingerprint::sha256_fingerprint(&identity.certificate_der),
                );
            }
            let updated = serde_json::to_vec_pretty(&identity)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            fs::write(path, updated)?;
            return Ok(identity);
        }

        let identity = Self::new(device_name)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_vec_pretty(&identity)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let temporary = path.with_extension(format!("tmp.{}", std::process::id()));
        fs::write(&temporary, bytes)?;
        fs::rename(temporary, path)?;
        Ok(identity)
    }

    pub fn ensure_certificate(&mut self) -> io::Result<()> {
        if self.certificate_der.is_empty() || self.private_key_der.is_empty() {
            self.regenerate_certificate()?;
        }
        Ok(())
    }

    pub fn regenerate_certificate(&mut self) -> io::Result<()> {
        let certified = generate_simple_self_signed(vec![
            format!("russ-{}", self.device_id),
            "localhost".to_owned(),
        ])
        .map_err(io::Error::other)?;
        self.certificate_der = certified.cert.der().as_ref().to_vec();
        self.private_key_der = certified.signing_key.serialize_der();
        self.certificate_fingerprint = Some(crate::security::fingerprint::sha256_fingerprint(
            &self.certificate_der,
        ));
        Ok(())
    }

    pub fn certificate(&self) -> io::Result<CertificateDer<'static>> {
        if self.certificate_der.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "device identity has no certificate",
            ));
        }
        Ok(CertificateDer::from(self.certificate_der.clone()))
    }

    pub fn private_key(&self) -> io::Result<PrivateKeyDer<'static>> {
        if self.private_key_der.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "device identity has no private key",
            ));
        }
        Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            self.private_key_der.clone(),
        )))
    }
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}
