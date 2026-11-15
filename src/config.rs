use crate::{
    core::OptimizerConfig,
    storage::{database, SavedFriend, TransferHistoryEntry},
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppConfig {
    pub device_name: String,
    pub selected_interface: Option<String>,
    pub output_directory: Option<PathBuf>,
    pub optimizer: OptimizerConfig,
    pub friends: Vec<SavedFriend>,
    pub history: Vec<TransferHistoryEntry>,
    #[serde(default)]
    pub internet_updates: crate::updater::internet::InternetUpdateConfig,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            device_name: default_device_name(),
            selected_interface: None,
            output_directory: dirs::download_dir(),
            optimizer: OptimizerConfig::default(),
            friends: Vec::new(),
            history: Vec::new(),
            internet_updates: Default::default(),
        }
    }
}

impl AppConfig {
    pub fn load() -> anyhow::Result<Self> {
        let path = database::config_path();
        if !path.exists() {
            return Ok(Self::default());
        }
        let mut config: Self = database::load_json(&path)?;
        if config.internet_updates.manifest_url.is_empty()
            && config.internet_updates.public_key.is_empty()
        {
            config.internet_updates = Default::default();
        }
        config.optimizer = config.optimizer.normalized();
        Ok(config)
    }

    pub fn save(&self) -> anyhow::Result<()> {
        database::save_json_atomic(&database::config_path(), self)
    }
}

fn default_device_name() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| "RUSS device".to_owned())
}
