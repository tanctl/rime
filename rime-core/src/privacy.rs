use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum SyncMode {
    #[default]
    Normal,
    FullMemo,
    Pir,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FullMemoConfig {
    pub require_confirmation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PirConfig {
    pub servers: Vec<PirServerConfig>,
    pub dummy_interval: Duration,
    pub bucket_size: usize,
    pub num_buckets: Option<usize>,
    pub start_height: Option<u32>,
}

impl Default for PirConfig {
    fn default() -> Self {
        Self {
            servers: Vec::new(),
            dummy_interval: Duration::from_secs(60),
            bucket_size: 1_000,
            num_buckets: None,
            start_height: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PirServerConfig {
    pub url: String,
    pub label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PrivacyConfig {
    pub sync_mode: SyncMode,
    pub full_memo: Option<FullMemoConfig>,
    pub pir: Option<PirConfig>,
    pub tor_only: bool,
    pub tor_state_dir: Option<String>,
    pub tor_cache_dir: Option<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PrivacyConfigError {
    #[error("Full-memo mode requires configuration")]
    MissingFullMemoConfig,
    #[error("PIR mode requires configuration")]
    MissingPirConfig,
    #[error("PIR mode requires at least two distinct servers")]
    PirServerCount,
    #[error("PIR dummy interval must be at least 10 seconds")]
    InvalidPirInterval,
}

impl PrivacyConfig {
    pub fn validate(&self) -> Result<(), PrivacyConfigError> {
        match self.sync_mode {
            SyncMode::Normal => {}
            SyncMode::FullMemo => {
                if self.full_memo.is_none() {
                    return Err(PrivacyConfigError::MissingFullMemoConfig);
                }
            }
            SyncMode::Pir => {
                let config = self
                    .pir
                    .as_ref()
                    .ok_or(PrivacyConfigError::MissingPirConfig)?;
                if config.servers.len() < 2 {
                    return Err(PrivacyConfigError::PirServerCount);
                }
                if config.dummy_interval < Duration::from_secs(10) {
                    return Err(PrivacyConfigError::InvalidPirInterval);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_normal_mode() {
        let cfg = PrivacyConfig::default();
        assert_eq!(cfg.sync_mode, SyncMode::Normal);
        assert!(cfg.pir.is_none());
        assert!(!cfg.tor_only);
    }

    #[test]
    fn pir_validation_requires_servers() {
        let mut cfg = PrivacyConfig {
            sync_mode: SyncMode::Pir,
            pir: Some(PirConfig::default()),
            ..PrivacyConfig::default()
        };
        assert_eq!(cfg.validate(), Err(PrivacyConfigError::PirServerCount));
        cfg.pir.as_mut().unwrap().servers = vec![
            PirServerConfig {
                url: "https://a".into(),
                label: None,
            },
            PirServerConfig {
                url: "https://b".into(),
                label: None,
            },
        ];
        assert!(cfg.validate().is_ok());
    }
}
