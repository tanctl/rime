use std::{io, path::PathBuf, sync::Arc};

use arti_client::{config::TorClientConfigBuilder, TorClient};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tor_rtcompat::PreferredRuntime;

#[derive(Clone, Debug)]
pub struct TorConfig {
    pub enabled: bool,
    pub state_dir: PathBuf,
    pub cache_dir: PathBuf,
}

impl TorConfig {
    pub fn new(enabled: bool, state_dir: PathBuf, cache_dir: PathBuf) -> Self {
        Self {
            enabled,
            state_dir,
            cache_dir,
        }
    }

    pub fn disabled() -> Self {
        Self {
            enabled: false,
            state_dir: PathBuf::new(),
            cache_dir: PathBuf::new(),
        }
    }
}

#[derive(Debug, Error)]
pub enum TorError {
    #[error("tor client: {0}")]
    Client(String),
    #[error("io: {0}")]
    Io(String),
}

pub struct TorManager {
    client: Arc<TorClient<PreferredRuntime>>,
    pub config: TorConfig,
}

impl TorManager {
    pub async fn new(config: TorConfig) -> Result<Self, TorError> {
        let tor_config = TorClientConfigBuilder::from_directories(
            config.state_dir.clone(),
            config.cache_dir.clone(),
        )
        .build()
        .map_err(|e| TorError::Client(e.to_string()))?;
        let tor_client = TorClient::builder()
            .config(tor_config)
            .create_bootstrapped()
            .await
            .map_err(|e| TorError::Client(e.to_string()))?;
        Ok(Self {
            client: Arc::new(tor_client),
            config,
        })
    }

    pub fn client(&self) -> Arc<TorClient<PreferredRuntime>> {
        self.client.clone()
    }

    pub async fn connect_stream(
        &self,
        addr: &str,
    ) -> Result<impl AsyncRead + AsyncWrite + Unpin + Send + 'static, TorError> {
        let stream = self
            .client
            .connect(addr)
            .await
            .map_err(|e| TorError::Client(e.to_string()))?;
        Ok(stream)
    }

    pub async fn check_connection(&self, target: &str) -> Result<(), TorError> {
        let _stream = self.connect_stream(target).await?;
        // successful connect implies tor is usable
        Ok(())
    }
}

impl From<TorError> for io::Error {
    fn from(err: TorError) -> Self {
        io::Error::other(err.to_string())
    }
}
