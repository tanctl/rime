use std::{io, path::PathBuf, sync::Arc};

use arti_client::{config::TorClientConfigBuilder, IsolationToken, StreamPrefs, TorClient};
use rand::Rng;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tor_rtcompat::PreferredRuntime;

#[derive(Clone, Debug)]
pub struct TorConfig {
    pub enabled: bool,
    pub state_dir: PathBuf,
    pub cache_dir: PathBuf,
    pub isolate: bool,
    pub isolation_group: Option<String>,
}

impl TorConfig {
    pub fn new(enabled: bool, state_dir: PathBuf, cache_dir: PathBuf) -> Self {
        Self {
            enabled,
            state_dir,
            cache_dir,
            isolate: false,
            isolation_group: None,
        }
    }

    pub fn disabled() -> Self {
        Self {
            enabled: false,
            state_dir: PathBuf::new(),
            cache_dir: PathBuf::new(),
            isolate: false,
            isolation_group: None,
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
    isolate: bool,
    isolation_token: Option<IsolationToken>,
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
        let isolation_token = if config.isolate {
            Some(IsolationToken::new())
        } else {
            None
        };
        Ok(Self {
            client: Arc::new(tor_client),
            isolate: config.isolate,
            isolation_token,
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
        if self.isolate {
            let delay = rand::thread_rng().gen_range(10..50);
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
        }
        let mut prefs = StreamPrefs::new();
        if let Some(tok) = self.isolation_token.as_ref() {
            prefs.set_isolation(*tok);
        }
        let stream = self
            .client
            .connect_with_prefs(addr, &prefs)
            .await
            .map_err(|e| TorError::Client(e.to_string()))?;
        Ok(stream)
    }

    pub async fn wait_for_bootstrap(&self) -> Result<(), TorError> {
        self.client
            .bootstrap()
            .await
            .map_err(|e| TorError::Client(e.to_string()))
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
