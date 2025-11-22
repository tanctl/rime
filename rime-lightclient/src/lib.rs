//! RIME lightclient: RPC + sync plumbing for the Unified Address light client.

use std::sync::Arc;

use reqwest::Client;
use rime_core::WalletSeed;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::Mutex;

pub mod rpc;
pub use rpc::{GrpcRpcClient, RpcClient, RpcConfig, RpcError};
pub mod db;
pub use db::RimeWalletDb;
pub mod sync;
pub use sync::{SyncError, SyncProgress, SyncResult, WalletSyncer};
pub mod full_memo;
pub use full_memo::{estimate_full_memo_bandwidth, FullMemoSyncer, OrchardMemoEntry, SyncStats};
pub mod source;
pub use source::{
    create_pir_source, GrpcNoteSource, MockNoteSource, NoteSource, PirNoteSource, SourceError,
};
pub mod tor;
pub use tor::{TorConfig, TorError, TorManager};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeStatus {
    pub block_height: u32,
    pub chain_tip: String,
}

#[derive(Debug, Error)]
pub enum LightClientError {
    #[error("network: {0}")]
    Network(#[from] reqwest::Error),
    #[error("decode: {0}")]
    Decode(#[from] serde_json::Error),
}

struct LightClientInner {
    endpoint: String,
    client: Client,
    #[allow(dead_code)]
    wallet: Mutex<WalletSeed>,
}

#[derive(Clone)]
pub struct LightClient {
    inner: Arc<LightClientInner>,
}

impl LightClient {
    pub fn from_seed(endpoint: impl Into<String>, seed: WalletSeed) -> Self {
        Self::new_with_wallet(endpoint, seed)
    }

    pub fn new_with_wallet(endpoint: impl Into<String>, wallet: WalletSeed) -> Self {
        let inner = LightClientInner {
            endpoint: endpoint.into(),
            client: Client::builder().build().expect("client"),
            wallet: Mutex::new(wallet),
        };
        Self {
            inner: Arc::new(inner),
        }
    }

    pub async fn fetch_status(&self) -> Result<NodeStatus, LightClientError> {
        let url = format!("{}/status", self.inner.endpoint);
        let response = self.inner.client.get(url).send().await?.text().await?;
        self.parse_status(&response)
    }

    pub async fn sync_once(&self) -> Result<NodeStatus, LightClientError> {
        let status = self.fetch_status().await?;
        Ok(status)
    }

    fn parse_status(&self, payload: &str) -> Result<NodeStatus, LightClientError> {
        let status: NodeStatus = serde_json::from_str(payload)?;
        Ok(status)
    }

    pub async fn wallet_alias(&self) -> String {
        // wallet state removed; retain placeholder alias
        "default".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn parse_status_from_sample() {
        let seed = WalletSeed::generate();
        let client = LightClient::from_seed("http://localhost:8232", seed);
        let payload = r#"{"block_height":10,"chain_tip":"000abc"}"#;
        let status = client.parse_status(payload).expect("status");
        assert_eq!(
            status,
            NodeStatus {
                block_height: 10,
                chain_tip: "000abc".into(),
            }
        );
        assert_eq!(client.wallet_alias().await, "default".to_string());
    }
}
