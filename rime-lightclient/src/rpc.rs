use arti_client::TorClient;
use async_trait::async_trait;
use futures::future::BoxFuture;
use rime_core::Network;
use std::io;
use std::{sync::Arc, time::Duration};
use thiserror::Error;
use tokio::time::sleep;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tonic::{
    transport::{Channel, ClientTlsConfig, Endpoint, Uri},
    Request,
};
use tor_rtcompat::PreferredRuntime;
use tower::service_fn;
use tracing::{debug, error, info};
use zcash_primitives::consensus::{BlockHeight, BranchId, MainNetwork, TestNetwork};

trait TlsConfigNative {
    fn with_native_roots(self) -> Self;
}

impl TlsConfigNative for ClientTlsConfig {
    fn with_native_roots(self) -> Self {
        // tonic with the tls-roots feature loads native roots by default; we keep this shim to match the intended API surface
        self
    }
}

#[allow(clippy::doc_overindented_list_items)]
pub mod proto {
    tonic::include_proto!("cash.z.wallet.sdk.rpc");
}

pub use proto::{
    BlockId, BlockRange, ChainSpec, CompactBlock, CompactOrchardAction, CompactSaplingOutput,
    CompactSaplingSpend, CompactTx, Empty, LightdInfo, RawTransaction, SendResponse, TreeState,
    TxFilter,
};

use proto::compact_tx_streamer_client::CompactTxStreamerClient;

#[derive(Clone)]
pub struct RpcConfig {
    pub endpoint: String,
    pub timeout: Duration,
    pub max_retries: u32,
    pub network: Network,
    pub tor_client: Option<Arc<TorClient<PreferredRuntime>>>,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            endpoint: "https://testnet.zec.rocks:443".to_string(),
            timeout: Duration::from_secs(10),
            max_retries: 3,
            network: Network::Testnet,
            tor_client: None,
        }
    }
}

#[derive(Debug, Error)]
pub enum RpcError {
    #[error("transport: {0}")]
    Transport(#[from] tonic::transport::Error),
    #[error("status: {0}")]
    Status(#[from] tonic::Status),
    #[error("server error {code}: {message}")]
    Server { code: i32, message: String },
    #[error("invalid response: {0}")]
    InvalidResponse(&'static str),
    #[error("retry budget exceeded")]
    BackoffExceeded,
}

#[async_trait]
pub trait RpcClient: Send + Sync {
    async fn get_latest_block(&self) -> Result<BlockId, RpcError>;
    async fn get_block(&self, height: u32) -> Result<CompactBlock, RpcError>;
    async fn get_block_range(&self, start: u32, end: u32) -> Result<Vec<CompactBlock>, RpcError>;
    async fn get_tree_state(&self, height: u32) -> Result<TreeState, RpcError>;
    async fn send_transaction(&self, raw_tx: &[u8]) -> Result<String, RpcError>;
    async fn get_transaction(&self, txid: Vec<u8>) -> Result<RawTransaction, RpcError>;
}

pub struct GrpcRpcClient {
    config: RpcConfig,
    client: tokio::sync::Mutex<CompactTxStreamerClient<Channel>>,
}

impl GrpcRpcClient {
    pub async fn connect(config: RpcConfig) -> Result<Self, RpcError> {
        let use_plaintext = config.endpoint.starts_with("http://");
        let base = Endpoint::from_shared(config.endpoint.clone())?
            .timeout(config.timeout)
            .connect_timeout(config.timeout);
        let channel = if let Some(tor) = config.tor_client.clone() {
            Self::connect_with_tor(base, use_plaintext, tor).await?
        } else if use_plaintext {
            base.connect().await?
        } else {
            let tls = ClientTlsConfig::new().with_native_roots();
            base.tls_config(tls)?.connect().await?
        };
        debug!(
            endpoint = %config.endpoint,
            plaintext = use_plaintext,
            "gRPC channel established"
        );
        let client = CompactTxStreamerClient::new(channel)
            .max_decoding_message_size(64 << 20)
            .max_encoding_message_size(32 << 20);
        let rpc = Self {
            config,
            client: tokio::sync::Mutex::new(client),
        };
        rpc.validate_chain().await?;
        Ok(rpc)
    }

    async fn connect_with_tor(
        mut base: Endpoint,
        use_plaintext: bool,
        tor: Arc<TorClient<PreferredRuntime>>,
    ) -> Result<Channel, RpcError> {
        if !use_plaintext {
            let tls = ClientTlsConfig::new().with_native_roots();
            base = base.tls_config(tls)?;
        }
        let connector = service_fn(move |uri: Uri| {
            let tor = tor.clone();
            async move {
                let host = uri
                    .host()
                    .ok_or_else(|| io::Error::other("missing host"))?
                    .to_string();
                let port = uri
                    .port_u16()
                    .unwrap_or(if use_plaintext { 80 } else { 443 });
                let addr = format!("{host}:{port}");
                let stream = tor
                    .connect(&addr)
                    .await
                    .map_err(|e| io::Error::other(e.to_string()))?;
                let stream = stream.compat();
                Ok::<_, io::Error>(stream)
            }
        });
        base.connect_with_connector(connector)
            .await
            .map_err(RpcError::from)
    }

    async fn validate_chain(&self) -> Result<LightdInfo, RpcError> {
        let info = self
            .call_with_retry(|client| {
                Box::pin(async move {
                    let result = client.get_lightd_info(Request::new(Empty {})).await;
                    match result {
                        Ok(response) => {
                            let info = response.into_inner();
                            debug!("get_lightd_info response: {:?}", info);
                            if info.chain_name.is_empty() {
                                return Err(RpcError::InvalidResponse("empty chain name"));
                            }
                            Ok(info)
                        }
                        Err(status) => {
                            error!(
                                "get_lightd_info failed: code={:?}, message={}",
                                status.code(),
                                status.message()
                            );
                            Err(RpcError::InvalidResponse("failed to call GetLightdInfo"))
                        }
                    }
                })
            })
            .await?;

        if chain_matches(self.config.network, &info.chain_name) {
            self.validate_branch_id(&info)?;
            Ok(info)
        } else {
            Err(RpcError::InvalidResponse("unsupported chain"))
        }
    }

    #[allow(clippy::result_large_err)]
    fn validate_branch_id(&self, info: &LightdInfo) -> Result<(), RpcError> {
        let branch_hex = info.consensus_branch_id.trim();
        let parsed = u32::from_str_radix(branch_hex.trim_start_matches("0x"), 16)
            .map_err(|_| RpcError::InvalidResponse("invalid consensus branch id"))?;
        let expected = match self.config.network {
            Network::Mainnet => BranchId::for_height(
                &MainNetwork,
                BlockHeight::from_u32(info.block_height as u32),
            ),
            Network::Testnet => BranchId::for_height(
                &TestNetwork,
                BlockHeight::from_u32(info.block_height as u32),
            ),
        };
        if parsed != u32::from(expected) {
            return Err(RpcError::InvalidResponse("branch id/network mismatch"));
        }
        Ok(())
    }

    async fn call_with_retry<F, T>(&self, mut op: F) -> Result<T, RpcError>
    where
        F: for<'a> FnMut(
                &'a mut CompactTxStreamerClient<Channel>,
            ) -> BoxFuture<'a, Result<T, RpcError>>
            + Send,
        T: Send,
    {
        let mut delay = Duration::from_millis(250);
        let mut attempt = 0u32;
        loop {
            let mut client = self.client.lock().await;
            match op(&mut client).await {
                Ok(value) => return Ok(value),
                Err(err) => {
                    let attempt_number = attempt + 1;
                    tracing::warn!(
                        attempt = attempt_number,
                        max_retries = self.config.max_retries,
                        endpoint = %self.config.endpoint,
                        error = %err,
                        "RPC call failed; retrying"
                    );
                    if attempt >= self.config.max_retries {
                        return Err(RpcError::BackoffExceeded);
                    }
                    attempt += 1;
                    drop(client);
                    sleep(delay).await;
                    delay = (delay * 2).min(self.config.timeout);
                }
            }
        }
    }

    fn block_id(height: u32) -> BlockId {
        BlockId {
            height: height as u64,
            hash: Vec::new(),
        }
    }

    fn chain_spec() -> ChainSpec {
        ChainSpec {}
    }
}

#[async_trait]
impl RpcClient for GrpcRpcClient {
    async fn get_latest_block(&self) -> Result<BlockId, RpcError> {
        self.call_with_retry(|client| {
            Box::pin(async move {
                let response = client
                    .get_latest_block(Request::new(Self::chain_spec()))
                    .await?;
                Ok(response.into_inner())
            })
        })
        .await
    }

    async fn get_block(&self, height: u32) -> Result<CompactBlock, RpcError> {
        self.call_with_retry(|client| {
            Box::pin(async move {
                let response = client
                    .get_block(Request::new(Self::block_id(height)))
                    .await?;
                Ok(response.into_inner())
            })
        })
        .await
    }

    async fn get_block_range(&self, start: u32, end: u32) -> Result<Vec<CompactBlock>, RpcError> {
        if start > end {
            return Err(RpcError::InvalidResponse("start > end"));
        }

        self.call_with_retry(|client| {
            Box::pin(async move {
                info!("Calling GetBlockRange [{}..{}]", start, end);
                let request = BlockRange {
                    start: Some(Self::block_id(start)),
                    end: Some(Self::block_id(end)),
                };
                let mut stream = client
                    .get_block_range(Request::new(request))
                    .await?
                    .into_inner();
                let mut blocks = Vec::new();
                while let Some(block) = stream.message().await? {
                    blocks.push(block);
                }
                Ok(blocks)
            })
        })
        .await
    }

    async fn get_tree_state(&self, height: u32) -> Result<TreeState, RpcError> {
        self.call_with_retry(|client| {
            Box::pin(async move {
                let response = client
                    .get_tree_state(Request::new(Self::block_id(height)))
                    .await?;
                Ok(response.into_inner())
            })
        })
        .await
    }

    async fn send_transaction(&self, raw_tx: &[u8]) -> Result<String, RpcError> {
        self.call_with_retry(|client| {
            let payload = RawTransaction {
                data: raw_tx.to_vec(),
                height: 0,
            };
            Box::pin(async move {
                let response = client.send_transaction(Request::new(payload)).await?;
                let SendResponse {
                    error_code,
                    error_message,
                } = response.into_inner();
                if error_code == 0 {
                    Ok(error_message)
                } else {
                    Err(RpcError::Server {
                        code: error_code,
                        message: error_message,
                    })
                }
            })
        })
        .await
    }

    async fn get_transaction(&self, txid: Vec<u8>) -> Result<RawTransaction, RpcError> {
        self.call_with_retry(|client| {
            let filter = TxFilter {
                block: None,
                index: 0,
                hash: txid.clone(),
            };
            Box::pin(async move {
                let response = client.get_transaction(Request::new(filter)).await?;
                Ok(response.into_inner())
            })
        })
        .await
    }
}

fn chain_matches(network: Network, chain: &str) -> bool {
    let normalized = chain.to_ascii_lowercase();
    match network {
        Network::Mainnet => matches!(normalized.as_str(), "main" | "mainnet"),
        Network::Testnet => matches!(normalized.as_str(), "test" | "testnet"),
    }
}

#[cfg(test)]
mod tests {
    use super::chain_matches;
    use rime_core::Network;

    #[test]
    fn chain_matching_behaves() {
        assert!(chain_matches(Network::Mainnet, "main"));
        assert!(chain_matches(Network::Mainnet, "MainNet"));
        assert!(!chain_matches(Network::Mainnet, "test"));

        assert!(chain_matches(Network::Testnet, "Test"));
        assert!(!chain_matches(Network::Testnet, "main"));
    }
}
