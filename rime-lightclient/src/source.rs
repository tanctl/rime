//! NoteSource abstraction decouples the sync engine from any concrete network backend.

use std::{
    collections::{BTreeMap, HashMap},
    ops::Range,
    sync::{Arc, Mutex as StdMutex},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use rime_core::privacy::PirConfig;
use rime_pir::{
    Error as PirError, PirBucket, PirClient, PirQuery, PirResponse, PirScheduler, PirServer,
    PirServerHandle, PirServerInterface, SchedulerStats,
};
use tokio::{sync::RwLock, task::JoinHandle};
use zcash_primitives::transaction::TxId;

use crate::rpc::{
    CompactBlock, CompactOrchardAction, CompactSaplingOutput, CompactTx, RawTransaction, RpcClient,
    RpcError, TreeState,
};
use crate::tor::TorManager;
use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, client::conn::http1, Request, Uri};
use hyper_util::rt::TokioIo;

/// errors that can occur when fetching data from a [`NoteSource`].
#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    #[error("network error: {0}")]
    Network(String),
    #[error("invalid data: {0}")]
    InvalidData(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("server error: {0}")]
    Server(String),
}

impl From<RpcError> for SourceError {
    fn from(err: RpcError) -> Self {
        match err {
            RpcError::Transport(e) => SourceError::Network(e.to_string()),
            RpcError::Status(e) => SourceError::Network(e.to_string()),
            RpcError::Server { message, .. } => SourceError::Server(message),
            RpcError::InvalidResponse(msg) => SourceError::InvalidData(msg.to_string()),
            RpcError::BackoffExceeded => {
                SourceError::Network("retry budget exceeded when contacting server".into())
            }
        }
    }
}

impl From<PirError> for SourceError {
    fn from(err: PirError) -> Self {
        match err {
            PirError::InsufficientServers => {
                SourceError::Network("pir requires at least two servers".into())
            }
            PirError::LengthMismatch => SourceError::InvalidData("pir length mismatch".into()),
            PirError::Server(msg) | PirError::Network(msg) => SourceError::Network(msg),
            PirError::InvalidIndex(idx) => {
                SourceError::InvalidData(format!("invalid pir bucket index {idx}"))
            }
            PirError::InvalidBucketSize | PirError::InvalidRecordLength => {
                SourceError::InvalidData("pir configuration invalid".into())
            }
            PirError::Io(e) => SourceError::Network(e.to_string()),
            PirError::Serialization(e) => SourceError::InvalidData(e.to_string()),
            PirError::ChannelClosed => SourceError::Network("pir scheduler channel closed".into()),
        }
    }
}

const SAPLING_ACTIVATION_HEIGHT: u32 = 419_200;
const PIR_RECORD_SIZE: usize = 256;
const PIR_INDEX_BATCH: u32 = 500;
const POOL_SAPLING: u8 = 1;
const POOL_ORCHARD: u8 = 2;
const RECORD_HEADER_LEN: usize = 4 + 1 + 32 + 4; // height + pool + txid + index
const SAPLING_RECORD_LEN: usize = RECORD_HEADER_LEN + 32 + 32 + 52;
const ORCHARD_RECORD_LEN: usize = RECORD_HEADER_LEN + 32 + 32 + 32 + 52;

#[derive(Clone, Debug)]
struct BlockMetadata {
    height: u32,
    proto_version: u32,
    hash: Vec<u8>,
    prev_hash: Vec<u8>,
    time: u32,
    header: Vec<u8>,
}

impl BlockMetadata {
    fn from_block(block: &CompactBlock) -> Self {
        Self {
            height: block.height as u32,
            proto_version: block.proto_version,
            hash: block.hash.clone(),
            prev_hash: block.prev_hash.clone(),
            time: block.time,
            header: block.header.clone(),
        }
    }

    fn placeholder(height: u32) -> Self {
        Self {
            height,
            proto_version: 0,
            hash: Vec::new(),
            prev_hash: Vec::new(),
            time: 0,
            header: Vec::new(),
        }
    }

    fn to_block(&self, vtx: Vec<CompactTx>) -> CompactBlock {
        CompactBlock {
            proto_version: self.proto_version,
            height: self.height as u64,
            hash: self.hash.clone(),
            prev_hash: self.prev_hash.clone(),
            time: self.time,
            header: self.header.clone(),
            vtx,
            chain_metadata: None,
        }
    }
}

struct ParsedRecord {
    height: u32,
    txid: Vec<u8>,
    index: u32,
    payload: RecordPayload,
}

enum RecordPayload {
    Sapling(CompactSaplingOutput),
    Orchard(CompactOrchardAction),
}

struct TorPirServer {
    authority: String,
    path_and_query: String,
    addr: String,
    tor: Arc<TorManager>,
}

impl TorPirServer {
    fn new(url: &str, tor: Arc<TorManager>) -> Result<Self, SourceError> {
        let uri: Uri = url
            .parse()
            .map_err(|e| SourceError::InvalidData(format!("invalid pir server url: {e}")))?;
        let scheme = uri.scheme_str().unwrap_or("http");
        if scheme != "http" {
            return Err(SourceError::InvalidData(
                "tor-backed pir currently supports http urls".into(),
            ));
        }
        let host = uri
            .host()
            .ok_or_else(|| SourceError::InvalidData("pir server url missing host".into()))?;
        let port = uri.port_u16().unwrap_or(80);
        let authority = if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
            host.to_string()
        } else {
            format!("{host}:{port}")
        };
        let addr = format!("{host}:{port}");
        let path_and_query = uri
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .filter(|pq| !pq.is_empty())
            .unwrap_or_else(|| "/query".to_string());
        Ok(Self {
            authority,
            path_and_query,
            addr,
            tor,
        })
    }
}

#[async_trait]
impl PirServerInterface for TorPirServer {
    async fn query(&self, query: &PirQuery) -> Result<PirResponse, PirError> {
        let stream = self
            .tor
            .connect_stream(&self.addr)
            .await
            .map_err(|e| PirError::Network(e.to_string()))?;
        let io = TokioIo::new(stream);
        let (mut sender, conn) = http1::handshake(io)
            .await
            .map_err(|e| PirError::Network(e.to_string()))?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let body = Full::new(Bytes::from(query.to_bytes()));
        let req = Request::builder()
            .method("POST")
            .uri(&self.path_and_query)
            .header("host", &self.authority)
            .header("content-type", "application/octet-stream")
            .body(body)
            .map_err(|e| PirError::Network(e.to_string()))?;
        let resp = sender
            .send_request(req)
            .await
            .map_err(|e| PirError::Network(e.to_string()))?;
        let status = resp.status();
        let data = resp
            .into_body()
            .collect()
            .await
            .map_err(|e| PirError::Network(e.to_string()))?
            .to_bytes();
        if !status.is_success() {
            return Err(PirError::Server(status.to_string()));
        }
        Ok(PirResponse {
            data: data.to_vec(),
        })
    }
}

struct OutputIndexMap {
    offsets: HashMap<u32, usize>,
    outputs_per_height: HashMap<u32, usize>,
    block_meta: HashMap<u32, BlockMetadata>,
    total_outputs: usize,
    bucket_size: usize,
    start_height: u32,
    end_height: u32,
}

/// NoteSource implementation that fetches compact outputs via PIR
pub struct PirNoteSource {
    scheduler: Arc<PirScheduler>,
    scheduler_task: StdMutex<Option<JoinHandle<()>>>,
    fallback_source: Arc<dyn NoteSource>,
    index_map: Arc<RwLock<OutputIndexMap>>,
    config: PirConfig,
}

impl PirNoteSource {
    async fn from_components(
        pir_client: Arc<PirClient>,
        fallback_source: Arc<dyn NoteSource>,
        config: PirConfig,
        index_map: OutputIndexMap,
    ) -> Result<Self, SourceError> {
        if config.bucket_size == 0 {
            return Err(SourceError::InvalidData(
                "PIR bucket size must be greater than zero".into(),
            ));
        }
        let total_buckets = index_map.total_buckets().max(1);
        let scheduler = Arc::new(PirScheduler::new(
            pir_client,
            config.dummy_interval,
            total_buckets,
        ));
        let scheduler_clone = scheduler.clone();
        let handle = tokio::spawn(async move {
            scheduler_clone.run().await;
        });
        Ok(Self {
            scheduler,
            scheduler_task: StdMutex::new(Some(handle)),
            fallback_source,
            index_map: Arc::new(RwLock::new(index_map)),
            config,
        })
    }

    pub async fn scheduler_stats(&self) -> SchedulerStats {
        self.scheduler.get_stats().await
    }

    pub fn estimate_bandwidth_per_hour(&self) -> f64 {
        self.scheduler.estimate_bandwidth_per_hour()
    }

    fn log_fetch_stats(&self, range: &Range<u32>, buckets: usize, elapsed: Duration) {
        tracing::info!(
            start = range.start,
            end = range.end,
            buckets,
            bucket_size = self.config.bucket_size,
            elapsed = elapsed.as_secs_f64(),
            "PIR bucket fetch complete"
        );
    }

    fn parse_record(record: &[u8]) -> Result<Option<ParsedRecord>, SourceError> {
        if record.iter().all(|&b| b == 0) {
            return Ok(None);
        }
        if record.len() < SAPLING_RECORD_LEN {
            return Err(SourceError::InvalidData("pir record too short".into()));
        }

        let mut cursor = 0usize;
        let height = u32::from_le_bytes(
            record[cursor..cursor + 4]
                .try_into()
                .map_err(|_| SourceError::InvalidData("invalid height bytes".into()))?,
        );
        cursor += 4;
        let pool = record[cursor];
        cursor += 1;
        let txid = record[cursor..cursor + 32].to_vec();
        cursor += 32;
        let index = u32::from_le_bytes(
            record[cursor..cursor + 4]
                .try_into()
                .map_err(|_| SourceError::InvalidData("invalid output index".into()))?,
        );
        cursor += 4;

        let payload = match pool {
            POOL_SAPLING => {
                if record.len() < SAPLING_RECORD_LEN {
                    return Err(SourceError::InvalidData(
                        "sapling pir record too short".into(),
                    ));
                }
                let cmu = record[cursor..cursor + 32].to_vec();
                cursor += 32;
                let eph = record[cursor..cursor + 32].to_vec();
                cursor += 32;
                let ciphertext = record[cursor..cursor + 52].to_vec();
                RecordPayload::Sapling(CompactSaplingOutput {
                    cmu,
                    ephemeral_key: eph,
                    ciphertext,
                })
            }
            POOL_ORCHARD => {
                if record.len() < ORCHARD_RECORD_LEN {
                    return Err(SourceError::InvalidData(
                        "orchard pir record too short".into(),
                    ));
                }
                let nullifier = record[cursor..cursor + 32].to_vec();
                cursor += 32;
                let cmx = record[cursor..cursor + 32].to_vec();
                cursor += 32;
                let eph = record[cursor..cursor + 32].to_vec();
                cursor += 32;
                let ciphertext = record[cursor..cursor + 52].to_vec();
                RecordPayload::Orchard(CompactOrchardAction {
                    nullifier,
                    cmx,
                    ephemeral_key: eph,
                    ciphertext,
                })
            }
            other => {
                return Err(SourceError::InvalidData(format!(
                    "unknown pool tag in pir record: {other}"
                )))
            }
        };

        Ok(Some(ParsedRecord {
            height,
            txid,
            index,
            payload,
        }))
    }

    async fn fetch_buckets_scheduled(
        &self,
        bucket_indices: Vec<usize>,
    ) -> Result<Vec<PirBucket>, SourceError> {
        if bucket_indices.is_empty() {
            return Ok(Vec::new());
        }
        let mut receivers = Vec::with_capacity(bucket_indices.len());
        for idx in bucket_indices {
            receivers.push(self.scheduler.request_bucket(idx).await);
        }
        let mut buckets = Vec::with_capacity(receivers.len());
        for rx in receivers {
            let bucket = rx
                .await
                .map_err(|_| SourceError::Network("pir scheduler shut down".into()))?;
            buckets.push(bucket);
        }
        Ok(buckets)
    }

    fn reconstruct_blocks(
        &self,
        buckets: Vec<PirBucket>,
        target_range: Range<u32>,
        metadata: HashMap<u32, BlockMetadata>,
    ) -> Result<Vec<CompactBlock>, SourceError> {
        let mut blocks: BTreeMap<u32, PendingBlock> = BTreeMap::new();
        for bucket in buckets {
            for record in bucket.records {
                if let Some(parsed) = Self::parse_record(&record)? {
                    if !target_range.contains(&parsed.height) {
                        continue;
                    }
                    let meta = metadata
                        .get(&parsed.height)
                        .cloned()
                        .unwrap_or_else(|| BlockMetadata::placeholder(parsed.height));
                    let pending = blocks
                        .entry(parsed.height)
                        .or_insert_with(|| PendingBlock::new(meta));
                    match parsed.payload {
                        RecordPayload::Sapling(output) => {
                            pending.add_output(parsed.txid, parsed.index, output)
                        }
                        RecordPayload::Orchard(action) => {
                            pending.add_action(parsed.txid, parsed.index, action)
                        }
                    }
                }
            }
        }
        let mut results = Vec::new();
        for height in target_range.clone() {
            if let Some(pending) = blocks.remove(&height) {
                results.push(pending.into_block());
            } else if let Some(meta) = metadata.get(&height) {
                results.push(meta.to_block(Vec::new()));
            } else {
                results.push(BlockMetadata::placeholder(height).to_block(Vec::new()));
            }
        }
        Ok(results)
    }

    async fn metadata_for_range(
        &self,
        range: Range<u32>,
    ) -> Result<(Vec<usize>, HashMap<u32, BlockMetadata>), SourceError> {
        if range.is_empty() {
            return Ok((Vec::new(), HashMap::new()));
        }
        let mut map = self.index_map.write().await;
        let target_end = range.end.saturating_sub(1);
        if target_end > map.end_height {
            map.extend_to(self.fallback_source.clone(), target_end)
                .await?;
            let new_total = map.total_buckets().max(1);
            if new_total > self.scheduler.num_buckets() {
                self.scheduler.update_bucket_count(new_total);
            }
        }
        let buckets = map.buckets_for_range(range.clone());
        let metadata = map.metadata_snapshot(range.clone());
        Ok((buckets, metadata))
    }
}

struct PendingBlock {
    tx_map: HashMap<Vec<u8>, usize>,
    block: CompactBlock,
}

impl PendingBlock {
    fn new(meta: BlockMetadata) -> Self {
        Self {
            tx_map: HashMap::new(),
            block: meta.to_block(Vec::new()),
        }
    }

    fn get_or_create_tx(&mut self, txid: Vec<u8>) -> &mut CompactTx {
        if let Some(&idx) = self.tx_map.get(&txid) {
            return &mut self.block.vtx[idx];
        }
        let index = self.block.vtx.len() as u64;
        let tx = CompactTx {
            index,
            hash: txid.clone(),
            fee: 0,
            spends: Vec::new(),
            outputs: Vec::new(),
            actions: Vec::new(),
        };
        self.block.vtx.push(tx);
        self.tx_map.insert(txid, self.block.vtx.len() - 1);
        self.block.vtx.last_mut().unwrap()
    }

    fn add_output(&mut self, txid: Vec<u8>, output_idx: u32, output: CompactSaplingOutput) {
        let tx = self.get_or_create_tx(txid);
        let idx = output_idx as usize;
        while tx.outputs.len() <= idx {
            tx.outputs.push(CompactSaplingOutput::default());
        }
        tx.outputs[idx] = output;
    }

    fn add_action(&mut self, txid: Vec<u8>, action_idx: u32, action: CompactOrchardAction) {
        let tx = self.get_or_create_tx(txid);
        let idx = action_idx as usize;
        while tx.actions.len() <= idx {
            tx.actions.push(CompactOrchardAction::default());
        }
        tx.actions[idx] = action;
    }

    fn into_block(self) -> CompactBlock {
        self.block
    }
}

impl Drop for PirNoteSource {
    fn drop(&mut self) {
        self.scheduler.shutdown();
        if let Ok(mut guard) = self.scheduler_task.lock() {
            if let Some(handle) = guard.take() {
                handle.abort();
            }
        }
    }
}

pub async fn create_pir_source(
    config: &PirConfig,
    grpc_source: Arc<dyn NoteSource>,
    tor: Option<Arc<TorManager>>,
) -> Result<PirNoteSource, SourceError> {
    if config.servers.len() < 2 {
        return Err(SourceError::Network(
            "PIR mode requires at least two servers".into(),
        ));
    }
    let latest = grpc_source.latest_height().await?;
    let start_height = config
        .start_height
        .unwrap_or(SAPLING_ACTIVATION_HEIGHT)
        .min(latest);
    let index_map = OutputIndexMap::build(
        grpc_source.clone(),
        start_height,
        latest,
        config.bucket_size,
    )
    .await?;
    let derived_buckets = index_map.total_buckets().max(1);
    let requested_buckets = config.num_buckets.unwrap_or(derived_buckets);
    let num_buckets = requested_buckets.max(derived_buckets).max(1);
    let mut handles: Vec<PirServerHandle> = Vec::new();
    for server in &config.servers {
        let handle: PirServerHandle = if let Some(tor_mgr) = tor.as_ref().map(Arc::clone) {
            let tor_server = TorPirServer::new(&server.url, tor_mgr.clone())?;
            Arc::new(tor_server)
        } else {
            Arc::new(PirServer::new(server.url.clone()))
        };
        handles.push(handle);
    }
    let client = PirClient::new(handles, config.bucket_size, num_buckets, PIR_RECORD_SIZE)
        .map_err(SourceError::from)?;
    PirNoteSource::from_components(Arc::new(client), grpc_source, config.clone(), index_map).await
}

#[async_trait]
impl NoteSource for PirNoteSource {
    async fn fetch_compact_blocks(
        &self,
        range: Range<u32>,
    ) -> Result<Vec<CompactBlock>, SourceError> {
        if range.is_empty() || range.start >= range.end {
            return Ok(Vec::new());
        }
        {
            let map = self.index_map.read().await;
            if range.start < map.start_height {
                return self.fallback_source.fetch_compact_blocks(range).await;
            }
        }
        let (bucket_indices, metadata) = self.metadata_for_range(range.clone()).await?;
        if bucket_indices.is_empty() {
            return self.fallback_source.fetch_compact_blocks(range).await;
        }
        let start = Instant::now();
        let buckets = self.fetch_buckets_scheduled(bucket_indices).await?;
        let duration = start.elapsed();
        self.log_fetch_stats(&range, buckets.len(), duration);
        self.reconstruct_blocks(buckets, range, metadata)
    }

    async fn fetch_block(&self, height: u32) -> Result<CompactBlock, SourceError> {
        self.fallback_source.fetch_block(height).await
    }

    async fn fetch_tree_state(&self, height: u32) -> Result<TreeState, SourceError> {
        self.fallback_source.fetch_tree_state(height).await
    }

    async fn fetch_transaction(&self, txid: TxId) -> Result<RawTransaction, SourceError> {
        self.fallback_source.fetch_transaction(txid).await
    }

    async fn latest_height(&self) -> Result<u32, SourceError> {
        self.fallback_source.latest_height().await
    }
}

impl OutputIndexMap {
    fn new(bucket_size: usize, start_height: u32) -> Self {
        Self {
            offsets: HashMap::new(),
            outputs_per_height: HashMap::new(),
            block_meta: HashMap::new(),
            total_outputs: 0,
            bucket_size,
            start_height,
            end_height: start_height.saturating_sub(1),
        }
    }

    async fn build(
        source: Arc<dyn NoteSource>,
        start_height: u32,
        end_height: u32,
        bucket_size: usize,
    ) -> Result<Self, SourceError> {
        let mut map = OutputIndexMap::new(bucket_size, start_height);
        map.extend_to(source, end_height).await?;
        Ok(map)
    }

    async fn extend_to(
        &mut self,
        source: Arc<dyn NoteSource>,
        target_end: u32,
    ) -> Result<(), SourceError> {
        if target_end <= self.end_height {
            return Ok(());
        }
        if self.bucket_size == 0 {
            return Err(SourceError::InvalidData(
                "pir bucket size must be greater than zero".into(),
            ));
        }
        let mut cursor = if self.offsets.is_empty() {
            self.start_height
        } else {
            self.end_height.saturating_add(1)
        };
        let mut total_outputs = self.total_outputs;
        while cursor <= target_end {
            let batch_end = cursor
                .saturating_add(PIR_INDEX_BATCH)
                .min(target_end.saturating_add(1));
            let blocks = source.fetch_compact_blocks(cursor..batch_end).await?;
            let mut block_map = HashMap::new();
            for block in blocks {
                block_map.insert(block.height as u32, block);
            }
            for height in cursor..batch_end {
                self.offsets.entry(height).or_insert(total_outputs);
                let outputs = block_map.get(&height).map(Self::count_outputs).unwrap_or(0);
                self.outputs_per_height.insert(height, outputs);
                if let Some(block) = block_map.get(&height) {
                    self.block_meta
                        .insert(height, BlockMetadata::from_block(block));
                } else {
                    self.block_meta
                        .entry(height)
                        .or_insert_with(|| BlockMetadata::placeholder(height));
                }
                total_outputs += outputs;
            }
            cursor = batch_end;
        }
        self.end_height = target_end;
        self.total_outputs = total_outputs;
        Ok(())
    }

    fn count_outputs(block: &CompactBlock) -> usize {
        block
            .vtx
            .iter()
            .map(|tx| tx.outputs.len() + tx.actions.len())
            .sum::<usize>()
    }

    fn offset_for_height(&self, height: u32) -> usize {
        *self.offsets.get(&height).unwrap_or(&0)
    }

    fn outputs_for_height(&self, height: u32) -> usize {
        *self.outputs_per_height.get(&height).unwrap_or(&0)
    }

    fn buckets_for_range(&self, range: Range<u32>) -> Vec<usize> {
        if range.is_empty() || range.start >= range.end {
            return Vec::new();
        }
        let start_offset = self.offset_for_height(range.start);
        let end_height = range.end.saturating_sub(1);
        let end_offset = self.offset_for_height(end_height) + self.outputs_for_height(end_height);
        if end_offset <= start_offset {
            return Vec::new();
        }
        let start_bucket = start_offset / self.bucket_size;
        let end_bucket = (end_offset.saturating_sub(1)) / self.bucket_size;
        (start_bucket..=end_bucket).collect()
    }

    fn metadata_snapshot(&self, range: Range<u32>) -> HashMap<u32, BlockMetadata> {
        let mut snapshot = HashMap::new();
        for height in range {
            if let Some(meta) = self.block_meta.get(&height) {
                snapshot.insert(height, meta.clone());
            } else {
                snapshot.insert(height, BlockMetadata::placeholder(height));
            }
        }
        snapshot
    }

    fn total_buckets(&self) -> usize {
        if self.bucket_size == 0 {
            0
        } else if self.total_outputs == 0 {
            1
        } else {
            self.total_outputs.div_ceil(self.bucket_size)
        }
    }
}

// NoteSource abstraction; object-safe so custom sources can layer privacy transports
#[async_trait]
pub trait NoteSource: Send + Sync {
    /// fetch compact blocks for the half-open height range [range.start, range.end)
    async fn fetch_compact_blocks(
        &self,
        range: Range<u32>,
    ) -> Result<Vec<CompactBlock>, SourceError>;

    async fn fetch_block(&self, height: u32) -> Result<CompactBlock, SourceError>;

    async fn fetch_tree_state(&self, height: u32) -> Result<TreeState, SourceError>;

    async fn fetch_transaction(&self, txid: TxId) -> Result<RawTransaction, SourceError>;

    async fn fetch_transactions(
        &self,
        txids: Vec<TxId>,
    ) -> Result<Vec<RawTransaction>, SourceError> {
        let mut out = Vec::with_capacity(txids.len());
        for txid in txids {
            out.push(self.fetch_transaction(txid).await?);
        }
        Ok(out)
    }

    async fn latest_height(&self) -> Result<u32, SourceError>;
}

/// gRPC-backed NoteSource that forwards requests to lightwalletd.
pub struct GrpcNoteSource {
    client: Arc<dyn RpcClient>,
}

impl GrpcNoteSource {
    pub fn new(client: Arc<dyn RpcClient>) -> Self {
        Self { client }
    }
}

#[async_trait]
impl NoteSource for GrpcNoteSource {
    async fn fetch_compact_blocks(
        &self,
        range: Range<u32>,
    ) -> Result<Vec<CompactBlock>, SourceError> {
        if range.is_empty() {
            return Ok(Vec::new());
        }
        let start = range.start;
        let end_inclusive = range.end - 1;
        self.client
            .get_block_range(start, end_inclusive)
            .await
            .map_err(SourceError::from)
    }

    async fn fetch_block(&self, height: u32) -> Result<CompactBlock, SourceError> {
        self.client
            .get_block(height)
            .await
            .map_err(SourceError::from)
    }

    async fn fetch_tree_state(&self, height: u32) -> Result<TreeState, SourceError> {
        self.client
            .get_tree_state(height)
            .await
            .map_err(SourceError::from)
    }

    async fn fetch_transaction(&self, txid: TxId) -> Result<RawTransaction, SourceError> {
        self.client
            .get_transaction(txid.as_ref().to_vec())
            .await
            .map_err(SourceError::from)
    }

    async fn latest_height(&self) -> Result<u32, SourceError> {
        let block_id = self
            .client
            .get_latest_block()
            .await
            .map_err(SourceError::from)?;
        Ok(block_id.height as u32)
    }
}

#[derive(Clone, Default)]
pub struct MockNoteSource {
    pub latest_height: u32,
    pub blocks: HashMap<u32, CompactBlock>,
    pub transactions: HashMap<TxId, RawTransaction>,
    pub tree_states: HashMap<u32, TreeState>,
}

impl MockNoteSource {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_blocks(blocks: Vec<CompactBlock>) -> Self {
        let mut source = Self::new();
        if !blocks.iter().any(|block| block.height == 0) {
            source.insert_block(CompactBlock::default());
        }
        for block in blocks {
            source.insert_block(block);
        }
        source
    }

    pub fn insert_block(&mut self, block: CompactBlock) {
        let height = block.height as u32;
        self.latest_height = self.latest_height.max(height);
        self.blocks.insert(height, block);
    }

    pub fn insert_tree_state(&mut self, state: TreeState) {
        self.tree_states.insert(state.height as u32, state);
    }

    pub fn insert_transaction(&mut self, txid: TxId, tx: RawTransaction) {
        self.transactions.insert(txid, tx);
    }

    pub fn set_latest_height(&mut self, height: u32) {
        self.latest_height = height;
    }
}

#[async_trait]
impl NoteSource for MockNoteSource {
    async fn fetch_compact_blocks(
        &self,
        range: Range<u32>,
    ) -> Result<Vec<CompactBlock>, SourceError> {
        if range.is_empty() {
            return Ok(Vec::new());
        }
        let mut blocks = Vec::new();
        for height in range {
            if let Some(block) = self.blocks.get(&height) {
                blocks.push(block.clone());
            }
        }
        Ok(blocks)
    }

    async fn fetch_block(&self, height: u32) -> Result<CompactBlock, SourceError> {
        Ok(self
            .blocks
            .get(&height)
            .cloned()
            .unwrap_or_else(|| CompactBlock {
                height: height as u64,
                ..CompactBlock::default()
            }))
    }

    async fn fetch_tree_state(&self, height: u32) -> Result<TreeState, SourceError> {
        self.tree_states
            .get(&height)
            .cloned()
            .ok_or_else(|| SourceError::NotFound(format!("tree state for height {height} missing")))
    }

    async fn fetch_transaction(&self, txid: TxId) -> Result<RawTransaction, SourceError> {
        self.transactions
            .get(&txid)
            .cloned()
            .ok_or_else(|| SourceError::NotFound("transaction not found".into()))
    }

    async fn latest_height(&self) -> Result<u32, SourceError> {
        Ok(self.latest_height)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::BlockId;
    use rime_core::privacy::PirServerConfig;
    use rime_pir::{MockPirServer, PirDatabase, PirRecord};
    use std::sync::Mutex as StdMutex;
    use std::time::Duration;

    #[tokio::test]
    async fn mock_source_serves_blocks() {
        let block = CompactBlock {
            height: 10,
            ..CompactBlock::default()
        };
        let source = MockNoteSource::from_blocks(vec![block.clone()]);
        let fetched = source.fetch_compact_blocks(10..11).await.expect("fetch");
        assert_eq!(fetched.len(), 1);
        assert_eq!(fetched[0].height, block.height);
    }

    #[tokio::test]
    async fn grpc_source_forwards_calls() {
        struct TestRpcClient;

        #[async_trait]
        impl RpcClient for TestRpcClient {
            async fn get_latest_block(&self) -> Result<BlockId, RpcError> {
                Ok(BlockId {
                    height: 5,
                    hash: vec![],
                })
            }

            async fn get_block(&self, height: u32) -> Result<CompactBlock, RpcError> {
                Ok(CompactBlock {
                    height: height as u64,
                    ..CompactBlock::default()
                })
            }

            async fn get_block_range(
                &self,
                start: u32,
                end: u32,
            ) -> Result<Vec<CompactBlock>, RpcError> {
                Ok((start..=end)
                    .map(|h| CompactBlock {
                        height: h as u64,
                        ..CompactBlock::default()
                    })
                    .collect())
            }

            async fn get_tree_state(&self, height: u32) -> Result<TreeState, RpcError> {
                Ok(TreeState {
                    height: height as u64,
                    ..TreeState::default()
                })
            }

            async fn send_transaction(&self, _raw_tx: &[u8]) -> Result<String, RpcError> {
                Ok(String::new())
            }

            async fn get_transaction(&self, _txid: Vec<u8>) -> Result<RawTransaction, RpcError> {
                Ok(RawTransaction {
                    data: vec![],
                    height: 0,
                })
            }
        }

        let source = GrpcNoteSource::new(Arc::new(TestRpcClient));
        let blocks = source.fetch_compact_blocks(1..3).await.expect("blocks");
        assert_eq!(blocks.len(), 2);
        assert_eq!(source.latest_height().await.unwrap(), 5);
        source.fetch_block(2).await.unwrap();
        source.fetch_tree_state(3).await.unwrap();
        source
            .fetch_transaction(TxId::from_bytes([0u8; 32]))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn mock_source_serves_transactions() {
        let mut source = MockNoteSource::new();
        let txid = TxId::from_bytes([1u8; 32]);
        source.insert_transaction(
            txid,
            RawTransaction {
                data: vec![1, 2, 3],
                height: 0,
            },
        );
        let fetched = source
            .fetch_transaction(TxId::from_bytes([1u8; 32]))
            .await
            .unwrap();
        assert_eq!(fetched.data, vec![1, 2, 3]);
    }

    fn sample_blocks() -> Vec<CompactBlock> {
        let mut blocks = Vec::new();
        for i in 0..2 {
            let height = 50u32 + i as u32;
            let mut tx = CompactTx {
                index: 0,
                hash: vec![i; 32],
                fee: 0,
                spends: Vec::new(),
                outputs: Vec::new(),
                actions: Vec::new(),
            };
            for j in 0..=i {
                tx.outputs.push(CompactSaplingOutput {
                    cmu: vec![j; 32],
                    ephemeral_key: vec![i.wrapping_add(j); 32],
                    ciphertext: vec![0xAA + j; 52],
                });
            }
            tx.actions.push(CompactOrchardAction {
                nullifier: vec![0xB0 + i; 32],
                cmx: vec![0xC0 + i; 32],
                ephemeral_key: vec![0xD0 + i; 32],
                ciphertext: vec![0xE0 + i; 52],
            });
            blocks.push(CompactBlock {
                proto_version: 0,
                height: height as u64,
                hash: vec![0x10 + i; 32],
                prev_hash: if i == 0 {
                    vec![0x01; 32]
                } else {
                    vec![0x10 + (i - 1); 32]
                },
                time: height,
                header: vec![0u8; 4],
                vtx: vec![tx],
                chain_metadata: None,
            });
        }
        blocks
    }

    fn serialize_records(blocks: &[CompactBlock]) -> Vec<PirRecord> {
        fn append(dst: &mut Vec<u8>, src: &[u8], len: usize) {
            if src.len() >= len {
                dst.extend_from_slice(&src[..len]);
            } else {
                dst.extend_from_slice(src);
                dst.resize(dst.len() + (len - src.len()), 0);
            }
        }
        let mut records = Vec::new();
        for block in blocks {
            let height = block.height as u32;
            for tx in &block.vtx {
                for (idx, output) in tx.outputs.iter().enumerate() {
                    let mut record = Vec::with_capacity(PIR_RECORD_SIZE);
                    record.extend_from_slice(&height.to_le_bytes());
                    record.push(POOL_SAPLING);
                    append(&mut record, &tx.hash, 32);
                    record.extend_from_slice(&(idx as u32).to_le_bytes());
                    append(&mut record, &output.cmu, 32);
                    append(&mut record, &output.ephemeral_key, 32);
                    append(&mut record, &output.ciphertext, 52);
                    record.resize(PIR_RECORD_SIZE, 0);
                    records.push(record);
                }
                for (idx, action) in tx.actions.iter().enumerate() {
                    let mut record = Vec::with_capacity(PIR_RECORD_SIZE);
                    record.extend_from_slice(&height.to_le_bytes());
                    record.push(POOL_ORCHARD);
                    append(&mut record, &tx.hash, 32);
                    record.extend_from_slice(&(idx as u32).to_le_bytes());
                    append(&mut record, &action.nullifier, 32);
                    append(&mut record, &action.cmx, 32);
                    append(&mut record, &action.ephemeral_key, 32);
                    append(&mut record, &action.ciphertext, 52);
                    record.resize(PIR_RECORD_SIZE, 0);
                    records.push(record);
                }
            }
        }
        records
    }

    #[tokio::test]
    async fn pir_note_source_reconstructs_blocks() {
        let blocks = sample_blocks();
        let bucket_size = 2;
        let records = serialize_records(&blocks);
        let db = PirDatabase::from_records(records, bucket_size).expect("db");
        let num_buckets = db.num_buckets();
        let shared = Arc::new(StdMutex::new(db));
        let server_a = Arc::new(MockPirServer::new(shared.clone())) as PirServerHandle;
        let server_b = Arc::new(MockPirServer::new(shared)) as PirServerHandle;
        let client = PirClient::new(
            vec![server_a, server_b],
            bucket_size,
            num_buckets.max(1),
            PIR_RECORD_SIZE,
        )
        .expect("client");
        let fallback = Arc::new(MockNoteSource::from_blocks(blocks.clone()));
        let start_height = blocks.first().unwrap().height as u32;
        let end_height = blocks.last().unwrap().height as u32;
        let index_map =
            OutputIndexMap::build(fallback.clone(), start_height, end_height, bucket_size)
                .await
                .expect("index map");
        let config = PirConfig {
            servers: vec![
                PirServerConfig {
                    url: "mock://a".into(),
                    label: None,
                },
                PirServerConfig {
                    url: "mock://b".into(),
                    label: None,
                },
            ],
            bucket_size,
            num_buckets: Some(num_buckets),
            start_height: Some(start_height),
            dummy_interval: Duration::from_millis(5),
        };
        let pir = PirNoteSource::from_components(Arc::new(client), fallback, config, index_map)
            .await
            .expect("pir source");
        let fetched = pir
            .fetch_compact_blocks(start_height..(start_height + blocks.len() as u32))
            .await
            .expect("pir blocks");
        assert_eq!(fetched.len(), blocks.len());
        for (expected, actual) in blocks.iter().zip(fetched.iter()) {
            assert_eq!(expected.height, actual.height);
            assert_eq!(expected.hash, actual.hash);
            assert_eq!(expected.vtx.len(), actual.vtx.len());
            assert_eq!(expected.vtx[0].outputs.len(), actual.vtx[0].outputs.len());
            for (exp_out, act_out) in expected.vtx[0]
                .outputs
                .iter()
                .zip(actual.vtx[0].outputs.iter())
            {
                assert_eq!(exp_out.cmu, act_out.cmu);
                assert_eq!(exp_out.ephemeral_key, act_out.ephemeral_key);
                assert_eq!(exp_out.ciphertext, act_out.ciphertext);
            }
            assert_eq!(expected.vtx[0].actions.len(), actual.vtx[0].actions.len());
            for (exp_act, act_act) in expected.vtx[0]
                .actions
                .iter()
                .zip(actual.vtx[0].actions.iter())
            {
                assert_eq!(exp_act.nullifier, act_act.nullifier);
                assert_eq!(exp_act.cmx, act_act.cmx);
                assert_eq!(exp_act.ephemeral_key, act_act.ephemeral_key);
                assert_eq!(exp_act.ciphertext, act_act.ciphertext);
            }
        }
    }
}
