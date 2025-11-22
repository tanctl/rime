use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use clap::{Parser, Subcommand, ValueEnum};
use rime_core::Network;
use rime_lightclient::{
    rpc::{CompactOrchardAction, CompactSaplingOutput, GrpcRpcClient, RpcConfig},
    RpcClient,
};
use rime_pir::{PirDatabase, PirRecord};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{
    net::TcpListener,
    sync::{Mutex, RwLock},
};
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(author, version, about = "RIME PIR server", long_about = None)]
struct Args {
    /// address to listen on when serving queries
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: SocketAddr,

    /// path to the serialized pir database file
    #[arg(long, short = 'd')]
    database: PathBuf,

    /// maximum accepted query size in bytes (bits.len() == buckets)
    #[arg(long, default_value_t = 1_000_000)]
    max_query_size: usize,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// build a pir database from a lightwalletd endpoint
    Build {
        #[arg(long)]
        lightwalletd: String,
        #[arg(long)]
        start: u32,
        #[arg(long)]
        end: u32,
        #[arg(long, default_value_t = 1000)]
        bucket_size: usize,
        #[arg(long, value_enum, default_value = "mainnet")]
        network: NetworkArg,
    },
    /// run the pir server
    Serve,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum NetworkArg {
    Mainnet,
    Testnet,
}

impl From<NetworkArg> for Network {
    fn from(value: NetworkArg) -> Self {
        match value {
            NetworkArg::Mainnet => Network::Mainnet,
            NetworkArg::Testnet => Network::Testnet,
        }
    }
}

#[derive(Clone)]
struct ServerConfig {
    listen_addr: SocketAddr,
    bucket_size: usize,
    max_query_size_bytes: usize,
}

struct PirServerState {
    database: Arc<RwLock<PirDatabase>>,
    config: ServerConfig,
    stats: Arc<Mutex<ServerStats>>,
}

struct ServerStats {
    queries_received: u64,
    bytes_sent: u64,
    start_time: Instant,
}

impl ServerStats {
    fn new() -> Self {
        Self {
            queries_received: 0,
            bytes_sent: 0,
            start_time: Instant::now(),
        }
    }

    fn record(&mut self, bytes: usize) {
        self.queries_received = self.queries_received.saturating_add(1);
        self.bytes_sent = self.bytes_sent.saturating_add(bytes as u64);
    }

    fn snapshot(&self) -> ServerStatsResponse {
        ServerStatsResponse {
            queries_received: self.queries_received,
            bytes_sent: self.bytes_sent,
            uptime_secs: self.start_time.elapsed().as_secs(),
        }
    }
}

#[derive(Serialize)]
struct ServerStatsResponse {
    queries_received: u64,
    bytes_sent: u64,
    uptime_secs: u64,
}

#[derive(Deserialize, Serialize, Debug)]
struct PirQueryRequest {
    bits: Vec<bool>,
}

#[derive(Serialize, Deserialize, Debug)]
struct PirQueryResponse {
    data: Vec<u8>,
}

#[derive(Debug, Error)]
enum ServerError {
    #[error("pir error: {0}")]
    Pir(#[from] rime_pir::Error),
    #[error("rpc error: {0}")]
    Rpc(#[from] Box<rime_lightclient::rpc::RpcError>),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("http error: {0}")]
    Http(#[from] hyper::Error),
    #[error("invalid block range: start {start} > end {end}")]
    InvalidRange { start: u32, end: u32 },
}

impl From<rime_lightclient::rpc::RpcError> for ServerError {
    fn from(err: rime_lightclient::rpc::RpcError) -> Self {
        ServerError::Rpc(Box::new(err))
    }
}

#[tokio::main]
async fn main() -> Result<(), ServerError> {
    tracing_subscriber::fmt::init();
    let Args {
        listen,
        database,
        max_query_size,
        command,
    } = Args::parse();

    match command {
        Some(Command::Build {
            lightwalletd,
            start,
            end,
            bucket_size,
            network,
        }) => {
            info!(start, end, bucket_size, "Building PIR database");
            let db =
                build_database_from_chain(&lightwalletd, network.into(), start, end, bucket_size)
                    .await?;
            db.save_to_file(&database)?;
            info!(path = %database.display(), buckets = db.num_buckets(), records = db.total_records(), "Database saved");
            Ok(())
        }
        Some(Command::Serve) | None => serve(listen, database, max_query_size).await,
    }
}

async fn serve(
    listen: SocketAddr,
    database: PathBuf,
    max_query_size: usize,
) -> Result<(), ServerError> {
    info!(path = %database.display(), "Loading PIR database");
    let db = PirDatabase::load_from_file(&database)?;
    let bucket_size = db.bucket_size();
    let config = ServerConfig {
        listen_addr: listen,
        bucket_size,
        max_query_size_bytes: max_query_size,
    };
    let state = Arc::new(PirServerState {
        database: Arc::new(RwLock::new(db)),
        config: config.clone(),
        stats: Arc::new(Mutex::new(ServerStats::new())),
    });
    let app = app_router(state.clone());
    let listener = TcpListener::bind(listen).await?;
    info!(
        addr = %config.listen_addr,
        bucket_size = config.bucket_size,
        "PIR server listening"
    );
    axum::serve(listener, app).await?;
    Ok(())
}

fn app_router(state: Arc<PirServerState>) -> Router {
    Router::new()
        .route("/query", post(handle_query))
        .route("/stats", get(handle_stats))
        .route("/health", get(handle_health))
        .with_state(state)
}

async fn handle_query(
    State(state): State<Arc<PirServerState>>,
    Json(query): Json<PirQueryRequest>,
) -> Result<Json<PirQueryResponse>, StatusCode> {
    let max_bits = state.config.max_query_size_bytes.saturating_mul(8);
    if query.bits.len() > max_bits {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }
    let response = {
        let db = state.database.read().await;
        if query.bits.len() != db.num_buckets() {
            return Err(StatusCode::BAD_REQUEST);
        }
        db.process_query_bits(&query.bits)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    };
    {
        let mut stats = state.stats.lock().await;
        stats.record(response.len());
    }
    Ok(Json(PirQueryResponse { data: response }))
}

async fn handle_stats(State(state): State<Arc<PirServerState>>) -> Json<ServerStatsResponse> {
    let stats = state.stats.lock().await;
    Json(stats.snapshot())
}

async fn handle_health() -> &'static str {
    "OK"
}

async fn build_database_from_chain(
    endpoint: &str,
    network: Network,
    start: u32,
    end: u32,
    bucket_size: usize,
) -> Result<PirDatabase, ServerError> {
    if end < start {
        return Err(ServerError::InvalidRange { start, end });
    }
    let config = RpcConfig {
        endpoint: endpoint.to_string(),
        timeout: Duration::from_secs(15),
        max_retries: 5,
        network,
        tor_client: None,
    };
    let client = GrpcRpcClient::connect(config).await?;
    let mut records = Vec::new();
    for height in start..=end {
        let block = client.get_block(height).await?;
        for tx in block.vtx {
            let txid: [u8; 32] = match tx.hash.as_slice().try_into() {
                Ok(id) => id,
                Err(_) => {
                    warn!(height, "Skipping tx with invalid hash length");
                    continue;
                }
            };
            for (idx, output) in tx.outputs.iter().enumerate() {
                records.push(serialize_compact_output(height, &txid, idx as u32, output));
            }
            for (idx, action) in tx.actions.iter().enumerate() {
                records.push(serialize_compact_action(height, &txid, idx as u32, action));
            }
        }
    }
    Ok(PirDatabase::from_records(records, bucket_size)?)
}

const RECORD_SIZE: usize = 256;
const POOL_SAPLING: u8 = 1;
const POOL_ORCHARD: u8 = 2;
const CMU_LEN: usize = 32;
const EPK_LEN: usize = 32;
const ENC_LEN: usize = 52;
const NULLIFIER_LEN: usize = 32;
const ORCHARD_CMX_LEN: usize = 32;

fn serialize_compact_output(
    height: u32,
    txid: &[u8; 32],
    output_idx: u32,
    output: &CompactSaplingOutput,
) -> PirRecord {
    let mut record = Vec::with_capacity(RECORD_SIZE);
    record.extend_from_slice(&height.to_le_bytes());
    record.push(POOL_SAPLING);
    record.extend_from_slice(txid);
    record.extend_from_slice(&output_idx.to_le_bytes());
    append_fixed(&mut record, &output.cmu, CMU_LEN);
    append_fixed(&mut record, &output.ephemeral_key, EPK_LEN);
    let enc_slice = if output.ciphertext.len() >= ENC_LEN {
        &output.ciphertext[..ENC_LEN]
    } else {
        &output.ciphertext
    };
    record.extend_from_slice(enc_slice);
    if enc_slice.len() < ENC_LEN {
        record.resize(record.len() + (ENC_LEN - enc_slice.len()), 0);
    }
    record.resize(RECORD_SIZE, 0);
    record
}

fn serialize_compact_action(
    height: u32,
    txid: &[u8; 32],
    action_idx: u32,
    action: &CompactOrchardAction,
) -> PirRecord {
    let mut record = Vec::with_capacity(RECORD_SIZE);
    record.extend_from_slice(&height.to_le_bytes());
    record.push(POOL_ORCHARD);
    record.extend_from_slice(txid);
    record.extend_from_slice(&action_idx.to_le_bytes());
    append_fixed(&mut record, &action.nullifier, NULLIFIER_LEN);
    append_fixed(&mut record, &action.cmx, ORCHARD_CMX_LEN);
    append_fixed(&mut record, &action.ephemeral_key, EPK_LEN);
    let enc_slice = if action.ciphertext.len() >= ENC_LEN {
        &action.ciphertext[..ENC_LEN]
    } else {
        &action.ciphertext
    };
    record.extend_from_slice(enc_slice);
    if enc_slice.len() < ENC_LEN {
        record.resize(record.len() + (ENC_LEN - enc_slice.len()), 0);
    }
    record.resize(RECORD_SIZE, 0);
    record
}

fn append_fixed(dst: &mut Vec<u8>, src: &[u8], len: usize) {
    if src.len() >= len {
        dst.extend_from_slice(&src[..len]);
    } else {
        dst.extend_from_slice(src);
        dst.resize(dst.len() + (len - src.len()), 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use tower::ServiceExt;

    fn small_database() -> PirDatabase {
        let mut records = Vec::new();
        for idx in 0..20 {
            let mut record = vec![0u8; 64];
            record[0] = idx as u8;
            records.push(record);
        }
        PirDatabase::from_records(records, 5).expect("db")
    }

    #[tokio::test]
    async fn test_server_query_handling() {
        let db = small_database();
        let num_buckets = db.num_buckets();
        let bucket_size = db.bucket_size();
        let state = Arc::new(PirServerState {
            database: Arc::new(RwLock::new(db)),
            config: ServerConfig {
                listen_addr: "127.0.0.1:0".parse().unwrap(),
                bucket_size,
                max_query_size_bytes: 1024,
            },
            stats: Arc::new(Mutex::new(ServerStats::new())),
        });
        let app = app_router(state);
        let bits = vec![false; num_buckets];
        let request = PirQueryRequest { bits };
        let body = serde_json::to_vec(&request).unwrap();
        let response = app
            .oneshot(
                Request::post("/query")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let payload = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let reply: PirQueryResponse = serde_json::from_slice(&payload).unwrap();
        assert_eq!(reply.data.len(), bucket_size * 64);
    }
}
