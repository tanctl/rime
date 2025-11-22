//! Two-server XOR-PIR primitives used for privacy-preserving note downloads.
//! The implementation groups fixed-size records into buckets and issues constant-size bit-vector queries to a pair of non-colluding servers. Each server receives a random share of the desired bucket index; XORing their responses reveals the requested bucket while hiding the selection as long as the servers do not collude. Bucketing shrinks the query vector at the cost of larger responses, creating a tunable tradeoff between bandwidth and privacy. (References: Chor et al., Private Information Retrieval (JACM 1998); Goldberg, Improving the Robustness of Private Information Retrieval (Oakland 2007)).

use std::{
    collections::VecDeque,
    fs::File,
    io::{BufReader, BufWriter},
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex as StdMutex,
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use bitvec::{order::Lsb0, slice::BitSlice, vec::BitVec};
use rand::{rngs::StdRng, Rng, SeedableRng};
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{
    sync::{oneshot, Mutex as AsyncMutex},
    time::{self, MissedTickBehavior},
};

/// alias for a fixed-size pir record (typically a compact output encoding)
pub type PirRecord = Vec<u8>;

/// a pir bucket containing fixed-size records
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PirBucket {
    /// fixed-size records stored in this bucket
    pub records: Vec<PirRecord>,
}

impl PirBucket {
    pub fn new(records: Vec<PirRecord>) -> Self {
        Self { records }
    }

    pub fn record_size(&self) -> Option<usize> {
        self.records.first().map(|r| r.len())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PirDatabase {
    pub buckets: Vec<PirBucket>,
    pub bucket_size: usize,
    pub total_records: usize,
    record_size: usize,
}

impl PirDatabase {
    pub fn from_records(records: Vec<PirRecord>, bucket_size: usize) -> Result<Self, Error> {
        if bucket_size == 0 {
            return Err(Error::InvalidBucketSize);
        }
        let total_records = records.len();
        let record_size = records.first().map(|r| r.len()).unwrap_or(0);
        if total_records > 0 && record_size == 0 {
            return Err(Error::InvalidRecordLength);
        }
        for record in &records {
            if record.len() != record_size {
                return Err(Error::InvalidRecordLength);
            }
        }
        let mut padded = records;
        if record_size > 0 {
            let remainder = padded.len() % bucket_size;
            if remainder != 0 {
                let missing = bucket_size - remainder;
                padded.extend((0..missing).map(|_| vec![0u8; record_size]));
            }
        }
        let mut buckets = Vec::new();
        for chunk in padded.chunks(bucket_size) {
            buckets.push(PirBucket::new(chunk.to_vec()));
        }
        Ok(Self {
            buckets,
            bucket_size,
            total_records,
            record_size,
        })
    }

    pub fn record_size(&self) -> usize {
        self.record_size
    }

    pub fn num_buckets(&self) -> usize {
        self.buckets.len()
    }

    pub fn bucket(&self, index: usize) -> Option<&PirBucket> {
        self.buckets.get(index)
    }

    pub fn bucket_size(&self) -> usize {
        self.bucket_size
    }

    pub fn total_records(&self) -> usize {
        self.total_records
    }

    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), Error> {
        let file = File::create(path)?;
        let writer = BufWriter::new(file);
        bincode::serialize_into(writer, self)?;
        Ok(())
    }

    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let db = bincode::deserialize_from(reader)?;
        Ok(db)
    }

    pub fn process_query_bits(&self, bits: &[bool]) -> Result<Vec<u8>, Error> {
        if self.record_size == 0 {
            return Ok(Vec::new());
        }
        if bits.len() != self.num_buckets() {
            return Err(Error::LengthMismatch);
        }
        let mut result = vec![0u8; self.bucket_size * self.record_size];
        for (bucket_idx, bucket) in self.buckets.iter().enumerate() {
            let include = bits[bucket_idx];
            let mask = 0u8.wrapping_sub(include as u8);
            for (record_idx, record) in bucket.records.iter().enumerate() {
                for (byte_idx, &byte) in record.iter().enumerate() {
                    let offset = record_idx * self.record_size + byte_idx;
                    result[offset] ^= byte & mask;
                }
            }
        }
        Ok(result)
    }
}

type PirBits = BitVec<u8, Lsb0>;
type PirBitSlice = BitSlice<u8, Lsb0>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PirQuery {
    bits: PirBits,
}

impl PirQuery {
    /// generate a random bit-vector of the requested length
    pub fn random(length: usize, rng: &mut impl Rng) -> Self {
        let mut bits = PirBits::with_capacity(length);
        for _ in 0..length {
            bits.push(rng.gen());
        }
        Self { bits }
    }

    /// xor this query with a unit vector at 'index' (flips the bit in-place)
    pub fn xor_unit_vector(&self, index: usize) -> Self {
        let mut result = self.bits.clone();
        if index >= result.len() {
            panic!("unit vector index out of range");
        }
        let current = result[index];
        result.set(index, !current);
        Self { bits: result }
    }

    /// serialize the query bit-vector for transmission
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bits.as_raw_slice().to_vec()
    }

    /// length of the bit-vector
    pub fn len(&self) -> usize {
        self.bits.len()
    }

    /// returns true when there are no bits
    pub fn is_empty(&self) -> bool {
        self.bits.is_empty()
    }

    /// return a view into the underlying bits
    pub fn bits(&self) -> &PirBitSlice {
        &self.bits
    }

    pub fn xor(&self, other: &Self) -> Result<Self, Error> {
        if self.bits.len() != other.bits.len() {
            return Err(Error::LengthMismatch);
        }
        let mut result = PirBits::with_capacity(self.bits.len());
        for idx in 0..self.bits.len() {
            result.push(self.bits[idx] ^ other.bits[idx]);
        }
        Ok(Self { bits: result })
    }

    pub fn is_unit_vector_at(&self, index: usize) -> bool {
        if index >= self.bits.len() || !self.bits[index] {
            return false;
        }
        self.bits.count_ones() == 1
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PirResponse {
    pub data: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("need at least 2 servers for xor-pir")]
    InsufficientServers,
    #[error("response length mismatch")]
    LengthMismatch,
    #[error("server error: {0}")]
    Server(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("invalid bucket index: {0}")]
    InvalidIndex(usize),
    #[error("bucket size must be greater than zero")]
    InvalidBucketSize,
    #[error("records must have uniform non-zero length")]
    InvalidRecordLength,
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] bincode::Error),
    #[error("scheduler channel closed")]
    ChannelClosed,
}

pub type PirServerHandle = Arc<dyn PirServerInterface>;

pub struct PirClient {
    servers: Vec<PirServerHandle>,
    bucket_size: usize,
    num_buckets: usize,
    record_size: usize,
}

impl PirClient {
    /// create a new pir client backed by at least two servers
    pub fn new(
        servers: Vec<PirServerHandle>,
        bucket_size: usize,
        num_buckets: usize,
        record_size: usize,
    ) -> Result<Self, Error> {
        if servers.len() < 2 {
            return Err(Error::InsufficientServers);
        }
        if bucket_size == 0 || num_buckets == 0 {
            return Err(Error::InvalidBucketSize);
        }
        if record_size == 0 {
            return Err(Error::InvalidRecordLength);
        }
        Ok(Self {
            servers,
            bucket_size,
            num_buckets,
            record_size,
        })
    }

    /// number of configured servers
    pub fn server_count(&self) -> usize {
        self.servers.len()
    }

    /// fetch a bucket obliviously using xor-pir
    pub async fn fetch_bucket(&self, bucket_index: usize) -> Result<PirBucket, Error> {
        if bucket_index >= self.num_buckets {
            return Err(Error::InvalidIndex(bucket_index));
        }
        let mut rng = StdRng::from_entropy();
        let q1 = PirQuery::random(self.num_buckets, &mut rng);
        let q2 = q1.xor_unit_vector(bucket_index);
        let server_a = self.servers[0].clone();
        let server_b = self.servers[1].clone();
        let (r1, r2) = tokio::join!(server_a.query(&q1), server_b.query(&q2));
        let bucket_bytes = xor_bytes(&r1?.data, &r2?.data)?;
        self.deserialize_bucket(bucket_bytes)
    }

    fn deserialize_bucket(&self, data: Vec<u8>) -> Result<PirBucket, Error> {
        let expected = self.bucket_size * self.record_size;
        if data.len() != expected {
            return Err(Error::LengthMismatch);
        }
        let mut records = Vec::with_capacity(self.bucket_size);
        for chunk in data.chunks(self.record_size) {
            records.push(chunk.to_vec());
        }
        Ok(PirBucket::new(records))
    }

    pub fn bucket_size(&self) -> usize {
        self.bucket_size
    }

    pub fn record_size(&self) -> usize {
        self.record_size
    }
}

pub struct PirScheduler {
    pir_client: Arc<PirClient>,
    work_queue: Arc<AsyncMutex<VecDeque<WorkItem>>>,
    dummy_interval: Duration,
    num_buckets: AtomicUsize,
    stats: Arc<AsyncMutex<SchedulerStats>>,
    shutdown: Arc<AtomicBool>,
}

struct WorkItem {
    bucket_index: usize,
    item_type: WorkItemType,
    result_tx: Option<oneshot::Sender<PirBucket>>,
}

enum WorkItemType {
    Real,
    Dummy,
}

#[derive(Default, Clone, Debug)]
pub struct SchedulerStats {
    pub real_queries: u64,
    pub dummy_queries: u64,
    pub total_queries: u64,
    pub bytes_downloaded: u64,
}

impl PirScheduler {
    pub fn new(pir_client: Arc<PirClient>, dummy_interval: Duration, num_buckets: usize) -> Self {
        Self {
            pir_client,
            work_queue: Arc::new(AsyncMutex::new(VecDeque::new())),
            dummy_interval,
            num_buckets: AtomicUsize::new(num_buckets.max(1)),
            stats: Arc::new(AsyncMutex::new(SchedulerStats::default())),
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    pub async fn request_bucket(&self, bucket_index: usize) -> oneshot::Receiver<PirBucket> {
        let (tx, rx) = oneshot::channel();
        self.ensure_capacity(bucket_index);
        let work_item = WorkItem {
            bucket_index,
            item_type: WorkItemType::Real,
            result_tx: Some(tx),
        };
        let mut queue = self.work_queue.lock().await;
        queue.push_back(work_item);
        rx
    }

    pub async fn run(self: Arc<Self>) {
        let period = if self.dummy_interval.is_zero() {
            Duration::from_secs(1)
        } else {
            self.dummy_interval
        };
        let mut interval = time::interval(period);
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        while !self.shutdown.load(Ordering::Relaxed) {
            interval.tick().await;
            if self.shutdown.load(Ordering::Relaxed) {
                break;
            }
            let work_item = self.get_next_work_item().await;
            if let Err(err) = self.execute_work_item(work_item).await {
                tracing::error!("PIR query failed: {err}");
            }
        }
    }

    async fn get_next_work_item(&self) -> WorkItem {
        let mut queue = self.work_queue.lock().await;
        if let Some(item) = queue.pop_front() {
            return item;
        }
        drop(queue);
        let limit = self.num_buckets.load(Ordering::Relaxed).max(1);
        let mut rng = rand::thread_rng();
        let bucket_index = rng.gen_range(0..limit);
        WorkItem {
            bucket_index,
            item_type: WorkItemType::Dummy,
            result_tx: None,
        }
    }

    async fn execute_work_item(&self, work_item: WorkItem) -> Result<(), Error> {
        let start = Instant::now();
        let bucket = self.pir_client.fetch_bucket(work_item.bucket_index).await?;
        let elapsed = start.elapsed();
        {
            let mut stats = self.stats.lock().await;
            match work_item.item_type {
                WorkItemType::Real => {
                    stats.real_queries = stats.real_queries.saturating_add(1);
                    tracing::debug!(
                        bucket = work_item.bucket_index,
                        elapsed = elapsed.as_secs_f64(),
                        "Real PIR query completed"
                    );
                }
                WorkItemType::Dummy => {
                    stats.dummy_queries = stats.dummy_queries.saturating_add(1);
                    tracing::debug!(
                        bucket = work_item.bucket_index,
                        elapsed = elapsed.as_secs_f64(),
                        "Dummy PIR query completed"
                    );
                }
            }
            stats.total_queries = stats.total_queries.saturating_add(1);
            stats.bytes_downloaded = stats
                .bytes_downloaded
                .saturating_add((bucket.records.len() * self.pir_client.record_size()) as u64);
        }
        if let Some(tx) = work_item.result_tx {
            let _ = tx.send(bucket);
        }
        Ok(())
    }

    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }

    pub async fn get_stats(&self) -> SchedulerStats {
        self.stats.lock().await.clone()
    }

    pub fn estimate_bandwidth_per_hour(&self) -> f64 {
        let queries_per_hour = 3600.0 / self.dummy_interval.as_secs_f64().max(1.0);
        let bytes_per_query =
            (self.pir_client.bucket_size() * self.pir_client.record_size()) as f64;
        let bytes_per_hour = queries_per_hour * bytes_per_query;
        bytes_per_hour / (1024.0 * 1024.0)
    }

    fn ensure_capacity(&self, bucket_index: usize) {
        loop {
            let current = self.num_buckets.load(Ordering::Relaxed);
            if bucket_index < current {
                break;
            }
            if self
                .num_buckets
                .compare_exchange(
                    current,
                    bucket_index + 1,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                break;
            }
        }
    }

    pub fn update_bucket_count(&self, buckets: usize) {
        self.num_buckets.store(buckets.max(1), Ordering::Relaxed);
    }

    pub fn num_buckets(&self) -> usize {
        self.num_buckets.load(Ordering::Relaxed)
    }
}

/// xor helper for two byte slices
pub fn xor_bytes(a: &[u8], b: &[u8]) -> Result<Vec<u8>, Error> {
    if a.len() != b.len() {
        return Err(Error::LengthMismatch);
    }
    Ok(a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect())
}

/// trait representing a pir server endpoint
#[async_trait]
pub trait PirServerInterface: Send + Sync {
    async fn query(&self, query: &PirQuery) -> Result<PirResponse, Error>;
}

/// network-backed pir server using http posts
#[derive(Clone)]
pub struct PirServer {
    url: String,
    client: HttpClient,
}

impl PirServer {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            client: HttpClient::new(),
        }
    }

    pub fn with_reqwest(url: impl Into<String>, client: HttpClient) -> Self {
        Self {
            url: url.into(),
            client,
        }
    }

    fn endpoint(&self) -> String {
        format!("{}/query", self.url.trim_end_matches('/'))
    }
}

#[async_trait]
impl PirServerInterface for PirServer {
    async fn query(&self, query: &PirQuery) -> Result<PirResponse, Error> {
        let response = self
            .client
            .post(self.endpoint())
            .body(query.to_bytes())
            .send()
            .await
            .map_err(|e| Error::Network(e.to_string()))?;
        if !response.status().is_success() {
            return Err(Error::Server(response.status().to_string()));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|e| Error::Network(e.to_string()))?;
        Ok(PirResponse {
            data: bytes.to_vec(),
        })
    }
}

/// in-memory mock pir server for deterministic tests
pub struct MockPirServer {
    database: Arc<StdMutex<PirDatabase>>,
    last_query: StdMutex<Option<PirQuery>>,
}

impl MockPirServer {
    pub fn new(database: Arc<StdMutex<PirDatabase>>) -> Self {
        Self {
            database,
            last_query: StdMutex::new(None),
        }
    }

    pub fn last_query(&self) -> Option<PirQuery> {
        match self.last_query.lock() {
            Ok(guard) => guard.clone(),
            Err(_) => None,
        }
    }

    fn process_query_constant_time(&self, query: &PirQuery) -> Vec<u8> {
        let db = self.database.lock().expect("db lock poisoned");
        let selectors: Vec<bool> = query.bits().iter().map(|bit| *bit).collect();
        db.process_query_bits(&selectors).unwrap_or_default()
    }
}

#[async_trait]
impl PirServerInterface for MockPirServer {
    async fn query(&self, query: &PirQuery) -> Result<PirResponse, Error> {
        if let Ok(mut slot) = self.last_query.lock() {
            *slot = Some(query.clone());
        }
        let data = self.process_query_constant_time(query);
        Ok(PirResponse { data })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::{sleep, timeout};

    fn create_test_database(
        num_buckets: usize,
        bucket_size: usize,
        record_size: usize,
    ) -> Arc<StdMutex<PirDatabase>> {
        let mut records = Vec::with_capacity(num_buckets * bucket_size);
        for idx in 0..(num_buckets * bucket_size) {
            let mut record = vec![0u8; record_size];
            for (byte_idx, byte) in record.iter_mut().enumerate() {
                *byte = ((idx + byte_idx) % 251) as u8;
            }
            records.push(record);
        }
        Arc::new(StdMutex::new(
            PirDatabase::from_records(records, bucket_size).expect("db builds"),
        ))
    }

    fn setup_client(
        num_buckets: usize,
        bucket_size: usize,
        record_size: usize,
    ) -> (
        PirClient,
        Arc<MockPirServer>,
        Arc<MockPirServer>,
        Arc<StdMutex<PirDatabase>>,
    ) {
        let db = create_test_database(num_buckets, bucket_size, record_size);
        let server_a = Arc::new(MockPirServer::new(db.clone()));
        let server_b = Arc::new(MockPirServer::new(db.clone()));
        let client = PirClient::new(
            vec![
                server_a.clone() as PirServerHandle,
                server_b.clone() as PirServerHandle,
            ],
            bucket_size,
            num_buckets,
            record_size,
        )
        .expect("client");
        (client, server_a, server_b, db)
    }

    #[tokio::test]
    async fn test_xor_pir_correctness() {
        let (client, _, _, db) = setup_client(10, 5, 8);
        let bucket = client.fetch_bucket(3).await.expect("bucket fetched");
        let guard = db.lock().unwrap();
        assert_eq!(bucket.records, guard.buckets[3].records);
    }

    #[tokio::test]
    async fn test_xor_pir_privacy() {
        let (client, server_a, server_b, _) = setup_client(10, 5, 8);
        client.fetch_bucket(7).await.expect("bucket fetched");
        let q1 = server_a.last_query().expect("query recorded");
        let q2 = server_b.last_query().expect("query recorded");
        assert_ne!(q1, q2);
        let xor = q1.xor(&q2).expect("xor");
        assert!(xor.is_unit_vector_at(7));
    }

    #[tokio::test]
    async fn scheduler_constant_rate_queries() {
        let (client, _, _, _) = setup_client(10, 5, 8);
        let scheduler = Arc::new(PirScheduler::new(
            Arc::new(client),
            Duration::from_millis(50),
            10,
        ));
        let runner = scheduler.clone();
        let handle = tokio::spawn(async move {
            runner.run().await;
        });
        sleep(Duration::from_millis(260)).await;
        scheduler.shutdown();
        handle.abort();
        let stats = scheduler.get_stats().await;
        assert!(stats.total_queries >= 4);
    }

    #[tokio::test]
    async fn scheduler_mixes_real_and_dummy_queries() {
        let (client, _, _, _) = setup_client(12, 4, 8);
        let scheduler = Arc::new(PirScheduler::new(
            Arc::new(client),
            Duration::from_millis(30),
            12,
        ));
        let runner = scheduler.clone();
        tokio::spawn(async move {
            runner.run().await;
        });
        let rx1 = scheduler.request_bucket(2).await;
        let rx2 = scheduler.request_bucket(3).await;
        timeout(Duration::from_secs(1), async {
            let _ = rx1.await;
            let _ = rx2.await;
        })
        .await
        .expect("real queries resolved");
        sleep(Duration::from_millis(120)).await;
        scheduler.shutdown();
        let stats = scheduler.get_stats().await;
        assert!(stats.real_queries >= 2);
        assert!(stats.dummy_queries > 0);
    }
}
