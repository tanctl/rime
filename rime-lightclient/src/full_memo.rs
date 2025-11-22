use std::{
    collections::{HashMap, HashSet},
    ops::Range,
};

use crate::rpc::{CompactOrchardAction, CompactSaplingOutput};
use rime_core::privacy::FullMemoConfig;

pub fn estimate_full_memo_bandwidth(range: Range<u32>) -> f64 {
    let blocks = range.end.saturating_sub(range.start) as f64;
    let avg_shielded_txs = 1.5_f64;
    let avg_outputs = 2.0_f64;
    let bytes_per_output = 600_f64;
    let estimated_bytes = blocks * avg_shielded_txs * avg_outputs * bytes_per_output;
    estimated_bytes / 1_000_000_f64
}

#[derive(Default, Debug, Clone, Copy)]
pub struct SyncStats {
    pub blocks_scanned: u32,
    pub transactions_fetched: u32,
    pub memos_cached: u32,
    pub memos_retrieved: u32,
    pub bytes_downloaded: u64,
    pub notes_found: u32,
}

pub struct FullMemoSyncer {
    pub config: FullMemoConfig,
    map: MemoCacheStore,
    fetched: HashSet<[u8; 32]>,
    pub stats: SyncStats,
}

impl FullMemoSyncer {
    pub fn new(config: FullMemoConfig) -> Self {
        Self {
            config,
            map: MemoCacheStore::new(),
            fetched: HashSet::new(),
            stats: SyncStats::default(),
        }
    }

    pub fn reset(&mut self) {
        self.map = MemoCacheStore::new();
        self.fetched.clear();
        self.stats = SyncStats::default();
    }

    pub fn mark_fetched(&mut self, txid: [u8; 32]) -> bool {
        self.fetched.insert(txid)
    }

    pub fn cache_sapling(&mut self, txid: [u8; 32], index: u32, ciphertext: Vec<u8>) {
        self.stats.memos_cached = self.stats.memos_cached.saturating_add(1);
        self.map.insert(
            MemoKey::sapling(txid, index),
            MemoPayload::Sapling { ciphertext },
        );
    }

    pub fn hydrate_sapling_output(
        &self,
        txid: &[u8; 32],
        index: u32,
        output: &mut CompactSaplingOutput,
    ) {
        if let Some(entry) = self
            .map
            .get(&MemoKey::sapling(*txid, index))
            .and_then(|payload| match payload {
                MemoPayload::Sapling { ciphertext } => Some(ciphertext),
                _ => None,
            })
        {
            output.ciphertext = entry.clone();
        }
    }

    pub fn cache_orchard(&mut self, txid: [u8; 32], index: u32, entry: OrchardMemoEntry) {
        self.stats.memos_cached = self.stats.memos_cached.saturating_add(1);
        self.map.insert(
            MemoKey::orchard(txid, index),
            MemoPayload::Orchard(Box::new(entry)),
        );
    }

    pub fn orchard_entry(&self, txid: &[u8; 32], index: u32) -> Option<&OrchardMemoEntry> {
        self.map
            .get(&MemoKey::orchard(*txid, index))
            .and_then(|payload| match payload {
                MemoPayload::Orchard(entry) => Some(entry.as_ref()),
                _ => None,
            })
    }

    pub fn hydrate_orchard_action(
        &self,
        txid: &[u8; 32],
        index: u32,
        action: &mut CompactOrchardAction,
    ) {
        if let Some(entry) = self.orchard_entry(txid, index) {
            action.ciphertext = entry.ciphertext.to_vec();
        }
    }

    pub fn record_memo_hit(&mut self) {
        self.stats.memos_retrieved = self.stats.memos_retrieved.saturating_add(1);
    }
}

#[derive(Clone)]
pub struct OrchardMemoEntry {
    pub nullifier: [u8; 32],
    pub rk: [u8; 32],
    pub cmx: [u8; 32],
    pub cv_net: [u8; 32],
    pub epk_bytes: [u8; 32],
    pub ciphertext: [u8; 580],
    pub out_ciphertext: [u8; 80],
}

#[derive(Hash, PartialEq, Eq)]
struct MemoKey {
    pool: MemoPool,
    txid: [u8; 32],
    index: u32,
}

impl MemoKey {
    fn sapling(txid: [u8; 32], index: u32) -> Self {
        Self {
            pool: MemoPool::Sapling,
            txid,
            index,
        }
    }

    fn orchard(txid: [u8; 32], index: u32) -> Self {
        Self {
            pool: MemoPool::Orchard,
            txid,
            index,
        }
    }
}

#[derive(Hash, PartialEq, Eq)]
enum MemoPool {
    Sapling,
    Orchard,
}

enum MemoPayload {
    Sapling { ciphertext: Vec<u8> },
    Orchard(Box<OrchardMemoEntry>),
}

struct MemoCacheStore {
    map: HashMap<MemoKey, MemoPayload>,
}

impl MemoCacheStore {
    fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    fn insert(&mut self, key: MemoKey, payload: MemoPayload) {
        self.map.insert(key, payload);
    }

    fn get(&self, key: &MemoKey) -> Option<&MemoPayload> {
        self.map.get(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::CompactSaplingOutput;
    use zcash_note_encryption::ENC_CIPHERTEXT_SIZE;

    #[test]
    fn mark_fetched_only_once() {
        let mut fm = FullMemoSyncer::new(FullMemoConfig {
            require_confirmation: false,
        });
        assert!(fm.mark_fetched([1u8; 32]));
        assert!(!fm.mark_fetched([1u8; 32]));
    }

    #[test]
    fn sapling_hydration_overwrites_ciphertext() {
        let mut fm = FullMemoSyncer::new(FullMemoConfig {
            require_confirmation: false,
        });
        let txid = [2u8; 32];
        let ciphertext = vec![0xAB; ENC_CIPHERTEXT_SIZE];
        fm.cache_sapling(txid, 0, ciphertext.clone());
        let mut output = CompactSaplingOutput {
            cmu: vec![],
            ephemeral_key: vec![],
            ciphertext: vec![0u8; 52],
        };
        fm.hydrate_sapling_output(&txid, 0, &mut output);
        assert_eq!(output.ciphertext, ciphertext);
    }

    #[test]
    fn bandwidth_estimation_matches_expectation() {
        let estimate_mb = estimate_full_memo_bandwidth(0..10_000);
        let expected_bytes = 10_000f64 * 1.5 * 2.0 * 600f64;
        let expected_mb = expected_bytes / 1_000_000f64;
        assert!((estimate_mb - expected_mb).abs() < 1e-6);
    }
}
