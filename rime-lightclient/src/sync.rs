use std::{convert::TryFrom, io::Cursor, sync::Arc};

use crate::full_memo::{FullMemoSyncer, OrchardMemoEntry, SyncStats};
use crate::rpc::{CompactBlock, CompactOrchardAction, CompactSaplingOutput, TreeState};
use crate::source::{NoteSource, SourceError};
use equihash::is_valid_solution;
use ff::PrimeField;
use num_bigint::BigUint;
use num_traits::Zero;
use orchard::{
    keys::{
        IncomingViewingKey as OrchardIncomingViewingKey,
        PreparedIncomingViewingKey as OrchardPreparedIncomingViewingKey, Scope as OrchardScope,
    },
    note::{
        ExtractedNoteCommitment as OrchardExtractedNoteCommitment, Note as OrchardNote,
        Nullifier as OrchardNullifier, TransmittedNoteCiphertext,
    },
    note_encryption::{CompactAction as OrchardCompactAction, OrchardDomain},
    primitives::redpallas,
    tree::MerkleHashOrchard,
    value::ValueCommitment as OrchardValueCommitment,
    Action as OrchardAction, Address as OrchardAddress,
    NOTE_COMMITMENT_TREE_DEPTH as ORCHARD_NOTE_DEPTH,
};
use rime_core::{
    notes::Pool,
    tree::{NoteCommitmentTree, OrchardNoteCommitmentTree},
    IncomingViewingKey, Network, Note, NoteId, PrivacyConfig, SyncMode, Wallet, WalletStore,
};
use sapling::{
    keys::PreparedIncomingViewingKey,
    note::{ExtractedNoteCommitment, Rseed},
    note_encryption::{
        try_sapling_compact_note_decryption, try_sapling_note_decryption, CompactOutputDescription,
        SaplingDomain, Zip212Enforcement,
    },
    PaymentAddress,
};
use thiserror::Error;
use tracing::warn;
use zcash_client_backend::proto::service as backend_service;
use zcash_note_encryption::{
    try_compact_note_decryption, try_note_decryption, EphemeralKeyBytes, ShieldedOutput,
    COMPACT_NOTE_SIZE, ENC_CIPHERTEXT_SIZE,
};
use zcash_primitives::{
    block::BlockHeader,
    consensus::{BlockHeight as ZBlockHeight, BranchId, MainNetwork, TestNetwork},
    merkle_tree::read_commitment_tree,
    transaction::{Transaction, TxId},
};
use zcash_protocol::consensus::Parameters as _;

pub struct TrialDecryptor {
    sapling: Option<SaplingDecryptor>,
    orchard: Option<OrchardDecryptor>,
}

struct SaplingDecryptor {
    ivk: PreparedIncomingViewingKey,
}

struct OrchardDecryptor {
    ivk: OrchardPreparedIncomingViewingKey,
}

pub struct SaplingDecryption {
    pub note: sapling::note::Note,
    pub address: PaymentAddress,
    pub cmu: [u8; 32],
    pub memo: Option<Vec<u8>>,
}

pub struct OrchardDecryption {
    pub note: OrchardNote,
    pub address: OrchardAddress,
    pub cmx: [u8; 32],
    pub memo: Option<Vec<u8>>,
}

pub struct DecryptedNote {
    pub pool: Pool,
    pub commitment: [u8; 32],
    pub nullifier: [u8; 32],
    pub value: u64,
    pub memo: Option<Vec<u8>>,
    pub height: u32,
    pub address_bytes: [u8; 43],
    pub address: String,
    pub rseed: [u8; 32],
    pub zip212: bool,
    pub position: u64,
    pub witness: Vec<u8>,
    pub txid: Option<TxId>,
    pub output_index: u32,
}

impl DecryptedNote {
    fn into_note(self, id: NoteId) -> Note {
        Note {
            id,
            pool: self.pool,
            value: self.value,
            commitment: self.commitment,
            nullifier: self.nullifier,
            address: self.address,
            address_bytes: self.address_bytes,
            rseed: self.rseed,
            zip212: self.zip212,
            height: self.height,
            spent: false,
            memo: self.memo,
            witness: self.witness,
            position: self.position,
        }
    }
}

impl TrialDecryptor {
    pub fn new(
        sapling_ivk: Option<IncomingViewingKey>,
        orchard_ivk: Option<OrchardIncomingViewingKey>,
    ) -> Self {
        let sapling = sapling_ivk.map(|ivk| SaplingDecryptor {
            ivk: ivk.inner().prepare(),
        });
        let orchard = orchard_ivk.map(|ivk| OrchardDecryptor { ivk: ivk.prepare() });
        Self { sapling, orchard }
    }

    #[allow(clippy::result_large_err)]
    pub fn try_decrypt_sapling_output(
        &self,
        output: &CompactSaplingOutput,
        enforcement: Zip212Enforcement,
    ) -> Result<Option<SaplingDecryption>, SyncError> {
        let Some(ctx) = &self.sapling else {
            return Ok(None);
        };
        let cmu_bytes: [u8; 32] = output
            .cmu
            .as_slice()
            .try_into()
            .map_err(|_| SyncError::Chain("cmu length mismatch".into()))?;
        let epk_bytes: [u8; 32] = output
            .ephemeral_key
            .as_slice()
            .try_into()
            .map_err(|_| SyncError::Chain("ephemeral key length mismatch".into()))?;
        let mut ciphertext = [0u8; COMPACT_NOTE_SIZE];
        if output.ciphertext.len() == COMPACT_NOTE_SIZE {
            ciphertext.copy_from_slice(&output.ciphertext[..]);
        } else if output.ciphertext.len() == ENC_CIPHERTEXT_SIZE {
            ciphertext.copy_from_slice(&output.ciphertext[..COMPACT_NOTE_SIZE]);
        } else {
            return Err(SyncError::Chain("ciphertext length mismatch".into()));
        }

        let cmu = ExtractedNoteCommitment::from_bytes(&cmu_bytes)
            .into_option()
            .ok_or_else(|| SyncError::Chain("invalid cmu".into()))?;
        let compact = CompactOutputDescription {
            ephemeral_key: EphemeralKeyBytes(epk_bytes),
            cmu,
            enc_ciphertext: ciphertext,
        };

        let decrypted = try_sapling_compact_note_decryption(&ctx.ivk, &compact, enforcement).map(
            |(note, address)| SaplingDecryption {
                note,
                address,
                cmu: cmu_bytes,
                memo: None,
            },
        );

        if decomposable_full_ciphertext(&output.ciphertext) {
            let full = FullOutput {
                cmu,
                ciphertext: output.ciphertext.clone(),
                epk: EphemeralKeyBytes(epk_bytes),
            };
            if let Some((note, address, memo)) =
                try_sapling_note_decryption(&ctx.ivk, &full, enforcement)
            {
                return Ok(Some(SaplingDecryption {
                    note,
                    address,
                    cmu: cmu_bytes,
                    memo: Some(memo.to_vec()),
                }));
            }
        }

        Ok(decrypted)
    }

    #[allow(clippy::result_large_err)]
    pub fn try_decrypt_orchard_action(
        &self,
        action: &CompactOrchardAction,
        memo_entry: Option<&OrchardMemoEntry>,
    ) -> Result<Option<OrchardDecryption>, SyncError> {
        let Some(ctx) = &self.orchard else {
            return Ok(None);
        };

        let nullifier_bytes: [u8; 32] = action
            .nullifier
            .as_slice()
            .try_into()
            .map_err(|_| SyncError::Chain("orchard nullifier length mismatch".into()))?;
        let cmx_bytes: [u8; 32] = action
            .cmx
            .as_slice()
            .try_into()
            .map_err(|_| SyncError::Chain("orchard cmx length mismatch".into()))?;
        let epk_bytes: [u8; 32] = action
            .ephemeral_key
            .as_slice()
            .try_into()
            .map_err(|_| SyncError::Chain("orchard epk length mismatch".into()))?;
        if action.ciphertext.len() < COMPACT_NOTE_SIZE {
            return Err(SyncError::Chain(
                "orchard ciphertext length mismatch".into(),
            ));
        }
        let mut ciphertext = [0u8; COMPACT_NOTE_SIZE];
        ciphertext.copy_from_slice(&action.ciphertext[..COMPACT_NOTE_SIZE]);

        let nullifier = OrchardNullifier::from_bytes(&nullifier_bytes)
            .into_option()
            .ok_or_else(|| SyncError::Chain("invalid orchard nullifier encoding".into()))?;
        let cmx = OrchardExtractedNoteCommitment::from_bytes(&cmx_bytes)
            .into_option()
            .ok_or_else(|| SyncError::Chain("invalid orchard commitment encoding".into()))?;
        let compact = OrchardCompactAction::from_parts(
            nullifier,
            cmx,
            EphemeralKeyBytes(epk_bytes),
            ciphertext,
        );
        let domain = OrchardDomain::for_compact_action(&compact);
        let result =
            try_compact_note_decryption(&domain, &ctx.ivk, &compact).map(|(note, address)| {
                OrchardDecryption {
                    note,
                    address,
                    cmx: cmx_bytes,
                    memo: None,
                }
            });
        if let Some(mut decrypted) = result {
            if let Some(entry) = memo_entry {
                if let Some(memo) = recover_orchard_memo(&ctx.ivk, entry)? {
                    decrypted.memo = Some(memo);
                }
            }
            Ok(Some(decrypted))
        } else {
            Ok(None)
        }
    }
}

struct FullOutput {
    cmu: ExtractedNoteCommitment,
    ciphertext: Vec<u8>,
    epk: EphemeralKeyBytes,
}

impl ShieldedOutput<SaplingDomain, ENC_CIPHERTEXT_SIZE> for FullOutput {
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        self.epk.clone()
    }

    fn cmstar_bytes(&self) -> [u8; 32] {
        self.cmu.to_bytes()
    }

    fn enc_ciphertext(&self) -> &[u8; ENC_CIPHERTEXT_SIZE] {
        self.ciphertext
            .as_slice()
            .try_into()
            .expect("checked length")
    }
}

fn decomposable_full_ciphertext(cipher: &[u8]) -> bool {
    cipher.len() == ENC_CIPHERTEXT_SIZE
}

#[derive(Debug, Error)]
pub enum SyncError {
    #[error("source: {0}")]
    Source(#[from] SourceError),
    #[error("chain: {0}")]
    Chain(String),
    #[error("wallet: {0}")]
    Wallet(#[from] zcash_client_sqlite::error::SqliteClientError),
    #[error("tree state: {0}")]
    Tree(String),
    #[error("storage: {0}")]
    Storage(#[from] rime_core::Error),
}

type ProgressCallback = Arc<dyn Fn(SyncProgress) + Send + Sync>;

pub struct WalletSyncer {
    wallet: Wallet,
    source: Arc<dyn NoteSource>,
    store: WalletStore,
    decryptor: TrialDecryptor,
    batch_size: u32,
    progress: Option<ProgressCallback>,
    verify_tree_roots: bool,
    verify_headers: bool,
    privacy: PrivacyConfig,
    full_memo: Option<FullMemoSyncer>,
}

impl WalletSyncer {
    pub fn new(
        wallet: Wallet,
        source: Arc<dyn NoteSource>,
        store: WalletStore,
        privacy: PrivacyConfig,
    ) -> Self {
        let orchard_ivk = wallet
            .unified_fvk
            .as_ref()
            .and_then(|ufvk| ufvk.orchard.as_ref())
            .map(|fvk| fvk.to_ivk(OrchardScope::External));
        let decryptor = TrialDecryptor::new(Some(wallet.ivk.clone()), orchard_ivk);
        let full_memo = match privacy.sync_mode {
            SyncMode::FullMemo => privacy.full_memo.clone().map(FullMemoSyncer::new),
            _ => None,
        };
        Self {
            wallet,
            source,
            store,
            decryptor,
            batch_size: 100,
            progress: None,
            verify_tree_roots: true,
            verify_headers: true,
            privacy,
            full_memo,
        }
    }

    pub fn with_batch_size(mut self, size: u32) -> Self {
        self.batch_size = size.max(1);
        self
    }

    pub fn with_progress_callback(mut self, cb: ProgressCallback) -> Self {
        self.progress = Some(cb);
        self
    }

    pub fn with_tree_verification(mut self, enabled: bool) -> Self {
        self.verify_tree_roots = enabled;
        self
    }

    pub fn with_header_validation(mut self, enabled: bool) -> Self {
        self.verify_headers = enabled;
        self
    }

    fn full_memo_enabled(&self) -> bool {
        matches!(self.privacy.sync_mode, SyncMode::FullMemo)
    }

    pub fn full_memo_stats(&self) -> Option<&SyncStats> {
        self.full_memo.as_ref().map(|fm| &fm.stats)
    }

    fn record_memo_hit(&mut self, present: bool) {
        if present {
            if let Some(fm) = self.full_memo.as_mut() {
                fm.record_memo_hit();
            }
        }
    }

    async fn fetch_block_batch(
        &self,
        start: u32,
        end_inclusive: u32,
    ) -> Result<Vec<CompactBlock>, SourceError> {
        if start > end_inclusive {
            return Ok(Vec::new());
        }
        let exclusive = end_inclusive.saturating_add(1);
        let mut blocks = self.source.fetch_compact_blocks(start..exclusive).await?;
        if exclusive == end_inclusive {
            // overflow occurred; fetch the last block separately if it exists
            blocks.push(self.source.fetch_block(end_inclusive).await?);
        }
        Ok(blocks)
    }

    async fn populate_full_memo_for_tx(
        &mut self,
        block_height: u32,
        tx: &crate::rpc::CompactTx,
    ) -> Result<(), SyncError> {
        let Some(fm) = self.full_memo.as_mut() else {
            return Ok(());
        };
        if tx.outputs.is_empty() && tx.actions.is_empty() {
            return Ok(());
        }
        let txid = match txid_from_slice(&tx.hash) {
            Ok(id) => id,
            Err(_) => return Ok(()),
        };
        if !fm.mark_fetched(txid) {
            return Ok(());
        }
        let raw = self
            .source
            .fetch_transaction(TxId::from_bytes(txid))
            .await?;
        fm.stats.transactions_fetched = fm.stats.transactions_fetched.saturating_add(1);
        fm.stats.bytes_downloaded = fm
            .stats
            .bytes_downloaded
            .saturating_add(raw.data.len() as u64);
        let branch = branch_id_for_height(self.wallet.metadata.network, block_height)?;
        let transaction = parse_transaction(&raw.data, branch)?;
        let sapling_len = transaction
            .sapling_bundle()
            .map(|b| b.shielded_outputs().len())
            .unwrap_or(0);
        cache_sapling_outputs(fm, txid, &transaction);
        cache_orchard_actions(fm, txid, &transaction);
        tracing::debug!(
            height = block_height,
            outputs = sapling_len,
            actions = transaction
                .orchard_bundle()
                .map(|b| b.actions().len())
                .unwrap_or(0),
            tx = %hex::encode(txid),
            "Fetched transaction for full-memo caching"
        );
        Ok(())
    }

    #[allow(clippy::result_large_err)]
    pub async fn sync_wallet(
        &mut self,
        sapling_tree: &mut NoteCommitmentTree,
        orchard_tree: &mut OrchardNoteCommitmentTree,
    ) -> Result<SyncResult, SyncError> {
        'resync: loop {
            let latest = self.source.latest_height().await?;
            let mut sapling_checkpoint_height =
                self.wallet.metadata.birthday_height.saturating_sub(1);
            if let Some(cp) = self.store.load_latest_checkpoint(Pool::Sapling)? {
                sapling_checkpoint_height = cp.height;
                *sapling_tree = NoteCommitmentTree::restore(&cp)?;
                self.wallet.metadata.last_synced_height =
                    self.wallet.metadata.last_synced_height.max(cp.height);
            }
            let mut orchard_checkpoint_height =
                self.wallet.metadata.birthday_height.saturating_sub(1);
            if let Some(cp) = self.store.load_latest_checkpoint(Pool::Orchard)? {
                orchard_checkpoint_height = cp.height;
                *orchard_tree = OrchardNoteCommitmentTree::restore(&cp)?;
                self.wallet.metadata.last_synced_height =
                    self.wallet.metadata.last_synced_height.max(cp.height);
            }
            let sapling_replay_start = sapling_checkpoint_height.saturating_add(1);
            let orchard_replay_start = orchard_checkpoint_height.saturating_add(1);
            if self
                .replay_existing_history(
                    sapling_tree,
                    orchard_tree,
                    sapling_replay_start,
                    orchard_replay_start,
                    self.wallet.metadata.last_synced_height,
                )
                .await?
            {
                continue 'resync;
            }
            let mut cursor = self.wallet.metadata.last_synced_height;
            if cursor <= self.wallet.metadata.birthday_height {
                cursor = self.wallet.metadata.birthday_height;
            } else {
                cursor = cursor.saturating_add(1);
            }

            if cursor > latest {
                return Ok(SyncResult::idle(cursor));
            }

            if self.full_memo_enabled() {
                tracing::info!(
                    start = cursor,
                    end = latest,
                    "Full-memo mode: downloading all memos for blocks {}-{}",
                    cursor,
                    latest
                );
            }

            let mut prev_block_hash = if cursor > 0 {
                Some(self.source.fetch_block(cursor - 1).await?.hash)
            } else {
                None
            };
            let mut last_scanned_hash: Option<Vec<u8>> = None;
            let mut last_sapling_root: Option<[u8; 32]> = None;

            let mut summary = SyncResult {
                blocks_processed: 0,
                notes_found_sapling: 0,
                notes_found_orchard: 0,
                start_height: cursor,
                end_height: cursor,
            };

            while cursor <= latest {
                let end = cursor
                    .saturating_add(self.batch_size)
                    .saturating_sub(1)
                    .min(latest);
                let blocks = self.fetch_block_batch(cursor, end).await?;
                if blocks.is_empty() {
                    cursor = end.saturating_add(1);
                    continue;
                }
                for mut block in blocks {
                    let block_height = block.height as u32;
                    if self.full_memo_enabled() {
                        for tx in &block.vtx {
                            self.populate_full_memo_for_tx(block_height, tx).await?;
                        }
                        if let Some(fm) = self.full_memo.as_ref() {
                            for tx in &mut block.vtx {
                                if let Ok(txid) = txid_from_slice(&tx.hash) {
                                    for (idx, output) in tx.outputs.iter_mut().enumerate() {
                                        fm.hydrate_sapling_output(&txid, idx as u32, output);
                                    }
                                    for (idx, action) in tx.actions.iter_mut().enumerate() {
                                        fm.hydrate_orchard_action(&txid, idx as u32, action);
                                    }
                                }
                            }
                        }
                    }
                    let header = if self.verify_headers {
                        if block.header.is_empty() {
                            warn!(
                                height = block.height,
                                "missing compact block header; skipping header validation"
                            );
                            None
                        } else {
                            Some(validate_block_header(&block)?)
                        }
                    } else {
                        None
                    };
                    let block_hash = block.hash.clone();
                    if let Some(expected_prev_hash) = &prev_block_hash {
                        if block.prev_hash != *expected_prev_hash {
                            self.handle_reorg(block_height, sapling_tree, orchard_tree)?;
                            continue 'resync;
                        }
                    }
                    if let Some(stored) = self.store.load_block_hash(block_height)? {
                        if stored != block_hash {
                            self.handle_reorg(block_height, sapling_tree, orchard_tree)?;
                            continue 'resync;
                        }
                    }
                    self.store.save_block_hash(block_height, &block_hash)?;
                    prev_block_hash = Some(block_hash.clone());

                    summary.blocks_processed += 1;
                    let sapling_zip212 =
                        zip212_enforcement(self.wallet.metadata.network, block_height);
                    self.scan_block(
                        sapling_tree,
                        orchard_tree,
                        &block,
                        block_height,
                        &mut summary,
                        sapling_zip212,
                    )?;
                    #[allow(clippy::manual_is_multiple_of)]
                    if block_height % 1000 == 0 {
                        if sapling_tree.size() > 0 {
                            let checkpoint =
                                sapling_tree.checkpoint(Pool::Sapling, block_height)?;
                            self.store.save_tree_checkpoint(&checkpoint)?;
                        }
                        if orchard_tree.size() > 0 {
                            let checkpoint = orchard_tree.checkpoint(block_height)?;
                            self.store.save_tree_checkpoint(&checkpoint)?;
                        }
                        if self.verify_tree_roots {
                            if let Some(h) = header.as_ref() {
                                self.verify_tree_state(
                                    block_height,
                                    &block_hash,
                                    sapling_tree,
                                    orchard_tree,
                                    &h.final_sapling_root,
                                )
                                .await?;
                            }
                        }
                    }
                    summary.end_height = block_height;
                    last_scanned_hash = Some(block_hash.clone());
                    if let Some(h) = header {
                        last_sapling_root = Some(h.final_sapling_root);
                    }
                    if let Some(cb) = &self.progress {
                        cb(SyncProgress {
                            start_height: summary.start_height,
                            current_height: summary.end_height,
                            target_height: latest,
                            blocks_processed: summary.blocks_processed,
                            notes_found_sapling: summary.notes_found_sapling,
                            notes_found_orchard: summary.notes_found_orchard,
                        });
                    }
                    if let Some(fm) = self.full_memo.as_mut() {
                        fm.stats.blocks_scanned = fm.stats.blocks_scanned.saturating_add(1);
                    }
                }
                cursor = end.saturating_add(1);
            }

            if summary.blocks_processed > 0 && self.verify_tree_roots {
                if let (Some(hash), Some(root)) = (&last_scanned_hash, &last_sapling_root) {
                    self.verify_tree_state(
                        summary.end_height,
                        hash,
                        sapling_tree,
                        orchard_tree,
                        root,
                    )
                    .await?;
                }
            }

            self.wallet.metadata.last_synced_height = summary.end_height;
            self.store
                .update_last_synced_height(self.wallet.metadata.last_synced_height)?;
            if self.full_memo_enabled() {
                if let Some(stats) = self.full_memo_stats() {
                    tracing::info!(
                        blocks = stats.blocks_scanned,
                        transactions = stats.transactions_fetched,
                        memos = stats.memos_cached,
                        bytes = stats.bytes_downloaded,
                        "Full-memo sync complete"
                    );
                }
            }
            return Ok(summary);
        }
    }

    async fn replay_existing_history(
        &mut self,
        sapling_tree: &mut NoteCommitmentTree,
        orchard_tree: &mut OrchardNoteCommitmentTree,
        sapling_start: u32,
        orchard_start: u32,
        target: u32,
    ) -> Result<bool, SyncError> {
        let need_sapling = sapling_start <= target;
        let need_orchard = orchard_start <= target;
        if !need_sapling && !need_orchard {
            return Ok(false);
        }
        let mut cursor = match (need_sapling, need_orchard) {
            (true, true) => sapling_start.min(orchard_start),
            (true, false) => sapling_start,
            (false, true) => orchard_start,
            (false, false) => unreachable!(),
        };
        while cursor <= target {
            let end = cursor
                .saturating_add(self.batch_size)
                .saturating_sub(1)
                .min(target);
            let blocks = self.fetch_block_batch(cursor, end).await?;
            if blocks.is_empty() {
                cursor = end.saturating_add(1);
                continue;
            }
            for block in blocks {
                let block_hash = block.hash.clone();
                let block_height = block.height as u32;
                if let Some(stored) = self.store.load_block_hash(block_height)? {
                    if stored != block_hash {
                        self.handle_reorg(block_height, sapling_tree, orchard_tree)?;
                        return Ok(true);
                    }
                }
                self.store.save_block_hash(block_height, &block_hash)?;
                if need_sapling && block_height >= sapling_start {
                    self.append_sapling_commitments_only(sapling_tree, &block)?;
                }
                if need_orchard && block_height >= orchard_start {
                    self.append_orchard_commitments_only(orchard_tree, &block)?;
                }
            }
            cursor = end.saturating_add(1);
        }
        Ok(false)
    }

    #[allow(clippy::result_large_err)]
    fn scan_block(
        &mut self,
        sapling_tree: &mut NoteCommitmentTree,
        orchard_tree: &mut OrchardNoteCommitmentTree,
        block: &CompactBlock,
        block_height: u32,
        summary: &mut SyncResult,
        enforcement: Zip212Enforcement,
    ) -> Result<(), SyncError> {
        for tx in &block.vtx {
            let txid = match txid_from_slice(&tx.hash) {
                Ok(id) => id,
                Err(_) => continue,
            };
            for (output_index, output) in tx.outputs.iter().enumerate() {
                let cmu_bytes: [u8; 32] = output
                    .cmu
                    .as_slice()
                    .try_into()
                    .map_err(|_| SyncError::Tree("invalid commitment length".into()))?;
                let position = sapling_tree.append(cmu_bytes)?;
                if let Some(found) = self
                    .decryptor
                    .try_decrypt_sapling_output(output, enforcement)?
                {
                    let decrypted = self.build_sapling_note(
                        sapling_tree,
                        block_height,
                        position,
                        found,
                        txid,
                        output_index as u32,
                    )?;
                    self.persist_note(decrypted, summary)?;
                }
            }
            for (action_index, action) in tx.actions.iter().enumerate() {
                let cmx_bytes: [u8; 32] = action
                    .cmx
                    .as_slice()
                    .try_into()
                    .map_err(|_| SyncError::Tree("invalid orchard commitment length".into()))?;
                let position = orchard_tree.append(cmx_bytes)?;
                let memo_entry = self
                    .full_memo
                    .as_ref()
                    .and_then(|fm| fm.orchard_entry(&txid, action_index as u32));
                if let Some(found) = self
                    .decryptor
                    .try_decrypt_orchard_action(action, memo_entry)?
                {
                    let decrypted = self.build_orchard_note(
                        orchard_tree,
                        block_height,
                        position,
                        found,
                        txid,
                        action_index as u32,
                    )?;
                    self.persist_note(decrypted, summary)?;
                }
            }
            for spend in &tx.spends {
                let nf = note_nullifier(&spend.nf)?;
                self.store.mark_note_spent(&nf)?;
            }
            for action in &tx.actions {
                let nf = note_nullifier(&action.nullifier)?;
                self.store.mark_note_spent(&nf)?;
            }
        }
        Ok(())
    }

    #[allow(clippy::result_large_err)]
    fn append_sapling_commitments_only(
        &self,
        sapling_tree: &mut NoteCommitmentTree,
        block: &CompactBlock,
    ) -> Result<(), SyncError> {
        for tx in &block.vtx {
            for output in &tx.outputs {
                let cmu_bytes: [u8; 32] = output
                    .cmu
                    .as_slice()
                    .try_into()
                    .map_err(|_| SyncError::Tree("invalid commitment length".into()))?;
                sapling_tree.append(cmu_bytes)?;
            }
        }
        Ok(())
    }

    #[allow(clippy::result_large_err)]
    fn append_orchard_commitments_only(
        &self,
        orchard_tree: &mut OrchardNoteCommitmentTree,
        block: &CompactBlock,
    ) -> Result<(), SyncError> {
        for tx in &block.vtx {
            for action in &tx.actions {
                let cmx_bytes: [u8; 32] = action
                    .cmx
                    .as_slice()
                    .try_into()
                    .map_err(|_| SyncError::Tree("invalid orchard commitment length".into()))?;
                orchard_tree.append(cmx_bytes)?;
            }
        }
        Ok(())
    }

    #[allow(clippy::result_large_err)]
    fn handle_reorg(
        &mut self,
        height: u32,
        sapling_tree: &mut NoteCommitmentTree,
        orchard_tree: &mut OrchardNoteCommitmentTree,
    ) -> Result<(), SyncError> {
        warn!(
            height,
            "chain reorg detected; resetting wallet state to birthday"
        );
        self.store
            .reset_state_to_birthday(self.wallet.metadata.birthday_height)?;
        *sapling_tree = NoteCommitmentTree::new();
        *orchard_tree = OrchardNoteCommitmentTree::new();
        self.wallet.metadata.last_synced_height =
            self.wallet.metadata.birthday_height.saturating_sub(1);
        if let Some(fm) = self.full_memo.as_mut() {
            fm.reset();
        }
        Ok(())
    }

    #[allow(clippy::result_large_err)]
    fn build_sapling_note(
        &mut self,
        tree: &mut NoteCommitmentTree,
        block_height: u32,
        position: u64,
        found: SaplingDecryption,
        txid: [u8; 32],
        output_index: u32,
    ) -> Result<DecryptedNote, SyncError> {
        let has_memo = found.memo.is_some();
        self.record_memo_hit(has_memo);
        let witness = tree.witness_for_position(position)?;
        let nk = self.wallet.fvk.as_inner().fvk.vk.nk;
        let nullifier = found.note.nf(&nk, position).0;
        let (zip212, rseed_bytes) = serialize_rseed(found.note.rseed());
        let address_bytes = found.address.to_bytes();
        Ok(DecryptedNote {
            pool: Pool::Sapling,
            commitment: found.cmu,
            nullifier,
            value: found.note.value().inner(),
            memo: found.memo,
            height: block_height,
            address_bytes,
            address: hex::encode(address_bytes),
            rseed: rseed_bytes,
            zip212,
            position,
            witness,
            txid: Some(TxId::from_bytes(txid)),
            output_index,
        })
    }

    #[allow(clippy::result_large_err)]
    fn build_orchard_note(
        &mut self,
        tree: &mut OrchardNoteCommitmentTree,
        block_height: u32,
        position: u64,
        found: OrchardDecryption,
        txid: [u8; 32],
        action_index: u32,
    ) -> Result<DecryptedNote, SyncError> {
        let has_memo = found.memo.is_some();
        self.record_memo_hit(has_memo);
        let witness = tree.witness_for_position(position)?;
        let orchard_fvk = self
            .wallet
            .unified_fvk
            .as_ref()
            .and_then(|ufvk| ufvk.orchard.as_ref())
            .ok_or_else(|| SyncError::Chain("orchard viewing key unavailable".into()))?;
        let nullifier = found.note.nullifier(orchard_fvk).to_bytes();
        let address_bytes = found.address.to_raw_address_bytes();
        Ok(DecryptedNote {
            pool: Pool::Orchard,
            commitment: found.cmx,
            nullifier,
            value: found.note.value().inner(),
            memo: found.memo,
            height: block_height,
            address_bytes,
            address: hex::encode(address_bytes),
            rseed: *found.note.rseed().as_bytes(),
            zip212: true,
            position,
            witness,
            txid: Some(TxId::from_bytes(txid)),
            output_index: action_index,
        })
    }

    #[allow(clippy::result_large_err)]
    fn persist_note(
        &mut self,
        decrypted: DecryptedNote,
        summary: &mut SyncResult,
    ) -> Result<(), SyncError> {
        let note_id = pack_note_id(decrypted.pool, decrypted.height, decrypted.position)?;
        let note = decrypted.into_note(note_id);
        self.store.insert_note(&note)?;
        match note.pool {
            Pool::Sapling => summary.notes_found_sapling += 1,
            Pool::Orchard => summary.notes_found_orchard += 1,
        }
        if let Some(fm) = self.full_memo.as_mut() {
            fm.stats.notes_found = fm.stats.notes_found.saturating_add(1);
        }
        Ok(())
    }

    async fn verify_tree_state(
        &self,
        height: u32,
        expected_block_hash: &[u8],
        sapling_tree: &NoteCommitmentTree,
        orchard_tree: &OrchardNoteCommitmentTree,
        header_sapling_root: &[u8; 32],
    ) -> Result<(), SyncError> {
        if sapling_tree.size() > 0 {
            let local_sapling_root = sapling_tree.root()?;
            if header_sapling_root != &local_sapling_root {
                return Err(SyncError::Tree(format!(
                    "sapling root mismatch at height {}",
                    height
                )));
            }
        }
        // orchard root still comes from server so at least bind it to the validated header hash
        let tree_state = self.source.fetch_tree_state(height).await?;
        if tree_state.height as u32 != height {
            return Err(SyncError::Tree(format!(
                "tree state height mismatch (expected {}, got {})",
                height, tree_state.height
            )));
        }
        let mut remote_hash = hex::decode(&tree_state.hash)
            .map_err(|e| SyncError::Tree(format!("invalid tree state hash: {e}")))?;
        remote_hash.reverse();
        if remote_hash != expected_block_hash {
            return Err(SyncError::Chain(format!(
                "tree state hash mismatch at height {}",
                height
            )));
        }

        let remote_orchard_root = orchard_root_from_tree_state(&tree_state)?;
        match remote_orchard_root {
            Some(remote_root) => {
                if orchard_tree.size() == 0 {
                    return Ok(());
                }
                let local_orchard_root = orchard_tree.root()?;
                if remote_root != local_orchard_root {
                    return Err(SyncError::Tree(format!(
                        "orchard root mismatch at height {}",
                        height
                    )));
                }
            }
            None => {
                if orchard_tree.size() > 0 {
                    return Err(SyncError::Tree(format!(
                        "orchard tree state missing at height {} while local tree is non-empty",
                        height
                    )));
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct SyncResult {
    pub blocks_processed: u32,
    pub notes_found_sapling: u32,
    pub notes_found_orchard: u32,
    pub start_height: u32,
    pub end_height: u32,
}

impl SyncResult {
    fn idle(height: u32) -> Self {
        Self {
            blocks_processed: 0,
            notes_found_sapling: 0,
            notes_found_orchard: 0,
            start_height: height,
            end_height: height,
        }
    }

    pub fn total_notes(&self) -> u32 {
        self.notes_found_sapling + self.notes_found_orchard
    }
}

#[derive(Debug, Clone)]
pub struct SyncProgress {
    pub start_height: u32,
    pub current_height: u32,
    pub target_height: u32,
    pub blocks_processed: u32,
    pub notes_found_sapling: u32,
    pub notes_found_orchard: u32,
}

#[allow(dead_code, clippy::result_large_err)]
fn convert_tree_state(
    tree: &TreeState,
) -> Result<zcash_client_backend::data_api::chain::ChainState, SyncError> {
    let backend = backend_service::TreeState {
        network: tree.network.clone(),
        height: tree.height,
        hash: tree.hash.clone(),
        time: tree.time,
        sapling_tree: tree.sapling_tree.clone(),
        orchard_tree: tree.orchard_tree.clone(),
    };
    backend
        .to_chain_state()
        .map_err(|e| SyncError::Tree(e.to_string()))
}

fn check_pow(header: &BlockHeader) -> Result<(), String> {
    const EQUIHASH_N: u32 = 200;
    const EQUIHASH_K: u32 = 9;

    let target = compact_to_target(header.bits).ok_or_else(|| "invalid target bits".to_string())?;
    let hash_value = BigUint::from_bytes_be(&header.hash().0);
    if hash_value > target {
        return Err("header hash exceeds target".into());
    }

    let mut input = Vec::with_capacity(4 + 32 + 32 + 32 + 4 + 4);
    input.extend_from_slice(&header.version.to_le_bytes());
    input.extend_from_slice(&header.prev_block.0);
    input.extend_from_slice(&header.merkle_root);
    input.extend_from_slice(&header.final_sapling_root);
    input.extend_from_slice(&header.time.to_le_bytes());
    input.extend_from_slice(&header.bits.to_le_bytes());

    is_valid_solution(
        EQUIHASH_N,
        EQUIHASH_K,
        &input,
        &header.nonce,
        &header.solution,
    )
    .map_err(|e| format!("invalid equihash solution: {e}"))?;

    Ok(())
}

fn compact_to_target(bits: u32) -> Option<BigUint> {
    let mantissa = bits & 0x007fffff;
    let exponent = (bits >> 24) as i32;
    if mantissa == 0 || exponent <= 0 {
        return None;
    }
    let mut target = BigUint::from(mantissa);
    if exponent > 3 {
        let shift = ((exponent - 3) * 8) as usize;
        target <<= shift;
    } else {
        let shift = ((3 - exponent) * 8) as usize;
        target >>= shift;
    }
    if target.is_zero() {
        None
    } else {
        Some(target)
    }
}

#[allow(clippy::result_large_err)]
fn orchard_root_from_tree_state(tree: &TreeState) -> Result<Option<[u8; 32]>, SyncError> {
    if tree.orchard_tree.is_empty() {
        return Ok(None);
    }
    let bytes = hex::decode(&tree.orchard_tree)
        .map_err(|e| SyncError::Tree(format!("invalid orchard tree encoding: {e}")))?;
    let commitment_tree =
        read_commitment_tree::<MerkleHashOrchard, _, { ORCHARD_NOTE_DEPTH as u8 }>(Cursor::new(
            &bytes,
        ))
        .map_err(|e| SyncError::Tree(format!("unable to decode orchard tree: {e}")))?;
    Ok(Some(commitment_tree.root().to_bytes()))
}

#[allow(clippy::result_large_err)]
fn validate_block_header(block: &CompactBlock) -> Result<BlockHeader, SyncError> {
    if block.header.is_empty() {
        return Err(SyncError::Chain(format!(
            "missing block header for height {}",
            block.height
        )));
    }
    let mut cursor = Cursor::new(&block.header);
    let header = BlockHeader::read(&mut cursor)
        .map_err(|e| SyncError::Chain(format!("invalid block header: {e}")))?;

    if block.hash.len() != 32 {
        return Err(SyncError::Chain(format!(
            "block hash missing for height {}",
            block.height
        )));
    }
    let mut expected_hash = [0u8; 32];
    expected_hash.copy_from_slice(&block.hash);
    if header.hash().0 != expected_hash {
        return Err(SyncError::Chain(format!(
            "header hash mismatch at height {}",
            block.height
        )));
    }

    if block.height > 0 {
        if block.prev_hash.len() != 32 {
            return Err(SyncError::Chain(format!(
                "previous hash missing at height {}",
                block.height
            )));
        }
        let mut prev = [0u8; 32];
        prev.copy_from_slice(&block.prev_hash);
        if header.prev_block.0 != prev {
            return Err(SyncError::Chain(format!(
                "header prev-hash mismatch at height {}",
                block.height
            )));
        }
    }

    check_pow(&header).map_err(SyncError::Chain)?;

    Ok(header)
}

fn serialize_rseed(rseed: &Rseed) -> (bool, [u8; 32]) {
    match rseed {
        Rseed::AfterZip212(bytes) => (true, *bytes),
        Rseed::BeforeZip212(before) => {
            let mut out = [0u8; 32];
            out.copy_from_slice(before.to_repr().as_ref());
            (false, out)
        }
    }
}

#[allow(clippy::result_large_err)]
fn note_nullifier(bytes: &[u8]) -> Result<[u8; 32], SyncError> {
    if bytes.len() != 32 {
        return Err(SyncError::Chain("nullifier length mismatch".into()));
    }
    let mut nf = [0u8; 32];
    nf.copy_from_slice(&bytes[..32]);
    Ok(nf)
}

#[allow(clippy::result_large_err)]
fn pack_note_id(pool: Pool, height: u32, position: u64) -> Result<NoteId, SyncError> {
    if position > u32::MAX as u64 {
        return Err(SyncError::Tree("note position overflow".into()));
    }
    let pool_bit: u128 = match pool {
        Pool::Sapling => 0,
        Pool::Orchard => 1,
    };
    let packed = ((height as u128) << 33) | (pool_bit << 32) | position as u128;
    if packed > i64::MAX as u128 {
        return Err(SyncError::Tree("note id overflow".into()));
    }
    Ok(NoteId::new(packed as i64))
}

fn zip212_enforcement(network: Network, height: u32) -> Zip212Enforcement {
    use zcash_protocol::consensus::{NetworkUpgrade, MAIN_NETWORK, TEST_NETWORK};

    let activation = match network {
        Network::Mainnet => MAIN_NETWORK
            .activation_height(NetworkUpgrade::Heartwood)
            .map(u32::from)
            .unwrap_or(u32::MAX),
        Network::Testnet => TEST_NETWORK
            .activation_height(NetworkUpgrade::Heartwood)
            .map(u32::from)
            .unwrap_or(u32::MAX),
    };

    if height >= activation {
        Zip212Enforcement::On
    } else {
        Zip212Enforcement::Off
    }
}

fn txid_from_slice(bytes: &[u8]) -> Result<[u8; 32], SyncError> {
    if bytes.len() != 32 {
        return Err(SyncError::Chain("txid length mismatch".into()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(bytes);
    Ok(arr)
}

fn branch_id_for_height(network: Network, height: u32) -> Result<BranchId, SyncError> {
    let branch = match network {
        Network::Mainnet => BranchId::for_height(&MainNetwork, ZBlockHeight::from(height)),
        Network::Testnet => BranchId::for_height(&TestNetwork, ZBlockHeight::from(height)),
    };
    Ok(branch)
}

fn parse_transaction(data: &[u8], branch: BranchId) -> Result<Transaction, SyncError> {
    Transaction::read(Cursor::new(data), branch)
        .map_err(|e| SyncError::Chain(format!("failed to decode transaction: {e}")))
}

fn cache_sapling_outputs(fm: &mut FullMemoSyncer, txid: [u8; 32], tx: &Transaction) {
    if let Some(bundle) = tx.sapling_bundle() {
        for (idx, output) in bundle.shielded_outputs().iter().enumerate() {
            fm.cache_sapling(txid, idx as u32, output.enc_ciphertext().to_vec());
        }
    }
}

fn cache_orchard_actions(fm: &mut FullMemoSyncer, txid: [u8; 32], tx: &Transaction) {
    if let Some(bundle) = tx.orchard_bundle() {
        for (idx, action) in bundle.actions().iter().enumerate() {
            let encrypted = action.encrypted_note();
            let rk_bytes: [u8; 32] = action.rk().into();
            let entry = OrchardMemoEntry {
                nullifier: action.nullifier().to_bytes(),
                rk: rk_bytes,
                cmx: action.cmx().to_bytes(),
                cv_net: action.cv_net().to_bytes(),
                epk_bytes: encrypted.epk_bytes,
                ciphertext: encrypted.enc_ciphertext,
                out_ciphertext: encrypted.out_ciphertext,
            };
            fm.cache_orchard(txid, idx as u32, entry);
        }
    }
}

fn recover_orchard_memo(
    ivk: &OrchardPreparedIncomingViewingKey,
    entry: &OrchardMemoEntry,
) -> Result<Option<Vec<u8>>, SyncError> {
    let nullifier = OrchardNullifier::from_bytes(&entry.nullifier)
        .into_option()
        .ok_or_else(|| SyncError::Chain("invalid orchard nullifier".into()))?;
    let rk = redpallas::VerificationKey::try_from(entry.rk)
        .map_err(|_| SyncError::Chain("invalid orchard rk".into()))?;
    let cmx = OrchardExtractedNoteCommitment::from_bytes(&entry.cmx)
        .into_option()
        .ok_or_else(|| SyncError::Chain("invalid orchard cmx".into()))?;
    let cv_net = OrchardValueCommitment::from_bytes(&entry.cv_net)
        .into_option()
        .ok_or_else(|| SyncError::Chain("invalid orchard cv_net".into()))?;
    let ciphertext = TransmittedNoteCiphertext {
        epk_bytes: entry.epk_bytes,
        enc_ciphertext: entry.ciphertext,
        out_ciphertext: entry.out_ciphertext,
    };
    let action = OrchardAction::from_parts(nullifier, rk, cmx, ciphertext, cv_net, ());
    let domain = OrchardDomain::for_action(&action);
    Ok(try_note_decryption(&domain, ivk, &action).map(|(_, _, memo)| memo.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::{CompactSaplingSpend, CompactTx, RawTransaction, TreeState};
    use crate::source::{MockNoteSource, NoteSource};
    use async_trait::async_trait;
    use ff::PrimeField;
    use jubjub::Fr;
    use rand::{rngs::StdRng, SeedableRng};
    use redjubjub::Signature;
    use rime_core::FullMemoConfig;
    use sapling::bundle::{
        Authorized as SapAuthorized, Bundle, GrothProofBytes, OutputDescription,
    };
    use sapling::note_encryption::Zip212Enforcement;
    use sapling::{
        keys::OutgoingViewingKey,
        note::Rseed,
        note_encryption::{sapling_note_encryption, SaplingDomain},
        value::{NoteValue, ValueCommitTrapdoor},
        PaymentAddress,
    };
    use sapling::{keys::SaplingIvk, value::ValueCommitment};
    use serde_json::Value;
    use std::collections::HashMap;
    use std::ops::Range;
    use std::sync::{
        atomic::{AtomicU32, Ordering},
        Arc, Mutex,
    };
    use zcash_note_encryption::{Domain, EphemeralKeyBytes};
    use zcash_primitives::consensus::BranchId;
    use zcash_primitives::transaction::{TransactionData, TxId, TxVersion};
    use zcash_protocol::consensus::BlockHeight;
    use zcash_protocol::value::ZatBalance;

    fn heartwood_mainnet() -> u32 {
        zcash_protocol::consensus::MAIN_NETWORK
            .activation_height(zcash_protocol::consensus::NetworkUpgrade::Heartwood)
            .map(u32::from)
            .expect("mainnet activation height available")
    }

    struct ReorgNoteSource {
        first: Vec<CompactBlock>,
        second: Vec<CompactBlock>,
        use_second: Mutex<bool>,
        latest: u32,
    }

    impl ReorgNoteSource {
        fn new(first: Vec<CompactBlock>, second: Vec<CompactBlock>) -> Self {
            let latest = first
                .iter()
                .chain(second.iter())
                .map(|block| block.height as u32)
                .max()
                .unwrap_or(0);
            Self {
                first,
                second,
                use_second: Mutex::new(false),
                latest,
            }
        }

        fn dataset(&self, second: bool) -> &Vec<CompactBlock> {
            if second {
                &self.second
            } else {
                &self.first
            }
        }
    }

    #[async_trait]
    impl NoteSource for ReorgNoteSource {
        async fn fetch_compact_blocks(
            &self,
            range: Range<u32>,
        ) -> Result<Vec<CompactBlock>, SourceError> {
            if range.is_empty() {
                return Ok(Vec::new());
            }
            let mut flag = self.use_second.lock().unwrap();
            let data = self.dataset(*flag);
            let blocks = data
                .iter()
                .filter(|block| {
                    let h = block.height as u32;
                    h >= range.start && h < range.end
                })
                .cloned()
                .collect::<Vec<_>>();
            if !*flag {
                *flag = true;
            }
            Ok(blocks)
        }

        async fn fetch_block(&self, height: u32) -> Result<CompactBlock, SourceError> {
            let flag = self.use_second.lock().unwrap();
            self.dataset(*flag)
                .iter()
                .find(|block| block.height as u32 == height)
                .cloned()
                .ok_or_else(|| SourceError::NotFound(format!("block height {height} missing")))
        }

        async fn fetch_tree_state(&self, height: u32) -> Result<TreeState, SourceError> {
            Ok(TreeState {
                height: height as u64,
                ..TreeState::default()
            })
        }

        async fn fetch_transaction(&self, _txid: TxId) -> Result<RawTransaction, SourceError> {
            Err(SourceError::NotFound(
                "mock source has no transactions".into(),
            ))
        }

        async fn latest_height(&self) -> Result<u32, SourceError> {
            Ok(self.latest)
        }
    }
    fn sample_phrase() -> &'static str {
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
    }

    fn sample_wallet() -> Wallet {
        use rime_core::{keys::KeyManager, Network};
        let km =
            KeyManager::from_mnemonic_with_network(sample_phrase(), "", Network::Mainnet).unwrap();
        let sk = km.sapling_spending_key().unwrap();
        Wallet::new(
            rime_core::WalletMetadata {
                network: Network::Mainnet,
                birthday_height: 0,
                last_synced_height: 0,
                unified_fvk: None,
            },
            sk.to_full_viewing_key(),
            km.ivk().unwrap(),
            None,
        )
    }

    fn sample_wallet_at(height: u32) -> Wallet {
        let mut wallet = sample_wallet();
        wallet.metadata.birthday_height = height;
        wallet.metadata.last_synced_height = height.saturating_sub(1);
        wallet
    }

    fn synthetic_hash(seed: u64) -> Vec<u8> {
        let mut out = [0u8; 32];
        for (i, chunk) in out.chunks_mut(8).enumerate() {
            let value = seed.wrapping_add(i as u64);
            chunk.copy_from_slice(&value.to_le_bytes());
        }
        out.to_vec()
    }

    fn block_hash(height: u32) -> Vec<u8> {
        synthetic_hash(0xB000_0000_0000_0000u64 | height as u64)
    }

    fn tx_hash(height: u32, index: u32) -> Vec<u8> {
        let seed = ((height as u64) << 32) | index as u64;
        synthetic_hash(0x7000_0000_0000_0000u64 | seed)
    }

    fn dummy_block(height: u32) -> CompactBlock {
        let prev = if height == 0 {
            vec![0u8; 32]
        } else {
            block_hash(height.saturating_sub(1))
        };
        CompactBlock {
            proto_version: 0,
            height: height as u64,
            hash: block_hash(height),
            prev_hash: prev,
            time: 0,
            header: Vec::new(),
            vtx: Vec::new(),
            chain_metadata: None,
        }
    }

    fn build_compact_output(pa: &PaymentAddress) -> CompactSaplingOutput {
        let mut rng = StdRng::seed_from_u64(42);
        let value = NoteValue::from_raw(5);
        let note = pa.create_note(value, Rseed::AfterZip212([7u8; 32]));
        let cmu = note.cmu();
        let enc = sapling_note_encryption(
            Some(OutgoingViewingKey([0; 32])),
            note,
            [0u8; 512],
            &mut rng,
        );
        let enc_cipher = enc.encrypt_note_plaintext();
        let mut compact_cipher = [0u8; COMPACT_NOTE_SIZE];
        compact_cipher.copy_from_slice(&enc_cipher[..COMPACT_NOTE_SIZE]);
        let epk_bytes = SaplingDomain::epk_bytes(enc.epk());
        let compact = CompactOutputDescription {
            ephemeral_key: epk_bytes,
            cmu,
            enc_ciphertext: compact_cipher,
        };

        CompactSaplingOutput {
            cmu: compact.cmu.to_bytes().to_vec(),
            ephemeral_key: compact.ephemeral_key.as_ref().to_vec(),
            ciphertext: compact.enc_ciphertext.to_vec(),
        }
    }

    fn build_full_output(pa: &PaymentAddress, memo: [u8; 512]) -> CompactSaplingOutput {
        let mut rng = StdRng::seed_from_u64(99);
        let value = NoteValue::from_raw(7);
        let note = pa.create_note(value, Rseed::AfterZip212([9u8; 32]));
        let cmu = note.cmu();
        let enc = sapling_note_encryption(Some(OutgoingViewingKey([0; 32])), note, memo, &mut rng);
        let enc_cipher = enc.encrypt_note_plaintext();
        let epk_bytes = SaplingDomain::epk_bytes(enc.epk());
        CompactSaplingOutput {
            cmu: cmu.to_bytes().to_vec(),
            ephemeral_key: epk_bytes.as_ref().to_vec(),
            ciphertext: enc_cipher.to_vec(),
        }
    }

    #[tokio::test]
    async fn trial_decryption_round_trip() {
        let wallet = sample_wallet_at(heartwood_mainnet());
        let pa = wallet.default_address().unwrap();
        let output = build_compact_output(&pa);
        let decryptor = TrialDecryptor::new(Some(wallet.ivk.clone()), None);
        let found = decryptor
            .try_decrypt_sapling_output(&output, Zip212Enforcement::On)
            .unwrap();
        assert!(found.is_some());
    }

    #[tokio::test]
    async fn trial_decryption_recovers_memo_with_full_ciphertext() {
        let wallet = sample_wallet_at(heartwood_mainnet());
        let pa = wallet.default_address().unwrap();
        let memo_bytes = [0x42u8; 512];
        let output = build_full_output(&pa, memo_bytes);
        let decryptor = TrialDecryptor::new(Some(wallet.ivk.clone()), None);
        let found = decryptor
            .try_decrypt_sapling_output(&output, Zip212Enforcement::On)
            .unwrap()
            .expect("decrypted");
        let memo = found.memo.expect("memo");
        assert_eq!(memo, memo_bytes.to_vec());
    }

    fn memo_bytes(text: &str) -> [u8; 512] {
        let mut buf = [0u8; 512];
        let bytes = text.as_bytes();
        let len = bytes.len().min(512);
        buf[..len].copy_from_slice(&bytes[..len]);
        buf
    }

    fn sapling_output_entry(
        addr: &PaymentAddress,
        memo: [u8; 512],
        seed: u64,
    ) -> (CompactSaplingOutput, OutputDescription<GrothProofBytes>) {
        let mut rng = StdRng::seed_from_u64(seed);
        let value = NoteValue::from_raw(5 + seed);
        let note = addr.create_note(value, Rseed::AfterZip212([seed as u8; 32]));
        let cmu = note.cmu();
        let encryptor =
            sapling_note_encryption(Some(OutgoingViewingKey([0; 32])), note, memo, &mut rng);
        let enc_cipher = encryptor.encrypt_note_plaintext();
        let mut compact_cipher = [0u8; COMPACT_NOTE_SIZE];
        compact_cipher.copy_from_slice(&enc_cipher[..COMPACT_NOTE_SIZE]);
        let epk_bytes = SaplingDomain::epk_bytes(encryptor.epk());
        let rcv = ValueCommitTrapdoor::random(&mut rng);
        let cv = ValueCommitment::derive(value, rcv);
        let mut rng_out = StdRng::seed_from_u64(seed + 100);
        let out_cipher = encryptor.encrypt_outgoing_plaintext(&cv, &cmu, &mut rng_out);
        let compact = CompactSaplingOutput {
            cmu: cmu.to_bytes().to_vec(),
            ephemeral_key: epk_bytes.as_ref().to_vec(),
            ciphertext: compact_cipher.to_vec(),
        };
        let proof: GrothProofBytes = [0u8; 192];
        let full = OutputDescription::from_parts(cv, cmu, epk_bytes, enc_cipher, out_cipher, proof);
        (compact, full)
    }

    fn build_sapling_transaction(
        outputs: &[(PaymentAddress, [u8; 512])],
    ) -> (CompactTx, Vec<u8>, TxId) {
        let mut compact_outputs = Vec::new();
        let mut full_outputs = Vec::new();
        for (idx, (addr, memo)) in outputs.iter().enumerate() {
            let seed = (idx as u64) + 1;
            let (compact, full) = sapling_output_entry(addr, *memo, seed);
            compact_outputs.push(compact);
            full_outputs.push(full);
        }
        let bundle = Bundle::from_parts(
            Vec::new(),
            full_outputs,
            ZatBalance::zero(),
            SapAuthorized {
                binding_sig: Signature::from([0u8; 64]),
            },
        )
        .expect("non-empty bundle");
        let tx_data = TransactionData::from_parts(
            TxVersion::V5,
            BranchId::Nu5,
            0,
            ZBlockHeight::from(0),
            None,
            None,
            Some(bundle),
            None,
        );
        let tx = tx_data.freeze().expect("transaction");
        let mut raw = Vec::new();
        tx.write(&mut raw).expect("serialize transaction");
        let txid = tx.txid();
        let compact_tx = CompactTx {
            index: 0,
            hash: txid.as_ref().to_vec(),
            fee: 0,
            spends: Vec::new(),
            outputs: compact_outputs,
            actions: Vec::new(),
        };
        (compact_tx, raw, txid)
    }

    fn build_counting_source(
        blocks: Vec<CompactBlock>,
        transactions: HashMap<TxId, RawTransaction>,
    ) -> (Arc<dyn NoteSource>, Arc<AtomicU32>) {
        CountingSource::new(blocks, transactions)
    }

    struct CountingSource {
        latest_height: u32,
        blocks: HashMap<u32, CompactBlock>,
        transactions: HashMap<TxId, RawTransaction>,
        fetches: Arc<AtomicU32>,
    }

    impl CountingSource {
        #[allow(clippy::new_ret_no_self)]
        fn new(
            blocks: Vec<CompactBlock>,
            transactions: HashMap<TxId, RawTransaction>,
        ) -> (Arc<dyn NoteSource>, Arc<AtomicU32>) {
            let latest = blocks.iter().map(|b| b.height as u32).max().unwrap_or(0);
            let map = blocks
                .into_iter()
                .map(|b| (b.height as u32, b))
                .collect::<HashMap<_, _>>();
            let counter = Arc::new(AtomicU32::new(0));
            let source = Arc::new(CountingSource {
                latest_height: latest,
                blocks: map,
                transactions,
                fetches: counter.clone(),
            });
            (source, counter)
        }
    }

    #[async_trait]
    impl NoteSource for CountingSource {
        async fn fetch_compact_blocks(
            &self,
            range: Range<u32>,
        ) -> Result<Vec<CompactBlock>, SourceError> {
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
                    proto_version: 0,
                    height: height as u64,
                    ..CompactBlock::default()
                }))
        }

        async fn fetch_tree_state(&self, _height: u32) -> Result<TreeState, SourceError> {
            Err(SourceError::NotFound("tree state unavailable".into()))
        }

        async fn fetch_transaction(&self, txid: TxId) -> Result<RawTransaction, SourceError> {
            self.fetches.fetch_add(1, Ordering::SeqCst);
            self.transactions
                .get(&txid)
                .cloned()
                .ok_or_else(|| SourceError::NotFound("transaction not found".into()))
        }

        async fn latest_height(&self) -> Result<u32, SourceError> {
            Ok(self.latest_height)
        }
    }

    #[tokio::test]
    async fn trial_decryption_computes_nullifier_deterministically() {
        let wallet = sample_wallet_at(heartwood_mainnet());
        let pa = wallet.default_address().unwrap();
        let output = build_compact_output(&pa);
        let decryptor = TrialDecryptor::new(Some(wallet.ivk.clone()), None);
        let found = decryptor
            .try_decrypt_sapling_output(&output, Zip212Enforcement::On)
            .unwrap()
            .expect("decrypted");
        let mut tree = NoteCommitmentTree::new();
        let position = tree
            .append(output.cmu.as_slice().try_into().expect("commitment bytes"))
            .unwrap();
        let store = WalletStore::in_memory().unwrap();
        let source: Arc<dyn NoteSource> = Arc::new(MockNoteSource::new());
        let mut syncer = WalletSyncer::new(wallet, source, store, PrivacyConfig::default());
        let direct_nf = found
            .note
            .nf(&syncer.wallet.fvk.as_inner().fvk.vk.nk, position)
            .0;
        let decrypted = syncer
            .build_sapling_note(&mut tree, 5, position, found, [0u8; 32], 0)
            .expect("build note");
        assert_eq!(decrypted.nullifier, direct_nf);
    }

    #[tokio::test]
    async fn trial_decryption_known_vector() {
        // load first sapling note-encryption vector (ZIP 212 off) from vendored file
        let text = include_str!("../test_vectors/sapling_note_encryption.json");
        let data: Value = serde_json::from_str(text).expect("json");
        let rows = data.as_array().expect("array");
        let header_line = rows[1].as_str().expect("header line");
        let header: Vec<String> = header_line
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();
        assert_eq!(header[0], "ovk");
        let fields: Vec<String> = rows[2]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| match v {
                Value::String(s) => s.clone(),
                Value::Number(n) => n.to_string(),
                _ => panic!("unexpected field type"),
            })
            .collect();
        let get = |name: &str| {
            let idx = header.iter().position(|h| h == name).unwrap();
            hex::decode(&fields[idx]).unwrap()
        };

        let ivk_bytes = get("ivk");
        let cmu_bytes = get("cmu");
        let cv_bytes = get("cv");
        let epk_bytes = get("epk");
        let c_enc = get("c_enc");
        let c_out = get("c_out");
        let memo = get("memo");
        let default_d = get("default_d");
        let default_pk_d = get("default_pk_d");

        let ivk_arr: [u8; 32] = ivk_bytes.as_slice().try_into().unwrap();
        let ivk_scalar = Fr::from_repr(ivk_arr).unwrap();
        let prepared_ivk =
            sapling::note_encryption::PreparedIncomingViewingKey::new(&SaplingIvk(ivk_scalar));

        let mut addr_bytes = [0u8; 43];
        addr_bytes[..11].copy_from_slice(&default_d);
        addr_bytes[11..].copy_from_slice(&default_pk_d);
        let to = PaymentAddress::from_bytes(&addr_bytes).unwrap();

        let cv =
            ValueCommitment::from_bytes_not_small_order(&cv_bytes.as_slice().try_into().unwrap())
                .unwrap();
        let cmu = sapling::note::ExtractedNoteCommitment::from_bytes(
            &cmu_bytes.as_slice().try_into().unwrap(),
        )
        .unwrap();
        let epk_arr: [u8; 32] = epk_bytes.as_slice().try_into().unwrap();
        let c_enc_arr: [u8; ENC_CIPHERTEXT_SIZE] = c_enc.as_slice().try_into().unwrap();
        let c_out_arr: [u8; 80] = c_out.as_slice().try_into().unwrap();
        let output = OutputDescription::from_parts(
            cv,
            cmu,
            EphemeralKeyBytes(epk_arr),
            c_enc_arr,
            c_out_arr,
            [0u8; 192],
        );

        let zip212 = Zip212Enforcement::Off;
        let decrypted =
            sapling::note_encryption::try_sapling_note_decryption(&prepared_ivk, &output, zip212)
                .expect("vector decrypts");
        assert_eq!(decrypted.1, to);
        let memo_arr: [u8; 512] = memo.as_slice().try_into().unwrap();
        assert_eq!(decrypted.2, memo_arr);

        let compact = sapling::note_encryption::CompactOutputDescription::from(output);
        let decrypted_compact = sapling::note_encryption::try_sapling_compact_note_decryption(
            &prepared_ivk,
            &compact,
            zip212,
        )
        .expect("compact decrypts");
        assert_eq!(decrypted_compact.1, to);
    }

    #[tokio::test]
    async fn sync_discovers_note_and_updates_height() {
        let wallet = sample_wallet_at(heartwood_mainnet());
        let pa = wallet.default_address().unwrap();
        let output = build_compact_output(&pa);
        let block_height = heartwood_mainnet();
        let tx = CompactTx {
            index: 0,
            hash: tx_hash(block_height, 0),
            fee: 0,
            spends: vec![CompactSaplingSpend { nf: vec![0u8; 32] }],
            outputs: vec![output],
            actions: Vec::new(),
        };
        let block = CompactBlock {
            proto_version: 0,
            height: block_height as u64,
            hash: block_hash(block_height),
            prev_hash: block_hash(block_height.saturating_sub(1)),
            time: 0,
            header: Vec::new(),
            vtx: vec![tx],
            chain_metadata: None,
        };

        let prev = dummy_block(block.height as u32 - 1);
        let source: Arc<dyn NoteSource> = Arc::new(MockNoteSource::from_blocks(vec![prev, block]));
        let store = WalletStore::in_memory().unwrap();
        let mut syncer = WalletSyncer::new(wallet, source, store, PrivacyConfig::default())
            .with_tree_verification(false)
            .with_header_validation(false);
        let mut sapling_tree = NoteCommitmentTree::new();
        let mut orchard_tree = OrchardNoteCommitmentTree::new();
        let result = syncer
            .sync_wallet(&mut sapling_tree, &mut orchard_tree)
            .await
            .unwrap();
        assert_eq!(result.notes_found_sapling, 1);
        assert_eq!(result.notes_found_orchard, 0);
        assert_eq!(result.blocks_processed, 1);
        assert_eq!(result.end_height, heartwood_mainnet());
    }

    #[tokio::test]
    async fn spent_notes_are_marked_after_matching_nullifier() {
        let wallet = sample_wallet_at(heartwood_mainnet());
        let pa = wallet.default_address().unwrap();
        let output = build_compact_output(&pa);
        let decryptor = TrialDecryptor::new(Some(wallet.ivk.clone()), None);
        let found = decryptor
            .try_decrypt_sapling_output(&output, Zip212Enforcement::On)
            .unwrap()
            .expect("sapling note decrypted");
        let mut tmp_tree = NoteCommitmentTree::new();
        let position = tmp_tree
            .append(
                output
                    .cmu
                    .as_slice()
                    .try_into()
                    .expect("commitment bytes for nullifier"),
            )
            .unwrap();
        let nullifier = found.note.nf(&wallet.fvk.as_inner().fvk.vk.nk, position).0;

        let receive_tx = CompactTx {
            index: 0,
            hash: tx_hash(heartwood_mainnet(), 0),
            fee: 0,
            spends: Vec::new(),
            outputs: vec![output.clone()],
            actions: Vec::new(),
        };
        let spend_tx = CompactTx {
            index: 1,
            hash: tx_hash(heartwood_mainnet().saturating_add(1), 1),
            fee: 0,
            spends: vec![CompactSaplingSpend {
                nf: nullifier.to_vec(),
            }],
            outputs: Vec::new(),
            actions: Vec::new(),
        };
        let blocks = vec![
            dummy_block(heartwood_mainnet().saturating_sub(1)),
            CompactBlock {
                proto_version: 0,
                height: heartwood_mainnet() as u64,
                hash: block_hash(heartwood_mainnet()),
                prev_hash: block_hash(heartwood_mainnet().saturating_sub(1)),
                time: 0,
                header: Vec::new(),
                vtx: vec![receive_tx],
                chain_metadata: None,
            },
            CompactBlock {
                proto_version: 0,
                height: (heartwood_mainnet() + 1) as u64,
                hash: block_hash(heartwood_mainnet().saturating_add(1)),
                prev_hash: block_hash(heartwood_mainnet()),
                time: 0,
                header: Vec::new(),
                vtx: vec![spend_tx],
                chain_metadata: None,
            },
        ];

        let source: Arc<dyn NoteSource> = Arc::new(MockNoteSource::from_blocks(blocks));
        let store = WalletStore::in_memory().unwrap();
        let mut syncer = WalletSyncer::new(wallet, source, store, PrivacyConfig::default())
            .with_tree_verification(false)
            .with_header_validation(false);
        let mut sapling_tree = NoteCommitmentTree::new();
        let mut orchard_tree = OrchardNoteCommitmentTree::new();
        syncer
            .sync_wallet(&mut sapling_tree, &mut orchard_tree)
            .await
            .unwrap();

        let unspent = syncer.store.get_unspent_notes().unwrap();
        assert!(unspent.is_empty());
    }

    #[tokio::test]
    async fn reorg_resets_state_and_rescans() {
        let wallet = sample_wallet_at(heartwood_mainnet());
        let pa = wallet.default_address().unwrap();
        let output = build_compact_output(&pa);
        let tx_good = CompactTx {
            index: 0,
            hash: tx_hash(heartwood_mainnet().saturating_add(1), 0),
            fee: 0,
            spends: Vec::new(),
            outputs: vec![output],
            actions: Vec::new(),
        };
        let prev = dummy_block(heartwood_mainnet().saturating_sub(1));

        let block0 = CompactBlock {
            proto_version: 0,
            height: heartwood_mainnet() as u64,
            hash: vec![0x11; 32],
            prev_hash: prev.hash.clone(),
            time: 0,
            header: Vec::new(),
            vtx: Vec::new(),
            chain_metadata: None,
        };
        let bad_block = CompactBlock {
            proto_version: 0,
            height: (heartwood_mainnet() + 1) as u64,
            hash: vec![0x22; 32],
            prev_hash: vec![0x33; 32],
            time: 0,
            header: Vec::new(),
            vtx: Vec::new(),
            chain_metadata: None,
        };
        let good_block = CompactBlock {
            proto_version: 0,
            height: (heartwood_mainnet() + 1) as u64,
            hash: vec![0x44; 32],
            prev_hash: block0.hash.clone(),
            time: 0,
            header: Vec::new(),
            vtx: vec![tx_good],
            chain_metadata: None,
        };

        let first_chain = vec![prev.clone(), block0.clone(), bad_block];
        let second_chain = vec![prev, block0, good_block];
        let source: Arc<dyn NoteSource> = Arc::new(ReorgNoteSource::new(first_chain, second_chain));
        let store = WalletStore::in_memory().unwrap();
        let mut syncer = WalletSyncer::new(wallet, source, store, PrivacyConfig::default())
            .with_tree_verification(false)
            .with_header_validation(false);
        let mut sapling_tree = NoteCommitmentTree::new();
        let mut orchard_tree = OrchardNoteCommitmentTree::new();
        let result = syncer
            .sync_wallet(&mut sapling_tree, &mut orchard_tree)
            .await
            .unwrap();
        assert!(result.notes_found_sapling >= 1);
        let notes = syncer.store.get_unspent_notes().unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].height, heartwood_mainnet() + 1);
    }

    #[tokio::test]
    async fn offline_reorg_detected_via_cached_hash() {
        use tempfile::tempdir;

        let wallet = sample_wallet_at(heartwood_mainnet());
        let pa = wallet.default_address().unwrap();
        let good_output = build_compact_output(&pa);
        let prev_anchor = dummy_block(heartwood_mainnet().saturating_sub(1));
        let block0 = CompactBlock {
            proto_version: 0,
            height: heartwood_mainnet() as u64,
            hash: vec![0x10; 32],
            prev_hash: prev_anchor.hash.clone(),
            time: 0,
            header: Vec::new(),
            vtx: Vec::new(),
            chain_metadata: None,
        };
        let block_good = CompactBlock {
            proto_version: 0,
            height: (heartwood_mainnet() + 1) as u64,
            hash: vec![0x20; 32],
            prev_hash: block0.hash.clone(),
            time: 0,
            header: Vec::new(),
            vtx: vec![CompactTx {
                index: 0,
                hash: tx_hash(heartwood_mainnet().saturating_add(1), 0),
                fee: 0,
                spends: Vec::new(),
                outputs: vec![good_output],
                actions: Vec::new(),
            }],
            chain_metadata: None,
        };
        let block_reorg = CompactBlock {
            proto_version: 0,
            height: (heartwood_mainnet() + 1) as u64,
            hash: vec![0x30; 32],
            prev_hash: block0.hash.clone(),
            time: 0,
            header: Vec::new(),
            vtx: Vec::new(),
            chain_metadata: None,
        };

        let dir = tempdir().unwrap();
        let db_path = dir.path().join("wallet.db");
        let mut store = WalletStore::open(&db_path).unwrap();
        let encrypted = rime_core::encrypt_seed(&rime_core::WalletSeed::generate(), "pw").unwrap();
        store
            .save_wallet(&wallet, &encrypted.payload, &encrypted.salt)
            .unwrap();
        drop(store);

        {
            let store = WalletStore::open(&db_path).unwrap();
            let wallet = store.load_wallet().unwrap();
            let source: Arc<dyn NoteSource> = Arc::new(MockNoteSource::from_blocks(vec![
                prev_anchor.clone(),
                block0.clone(),
                block_good.clone(),
            ]));
            let mut syncer = WalletSyncer::new(wallet, source, store, PrivacyConfig::default())
                .with_tree_verification(false)
                .with_header_validation(false);
            let mut sapling_tree = NoteCommitmentTree::new();
            let mut orchard_tree = OrchardNoteCommitmentTree::new();
            let result = syncer
                .sync_wallet(&mut sapling_tree, &mut orchard_tree)
                .await
                .unwrap();
            assert_eq!(result.notes_found_sapling, 1);
        }

        let store = WalletStore::open(&db_path).unwrap();
        let wallet = store.load_wallet().unwrap();
        let source: Arc<dyn NoteSource> = Arc::new(MockNoteSource::from_blocks(vec![
            prev_anchor,
            block0,
            block_reorg,
        ]));
        let mut syncer = WalletSyncer::new(wallet, source, store, PrivacyConfig::default())
            .with_tree_verification(false)
            .with_header_validation(false);
        let mut sapling_tree = NoteCommitmentTree::new();
        let mut orchard_tree = OrchardNoteCommitmentTree::new();
        let result = syncer
            .sync_wallet(&mut sapling_tree, &mut orchard_tree)
            .await
            .unwrap();
        assert_eq!(result.notes_found_sapling, 0);
        let notes = syncer.store.get_unspent_notes().unwrap();
        assert!(notes.is_empty());
    }

    #[tokio::test]
    async fn checkpoint_is_created_and_loaded() {
        use tempfile::tempdir;

        let checkpoint_height = heartwood_mainnet() + 1000;
        let wallet = sample_wallet_at(checkpoint_height);
        let pa = wallet.default_address().unwrap();
        let output = build_compact_output(&pa);
        let tx = CompactTx {
            index: 0,
            hash: tx_hash(checkpoint_height, 0),
            fee: 0,
            spends: vec![CompactSaplingSpend { nf: vec![0u8; 32] }],
            outputs: vec![output],
            actions: Vec::new(),
        };
        let block = CompactBlock {
            proto_version: 0,
            height: checkpoint_height as u64,
            hash: block_hash(checkpoint_height),
            prev_hash: block_hash(checkpoint_height.saturating_sub(1)),
            time: 0,
            header: Vec::new(),
            vtx: vec![tx],
            chain_metadata: None,
        };

        let dir = tempdir().unwrap();
        let db_path = dir.path().join("wallet.db");
        {
            let prev = dummy_block(checkpoint_height.saturating_sub(1));
            let source: Arc<dyn NoteSource> =
                Arc::new(MockNoteSource::from_blocks(vec![prev, block.clone()]));
            let store = WalletStore::open(&db_path).unwrap();
            let mut syncer = WalletSyncer::new(
                Wallet {
                    metadata: wallet.metadata.clone(),
                    fvk: wallet.fvk.clone(),
                    ivk: wallet.ivk.clone(),
                    unified_fvk: wallet.unified_fvk.clone(),
                },
                source,
                store,
                PrivacyConfig::default(),
            )
            .with_tree_verification(false)
            .with_header_validation(false);
            let mut sapling_tree = NoteCommitmentTree::new();
            let mut orchard_tree = OrchardNoteCommitmentTree::new();
            let result = syncer
                .sync_wallet(&mut sapling_tree, &mut orchard_tree)
                .await
                .unwrap();
            assert_eq!(result.blocks_processed, 1);
            let root = sapling_tree.root().unwrap();
            let store = WalletStore::open(&db_path).unwrap();
            let checkpoint = store
                .load_latest_checkpoint(Pool::Sapling)
                .unwrap()
                .unwrap();
            assert_eq!(checkpoint.height, checkpoint_height);
            assert_eq!(checkpoint.root, root);
        }

        let prev = dummy_block(checkpoint_height.saturating_sub(1));
        let source: Arc<dyn NoteSource> = Arc::new(MockNoteSource::from_blocks(vec![prev, block]));
        let store = WalletStore::open(&db_path).unwrap();
        let mut syncer = WalletSyncer::new(
            Wallet {
                metadata: rime_core::WalletMetadata {
                    network: wallet.metadata.network,
                    birthday_height: 0,
                    last_synced_height: 0,
                    unified_fvk: None,
                },
                fvk: wallet.fvk,
                ivk: wallet.ivk,
                unified_fvk: None,
            },
            source,
            store,
            PrivacyConfig::default(),
        )
        .with_tree_verification(false)
        .with_header_validation(false);
        let mut sapling_tree = NoteCommitmentTree::new();
        let mut orchard_tree = OrchardNoteCommitmentTree::new();
        let resume = syncer
            .sync_wallet(&mut sapling_tree, &mut orchard_tree)
            .await
            .unwrap();
        assert_eq!(resume.blocks_processed, 0);
        assert!(resume.start_height > checkpoint_height);
    }

    #[test]
    fn tree_state_conversion_handles_empty_tree() {
        let tree = TreeState {
            network: "main".into(),
            height: 0,
            hash: "00".repeat(32),
            time: 0,
            sapling_tree: String::new(),
            orchard_tree: String::new(),
        };
        let chain_state = convert_tree_state(&tree).expect("convert tree state");
        assert_eq!(chain_state.block_height(), BlockHeight::from(0));
    }

    #[tokio::test]
    async fn full_memo_downloads_all_memos() {
        let height = heartwood_mainnet() + 5;
        let wallet_normal = sample_wallet_at(height);
        let wallet_full = sample_wallet_at(height);
        let wallet_address = wallet_normal.default_address().unwrap();
        let other_address_one = {
            let km = rime_core::keys::KeyManager::from_mnemonic_with_network(
                sample_phrase(),
                "pass-one",
                Network::Mainnet,
            )
            .unwrap();
            let sk = km.sapling_spending_key().unwrap();
            let dfvk = sk
                .to_full_viewing_key()
                .as_inner()
                .to_diversifiable_full_viewing_key();
            dfvk.default_address().1
        };
        let other_address_two = {
            let km = rime_core::keys::KeyManager::from_mnemonic_with_network(
                sample_phrase(),
                "pass-two",
                Network::Mainnet,
            )
            .unwrap();
            let sk = km.sapling_spending_key().unwrap();
            let dfvk = sk
                .to_full_viewing_key()
                .as_inner()
                .to_diversifiable_full_viewing_key();
            dfvk.default_address().1
        };
        let outputs = vec![
            (wallet_address, memo_bytes("wallet memo")),
            (other_address_one, memo_bytes("memo two")),
            (other_address_two, memo_bytes("memo three")),
        ];
        let (compact_tx, raw_tx, txid) = build_sapling_transaction(&outputs);
        let mut blocks = Vec::new();
        let prev_height = height.saturating_sub(1);
        let prev_block = CompactBlock {
            proto_version: 0,
            height: prev_height as u64,
            hash: vec![0x33; 32],
            prev_hash: block_hash(prev_height.saturating_sub(1)),
            ..CompactBlock::default()
        };
        blocks.push(prev_block.clone());
        let block = CompactBlock {
            proto_version: 0,
            height: height as u64,
            hash: vec![0x55; 32],
            prev_hash: prev_block.hash.clone(),
            time: 0,
            header: Vec::new(),
            vtx: vec![compact_tx.clone()],
            chain_metadata: None,
        };
        blocks.push(block);
        let mut transactions = HashMap::new();
        transactions.insert(
            txid,
            RawTransaction {
                data: raw_tx.clone(),
                height: height as u64,
            },
        );
        let (source_normal, counter_normal) =
            build_counting_source(blocks.clone(), transactions.clone());
        let store = WalletStore::in_memory().unwrap();
        let mut syncer = WalletSyncer::new(
            wallet_normal,
            source_normal,
            store,
            PrivacyConfig::default(),
        )
        .with_tree_verification(false)
        .with_header_validation(false);
        let mut sapling_tree = NoteCommitmentTree::new();
        let mut orchard_tree = OrchardNoteCommitmentTree::new();
        syncer
            .sync_wallet(&mut sapling_tree, &mut orchard_tree)
            .await
            .unwrap();
        assert_eq!(counter_normal.load(Ordering::SeqCst), 0);
        let notes = syncer.store.list_notes(None).unwrap();
        assert_eq!(notes.len(), 1);
        assert!(notes[0].memo.is_none());

        let privacy = PrivacyConfig {
            sync_mode: SyncMode::FullMemo,
            full_memo: Some(FullMemoConfig {
                require_confirmation: false,
            }),
            ..PrivacyConfig::default()
        };
        let (source_full, counter_full) = build_counting_source(blocks, transactions);
        let store_full = WalletStore::in_memory().unwrap();
        let mut syncer_full = WalletSyncer::new(wallet_full, source_full, store_full, privacy)
            .with_tree_verification(false)
            .with_header_validation(false);
        let mut sapling_tree_full = NoteCommitmentTree::new();
        let mut orchard_tree_full = OrchardNoteCommitmentTree::new();
        syncer_full
            .sync_wallet(&mut sapling_tree_full, &mut orchard_tree_full)
            .await
            .unwrap();
        assert_eq!(counter_full.load(Ordering::SeqCst), 1);
        let stats = syncer_full.full_memo_stats().unwrap();
        assert_eq!(stats.memos_cached as usize, outputs.len());
        let notes_full = syncer_full.store.list_notes(None).unwrap();
        assert_eq!(notes_full.len(), 1);
        let memo_text = notes_full[0]
            .memo_utf8()
            .map(|m| m.trim_end_matches('\0').to_string());
        assert_eq!(memo_text.as_deref(), Some("wallet memo"));
    }
}
