use orchard::keys::Scope as OrchardScope;
use rime_core::{notes::Pool, Note, Wallet};
use std::sync::Arc;

use crate::{
    rpc::CompactBlock,
    source::NoteSource,
    sync::{pack_note_id, serialize_rseed, zip212_enforcement, OrchardDecryption, SaplingDecryption, TrialDecryptor},
    SyncError,
};
use hex;

#[derive(Default, Debug, Clone, Copy)]
pub struct StatelessStats {
    pub blocks_scanned: u32,
    pub sapling_notes: u32,
    pub orchard_notes: u32,
}

/// Stateless scan: no DB, no checkpoints, no witness storage, no retained notes.
/// Notes are streamed to `on_note` as they are found.
pub async fn stateless_scan(
    wallet: &Wallet,
    source: Arc<dyn NoteSource>,
    start_height: u32,
    batch_size: u32,
    mut on_note: impl FnMut(&Note),
) -> Result<StatelessStats, SyncError> {
    let latest = source.latest_height().await?;
    if start_height > latest {
        return Ok(StatelessStats::default());
    }

    let orchard_ivk = wallet
        .unified_fvk
        .as_ref()
        .and_then(|ufvk| ufvk.orchard.as_ref())
        .map(|fvk| fvk.to_ivk(OrchardScope::External));
    let mut decryptor = TrialDecryptor::new(Some(wallet.ivk.clone()), orchard_ivk);

    let mut stats = StatelessStats::default();
    let mut sapling_position: u64 = 0;
    let mut orchard_position: u64 = 0;

    let mut cursor = start_height;
    while cursor <= latest {
        let end = cursor
            .saturating_add(batch_size.max(1))
            .saturating_sub(1)
            .min(latest);
        let blocks = source.fetch_compact_blocks(cursor..end.saturating_add(1)).await?;
        for block in blocks {
            stats.blocks_scanned = stats.blocks_scanned.saturating_add(1);
            scan_block_stateless(
                wallet,
                &mut decryptor,
                &mut sapling_position,
                &mut orchard_position,
                &mut stats,
                &mut on_note,
                &block,
            )?;
        }
        cursor = end.saturating_add(1);
    }
    Ok(stats)
}

fn scan_block_stateless(
    wallet: &Wallet,
    decryptor: &mut TrialDecryptor,
    sapling_position: &mut u64,
    orchard_position: &mut u64,
    stats: &mut StatelessStats,
    on_note: &mut impl FnMut(&Note),
    block: &CompactBlock,
) -> Result<(), SyncError> {
    let block_height = block.height as u32;
    let sapling_zip212 = zip212_enforcement(wallet.metadata.network, block_height);

    for tx in &block.vtx {
        for output in &tx.outputs {
            let position = *sapling_position;
            *sapling_position = sapling_position.saturating_add(1);
            if let Some(found) = decryptor.try_decrypt_sapling_output(output, sapling_zip212)? {
                let note = build_sapling_note_stateless(wallet, block_height, position, found)?;
                stats.sapling_notes = stats.sapling_notes.saturating_add(1);
                on_note(&note);
            }
        }

        for action in &tx.actions {
            let position = *orchard_position;
            *orchard_position = orchard_position.saturating_add(1);
            if let Some(found) = decryptor.try_decrypt_orchard_action(action, None)? {
                let note = build_orchard_note_stateless(wallet, block_height, position, found)?;
                stats.orchard_notes = stats.orchard_notes.saturating_add(1);
                on_note(&note);
            }
        }
    }

    Ok(())
}

fn build_sapling_note_stateless(
    wallet: &Wallet,
    block_height: u32,
    position: u64,
    found: SaplingDecryption,
) -> Result<Note, SyncError> {
    let nk = wallet.fvk.as_inner().fvk.vk.nk;
    let nullifier = found.note.nf(&nk, position).0;
    let (zip212, rseed_bytes) = serialize_rseed(found.note.rseed());
    let address_bytes = found.address.to_bytes();

    let note_id = pack_note_id(Pool::Sapling, block_height, position)?;
    Ok(Note {
        id: note_id,
        pool: Pool::Sapling,
        value: found.note.value().inner(),
        commitment: found.cmu,
        nullifier,
        address: hex::encode(address_bytes),
        address_bytes,
        rseed: rseed_bytes,
        zip212,
        height: block_height,
        spent: false,
        memo: found.memo,
        witness: Vec::new(),
        position,
    })
}

fn build_orchard_note_stateless(
    wallet: &Wallet,
    block_height: u32,
    position: u64,
    found: OrchardDecryption,
) -> Result<Note, SyncError> {
    let orchard_fvk = wallet
        .unified_fvk
        .as_ref()
        .and_then(|ufvk| ufvk.orchard.as_ref())
        .ok_or_else(|| SyncError::Chain("orchard viewing key unavailable".into()))?;
    let nullifier = found.note.nullifier(orchard_fvk).to_bytes();
    let address_bytes = found.address.to_raw_address_bytes();

    let note_id = pack_note_id(Pool::Orchard, block_height, position)?;
    Ok(Note {
        id: note_id,
        pool: Pool::Orchard,
        value: found.note.value().inner(),
        commitment: found.cmx,
        nullifier,
        address: hex::encode(address_bytes),
        address_bytes,
        rseed: *found.note.rseed().as_bytes(),
        zip212: true,
        height: block_height,
        spent: false,
        memo: found.memo,
        witness: Vec::new(),
        position,
    })
}
