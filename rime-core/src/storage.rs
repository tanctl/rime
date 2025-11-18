use std::{io, path::Path};

use hex::{decode, encode};
use rusqlite::{params, types::Type, Connection, OptionalExtension, Row};

use crate::{
    keys::{FullViewingKey, IncomingViewingKey},
    notes::{Note, Pool},
    tree::TreeCheckpoint,
    types::{Network, NoteId},
    ua::UnifiedFullViewingKey,
    wallet::WalletMetadata,
    Error, Wallet,
};

pub struct WalletStore {
    conn: Connection,
}

impl WalletStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        let conn = Connection::open(path)?;
        let store = Self { conn };
        store.prepare_schema()?;
        Ok(store)
    }

    pub fn in_memory() -> Result<Self, Error> {
        let conn = Connection::open_in_memory()?;
        let store = Self { conn };
        store.prepare_schema()?;
        Ok(store)
    }

    fn prepare_schema(&self) -> Result<(), Error> {
        self.conn.execute_batch(
            r#"
            PRAGMA journal_mode=WAL;
            PRAGMA foreign_keys=ON;

            CREATE TABLE IF NOT EXISTS wallet (
                id INTEGER PRIMARY KEY,
                fvk TEXT NOT NULL,
                ivk TEXT NOT NULL,
                encrypted_seed BLOB NOT NULL,
                salt BLOB NOT NULL,
                network TEXT NOT NULL,
                birthday_height INTEGER NOT NULL,
                last_synced_height INTEGER NOT NULL,
                unified_fvk TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS notes (
                id INTEGER PRIMARY KEY,
                commitment BLOB NOT NULL UNIQUE,
                nullifier BLOB NOT NULL UNIQUE,
                value INTEGER NOT NULL,
                height INTEGER NOT NULL,
                position INTEGER NOT NULL,
                witness BLOB NOT NULL,
                spent INTEGER DEFAULT 0,
                address TEXT NOT NULL DEFAULT '',
                address_bytes BLOB NOT NULL,
                rseed BLOB NOT NULL,
                zip212 INTEGER NOT NULL,
                memo BLOB,
                pool TEXT NOT NULL DEFAULT 'sapling' CHECK (pool IN ('sapling','orchard'))
            );

            CREATE TABLE IF NOT EXISTS tree_checkpoints (
                id INTEGER PRIMARY KEY,
                height INTEGER NOT NULL,
                root BLOB NOT NULL,
                tree_state BLOB NOT NULL,
                pool TEXT NOT NULL DEFAULT 'sapling' CHECK (pool IN ('sapling','orchard')),
                UNIQUE(height, pool)
            );

            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY,
                txid BLOB NOT NULL UNIQUE,
                height INTEGER NOT NULL,
                block_hash BLOB
            );

            CREATE TABLE IF NOT EXISTS block_hashes (
                height INTEGER PRIMARY KEY,
                hash BLOB NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_notes_nullifier ON notes(nullifier);
            CREATE INDEX IF NOT EXISTS idx_notes_commitment ON notes(commitment);
            CREATE INDEX IF NOT EXISTS idx_notes_height ON notes(height);
            CREATE INDEX IF NOT EXISTS idx_tree_checkpoints_height ON tree_checkpoints(height);
            CREATE INDEX IF NOT EXISTS idx_transactions_txid ON transactions(txid);
        "#,
        )?;
        self.ensure_column(
            "notes",
            "pool",
            "TEXT NOT NULL DEFAULT 'sapling' CHECK (pool IN ('sapling','orchard'))",
        )?;
        self.ensure_column(
            "tree_checkpoints",
            "pool",
            "TEXT NOT NULL DEFAULT 'sapling' CHECK (pool IN ('sapling','orchard'))",
        )?;
        Ok(())
    }

    fn ensure_column(&self, table: &str, column: &str, definition: &str) -> Result<(), Error> {
        let query = format!("PRAGMA table_info({table})");
        let mut stmt = self.conn.prepare(&query)?;
        let mut has_column = false;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let name: String = row.get(1)?;
            if name == column {
                has_column = true;
                break;
            }
        }
        if !has_column {
            let sql = format!("ALTER TABLE {table} ADD COLUMN {column} {definition}");
            self.conn.execute(&sql, [])?;
        }
        Ok(())
    }

    pub fn save_wallet(
        &mut self,
        wallet: &Wallet,
        encrypted_seed: &[u8],
        salt: &[u8],
    ) -> Result<(), Error> {
        let fvk = wallet.fvk.encode(wallet.metadata.network)?;
        let ivk_hex = encode(wallet.ivk.to_bytes());
        let unified_str = match wallet.metadata.unified_fvk.clone() {
            Some(s) => s,
            None => wallet
                .unified_fvk
                .as_ref()
                .map(|ufvk| ufvk.encode_uview())
                .transpose()
                .map_err(|e| Error::InvalidData(e.to_string()))?
                .unwrap_or_default(),
        };
        self.conn.execute(
            "INSERT INTO wallet (id, fvk, ivk, encrypted_seed, salt, network, birthday_height, last_synced_height, unified_fvk)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(id) DO UPDATE SET
                fvk=excluded.fvk,
                ivk=excluded.ivk,
                encrypted_seed=excluded.encrypted_seed,
                salt=excluded.salt,
                network=excluded.network,
                birthday_height=excluded.birthday_height,
                last_synced_height=excluded.last_synced_height,
                unified_fvk=excluded.unified_fvk",
            params![
                fvk,
                ivk_hex,
                encrypted_seed,
                salt,
                network_to_str(wallet.metadata.network),
                wallet.metadata.birthday_height as i64,
                wallet.metadata.last_synced_height as i64,
                unified_str,
            ],
        )?;
        Ok(())
    }

    pub fn load_wallet(&self) -> Result<Wallet, Error> {
        let row = self
            .conn
            .query_row(
                "SELECT fvk, ivk, encrypted_seed, salt, network, birthday_height, last_synced_height, unified_fvk FROM wallet LIMIT 1",
                [],
                |row| {
                    let fvk: String = row.get(0)?;
                    let ivk_hex: String = row.get(1)?;
                    let encrypted: Vec<u8> = row.get(2)?;
                    let salt: Vec<u8> = row.get(3)?;
                    let network: String = row.get(4)?;
                    let birthday: i64 = row.get(5)?;
                    let last_synced: i64 = row.get(6)?;
                    let unified_fvk: String = row.get(7)?;
                    Ok((fvk, ivk_hex, encrypted, salt, network, birthday, last_synced, unified_fvk))
                },
            )
            .optional()?;
        match row {
            None => Err(Error::NotFound("wallet".into())),
            Some((
                fvk_enc,
                ivk_hex,
                _encrypted_seed,
                _salt,
                net,
                birthday,
                last_synced,
                unified,
            )) => {
                let (fvk, encoded_network) = FullViewingKey::decode(&fvk_enc)?;
                let parsed_network = network_from_str(&net)?;
                if parsed_network != encoded_network {
                    return Err(Error::InvalidData("network mismatch".into()));
                }
                let ivk_bytes = decode(ivk_hex).map_err(|e| Error::InvalidData(e.to_string()))?;
                if ivk_bytes.len() != 64 {
                    return Err(Error::InvalidData("ivk length mismatch".into()));
                }
                let mut ivk_array = [0u8; 64];
                ivk_array.copy_from_slice(&ivk_bytes);
                let ivk = IncomingViewingKey::from_bytes(ivk_array)?;
                let mut unified_opt = if unified.is_empty() {
                    None
                } else {
                    Some(unified.clone())
                };
                let mut decoded_unified = match unified_opt {
                    Some(ref encoded) => {
                        let decoded = UnifiedFullViewingKey::decode_uview(encoded)?;
                        if decoded.network() != parsed_network {
                            return Err(Error::InvalidData("unified key network mismatch".into()));
                        }
                        Some(decoded)
                    }
                    None => None,
                };
                if decoded_unified.is_none() {
                    // backfill sapling-only ufvk so legacy databases still expose a unified address
                    let fallback = UnifiedFullViewingKey::from_components(
                        parsed_network,
                        Some(fvk.as_inner().clone()),
                        None,
                    );
                    let encoded = fallback.encode_uview()?;
                    if unified_opt.is_none() {
                        self.conn.execute(
                            "UPDATE wallet SET unified_fvk=?1 WHERE id=1",
                            params![&encoded],
                        )?;
                    }
                    unified_opt = Some(encoded.clone());
                    decoded_unified = Some(fallback);
                }
                let birthday_u32 = birthday as u32;
                let mut last_synced_u32 = last_synced as u32;
                if last_synced_u32 == birthday_u32 {
                    let corrected = birthday_u32.saturating_sub(1);
                    if corrected as i64 != last_synced {
                        self.conn.execute(
                            "UPDATE wallet SET last_synced_height=?1 WHERE id=1",
                            params![corrected as i64],
                        )?;
                    }
                    last_synced_u32 = corrected;
                }
                let metadata = WalletMetadata {
                    network: parsed_network,
                    birthday_height: birthday_u32,
                    last_synced_height: last_synced_u32,
                    unified_fvk: unified_opt.clone(),
                };
                Ok(Wallet::new(metadata, fvk, ivk, decoded_unified))
            }
        }
    }

    pub fn load_encrypted_seed(&self) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let row = self
            .conn
            .query_row(
                "SELECT encrypted_seed, salt FROM wallet LIMIT 1",
                [],
                |row| {
                    let encrypted: Vec<u8> = row.get(0)?;
                    let salt: Vec<u8> = row.get(1)?;
                    Ok((encrypted, salt))
                },
            )
            .optional()?;
        row.ok_or_else(|| Error::NotFound("wallet".into()))
    }

    pub fn update_last_synced_height(&self, height: u32) -> Result<(), Error> {
        self.conn.execute(
            "UPDATE wallet SET last_synced_height=?1 WHERE id=1",
            params![height as i64],
        )?;
        Ok(())
    }

    pub fn insert_note(&mut self, note: &Note) -> Result<i64, Error> {
        self.conn.execute(
            "INSERT OR REPLACE INTO notes
            (id, commitment, nullifier, value, height, position, witness, spent, address, address_bytes, rseed, zip212, memo, pool)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                note.id.value(),
                &note.commitment[..],
                &note.nullifier[..],
                note.value as i64,
                note.height as i64,
                note.position as i64,
                &note.witness,
                if note.spent { 1 } else { 0 },
                &note.address,
                &note.address_bytes[..],
                &note.rseed[..],
                if note.zip212 { 1 } else { 0 },
                note.memo.as_deref(),
                pool_to_str(note.pool),
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn get_unspent_notes(&self) -> Result<Vec<Note>, Error> {
        let mut stmt = self.conn.prepare(
            "SELECT id, commitment, nullifier, value, height, position, witness, spent, address, address_bytes, rseed, zip212, memo, pool
             FROM notes WHERE spent=0 ORDER BY height ASC",
        )?;
        let rows = stmt.query_map([], Self::map_note)?;
        let mut notes = Vec::new();
        for row in rows {
            notes.push(row?);
        }
        Ok(notes)
    }

    pub fn list_notes(&self, limit: Option<usize>) -> Result<Vec<Note>, Error> {
        let base = "SELECT id, commitment, nullifier, value, height, position, witness, spent, address, address_bytes, rseed, zip212, memo, pool FROM notes ORDER BY height DESC, position DESC";
        let mut query = base.to_string();
        if limit.is_some() {
            query.push_str(" LIMIT ?1");
        }
        let mut stmt = self.conn.prepare(&query)?;
        let rows = match limit {
            Some(limit) => stmt.query_map([limit as i64], Self::map_note)?,
            None => stmt.query_map([], Self::map_note)?,
        };
        let mut notes = Vec::new();
        for row in rows {
            notes.push(row?);
        }
        Ok(notes)
    }

    pub fn mark_note_spent(&mut self, nullifier: &[u8; 32]) -> Result<(), Error> {
        self.conn.execute(
            "UPDATE notes SET spent=1 WHERE nullifier=?1",
            params![&nullifier[..]],
        )?;
        Ok(())
    }

    pub fn save_block_hash(&mut self, height: u32, hash: &[u8]) -> Result<(), Error> {
        self.conn.execute(
            "INSERT INTO block_hashes (height, hash)
             VALUES (?1, ?2)
             ON CONFLICT(height) DO UPDATE SET hash=excluded.hash",
            params![height as i64, hash],
        )?;
        Ok(())
    }

    pub fn load_block_hash(&self, height: u32) -> Result<Option<Vec<u8>>, Error> {
        let hash = self
            .conn
            .query_row(
                "SELECT hash FROM block_hashes WHERE height=?1",
                params![height as i64],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        Ok(hash)
    }

    pub fn delete_block_hashes_from(&mut self, height: u32) -> Result<(), Error> {
        self.conn.execute(
            "DELETE FROM block_hashes WHERE height >= ?1",
            params![height as i64],
        )?;
        Ok(())
    }

    pub fn reset_state_to_birthday(&mut self, birthday: u32) -> Result<(), Error> {
        self.conn.execute("DELETE FROM notes", [])?;
        self.conn.execute("DELETE FROM tree_checkpoints", [])?;
        let reset_height = birthday.saturating_sub(1) as i64;
        self.conn.execute(
            "UPDATE wallet SET last_synced_height=?1 WHERE id=1",
            params![reset_height],
        )?;
        self.delete_block_hashes_from(birthday)?;
        Ok(())
    }

    pub fn save_tree_checkpoint(&mut self, checkpoint: &TreeCheckpoint) -> Result<(), Error> {
        self.conn.execute(
            "INSERT INTO tree_checkpoints (height, root, tree_state, pool)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(height, pool) DO UPDATE SET root=excluded.root, tree_state=excluded.tree_state",
            params![
                checkpoint.height as i64,
                &checkpoint.root[..],
                &checkpoint.tree_state,
                pool_to_str(checkpoint.pool),
            ],
        )?;
        Ok(())
    }

    pub fn load_latest_checkpoint(&self, pool: Pool) -> Result<Option<TreeCheckpoint>, Error> {
        let checkpoint = self
            .conn
            .query_row(
                "SELECT height, root, tree_state FROM tree_checkpoints WHERE pool=?1 ORDER BY height DESC LIMIT 1",
                [pool_to_str(pool)],
                |row| {
                    let height: i64 = row.get(0)?;
                    let root_vec: Vec<u8> = row.get(1)?;
                    let mut root = [0u8; 32];
                    root.copy_from_slice(&root_vec[..32]);
                    let tree_state: Vec<u8> = row.get(2)?;
                    Ok(TreeCheckpoint {
                        height: height as u32,
                        pool,
                        root,
                        tree_state,
                    })
                },
            )
            .optional()?;
        Ok(checkpoint)
    }

    fn map_note(row: &Row<'_>) -> Result<Note, rusqlite::Error> {
        let id = NoteId::new(row.get::<_, i64>(0)?);
        let commitment_vec: Vec<u8> = row.get(1)?;
        let nullifier_vec: Vec<u8> = row.get(2)?;
        let mut commitment = [0u8; 32];
        let mut nullifier = [0u8; 32];
        commitment.copy_from_slice(&commitment_vec[..32]);
        nullifier.copy_from_slice(&nullifier_vec[..32]);
        let address_bytes_vec: Vec<u8> = row.get(9)?;
        let rseed_vec: Vec<u8> = row.get(10)?;
        let pool_str: String = row.get(13)?;
        Ok(Note {
            id,
            pool: pool_from_str_sql(pool_str)?,
            commitment,
            nullifier,
            value: row.get::<_, i64>(3)? as u64,
            height: row.get::<_, i64>(4)? as u32,
            position: row.get::<_, i64>(5)? as u64,
            witness: row.get(6)?,
            spent: row.get::<_, i64>(7)? != 0,
            address: row.get(8)?,
            address_bytes: blob_to_array(address_bytes_vec)?,
            rseed: blob_to_array(rseed_vec)?,
            zip212: row.get::<_, i64>(11)? != 0,
            memo: row.get(12)?,
        })
    }
}

fn network_to_str(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "Mainnet",
        Network::Testnet => "Testnet",
    }
}

fn network_from_str(value: &str) -> Result<Network, Error> {
    match value {
        "Mainnet" => Ok(Network::Mainnet),
        "Testnet" => Ok(Network::Testnet),
        other => Err(Error::InvalidData(format!("unknown network: {other}"))),
    }
}

fn pool_to_str(pool: Pool) -> &'static str {
    match pool {
        Pool::Sapling => "sapling",
        Pool::Orchard => "orchard",
    }
}

fn pool_from_str_sql(value: String) -> Result<Pool, rusqlite::Error> {
    match value.as_str() {
        "sapling" => Ok(Pool::Sapling),
        "orchard" => Ok(Pool::Orchard),
        other => Err(rusqlite::Error::FromSqlConversionFailure(
            other.len(),
            Type::Text,
            Box::new(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown pool value: {other}"),
            )),
        )),
    }
}

fn blob_to_array<const N: usize>(blob: Vec<u8>) -> Result<[u8; N], rusqlite::Error> {
    if blob.len() != N {
        return Err(rusqlite::Error::FromSqlConversionFailure(
            blob.len(),
            Type::Blob,
            Box::new(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("blob length mismatch: expected {N} got {}", blob.len()),
            )),
        ));
    }
    let mut arr = [0u8; N];
    arr.copy_from_slice(&blob);
    Ok(arr)
}

#[cfg(test)]
fn sample_address_bytes() -> [u8; 43] {
    let mut bytes = [0u8; 43];
    bytes[0] = 2;
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        encrypt_seed, keys::KeyManager, notes::Pool, tree::NoteCommitmentTree, wallet::WalletSeed,
    };
    use tempfile::tempdir;

    fn sample_wallet(network: Network) -> Wallet {
        let km = KeyManager::from_mnemonic_with_network(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
            "",
            network,
        )
        .unwrap();
        let sk = km.sapling_spending_key().unwrap();
        Wallet::new(
            WalletMetadata {
                network,
                birthday_height: 1,
                last_synced_height: 1,
                unified_fvk: None,
            },
            sk.to_full_viewing_key(),
            km.ivk().unwrap(),
            None,
        )
    }

    #[test]
    fn wallet_save_and_load_cycle() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.db");
        let mut store = WalletStore::open(&path).unwrap();
        let wallet = sample_wallet(Network::Mainnet);
        let encrypted = encrypt_seed(&WalletSeed::generate(), "secret").unwrap();
        store
            .save_wallet(&wallet, &encrypted.payload, &encrypted.salt)
            .unwrap();
        let loaded_wallet = store.load_wallet().unwrap();
        assert_eq!(loaded_wallet.metadata.network, wallet.metadata.network);
        assert_eq!(
            loaded_wallet.metadata.birthday_height,
            wallet.metadata.birthday_height
        );
        assert!(loaded_wallet.metadata.unified_fvk.is_some());
        let (cipher, salt) = store.load_encrypted_seed().unwrap();
        assert_eq!(cipher, encrypted.payload);
        assert_eq!(salt, encrypted.salt);
    }

    #[test]
    fn note_crud_operations() {
        let mut store = WalletStore::in_memory().unwrap();
        let mut note = Note {
            id: NoteId::new(1),
            pool: Pool::Sapling,
            value: 25,
            commitment: [1u8; 32],
            nullifier: [2u8; 32],
            address: "zs1test".into(),
            address_bytes: sample_address_bytes(),
            rseed: [8u8; 32],
            zip212: true,
            height: 5,
            spent: false,
            memo: None,
            witness: vec![0u8; 32],
            position: 3,
        };
        store.insert_note(&note).unwrap();
        let notes = store.get_unspent_notes().unwrap();
        assert_eq!(notes.len(), 1);
        store.mark_note_spent(&note.nullifier).unwrap();
        let notes = store.get_unspent_notes().unwrap();
        assert!(notes.is_empty());
        note.id = NoteId::new(2);
        note.nullifier = [3u8; 32];
        note.spent = false;
        store.insert_note(&note).unwrap();
        let notes = store.get_unspent_notes().unwrap();
        assert_eq!(notes.len(), 1);
    }

    #[test]
    fn block_hash_persistence_round_trip() {
        let mut store = WalletStore::in_memory().unwrap();
        store.save_block_hash(100, &[1, 2, 3, 4]).unwrap();
        store.save_block_hash(101, &[5, 6]).unwrap();
        let hash_100 = store.load_block_hash(100).unwrap().unwrap();
        assert_eq!(hash_100, vec![1, 2, 3, 4]);
        store.delete_block_hashes_from(101).unwrap();
        assert!(store.load_block_hash(101).unwrap().is_none());
        assert!(store.load_block_hash(100).unwrap().is_some());
    }

    #[test]
    fn checkpoint_persistence_round_trip() {
        let mut tree = NoteCommitmentTree::new();
        tree.append([5u8; 32]).unwrap();
        let checkpoint = tree.checkpoint(Pool::Sapling, 10).unwrap();
        let mut store = WalletStore::in_memory().unwrap();
        store.save_tree_checkpoint(&checkpoint).unwrap();
        let loaded = store
            .load_latest_checkpoint(Pool::Sapling)
            .unwrap()
            .unwrap();
        assert_eq!(loaded.height, 10);
        assert_eq!(loaded.root, checkpoint.root);
    }

    #[test]
    fn concurrent_access_readers() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("shared.db");
        {
            let mut writer = WalletStore::open(&path).unwrap();
            let note = Note {
                id: NoteId::new(9),
                pool: Pool::Sapling,
                value: 10,
                commitment: [9u8; 32],
                nullifier: [8u8; 32],
                address: "zs1shared".into(),
                address_bytes: sample_address_bytes(),
                rseed: [5u8; 32],
                zip212: true,
                height: 7,
                spent: false,
                memo: None,
                witness: vec![1, 2, 3],
                position: 0,
            };
            writer.insert_note(&note).unwrap();
        }
        let reader = WalletStore::open(&path).unwrap();
        let notes = reader.get_unspent_notes().unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].address, "zs1shared");
    }
}
