use rand::{rngs::StdRng, RngCore, SeedableRng};
use serde::{
    de::{Error as SerdeError, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use thiserror::Error;
use zeroize::Zeroizing;

use orchard::keys::Scope;
use sapling::{zip32::DiversifiableFullViewingKey, PaymentAddress};

use crate::{
    keys::{FullViewingKey, IncomingViewingKey},
    notes::{Note, Pool},
    types::Network,
    ua::{UnifiedAddress, UnifiedFullViewingKey, UnifiedReceiver},
    Error, WalletStore,
};
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum WalletError {
    #[error("invalid seed length")]
    InvalidSeedLength,
}

const SEED_LEN: usize = 64;
const LEGACY_SEED_LEN: usize = 32;

#[derive(Clone)]
pub struct WalletSeed {
    inner: Zeroizing<Vec<u8>>,
    legacy: bool,
}

impl WalletSeed {
    pub fn generate() -> Self {
        let mut rng = StdRng::from_entropy();
        let mut bytes = vec![0u8; SEED_LEN];
        rng.fill_bytes(&mut bytes);
        Self::from_vec(bytes, false).expect("seed length enforced")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WalletError> {
        Self::from_vec(bytes.to_vec(), false)
    }

    pub(crate) fn from_legacy_bytes(bytes: &[u8]) -> Result<Self, WalletError> {
        if bytes.len() != LEGACY_SEED_LEN {
            return Err(WalletError::InvalidSeedLength);
        }
        let mut padded = vec![0u8; SEED_LEN];
        padded[..LEGACY_SEED_LEN].copy_from_slice(bytes);
        Self::from_vec(padded, true)
    }

    fn from_vec(bytes: Vec<u8>, legacy: bool) -> Result<Self, WalletError> {
        if bytes.len() != SEED_LEN {
            return Err(WalletError::InvalidSeedLength);
        }
        Ok(Self {
            inner: Zeroizing::new(bytes),
            legacy,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    pub fn is_legacy(&self) -> bool {
        self.legacy
    }
}

impl Default for WalletSeed {
    fn default() -> Self {
        Self::generate()
    }
}

impl Serialize for WalletSeed {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.as_bytes())
    }
}

struct WalletSeedVisitor;

impl<'de> Visitor<'de> for WalletSeedVisitor {
    type Value = WalletSeed;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a 64-byte wallet seed")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: SerdeError,
    {
        match v.len() {
            SEED_LEN => WalletSeed::from_bytes(v).map_err(E::custom),
            LEGACY_SEED_LEN => WalletSeed::from_legacy_bytes(v).map_err(E::custom),
            len => Err(E::custom(format!("invalid seed length: {len}"))),
        }
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut bytes = Vec::with_capacity(SEED_LEN);
        while let Some(byte) = seq.next_element()? {
            bytes.push(byte);
        }
        self.visit_bytes(&bytes)
    }
}

impl<'de> Deserialize<'de> for WalletSeed {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(WalletSeedVisitor)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletMetadata {
    pub network: Network,
    pub birthday_height: u32,
    pub last_synced_height: u32,
    pub unified_fvk: Option<String>,
}

pub struct Wallet {
    pub metadata: WalletMetadata,
    pub fvk: FullViewingKey,
    pub ivk: IncomingViewingKey,
    pub unified_fvk: Option<UnifiedFullViewingKey>,
}

impl Wallet {
    pub fn new(
        metadata: WalletMetadata,
        fvk: FullViewingKey,
        ivk: IncomingViewingKey,
        unified_fvk: Option<UnifiedFullViewingKey>,
    ) -> Self {
        Self {
            metadata,
            fvk,
            ivk,
            unified_fvk,
        }
    }

    pub fn shielded_balance(&self, store: &WalletStore) -> Result<u64, Error> {
        self.total_balance(store)
    }

    pub fn sapling_balance(&self, store: &WalletStore) -> Result<u64, Error> {
        let total = self
            .unspent_notes(store)?
            .into_iter()
            .filter(|note| note.pool == Pool::Sapling)
            .map(|note| note.value)
            .sum();
        Ok(total)
    }

    pub fn orchard_balance(&self, store: &WalletStore) -> Result<u64, Error> {
        let total = self
            .unspent_notes(store)?
            .into_iter()
            .filter(|note| note.pool == Pool::Orchard)
            .map(|note| note.value)
            .sum();
        Ok(total)
    }

    pub fn total_balance(&self, store: &WalletStore) -> Result<u64, Error> {
        Ok(self.sapling_balance(store)? + self.orchard_balance(store)?)
    }

    pub fn unspent_notes(&self, store: &WalletStore) -> Result<Vec<Note>, Error> {
        store.get_unspent_notes()
    }

    pub fn default_address(&self) -> Result<PaymentAddress, Error> {
        let dfvk: DiversifiableFullViewingKey =
            self.fvk.as_inner().to_diversifiable_full_viewing_key();
        let (_, address) = dfvk.default_address();
        Ok(address)
    }

    pub fn unified_address(&self) -> Result<UnifiedAddress, Error> {
        let mut receivers = vec![UnifiedReceiver::Sapling(self.default_address()?)];
        if let Some(ufvk) = &self.unified_fvk {
            if let Some(orchard) = &ufvk.orchard {
                let address = orchard.address_at(0u32, Scope::External);
                receivers.push(UnifiedReceiver::Orchard(address));
            }
        }
        UnifiedAddress::from_receivers(self.metadata.network, receivers)
    }

    pub fn default_unified_address(&self) -> Result<String, Error> {
        Ok(self.unified_address()?.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{keys::KeyManager, Network, NoteId};
    use hex;

    fn sample_wallet() -> Wallet {
        let km = KeyManager::from_mnemonic_with_network(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
            "",
            Network::Mainnet,
        )
        .unwrap();
        let sk = km.sapling_spending_key().unwrap();
        Wallet::new(
            WalletMetadata {
                network: Network::Mainnet,
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
    fn metadata_round_trip() {
        let meta = WalletMetadata {
            network: Network::Testnet,
            birthday_height: 200,
            last_synced_height: 250,
            unified_fvk: Some("ufvk".into()),
        };
        let encoded = serde_json::to_string(&meta).unwrap();
        let decoded: WalletMetadata = serde_json::from_str(&encoded).unwrap();
        assert_eq!(meta, decoded);
    }

    #[test]
    fn wallet_balance_queries() {
        let wallet = sample_wallet();
        let mut store = WalletStore::in_memory().unwrap();
        let pa_bytes = wallet.default_address().unwrap().to_bytes();
        let note = Note {
            id: NoteId::new(11),
            pool: Pool::Sapling,
            value: 50,
            commitment: [0; 32],
            nullifier: [0; 32],
            address: hex::encode(pa_bytes),
            address_bytes: pa_bytes,
            rseed: [1u8; 32],
            zip212: true,
            height: 1,
            spent: false,
            memo: None,
            witness: Vec::new(),
            position: 0,
        };
        store.insert_note(&note).unwrap();
        assert_eq!(wallet.shielded_balance(&store).unwrap(), 50);
        assert_eq!(wallet.unspent_notes(&store).unwrap().len(), 1);
        assert_eq!(wallet.default_address().unwrap().to_bytes().len(), 43);
    }
}
