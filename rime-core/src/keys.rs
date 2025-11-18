use std::io::Cursor;

use bech32::{self, FromBase32, ToBase32, Variant};
use bip0039::{English, Mnemonic};
use blake2b_simd::Params as Blake2bParams;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use orchard::keys::{FullViewingKey as OrchardFullViewingKey, SpendingKey as OrchardSpendingKey};
use subtle::CtOption;
use zeroize::{Zeroize, Zeroizing};

use crate::{ua::UnifiedFullViewingKey, Error, Network};
use rand::rngs::OsRng;
use sapling::zip32::{
    DiversifiableFullViewingKey, ExtendedFullViewingKey as SaplingExtendedFullViewingKey,
    ExtendedSpendingKey as SaplingExtendedSpendingKey,
    IncomingViewingKey as SaplingIncomingViewingKey,
};
use zcash_protocol::constants;
use zip32::{AccountId, ChildIndex};

/// Wrapper around the raw BIP-39 seed material.
#[derive(Clone)]
pub struct Seed(Zeroizing<Vec<u8>>);

impl Seed {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn from_slice(bytes: &[u8]) -> Self {
        Self::new(bytes.to_vec())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Zeroize for Seed {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for Seed {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl AsRef<[u8]> for Seed {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

#[derive(Clone)]
pub struct SpendingKey {
    inner: SaplingExtendedSpendingKey,
}

impl SpendingKey {
    fn new(inner: SaplingExtendedSpendingKey) -> Self {
        Self { inner }
    }

    pub fn as_inner(&self) -> &SaplingExtendedSpendingKey {
        &self.inner
    }

    pub fn to_bytes(&self) -> [u8; 169] {
        self.inner.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut cursor = Cursor::new(bytes);
        let sk = SaplingExtendedSpendingKey::read(&mut cursor)
            .map_err(|err| Error::Serialization(err.to_string()))?;
        Ok(Self { inner: sk })
    }

    pub fn encode(&self, network: Network) -> Result<String, Error> {
        let hrp = hrp_for_spending(network);
        encode_bech32(hrp, &self.inner.to_bytes())
    }

    pub fn decode(encoded: &str) -> Result<(Self, Network), Error> {
        let (hrp, data, variant) =
            bech32::decode(encoded).map_err(|e| Error::Serialization(e.to_string()))?;
        if variant != Variant::Bech32m {
            return Err(Error::Serialization("expected bech32m variant".into()));
        }
        let network = match hrp.as_str() {
            h if h == hrp_for_spending(Network::Mainnet) => Network::Mainnet,
            h if h == hrp_for_spending(Network::Testnet) => Network::Testnet,
            _ => return Err(Error::InvalidData("unknown spending key hrp".into())),
        };
        let bytes =
            Vec::<u8>::from_base32(&data).map_err(|e| Error::Serialization(e.to_string()))?;
        let key = SpendingKey::from_bytes(&bytes)?;
        Ok((key, network))
    }

    pub fn to_full_viewing_key(&self) -> FullViewingKey {
        #[allow(deprecated)]
        let inner = self.inner.to_extended_full_viewing_key();
        FullViewingKey::new(inner)
    }
}

#[derive(Clone)]
pub struct FullViewingKey {
    inner: SaplingExtendedFullViewingKey,
}

impl FullViewingKey {
    pub fn new(inner: SaplingExtendedFullViewingKey) -> Self {
        Self { inner }
    }

    pub fn as_inner(&self) -> &SaplingExtendedFullViewingKey {
        &self.inner
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(169);
        self.inner
            .write(&mut buf)
            .expect("write to vec does not fail");
        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let mut cursor = Cursor::new(bytes);
        let fvk = SaplingExtendedFullViewingKey::read(&mut cursor)
            .map_err(|err| Error::Serialization(err.to_string()))?;
        Ok(Self { inner: fvk })
    }

    pub fn encode(&self, network: Network) -> Result<String, Error> {
        let hrp = hrp_for_fvk(network);
        encode_bech32(hrp, &self.to_bytes())
    }

    pub fn decode(encoded: &str) -> Result<(Self, Network), Error> {
        let (hrp, data, variant) =
            bech32::decode(encoded).map_err(|e| Error::Serialization(e.to_string()))?;
        if variant != Variant::Bech32m {
            return Err(Error::Serialization("expected bech32m variant".into()));
        }
        let network = match hrp.as_str() {
            h if h == hrp_for_fvk(Network::Mainnet) => Network::Mainnet,
            h if h == hrp_for_fvk(Network::Testnet) => Network::Testnet,
            _ => return Err(Error::InvalidData("unknown viewing key hrp".into())),
        };
        let raw = Vec::<u8>::from_base32(&data).map_err(|e| Error::Serialization(e.to_string()))?;
        let fvk = FullViewingKey::from_bytes(&raw)?;
        Ok((fvk, network))
    }

    pub fn to_incoming_viewing_key(&self) -> IncomingViewingKey {
        let dfvk: DiversifiableFullViewingKey = self.inner.to_diversifiable_full_viewing_key();
        IncomingViewingKey {
            inner: dfvk.to_external_ivk(),
        }
    }
}

#[derive(Clone)]
pub struct IncomingViewingKey {
    inner: SaplingIncomingViewingKey,
}

impl IncomingViewingKey {
    pub fn to_bytes(&self) -> [u8; 64] {
        self.inner.to_bytes()
    }

    pub fn from_bytes(bytes: [u8; 64]) -> Result<Self, Error> {
        let decoded: CtOption<SaplingIncomingViewingKey> =
            SaplingIncomingViewingKey::from_bytes(&bytes);
        if decoded.is_some().into() {
            Ok(IncomingViewingKey {
                inner: decoded.unwrap(),
            })
        } else {
            Err(Error::InvalidData("unable to parse ivk bytes".into()))
        }
    }

    pub fn inner(&self) -> &SaplingIncomingViewingKey {
        &self.inner
    }
}

#[derive(Clone)]
pub struct ReceiptKey {
    signing: SigningKey,
    verifying: VerifyingKey,
}

impl ReceiptKey {
    fn new(signing: SigningKey) -> Self {
        let verifying = signing.verifying_key();
        Self { signing, verifying }
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.verifying.to_bytes()
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing.sign(message)
    }

    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        self.verifying.verify(message, signature).is_ok()
    }
}

pub struct KeyManager {
    seed: Seed,
    network: Network,
}

impl KeyManager {
    pub fn from_mnemonic(mnemonic: &str, passphrase: &str) -> Result<Self, Error> {
        Self::from_mnemonic_with_network(mnemonic, passphrase, Network::Mainnet)
    }

    pub fn from_mnemonic_with_network(
        mnemonic: &str,
        passphrase: &str,
        network: Network,
    ) -> Result<Self, Error> {
        if !passphrase.is_empty() && passphrase.chars().count() < 4 {
            return Err(Error::InvalidPassphrase);
        }

        let parsed = Mnemonic::<English>::from_phrase(mnemonic)
            .map_err(|err| Error::InvalidMnemonic(err.to_string()))?;
        if parsed.phrase().split_whitespace().count() != 24 {
            return Err(Error::InvalidMnemonic("expected a 24-word mnemonic".into()));
        }

        let mut seed_bytes = parsed.to_seed(passphrase);
        let seed = Seed::from_slice(&seed_bytes);
        seed_bytes.zeroize();

        Ok(Self { seed, network })
    }

    fn coin_type(&self) -> u32 {
        match self.network {
            Network::Mainnet => constants::mainnet::COIN_TYPE,
            Network::Testnet => constants::testnet::COIN_TYPE,
        }
    }

    fn derivation_path(&self, change: u32, address_index: u32) -> [ChildIndex; 5] {
        // derivation path is non-standard (hardened change/address).
        // this client is not ZIP-32 compatible with other wallets, keys are intended for internal Rime use only.
        [
            ChildIndex::hardened(32),
            ChildIndex::hardened(self.coin_type()),
            ChildIndex::hardened(0),
            ChildIndex::hardened(change),
            ChildIndex::hardened(address_index),
        ]
    }

    fn master(&self) -> SaplingExtendedSpendingKey {
        SaplingExtendedSpendingKey::master(self.seed.as_bytes())
    }

    pub fn from_seed_bytes(bytes: &[u8], network: Network) -> Self {
        let seed = Seed::from_slice(bytes);
        Self { seed, network }
    }

    fn derive_spending_key(&self, change: u32, index: u32) -> SpendingKey {
        let master = self.master();
        let path = self.derivation_path(change, index);
        let derived = SaplingExtendedSpendingKey::from_path(&master, &path);
        SpendingKey::new(derived)
    }

    pub fn sapling_spending_key(&self) -> Result<SpendingKey, Error> {
        Ok(self.derive_spending_key(0, 0))
    }

    pub fn fvk(&self) -> Result<FullViewingKey, Error> {
        Ok(self.sapling_spending_key()?.to_full_viewing_key())
    }

    pub fn ivk(&self) -> Result<IncomingViewingKey, Error> {
        Ok(self.fvk()?.to_incoming_viewing_key())
    }

    pub fn receipt_key(&self) -> Result<ReceiptKey, Error> {
        let derived = self.derive_spending_key(1, 0);
        let mut hasher = Blake2bParams::new()
            .hash_length(32)
            .personal(b"RimeReceiptKey!!")
            .to_state();
        hasher.update(self.seed.as_bytes());
        let mut encoded = derived.to_bytes();
        hasher.update(&encoded);
        encoded.zeroize();
        let mut out = [0u8; 32];
        out.copy_from_slice(hasher.finalize().as_bytes());
        let signing = SigningKey::from_bytes(&out);
        Ok(ReceiptKey::new(signing))
    }

    pub fn unified_full_viewing_key(&self) -> Result<UnifiedFullViewingKey, Error> {
        let sapling = {
            let sk = self.sapling_spending_key()?;
            #[allow(deprecated)]
            sk.as_inner().to_extended_full_viewing_key()
        };
        let orchard = OrchardSpendingKey::from_zip32_seed(
            self.seed.as_bytes(),
            self.coin_type(),
            AccountId::ZERO,
        )
        .ok()
        .map(|sk| OrchardFullViewingKey::from(&sk));
        Ok(UnifiedFullViewingKey::from_components(
            self.network,
            Some(sapling),
            orchard,
        ))
    }
}

const fn hrp_for_spending(network: Network) -> &'static str {
    match network {
        Network::Mainnet => constants::mainnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
        Network::Testnet => constants::testnet::HRP_SAPLING_EXTENDED_SPENDING_KEY,
    }
}

const fn hrp_for_fvk(network: Network) -> &'static str {
    match network {
        Network::Mainnet => constants::mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
        Network::Testnet => constants::testnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY,
    }
}

fn encode_bech32(hrp: &str, bytes: &[u8]) -> Result<String, Error> {
    bech32::encode(hrp, bytes.to_base32(), Variant::Bech32m)
        .map_err(|err| Error::Serialization(err.to_string()))
}

#[derive(Clone)]
pub struct SaplingSignature(pub Signature);

pub struct SaplingKeypair {
    signing: SigningKey,
    viewing: VerifyingKey,
}

impl SaplingKeypair {
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let signing = SigningKey::generate(&mut rng);
        let viewing = signing.verifying_key();
        Self { signing, viewing }
    }

    pub fn viewing_key(&self) -> &VerifyingKey {
        &self.viewing
    }

    pub fn sign(&self, message: &[u8]) -> SaplingSignature {
        SaplingSignature(self.signing.sign(message))
    }

    pub fn verify(&self, message: &[u8], signature: &SaplingSignature) -> bool {
        self.viewing.verify(message, &signature.0).is_ok()
    }

    pub fn diversify_hash(&self) -> [u8; 11] {
        let mut digest = [0u8; 11];
        let bytes = self.viewing.as_bytes();
        for (i, byte) in bytes.iter().enumerate() {
            digest[i % 11] ^= byte;
        }
        digest
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip0039::{Count, English, Mnemonic};

    fn sample_phrase() -> &'static str {
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon art"
    }

    #[test]
    fn mnemonic_generation_and_validation() {
        let mnemonic = Mnemonic::<English>::generate(Count::Words24);
        assert_eq!(mnemonic.phrase().split_whitespace().count(), 24);
        KeyManager::from_mnemonic(mnemonic.phrase(), "").expect("valid mnemonic");
    }

    #[test]
    fn deterministic_derivation() {
        let km1 = KeyManager::from_mnemonic(sample_phrase(), "").unwrap();
        let km2 = KeyManager::from_mnemonic(sample_phrase(), "").unwrap();
        let sk1 = km1.sapling_spending_key().unwrap().to_bytes();
        let sk2 = km2.sapling_spending_key().unwrap().to_bytes();
        assert_eq!(sk1, sk2);
        let receipt1 = km1.receipt_key().unwrap().public_key();
        let receipt2 = km2.receipt_key().unwrap().public_key();
        assert_eq!(receipt1, receipt2);
    }

    #[test]
    fn key_encoding_roundtrips() {
        let km = KeyManager::from_mnemonic(sample_phrase(), "").unwrap();
        let sk = km.sapling_spending_key().unwrap();
        let encoded = sk.encode(Network::Mainnet).unwrap();
        let (decoded, network) = SpendingKey::decode(&encoded).unwrap();
        assert_eq!(network, Network::Mainnet);
        assert_eq!(decoded.to_bytes(), sk.to_bytes());

        let fvk = sk.to_full_viewing_key();
        let encoded_fvk = fvk.encode(Network::Mainnet).unwrap();
        let (decoded_fvk, net) = FullViewingKey::decode(&encoded_fvk).unwrap();
        assert_eq!(net, Network::Mainnet);
        assert_eq!(decoded_fvk.to_bytes(), fvk.to_bytes());
    }

    #[test]
    fn seed_zeroizes() {
        let mut seed = Seed::from_slice(&[1u8, 2, 3, 4]);
        seed.zeroize();
        assert!(seed.as_bytes().iter().all(|b| *b == 0));
    }

    #[test]
    fn receipt_key_signs_and_verifies() {
        let km = KeyManager::from_mnemonic(sample_phrase(), "").unwrap();
        let receipt = km.receipt_key().unwrap();
        let msg = b"rime receipts";
        let sig = receipt.sign(msg);
        assert!(receipt.verify(msg, &sig));
    }
}
