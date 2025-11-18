//! RIME core: keys, wallet metadata, and storage for a Unified Address light client.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::{rngs::StdRng, RngCore, SeedableRng};

pub mod error;
pub mod keys;
pub mod notes;
pub mod storage;
pub mod tree;
pub mod types;
pub mod ua;
pub mod wallet;

pub use error::Error;
pub use keys::{
    FullViewingKey, IncomingViewingKey, KeyManager, ReceiptKey, SaplingKeypair, SaplingSignature,
    Seed, SpendingKey,
};
pub use notes::Note;
pub use storage::WalletStore;
pub use tree::TreeCheckpoint;
pub use types::{zatoshi_to_zec, zec_to_zatoshi, Network, NoteId, ZATOSHI_PER_ZEC};
pub use ua::{TransparentReceiver, UnifiedAddress, UnifiedFullViewingKey, UnifiedReceiver};
pub use wallet::{Wallet, WalletError, WalletMetadata, WalletSeed};

const ARGON_MEMORY_KIB: u32 = 19 * 1024;
const ARGON_TIME_COST: u32 = 2;

pub struct EncryptedSeed {
    pub salt: [u8; 16],
    pub payload: Vec<u8>,
}

pub fn encrypt_seed(seed: &WalletSeed, passphrase: &str) -> Result<EncryptedSeed, Error> {
    let mut salt = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    let mut rng = StdRng::from_entropy();
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce_bytes);
    let key = derive_argon_key(passphrase, &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|err| Error::Crypto(format!("cipher init: {err}")))?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), seed.as_bytes())
        .map_err(Error::from)?;
    let mut payload = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
    payload.extend_from_slice(&nonce_bytes);
    payload.extend_from_slice(&ciphertext);
    Ok(EncryptedSeed { salt, payload })
}

pub fn decrypt_seed(payload: &[u8], salt: &[u8], passphrase: &str) -> Result<WalletSeed, Error> {
    if payload.len() < 12 {
        return Err(Error::InvalidData("ciphertext too short".into()));
    }
    if salt.len() != 16 {
        return Err(Error::InvalidData("salt length mismatch".into()));
    }
    let (nonce_bytes, ciphertext) = payload.split_at(12);
    let key = derive_argon_key(passphrase, salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|err| Error::Crypto(format!("cipher init: {err}")))?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(Error::from)?;
    match plaintext.len() {
        64 => WalletSeed::from_bytes(&plaintext)
            .map_err(|_| Error::InvalidData("seed length mismatch".into())),
        32 => WalletSeed::from_legacy_bytes(&plaintext)
            .map_err(|_| Error::InvalidData("seed length mismatch".into())),
        _ => Err(Error::InvalidData("seed length mismatch".into())),
    }
}

fn derive_argon_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32], Error> {
    let params = Params::new(ARGON_MEMORY_KIB, ARGON_TIME_COST, 1, Some(32))
        .map_err(|err| Error::Crypto(format!("invalid kdf params: {err}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|err| Error::Crypto(format!("kdf failure: {err}")))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_round_trip() {
        let seed = WalletSeed::generate();
        let cipher = encrypt_seed(&seed, "password").expect("encryption works");
        let recovered =
            decrypt_seed(&cipher.payload, &cipher.salt, "password").expect("decryption works");
        assert_eq!(seed.as_bytes(), recovered.as_bytes());
    }
}
