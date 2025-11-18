use serde::{Deserialize, Serialize};

use crate::{tree, Error, NoteId, ZATOSHI_PER_ZEC};

use orchard::tree::MerklePath as OrchardMerklePath;
use sapling::{
    note::{Note as SaplingNote, Rseed},
    value::NoteValue,
    PaymentAddress,
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Pool {
    Sapling,
    Orchard,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Note {
    pub id: NoteId,
    pub pool: Pool,
    pub value: u64,
    pub commitment: [u8; 32],
    pub nullifier: [u8; 32],
    pub address: String,
    #[serde(with = "address_bytes_serde")]
    pub address_bytes: [u8; 43],
    pub rseed: [u8; 32],
    pub zip212: bool,
    pub height: u32,
    pub spent: bool,
    pub memo: Option<Vec<u8>>,
    pub witness: Vec<u8>,
    pub position: u64,
}

impl Note {
    pub fn is_spendable(&self, current_height: u32) -> bool {
        !self.spent && self.height <= current_height
    }

    pub fn value_zec(&self) -> f64 {
        self.value as f64 / ZATOSHI_PER_ZEC as f64
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.value == 0 {
            return Err("note value must be positive");
        }
        if self.address.is_empty() {
            return Err("address is required");
        }
        if self.address_bytes.iter().all(|b| *b == 0) {
            return Err("address bytes missing");
        }
        Ok(())
    }

    pub fn memo_utf8(&self) -> Option<String> {
        self.memo
            .as_ref()
            .and_then(|m| String::from_utf8(m.clone()).ok())
    }

    pub fn summary(&self) -> String {
        format!(
            "note#{}: {} at {}",
            self.id.value(),
            self.value,
            self.address
        )
    }

    pub fn payment_address(&self) -> Result<PaymentAddress, Error> {
        PaymentAddress::from_bytes(&self.address_bytes)
            .ok_or_else(|| Error::InvalidData("invalid sapling payment address".into()))
    }

    pub fn sapling_note(&self) -> Result<SaplingNote, Error> {
        if self.pool != Pool::Sapling {
            return Err(Error::InvalidData(
                "sapling note method called on non-sapling pool".into(),
            ));
        }
        let address = self.payment_address()?;
        let rseed = if self.zip212 {
            Rseed::AfterZip212(self.rseed)
        } else {
            return Err(Error::InvalidData(
                "zip212-disabled notes unsupported".into(),
            ));
        };
        Ok(SaplingNote::from_parts(
            address,
            NoteValue::from_raw(self.value),
            rseed,
        ))
    }

    pub fn merkle_path(&self) -> Result<sapling::MerklePath, Error> {
        if self.pool != Pool::Sapling {
            return Err(Error::InvalidData(
                "sapling merkle path requested on non-sapling note".into(),
            ));
        }
        let witness = tree::deserialize_sapling_witness(&self.witness)?;
        let path = witness
            .path()
            .ok_or_else(|| Error::InvalidData("witness missing".into()))?;
        tree::convert_path_to_sapling(path)
    }

    pub fn orchard_merkle_path(&self) -> Result<OrchardMerklePath, Error> {
        if self.pool != Pool::Orchard {
            return Err(Error::InvalidData(
                "orchard merkle path requested on non-orchard note".into(),
            ));
        }
        // orchard witnesses are stored verbatim; convert to orchard::MerklePath on demand
        let witness = tree::deserialize_orchard_witness(&self.witness)?;
        let path = witness
            .path()
            .ok_or_else(|| Error::InvalidData("witness missing".into()))?;
        tree::convert_path_to_orchard(path)
    }
}

mod address_bytes_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8; 43], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 43], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::<u8>::deserialize(deserializer)?;
        if bytes.len() != 43 {
            return Err(serde::de::Error::invalid_length(bytes.len(), &"43"));
        }
        let mut arr = [0u8; 43];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_note() -> Note {
        Note {
            id: NoteId::new(1),
            pool: Pool::Sapling,
            value: 5,
            commitment: [0; 32],
            nullifier: [0; 32],
            address: "zs1test".into(),
            address_bytes: sample_address_bytes(),
            rseed: [7u8; 32],
            zip212: true,
            height: 10,
            spent: false,
            memo: Some(b"hello".to_vec()),
            witness: Vec::new(),
            position: 0,
        }
    }

    fn sample_address_bytes() -> [u8; 43] {
        let mut bytes = [0u8; 43];
        bytes[0] = 1;
        bytes
    }

    #[test]
    fn note_validation() {
        assert!(sample_note().validate().is_ok());
    }

    #[test]
    fn validation_catches_missing_data() {
        let mut note = sample_note();
        note.value = 0;
        assert!(note.validate().is_err());
    }

    #[test]
    fn memo_is_readable() {
        let note = sample_note();
        assert_eq!(note.memo_utf8().as_deref(), Some("hello"));
    }
}
