use serde::{Deserialize, Serialize};

pub const ZATOSHI_PER_ZEC: i64 = 100_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Network {
    Mainnet,
    Testnet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NoteId(pub i64);

impl NoteId {
    pub fn new(value: i64) -> Self {
        Self(value)
    }

    pub fn value(self) -> i64 {
        self.0
    }
}

pub fn zatoshi_to_zec(zatoshi: i64) -> f64 {
    zatoshi as f64 / ZATOSHI_PER_ZEC as f64
}

pub fn zec_to_zatoshi(zec: f64) -> i64 {
    (zec * ZATOSHI_PER_ZEC as f64).round() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zatoshi_round_trip() {
        let zec = 1.2345;
        let zatoshi = zec_to_zatoshi(zec);
        let recovered = zatoshi_to_zec(zatoshi);
        assert!((zec - recovered).abs() < 0.000_000_1);
    }

    #[test]
    fn note_id_exposes_value() {
        let nid = NoteId::new(42);
        assert_eq!(nid.value(), 42);
    }
}
