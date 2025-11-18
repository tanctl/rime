use aes_gcm::Error as AesError;
use argon2::password_hash::Error as PasswordHashError;
use ed25519_dalek::SignatureError;
use rusqlite::Error as SqlError;
use serde_json::Error as JsonError;
use thiserror::Error as ThisError;

#[derive(Debug, ThisError)]
pub enum Error {
    #[error("storage: {0}")]
    Storage(String),
    #[error("crypto failure: {0}")]
    Crypto(String),
    #[error("invalid key: {0}")]
    InvalidKey(String),
    #[error("invalid mnemonic: {0}")]
    InvalidMnemonic(String),
    #[error("invalid passphrase")]
    InvalidPassphrase,
    #[error("not found: {0}")]
    NotFound(String),
    #[error("invalid data: {0}")]
    InvalidData(String),
    #[error("serialization: {0}")]
    Serialization(String),
}

impl From<SqlError> for Error {
    fn from(err: SqlError) -> Self {
        Self::Storage(err.to_string())
    }
}

impl From<JsonError> for Error {
    fn from(err: JsonError) -> Self {
        Self::Serialization(err.to_string())
    }
}

impl From<AesError> for Error {
    fn from(err: AesError) -> Self {
        Self::Crypto(err.to_string())
    }
}

impl From<PasswordHashError> for Error {
    fn from(err: PasswordHashError) -> Self {
        Self::Crypto(err.to_string())
    }
}

impl From<SignatureError> for Error {
    fn from(err: SignatureError) -> Self {
        Self::InvalidKey(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::Error;
    use argon2::password_hash::Error as PasswordError;
    use rusqlite::Error as SqlError;

    #[test]
    fn sqlite_conversion_preserves_message() {
        let src = SqlError::InvalidQuery;
        let original = src.to_string();
        let err: Error = src.into();
        match err {
            Error::Storage(msg) => assert_eq!(msg, original),
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[test]
    fn serde_conversion_maps_to_serialization() {
        let src = serde_json::from_str::<serde_json::Value>("not json").unwrap_err();
        let expected = src.to_string();
        let err: Error = src.into();
        match err {
            Error::Serialization(msg) => assert_eq!(msg, expected),
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[test]
    fn crypto_conversion_from_password_hash() {
        let err: Error = PasswordError::Password.into();
        match err {
            Error::Crypto(msg) => assert!(msg.to_lowercase().contains("password")),
            other => panic!("unexpected variant: {:?}", other),
        }
    }
}
