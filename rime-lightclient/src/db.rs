use std::path::Path;

use rand::rngs::OsRng;
use rusqlite::Connection;
use zcash_client_sqlite::{util::SystemClock, WalletDb};
use zcash_protocol::consensus::Parameters;

pub struct RimeWalletDb<P: Parameters + Clone + 'static> {
    inner: WalletDb<Connection, P, SystemClock, OsRng>,
}

impl<P: Parameters + Clone + 'static> RimeWalletDb<P> {
    pub fn for_path(path: impl AsRef<Path>, params: P) -> Result<Self, rusqlite::Error> {
        let inner = WalletDb::for_path(path, params, SystemClock, OsRng)?;
        Ok(Self { inner })
    }

    pub fn inner(&self) -> &WalletDb<Connection, P, SystemClock, OsRng> {
        &self.inner
    }

    pub fn inner_mut(&mut self) -> &mut WalletDb<Connection, P, SystemClock, OsRng> {
        &mut self.inner
    }
}
