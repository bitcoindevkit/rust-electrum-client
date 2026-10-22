// cargo run --example tofu --features tofu
extern crate electrum_client;

use electrum_client::{Client, Config, ElectrumApi, TofuStore};
use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};

#[derive(Debug, Default)]
struct InMemoryTofuStore {
    certs: Mutex<HashMap<String, Vec<u8>>>,
}

impl TofuStore for InMemoryTofuStore {
    fn get_certificate(&self, host: &str) -> io::Result<Option<Vec<u8>>> {
        Ok(self.certs.lock().unwrap().get(host).cloned())
    }

    fn set_certificate(&self, host: &str, cert: Vec<u8>) -> io::Result<()> {
        self.certs.lock().unwrap().insert(host.to_string(), cert);
        Ok(())
    }
}

fn main() {
    let store = Arc::new(InMemoryTofuStore::default());

    let client = Client::from_config_with_tofu(
        "ssl://electrum.blockstream.info:50002",
        Config::default(),
        store,
    )
    .unwrap();

    println!("{:#?}", client.server_features());
}
