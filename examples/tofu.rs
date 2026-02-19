extern crate electrum_client;

use electrum_client::{Client, Config, ElectrumApi, TofuStore};
use std::collections::HashMap;
use std::io::Result;
use std::sync::{Arc, Mutex};

/// A simple in-memory implementation of TofuStore for demonstration purposes.
#[derive(Debug, Default)]
struct MyTofuStore {
    certs: Mutex<HashMap<String, Vec<u8>>>,
}

impl TofuStore for MyTofuStore {
    fn get_certificate(&self, host: &str) -> Result<Option<Vec<u8>>> {
        let certs = self.certs.lock().unwrap();
        Ok(certs.get(host).cloned())
    }

    fn set_certificate(&self, host: &str, cert: Vec<u8>) -> Result<()> {
        let mut certs = self.certs.lock().unwrap();
        certs.insert(host.to_string(), cert);
        Ok(())
    }
}

fn main() {
    let store = Arc::new(MyTofuStore::default());

    let client = Client::from_config_with_tofu(
        "ssl://electrum.blockstream.info:50002",
        Config::default(),
        store,
    )
    .unwrap();

    let res = client.server_features();
    println!("{:#?}", res);
}
