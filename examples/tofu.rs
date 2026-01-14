extern crate electrum_client;

use electrum_client::{Client, ConfigBuilder, ElectrumApi, TofuStore};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// A simple in-memory implementation of TofuStore for demonstration purposes.
#[derive(Debug, Default)]
struct MyTofuStore {
    certs: Mutex<HashMap<String, Vec<u8>>>,
}

impl TofuStore for MyTofuStore {
    fn get_certificate(
        &self,
        host: &str,
    ) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
        let certs = self.certs.lock().unwrap();
        Ok(certs.get(host).cloned())
    }

    fn set_certificate(
        &self,
        host: &str,
        cert: Vec<u8>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut certs = self.certs.lock().unwrap();
        certs.insert(host.to_string(), cert);
        Ok(())
    }
}

fn main() {
    let store = Arc::new(MyTofuStore::default());
    let config = ConfigBuilder::new().tofu_store(store).build();

    let client =
        Client::from_config("ssl://electrum.blockstream.info:50002", config).unwrap();
    let res = client.server_features();
    println!("{:#?}", res);
}


