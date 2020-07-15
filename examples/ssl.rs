extern crate electrum_client;

use electrum_client::{Client, ElectrumApi};

fn main() {
    let client = Client::new("ssl://electrum.blockstream.info:50002", None).unwrap();
    let res = client.server_features();
    println!("{:#?}", res);
}
