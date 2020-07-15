extern crate electrum_client;

use electrum_client::{Client, ElectrumApi};

fn main() {
    let client = Client::new("tcp://electrum.blockstream.info:50001", None).unwrap();
    let res = client.server_features();
    println!("{:#?}", res);
}
