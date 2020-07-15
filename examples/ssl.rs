extern crate electrum_client;

use electrum_client::Client;

fn main() {
    let client = Client::new_ssl("electrum2.hodlister.co:50002", true).unwrap();
    let res = client.server_features();
    println!("{:#?}", res);
}
