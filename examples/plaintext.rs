extern crate electrum_client;
extern crate env_logger;

use electrum_client::Client;

fn main() {
    env_logger::init();

    let mut client = Client::new("electrum.blockstream.info:60001").unwrap();
    let res = client.server_features();
    println!("{:#?}", res);
}
