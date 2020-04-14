extern crate electrum_client;

use electrum_client::Client;

fn main() {
    let mut client = Client::sync_new("kirsche.emzy.de:50001").unwrap();
    let res = client.sync_server_features();
    println!("{:#?}", res);
}
