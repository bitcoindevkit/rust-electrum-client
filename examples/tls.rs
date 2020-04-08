extern crate electrum_client;

use electrum_client::Client;

#[tokio::main]
async fn main() {
    let mut client = Client::new_tls("electrum2.hodlister.co:50002", true)
        .await
        .unwrap();
    let res = client.server_features().await;
    println!("{:#?}", res);
}
