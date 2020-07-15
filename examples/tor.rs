extern crate electrum_client;

use electrum_client::{Client, ElectrumApi};

fn main() {
    // NOTE: This assumes Tor is running localy, with an unauthenticated Socks5 listening at
    // localhost:9050

    let client = Client::new("tcp://explorernuoc63nb.onion:110", Some("127.0.0.1:9050")).unwrap();
    let res = client.server_features();
    println!("{:#?}", res);

    // works both with onion v2/v3 (if your Tor supports them)
    let client = Client::new(
        "tcp://explorerzydxu5ecjrkwceayqybizmpjjznk5izmitf2modhcusuqlid.onion:110",
        Some("127.0.0.1:9050"),
    )
    .unwrap();
    let res = client.server_features();
    println!("{:#?}", res);
}
