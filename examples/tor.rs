extern crate electrum_client;

use electrum_client::{Client, ConfigBuilder, ElectrumApi, Socks5Config};

fn main() {
    // NOTE: This assumes Tor is running localy, with an unauthenticated Socks5 listening at
    // localhost:9050
    let proxy = Socks5Config::new("127.0.0.1:9050");
    let config = ConfigBuilder::new().socks5(Some(proxy)).build();

    let client = Client::from_config("tcp://explorernuoc63nb.onion:110", config.clone()).unwrap();
    let res = client.server_features();
    println!("{:#?}", res);

    // works both with onion v2/v3 (if your Tor supports them)
    let client = Client::from_config(
        "tcp://explorerzydxu5ecjrkwceayqybizmpjjznk5izmitf2modhcusuqlid.onion:110",
        config,
    )
    .unwrap();
    let res = client.server_features();
    println!("{:#?}", res);
}
