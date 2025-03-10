extern crate electrum_client;
extern crate rstest;

use electrum_client::{Client, ElectrumApi};
use rstest::rstest;

// picked some random servers from https://1209k.com/bitcoin-eye/ele.php
#[cfg(feature = "test_servers")]
#[rstest]
#[case::electrs(["electrum.blockstream.info", "ax101.blockeng.ch", "ax102.blockeng.ch", "ulrichard.ch"])]
#[case::electrumx(["electrumx-core.1209k.com", "skbxmit.coinjoined.com", "eai.coincited.net", "bitcoin.lu.ke"])]
#[case::fulcrum(["poonode-bitcoin.duckdns.org", "btc.lastingcoin.net", "de.poiuty.com", "fullnode.titanconnect.ca"])]
fn test_electrum_servers(#[case] servers: [&str; 4]) {
    for srv in servers {
        let url = "ssl://".to_string() + srv + ":50002";
        let client = Client::new(&url).unwrap();
        if let Err(err) = client.ping() {
            panic!("electrum server error {} : {:?}", url, err);
        }
    }
}
