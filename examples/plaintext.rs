extern crate electrum_client;
extern crate env_logger;

use std::sync::Arc;
use std::thread;

use electrum_client::Client;

fn main() {
    env_logger::init();

    let client = Arc::new(Client::new("electrum.blockstream.info:50001").unwrap());

    let mut handles = Vec::new();

    /*let _client = Arc::clone(&client);
    let handle = thread::spawn(move || {
        _client.reader_thread().unwrap();
        println!("reader thread exited");
    });

    handles.push(handle);*/

    thread::sleep(std::time::Duration::from_secs(1));

    for _ in 0..4 {
        let client = Arc::clone(&client);
        let handle = thread::spawn(move || {
            let res = client.batch_estimate_fee(vec![1, 3, 6, 12]);
            println!("{:?}", res);
        });

        handles.push(handle);
    }

    for h in handles {
        h.join().unwrap();
    }
}
