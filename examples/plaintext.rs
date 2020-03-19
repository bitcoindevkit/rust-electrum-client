extern crate electrum_client;
extern crate log;

use electrum_client::Client;

use log::{Level, Metadata, Record};

struct SimpleLogger;

impl log::Log for SimpleLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Trace
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            println!("{} - {}", record.level(), record.args());
        }
    }

    fn flush(&self) {}
}

use log::{LevelFilter, SetLoggerError};

static LOGGER: SimpleLogger = SimpleLogger;

pub fn init() -> Result<(), SetLoggerError> {
    log::set_logger(&LOGGER).map(|()| log::set_max_level(LevelFilter::Trace))
}

fn main() {
    init().unwrap();

    let mut client = Client::new("localhost:50001").unwrap();
    loop {
        let res = client.relay_fee();
        println!("{:?}", res);

        std::thread::sleep(std::time::Duration::from_secs(3));
    }
}
