//! Electrum Client

use std::sync::RwLock;

use log::{info, warn};

use bitcoin::{Script, Txid};

use api::ElectrumApi;
use batch::Batch;
use config::Config;
use raw_client::*;
use std::convert::TryFrom;
use types::*;

/// Generalized Electrum client that supports multiple backends. This wraps
/// [`RawClient`](client/struct.RawClient.html) and provides a more user-friendly
/// constructor that can choose the right backend based on the url prefix.
///
/// **This is available only with the `default` features, or if `proxy` and one ssl implementation are enabled**
pub enum ClientType {
    #[allow(missing_docs)]
    TCP(RawClient<ElectrumPlaintextStream>),
    #[allow(missing_docs)]
    SSL(RawClient<ElectrumSslStream>),
    #[allow(missing_docs)]
    Socks5(RawClient<ElectrumProxyStream>),
}

/// Generalized Electrum client that supports multiple backends. Can re-instantiate client_type if connections
/// drops
pub struct Client {
    client_type: RwLock<ClientType>,
    config: Config,
    url: String,
}

macro_rules! impl_inner_call {
    ( $self:expr, $name:ident $(, $args:expr)* ) => {
    {
        let mut errors = vec![];
        loop {
            let read_client = $self.client_type.read().unwrap();
            let res = match &*read_client {
                ClientType::TCP(inner) => inner.$name( $($args, )* ),
                ClientType::SSL(inner) => inner.$name( $($args, )* ),
                ClientType::Socks5(inner) => inner.$name( $($args, )* ),
            };
            drop(read_client);
            match res {
                Ok(val) => return Ok(val),
                Err(Error::Protocol(_)) => {
                    return res;
                },
                Err(e) => {
                    let failed_attempts = errors.len() + 1;

                    if retries_exhausted(failed_attempts, $self.config.retry()) {
                        warn!("call '{}' failed after {} attempts", stringify!($name), failed_attempts);
                        return Err(Error::AllAttemptsErrored(errors));
                    }

                    warn!("call '{}' failed with {}, retry: {}/{}", stringify!($name), e, failed_attempts, $self.config.retry());

                    errors.push(e);

                    // Only one thread will try to recreate the client getting the write lock,
                    // other eventual threads will get Err and will block at the beginning of
                    // previous loop when trying to read()
                    if let Ok(mut write_client) = $self.client_type.try_write() {
                        loop {
                            std::thread::sleep(std::time::Duration::from_secs((1 << errors.len()).min(30) as u64));
                            match ClientType::from_config(&$self.url, &$self.config) {
                                Ok(new_client) => {
                                    info!("Succesfully created new client");
                                    *write_client = new_client;
                                    break;
                                },
                                Err(e) => {
                                    let failed_attempts = errors.len() + 1;

                                    if retries_exhausted(failed_attempts, $self.config.retry()) {
                                        warn!("re-creating client failed after {} attempts", failed_attempts);
                                        return Err(Error::AllAttemptsErrored(errors));
                                    }

                                    warn!("re-creating client failed with {}, retry: {}/{}", e, failed_attempts, $self.config.retry());

                                    errors.push(e);
                                }
                            }
                        }
                    }
                },
            }
        }}
    }
}

fn retries_exhausted(failed_attempts: usize, configured_retries: u8) -> bool {
    match u8::try_from(failed_attempts) {
        Ok(failed_attempts) => failed_attempts > configured_retries,
        Err(_) => true, // if the usize doesn't fit into a u8, we definitely exhausted our retries
    }
}

impl ClientType {
    /// Constructor that supports multiple backends and allows configuration through
    /// the [Config]
    pub fn from_config(url: &str, config: &Config) -> Result<Self, Error> {
        if url.starts_with("ssl://") {
            let url = url.replacen("ssl://", "", 1);
            let client = match config.socks5() {
                Some(socks5) => {
                    RawClient::new_proxy_ssl(url.as_str(), config.validate_domain(), socks5)?
                }
                None => {
                    RawClient::new_ssl(url.as_str(), config.validate_domain(), config.timeout())?
                }
            };

            Ok(ClientType::SSL(client))
        } else {
            let url = url.replacen("tcp://", "", 1);

            Ok(match config.socks5().as_ref() {
                None => ClientType::TCP(RawClient::new(url.as_str(), config.timeout())?),
                Some(socks5) => ClientType::Socks5(RawClient::new_proxy(url.as_str(), socks5)?),
            })
        }
    }
}

impl Client {
    /// Default constructor supporting multiple backends by providing a prefix
    ///
    /// Supported prefixes are:
    /// - tcp:// for a TCP plaintext client.
    /// - ssl:// for an SSL-encrypted client. The server certificate will be verified.
    ///
    /// If no prefix is specified, then `tcp://` is assumed.
    ///
    /// See [Client::from_config] for more configuration options
    ///
    pub fn new(url: &str) -> Result<Self, Error> {
        Self::from_config(url, Config::default())
    }

    /// Generic constructor that supports multiple backends and allows configuration through
    /// the [Config]
    pub fn from_config(url: &str, config: Config) -> Result<Self, Error> {
        let client_type = RwLock::new(ClientType::from_config(url, &config)?);

        Ok(Client {
            client_type,
            config,
            url: url.to_string(),
        })
    }
}

impl ElectrumApi for Client {
    #[inline]
    fn batch_call(&self, batch: &Batch) -> Result<Vec<serde_json::Value>, Error> {
        impl_inner_call!(self, batch_call, batch)
    }

    #[inline]
    fn block_headers_subscribe_raw(&self) -> Result<RawHeaderNotification, Error> {
        impl_inner_call!(self, block_headers_subscribe_raw)
    }

    #[inline]
    fn block_headers_pop_raw(&self) -> Result<Option<RawHeaderNotification>, Error> {
        impl_inner_call!(self, block_headers_pop_raw)
    }

    #[inline]
    fn block_header_raw(&self, height: usize) -> Result<Vec<u8>, Error> {
        impl_inner_call!(self, block_header_raw, height)
    }

    #[inline]
    fn block_headers(&self, start_height: usize, count: usize) -> Result<GetHeadersRes, Error> {
        impl_inner_call!(self, block_headers, start_height, count)
    }

    #[inline]
    fn estimate_fee(&self, number: usize) -> Result<f64, Error> {
        impl_inner_call!(self, estimate_fee, number)
    }

    #[inline]
    fn relay_fee(&self) -> Result<f64, Error> {
        impl_inner_call!(self, relay_fee)
    }

    #[inline]
    fn script_subscribe(&self, script: &Script) -> Result<Option<ScriptStatus>, Error> {
        impl_inner_call!(self, script_subscribe, script)
    }

    #[inline]
    fn script_unsubscribe(&self, script: &Script) -> Result<bool, Error> {
        impl_inner_call!(self, script_unsubscribe, script)
    }

    #[inline]
    fn script_pop(&self, script: &Script) -> Result<Option<ScriptStatus>, Error> {
        impl_inner_call!(self, script_pop, script)
    }

    #[inline]
    fn script_get_balance(&self, script: &Script) -> Result<GetBalanceRes, Error> {
        impl_inner_call!(self, script_get_balance, script)
    }

    #[inline]
    fn batch_script_get_balance<'s, I>(&self, scripts: I) -> Result<Vec<GetBalanceRes>, Error>
    where
        I: IntoIterator<Item = &'s Script> + Clone,
    {
        impl_inner_call!(self, batch_script_get_balance, scripts.clone())
    }

    #[inline]
    fn script_get_history(&self, script: &Script) -> Result<Vec<GetHistoryRes>, Error> {
        impl_inner_call!(self, script_get_history, script)
    }

    #[inline]
    fn batch_script_get_history<'s, I>(&self, scripts: I) -> Result<Vec<Vec<GetHistoryRes>>, Error>
    where
        I: IntoIterator<Item = &'s Script> + Clone,
    {
        impl_inner_call!(self, batch_script_get_history, scripts.clone())
    }

    #[inline]
    fn script_list_unspent(&self, script: &Script) -> Result<Vec<ListUnspentRes>, Error> {
        impl_inner_call!(self, script_list_unspent, script)
    }

    #[inline]
    fn batch_script_list_unspent<'s, I>(
        &self,
        scripts: I,
    ) -> Result<Vec<Vec<ListUnspentRes>>, Error>
    where
        I: IntoIterator<Item = &'s Script> + Clone,
    {
        impl_inner_call!(self, batch_script_list_unspent, scripts.clone())
    }

    #[inline]
    fn transaction_get_verbose(&self, txid: &Txid) -> Result<GetTransactionVerboseRes, Error> {
        impl_inner_call!(self, transaction_get_verbose, txid)
    }

    #[inline]
    fn transaction_get_raw(&self, txid: &Txid) -> Result<Vec<u8>, Error> {
        impl_inner_call!(self, transaction_get_raw, txid)
    }

    #[inline]
    fn batch_transaction_get_raw<'t, I>(&self, txids: I) -> Result<Vec<Vec<u8>>, Error>
    where
        I: IntoIterator<Item = &'t Txid> + Clone,
    {
        impl_inner_call!(self, batch_transaction_get_raw, txids.clone())
    }

    #[inline]
    fn batch_block_header_raw<'s, I>(&self, heights: I) -> Result<Vec<Vec<u8>>, Error>
    where
        I: IntoIterator<Item = u32> + Clone,
    {
        impl_inner_call!(self, batch_block_header_raw, heights.clone())
    }

    #[inline]
    fn batch_estimate_fee<'s, I>(&self, numbers: I) -> Result<Vec<f64>, Error>
    where
        I: IntoIterator<Item = usize> + Clone,
    {
        impl_inner_call!(self, batch_estimate_fee, numbers.clone())
    }

    #[inline]
    fn transaction_broadcast_raw(&self, raw_tx: &[u8]) -> Result<Txid, Error> {
        impl_inner_call!(self, transaction_broadcast_raw, raw_tx)
    }

    #[inline]
    fn transaction_get_merkle(&self, txid: &Txid, height: usize) -> Result<GetMerkleRes, Error> {
        impl_inner_call!(self, transaction_get_merkle, txid, height)
    }

    #[inline]
    fn server_features(&self) -> Result<ServerFeaturesRes, Error> {
        impl_inner_call!(self, server_features)
    }

    #[inline]
    fn ping(&self) -> Result<(), Error> {
        impl_inner_call!(self, ping)
    }

    #[inline]
    #[cfg(feature = "debug-calls")]
    fn calls_made(&self) -> Result<usize, Error> {
        impl_inner_call!(self, calls_made)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn more_failed_attempts_than_retries_means_exhausted() {
        let exhausted = retries_exhausted(10, 5);

        assert_eq!(exhausted, true)
    }

    #[test]
    fn failed_attempts_bigger_than_u8_means_exhausted() {
        let failed_attempts = u8::MAX as usize + 1;

        let exhausted = retries_exhausted(failed_attempts, u8::MAX);

        assert_eq!(exhausted, true)
    }

    #[test]
    fn less_failed_attempts_means_not_exhausted() {
        let exhausted = retries_exhausted(2, 5);

        assert_eq!(exhausted, false)
    }

    #[test]
    fn attempts_equals_retries_means_not_exhausted_yet() {
        let exhausted = retries_exhausted(2, 2);

        assert_eq!(exhausted, false)
    }

    #[test]
    #[ignore]
    fn test_local_timeout() {
        // This test assumes a couple things:
        // - that `localhost` is resolved to two IP addresses, `127.0.0.1` and `::1` (with the v6
        //   one having higher priority)
        // - that the system silently drops packets to `[::1]:60000` or a different port if
        //   specified through `TEST_ELECTRUM_TIMEOUT_PORT`
        //
        //   this can be setup with: ip6tables -I INPUT 1 -p tcp -d ::1 --dport 60000 -j DROP
        //   and removed with:       ip6tables -D INPUT -p tcp -d ::1 --dport 60000 -j DROP
        //
        // The test tries to create a client to `localhost` and expects it to succeed, but only
        // after at least 2 seconds have passed which is roughly the timeout time for the first
        // try.

        use std::net::TcpListener;
        use std::sync::mpsc::channel;
        use std::time::{Duration, Instant};

        let endpoint =
            std::env::var("TEST_ELECTRUM_TIMEOUT_PORT").unwrap_or("localhost:60000".into());
        let (sender, receiver) = channel();

        std::thread::spawn(move || {
            let listener = TcpListener::bind("127.0.0.1:60000").unwrap();
            sender.send(()).unwrap();

            for _stream in listener.incoming() {
                loop {}
            }
        });

        receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("Can't start local listener");

        let now = Instant::now();
        let client = Client::from_config(
            &endpoint,
            crate::config::ConfigBuilder::new()
                .timeout(Some(5))
                .unwrap()
                .build(),
        );
        let elapsed = now.elapsed();

        assert!(client.is_ok());
        assert!(elapsed > Duration::from_secs(2));
    }
}
