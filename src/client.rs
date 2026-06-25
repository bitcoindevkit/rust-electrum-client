// SPDX-License-Identifier: MIT OR Apache-2.0

//! Electrum Client

use std::{borrow::Borrow, sync::RwLock};

use log::{info, warn};

use bitcoin::{Script, Txid};

use crate::api::ElectrumApi;
use crate::batch::Batch;
use crate::config::Config;
use crate::raw_client::*;
use crate::types::*;
use std::convert::TryFrom;

/// Generalized Electrum client that supports multiple backends. This wraps
/// [`RawClient`](client/struct.RawClient.html) and provides a more user-friendly
/// constructor that can choose the right backend based on the url prefix.
///
/// **Note the `Socks5` client type requires the `proxy` feature to be enabled.**
pub enum ClientType {
    #[allow(missing_docs)]
    TCP(RawClient<ElectrumPlaintextStream>),
    #[allow(missing_docs)]
    #[cfg(any(feature = "openssl", feature = "rustls", feature = "rustls-ring"))]
    SSL(RawClient<ElectrumSslStream>),
    #[allow(missing_docs)]
    #[cfg(feature = "proxy")]
    Socks5(RawClient<ElectrumProxyStream>),
}

/// Generalized Electrum client that supports multiple backends. Can re-instantiate client_type if connections
/// drops
pub struct Client {
    client_type: RwLock<Option<ClientType>>,
    config: Config,
    url: String,
}

macro_rules! impl_inner_call {
    ( $self:expr, $name:ident $(, $args:expr)* ) => {
    {
        let mut errors = vec![];
        loop {
            $self.connect()?;
            let read_client = $self.client_type.read().unwrap();
            let res = match read_client.as_ref().expect("connect populated client") {
                ClientType::TCP(inner) => inner.$name( $($args, )* ),
                #[cfg(any(feature = "openssl", feature = "rustls", feature = "rustls-ring"))]
                ClientType::SSL(inner) => inner.$name( $($args, )* ),
                #[cfg(feature = "proxy")]
                ClientType::Socks5(inner) => inner.$name( $($args, )* ),
            };
            drop(read_client);
            match res {
                Ok(val) => return Ok(val),
                Err(Error::Protocol(_) | Error::AlreadySubscribed(_)) => {
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
                                    *write_client = Some(new_client);
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
        let auth_provider = config.authorization_provider().cloned();

        #[cfg(any(feature = "openssl", feature = "rustls", feature = "rustls-ring"))]
        if url.starts_with("ssl://") {
            let url = url.replacen("ssl://", "", 1);
            #[cfg(feature = "proxy")]
            let raw_client = match config.socks5() {
                Some(socks5) => RawClient::new_proxy_ssl(
                    url.as_str(),
                    config.validate_domain(),
                    socks5,
                    config.timeout(),
                    auth_provider,
                )?,
                None => RawClient::new_ssl(
                    url.as_str(),
                    config.validate_domain(),
                    config.timeout(),
                    auth_provider,
                )?,
            };
            #[cfg(not(feature = "proxy"))]
            let raw_client = RawClient::new_ssl(
                url.as_str(),
                config.validate_domain(),
                config.timeout(),
                auth_provider,
            )?;

            return Ok(ClientType::SSL(raw_client));
        }

        #[cfg(not(any(feature = "openssl", feature = "rustls", feature = "rustls-ring")))]
        if url.starts_with("ssl://") {
            return Err(Error::Message(
                "SSL connections require one of the following features to be enabled: openssl, rustls, or rustls-ring".to_string()
            ));
        }

        {
            let url = url.replacen("tcp://", "", 1);

            #[cfg(feature = "proxy")]
            let client = match config.socks5() {
                Some(socks5) => ClientType::Socks5(RawClient::new_proxy(
                    url.as_str(),
                    socks5,
                    config.timeout(),
                    auth_provider,
                )?),
                None => ClientType::TCP(RawClient::new(
                    url.as_str(),
                    config.timeout(),
                    auth_provider,
                )?),
            };

            #[cfg(not(feature = "proxy"))]
            let client = ClientType::TCP(RawClient::new(
                url.as_str(),
                config.timeout(),
                auth_provider,
            )?);

            Ok(client)
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
    pub fn new(url: &str) -> Result<Self, Error> {
        Self::from_config(url, Config::default())
    }

    /// Generic constructor that supports multiple backends and allows configuration through
    /// the [Config]
    ///
    /// This stores the URL and configuration without opening a network connection.
    pub fn from_config(url: &str, config: Config) -> Result<Self, Error> {
        #[cfg(not(any(feature = "openssl", feature = "rustls", feature = "rustls-ring")))]
        if url.starts_with("ssl://") {
            return Err(Error::Message(
                "SSL connections require one of the following features to be enabled: openssl, rustls, or rustls-ring".to_string()
            ));
        }

        Ok(Client {
            client_type: RwLock::new(None),
            config,
            url: url.to_string(),
        })
    }

    /// Establishes the Electrum connection and negotiates the protocol version.
    ///
    /// Does nothing if the client is already connected.
    pub fn connect(&self) -> Result<(), Error> {
        {
            let client_type = self.client_type.read().unwrap();
            if client_type.is_some() {
                return Ok(());
            }
        }

        let mut client_type = self.client_type.write().unwrap();
        if client_type.is_none() {
            *client_type = Some(ClientType::from_config(&self.url, &self.config)?);
        }

        Ok(())
    }
}

impl ElectrumApi for Client {
    #[inline]
    fn raw_call(
        &self,
        method_name: &str,
        params: impl IntoIterator<Item = Param>,
    ) -> Result<serde_json::Value, Error> {
        // We can't passthrough this method to the inner client because it would require the
        // `params` argument to also be `Copy` (because it's used multiple times for multiple
        // retries). To avoid adding this extra trait bound we instead re-direct this call to the internal
        // `RawClient::internal_raw_call_with_vec` method.

        let vec = params.into_iter().collect::<Vec<Param>>();
        impl_inner_call!(self, internal_raw_call_with_vec, method_name, vec.clone());
    }

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
    fn estimate_fee(&self, number: usize, mode: Option<EstimationMode>) -> Result<f64, Error> {
        impl_inner_call!(self, estimate_fee, number, mode)
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
    fn batch_script_subscribe<'s, I>(&self, scripts: I) -> Result<Vec<Option<ScriptStatus>>, Error>
    where
        I: IntoIterator + Clone,
        I::Item: Borrow<&'s Script>,
    {
        impl_inner_call!(self, batch_script_subscribe, scripts.clone())
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
        I: IntoIterator + Clone,
        I::Item: Borrow<&'s Script>,
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
        I: IntoIterator + Clone,
        I::Item: Borrow<&'s Script>,
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
        I: IntoIterator + Clone,
        I::Item: Borrow<&'s Script>,
    {
        impl_inner_call!(self, batch_script_list_unspent, scripts.clone())
    }

    #[inline]
    fn transaction_get_raw(&self, txid: &Txid) -> Result<Vec<u8>, Error> {
        impl_inner_call!(self, transaction_get_raw, txid)
    }

    #[inline]
    fn batch_transaction_get_raw<'t, I>(&self, txids: I) -> Result<Vec<Vec<u8>>, Error>
    where
        I: IntoIterator + Clone,
        I::Item: Borrow<&'t Txid>,
    {
        impl_inner_call!(self, batch_transaction_get_raw, txids.clone())
    }

    #[inline]
    fn batch_block_header_raw<'s, I>(&self, heights: I) -> Result<Vec<Vec<u8>>, Error>
    where
        I: IntoIterator + Clone,
        I::Item: Borrow<u32>,
    {
        impl_inner_call!(self, batch_block_header_raw, heights.clone())
    }

    #[inline]
    fn batch_estimate_fee<'s, I>(&self, numbers: I) -> Result<Vec<f64>, Error>
    where
        I: IntoIterator + Clone,
        I::Item: Borrow<usize>,
    {
        impl_inner_call!(self, batch_estimate_fee, numbers.clone())
    }

    #[inline]
    fn transaction_broadcast_raw(&self, raw_tx: &[u8]) -> Result<Txid, Error> {
        impl_inner_call!(self, transaction_broadcast_raw, raw_tx)
    }

    #[inline]
    fn transaction_broadcast_package_raw<T: AsRef<[u8]>>(
        &self,
        raw_txs: &[T],
    ) -> Result<BroadcastPackageRes, Error> {
        impl_inner_call!(self, transaction_broadcast_package_raw, raw_txs)
    }

    #[inline]
    fn transaction_get_merkle(&self, txid: &Txid, height: usize) -> Result<GetMerkleRes, Error> {
        impl_inner_call!(self, transaction_get_merkle, txid, height)
    }

    #[inline]
    fn batch_transaction_get_merkle<I>(
        &self,
        txids_and_heights: I,
    ) -> Result<Vec<GetMerkleRes>, Error>
    where
        I: IntoIterator + Clone,
        I::Item: Borrow<(Txid, usize)>,
    {
        impl_inner_call!(
            self,
            batch_transaction_get_merkle,
            txids_and_heights.clone()
        )
    }

    #[inline]
    fn txid_from_pos(&self, height: usize, tx_pos: usize) -> Result<Txid, Error> {
        impl_inner_call!(self, txid_from_pos, height, tx_pos)
    }

    #[inline]
    fn txid_from_pos_with_merkle(
        &self,
        height: usize,
        tx_pos: usize,
    ) -> Result<TxidFromPosRes, Error> {
        impl_inner_call!(self, txid_from_pos_with_merkle, height, tx_pos)
    }

    #[inline]
    fn server_features(&self) -> Result<ServerFeaturesRes, Error> {
        impl_inner_call!(self, server_features)
    }

    #[inline]
    fn protocol_version(&self) -> Result<String, Error> {
        impl_inner_call!(self, protocol_version)
    }

    #[inline]
    fn mempool_get_info(&self) -> Result<MempoolInfoRes, Error> {
        impl_inner_call!(self, mempool_get_info)
    }

    #[inline]
    fn ping(&self) -> Result<(), Error> {
        impl_inner_call!(self, ping)
    }

    #[inline]
    fn calls_made(&self) -> Result<usize, Error> {
        impl_inner_call!(self, calls_made)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, ErrorKind, Write};
    use std::net::TcpListener;
    use std::thread;

    const VERSION_RESPONSE: &[u8] = br#"{"jsonrpc":"2.0","result":["test-server","1.6"],"id":0}"#;
    const FEATURES_RESPONSE: &[u8] =
        br#"{"jsonrpc":"2.0","result":{"server_version":"test-server","genesis_hash":"0000000000000000000000000000000000000000000000000000000000000000","protocol_min":"1.4","protocol_max":"1.6","hash_function":"sha256","pruning":null},"id":1}"#;

    fn listener_url(listener: &TcpListener) -> String {
        format!("tcp://{}", listener.local_addr().unwrap())
    }

    fn read_request(reader: &mut impl BufRead) -> String {
        let mut request = String::new();
        reader.read_line(&mut request).unwrap();
        request
    }

    fn write_response(stream: &mut impl Write, response: &[u8]) {
        stream.write_all(response).unwrap();
        stream.write_all(b"\n").unwrap();
    }

    #[test]
    fn more_failed_attempts_than_retries_means_exhausted() {
        let exhausted = retries_exhausted(10, 5);

        assert!(exhausted)
    }

    #[test]
    fn failed_attempts_bigger_than_u8_means_exhausted() {
        let failed_attempts = u8::MAX as usize + 1;

        let exhausted = retries_exhausted(failed_attempts, u8::MAX);

        assert!(exhausted)
    }

    #[test]
    fn less_failed_attempts_means_not_exhausted() {
        let exhausted = retries_exhausted(2, 5);

        assert!(!exhausted)
    }

    #[test]
    fn attempts_equals_retries_means_not_exhausted_yet() {
        let exhausted = retries_exhausted(2, 2);

        assert!(!exhausted)
    }

    #[test]
    fn client_constructor_does_not_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = listener_url(&listener);

        let client = Client::new(&url).unwrap();

        assert!(client.client_type.read().unwrap().is_none());
        match listener.accept() {
            Ok(_) => panic!("constructor opened a connection"),
            Err(err) if err.kind() == ErrorKind::WouldBlock => {}
            Err(err) => panic!("unexpected accept error: {err}"),
        }
    }

    #[test]
    fn client_connect_opens_connection_and_negotiates_protocol() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = listener_url(&listener);
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let request = read_request(&mut reader);
            write_response(&mut stream, VERSION_RESPONSE);

            request
        });

        let client = Client::new(&url).unwrap();

        client.connect().unwrap();

        assert!(client.client_type.read().unwrap().is_some());
        let request = server.join().unwrap();
        assert!(request.contains(r#""method":"server.version""#));
    }

    #[test]
    fn first_api_call_connects_before_dispatching_request() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = listener_url(&listener);
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());

            let version_request = read_request(&mut reader);
            write_response(&mut stream, VERSION_RESPONSE);

            let features_request = read_request(&mut reader);
            write_response(&mut stream, FEATURES_RESPONSE);

            (version_request, features_request)
        });

        let client = Client::new(&url).unwrap();

        let features = client.server_features().unwrap();

        assert_eq!(features.server_version, "test-server");
        let (version_request, features_request) = server.join().unwrap();
        assert!(version_request.contains(r#""method":"server.version""#));
        assert!(features_request.contains(r#""method":"server.features""#));
    }
}
