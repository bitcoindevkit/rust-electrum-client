//! Electrum client
//!
//! This module contains definitions of all the complex data structures that are returned by calls

use core::sync::atomic::{AtomicUsize, Ordering};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::mem::drop;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Mutex, TryLockError};

#[allow(unused_imports)]
use log::{debug, error, info, trace, warn};

use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hashes::hex::{FromHex, ToHex};
use bitcoin::{BlockHeader, Script, Transaction, Txid};

#[cfg(feature = "use-openssl")]
use openssl::ssl::{SslConnector, SslMethod, SslStream, SslVerifyMode};
#[cfg(all(
    any(feature = "default", feature = "use-rustls"),
    not(feature = "use-openssl")
))]
use rustls::{ClientConfig, ClientSession, StreamOwned};

#[cfg(any(feature = "default", feature = "proxy"))]
use socks::{Socks5Stream, ToTargetAddr};

use stream::ClonableStream;

use batch::Batch;
use types::*;

macro_rules! impl_batch_call {
    ( $self:expr, $data:expr, $call:ident ) => {{
        let mut batch = Batch::default();
        for i in $data {
            batch.$call(i);
        }

        let resp = $self.batch_call(batch)?;
        let mut answer = Vec::new();

        for x in resp {
            answer.push(serde_json::from_value(x)?);
        }

        Ok(answer)
    }};
}

/// A trait for [`ToSocketAddrs`](https://doc.rust-lang.org/std/net/trait.ToSocketAddrs.html) that
/// can also be turned into a domain. Used when an SSL client needs to validate the server's
/// certificate.
pub trait ToSocketAddrsDomain: ToSocketAddrs {
    /// Returns the domain, if present
    fn domain(&self) -> Option<&str> {
        None
    }
}

impl ToSocketAddrsDomain for &str {
    fn domain(&self) -> Option<&str> {
        self.splitn(2, ':').next()
    }
}

impl ToSocketAddrsDomain for (&str, u16) {
    fn domain(&self) -> Option<&str> {
        self.0.domain()
    }
}

/// Instance of an Electrum client
///
/// A `Client` maintains a constant connection with an Electrum server and exposes methods to
/// interact with it. It can also subscribe and receive notifictations from the server about new
/// blocks or activity on a specific *scriptPubKey*.
///
/// The `Client` is modeled in such a way that allows the external caller to have full control over
/// its functionality: no threads or tasks are spawned internally to monitor the state of the
/// connection. This allows the caller to control its behavior through some *polling* functions,
/// and ultimately makes the library more lightweight and easier to embed into existing
/// projects.
///
/// More transport methods can be used by manually creating an instance of this struct with an
/// arbitray `S` type.
#[derive(Debug)]
pub struct Client<S>
where
    S: Read + Write,
{
    stream: Mutex<ClonableStream<S>>,
    buf_reader: Mutex<BufReader<ClonableStream<S>>>,

    last_id: AtomicUsize,
    waiting_map: Mutex<BTreeMap<usize, Sender<ChannelMessage>>>,

    headers: Mutex<VecDeque<HeaderNotification>>,
    script_notifications: Mutex<BTreeMap<ScriptHash, VecDeque<ScriptStatus>>>,

    #[cfg(feature = "debug-calls")]
    calls: usize,
}

impl<S> From<S> for Client<S>
where
    S: Read + Write,
{
    fn from(stream: S) -> Self {
        let stream: ClonableStream<_> = stream.into();

        Self {
            buf_reader: Mutex::new(BufReader::new(stream.clone())),
            stream: Mutex::new(stream),

            last_id: AtomicUsize::new(0),
            waiting_map: Mutex::new(BTreeMap::new()),

            headers: Mutex::new(VecDeque::new()),
            script_notifications: Mutex::new(BTreeMap::new()),

            #[cfg(feature = "debug-calls")]
            calls: 0,
        }
    }
}

/// Transport type used to establish a plaintext TCP connection with the server
pub type ElectrumPlaintextStream = TcpStream;
impl Client<ElectrumPlaintextStream> {
    /// Creates a new plaintext client and tries to connect to `socket_addr`.
    pub fn new<A: ToSocketAddrs>(socket_addr: A) -> Result<Self, Error> {
        let stream = TcpStream::connect(socket_addr)?;

        Ok(stream.into())
    }
}

#[cfg(feature = "use-openssl")]
/// Transport type used to establish an OpenSSL TLS encrypted/authenticated connection with the server
pub type ElectrumSslStream = SslStream<TcpStream>;
#[cfg(feature = "use-openssl")]
impl Client<ElectrumSslStream> {
    /// Creates a new SSL client and tries to connect to `socket_addr`. Optionally, if
    /// `validate_domain` is `true`, validate the server's certificate.
    pub fn new_ssl<A: ToSocketAddrsDomain>(
        socket_addr: A,
        validate_domain: bool,
    ) -> Result<Self, Error> {
        let mut builder =
            SslConnector::builder(SslMethod::tls()).map_err(Error::InvalidSslMethod)?;
        // TODO: support for certificate pinning
        if validate_domain {
            socket_addr.domain().ok_or(Error::MissingDomain)?;
        } else {
            builder.set_verify(SslVerifyMode::NONE);
        }
        let connector = builder.build();

        let domain = socket_addr.domain().unwrap_or("NONE").to_string();
        let stream = TcpStream::connect(socket_addr)?;
        let stream = connector
            .connect(&domain, stream)
            .map_err(Error::SslHandshakeError)?;

        Ok(stream.into())
    }
}

#[cfg(all(
    any(feature = "default", feature = "use-rustls"),
    not(feature = "use-openssl")
))]
mod danger {
    use rustls;
    use webpki;

    pub struct NoCertificateVerification {}

    impl rustls::ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _roots: &rustls::RootCertStore,
            _presented_certs: &[rustls::Certificate],
            _dns_name: webpki::DNSNameRef<'_>,
            _ocsp: &[u8],
        ) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
            Ok(rustls::ServerCertVerified::assertion())
        }
    }
}

#[cfg(all(
    any(feature = "default", feature = "use-rustls"),
    not(feature = "use-openssl")
))]
/// Transport type used to establish a Rustls TLS encrypted/authenticated connection with the server
pub type ElectrumSslStream = StreamOwned<ClientSession, TcpStream>;
#[cfg(all(
    any(feature = "default", feature = "use-rustls"),
    not(feature = "use-openssl")
))]
impl Client<ElectrumSslStream> {
    /// Creates a new SSL client and tries to connect to `socket_addr`. Optionally, if
    /// `validate_domain` is `true`, validate the server's certificate.
    pub fn new_ssl<A: ToSocketAddrsDomain>(
        socket_addr: A,
        validate_domain: bool,
    ) -> Result<Self, Error> {
        let mut config = ClientConfig::new();
        if validate_domain {
            socket_addr.domain().ok_or(Error::MissingDomain)?;

            // TODO: cert pinning
            config
                .root_store
                .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        } else {
            config
                .dangerous()
                .set_certificate_verifier(std::sync::Arc::new(danger::NoCertificateVerification {}))
        }

        let domain = socket_addr.domain().unwrap_or("NONE").to_string();
        let tcp_stream = TcpStream::connect(socket_addr)?;
        let session = ClientSession::new(
            &std::sync::Arc::new(config),
            webpki::DNSNameRef::try_from_ascii_str(&domain)
                .map_err(|_| Error::InvalidDNSNameError(domain.clone()))?,
        );
        let stream = StreamOwned::new(session, tcp_stream);

        Ok(stream.into())
    }
}

#[cfg(any(feature = "default", feature = "proxy"))]
/// Transport type used to establish a connection to a server through a socks proxy
pub type ElectrumProxyStream = Socks5Stream;
#[cfg(any(feature = "default", feature = "proxy"))]
impl Client<ElectrumProxyStream> {
    /// Creates a new socks client and tries to connect to `target_addr` using `proxy_addr` as an
    /// unauthenticated socks proxy server. The DNS resolution of `target_addr`, if required, is done
    /// through the proxy. This allows to specify, for instance, `.onion` addresses.
    pub fn new_proxy<A: ToSocketAddrs, T: ToTargetAddr>(
        target_addr: T,
        proxy_addr: A,
    ) -> Result<Self, Error> {
        // TODO: support proxy credentials
        let stream = Socks5Stream::connect(proxy_addr, target_addr)?;

        Ok(stream.into())
    }
}

#[derive(Debug)]
enum ChannelMessage {
    Response(serde_json::Value),
    WakeUp,
}

impl<S: Read + Write> Client<S> {
    // TODO: to enable this we have to find a way to allow concurrent read and writes to the
    // underlying transport struct. This can be done pretty easily for TcpStream because it can be
    // split into a "read" and a "write" object, but it's not as trivial for other types. Without
    // such thing, this causes a deadlock, because the reader thread takes a lock on the
    // `ClonableStream` before other threads can send a request to the server. They will block
    // waiting for the reader to release the mutex, but this will never happen because the server
    // didn't receive any request, so it has nothing to send back.
    // pub fn reader_thread(&self) -> Result<(), Error> {
    //     self._reader_thread(None).map(|_| ())
    // }

    fn _reader_thread(&self, until_message: Option<usize>) -> Result<serde_json::Value, Error> {
        let mut raw_resp = String::new();
        let resp = match self.buf_reader.try_lock() {
            Ok(mut reader) => {
                trace!(
                    "Starting reader thread with `until_message` = {:?}",
                    until_message
                );

                // Loop over every message
                loop {
                    raw_resp.clear();

                    reader.read_line(&mut raw_resp)?;
                    trace!("<== {}", raw_resp);

                    let resp: serde_json::Value = serde_json::from_str(&raw_resp)?;

                    // Normally there is and id, but it's missing for spontaneous notifications
                    // from the server
                    let resp_id = resp["id"]
                        .as_str()
                        .and_then(|s| s.parse().ok())
                        .or(resp["id"].as_u64().map(|i| i as usize));
                    match resp_id {
                        Some(resp_id)
                            if until_message.is_some() && resp_id == until_message.unwrap() =>
                        {
                            // We have a valid id and it's exactly the one we were waiting for!
                            trace!(
                                "Reader thread {} received a response for its request",
                                resp_id
                            );

                            // Remove ourselves from the "waiting map"
                            let mut map = self.waiting_map.lock().unwrap();
                            map.remove(&resp_id);

                            // If the map is not empty, we select a random thread to become the
                            // new reader thread.
                            if !map.is_empty() {
                                map.values()
                                    .nth(0)
                                    .unwrap()
                                    .send(ChannelMessage::WakeUp)
                                    .unwrap(); // TODO: unwrap
                            }

                            break Ok(resp);
                        }
                        Some(resp_id) => {
                            // We have an id, but it's not our response. Notify the thread and
                            // move on
                            trace!("Reader thread received response for {}", resp_id);

                            let mut map = self.waiting_map.lock().unwrap();
                            if map.get(&resp_id).is_some() {
                                map.get(&resp_id)
                                    .unwrap()
                                    .send(ChannelMessage::Response(resp))
                                    .unwrap(); // TODO: unwrap
                                map.remove(&resp_id);
                            } else {
                                warn!("Missing listener for {}", resp_id);
                            }
                        }
                        None => {
                            // No id, that's probably a notification.
                            let mut resp = resp;

                            match resp["method"].take().as_str() {
                                Some(ref method) => {
                                    self.handle_notification(method, resp["params"].take())?
                                }
                                _ => continue,
                            }
                        }
                    }
                }
            }
            Err(TryLockError::WouldBlock) => {
                // If we "WouldBlock" here it means that there's already a reader thread
                // running somewhere.
                Err(Error::CouldntLockReader)
            }
            e @ Err(TryLockError::Poisoned(_)) => e
                .map(|_| Ok(serde_json::Value::Null))
                .expect("Poisoned reader mutex"), // panic if the reader mutex has been poisoned
        };

        let resp = resp?;
        if let Some(err) = resp.get("error") {
            Err(Error::Protocol(err.clone()))
        } else {
            Ok(resp)
        }
    }

    fn call(&self, req: Request) -> Result<serde_json::Value, Error> {
        // Add our listener to the map before we send the request, to make sure we don't get a
        // reply before the receiver is added
        let (sender, receiver) = channel();
        self.waiting_map.lock().unwrap().insert(req.id, sender);

        let mut raw = serde_json::to_vec(&req)?;
        trace!("==> {}", String::from_utf8_lossy(&raw));

        raw.extend_from_slice(b"\n");
        let mut stream = self.stream.lock().unwrap();
        stream.write_all(&raw)?;
        stream.flush()?;
        drop(stream); // release the lock

        self.increment_calls();

        let mut resp = self.recv(&receiver, req.id)?;
        Ok(resp["result"].take())
    }

    /// Execute a queue of calls stored in a [`Batch`](../batch/struct.Batch.html) struct. Returns
    /// `Ok()` **only if** all of the calls are successful. The order of the JSON `Value`s returned
    /// reflects the order in which the calls were made on the `Batch` struct.
    pub fn batch_call(&self, batch: Batch) -> Result<Vec<serde_json::Value>, Error> {
        let mut raw = Vec::new();

        let mut missing_responses = BTreeSet::new();
        let mut answer = Vec::new();

        // Add our listener to the map before we send the request, Here we will clone the sender
        // for every request id, so that we only have to monitor one receiver.
        let (sender, receiver) = channel();

        for (method, params) in batch.into_iter() {
            let req = Request::new_id(self.last_id.fetch_add(1, Ordering::SeqCst), &method, params);
            missing_responses.insert(req.id);

            self.waiting_map
                .lock()
                .unwrap()
                .insert(req.id, sender.clone());

            raw.append(&mut serde_json::to_vec(&req)?);
            raw.extend_from_slice(b"\n");
        }

        if missing_responses.is_empty() {
            return Ok(vec![]);
        }

        trace!("==> {}", String::from_utf8_lossy(&raw));

        let mut stream = self.stream.lock().unwrap();
        stream.write_all(&raw)?;
        stream.flush()?;
        drop(stream); // release the lock

        self.increment_calls();

        while !missing_responses.is_empty() {
            let resp = self.recv(&receiver, *missing_responses.iter().nth(0).unwrap())?;
            let resp_id = resp["id"].as_u64().unwrap() as usize;

            missing_responses.remove(&resp_id);
            answer.push(resp);
        }

        answer.sort_by(|a, b| a["id"].as_u64().partial_cmp(&b["id"].as_u64()).unwrap());
        let answer = answer.into_iter().map(|mut x| x["result"].take()).collect();

        Ok(answer)
    }

    fn recv(
        &self,
        receiver: &Receiver<ChannelMessage>,
        req_id: usize,
    ) -> Result<serde_json::Value, Error> {
        loop {
            // Try to take the lock on the reader. If we manage to do so, we'll become the reader
            // thread until we get our reponse
            match self._reader_thread(Some(req_id)) {
                Ok(response) => break Ok(response),
                Err(Error::CouldntLockReader) => {
                    trace!("CouldntLockReader for {}", req_id);

                    match receiver.recv() {
                        // Received our response, returning it
                        Ok(ChannelMessage::Response(received)) => break Ok(received),
                        Ok(ChannelMessage::WakeUp) => {
                            // We have been woken up, this means that we should try becoming the
                            // reader thread ourselves
                            trace!("WakeUp for {}", req_id);

                            continue;
                        }
                        e @ Err(_) => e.map(|_| ()).expect("Error receiving from channel"), // panic if there's something wrong with the channels
                    }
                }
                e @ Err(_) => break e,
            }
        }
    }

    fn handle_notification(&self, method: &str, result: serde_json::Value) -> Result<(), Error> {
        match method {
            "blockchain.headers.subscribe" => self.headers.lock().unwrap().append(
                &mut serde_json::from_value::<Vec<HeaderNotification>>(result)?
                    .into_iter()
                    .collect(),
            ),
            "blockchain.scripthash.subscribe" => {
                let unserialized: ScriptNotification = serde_json::from_value(result)?;
                let mut script_notifications = self.script_notifications.lock().unwrap();

                let queue = script_notifications
                    .get_mut(&unserialized.scripthash)
                    .ok_or_else(|| Error::NotSubscribed(unserialized.scripthash))?;

                queue.push_back(unserialized.status);
            }
            _ => info!("received unknown notification for method `{}`", method),
        }

        Ok(())
    }

    /// Subscribes to notifications for new block headers, by sending a `blockchain.headers.subscribe` call.
    pub fn block_headers_subscribe(&self) -> Result<HeaderNotification, Error> {
        let req = Request::new_id(
            self.last_id.fetch_add(1, Ordering::SeqCst),
            "blockchain.headers.subscribe",
            vec![],
        );
        let value = self.call(req)?;

        Ok(serde_json::from_value(value)?)
    }

    /// Tries to pop one queued notification for a new block header that we might have received.
    /// Returns `None` if there are no items in the queue.
    pub fn block_headers_pop(&self) -> Result<Option<HeaderNotification>, Error> {
        Ok(self.headers.lock().unwrap().pop_front())
    }

    /// Gets the block header for height `height`.
    pub fn block_header(&self, height: usize) -> Result<BlockHeader, Error> {
        Ok(deserialize(&self.block_header_raw(height)?)?)
    }

    /// Gets the raw bytes of block header for height `height`.
    pub fn block_header_raw(&self, height: usize) -> Result<Vec<u8>, Error> {
        let req = Request::new_id(
            self.last_id.fetch_add(1, Ordering::SeqCst),
            "blockchain.block.header",
            vec![Param::Usize(height)],
        );
        let result = self.call(req)?;

        Ok(Vec::<u8>::from_hex(
            result
                .as_str()
                .ok_or_else(|| Error::InvalidResponse(result.clone()))?,
        )?)
    }

    /// Tries to fetch `count` block headers starting from `start_height`.
    pub fn block_headers(&self, start_height: usize, count: usize) -> Result<GetHeadersRes, Error> {
        let req = Request::new_id(
            self.last_id.fetch_add(1, Ordering::SeqCst),
            "blockchain.block.headers",
            vec![Param::Usize(start_height), Param::Usize(count)],
        );
        let result = self.call(req)?;

        let mut deserialized: GetHeadersRes = serde_json::from_value(result)?;
        for i in 0..deserialized.count {
            let (start, end) = (i * 80, (i + 1) * 80);
            deserialized
                .headers
                .push(deserialize(&deserialized.raw_headers[start..end])?);
        }
        deserialized.raw_headers.clear();

        Ok(deserialized)
    }

    /// Estimates the fee required in **Satoshis per kilobyte** to confirm a transaction in `number` blocks.
    pub fn estimate_fee(&self, number: usize) -> Result<f64, Error> {
        let req = Request::new_id(
            self.last_id.fetch_add(1, Ordering::SeqCst),
            "blockchain.estimatefee",
            vec![Param::Usize(number)],
        );
        let result = self.call(req)?;

        result
            .as_f64()
            .ok_or_else(|| Error::InvalidResponse(result.clone()))
    }

    /// Returns the minimum accepted fee by the server's node in **Bitcoin, not Satoshi**.
    pub fn relay_fee(&self) -> Result<f64, Error> {
        let req = Request::new_id(
            self.last_id.fetch_add(1, Ordering::SeqCst),
            "blockchain.relayfee",
            vec![],
        );
        let result = self.call(req)?;

        result
            .as_f64()
            .ok_or_else(|| Error::InvalidResponse(result.clone()))
    }

    /// Subscribes to notifications for activity on a specific *scriptPubKey*.
    ///
    /// Returns a [`ScriptStatus`](../types/type.ScriptStatus.html) when successful that represents
    /// the current status for the requested script.
    ///
    /// Returns [`Error::AlreadySubscribed`](../types/enum.Error.html#variant.AlreadySubscribed) if
    /// already subscribed to the same script.
    pub fn script_subscribe(&self, script: &Script) -> Result<ScriptStatus, Error> {
        let script_hash = script.to_electrum_scripthash();
        let mut script_notifications = self.script_notifications.lock().unwrap();

        if script_notifications.contains_key(&script_hash) {
            return Err(Error::AlreadySubscribed(script_hash));
        }

        script_notifications.insert(script_hash.clone(), VecDeque::new());

        let req = Request::new_id(
            self.last_id.fetch_add(1, Ordering::SeqCst),
            "blockchain.scripthash.subscribe",
            vec![Param::String(script_hash.to_hex())],
        );
        let value = self.call(req)?;

        Ok(serde_json::from_value(value)?)
    }

    /// Subscribes to notifications for activity on a specific *scriptPubKey*.
    ///
    /// Returns a `bool` with the server response when successful.
    ///
    /// Returns [`Error::NotSubscribed`](../types/enum.Error.html#variant.NotSubscribed) if
    /// not subscribed to the script.
    pub fn script_unsubscribe(&self, script: &Script) -> Result<bool, Error> {
        let script_hash = script.to_electrum_scripthash();
        let mut script_notifications = self.script_notifications.lock().unwrap();

        if !script_notifications.contains_key(&script_hash) {
            return Err(Error::NotSubscribed(script_hash));
        }

        let req = Request::new_id(
            self.last_id.fetch_add(1, Ordering::SeqCst),
            "blockchain.scripthash.unsubscribe",
            vec![Param::String(script_hash.to_hex())],
        );
        let value = self.call(req)?;
        let answer = serde_json::from_value(value)?;

        script_notifications.remove(&script_hash);

        Ok(answer)
    }

    /// Tries to pop one queued notification for a the requested script. Returns `None` if there are no items in the queue.
    pub fn script_pop(&mut self, script: &Script) -> Result<Option<ScriptStatus>, Error> {
        let script_hash = script.to_electrum_scripthash();

        match self
            .script_notifications
            .lock()
            .unwrap()
            .get_mut(&script_hash)
        {
            None => Err(Error::NotSubscribed(script_hash)),
            Some(queue) => Ok(queue.pop_front()),
        }
    }

    /// Returns the balance for a *scriptPubKey*
    pub fn script_get_balance(&self, script: &Script) -> Result<GetBalanceRes, Error> {
        let params = vec![Param::String(script.to_electrum_scripthash().to_hex())];
        let req = Request::new_id(
            self.last_id.fetch_add(1, Ordering::SeqCst),
            "blockchain.scripthash.get_balance",
            params,
        );
        let result = self.call(req)?;

        Ok(serde_json::from_value(result)?)
    }
    /// Batch version of [`script_get_balance`](#method.script_get_balance).
    ///
    /// Takes a list of scripts and returns a list of balance responses.
    pub fn batch_script_get_balance<'s, I>(&self, scripts: I) -> Result<Vec<GetBalanceRes>, Error>
    where
        I: IntoIterator<Item = &'s Script>,
    {
        impl_batch_call!(self, scripts, script_get_balance)
    }

    /// Returns the history for a *scriptPubKey*
    pub fn script_get_history(&self, script: &Script) -> Result<Vec<GetHistoryRes>, Error> {
        let params = vec![Param::String(script.to_electrum_scripthash().to_hex())];
        let req = Request::new_id(
            self.last_id.fetch_add(1, Ordering::SeqCst),
            "blockchain.scripthash.get_history",
            params,
        );
        let result = self.call(req)?;

        Ok(serde_json::from_value(result)?)
    }
    /// Batch version of [`script_get_history`](#method.script_get_history).
    ///
    /// Takes a list of scripts and returns a list of history responses.
    pub fn batch_script_get_history<'s, I>(
        &self,
        scripts: I,
    ) -> Result<Vec<Vec<GetHistoryRes>>, Error>
    where
        I: IntoIterator<Item = &'s Script>,
    {
        impl_batch_call!(self, scripts, script_get_history)
    }

    /// Returns the list of unspent outputs for a *scriptPubKey*
    pub fn script_list_unspent(&self, script: &Script) -> Result<Vec<ListUnspentRes>, Error> {
        let params = vec![Param::String(script.to_electrum_scripthash().to_hex())];
        let req = Request::new_id(
            self.last_id.fetch_add(1, Ordering::SeqCst),
            "blockchain.scripthash.listunspent",
            params,
        );
        let result = self.call(req)?;

        Ok(serde_json::from_value(result)?)
    }

    /// Batch version of [`script_list_unspent`](#method.script_list_unspent).
    ///
    /// Takes a list of scripts and returns a list of a list of utxos.
    pub fn batch_script_list_unspent<'s, I>(
        &self,
        scripts: I,
    ) -> Result<Vec<Vec<ListUnspentRes>>, Error>
    where
        I: IntoIterator<Item = &'s Script>,
    {
        impl_batch_call!(self, scripts, script_list_unspent)
    }

    /// Gets the transaction with `txid`. Returns an error if not found.
    pub fn transaction_get(&self, txid: &Txid) -> Result<Transaction, Error> {
        Ok(deserialize(&self.transaction_get_raw(txid)?)?)
    }

    /// Gets the raw bytes of a transaction with `txid`. Returns an error if not found.
    pub fn transaction_get_raw(&self, txid: &Txid) -> Result<Vec<u8>, Error> {
        let params = vec![Param::String(txid.to_hex())];
        let req = Request::new_id(
            self.last_id.fetch_add(1, Ordering::SeqCst),
            "blockchain.transaction.get",
            params,
        );
        let result = self.call(req)?;

        Ok(Vec::<u8>::from_hex(
            result
                .as_str()
                .ok_or_else(|| Error::InvalidResponse(result.clone()))?,
        )?)
    }

    /// Batch version of [`transaction_get`](#method.transaction_get).
    ///
    /// Takes a list of `txids` and returns a list of transactions.
    pub fn batch_transaction_get<'t, I>(&self, txids: I) -> Result<Vec<Transaction>, Error>
    where
        I: IntoIterator<Item = &'t Txid>,
    {
        self.batch_transaction_get_raw(txids)?
            .iter()
            .map(|s| Ok(deserialize(s)?))
            .collect()
    }

    /// Batch version of [`transaction_get_raw`](#method.transaction_get_raw).
    ///
    /// Takes a list of `txids` and returns a list of transactions raw bytes.
    pub fn batch_transaction_get_raw<'t, I>(&self, txids: I) -> Result<Vec<Vec<u8>>, Error>
    where
        I: IntoIterator<Item = &'t Txid>,
    {
        let txs_string: Result<Vec<String>, Error> = impl_batch_call!(self, txids, transaction_get);
        txs_string?
            .iter()
            .map(|s| Ok(Vec::<u8>::from_hex(s)?))
            .collect()
    }

    /// Batch version of [`block_header_raw`](#method.block_header_raw).
    ///
    /// Takes a list of `heights` of blocks and returns a list of block header raw bytes.
    pub fn batch_block_header_raw<'s, I>(&self, heights: I) -> Result<Vec<Vec<u8>>, Error>
    where
        I: IntoIterator<Item = u32>,
    {
        let headers_string: Result<Vec<String>, Error> =
            impl_batch_call!(self, heights, block_header);
        headers_string?
            .iter()
            .map(|s| Ok(Vec::<u8>::from_hex(s)?))
            .collect()
    }

    /// Batch version of [`block_header`](#method.block_header).
    ///
    /// Takes a list of `heights` of blocks and returns a list of headers.
    pub fn batch_block_header<'s, I>(&self, heights: I) -> Result<Vec<BlockHeader>, Error>
    where
        I: IntoIterator<Item = u32>,
    {
        self.batch_block_header_raw(heights)?
            .iter()
            .map(|s| Ok(deserialize(s)?))
            .collect()
    }

    /// Batch version of [`estimate_fee`](#method.estimate_fee).
    ///
    /// Takes a list of `numbers` of blocks and returns a list of fee required in
    /// **Satoshis per kilobyte** to confirm a transaction in the given number of blocks.
    pub fn batch_estimate_fee<'s, I>(&self, numbers: I) -> Result<Vec<f64>, Error>
    where
        I: IntoIterator<Item = usize>,
    {
        impl_batch_call!(self, numbers, estimate_fee)
    }

    /// Broadcasts the raw bytes of a transaction to the network.
    pub fn transaction_broadcast_raw(&self, raw_tx: &[u8]) -> Result<Txid, Error> {
        let params = vec![Param::String(raw_tx.to_hex())];
        let req = Request::new_id(
            self.last_id.fetch_add(1, Ordering::SeqCst),
            "blockchain.transaction.broadcast",
            params,
        );
        let result = self.call(req)?;

        Ok(serde_json::from_value(result)?)
    }

    /// Broadcasts a transaction to the network.
    pub fn transaction_broadcast(&self, tx: &Transaction) -> Result<Txid, Error> {
        let buffer: Vec<u8> = serialize(tx);
        self.transaction_broadcast_raw(&buffer)
    }

    /// Returns the merkle path for the transaction `txid` confirmed in the block at `height`.
    pub fn transaction_get_merkle(
        &self,
        txid: &Txid,
        height: usize,
    ) -> Result<GetMerkleRes, Error> {
        let params = vec![Param::String(txid.to_hex()), Param::Usize(height)];
        let req = Request::new_id(
            self.last_id.fetch_add(1, Ordering::SeqCst),
            "blockchain.transaction.get_merkle",
            params,
        );
        let result = self.call(req)?;

        Ok(serde_json::from_value(result)?)
    }

    /// Returns the capabilities of the server.
    pub fn server_features(&self) -> Result<ServerFeaturesRes, Error> {
        let req = Request::new_id(
            self.last_id.fetch_add(1, Ordering::SeqCst),
            "server.features",
            vec![],
        );
        let result = self.call(req)?;

        Ok(serde_json::from_value(result)?)
    }

    #[cfg(feature = "debug-calls")]
    /// Returns the number of network calls made since the creation of the client.
    pub fn calls_made(&self) -> usize {
        self.calls
    }

    #[inline]
    #[cfg(feature = "debug-calls")]
    fn increment_calls(&mut self) {
        self.calls += 1;
    }

    #[inline]
    #[cfg(not(feature = "debug-calls"))]
    fn increment_calls(&self) {}
}

#[cfg(test)]
mod test {
    use std::fs::File;
    use std::io::Read;
    use test_stream::TestStream;

    use client::Client;

    impl Client<TestStream> {
        pub fn new_test(file: File) -> Self {
            TestStream::new(file).into()
        }
    }

    macro_rules! impl_test_prelude {
        ( $testcase:expr ) => {{
            let data_in = File::open(format!("./test_data/{}.in", $testcase)).unwrap();
            Client::new_test(data_in)
        }};
    }

    macro_rules! impl_test_conclusion {
        ( $testcase:expr, $stream:expr ) => {
            let mut data_out = File::open(format!("./test_data/{}.out", $testcase)).unwrap();
            let mut buffer = Vec::new();
            data_out.read_to_end(&mut buffer).unwrap();
            let stream_buffer = $stream.stream().lock().unwrap().buffer.clone();

            assert_eq!(
                stream_buffer,
                buffer,
                "Expecting `{}`, got `{}`",
                String::from_utf8_lossy(&buffer.to_vec()),
                String::from_utf8_lossy(&stream_buffer)
            );
        };
    }

    #[test]
    fn test_server_features_simple() {
        let test_case = "server_features_simple";
        let mut client = impl_test_prelude!(test_case);

        let resp = client.server_features().unwrap();
        assert_eq!(resp.server_version, "ElectrumX 1.0.17");
        assert_eq!(
            resp.genesis_hash,
            [
                0x00, 0x00, 0x00, 0x00, 0x09, 0x33, 0xEA, 0x01, 0xAD, 0x0E, 0xE9, 0x84, 0x20, 0x97,
                0x79, 0xBA, 0xAE, 0xC3, 0xCE, 0xD9, 0x0F, 0xA3, 0xF4, 0x08, 0x71, 0x95, 0x26, 0xF8,
                0xD7, 0x7F, 0x49, 0x43
            ]
        );
        assert_eq!(resp.protocol_min, "1.0");
        assert_eq!(resp.protocol_max, "1.0");
        assert_eq!(resp.hash_function, Some("sha256".into()));
        assert_eq!(resp.pruning, None);

        impl_test_conclusion!(test_case, client.stream);
    }
    #[test]
    fn test_relay_fee() {
        let test_case = "relay_fee";
        let mut client = impl_test_prelude!(test_case);

        let resp = client.relay_fee().unwrap();
        assert_eq!(resp, 123.4);

        impl_test_conclusion!(test_case, client.stream);
    }

    #[test]
    fn test_estimate_fee() {
        let test_case = "estimate_fee";
        let mut client = impl_test_prelude!(test_case);

        let resp = client.estimate_fee(10).unwrap();
        assert_eq!(resp, 10.0);

        impl_test_conclusion!(test_case, client.stream);
    }

    #[test]
    fn test_block_header() {
        let test_case = "block_header";
        let mut client = impl_test_prelude!(test_case);

        let resp = client.block_header(500).unwrap();
        assert_eq!(resp.version, 536870912);
        assert_eq!(resp.time, 1578166214);
        assert_eq!(resp.nonce, 0);

        impl_test_conclusion!(test_case, client.stream);
    }

    #[test]
    fn test_block_headers() {
        let test_case = "block_headers";
        let mut client = impl_test_prelude!(test_case);

        let resp = client.block_headers(100, 4).unwrap();
        assert_eq!(resp.count, 4);
        assert_eq!(resp.max, 2016);
        assert_eq!(resp.headers.len(), 4);

        assert_eq!(resp.headers[0].time, 1563694949);

        impl_test_conclusion!(test_case, client.stream);
    }

    #[test]
    fn test_script_get_balance() {
        use std::str::FromStr;

        let test_case = "script_get_balance";
        let mut client = impl_test_prelude!(test_case);

        let addr = bitcoin::Address::from_str("2N1xJCxBUXTDs6y8Sydz3axhAiXrrQwcosi").unwrap();
        let resp = client.script_get_balance(&addr.script_pubkey()).unwrap();
        assert_eq!(resp.confirmed, 0);
        assert_eq!(resp.unconfirmed, 130000000);

        impl_test_conclusion!(test_case, client.stream);
    }

    #[test]
    fn test_script_get_history() {
        use std::str::FromStr;

        use bitcoin::hashes::hex::FromHex;
        use bitcoin::Txid;

        let test_case = "script_get_history";
        let mut client = impl_test_prelude!(test_case);

        let addr = bitcoin::Address::from_str("2N1xJCxBUXTDs6y8Sydz3axhAiXrrQwcosi").unwrap();
        let resp = client.script_get_history(&addr.script_pubkey()).unwrap();
        assert_eq!(resp.len(), 2);
        assert_eq!(
            resp[0].tx_hash,
            Txid::from_hex("a1aa2b52fb79641f918d44a27f51781c3c0c49f7ee0e4b14dbb37c722853f046")
                .unwrap()
        );

        impl_test_conclusion!(test_case, client.stream);
    }

    #[test]
    fn test_script_list_unspent() {
        use std::str::FromStr;

        use bitcoin::hashes::hex::FromHex;
        use bitcoin::Txid;

        let test_case = "script_list_unspent";
        let mut client = impl_test_prelude!(test_case);

        let addr = bitcoin::Address::from_str("2N1xJCxBUXTDs6y8Sydz3axhAiXrrQwcosi").unwrap();
        let resp = client.script_list_unspent(&addr.script_pubkey()).unwrap();
        assert_eq!(resp.len(), 2);
        assert_eq!(resp[0].value, 30000000);
        assert_eq!(resp[0].height, 0);
        assert_eq!(resp[0].tx_pos, 1);
        assert_eq!(
            resp[0].tx_hash,
            Txid::from_hex("a1aa2b52fb79641f918d44a27f51781c3c0c49f7ee0e4b14dbb37c722853f046")
                .unwrap()
        );

        impl_test_conclusion!(test_case, client.stream);
    }

    #[test]
    fn test_batch_script_list_unspent() {
        use std::str::FromStr;

        let test_case = "batch_script_list_unspent";
        let mut client = impl_test_prelude!(test_case);

        let script_1 = bitcoin::Address::from_str("2N1xJCxBUXTDs6y8Sydz3axhAiXrrQwcosi")
            .unwrap()
            .script_pubkey();
        let script_2 = bitcoin::Address::from_str("2MyEi7dbTfQxo1M4hJaAzA2tgEJFQhYv5Au")
            .unwrap()
            .script_pubkey();

        let resp = client
            .batch_script_list_unspent(vec![&script_1, &script_2])
            .unwrap();
        assert_eq!(resp.len(), 2);
        assert_eq!(resp[0].len(), 2);
        assert_eq!(resp[1].len(), 1);

        impl_test_conclusion!(test_case, client.stream);
    }

    #[test]
    fn test_batch_estimate_fee() {
        let test_case = "batch_estimate_fee";
        let mut client = impl_test_prelude!(test_case);

        let resp = client.batch_estimate_fee(vec![10, 20]).unwrap();
        assert_eq!(resp[0], 10.0);
        assert_eq!(resp[1], 20.0);

        impl_test_conclusion!(test_case, client.stream);
    }

    #[test]
    fn test_transaction_get() {
        use bitcoin::hashes::hex::FromHex;
        use bitcoin::Txid;

        let test_case = "transaction_get";
        let mut client = impl_test_prelude!(test_case);

        let resp = client
            .transaction_get(
                &Txid::from_hex("a1aa2b52fb79641f918d44a27f51781c3c0c49f7ee0e4b14dbb37c722853f046")
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(resp.version, 2);
        assert_eq!(resp.lock_time, 1376);

        impl_test_conclusion!(test_case, client.stream);
    }

    #[test]
    fn test_transaction_broadcast() {
        use bitcoin::consensus::deserialize;
        use bitcoin::hashes::hex::FromHex;
        use bitcoin::Txid;

        let test_case = "transaction_broadcast";
        let mut client = impl_test_prelude!(test_case);

        let buf = Vec::<u8>::from_hex("02000000000101f6cd5873d669cc2de550453623d9d10ed5b5ba906d81160ee3ab853ebcfffa0c0100000000feffffff02e22f82000000000017a914e229870f3af1b1a3aefc3452a4d2939b443e6eba8780c3c9010000000017a9145f859501ff79211aeb972633b782743dd3b31dab8702473044022046ff3b0618107e08bd25fb753e31542b8c23575d7e9faf43dd17f59727cfb9c902200a4f3837105808d810de01fcd63fb18e66a69026090dc72b66840d41e55c6bf3012103e531113bbca998f8d164235e3395db336d3ba03552d1bfaa83fd7cffe6e5c6c960050000").unwrap();
        let tx: bitcoin::Transaction = deserialize(&buf).unwrap();

        let resp = client.transaction_broadcast(&tx).unwrap();
        assert_eq!(
            resp,
            Txid::from_hex("a1aa2b52fb79641f918d44a27f51781c3c0c49f7ee0e4b14dbb37c722853f046")
                .unwrap()
        );

        impl_test_conclusion!(test_case, client.stream);
    }

    #[test]
    fn test_transaction_get_merkle() {
        use bitcoin::hashes::hex::FromHex;
        use bitcoin::Txid;

        let test_case = "transaction_get_merkle";
        let mut client = impl_test_prelude!(test_case);

        let resp = client
            .transaction_get_merkle(
                &Txid::from_hex("2d64851151550e8c4d337f335ee28874401d55b358a66f1bafab2c3e9f48773d")
                    .unwrap(),
                1234,
            )
            .unwrap();
        assert_eq!(resp.block_height, 450538);
        assert_eq!(resp.pos, 710);
        assert_eq!(resp.merkle.len(), 11);
        assert_eq!(
            resp.merkle[0],
            [
                0x71, 0x3D, 0x6C, 0x7E, 0x6C, 0xE7, 0xBB, 0xEA, 0x70, 0x8D, 0x61, 0x16, 0x22, 0x31,
                0xEA, 0xA8, 0xEC, 0xB3, 0x1C, 0x4C, 0x5D, 0xD8, 0x4F, 0x81, 0xC2, 0x04, 0x09, 0xA9,
                0x00, 0x69, 0xCB, 0x24
            ]
        );

        impl_test_conclusion!(test_case, client.stream);
    }
}
