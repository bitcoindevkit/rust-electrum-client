//! Electrum client
//!
//! This module contains definition of the main Client structure

use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;

use futures::task;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{
    split, AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader,
    ReadHalf, WriteHalf,
};
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio::runtime::{Builder as RuntimeBuilder, Runtime};

#[allow(unused_imports)]
use log::{debug, error, info, trace};

use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hashes::hex::{FromHex, ToHex};
use bitcoin::{BlockHeader, Script, Transaction, Txid};

#[cfg(any(feature = "default", feature = "tls"))]
use native_tls::TlsConnector;
#[cfg(any(feature = "default", feature = "tls"))]
use tokio_tls::TlsStream;

#[cfg(any(feature = "default", feature = "proxy"))]
use tokio_socks::{tcp::Socks5Stream, IntoTargetAddr, ToProxyAddrs};

use crate::batch::Batch;
use crate::types::*;

#[cfg(not(feature = "no-sync"))]
lazy_static! {
    static ref INTERNAL_RUNTIME: Mutex<Runtime> = Mutex::new(
        RuntimeBuilder::new()
            .basic_scheduler()
            .enable_all()
            .build()
            .expect("Couldn't create the internal tokio runtime")
    );
}

macro_rules! impl_batch_call {
    ( $self:expr, $data:expr, $call:ident ) => {{
        let mut batch = Batch::default();
        for i in $data {
            batch.$call(i);
        }

        let resp = $self.batch_call(batch).await?;
        let mut answer = Vec::new();

        for x in resp {
            answer.push(serde_json::from_value(x)?);
        }

        Ok(answer)
    }};
}

macro_rules! impl_sync_version {
    ( $doc:expr, $wrapped:ident, $new_name:ident, $return:ty, $( $arg:ident:$type:ty ),* ) => {
        #[doc=$doc]
        #[cfg(not(feature = "no-sync"))]
        pub fn $new_name(&mut self, $($arg:$type),*) -> $return {
             INTERNAL_RUNTIME.lock().expect("Couldn't lock on the internal runtime mutex").block_on(self.$wrapped($($arg),*))
        }
    };

    ( $iter_item:ty, $doc:expr, $wrapped:ident, $new_name:ident, $return:ty, $( $arg:ident:$type:ty ),* ) => {
        #[doc=$doc]
        #[cfg(not(feature = "no-sync"))]
        pub fn $new_name<'a, I>(&mut self, $($arg:$type),*) -> $return
        where
            I: IntoIterator<Item = $iter_item>
        {
             INTERNAL_RUNTIME.lock().expect("Couldn't lock on the internal runtime mutex").block_on(self.$wrapped($($arg),*))
        }
    };

    ( $lifetime:tt, $iter_item:ty, $doc:expr, $wrapped:ident, $new_name:ident, $return:ty, $( $arg:ident:$type:ty ),* ) => {
        #[doc=$doc]
        #[cfg(not(feature = "no-sync"))]
        pub fn $new_name<'a, I>(&mut self, $($arg:$type),*) -> $return
        where
            I: IntoIterator<Item = &'a $iter_item>
        {
             INTERNAL_RUNTIME.lock().expect("Couldn't lock on the internal runtime mutex").block_on(self.$wrapped($($arg),*))
        }
    };

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
    S: AsyncRead + AsyncWrite,
{
    writer: WriteHalf<S>,
    buf_reader: BufReader<ReadHalf<S>>,

    headers: VecDeque<HeaderNotification>,
    script_notifications: BTreeMap<ScriptHash, VecDeque<ScriptStatus>>,

    #[cfg(feature = "debug-calls")]
    calls: usize,
}

impl<S> From<S> for Client<S>
where
    S: AsyncRead + AsyncWrite,
{
    fn from(stream: S) -> Self {
        let (read, write) = split(stream);

        Self {
            writer: write,
            buf_reader: BufReader::new(read),

            headers: VecDeque::new(),
            script_notifications: BTreeMap::new(),

            #[cfg(feature = "debug-calls")]
            calls: 0,
        }
    }
}

/// Transport type used to establish a plaintext TCP connection with the server
pub type ElectrumPlaintextStream = TcpStream;
impl Client<ElectrumPlaintextStream> {
    /// Creates a new plaintext client and tries to connect to `socket_addr`.
    pub async fn new<A: ToSocketAddrs>(socket_addr: A) -> Result<Self, Error> {
        let stream = TcpStream::connect(socket_addr).await?;

        Ok(stream.into())
    }

    /// Synchronous constructor. Creates a new plaintext client and tries to connect to `socket_addr`.
    #[cfg(not(feature = "no-sync"))]
    pub fn sync_new<A: ToSocketAddrs>(socket_addr: A) -> Result<Self, Error> {
        INTERNAL_RUNTIME
            .lock()
            .expect("Couldn't lock on the internal runtime mutex")
            .block_on(Self::new(socket_addr))
    }
}

#[cfg(any(feature = "default", feature = "tls"))]
/// Transport type used to establish a TLS encrypted/authenticated connection with the server
pub type ElectrumTlsStream = TlsStream<TcpStream>;
#[cfg(any(feature = "default", feature = "tls"))]
impl Client<ElectrumTlsStream> {
    /// Creates a new TLS client and tries to connect to `socket_addr`. Optionally, if
    /// `validate_domain` is `true`, validate the server's certificate.
    pub async fn new_tls<A: ToSocketAddrsDomain>(
        socket_addr: A,
        validate_domain: bool,
    ) -> Result<Self, Error> {
        let connector = TlsConnector::builder()
            .danger_accept_invalid_certs(!validate_domain)
            .build()?;
        let connector: tokio_tls::TlsConnector = connector.into();

        let domain = socket_addr.domain().unwrap_or("NONE").to_string();
        let stream = TcpStream::connect(socket_addr).await?;
        let stream = connector.connect(&domain, stream).await?;

        Ok(stream.into())
    }

    /// Synchronous constructor. Creates a new TLS client and tries to connect to `socket_addr`. Optionally, if
    /// `validate_domain` is `true`, validate the server's certificate.
    #[cfg(not(feature = "no-sync"))]
    pub fn sync_new_tls<A: ToSocketAddrsDomain>(
        socket_addr: A,
        validate_domain: bool,
    ) -> Result<Self, Error> {
        INTERNAL_RUNTIME
            .lock()
            .expect("Couldn't lock on the internal runtime mutex")
            .block_on(Self::new_tls(socket_addr, validate_domain))
    }
}

#[cfg(any(feature = "default", feature = "proxy"))]
/// Transport type used to establish a connection to a server through a socks proxy
pub type ElectrumProxyStream = Socks5Stream;
#[cfg(any(feature = "default", feature = "proxy"))]
impl Client<ElectrumProxyStream> {
    /// Creates a new socks client and tries to connect to `target_addr` using `proxy_addr` as an
    /// unauthenticated socks proxy server. The DNS resolution of `target_addr`, if necessary, is done
    /// through the proxy. This allows to specify, for instance, `.onion` addresses.
    pub async fn new_proxy<'t, A: ToProxyAddrs, T: IntoTargetAddr<'t>>(
        target_addr: T,
        proxy_addr: A,
    ) -> Result<Self, Error> {
        let stream = Socks5Stream::connect(proxy_addr, target_addr).await?;

        Ok(stream.into())
    }

    /// Creates a new socks client and connects to the proxy server using the provided `username`
    /// and `password`. Alternative to [`new_proxy`](#method.new_proxy)
    pub async fn new_proxy_with_credentials<'t, A: ToProxyAddrs, T: IntoTargetAddr<'t>>(
        target_addr: T,
        proxy_addr: A,
        username: &str,
        password: &str,
    ) -> Result<Self, Error> {
        let stream =
            Socks5Stream::connect_with_password(proxy_addr, target_addr, username, password)
                .await?;

        Ok(stream.into())
    }

    /// Synchronous constructor. Creates a new socks client and tries to connect to `target_addr` using
    /// `proxy_addr` as an unauthenticated socks proxy server. The DNS resolution of `target_addr`, if
    /// necessary, is done through the proxy. This allows to specify, for instance, `.onion` addresses.
    #[cfg(not(feature = "no-sync"))]
    pub fn sync_new_proxy<'t, A: ToProxyAddrs, T: IntoTargetAddr<'t>>(
        target_addr: T,
        proxy_addr: A,
    ) -> Result<Self, Error> {
        INTERNAL_RUNTIME
            .lock()
            .expect("Couldn't lock on the internal runtime mutex")
            .block_on(Self::new_proxy(target_addr, proxy_addr))
    }

    /// Synchronous version of [`new_proxy_with_credentials`](#method.new_proxy_with_credentials)
    #[cfg(not(feature = "no-sync"))]
    pub fn sync_new_proxy_with_credentials<'t, A: ToProxyAddrs, T: IntoTargetAddr<'t>>(
        target_addr: T,
        proxy_addr: A,
        username: &str,
        password: &str,
    ) -> Result<Self, Error> {
        INTERNAL_RUNTIME
            .lock()
            .expect("Couldn't lock on the internal runtime mutex")
            .block_on(Self::new_proxy_with_credentials(
                target_addr,
                proxy_addr,
                username,
                password,
            ))
    }
}

impl<S: AsyncRead + AsyncWrite> Client<S> {
    async fn call<'a>(&mut self, req: Request<'a>) -> Result<serde_json::Value, Error> {
        let mut raw = serde_json::to_vec(&req)?;
        trace!("==> {}", String::from_utf8_lossy(&raw));

        raw.extend_from_slice(b"\n");
        self.writer.write_all(&raw).await?;

        self.increment_calls();

        let mut resp = loop {
            let raw = self.recv().await?;
            let mut resp: serde_json::Value = serde_json::from_slice(&raw)?;

            match resp["method"].take().as_str() {
                Some(ref method) if method == &req.method => break resp,
                Some(ref method) => self.handle_notification(method, resp["result"].take())?,
                _ => break resp,
            };
        };

        if let Some(err) = resp.get("error") {
            return Err(Error::Protocol(err.clone()));
        }

        Ok(resp["result"].take())
    }

    /// Execute a queue of calls stored in a [`Batch`](../batch/struct.Batch.html) struct. Returns
    /// `Ok()` **only if** all of the calls are successful. The order of the JSON `Value`s returned
    /// reflects the order in which the calls were made on the `Batch` struct.
    pub async fn batch_call(&mut self, batch: Batch) -> Result<Vec<serde_json::Value>, Error> {
        let mut id_map = BTreeMap::new();
        let mut raw = Vec::new();
        let mut answer = Vec::new();

        for (i, (method, params)) in batch.into_iter().enumerate() {
            let req = Request::new_id(i, &method, params);

            raw.append(&mut serde_json::to_vec(&req)?);
            raw.extend_from_slice(b"\n");

            id_map.insert(req.id, method);
        }

        trace!("==> {}", String::from_utf8_lossy(&raw));

        self.writer.write_all(&raw).await?;

        self.increment_calls();

        while answer.len() < id_map.len() {
            let raw = self.recv().await?;
            let mut resp: serde_json::Value = serde_json::from_slice(&raw)?;

            let resp = match resp["id"].as_u64() {
                Some(id) if id_map.contains_key(&(id as usize)) => resp,
                _ => {
                    self.handle_notification(
                        resp["method"].take().as_str().unwrap_or(""),
                        resp["result"].take(),
                    )?;
                    continue;
                }
            };

            if let Some(err) = resp.get("error") {
                return Err(Error::Protocol(err.clone()));
            }

            answer.push(resp.clone());
        }

        answer.sort_by(|a, b| a["id"].as_u64().partial_cmp(&b["id"].as_u64()).unwrap());

        let answer = answer.into_iter().map(|mut x| x["result"].take()).collect();
        Ok(answer)
    }
    impl_sync_version!(
        "Synchronous version of [`batch_call`](#method.batch_call).",
        batch_call,
        sync_batch_call,
        Result<Vec<serde_json::Value>, Error>,
        batch: Batch
    );

    async fn recv(&mut self) -> Result<Vec<u8>, Error> {
        let mut resp = String::new();
        if self.buf_reader.read_line(&mut resp).await? == 0 {
            return Err(Error::EOF);
        }

        trace!("<== {}", resp);

        Ok(resp.as_bytes().to_vec())
    }

    fn handle_notification(
        &mut self,
        method: &str,
        result: serde_json::Value,
    ) -> Result<(), Error> {
        match method {
            "blockchain.headers.subscribe" => {
                self.headers.push_back(serde_json::from_value(result)?)
            }
            "blockchain.scripthash.subscribe" => {
                let unserialized: ScriptNotification = serde_json::from_value(result)?;

                let queue = self
                    .script_notifications
                    .get_mut(&unserialized.scripthash)
                    .ok_or_else(|| Error::NotSubscribed(unserialized.scripthash))?;

                queue.push_back(unserialized.status);
            }
            _ => info!("received unknown notification for method `{}`", method),
        }

        Ok(())
    }

    fn internal_buf_reader_poll(&mut self) -> Result<Vec<u8>, Error> {
        // try to pull data from the stream
        let pin_buf_reader = Pin::new(&mut self.buf_reader);
        let mut ctx = Context::from_waker(task::noop_waker_ref());
        match pin_buf_reader.poll_fill_buf(&mut ctx) {
            Poll::Ready(Ok(data)) if data.is_empty() => Err(Error::EOF),
            Poll::Ready(Ok(data)) => Ok(data.into()),
            Poll::Ready(Err(e)) => Err(e.into()),
            _ => Ok(vec![]),
        }
    }

    /// Tries to read from the read buffer if any notifications were received since the last call
    /// or `poll`, and processes them. Returns the number of notifications queued when successful.
    pub fn poll(&mut self) -> Result<usize, Error> {
        let data = self.internal_buf_reader_poll()?;
        if data.is_empty() {
            return Ok(0);
        }

        let mut consumed_bytes = 0;
        let mut notifications = 0;
        for raw in data.split(|byte| *byte == '\n' as u8) {
            consumed_bytes += raw.len() + 1;
            notifications += 1;

            let mut resp: serde_json::Value = serde_json::from_slice(raw)?;

            match resp["method"].take().as_str() {
                Some(ref method) => self.handle_notification(method, resp["params"].take())?,
                _ => continue,
            }
        }

        let pin_buf_reader = Pin::new(&mut self.buf_reader);
        pin_buf_reader.consume(consumed_bytes);

        Ok(notifications)
    }

    /// Subscribes to notifications for new block headers, by sending a `blockchain.headers.subscribe` call.
    pub async fn block_headers_subscribe(&mut self) -> Result<HeaderNotification, Error> {
        let req = Request::new("blockchain.headers.subscribe", vec![]);
        let value = self.call(req).await?;

        Ok(serde_json::from_value(value)?)
    }
    impl_sync_version!("Synchronous version of [`block_headers_subscribe`](#method.block_headers_subscribe).", block_headers_subscribe, sync_block_headers_subscribe, Result<HeaderNotification, Error>, );

    /// Tries to pop one queued notification for a new block header that we might have received.
    /// Returns `None` if there are no items in the queue.
    pub fn block_headers_poll(&mut self) -> Result<Option<HeaderNotification>, Error> {
        self.poll()?;

        Ok(self.headers.pop_front())
    }

    /// Gets the block header for height `height`.
    pub async fn block_header(&mut self, height: usize) -> Result<BlockHeader, Error> {
        Ok(deserialize(&self.block_header_raw(height).await?)?)
    }
    impl_sync_version!("Synchronous version of [`block_header`](#method.block_header).", block_header, sync_block_header, Result<BlockHeader, Error>, height: usize);

    /// Gets the raw bytes of block header for height `height`.
    pub async fn block_header_raw(&mut self, height: usize) -> Result<Vec<u8>, Error> {
        let req = Request::new("blockchain.block.header", vec![Param::Usize(height)]);
        let result = self.call(req).await?;

        Ok(Vec::<u8>::from_hex(
            result
                .as_str()
                .ok_or_else(|| Error::InvalidResponse(result.clone()))?,
        )?)
    }
    impl_sync_version!(
        "Synchronous version of [`block_header_raw`](#method.block_header_raw).",
        block_header_raw,
        sync_block_header_raw,
        Result<Vec<u8>, Error>,
        height: usize
    );

    /// Tries to fetch `count` block headers starting from `start_height`.
    pub async fn block_headers(
        &mut self,
        start_height: usize,
        count: usize,
    ) -> Result<GetHeadersRes, Error> {
        let req = Request::new(
            "blockchain.block.headers",
            vec![Param::Usize(start_height), Param::Usize(count)],
        );
        let result = self.call(req).await?;

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
    impl_sync_version!("Synchronous version of [`block_headers`](#method.block_headers).", block_headers, sync_block_headers, Result<GetHeadersRes, Error>, start_height: usize, count: usize);

    /// Estimates the fee required in **Satoshis per kilobyte** to confirm a transaction in `number` blocks.
    pub async fn estimate_fee(&mut self, number: usize) -> Result<f64, Error> {
        let req = Request::new("blockchain.estimatefee", vec![Param::Usize(number)]);
        let result = self.call(req).await?;

        result
            .as_f64()
            .ok_or_else(|| Error::InvalidResponse(result.clone()))
    }
    impl_sync_version!("Synchronous version of [`estimate_fee`](#method.estimate_fee).", estimate_fee, sync_estimate_fee, Result<f64, Error>, number: usize);

    /// Returns the minimum accepted fee by the server's node in **Bitcoin, not Satoshi**.
    pub async fn relay_fee(&mut self) -> Result<f64, Error> {
        let req = Request::new("blockchain.relayfee", vec![]);
        let result = self.call(req).await?;

        result
            .as_f64()
            .ok_or_else(|| Error::InvalidResponse(result.clone()))
    }
    impl_sync_version!("Synchronous version of [`relay_fee`](#method.relay_fee).", relay_fee, sync_relay_fee, Result<f64, Error>, );

    /// Subscribes to notifications for activity on a specific *scriptPubKey*.
    ///
    /// Returns a [`ScriptStatus`](../types/type.ScriptStatus.html) when successful that represents
    /// the current status for the requested script.
    ///
    /// Returns [`Error::AlreadySubscribed`](../types/enum.Error.html#variant.AlreadySubscribed) if
    /// already subscribed to the same script.
    pub async fn script_subscribe(&mut self, script: &Script) -> Result<ScriptStatus, Error> {
        let script_hash = script.to_electrum_scripthash();

        if self.script_notifications.contains_key(&script_hash) {
            return Err(Error::AlreadySubscribed(script_hash));
        }

        self.script_notifications
            .insert(script_hash.clone(), VecDeque::new());

        let req = Request::new(
            "blockchain.scripthash.subscribe",
            vec![Param::String(script_hash.to_hex())],
        );
        let value = self.call(req).await?;

        Ok(serde_json::from_value(value)?)
    }
    impl_sync_version!("Synchronous version of [`script_subscribe`](#method.script_subscribe).", script_subscribe, sync_script_subscribe, Result<ScriptStatus, Error>, script: &Script);

    /// Subscribes to notifications for activity on a specific *scriptPubKey*.
    ///
    /// Returns a `bool` with the server response when successful.
    ///
    /// Returns [`Error::NotSubscribed`](../types/enum.Error.html#variant.NotSubscribed) if
    /// not subscribed to the script.
    pub async fn script_unsubscribe(&mut self, script: &Script) -> Result<bool, Error> {
        let script_hash = script.to_electrum_scripthash();

        if !self.script_notifications.contains_key(&script_hash) {
            return Err(Error::NotSubscribed(script_hash));
        }

        let req = Request::new(
            "blockchain.scripthash.unsubscribe",
            vec![Param::String(script_hash.to_hex())],
        );
        let value = self.call(req).await?;
        let answer = serde_json::from_value(value)?;

        self.script_notifications.remove(&script_hash);

        Ok(answer)
    }
    impl_sync_version!("Synchronous version of [`script_unsubscribe`](#method.script_unsubscribe).", script_unsubscribe, sync_script_unsubscribe, Result<bool, Error>, script: &Script);

    /// Tries to pop one queued notification for a the requested script. Returns `None` if there are no items in the queue.
    pub fn script_poll(&mut self, script: &Script) -> Result<Option<ScriptStatus>, Error> {
        self.poll()?;

        let script_hash = script.to_electrum_scripthash();

        match self.script_notifications.get_mut(&script_hash) {
            None => Err(Error::NotSubscribed(script_hash)),
            Some(queue) => Ok(queue.pop_front()),
        }
    }

    /// Returns the balance for a *scriptPubKey*
    pub async fn script_get_balance(&mut self, script: &Script) -> Result<GetBalanceRes, Error> {
        let params = vec![Param::String(script.to_electrum_scripthash().to_hex())];
        let req = Request::new("blockchain.scripthash.get_balance", params);
        let result = self.call(req).await?;

        Ok(serde_json::from_value(result)?)
    }
    impl_sync_version!("Synchronous version of [`script_get_balance`](#method.script_get_balance).", script_get_balance, sync_script_get_balance, Result<GetBalanceRes, Error>, script: &Script);
    /// Batch version of [`script_get_balance`](#method.script_get_balance).
    ///
    /// Takes a list of scripts and returns a list of balance responses.
    pub async fn batch_script_get_balance<'s, I>(
        &mut self,
        scripts: I,
    ) -> Result<Vec<GetBalanceRes>, Error>
    where
        I: IntoIterator<Item = &'s Script>,
    {
        impl_batch_call!(self, scripts, script_get_balance)
    }
    impl_sync_version!(
        _,
        Script,
        "Synchronous version of [`batch_script_get_balance`](#method.batch_script_get_balance).",
        batch_script_get_balance,
        sync_batch_script_get_balance,
        Result<Vec<GetBalanceRes>, Error>,
        scripts: I
    );

    /// Returns the history for a *scriptPubKey*
    pub async fn script_get_history(
        &mut self,
        script: &Script,
    ) -> Result<Vec<GetHistoryRes>, Error> {
        let params = vec![Param::String(script.to_electrum_scripthash().to_hex())];
        let req = Request::new("blockchain.scripthash.get_history", params);
        let result = self.call(req).await?;

        Ok(serde_json::from_value(result)?)
    }
    impl_sync_version!(
        "Synchronous version of [`script_get_history`](#method.script_get_history).",
        script_get_history,
        sync_script_get_history,
        Result<Vec<GetHistoryRes>, Error>,
        script: &Script
    );
    /// Batch version of [`script_get_history`](#method.script_get_history).
    ///
    /// Takes a list of scripts and returns a list of history responses.
    pub async fn batch_script_get_history<'s, I>(
        &mut self,
        scripts: I,
    ) -> Result<Vec<Vec<GetHistoryRes>>, Error>
    where
        I: IntoIterator<Item = &'s Script>,
    {
        impl_batch_call!(self, scripts, script_get_history)
    }
    impl_sync_version!(
        _,
        Script,
        "Synchronous version of [`batch_script_get_history`](#method.batch_script_get_history).",
        batch_script_get_history,
        sync_batch_script_get_history,
        Result<Vec<Vec<GetHistoryRes>>, Error>,
        scripts: I
    );

    /// Returns the list of unspent outputs for a *scriptPubKey*
    pub async fn script_list_unspent(
        &mut self,
        script: &Script,
    ) -> Result<Vec<ListUnspentRes>, Error> {
        let params = vec![Param::String(script.to_electrum_scripthash().to_hex())];
        let req = Request::new("blockchain.scripthash.listunspent", params);
        let result = self.call(req).await?;

        Ok(serde_json::from_value(result)?)
    }
    impl_sync_version!(
        "Synchronous version of [`script_list_unspent`](#method.script_list_unspent).",
        script_list_unspent,
        sync_script_list_unspent,
        Result<Vec<ListUnspentRes>, Error>,
        script: &Script
    );
    /// Batch version of [`script_list_unspent`](#method.script_list_unspent).
    ///
    /// Takes a list of scripts and returns a list of a list of utxos.
    pub async fn batch_script_list_unspent<'s, I>(
        &mut self,
        scripts: I,
    ) -> Result<Vec<Vec<ListUnspentRes>>, Error>
    where
        I: IntoIterator<Item = &'s Script>,
    {
        impl_batch_call!(self, scripts, script_list_unspent)
    }
    impl_sync_version!(
        _,
        Script,
        "Synchronous version of [`batch_script_list_unspent`](#method.batch_script_list_unspent).",
        batch_script_list_unspent,
        sync_batch_script_list_unspent,
        Result<Vec<Vec<ListUnspentRes>>, Error>,
        scripts: I
    );

    /// Gets the transaction with `txid`. Returns an error if not found.
    pub async fn transaction_get(&mut self, txid: &Txid) -> Result<Transaction, Error> {
        Ok(deserialize(&self.transaction_get_raw(txid).await?)?)
    }
    impl_sync_version!("Synchronous version of [`transaction_get`](#method.transaction_get).", transaction_get, sync_transaction_get, Result<Transaction, Error>, txid: &Txid);

    /// Gets the raw bytes of a transaction with `txid`. Returns an error if not found.
    pub async fn transaction_get_raw(&mut self, txid: &Txid) -> Result<Vec<u8>, Error> {
        let params = vec![Param::String(txid.to_hex())];
        let req = Request::new("blockchain.transaction.get", params);
        let result = self.call(req).await?;

        Ok(Vec::<u8>::from_hex(
            result
                .as_str()
                .ok_or_else(|| Error::InvalidResponse(result.clone()))?,
        )?)
    }
    impl_sync_version!(
        "Synchronous version of [`transaction_get_raw`](#method.transaction_get_raw).",
        transaction_get_raw,
        sync_transaction_get_raw,
        Result<Vec<u8>, Error>,
        txid: &Txid
    );
    /// Batch version of [`transaction_get`](#method.transaction_get).
    ///
    /// Takes a list of `txids` and returns a list of transactions.
    pub async fn batch_transaction_get<'t, I>(
        &mut self,
        txids: I,
    ) -> Result<Vec<Transaction>, Error>
    where
        I: IntoIterator<Item = &'t Txid>,
    {
        self.batch_transaction_get_raw(txids)
            .await?
            .iter()
            .map(|s| Ok(deserialize(s)?))
            .collect()
    }
    impl_sync_version!(
        _,
        Txid,
        "Synchronous version of [`batch_transaction_get`](#method.batch_transaction_get).",
        batch_transaction_get,
        sync_batch_transaction_get,
        Result<Vec<Transaction>, Error>,
        txids: I
    );

    /// Batch version of [`transaction_get_raw`](#method.transaction_get_raw).
    ///
    /// Takes a list of `txids` and returns a list of transactions raw bytes.
    pub async fn batch_transaction_get_raw<'t, I>(
        &mut self,
        txids: I,
    ) -> Result<Vec<Vec<u8>>, Error>
    where
        I: IntoIterator<Item = &'t Txid>,
    {
        let txs_string: Result<Vec<String>, Error> = impl_batch_call!(self, txids, transaction_get);
        txs_string?
            .iter()
            .map(|s| Ok(Vec::<u8>::from_hex(s)?))
            .collect()
    }
    impl_sync_version!(
        _,
        Txid,
        "Synchronous version of [`batch_transaction_get_raw`](#method.batch_transaction_get_raw).",
        batch_transaction_get_raw,
        sync_batch_transaction_get_raw,
        Result<Vec<Vec<u8>>, Error>,
        txids: I
    );

    /// Batch version of [`block_header_raw`](#method.block_header_raw).
    ///
    /// Takes a list of `heights` of blocks and returns a list of block header raw bytes.
    pub async fn batch_block_header_raw<'s, I>(&mut self, heights: I) -> Result<Vec<Vec<u8>>, Error>
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
    impl_sync_version!(
        u32,
        "Synchronous version of [`batch_block_header_raw`](#method.batch_block_header_raw).",
        batch_block_header_raw,
        sync_batch_block_header_raw,
        Result<Vec<Vec<u8>>, Error>,
        heights: I
    );

    /// Batch version of [`block_header`](#method.block_header).
    ///
    /// Takes a list of `heights` of blocks and returns a list of headers.
    pub async fn batch_block_header<'s, I>(&mut self, heights: I) -> Result<Vec<BlockHeader>, Error>
    where
        I: IntoIterator<Item = u32>,
    {
        self.batch_block_header_raw(heights)
            .await?
            .iter()
            .map(|s| Ok(deserialize(s)?))
            .collect()
    }
    impl_sync_version!(
        u32,
        "Synchronous version of [`batch_block_header`](#method.batch_block_header).",
        batch_block_header,
        sync_batch_block_header,
        Result<Vec<BlockHeader>, Error>,
        heights: I
    );

    /// Batch version of [`estimate_fee`](#method.estimate_fee).
    ///
    /// Takes a list of `numbers` of blocks and returns a list of fee required in
    /// **Satoshis per kilobyte** to confirm a transaction in the given number of blocks.
    pub async fn batch_estimate_fee<'s, I>(&mut self, numbers: I) -> Result<Vec<f64>, Error>
    where
        I: IntoIterator<Item = usize>,
    {
        impl_batch_call!(self, numbers, estimate_fee)
    }
    impl_sync_version!(
        usize,
        "Synchronous version of [`batch_estimate_fee`](#method.batch_estimate_fee).",
        batch_estimate_fee,
        sync_batch_estimate_fee,
        Result<Vec<f64>, Error>,
        numbers: I
    );

    /// Broadcasts the raw bytes of a transaction to the network.
    pub async fn transaction_broadcast_raw(&mut self, raw_tx: &[u8]) -> Result<Txid, Error> {
        let params = vec![Param::String(raw_tx.to_hex())];
        let req = Request::new("blockchain.transaction.broadcast", params);
        let result = self.call(req).await?;

        Ok(serde_json::from_value(result)?)
    }
    impl_sync_version!("Synchronous version of [`transaction_broadcast_raw`](#method.transaction_broadcast_raw).", transaction_broadcast_raw, sync_transaction_broadcast_raw, Result<Txid, Error>, raw_tx: &[u8]);

    /// Broadcasts a transaction to the network.
    pub async fn transaction_broadcast(&mut self, tx: &Transaction) -> Result<Txid, Error> {
        let buffer: Vec<u8> = serialize(tx);
        self.transaction_broadcast_raw(&buffer).await
    }
    impl_sync_version!("Synchronous version of [`transaction_broadcast`](#method.transaction_broadcast).", transaction_broadcast, sync_transaction_broadcast, Result<Txid, Error>, tx: &Transaction);

    /// Returns the merkle path for the transaction `txid` confirmed in the block at `height`.
    pub async fn transaction_get_merkle(
        &mut self,
        txid: &Txid,
        height: usize,
    ) -> Result<GetMerkleRes, Error> {
        let params = vec![Param::String(txid.to_hex()), Param::Usize(height)];
        let req = Request::new("blockchain.transaction.get_merkle", params);
        let result = self.call(req).await?;

        Ok(serde_json::from_value(result)?)
    }
    impl_sync_version!("Synchronous version of [`transaction_get_merkle`](#method.transaction_get_merkle).", transaction_get_merkle, sync_transaction_get_merkle, Result<GetMerkleRes, Error>, txid: &Txid, height: usize);

    /// Returns the capabilities of the server.
    pub async fn server_features(&mut self) -> Result<ServerFeaturesRes, Error> {
        let req = Request::new("server.features", vec![]);
        let result = self.call(req).await?;

        Ok(serde_json::from_value(result)?)
    }
    impl_sync_version!("Synchronous version of [`server_features`](#method.server_features).", server_features, sync_server_features, Result<ServerFeaturesRes, Error>, );

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

    use crate::client::Client;
    use crate::test_stream::TestStream;

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
        ( $testcase:expr, $client:expr ) => {
            let mut data_out = File::open(format!("./test_data/{}.out", $testcase)).unwrap();
            let mut buffer = Vec::new();
            data_out.read_to_end(&mut buffer).unwrap();
            let reader = $client.buf_reader.into_inner();
            let test_stream = reader.unsplit($client.writer);
            let stream_buffer = test_stream.buffer;

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

        let resp = client.sync_server_features().unwrap();
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

        impl_test_conclusion!(test_case, client);
    }
    #[test]
    fn test_relay_fee() {
        let test_case = "relay_fee";
        let mut client = impl_test_prelude!(test_case);

        let resp = client.sync_relay_fee().unwrap();
        assert_eq!(resp, 123.4);

        impl_test_conclusion!(test_case, client);
    }

    #[test]
    fn test_estimate_fee() {
        let test_case = "estimate_fee";
        let mut client = impl_test_prelude!(test_case);

        let resp = client.sync_estimate_fee(10).unwrap();
        assert_eq!(resp, 10.0);

        impl_test_conclusion!(test_case, client);
    }

    #[test]
    fn test_block_header() {
        let test_case = "block_header";
        let mut client = impl_test_prelude!(test_case);

        let resp = client.sync_block_header(500).unwrap();
        assert_eq!(resp.version, 536870912);
        assert_eq!(resp.time, 1578166214);
        assert_eq!(resp.nonce, 0);

        impl_test_conclusion!(test_case, client);
    }

    #[test]
    fn test_block_headers() {
        let test_case = "block_headers";
        let mut client = impl_test_prelude!(test_case);

        let resp = client.sync_block_headers(100, 4).unwrap();
        assert_eq!(resp.count, 4);
        assert_eq!(resp.max, 2016);
        assert_eq!(resp.headers.len(), 4);

        assert_eq!(resp.headers[0].time, 1563694949);

        impl_test_conclusion!(test_case, client);
    }

    #[test]
    fn test_script_get_balance() {
        use std::str::FromStr;

        let test_case = "script_get_balance";
        let mut client = impl_test_prelude!(test_case);

        let addr = bitcoin::Address::from_str("2N1xJCxBUXTDs6y8Sydz3axhAiXrrQwcosi").unwrap();
        let resp = client
            .sync_script_get_balance(&addr.script_pubkey())
            .unwrap();
        assert_eq!(resp.confirmed, 0);
        assert_eq!(resp.unconfirmed, 130000000);

        impl_test_conclusion!(test_case, client);
    }

    #[test]
    fn test_script_get_history() {
        use std::str::FromStr;

        use bitcoin::hashes::hex::FromHex;
        use bitcoin::Txid;

        let test_case = "script_get_history";
        let mut client = impl_test_prelude!(test_case);

        let addr = bitcoin::Address::from_str("2N1xJCxBUXTDs6y8Sydz3axhAiXrrQwcosi").unwrap();
        let resp = client
            .sync_script_get_history(&addr.script_pubkey())
            .unwrap();
        assert_eq!(resp.len(), 2);
        assert_eq!(
            resp[0].tx_hash,
            Txid::from_hex("a1aa2b52fb79641f918d44a27f51781c3c0c49f7ee0e4b14dbb37c722853f046")
                .unwrap()
        );

        impl_test_conclusion!(test_case, client);
    }

    #[test]
    fn test_script_list_unspent() {
        use std::str::FromStr;

        use bitcoin::hashes::hex::FromHex;
        use bitcoin::Txid;

        let test_case = "script_list_unspent";
        let mut client = impl_test_prelude!(test_case);

        let addr = bitcoin::Address::from_str("2N1xJCxBUXTDs6y8Sydz3axhAiXrrQwcosi").unwrap();
        let resp = client
            .sync_script_list_unspent(&addr.script_pubkey())
            .unwrap();
        assert_eq!(resp.len(), 2);
        assert_eq!(resp[0].value, 30000000);
        assert_eq!(resp[0].height, 0);
        assert_eq!(resp[0].tx_pos, 1);
        assert_eq!(
            resp[0].tx_hash,
            Txid::from_hex("a1aa2b52fb79641f918d44a27f51781c3c0c49f7ee0e4b14dbb37c722853f046")
                .unwrap()
        );

        impl_test_conclusion!(test_case, client);
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
            .sync_batch_script_list_unspent(vec![&script_1, &script_2])
            .unwrap();
        assert_eq!(resp.len(), 2);
        assert_eq!(resp[0].len(), 2);
        assert_eq!(resp[1].len(), 1);

        impl_test_conclusion!(test_case, client);
    }

    #[test]
    fn test_batch_estimate_fee() {
        let test_case = "batch_estimate_fee";
        let mut client = impl_test_prelude!(test_case);

        let resp = client.sync_batch_estimate_fee(vec![10, 20]).unwrap();
        assert_eq!(resp[0], 10.0);
        assert_eq!(resp[1], 20.0);

        impl_test_conclusion!(test_case, client);
    }

    #[test]
    fn test_transaction_get() {
        use bitcoin::hashes::hex::FromHex;
        use bitcoin::Txid;

        let test_case = "transaction_get";
        let mut client = impl_test_prelude!(test_case);

        let resp = client
            .sync_transaction_get(
                &Txid::from_hex("a1aa2b52fb79641f918d44a27f51781c3c0c49f7ee0e4b14dbb37c722853f046")
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(resp.version, 2);
        assert_eq!(resp.lock_time, 1376);

        impl_test_conclusion!(test_case, client);
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

        let resp = client.sync_transaction_broadcast(&tx).unwrap();
        assert_eq!(
            resp,
            Txid::from_hex("a1aa2b52fb79641f918d44a27f51781c3c0c49f7ee0e4b14dbb37c722853f046")
                .unwrap()
        );

        impl_test_conclusion!(test_case, client);
    }

    #[test]
    fn test_transaction_get_merkle() {
        use bitcoin::hashes::hex::FromHex;
        use bitcoin::Txid;

        let test_case = "transaction_get_merkle";
        let mut client = impl_test_prelude!(test_case);

        let resp = client
            .sync_transaction_get_merkle(
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

        impl_test_conclusion!(test_case, client);
    }
}
