//! Electrum Client

use bitcoin::{Script, Txid};

use api::ElectrumApi;
use batch::Batch;
use raw_client::*;
use types::*;

/// Generalized Electrum client that supports multiple backends. This wraps
/// [`RawClient`](client/struct.RawClient.html) and provides a more user-friendly
/// constructor that can choose the right backend based on the url prefix.
///
/// **This is only available with the `default` features.**
#[cfg(feature = "default")]
pub enum Client {
    #[doc(hidden)]
    TCP(RawClient<ElectrumPlaintextStream>),
    #[doc(hidden)]
    SSL(RawClient<ElectrumSslStream>),
    #[doc(hidden)]
    Socks5(RawClient<ElectrumProxyStream>),
}

macro_rules! impl_inner_call {
    ( $self:expr, $name:ident $(, $args:expr)* ) => {
        match $self {
            Client::TCP(inner) => inner.$name( $($args, )* ),
            Client::SSL(inner) => inner.$name( $($args, )* ),
            Client::Socks5(inner) => inner.$name( $($args, )* ),
        }
    }
}

#[cfg(feature = "default")]
impl Client {
    /// Generic constructor that supports multiple backends and, optionally, a socks5 proxy.
    ///
    /// Supported prefixes are:
    /// - tcp:// for a TCP plaintext client.
    /// - ssl:// for an SSL-encrypted client. The server certificate will be verified.
    ///
    /// If no prefix is specified, then `tcp://` is assumed.
    ///
    /// The `socks5` argument can optionally be prefixed with `socks5://`.
    ///
    /// **NOTE**: SSL-over-socks5 is currently not supported and will generate a runtime error.
    pub fn new(url: &str, socks5: Option<&str>) -> Result<Self, Error> {
        let socks5 = socks5.map(|s| s.replacen("socks5://", "", 1));

        if url.starts_with("ssl://") {
            if socks5.is_some() {
                return Err(Error::SSLOverSocks5);
            }

            let url = url.replacen("ssl://", "", 1);
            let client = RawClient::new_ssl(url.as_str(), true)?;

            Ok(Client::SSL(client))
        } else {
            let url = url.replacen("tcp://", "", 1);

            let client = match socks5 {
                None => Client::TCP(RawClient::new(url.as_str())?),
                Some(socks5) => Client::Socks5(RawClient::new_proxy(url.as_str(), socks5)?),
            };

            Ok(client)
        }
    }
}

#[cfg(feature = "default")]
impl ElectrumApi for Client {
    #[inline]
    fn batch_call(&self, batch: Batch) -> Result<Vec<serde_json::Value>, Error> {
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
        I: IntoIterator<Item = &'s Script>,
    {
        impl_inner_call!(self, batch_script_get_balance, scripts)
    }

    #[inline]
    fn script_get_history(&self, script: &Script) -> Result<Vec<GetHistoryRes>, Error> {
        impl_inner_call!(self, script_get_history, script)
    }

    #[inline]
    fn batch_script_get_history<'s, I>(&self, scripts: I) -> Result<Vec<Vec<GetHistoryRes>>, Error>
    where
        I: IntoIterator<Item = &'s Script>,
    {
        impl_inner_call!(self, batch_script_get_history, scripts)
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
        I: IntoIterator<Item = &'s Script>,
    {
        impl_inner_call!(self, batch_script_list_unspent, scripts)
    }

    #[inline]
    fn transaction_get_raw(&self, txid: &Txid) -> Result<Vec<u8>, Error> {
        impl_inner_call!(self, transaction_get_raw, txid)
    }

    #[inline]
    fn batch_transaction_get_raw<'t, I>(&self, txids: I) -> Result<Vec<Vec<u8>>, Error>
    where
        I: IntoIterator<Item = &'t Txid>,
    {
        impl_inner_call!(self, batch_transaction_get_raw, txids)
    }

    #[inline]
    fn batch_block_header_raw<'s, I>(&self, heights: I) -> Result<Vec<Vec<u8>>, Error>
    where
        I: IntoIterator<Item = u32>,
    {
        impl_inner_call!(self, batch_block_header_raw, heights)
    }

    #[inline]
    fn batch_estimate_fee<'s, I>(&self, numbers: I) -> Result<Vec<f64>, Error>
    where
        I: IntoIterator<Item = usize>,
    {
        impl_inner_call!(self, batch_estimate_fee, numbers)
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
    fn calls_made(&self) -> usize {
        impl_inner_call!(self, calls_made)
    }
}
