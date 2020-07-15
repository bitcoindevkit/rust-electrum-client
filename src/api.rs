use bitcoin::{BlockHeader, Script, Transaction, Txid};

use batch::Batch;
use types::*;

/// API calls exposed by an Electrum client
pub trait ElectrumApi {
    /// Execute a queue of calls stored in a [`Batch`](../batch/struct.Batch.html) struct. Returns
    /// `Ok()` **only if** all of the calls are successful. The order of the JSON `Value`s returned
    /// reflects the order in which the calls were made on the `Batch` struct.
    fn batch_call(&self, batch: Batch) -> Result<Vec<serde_json::Value>, Error>;

    /// Subscribes to notifications for new block headers, by sending a `blockchain.headers.subscribe` call.
    fn block_headers_subscribe(&self) -> Result<HeaderNotification, Error>;

    /// Tries to pop one queued notification for a new block header that we might have received.
    /// Returns `None` if there are no items in the queue.
    fn block_headers_pop(&self) -> Result<Option<HeaderNotification>, Error>;

    /// Gets the block header for height `height`.
    fn block_header(&self, height: usize) -> Result<BlockHeader, Error>;

    /// Gets the raw bytes of block header for height `height`.
    fn block_header_raw(&self, height: usize) -> Result<Vec<u8>, Error>;

    /// Tries to fetch `count` block headers starting from `start_height`.
    fn block_headers(&self, start_height: usize, count: usize) -> Result<GetHeadersRes, Error>;

    /// Estimates the fee required in **Satoshis per kilobyte** to confirm a transaction in `number` blocks.
    fn estimate_fee(&self, number: usize) -> Result<f64, Error>;

    /// Returns the minimum accepted fee by the server's node in **Bitcoin, not Satoshi**.
    fn relay_fee(&self) -> Result<f64, Error>;

    /// Subscribes to notifications for activity on a specific *scriptPubKey*.
    ///
    /// Returns a [`ScriptStatus`](../types/type.ScriptStatus.html) when successful that represents
    /// the current status for the requested script.
    ///
    /// Returns [`Error::AlreadySubscribed`](../types/enum.Error.html#variant.AlreadySubscribed) if
    /// already subscribed to the script.
    fn script_subscribe(&self, script: &Script) -> Result<Option<ScriptStatus>, Error>;

    /// Subscribes to notifications for activity on a specific *scriptPubKey*.
    ///
    /// Returns a `bool` with the server response when successful.
    ///
    /// Returns [`Error::NotSubscribed`](../types/enum.Error.html#variant.NotSubscribed) if
    /// not subscribed to the script.
    fn script_unsubscribe(&self, script: &Script) -> Result<bool, Error>;

    /// Tries to pop one queued notification for a the requested script. Returns `None` if there are no items in the queue.
    fn script_pop(&self, script: &Script) -> Result<Option<ScriptStatus>, Error>;

    /// Returns the balance for a *scriptPubKey*.
    fn script_get_balance(&self, script: &Script) -> Result<GetBalanceRes, Error>;

    /// Batch version of [`script_get_balance`](#method.script_get_balance).
    ///
    /// Takes a list of scripts and returns a list of balance responses.
    fn batch_script_get_balance<'s, I>(&self, scripts: I) -> Result<Vec<GetBalanceRes>, Error>
    where
        I: IntoIterator<Item = &'s Script>;

    /// Returns the history for a *scriptPubKey*
    fn script_get_history(&self, script: &Script) -> Result<Vec<GetHistoryRes>, Error>;

    /// Batch version of [`script_get_history`](#method.script_get_history).
    ///
    /// Takes a list of scripts and returns a list of history responses.
    fn batch_script_get_history<'s, I>(&self, scripts: I) -> Result<Vec<Vec<GetHistoryRes>>, Error>
    where
        I: IntoIterator<Item = &'s Script>;

    /// Returns the list of unspent outputs for a *scriptPubKey*
    fn script_list_unspent(&self, script: &Script) -> Result<Vec<ListUnspentRes>, Error>;

    /// Batch version of [`script_list_unspent`](#method.script_list_unspent).
    ///
    /// Takes a list of scripts and returns a list of a list of utxos.
    fn batch_script_list_unspent<'s, I>(
        &self,
        scripts: I,
    ) -> Result<Vec<Vec<ListUnspentRes>>, Error>
    where
        I: IntoIterator<Item = &'s Script>;

    /// Gets the transaction with `txid`. Returns an error if not found.
    fn transaction_get(&self, txid: &Txid) -> Result<Transaction, Error>;

    /// Gets the raw bytes of a transaction with `txid`. Returns an error if not found.
    fn transaction_get_raw(&self, txid: &Txid) -> Result<Vec<u8>, Error>;

    /// Batch version of [`transaction_get`](#method.transaction_get).
    ///
    /// Takes a list of `txids` and returns a list of transactions.
    fn batch_transaction_get<'t, I>(&self, txids: I) -> Result<Vec<Transaction>, Error>
    where
        I: IntoIterator<Item = &'t Txid>;

    /// Batch version of [`transaction_get_raw`](#method.transaction_get_raw).
    ///
    /// Takes a list of `txids` and returns a list of transactions raw bytes.
    fn batch_transaction_get_raw<'t, I>(&self, txids: I) -> Result<Vec<Vec<u8>>, Error>
    where
        I: IntoIterator<Item = &'t Txid>;

    /// Batch version of [`block_header_raw`](#method.block_header_raw).
    ///
    /// Takes a list of `heights` of blocks and returns a list of block header raw bytes.
    fn batch_block_header_raw<'s, I>(&self, heights: I) -> Result<Vec<Vec<u8>>, Error>
    where
        I: IntoIterator<Item = u32>;

    /// Batch version of [`block_header`](#method.block_header).
    ///
    /// Takes a list of `heights` of blocks and returns a list of headers.
    fn batch_block_header<'s, I>(&self, heights: I) -> Result<Vec<BlockHeader>, Error>
    where
        I: IntoIterator<Item = u32>;

    /// Batch version of [`estimate_fee`](#method.estimate_fee).
    ///
    /// Takes a list of `numbers` of blocks and returns a list of fee required in
    /// **Satoshis per kilobyte** to confirm a transaction in the given number of blocks.
    fn batch_estimate_fee<'s, I>(&self, numbers: I) -> Result<Vec<f64>, Error>
    where
        I: IntoIterator<Item = usize>;

    /// Broadcasts the raw bytes of a transaction to the network.
    fn transaction_broadcast_raw(&self, raw_tx: &[u8]) -> Result<Txid, Error>;

    /// Broadcasts a transaction to the network.
    fn transaction_broadcast(&self, tx: &Transaction) -> Result<Txid, Error>;

    /// Returns the merkle path for the transaction `txid` confirmed in the block at `height`.
    fn transaction_get_merkle(&self, txid: &Txid, height: usize) -> Result<GetMerkleRes, Error>;

    /// Returns the capabilities of the server.
    fn server_features(&self) -> Result<ServerFeaturesRes, Error>;

    #[cfg(feature = "debug-calls")]
    /// Returns the number of network calls made since the creation of the client.
    fn calls_made(&self) -> usize;
}
