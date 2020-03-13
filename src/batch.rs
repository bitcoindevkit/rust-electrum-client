//! Batch utilities
//!
//! This module contains definitions and helper functions used when making batch calls.

use bitcoin::hashes::hex::ToHex;
use bitcoin::{Script, Txid};

use types::{Param, ToElectrumScriptHash};

/// Helper structure that caches all the requests before they are actually sent to the server.
///
/// Calls on this function are stored and run when [`batch_call`](../client/struct.Client.html#method.batch_call)
/// is run on a [`Client`](../client/struct.Client.html).
///
/// This structure can be used to make multiple *different* calls in one single run. For batch
/// calls of the same type, there are shorthands methods defined on the
/// [`Client`](../client/struct.Client.html), like
/// [`batch_script_get_balance`](../client/struct.Client.html#method.batch_script_get_balance) to ask the
/// server for the balance of multiple scripts with a single request.
pub struct Batch {
    calls: Vec<(String, Vec<Param>)>,
}

impl Batch {
    /// Add one `blockchain.scripthash.listunspent` request to the batch queue
    pub fn script_list_unspent(&mut self, script: &Script) {
        let params = vec![Param::String(script.to_electrum_scripthash().to_hex())];
        self.calls
            .push((String::from("blockchain.scripthash.listunspent"), params));
    }

    /// Add one `blockchain.scripthash.get_history` request to the batch queue
    pub fn script_get_history(&mut self, script: &Script) {
        let params = vec![Param::String(script.to_electrum_scripthash().to_hex())];
        self.calls
            .push((String::from("blockchain.scripthash.get_history"), params));
    }

    /// Add one `blockchain.scripthash.get_balance` request to the batch queue
    pub fn script_get_balance(&mut self, script: &Script) {
        let params = vec![Param::String(script.to_electrum_scripthash().to_hex())];
        self.calls
            .push((String::from("blockchain.scripthash.get_balance"), params));
    }

    /// Add one `blockchain.transaction.get` request to the batch queue
    pub fn transaction_get(&mut self, tx_hash: &Txid) {
        let params = vec![Param::String(tx_hash.to_hex())];
        self.calls
            .push((String::from("blockchain.transaction.get"), params));
    }

    /// Add one `blockchain.estimatefee` request to the batch queue
    pub fn estimate_fee(&mut self, number: usize) {
        let params = vec![Param::Usize(number)];
        self.calls
            .push((String::from("blockchain.estimatefee"), params));
    }

    /// Add one `blockchain.block.get_header` request to the batch queue
    pub fn block_header(&mut self, height: u32) {
        let params = vec![Param::U32(height)];
        self.calls
            .push((String::from("blockchain.block.header"), params));
    }
}

impl std::iter::IntoIterator for Batch {
    type Item = (String, Vec<Param>);
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.calls.into_iter()
    }
}

impl std::default::Default for Batch {
    fn default() -> Self {
        Batch { calls: Vec::new() }
    }
}
