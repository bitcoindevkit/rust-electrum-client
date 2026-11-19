// SPDX-License-Identifier: MIT OR Apache-2.0

//! Batch utilities
//!
//! This module contains definitions and helper functions used when making batch calls.

use bitcoin::{Script, ScriptBuf, Txid};

use crate::types::{Call, EstimationMode, Param, ScriptCall};

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
///
/// The script calls (`script_*`) are sent in the format of the protocol version negotiated by the
/// client that executes the batch, so the raw results returned by `batch_call` differ between
/// protocol versions. The typed `batch_script_*` methods on the client hide that difference.
#[derive(Default)]
pub struct Batch {
    entries: Vec<BatchEntry>,
}

struct BatchEntry {
    /// The call in the form used up to protocol v1.6, as exposed by [`Batch::iter`].
    call: Call,
    /// Set for script calls, which are resolved against the negotiated version when sent.
    script_call: Option<(ScriptCall, ScriptBuf)>,
}

impl Batch {
    /// Add a raw request to the batch queue
    pub fn raw(&mut self, method: String, params: Vec<Param>) {
        self.entries.push(BatchEntry {
            call: (method, params),
            script_call: None,
        });
    }

    fn push_script_call(&mut self, script_call: ScriptCall, script: &Script) {
        let (method, param) = script_call.request(script, false);
        self.entries.push(BatchEntry {
            call: (method.to_string(), vec![param]),
            script_call: Some((script_call, script.to_owned())),
        });
    }

    /// Add one `listunspent` request for `script` to the batch queue
    pub fn script_list_unspent(&mut self, script: &Script) {
        self.push_script_call(ScriptCall::ListUnspent, script);
    }

    /// Add one `get_history` request for `script` to the batch queue
    pub fn script_get_history(&mut self, script: &Script) {
        self.push_script_call(ScriptCall::GetHistory, script);
    }

    /// Add one `get_mempool` request for `script` to the batch queue
    pub fn script_get_mempool(&mut self, script: &Script) {
        self.push_script_call(ScriptCall::GetMempool, script);
    }

    /// Add one `get_balance` request for `script` to the batch queue
    pub fn script_get_balance(&mut self, script: &Script) {
        self.push_script_call(ScriptCall::GetBalance, script);
    }

    /// Add one `subscribe` request for `script` to the batch queue
    pub fn script_subscribe(&mut self, script: &Script) {
        self.push_script_call(ScriptCall::Subscribe, script);
    }

    /// Add one `blockchain.transaction.get` request to the batch queue
    pub fn transaction_get(&mut self, tx_hash: &Txid) {
        let params = vec![Param::String(format!("{:x}", tx_hash))];
        self.raw(String::from("blockchain.transaction.get"), params);
    }

    /// Add one `blockchain.transaction.get_merkle` request to the batch queue
    pub fn transaction_get_merkle(&mut self, tx_hash_and_height: &(Txid, usize)) {
        let (tx_hash, height) = tx_hash_and_height;
        let params = vec![
            Param::String(format!("{:x}", tx_hash)),
            Param::Usize(*height),
        ];
        self.raw(String::from("blockchain.transaction.get_merkle"), params);
    }

    /// Add one `blockchain.estimatefee` request to the batch queue
    pub fn estimate_fee(&mut self, number: usize, mode: Option<EstimationMode>) {
        let mut params = vec![Param::Usize(number)];
        if let Some(mode) = mode {
            params.push(Param::String(mode.to_string()));
        }
        self.raw(String::from("blockchain.estimatefee"), params);
    }

    /// Add one `blockchain.block.get_header` request to the batch queue
    pub fn block_header(&mut self, height: u32) {
        let params = vec![Param::U32(height)];
        self.raw(String::from("blockchain.block.header"), params);
    }

    /// Returns an iterator on the batch
    ///
    /// Script calls are yielded in their `blockchain.scripthash.*` form, used up to protocol
    /// v1.6. A client that negotiated protocol v1.7 sends them as `blockchain.scriptpubkey.*`
    /// calls instead.
    pub fn iter(&self) -> BatchIter<'_> {
        BatchIter {
            batch: self,
            index: 0,
        }
    }

    /// Returns the calls to send, with script calls in the format of the negotiated version.
    pub(crate) fn resolved_calls(
        &self,
        use_scriptpubkey: bool,
    ) -> impl Iterator<Item = (&str, Vec<Param>)> + '_ {
        self.entries
            .iter()
            .map(move |entry| match &entry.script_call {
                Some((script_call, script)) => {
                    let (method, param) = script_call.request(script, use_scriptpubkey);
                    (method, vec![param])
                }
                None => (entry.call.0.as_str(), entry.call.1.clone()),
            })
    }
}

impl std::iter::IntoIterator for Batch {
    type Item = (String, Vec<Param>);
    type IntoIter = BatchIntoIter;

    fn into_iter(self) -> Self::IntoIter {
        BatchIntoIter(self.entries.into_iter())
    }
}

pub struct BatchIntoIter(std::vec::IntoIter<BatchEntry>);

impl std::iter::Iterator for BatchIntoIter {
    type Item = (String, Vec<Param>);

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|entry| entry.call)
    }
}

pub struct BatchIter<'a> {
    batch: &'a Batch,
    index: usize,
}

impl<'a> std::iter::Iterator for BatchIter<'a> {
    type Item = &'a (String, Vec<Param>);

    fn next(&mut self) -> Option<Self::Item> {
        let val = self.batch.entries.get(self.index).map(|entry| &entry.call);
        self.index += 1;
        val
    }
}
