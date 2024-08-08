//! Utilities helping to handle Electrum-related data.

use crate::types::GetMerkleRes;
use crate::Error;
use bitcoin::hash_types::TxMerkleNode;
use bitcoin::hashes::sha256d::Hash as Sha256d;
use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::{Amount, FeeRate, Txid};
use serde_json::Value;

/// Verifies a Merkle inclusion proof as retrieved via [`transaction_get_merkle`] for a transaction with the
/// given `txid` and `merkle_root` as included in the [`BlockHeader`].
///
/// Returns `true` if the transaction is included in the corresponding block, and `false`
/// otherwise.
///
/// [`transaction_get_merkle`]: crate::ElectrumApi::transaction_get_merkle
/// [`BlockHeader`]: bitcoin::BlockHeader
pub fn validate_merkle_proof(
    txid: &Txid,
    merkle_root: &TxMerkleNode,
    merkle_res: &GetMerkleRes,
) -> bool {
    let mut index = merkle_res.pos;
    let mut cur = txid.to_raw_hash();
    for mut bytes in merkle_res.merkle.iter().cloned() {
        bytes.reverse();
        let next_hash = Sha256d::from_byte_array(bytes);

        cur = Sha256d::from_engine({
            let mut engine = Sha256d::engine();
            if index % 2 == 0 {
                engine.input(cur.as_ref());
                engine.input(next_hash.as_ref());
            } else {
                engine.input(next_hash.as_ref());
                engine.input(cur.as_ref());
            };
            engine
        });
        index /= 2;
    }

    cur == merkle_root.to_raw_hash()
}

/// Converts a fee rate in BTC/kB to sats/vbyte.
pub(crate) fn convert_fee_rate(fee_rate_kvb: Value) -> Result<FeeRate, Error> {
    let fee_rate_kvb = match fee_rate_kvb.as_f64() {
        Some(fee_rate_kvb) => fee_rate_kvb,
        None => {
            return Err(Error::FeeRate("Fee rate conversion failed".to_string()));
        }
    };
    let fee_rate_sat_vb = (Amount::ONE_BTC.to_sat() as f64) * fee_rate_kvb;
    let fee_rate = FeeRate::from_sat_per_vb(fee_rate_sat_vb as u64);
    match fee_rate {
        Some(fee_rate) => Ok(fee_rate),
        None => Err(Error::FeeRate("Fee rate conversion failed".to_string())),
    }
}
