//! Utilities helping to handle Electrum-related data.

use bitcoin::hash_types::TxMerkleNode;
use bitcoin::hashes::sha256d::Hash as Sha256d;
use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::Txid;
use types::GetMerkleRes;

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
