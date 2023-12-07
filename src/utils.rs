//! Utilities helping to handle Electrum-related data.

use bitcoin::hash_types::TxMerkleNode;
use bitcoin::hashes::sha256d::Hash as Sha256d;
use bitcoin::hashes::Hash;
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
    for bytes in &merkle_res.merkle {
        let mut reversed = [0u8; 32];
        reversed.copy_from_slice(bytes);
        reversed.reverse();
        // unwrap() safety: `reversed` has len 32 so `from_slice` can never fail.
        let next_hash = Sha256d::from_slice(&reversed).unwrap();

        let (left, right) = if index % 2 == 0 {
            (cur, next_hash)
        } else {
            (next_hash, cur)
        };

        let data = [&left[..], &right[..]].concat();
        cur = Sha256d::hash(&data);
        index /= 2;
    }

    cur == merkle_root.to_raw_hash()
}
