//! Return types
//!
//! This module contains definitions of all the complex data structures that are returned by calls

use std::convert::TryFrom;
use std::fmt::{self, Display, Formatter};
use std::ops::Deref;
use std::sync::Arc;

use bitcoin_lib::blockdata::block;
use bitcoin_lib::consensus::encode::deserialize;
use bitcoin_lib::hashes::hex::FromHex;
use bitcoin_lib::hashes::{sha256, Hash};
use bitcoin_lib::{Script, Txid};

use bitcoin_private::hex::exts::DisplayHex;
use bitcoin_private::hex::Case;
use serde::{de, Deserialize, Serialize};

static JSONRPC_2_0: &str = "2.0";

pub type Call = (String, Vec<Param>);

#[cfg(feature = "use-bitcoin")]
pub use bitcoin_lib::blockdata::block::Header as HeaderType;

#[cfg(feature = "use-bitcoincash")]
pub use bitcoin_lib::blockdata::block::BlockHeader as HeaderType;

#[derive(Serialize, Clone)]
#[serde(untagged)]
/// A single parameter of a [`Request`](struct.Request.html)
pub enum Param {
    /// Integer parameter
    U32(u32),
    /// Integer parameter
    Usize(usize),
    /// String parameter
    String(String),
    /// Boolean parameter
    Bool(bool),
    /// Bytes array parameter
    Bytes(Vec<u8>),
}

#[derive(Serialize, Clone)]
/// A request that can be sent to the server
pub struct Request<'a> {
    jsonrpc: &'static str,

    /// The JSON-RPC request id
    pub id: usize,
    /// The request method
    pub method: &'a str,
    /// The request parameters
    pub params: Vec<Param>,
}

impl<'a> Request<'a> {
    /// Creates a new request with a default id
    fn new(method: &'a str, params: Vec<Param>) -> Self {
        Self {
            id: 0,
            jsonrpc: JSONRPC_2_0,
            method,
            params,
        }
    }

    /// Creates a new request with a user-specified id
    pub fn new_id(id: usize, method: &'a str, params: Vec<Param>) -> Self {
        let mut instance = Self::new(method, params);
        instance.id = id;

        instance
    }
}

#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct Hex32Bytes(#[serde(deserialize_with = "from_hex", serialize_with = "to_hex")] [u8; 32]);

impl Deref for Hex32Bytes {
    type Target = [u8; 32];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<[u8; 32]> for Hex32Bytes {
    fn from(other: [u8; 32]) -> Hex32Bytes {
        Hex32Bytes(other)
    }
}

impl Hex32Bytes {
    pub(crate) fn to_hex(&self) -> String {
        #[cfg(feature = "use-bitcoin")]
        return self.0.to_lower_hex_string();
        #[cfg(feature = "use-bitcoincash")]
        {
            let mut string = String::new();
            lower_hex_string(&self.0, &mut string);
            return string;
        }
    }
}

/// Format used by the Electrum server to identify an address. The reverse sha256 hash of the
/// scriptPubKey. Documented [here](https://electrumx.readthedocs.io/en/latest/protocol-basics.html#script-hashes).
pub type ScriptHash = Hex32Bytes;

/// Binary blob that condenses all the activity of an address. Used to detect changes without
/// having to compare potentially long lists of transactions.
pub type ScriptStatus = Hex32Bytes;

/// Trait used to convert a struct into the Electrum representation of an address
pub trait ToElectrumScriptHash {
    /// Transforms the current struct into a `ScriptHash`
    fn to_electrum_scripthash(&self) -> ScriptHash;
}

impl ToElectrumScriptHash for Script {
    fn to_electrum_scripthash(&self) -> ScriptHash {
        #[cfg(feature = "use-bitcoin")]
        let mut result = sha256::Hash::hash(self.as_bytes()).to_byte_array();
        #[cfg(feature = "use-bitcoincash")]
        let mut result = sha256::Hash::hash(self.as_bytes()).into_inner();

        result.reverse();

        result.into()
    }
}

fn from_hex<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: FromHex,
    D: de::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    T::from_hex(&s).map_err(de::Error::custom)
}

fn lower_hex_string(bytes: &[u8], string: &mut String) {
    use self::fmt::Write;
    string.reserve(0);

    write!(string, "{:x}", bytes.as_hex()).unwrap_or_else(|_| {
        let name = core::any::type_name::<dyn Display>();
        // We don't expect `std` to ever be buggy, so the bug is most likely in the `Display`
        // impl of `Self::Display`.
        panic!(
            "The implementation of Display for {} returned an error when it shouldn't",
            name
        )
    })
}

fn to_hex<S>(bytes: &[u8], serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::ser::Serializer,
{
    #[cfg(feature = "use-bitcoin")]
    return serializer.serialize_str(&bytes.to_lower_hex_string());
    #[cfg(feature = "use-bitcoincash")]
    {
        let mut string = String::new();
        lower_hex_string(bytes, &mut string);
        return serializer.serialize_str(&string);
    }
}

fn from_hex_array<'de, T, D>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    T: FromHex + std::fmt::Debug,
    D: de::Deserializer<'de>,
{
    let arr = Vec::<String>::deserialize(deserializer)?;

    let results: Vec<Result<T, _>> = arr
        .into_iter()
        .map(|s| T::from_hex(&s).map_err(de::Error::custom))
        .collect();

    let mut answer = Vec::new();
    for x in results.into_iter() {
        answer.push(x?);
    }

    Ok(answer)
}

fn from_hex_header<'de, D>(deserializer: D) -> Result<HeaderType, D::Error>
where
    D: de::Deserializer<'de>,
{
    let vec: Vec<u8> = from_hex(deserializer)?;
    deserialize(&vec).map_err(de::Error::custom)
}

/// Response to a [`script_get_history`](../client/struct.Client.html#method.script_get_history) request.
#[derive(Debug, Deserialize)]
pub struct GetHistoryRes {
    /// Confirmation height of the transaction. 0 if unconfirmed, -1 if unconfirmed while some of
    /// its inputs are unconfirmed too.
    pub height: i32,
    /// Txid of the transaction.
    pub tx_hash: Txid,
    /// Fee of the transaction.
    pub fee: Option<u64>,
}

/// Response to a [`script_list_unspent`](../client/struct.Client.html#method.script_list_unspent) request.
#[derive(Debug, Deserialize)]
pub struct ListUnspentRes {
    /// Confirmation height of the transaction that created this output.
    pub height: usize,
    /// Txid of the transaction
    pub tx_hash: Txid,
    /// Index of the output in the transaction.
    pub tx_pos: usize,
    /// Value of the output.
    pub value: u64,
}

/// Response to a [`server_features`](../client/struct.Client.html#method.server_features) request.
#[derive(Debug, Deserialize)]
pub struct ServerFeaturesRes {
    /// Server version reported.
    pub server_version: String,
    /// Hash of the genesis block.
    #[serde(deserialize_with = "from_hex")]
    pub genesis_hash: [u8; 32],
    /// Minimum supported version of the protocol.
    pub protocol_min: String,
    /// Maximum supported version of the protocol.
    pub protocol_max: String,
    /// Hash function used to create the [`ScriptHash`](type.ScriptHash.html).
    pub hash_function: Option<String>,
    /// Pruned height of the server.
    pub pruning: Option<i64>,
}

/// Response to a [`server_features`](../client/struct.Client.html#method.server_features) request.
#[derive(Debug, Deserialize)]
pub struct GetHeadersRes {
    /// Maximum number of headers returned in a single response.
    pub max: usize,
    /// Number of headers in this response.
    pub count: usize,
    /// Raw headers concatenated. Normally cleared before returning.
    #[serde(rename(deserialize = "hex"), deserialize_with = "from_hex")]
    pub raw_headers: Vec<u8>,
    /// Array of block headers.
    #[serde(skip)]
    pub headers: Vec<HeaderType>,
}

/// Response to a [`script_get_balance`](../client/struct.Client.html#method.script_get_balance) request.
#[derive(Debug, Deserialize)]
pub struct GetBalanceRes {
    /// Confirmed balance in Satoshis for the address.
    pub confirmed: u64,
    /// Unconfirmed balance in Satoshis for the address.
    ///
    /// Some servers (e.g. `electrs`) return this as a negative value.
    pub unconfirmed: i64,
}

/// Response to a [`transaction_get_merkle`](../client/struct.Client.html#method.transaction_get_merkle) request.
#[derive(Debug, Deserialize)]
pub struct GetMerkleRes {
    /// Height of the block that confirmed the transaction
    pub block_height: usize,
    /// Position in the block of the transaction.
    pub pos: usize,
    /// The merkle path of the transaction.
    #[serde(deserialize_with = "from_hex_array")]
    pub merkle: Vec<[u8; 32]>,
}

/// Notification of a new block header
#[derive(Debug, Deserialize)]
pub struct HeaderNotification {
    /// New block height.
    pub height: usize,
    /// Newly added header.
    #[serde(rename = "hex", deserialize_with = "from_hex_header")]
    pub header: HeaderType,
}

/// Notification of a new block header with the header encoded as raw bytes
#[derive(Debug, Deserialize)]
pub struct RawHeaderNotification {
    /// New block height.
    pub height: usize,
    /// Newly added header.
    #[serde(rename = "hex", deserialize_with = "from_hex")]
    pub header: Vec<u8>,
}

impl TryFrom<RawHeaderNotification> for HeaderNotification {
    type Error = Error;

    fn try_from(raw: RawHeaderNotification) -> Result<Self, Self::Error> {
        Ok(HeaderNotification {
            height: raw.height,
            header: deserialize(&raw.header).unwrap(),
        })
    }
}

/// Notification of the new status of a script
#[derive(Debug, Deserialize)]
pub struct ScriptNotification {
    /// Address that generated this notification.
    pub scripthash: ScriptHash,
    /// The new status of the address.
    pub status: ScriptStatus,
}

/// Errors
#[derive(Debug)]
pub enum Error {
    /// Wraps `std::io::Error`
    IOError(std::io::Error),
    /// Wraps `serde_json::error::Error`
    JSON(serde_json::error::Error),
    /// Wraps `bitcoin::hashes::hex::Error`
    Hex(bitcoin_lib::hashes::hex::Error),
    /// Error returned by the Electrum server
    Protocol(serde_json::Value),
    /// Error during the deserialization of a Bitcoin data structure
    Bitcoin(bitcoin_lib::consensus::encode::Error),
    /// Already subscribed to the notifications of an address
    AlreadySubscribed(ScriptHash),
    /// Not subscribed to the notifications of an address
    NotSubscribed(ScriptHash),
    /// Error during the deserialization of a response from the server
    InvalidResponse(serde_json::Value),
    /// Generic error with a message
    Message(String),
    /// Invalid domain name for an SSL certificate
    InvalidDNSNameError(String),
    /// Missing domain while it was explicitly asked to validate it
    MissingDomain,
    /// Made one or multiple attempts, always in Error
    AllAttemptsErrored(Vec<Error>),
    /// There was an io error reading the socket, to be shared between threads
    SharedIOError(Arc<std::io::Error>),

    /// Couldn't take a lock on the reader mutex. This means that there's already another reader
    /// thread running
    CouldntLockReader,
    /// Broken IPC communication channel: the other thread probably has exited
    Mpsc,

    #[cfg(feature = "use-rustls")]
    /// Could not create a rustls client connection
    CouldNotCreateConnection(rustls::Error),

    #[cfg(feature = "use-openssl")]
    /// Invalid OpenSSL method used
    InvalidSslMethod(openssl::error::ErrorStack),
    #[cfg(feature = "use-openssl")]
    /// SSL Handshake failed with the server
    SslHandshakeError(openssl::ssl::HandshakeError<std::net::TcpStream>),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Error::IOError(e) => Display::fmt(e, f),
            Error::JSON(e) => Display::fmt(e, f),
            Error::Hex(e) => Display::fmt(e, f),
            Error::Bitcoin(e) => Display::fmt(e, f),
            Error::SharedIOError(e) => Display::fmt(e, f),
            #[cfg(feature = "use-openssl")]
            Error::SslHandshakeError(e) => Display::fmt(e, f),
            #[cfg(feature = "use-openssl")]
            Error::InvalidSslMethod(e) => Display::fmt(e, f),
            #[cfg(feature = "use-rustls")]
            Error::CouldNotCreateConnection(e) => Display::fmt(e, f),

            Error::Message(e) => f.write_str(e),
            Error::InvalidDNSNameError(domain) => write!(f, "Invalid domain name {} not matching SSL certificate", domain),
            Error::AllAttemptsErrored(errors) => {
                f.write_str("Made one or multiple attempts, all errored:\n")?;
                for err in errors {
                    writeln!(f, "\t- {}", err)?;
                }
                Ok(())
            }

            Error::Protocol(e) => write!(f, "Electrum server error: {}", e.clone().take()),
            Error::InvalidResponse(e) => write!(f, "Error during the deserialization of a response from the server: {}", e.clone().take()),

            // TODO: Print out addresses once `ScriptHash` will implement `Display`
            Error::AlreadySubscribed(_) => write!(f, "Already subscribed to the notifications of an address"),
            Error::NotSubscribed(_) => write!(f, "Not subscribed to the notifications of an address"),

            Error::MissingDomain => f.write_str("Missing domain while it was explicitly asked to validate it"),
            Error::CouldntLockReader => f.write_str("Couldn't take a lock on the reader mutex. This means that there's already another reader thread is running"),
            Error::Mpsc => f.write_str("Broken IPC communication channel: the other thread probably has exited"),
        }
    }
}

impl std::error::Error for Error {}

macro_rules! impl_error {
    ( $from:ty, $to:ident ) => {
        impl std::convert::From<$from> for Error {
            fn from(err: $from) -> Self {
                Error::$to(err.into())
            }
        }
    };
}

impl_error!(std::io::Error, IOError);
impl_error!(serde_json::Error, JSON);
impl_error!(bitcoin_lib::hashes::hex::Error, Hex);
impl_error!(bitcoin_lib::consensus::encode::Error, Bitcoin);

impl<T> From<std::sync::PoisonError<T>> for Error {
    fn from(_: std::sync::PoisonError<T>) -> Self {
        Error::IOError(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
    }
}

impl<T> From<std::sync::mpsc::SendError<T>> for Error {
    fn from(_: std::sync::mpsc::SendError<T>) -> Self {
        Error::Mpsc
    }
}

impl From<std::sync::mpsc::RecvError> for Error {
    fn from(_: std::sync::mpsc::RecvError) -> Self {
        Error::Mpsc
    }
}

#[cfg(test)]
mod tests {
    use crate::ScriptStatus;

    #[test]
    fn script_status_roundtrip() {
        let script_status: ScriptStatus = [1u8; 32].into();
        let script_status_json = serde_json::to_string(&script_status).unwrap();
        let script_status_back = serde_json::from_str(&script_status_json).unwrap();
        assert_eq!(script_status, script_status_back);
    }
}
