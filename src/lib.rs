#![warn(missing_docs)]

//! This library provides an extendable Bitcoin-Electrum client that supports batch calls,
//! notifications and multiple transport methods.
//!
//! By default this library is compiled with support for SSL servers using [`rustls`](https://docs.rs/rustls) and support for
//! plaintext connections over a socks proxy, useful for Onion servers. Using different features,
//! the SSL implementation can be removed or replaced with [`openssl`](https://docs.rs/openssl).
//!
//! A `minimal` configuration is also provided, which only includes the plaintext TCP client.
//!
//! # Example
//!
//! ```no_run
//! use electrum_client::{Client, ElectrumApi};
//!
//! let mut client = Client::new("tcp://electrum.blockstream.info:50001", None)?;
//! let response = client.server_features()?;
//! # Ok::<(), electrum_client::Error>(())
//! ```

pub extern crate bitcoin;
extern crate core;
extern crate log;
#[cfg(feature = "use-openssl")]
extern crate openssl;
#[cfg(all(
    any(feature = "default", feature = "use-rustls"),
    not(feature = "use-openssl")
))]
extern crate rustls;
extern crate serde;
extern crate serde_json;
#[cfg(any(feature = "default", feature = "proxy"))]
extern crate socks;
#[cfg(any(feature = "use-rustls", feature = "default"))]
extern crate webpki;
#[cfg(any(feature = "use-rustls", feature = "default"))]
extern crate webpki_roots;

mod api;
mod batch;
pub mod client;
pub mod raw_client;
mod stream;
mod types;

pub use api::ElectrumApi;
pub use batch::Batch;
pub use client::*;
pub use types::*;
