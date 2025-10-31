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
//! let mut client = Client::new("tcp://electrum.blockstream.info:50001")?;
//! let response = client.server_features()?;
//! # Ok::<(), electrum_client::Error>(())
//! ```

pub extern crate bitcoin;
extern crate core;
extern crate log;
#[cfg(feature = "openssl")]
extern crate openssl;
#[cfg(any(feature = "rustls", feature = "rustls-ring"))]
extern crate rustls;
extern crate serde;
extern crate serde_json;

#[cfg(any(feature = "rustls", feature = "rustls-ring"))]
extern crate webpki_roots;

#[cfg(feature = "proxy")]
extern crate byteorder;

#[cfg(all(unix, feature = "proxy"))]
extern crate libc;
#[cfg(all(windows, feature = "proxy"))]
extern crate winapi;

#[cfg(feature = "proxy")]
pub mod socks;

mod api;
mod batch;

#[cfg(any(feature = "openssl", feature = "rustls", feature = "rustls-ring"))]
pub mod client;

mod config;

pub mod raw_client;
mod stream;
mod types;
pub mod utils;

pub use api::ElectrumApi;
pub use batch::Batch;
#[cfg(any(feature = "openssl", feature = "rustls", feature = "rustls-ring"))]
pub use client::*;
pub use config::{Config, ConfigBuilder, Socks5Config};
pub use types::*;
