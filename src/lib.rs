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
//! use electrum_client::{Client, Error};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Error> {
//!     let mut client = Client::new("kirsche.emzy.de:50001").await?;
//!     let response = client.server_features().await?;
//!
//!     Ok(())
//! }
//! ```

pub extern crate bitcoin;
pub extern crate tokio;

#[macro_use]
extern crate lazy_static;

pub mod batch;
pub mod client;
#[cfg(test)]
mod test_stream;
pub mod types;

pub use batch::Batch;
pub use client::Client;
pub use types::*;
