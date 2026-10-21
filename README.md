# rust-electrum-client 
[![Build Status]][GitHub Workflow] [![Latest Version]][crates.io] [![MSRV Badge]][Rust Blog]

[Build Status]: https://github.com/bitcoindevkit/rust-electrum-client/actions/workflows/cont_integration.yml/badge.svg
[GitHub Workflow]: https://github.com/bitcoindevkit/rust-electrum-client/actions?query=workflow%3ACI
[Latest Version]: https://img.shields.io/crates/v/electrum-client.svg
[crates.io]: https://crates.io/crates/electrum-client
[MSRV Badge]: https://img.shields.io/badge/rustc-1.75.0%2B-lightgrey.svg
[Rust Blog]: https://blog.rust-lang.org/2023/12/28/Rust-1.75.0.html

Bitcoin Electrum client library. Supports plaintext, TLS and Onion servers.

## Minimum Supported Rust Version (MSRV)

This library should compile with any combination of features with Rust 1.75.0.

To build with the MSRV you will need to pin dependencies by running:

``` bash
cargo update -p openssl --precise "0.10.78"
cargo update -p openssl-sys --precise "0.9.114"
cargo update -p zeroize --precise "1.8.2"
cargo update -p jobserver --precise "0.1.34"
```
