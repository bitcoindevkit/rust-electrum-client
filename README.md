# rust-electrum-client 
[![Build Status]][GitHub Workflow] [![Latest Version]][crates.io] [![MSRV Badge]][Rust Blog]

[Build Status]: https://github.com/bitcoindevkit/rust-electrum-client/actions/workflows/cont_integration.yml/badge.svg
[GitHub Workflow]: https://github.com/bitcoindevkit/rust-electrum-client/actions?query=workflow%3ACI
[Latest Version]: https://img.shields.io/crates/v/electrum-client.svg
[crates.io]: https://crates.io/crates/electrum-client
[MSRV Badge]: https://img.shields.io/badge/rustc-1.63.0%2B-lightgrey.svg
[Rust Blog]: https://blog.rust-lang.org/2022/08/11/Rust-1.63.0.html

Bitcoin Electrum client library. Supports plaintext, TLS and Onion servers.

## Minimum Supported Rust Version (MSRV)

This library should compile with any combination of features with Rust 1.63.0.

To build with the MSRV you will need to pin dependencies as follows:

```shell
cargo update -p rustls --precise "0.23.19"
```

