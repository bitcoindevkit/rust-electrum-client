# rust-electrum-client

<p>
    <a href="https://crates.io/crates/electrum-client"><img src="https://img.shields.io/crates/v/electrum-client.svg"/></a>
    <a href="https://docs.rs/electrum-client"><img src="https://img.shields.io/badge/docs.rs-electrum--client-blue"/></a>
    <a href="https://blog.rust-lang.org/2023/12/28/Rust-1.75.0.html"><img src="https://img.shields.io/badge/MSRV-1.75.0%2B-orange.svg"/></a>
    <a href="https://github.com/bitcoindevkit/rust-electrum-client/blob/master/LICENSE.md"><img src="https://img.shields.io/badge/License-MIT%2FApache--2.0-red.svg"/></a>
    <a href="https://github.com/bitcoindevkit/rust-electrum-client/actions/workflows/cont_integration.yml"><img src="https://github.com/bitcoindevkit/rust-electrum-client/actions/workflows/cont_integration.yml/badge.svg"></a>
</p>

Bitcoin Electrum client library. Supports plaintext, TLS and Onion servers.

## Security Policy

To report a security issue, please refer to the [security policy](SECURITY.md).

## Minimum Supported Rust Version (MSRV)

This library should compile with any combination of features with Rust 1.75.0.

To build with the MSRV you will need to pin dependencies by running:

``` bash
cargo update -p openssl --precise "0.10.78"
cargo update -p openssl-sys --precise "0.9.114"
cargo update -p zeroize --precise "1.8.2"
cargo update -p jobserver --precise "0.1.34"
cargo update -p tokio --precise "1.53.3"
```

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
