# Changelog

All notable changes to this project can be found here and in each release's git tag and can be viewed with `git tag -ln100 "v*"`.

Contributors do not need to change this file but do need to add changelog details in their PR descriptions. The person making the next release will collect changelog details from included PRs and edit this file prior to each release.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.25.1]

### Added

- Add `protocol_version()` to `ElectrumApi`, returning the protocol version negotiated during connection setup #213

### Fixed

- Fix `rustls` to handle concurrent `CryptoProvider` initialization #217
- Fix `authorization` token leaking into TRACE logs in `call` and `batch_call` #218
- Fix concurrent requests on EOF #225

## [0.25.0]

### Added

 - Add new `justfile` #195
 - Add new simpler feature names `openssl`, `rustls`, and `rustls-ring` #182
 - Add support for [Electrum Protocol v1.6](https://electrum-protocol.readthedocs.io/en/latest/protocol-changes.html#version-1-6) #190
 - Add automatic `server.version` negotiation on connect, exposed via a new `protocol_version()` method and `CLIENT_NAME`/`PROTOCOL_VERSION_MIN`/`PROTOCOL_VERSION_MAX` constants #190
 - Add new `mempool_get_info` method returning `mempoolminfee`, `minrelaytxfee`, and `incrementalrelayfee` #190
 - Add new `transaction_broadcast_package` method for package relay (CPFP) #190
 - Add new optional `EstimationMode` (`Conservative`/`Economical`) parameter on `estimate_fee` #190
 - Add new `AuthProvider` type alias (`Arc<dyn Fn() -> Option<String> + Send + Sync>`) for dynamic authorization token support (e.g. JWT Bearer, API keys, OAuth) #194

### Fixed

 - Fix `bitcoin::block::Header` documentation link #195

### Changed

 - Change `ConfigBuilder::timeout()` to accept `Option<Duration>` #180
 - Remove `Client` dependency on the `proxy` feature #182
 - The `Client` constructors (`new`, `new_ssl`, `new_ssl_from_stream`, `new_proxy`) now fail if protocol version negotiation fails #190
 - The `estimate_fee` now takes `Option<EstimationMode>` as its second parameter #190
 - Remove `minimal`, `debug-calls` features #182
 - Remove conditional compilation of `ElectrumApi::calls_made` #182
 - `ConfigBuilder` now accepts an optional `AuthProvider` via `authorization_provider()`, enabling token-refresh patterns without reconnecting #194
 - `RawClient` and `ClientType::from_config` updated to propagate the auth provider across all transport backends (TCP, SSL, SOCKS5) #194

## [0.24.1]
 - Default to `ring` if multiple `rustls` features are set #183

## [0.24.0]
 - Use default `CryptoProvider` if available, otherwise install `rustls`'s `CryptoProvider` based on features #171
 - Add a new batch method for `blockchain.transaction.get_merkle` #170

## [0.23.1]
 - Fix batch request to Electrum servers out of order responses #160
 - Allow types that references to `ElectrumApi` to also implement it #163

## [0.23.0]

 - Raise MSRV to `1.75` and bump `rustls` to `0.23.21` #159
 - Enforce min `rustls` version 0.23.19 to support MSRV with fix for RUSTSEC-2024-0399 #158

## [0.22.0]

 - Updates the NoCertificateVerification implementation for the rustls::client::danger::ServerCertVerifier to use the rustls::SignatureScheme from CryptoProvider in use #150
 - Add `id_from_pos` support #155

## [0.21.0]

 - Add use-rustls-ring feature #135
 - refactor: make validate_merkle_proof more efficient #134
 - chore: set rust edition to 2021, fix clippy, add ci fmt and clippy checks #139

## [0.20.0]

- Upgrade rustls to 0.23 #132
- chore(deps): upgrade rust-bitcoin to 0.32.0 #133
- ci: add test with MSRV 1.63.0 #128

## [0.19.0]

 - Add Batch::raw and improve docs #94
 - Remove webpki and bump webpki-roots to v0.25 #117
 - Upgrade rust-bitcoin to v0.31.0 #121
 - Add utility to validate GetMerkleRes #122
 - Enforce timeout on initial socks5 proxy connection #125

## [0.18.0]

 - Revert "errors if expecting headers notification but not subscribed" #115

[0.18.0]: https://github.com/bitcoindevkit/rust-electrum-client/compare/0.17.0...0.18.0
[0.19.0]: https://github.com/bitcoindevkit/rust-electrum-client/compare/0.18.0...0.19.0
[0.20.0]: https://github.com/bitcoindevkit/rust-electrum-client/compare/0.19.0...0.20.0
[0.21.0]: https://github.com/bitcoindevkit/rust-electrum-client/compare/0.20.0...0.21.0
[0.22.0]: https://github.com/bitcoindevkit/rust-electrum-client/compare/0.21.0...0.22.0
[0.23.0]: https://github.com/bitcoindevkit/rust-electrum-client/compare/0.22.0...0.23.0
[0.23.1]: https://github.com/bitcoindevkit/rust-electrum-client/compare/0.23.0...0.23.1
[0.24.0]: https://github.com/bitcoindevkit/rust-electrum-client/compare/0.23.1...0.24.0
[0.24.1]: https://github.com/bitcoindevkit/rust-electrum-client/compare/0.24.0...0.24.1
[0.25.0]: https://github.com/bitcoindevkit/rust-electrum-client/compare/0.24.1...0.25.0
[0.25.1]: https://github.com/bitcoindevkit/rust-electrum-client/compare/0.25.0...0.25.1
[Unreleased]: https://github.com/bitcoindevkit/rust-electrum-client/compare/0.25.1...HEAD
