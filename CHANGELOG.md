# Changelog

All notable changes to this project can be found here and in each release's git tag and can be viewed with `git tag -ln100 "v*"`.

Contributors do not need to change this file but do need to add changelog details in their PR descriptions. The person making the next release will collect changelog details from included PRs and edit this file prior to each release.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.22.1]

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
[0.19.0]: https://github.com/bitcoindevkit/rust-electrum-client/compare/0.18.0...v0.19.0
[0.20.0]: https://github.com/bitcoindevkit/rust-electrum-client/compare/0.19.0...v0.20.0
[0.21.0]: https://github.com/bitcoindevkit/rust-electrum-client/compare/0.20.0...v0.21.0
[0.22.0]: https://github.com/bitcoindevkit/rust-electrum-client/compare/0.21.0...v0.22.0
[0.22.1]: https://github.com/bitcoindevkit/rust-electrum-client/compare/0.22.0...v0.22.1
[Unreleased]: https://github.com/bitcoindevkit/rust-electrum-client/compare/0.22.1...HEAD
