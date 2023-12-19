# Changelog

All notable changes to this project can be found here and in each release's git tag and can be viewed with `git tag -ln100 "v*"`.

Contributors do not need to change this file but do need to add changelog details in their PR descriptions. The person making the next release will collect changelog details from included PRs and edit this file prior to each release.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
[Unreleased]: https://github.com/bitcoindevkit/rust-electrum-client/compare/0.19.0...HEAD
