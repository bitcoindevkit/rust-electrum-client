alias b := build
alias c := check
alias f := fmt
alias t := test
alias p := pre-push

_default:
   @just --list

# Build the project
build:
   cargo build

# Check code: formatting, compilation, linting, doc comments, and commit signature
check:
   cargo +nightly fmt --all -- --check
   @just _check-features
   cargo clippy --all-features --all-targets -- -D warnings
   cargo rustdoc --all-features -- -D warnings
   @[ "$(git log --pretty='format:%G?' -1 HEAD)" = "N" ] && \
       echo "\n⚠️  Unsigned commit: BDK requires that commits be signed." || \
       true

# Check feature configurations (matches CI)
_check-features:
   cargo check --features "default"
   cargo check --no-default-features
   cargo check --no-default-features --features "proxy"
   cargo check --no-default-features --features "openssl"
   cargo check --no-default-features --features "rustls"
   cargo check --no-default-features --features "rustls-ring"
   cargo check --no-default-features --features "proxy,openssl,rustls,rustls-ring"   

# Format all code
fmt:
   cargo +nightly fmt

# Run all tests on the workspace with all features
test:
   cargo test --all-features -- --test-threads=1

# Run pre-push suite: format, check, and test
pre-push: fmt check test

