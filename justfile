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
   cargo check --all-features --all-targets
   cargo clippy --all-features --all-targets -- -D warnings
   RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps
   @[ "$(git log --pretty='format:%G?' -1 HEAD)" = "N" ] && \
       echo "\n⚠️  Unsigned commit: BDK requires that commits be signed." || \
       true

# Format all code
fmt:
   cargo +nightly fmt

# Run all tests on the workspace with all features
test:
   cargo test --all-features -- --test-threads=1

# Run pre-push suite: format, check, and test
pre-push: fmt check test

