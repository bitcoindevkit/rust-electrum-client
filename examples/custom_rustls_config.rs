// SPDX-License-Identifier: MIT OR Apache-2.0

//! # Connecting with a caller-provided `rustls` configuration
//!
//! By default `ssl://` connections are validated against the `webpki` root store, which
//! only contains public certificate authorities. Server and mobile applications often
//! need to trust something else: a private or self-signed certificate (for example the
//! one served by a self-hosted Fulcrum/Electrum server), or the operating system's own
//! trust store, or a custom certificate verifier.
//!
//! Passing a [`rustls::ClientConfig`] through [`ConfigBuilder::rustls_config`] gives the
//! caller full control. When set, it is used as-is and `validate_domain` is ignored.
//!
//! Run it with the DER-encoded CA certificate and the server URL, e.g.:
//!
//! ```text
//! cargo run --example custom_rustls_config -- ca.der ssl://192.168.0.2:50002
//! ```

#[cfg(all(
    any(feature = "rustls", feature = "rustls-ring"),
    not(feature = "openssl")
))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;

    use electrum_client::{Client, ConfigBuilder, ElectrumApi};

    // A DER-encoded certificate to trust in addition to the bundled roots. This can be the
    // certificate served by a self-hosted server, or a private CA that signed it.
    let ca_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "ca.der".to_string());
    let ca_der = std::fs::read(&ca_path)?;
    let url = std::env::args()
        .nth(2)
        .unwrap_or_else(|| "ssl://localhost:50002".to_string());

    let mut roots = rustls::RootCertStore::empty();
    roots.add(rustls::pki_types::CertificateDer::from(ca_der))?;
    // To also honour the operating system's trust store, add every certificate returned by
    // `rustls_native_certs::load_native_certs()` here.

    // Pick the crypto provider that matches the enabled feature.
    #[cfg(feature = "rustls-ring")]
    let provider = rustls::crypto::ring::default_provider();
    #[cfg(not(feature = "rustls-ring"))]
    let provider = rustls::crypto::aws_lc_rs::default_provider();

    let tls = Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );

    let config = ConfigBuilder::new().rustls_config(Some(tls)).build();
    let client = Client::from_config(&url, config)?;
    println!("{:#?}", client.server_features()?);

    Ok(())
}

// This example requires the `rustls` (or `rustls-ring`) feature and is a no-op otherwise.
#[cfg(not(all(
    any(feature = "rustls", feature = "rustls-ring"),
    not(feature = "openssl")
)))]
fn main() {}
