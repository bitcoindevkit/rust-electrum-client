// SPDX-License-Identifier: MIT OR Apache-2.0

//! End-to-end tests for a caller-provided [`rustls::ClientConfig`].
//!
//! These spin up a local TLS server that speaks just enough of the Electrum protocol to
//! complete the `server.version` handshake and verify that:
//!
//! 1. a [`rustls::ClientConfig`] trusting a private CA is actually used, and
//! 2. the default configuration (bundled `webpki` roots) rejects the same server, and
//! 3. a custom certificate verifier (for example a pinned/self-signed certificate) works too.
#![cfg(all(
    any(feature = "rustls", feature = "rustls-ring"),
    not(feature = "openssl")
))]

use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::sync::Arc;

use electrum_client::{Client, Config, ConfigBuilder, ElectrumApi};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

fn provider() -> rustls::crypto::CryptoProvider {
    #[cfg(feature = "rustls-ring")]
    {
        rustls::crypto::ring::default_provider()
    }
    #[cfg(not(feature = "rustls-ring"))]
    {
        rustls::crypto::aws_lc_rs::default_provider()
    }
}

/// A self-signed CA, and a leaf certificate (for `127.0.0.1`) signed by it.
fn private_ca_and_leaf() -> (CertificateDer<'static>, CertificateDer<'static>, Vec<u8>) {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "electrum-client test CA");
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    let leaf_key = KeyPair::generate().unwrap();
    let leaf_params = CertificateParams::new(vec!["127.0.0.1".to_string()]).unwrap();
    let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();

    (
        ca_cert.der().clone(),
        leaf_cert.der().clone(),
        leaf_key.serialize_der(),
    )
}

/// A single self-signed certificate (and its key) for `127.0.0.1`.
fn self_signed() -> (CertificateDer<'static>, Vec<u8>) {
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec!["127.0.0.1".to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    (cert.der().clone(), key.serialize_der())
}

/// Spawns a TLS server on a random localhost port that answers a single `server.version`
/// request, and returns the port it listens on.
fn spawn_server(cert: CertificateDer<'static>, key_der: Vec<u8>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    std::thread::spawn(move || {
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));
        let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();

        let (tcp_stream, _) = listener.accept().unwrap();
        let connection = rustls::ServerConnection::new(Arc::new(server_config)).unwrap();
        let mut tls = rustls::StreamOwned::new(connection, tcp_stream);

        // Read the request line (the client rejected the certificate if this errors).
        let mut request = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            match tls.read(&mut byte) {
                Ok(0) | Err(_) => return,
                Ok(_) if byte[0] == b'\n' => break,
                Ok(_) => request.push(byte[0]),
            }
        }

        let request: serde_json::Value = serde_json::from_slice(&request).unwrap();
        let response = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":{},\"result\":[\"ElectrumX 1.18.0\",\"1.6\"]}}\n",
            request["id"]
        );
        tls.write_all(response.as_bytes()).unwrap();
        tls.flush().unwrap();
    });

    port
}

/// A verifier that accepts exactly one pinned certificate and nothing else.
#[derive(Debug)]
struct PinnedCertificate(CertificateDer<'static>);

impl ServerCertVerifier for PinnedCertificate {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if end_entity == &self.0 {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("pinned certificate mismatch".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[test]
fn custom_rustls_config_trusting_a_private_ca_is_used() {
    let (ca_der, leaf_der, leaf_key) = private_ca_and_leaf();
    let port = spawn_server(leaf_der, leaf_key);

    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca_der).unwrap();
    let tls = Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );

    let config = ConfigBuilder::new().rustls_config(Some(tls)).build();
    let client = Client::from_config(&format!("ssl://127.0.0.1:{port}"), config)
        .expect("the private CA must be trusted");

    assert_eq!(client.protocol_version().unwrap(), "1.6");
}

#[test]
fn default_config_rejects_a_private_ca() {
    let (_ca_der, leaf_der, leaf_key) = private_ca_and_leaf();
    let port = spawn_server(leaf_der, leaf_key);

    let result = Client::from_config(&format!("ssl://127.0.0.1:{port}"), Config::default());

    assert!(
        result.is_err(),
        "the bundled `webpki` roots must not trust a private CA"
    );
}

#[test]
fn custom_rustls_config_with_a_pinned_verifier_is_used() {
    let (cert_der, key_der) = self_signed();
    let port = spawn_server(cert_der.clone(), key_der);

    let tls = Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedCertificate(cert_der)))
            .with_no_client_auth(),
    );

    let config = ConfigBuilder::new().rustls_config(Some(tls)).build();
    let client = Client::from_config(&format!("ssl://127.0.0.1:{port}"), config)
        .expect("the pinned certificate must be accepted");

    assert_eq!(client.protocol_version().unwrap(), "1.6");
}
