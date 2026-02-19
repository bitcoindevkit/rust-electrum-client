use std::fmt::Debug;
use std::io;

/// A trait for storing and retrieving TOFU (Trust On First Use) certificate data.
/// Implementors of this trait are responsible for persisting certificate data and retrieving it based on the host.
pub trait TofuStore: Send + Sync + Debug {
    /// Retrieves the certificate for the given host.
    /// Returns `Ok(Some(cert))` if a certificate is found, `Ok(None)` if no certificate
    /// is stored for this host, or an error if the operation fails.
    fn get_certificate(&self, host: &str) -> io::Result<Option<Vec<u8>>>;

    /// Stores or updates the certificate for the given host.
    /// If a certificate already exists for this host, it should be replaced.
    /// Returns an error if the operation fails.
    fn set_certificate(&self, host: &str, cert: Vec<u8>) -> io::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Debug)]
    struct InMemoryTofuStore {
        store: Mutex<HashMap<String, Vec<u8>>>,
    }

    impl InMemoryTofuStore {
        fn new() -> Self {
            Self {
                store: Mutex::new(HashMap::new()),
            }
        }
    }

    impl TofuStore for InMemoryTofuStore {
        fn get_certificate(&self, host: &str) -> io::Result<Option<Vec<u8>>> {
            let store = self.store.lock().unwrap();
            Ok(store.get(host).cloned())
        }

        fn set_certificate(&self, host: &str, cert: Vec<u8>) -> io::Result<()> {
            let mut store = self.store.lock().unwrap();
            store.insert(host.to_string(), cert);
            Ok(())
        }
    }

    #[test]
    fn test_tofu_first_use() {
        let store = InMemoryTofuStore::new();

        let host = "example.com";
        let cert = b"test certificate data".to_vec();

        // First use: certificate should not exist
        let result = store.get_certificate(host).unwrap();
        assert!(
            result.is_none(),
            "Certificate should not exist on first use"
        );

        store.set_certificate(host, cert.clone()).unwrap();

        let stored = store.get_certificate(host).unwrap();
        assert_eq!(stored, Some(cert), "Certificate should be stored");
    }

    #[test]
    fn test_tofu_certificate_match() {
        let store = InMemoryTofuStore::new();

        let host = "example.com";
        let cert = b"test certificate data".to_vec();

        // Store certificate
        store.set_certificate(host, cert.clone()).unwrap();

        // Retrieve and verify it matches
        let stored = store.get_certificate(host).unwrap();
        assert_eq!(stored, Some(cert), "Stored certificate should match");
    }

    #[test]
    fn test_tofu_certificate_change() {
        let store = InMemoryTofuStore::new();

        let host = "example.com";
        let cert1 = b"first certificate".to_vec();
        let cert2 = b"second certificate".to_vec();

        // Store first certificate
        store.set_certificate(host, cert1.clone()).unwrap();
        let stored1 = store.get_certificate(host).unwrap();
        assert_eq!(
            stored1,
            Some(cert1.clone()),
            "First certificate should be stored"
        );

        // Update with different certificate
        store.set_certificate(host, cert2.clone()).unwrap();
        let stored2 = store.get_certificate(host).unwrap();
        assert_eq!(
            stored2,
            Some(cert2.clone()),
            "Second certificate should replace first"
        );
        assert_ne!(
            stored2,
            Some(cert1),
            "Stored certificate should not match first"
        );
    }

    #[test]
    fn test_tofu_large_certificate() {
        let store = InMemoryTofuStore::new();

        let host = "example.com";
        // Create a large certificate (10KB)
        let cert = vec![0x42; 10 * 1024];

        // Store large certificate
        store.set_certificate(host, cert.clone()).unwrap();
        let stored = store.get_certificate(host).unwrap();
        assert_eq!(
            stored,
            Some(cert),
            "Large certificate should be stored correctly"
        );
    }
}
