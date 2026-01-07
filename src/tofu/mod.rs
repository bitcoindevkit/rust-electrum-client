use std::{fs::create_dir_all, path::PathBuf, sync::Mutex};
use rusqlite::{Connection, OptionalExtension, Result as SqlResult, params};

#[derive(Debug)]
pub struct TofuData {
    db_path: PathBuf,
    connection: Mutex<Connection>
}



impl TofuData {
    pub fn setData(&self, host: &str, cert: Vec<u8>) -> SqlResult<()> {
        if cert.is_empty() {
            return Err(rusqlite::Error::InvalidQuery);
        }
        
        let connection = self.connection.lock().unwrap();
        let sql = "INSERT INTO tofu (host, cert) VALUES (?1, ?2)
        ON CONFLICT(host) DO UPDATE SET cert = excluded.cert";
        
        connection.execute(sql, params![host, cert])?;
        
        Ok(())
    }

    pub fn getData(&self, host: &str) -> SqlResult<Option<Vec<u8>>> {
        let connection = self.connection.lock().unwrap();
        let sql = "SELECT cert FROM tofu WHERE host = ?1";

        connection
            .query_row(sql, params![host], |row| row.get(0))
            .optional()
    }

    pub fn setup() -> SqlResult<Self> {
        let mut path = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        path.push(".electrum-client");
        create_dir_all(&path).ok();
        path.push("tofu.sqlite");

        let connection = Connection::open(&path)?;
        let sql = "CREATE TABLE IF NOT EXISTS tofu(
            host TEXT PRIMARY KEY,
            cert BLOB NOT NULL
        )";

        connection.execute(sql, [])?;

        Ok(TofuData { 
            db_path: path, 
            connection: Mutex::new(connection) 
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn setup_with_path(db_path: PathBuf) -> SqlResult<TofuData> {
        if let Some(parent) = db_path.parent() {
            create_dir_all(parent).ok();
        }
        let connection = Connection::open(&db_path)?;
        let sql = "CREATE TABLE IF NOT EXISTS tofu(
            host TEXT PRIMARY KEY,
            cert BLOB NOT NULL
        )";

        connection.execute(sql, [])?;

        Ok(TofuData { 
            db_path, 
            connection: Mutex::new(connection) 
        })
    }

    fn create_temp_db() -> (PathBuf, TofuData) {
        let temp_dir = std::env::temp_dir();
        let counter = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let db_path = temp_dir.join(format!("tofu_test_{}_{}.sqlite", std::process::id(), counter));
        // Clean up any existing test database
        let _ = fs::remove_file(&db_path);
        let store = setup_with_path(db_path.clone()).unwrap();
        (db_path, store)
    }

    fn cleanup_temp_db(db_path: &Path) {
        // Small delay to ensure file handles are released
        std::thread::sleep(std::time::Duration::from_millis(50));
        let _ = fs::remove_file(db_path);
    }

    #[test]
    fn test_tofu_first_use() {
        let (db_path, store) = create_temp_db();
        
        let host = "example.com";
        let cert = b"test certificate data".to_vec();

        // First use: certificate should not exist
        let result = store.getData(host).unwrap();
        assert!(result.is_none(), "Certificate should not exist on first use");

        store.setData(host, cert.clone()).unwrap();

        let stored = store.getData(host).unwrap();
        assert_eq!(stored, Some(cert), "Certificate should be stored");

        drop(store);
        cleanup_temp_db(&db_path);
    }

    #[test]
    fn test_tofu_certificate_match() {
        let (db_path, store) = create_temp_db();
        
        let host = "example.com";
        let cert = b"test certificate data".to_vec();

        // Store certificate
        store.setData(host, cert.clone()).unwrap();

        // Retrieve and verify it matches
        let stored = store.getData(host).unwrap();
        assert_eq!(stored, Some(cert), "Stored certificate should match");

        drop(store);
        cleanup_temp_db(&db_path);
    }

    #[test]
    fn test_tofu_certificate_change() {
        let (db_path, store) = create_temp_db();
        
        let host = "example.com";
        let cert1 = b"first certificate".to_vec();
        let cert2 = b"second certificate".to_vec();

        // Store first certificate
        store.setData(host, cert1.clone()).unwrap();
        let stored1 = store.getData(host).unwrap();
        assert_eq!(stored1, Some(cert1.clone()), "First certificate should be stored");

        // Update with different certificate
        store.setData(host, cert2.clone()).unwrap();
        let stored2 = store.getData(host).unwrap();
        assert_eq!(stored2, Some(cert2.clone()), "Second certificate should replace first");
        assert_ne!(stored2, Some(cert1), "Stored certificate should not match first");

        drop(store);
        cleanup_temp_db(&db_path);
    }

    #[test]
    fn test_tofu_persistence() {
        let temp_dir = std::env::temp_dir();
        let db_path = temp_dir.join(format!("tofu_persistence_test_{}.sqlite", std::process::id()));
        let _ = fs::remove_file(&db_path);

        let host = "example.com";
        let cert = b"persistent certificate".to_vec();

        // Create first store instance and save certificate
        {
            let store1 = setup_with_path(db_path.clone()).unwrap();
            store1.setData(host, cert.clone()).unwrap();
        }

        // Create second store instance and verify certificate persists
        {
            let store2 = setup_with_path(db_path.clone()).unwrap();
            let stored = store2.getData(host).unwrap();
            assert_eq!(stored, Some(cert), "Certificate should persist across instances");
        }

        cleanup_temp_db(&db_path);
    }

    #[test]
    fn test_tofu_empty_certificate() {
        let (db_path, store) = create_temp_db();
        
        let host = "example.com";
        let cert = vec![];

        // Attempt to store empty certificate should fail
        let result = store.setData(host, cert.clone());
        assert!(result.is_err(), "Storing empty certificate should return an error");

        drop(store);
        cleanup_temp_db(&db_path);
    }

    #[test]
    fn test_tofu_large_certificate() {
        let (db_path, store) = create_temp_db();
        
        let host = "example.com";
        // Create a large certificate (10KB)
        let cert = vec![0x42; 10 * 1024];

        // Store large certificate
        store.setData(host, cert.clone()).unwrap();
        let stored = store.getData(host).unwrap();
        assert_eq!(stored, Some(cert), "Large certificate should be stored correctly");

        drop(store);
        cleanup_temp_db(&db_path);
    }
}
