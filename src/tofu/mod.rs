use std::{fs::create_dir_all, path::PathBuf, sync::Mutex};
use rusqlite::{Connection, OptionalExtension, Result as SqlResult, params};


#[derive(Debug)]
pub struct TofuData {
    db_path: PathBuf,
    connection: Mutex<Connection>
}



impl TofuData {
    pub fn setData(&self, host: &str, cert: Vec<u8>) -> SqlResult<()> {
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
