use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use bdk_testenv::TestEnv;
use electrum_client::ElectrumApi;
use electrum_client::{Client, ConfigBuilder};
mod helper;

fn start_auth_proxy(
    target_addr: String,
    expected_auths: Option<Arc<Mutex<Vec<String>>>>,
    recorded_auth: Arc<Mutex<Vec<String>>>,
) -> std::io::Result<String> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let listen_addr = listener.local_addr()?.to_string();

    thread::spawn(move || {
        let (client_stream, _) = match listener.accept() {
            Ok(pair) => pair,
            Err(_) => return,
        };

        let expected_auths = expected_auths.clone();
        let recorded_auth = recorded_auth.clone();

        let server_stream =
            TcpStream::connect(&target_addr).expect("failed to connect to electrum target");
        let mut client_reader = BufReader::new(client_stream.try_clone().unwrap());
        let mut client_writer_copy = client_stream.try_clone().unwrap();
        let mut client_writer_error = client_stream;
        let mut server_writer = server_stream.try_clone().unwrap();

        let mut server_reader = BufReader::new(server_stream.try_clone().unwrap());
        thread::spawn(move || {
            let mut server_line = String::new();
            while let Ok(bytes_read) = server_reader.read_line(&mut server_line) {
                if bytes_read == 0 {
                    break;
                }
                client_writer_copy
                    .write_all(server_line.as_bytes())
                    .unwrap();
                client_writer_copy.flush().unwrap();
                server_line.clear();
            }
        });

        let mut line = String::new();
        let mut request_index = 0;
        while let Ok(bytes_read) = client_reader.read_line(&mut line) {
            if bytes_read == 0 {
                break;
            }

            let trimmed = line.trim_end();
            let parsed = serde_json::from_str::<serde_json::Value>(trimmed);
            let mut auth_value = None;
            let mut forward_line = trimmed.to_string();
            if let Ok(mut json) = parsed {
                if let Some(auth) = json.get("authorization").and_then(|v| v.as_str()) {
                    auth_value = Some(auth.to_string());
                }

                {
                    let mut recorded = recorded_auth.lock().unwrap();
                    recorded.push(auth_value.clone().unwrap_or_default());
                }

                let auth_ok = if let Some(expected_auths) = expected_auths.as_ref() {
                    let expected = expected_auths.lock().unwrap();
                    match expected.get(request_index) {
                        Some(expected) => auth_value.as_ref() == Some(expected),
                        None => auth_value.is_some(),
                    }
                } else {
                    true
                };

                request_index += 1;

                if !auth_ok {
                    let resp = serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": json.get("id").cloned().unwrap_or(serde_json::json!(0)),
                        "error": {"code": -32600, "message": "authorization failed"}
                    });
                    let mut out = serde_json::to_vec(&resp).unwrap();
                    out.extend_from_slice(b"\n");
                    client_writer_error.write_all(&out).unwrap();
                    client_writer_error.flush().unwrap();
                    line.clear();
                    continue;
                }

                json.as_object_mut().map(|obj| obj.remove("authorization"));
                forward_line = serde_json::to_string(&json).unwrap();
            }

            server_writer.write_all(forward_line.as_bytes()).unwrap();
            server_writer.write_all(b"\n").unwrap();
            server_writer.flush().unwrap();
            line.clear();
        }
    });

    Ok(listen_addr)
}

#[test]
fn test_auth_success_with_regtest_electrum() {
    let env = TestEnv::new().expect("start regtest env");
    env.mine_blocks(1, None).expect("mine initial block");
    env.wait_until_electrum_sees_block(Duration::from_secs(6))
        .expect("electrum should see block");

    let recorded_auth = Arc::new(Mutex::new(Vec::new()));
    let expected_auths = Arc::new(Mutex::new(vec![
        "Bearer test-token-1".to_string(),
        "Bearer test-token-1".to_string(),
    ]));
    let proxy_addr = start_auth_proxy(
        env.electrsd.electrum_url.clone(),
        Some(expected_auths),
        recorded_auth.clone(),
    )
    .expect("start auth proxy");

    let token = Arc::new(Mutex::new(Some("Bearer test-token-1".to_string())));
    let auth_provider = {
        let token = token.clone();
        Arc::new(move || token.lock().unwrap().clone())
    };

    let config = ConfigBuilder::new()
        .timeout(Some(Duration::from_secs(5)))
        .authorization_provider(Some(auth_provider))
        .build();
    let client =
        Client::from_config(&format!("tcp://{}", proxy_addr), config).expect("create client");

    client.ping().expect("ping ok");

    let auths = recorded_auth.lock().unwrap();
    assert_eq!(
        auths.as_slice(),
        ["Bearer test-token-1", "Bearer test-token-1"]
    );
}

#[test]
fn test_auth_failure_when_missing_token_with_regtest_electrum() {
    let env = TestEnv::new().expect("start regtest env");
    env.mine_blocks(1, None).expect("mine initial block");
    env.wait_until_electrum_sees_block(Duration::from_secs(6))
        .expect("electrum should see block");

    let recorded_auth = Arc::new(Mutex::new(Vec::new()));
    let expected_auths = Arc::new(Mutex::new(vec!["Bearer secret".to_string()]));
    let proxy_addr = start_auth_proxy(
        env.electrsd.electrum_url.clone(),
        Some(expected_auths),
        recorded_auth,
    )
    .expect("start auth proxy");

    let config = ConfigBuilder::new()
        .timeout(Some(Duration::from_secs(5)))
        .build();
    let client_res = Client::from_config(&format!("tcp://{}", proxy_addr), config);
    assert!(client_res.is_err());
}

#[test]
fn test_token_refresh_with_regtest_electrum() {
    let env = TestEnv::new().expect("start regtest env");
    env.mine_blocks(1, None).expect("mine initial block");
    env.wait_until_electrum_sees_block(Duration::from_secs(6))
        .expect("electrum should see block");

    let recorded_auth = Arc::new(Mutex::new(Vec::new()));
    let expected_auths = Arc::new(Mutex::new(vec![
        "Bearer test-token-1".to_string(),
        "Bearer test-token-1".to_string(),
        "Bearer test-token-2".to_string(),
    ]));
    let proxy_addr = start_auth_proxy(
        env.electrsd.electrum_url.clone(),
        Some(expected_auths),
        recorded_auth.clone(),
    )
    .expect("start auth proxy");

    let token = Arc::new(Mutex::new(Some("Bearer test-token-1".to_string())));
    let auth_provider = {
        let token = token.clone();
        Arc::new(move || token.lock().unwrap().clone())
    };

    let config = ConfigBuilder::new()
        .timeout(Some(Duration::from_secs(5)))
        .authorization_provider(Some(auth_provider.clone()))
        .build();
    let client =
        Client::from_config(&format!("tcp://{}", proxy_addr), config).expect("create client");

    client.ping().expect("first request ok");
    *token.lock().unwrap() = Some("Bearer test-token-2".to_string());
    client.ping().expect("second request ok");

    let auths = recorded_auth.lock().unwrap();
    assert_eq!(
        auths.as_slice(),
        [
            "Bearer test-token-1",
            "Bearer test-token-1",
            "Bearer test-token-2"
        ]
    );
}

#[test]
fn test_auth_with_keycloak() {
    use helper::keycloak::TestKeycloak;

    println!("Starting Keycloak container...");
    // Start Keycloak container
    let kc = TestKeycloak::start().unwrap();
    println!("Keycloak container started at: {}", kc.base_url);

    println!("Setting up Realm, Client, and User in Keycloak...");
    // Setup realm/client/user
    let token_url = kc
        .setup_realm("test-realm", "test-client", "test-user", "password")
        .expect("setup realm");
    println!("Keycloak setup complete. Token URL: {}", token_url);

    println!("Acquiring token from Keycloak...");
    // Acquire token
    let token = helper::keycloak::TestKeycloak::get_token(
        &token_url,
        "test-client",
        "test-user",
        "password",
    )
    .expect("get token");
    println!("Acquired token successfully.");

    println!("Initializing regtest environment...");
    // Use token in auth provider
    let recorded_auth = Arc::new(Mutex::new(Vec::new()));
    let env = TestEnv::new().unwrap();

    println!("Mining block and waiting for Electrum to sync...");
    env.mine_blocks(1, None).expect("mine initial block");
    env.wait_until_electrum_sees_block(Duration::from_secs(6))
        .expect("electrum should see block");
    println!("Electrum is in sync.");

    println!("Starting local auth proxy...");
    let proxy_addr = start_auth_proxy(
        env.electrsd.electrum_url.clone(),
        None,
        recorded_auth.clone(),
    )
    .expect("start auth proxy");
    println!("Auth proxy running at {}", proxy_addr);

    let token_val = Arc::new(Mutex::new(Some(format!("Bearer {}", token))));
    let auth_provider = {
        let token_val = token_val.clone();
        Arc::new(move || token_val.lock().unwrap().clone())
    };

    println!("Creating Client and performing handshake...");
    let config = ConfigBuilder::new()
        .timeout(Some(Duration::from_secs(5)))
        .authorization_provider(Some(auth_provider))
        .build();
    let client =
        Client::from_config(&format!("tcp://{}", proxy_addr), config).expect("create client");

    println!("Fetching block header 0 via proxy...");
    client.block_header_raw(0).expect("get header ok");
}
