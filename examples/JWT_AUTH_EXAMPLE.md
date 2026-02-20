# JWT Authentication with Electrum Client

This guide demonstrates how to use dynamic JWT authentication with the electrum-client library.

## Overview

The electrum-client now supports embedding authorization tokens (such as JWT Bearer tokens) directly in JSON-RPC requests. This is achieved through an `AuthProvider` callback that is invoked before each request.

## Basic Usage

```rust
use electrum_client::{Client, ConfigBuilder};
use std::sync::{Arc, RwLock};

// Simple example: Static token
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let token = "your-jwt-token-here".to_string();

    let config = ConfigBuilder::new()
        .authorization_provider(Some(Arc::new(move || {
            Some(format!("Bearer {}", token))
        })))
        .build();

    let client = Client::from_config("tcp://your-server:50001", config)?;

    // All RPC calls will now include: "authorization": "Bearer your-jwt-token-here"
    let features = client.server_features()?;
    println!("{:?}", features);

    Ok(())
}
```

## Advanced: Token Refresh with Keycloak

This example demonstrates automatic token refresh every 4 minutes (before the 5-minute expiration).

```rust
use electrum_client::{Client, ConfigBuilder, ElectrumApi};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::time::sleep;

/// Manages JWT tokens from Keycloak with automatic refresh
struct KeycloakTokenManager {
    token: Arc<RwLock<Option<String>>>,
    keycloak_url: String,
    client_id: String,
    client_secret: String,
}

impl KeycloakTokenManager {
    fn new(keycloak_url: String, client_id: String, client_secret: String) -> Self {
        Self {
            token: Arc::new(RwLock::new(None)),
            keycloak_url,
            client_id,
            client_secret,
        }
    }

    /// Get the current token (for the auth provider)
    fn get_token(&self) -> Option<String> {
        self.token.read().unwrap().clone()
    }

    /// Fetch a fresh token from Keycloak
    async fn fetch_token(&self) -> Result<String, Box<dyn std::error::Error>> {
        // Example using reqwest to get JWT from Keycloak
        let client = reqwest::Client::new();
        let response = client
            .post(&format!("{}/protocol/openid-connect/token", self.keycloak_url))
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", &self.client_id),
                ("client_secret", &self.client_secret),
            ])
            .send()
            .await?;

        let json: serde_json::Value = response.json().await?;
        let access_token = json["access_token"]
            .as_str()
            .ok_or("Missing access_token")?
            .to_string();

        Ok(format!("Bearer {}", access_token))
    }

    /// Background task that refreshes the token every 4 minutes
    async fn refresh_loop(self: Arc<Self>) {
        loop {
            // Refresh every 4 minutes (tokens expire at 5 minutes)
            sleep(Duration::from_secs(240)).await;

            match self.fetch_token().await {
                Ok(new_token) => {
                    println!("Token refreshed successfully");
                    *self.token.write().unwrap() = Some(new_token);
                }
                Err(e) => {
                    eprintln!("Failed to refresh token: {}", e);
                    // Keep using old token until we can refresh
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup token manager
    let token_manager = Arc::new(KeycloakTokenManager::new(
        "https://your-keycloak-server/auth/realms/your-realm".to_string(),
        "your-client-id".to_string(),
        "your-client-secret".to_string(),
    ));

    // Fetch initial token
    let initial_token = token_manager.fetch_token().await?;
    *token_manager.token.write().unwrap() = Some(initial_token);

    // Start background refresh task
    let tm_clone = token_manager.clone();
    tokio::spawn(async move {
        tm_clone.refresh_loop().await;
    });

    // Create Electrum client with dynamic auth provider
    let tm_for_provider = token_manager.clone();
    let config = ConfigBuilder::new()
        .authorization_provider(Some(Arc::new(move || {
            tm_for_provider.get_token()
        })))
        .build();

    let client = Client::from_config("tcp://your-api-gateway:50001", config)?;

    // All RPC calls will automatically include fresh JWT tokens
    loop {
        match client.server_features() {
            Ok(features) => println!("Connected: {:?}", features),
            Err(e) => eprintln!("Error: {}", e),
        }

        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}
```

## Integration with BDK

To use with BDK, create the electrum client with your config, then wrap it:

```rust
use bdk_electrum::BdkElectrumClient;
use electrum_client::{Client, ConfigBuilder};
use std::sync::Arc;
use std::time::Duration;

let config = ConfigBuilder::new()
    .authorization_provider(Some(Arc::new(move || {
        token_manager.get_token()
    })))
    .timeout(Some(Duration::from_secs(30)))
    .build();

let electrum_client = Client::from_config("tcp://your-api-gateway:50001", config)?;
let bdk_client = BdkElectrumClient::new(electrum_client);
```

## JSON-RPC Request Format

With the auth provider configured, each JSON-RPC request will include the authorization field:

```json
{
  "jsonrpc": "2.0",
  "method": "blockchain.headers.subscribe",
  "params": [],
  "id": 1,
  "authorization": "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

If the provider returns `None`, the authorization field is omitted from the request.

## Thread Safety

The `AuthProvider` type is defined as:
```rust
pub type AuthProvider = Arc<dyn Fn() -> Option<String> + Send + Sync>;
```

This ensures thread-safe access to tokens across all RPC calls.
