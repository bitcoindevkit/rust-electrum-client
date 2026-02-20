extern crate electrum_client;

use electrum_client::{Client, ConfigBuilder, ElectrumApi};
use std::sync::Arc;

fn main() {
    // Example 1: Static JWT token
    println!("Example 1: Static JWT token");

    let config = ConfigBuilder::new()
        .authorization_provider(Some(Arc::new(|| {
            // In production, fetch this from your token manager
            Some("Bearer example-jwt-token-12345".to_string())
        })))
        .build();

    match Client::from_config("tcp://localhost:50001", config) {
        Ok(client) => {
            println!("Connected to server with JWT auth");
            match client.server_features() {
                Ok(features) => println!("Server features: {:#?}", features),
                Err(e) => eprintln!("Error fetching features: {}", e),
            }
        }
        Err(e) => {
            eprintln!("Connection error: {}", e);
            eprintln!("\nNote: This example requires an Electrum server that accepts JWT auth.");
            eprintln!("Update the URL and token to match your setup.");
        }
    }

    // Example 2: Dynamic token with refresh
    // See JWT_AUTH_EXAMPLE.md for complete implementation with automatic token refresh
}
