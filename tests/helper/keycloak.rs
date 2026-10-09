use std::path::Path;
use std::process::Command;
use std::thread::sleep;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use testcontainers::core::{RunnableImage, WaitFor};
use testcontainers::runners::SyncRunner;
use testcontainers::{Container, GenericImage};

/// Minimal Keycloak test helper that starts a Keycloak container via testcontainers.
pub struct TestKeycloak {
    pub base_url: String,
    // Keep the container alive for the lifetime of the test.
    _container: Container<GenericImage>,
}

#[derive(Serialize)]
struct CreateUser {
    username: String,
    enabled: bool,
    credentials: Vec<Credential>,
}

#[derive(Serialize)]
struct Credential {
    #[serde(rename = "type")]
    typ: String,
    value: String,
    temporary: bool,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

impl TestKeycloak {
    /// Start Keycloak using testcontainers and return a helper bound to the mapped host port.
    pub fn start() -> Result<Self, Box<dyn std::error::Error>> {
        if !docker_is_available() {
            return Err("Docker is not available or the Docker daemon is not running".into());
        }

        let image = GenericImage::new("quay.io/keycloak/keycloak", "20.0.2")
            .with_exposed_port(8080)
            .with_wait_for(WaitFor::message_on_stdout("Listening on:"));

        let runnable = RunnableImage::from(image)
            .with_args(vec!["start-dev".to_string()])
            .with_env_var(("KEYCLOAK_ADMIN", "admin"))
            .with_env_var(("KEYCLOAK_ADMIN_PASSWORD", "admin"));

        let container = runnable.start().map_err(|e| {
            let hint = if docker_is_available() {
                "Docker is available, but the container runtime could not create the Keycloak container."
            } else {
                "Docker does not appear to be available or the Docker daemon is not running."
            };
            format!("{} Error: {}", hint, e)
        })?;

        sleep(Duration::from_secs(2));

        let host_port = container.get_host_port_ipv4(8080)?;
        let base_url = format!("http://127.0.0.1:{}", host_port);

        Ok(Self {
            base_url,
            _container: container,
        })
    }

    /// Create a realm, client, and user via the admin REST API.
    pub fn setup_realm(
        &self,
        realm: &str,
        client_id: &str,
        username: &str,
        password: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let admin_token = self.get_admin_token()?;

        let realm_payload = serde_json::json!({ "realm": realm, "enabled": true });
        let body = serde_json::to_vec(&realm_payload)?;
        let resp = bitreq::post(format!("{}/admin/realms", self.base_url))
            .with_header("Authorization", format!("Bearer {}", admin_token))
            .with_header("Content-Type", "application/json")
            .with_body(body)
            .send()?;
        if !(200..300).contains(&resp.status_code) {
            return Err(format!("create realm failed: {}", resp.status_code).into());
        }

        let client_payload = serde_json::json!({
            "clientId": client_id,
            "enabled": true,
            "publicClient": true,
            "directAccessGrantsEnabled": true,
            "redirectUris": ["*"],
        });
        let body = serde_json::to_vec(&client_payload)?;
        let resp = bitreq::post(format!("{}/admin/realms/{}/clients", self.base_url, realm))
            .with_header("Authorization", format!("Bearer {}", admin_token))
            .with_header("Content-Type", "application/json")
            .with_body(body)
            .send()?;
        if !(200..300).contains(&resp.status_code) {
            return Err(format!("create client failed: {}", resp.status_code).into());
        }

        let cred = Credential {
            typ: "password".to_string(),
            value: password.to_string(),
            temporary: false,
        };
        let user_payload = CreateUser {
            username: username.to_string(),
            enabled: true,
            credentials: vec![cred],
        };
        let body = serde_json::to_vec(&user_payload)?;
        let resp = bitreq::post(format!("{}/admin/realms/{}/users", self.base_url, realm))
            .with_header("Authorization", format!("Bearer {}", admin_token))
            .with_header("Content-Type", "application/json")
            .with_body(body)
            .send()?;
        if !(200..300).contains(&resp.status_code) {
            return Err(format!("create user failed: {}", resp.status_code).into());
        }

        sleep(Duration::from_secs(1));

        Ok(format!(
            "{}/realms/{}/protocol/openid-connect/token",
            self.base_url, realm
        ))
    }

    fn get_admin_token(&self) -> Result<String, Box<dyn std::error::Error>> {
        let body = build_form_body(&[
            ("grant_type", "password"),
            ("client_id", "admin-cli"),
            ("username", "admin"),
            ("password", "admin"),
        ]);
        let resp = bitreq::post(format!(
            "{}/realms/master/protocol/openid-connect/token",
            self.base_url
        ))
        .with_header("Content-Type", "application/x-www-form-urlencoded")
        .with_body(body)
        .send()?;

        if !(200..300).contains(&resp.status_code) {
            return Err(format!("admin token request failed: {}", resp.status_code).into());
        }
        let tr: TokenResponse = resp.json()?;
        Ok(tr.access_token)
    }

    /// Request an access token using password grant for the configured realm token endpoint.
    pub fn get_token(
        token_url: &str,
        client_id: &str,
        username: &str,
        password: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let body = build_form_body(&[
            ("grant_type", "password"),
            ("client_id", client_id),
            ("username", username),
            ("password", password),
        ]);
        let resp = bitreq::post(token_url)
            .with_header("Content-Type", "application/x-www-form-urlencoded")
            .with_body(body)
            .send()?;

        if !(200..300).contains(&resp.status_code) {
            return Err(format!("token request failed: {}", resp.status_code).into());
        }

        let tr: TokenResponse = resp.json()?;
        Ok(tr.access_token)
    }
}

fn build_form_body(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .enumerate()
        .map(|(idx, (key, value))| {
            let prefix = if idx == 0 {
                String::new()
            } else {
                "&".to_string()
            };
            format!("{prefix}{key}={value}")
        })
        .collect()
}

fn docker_is_available() -> bool {
    if std::env::var_os("DOCKER_HOST").is_some() {
        return true;
    }

    if ["/var/run/docker.sock", "/run/docker.sock"]
        .iter()
        .any(|p| Path::new(p).exists())
    {
        return true;
    }

    Command::new("docker")
        .arg("info")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}
