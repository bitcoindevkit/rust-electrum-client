use std::sync::Arc;
use std::time::Duration;

/// A function that provides authorization tokens dynamically (e.g., for JWT refresh)
pub type AuthProvider = Arc<dyn Fn() -> Option<String> + Send + Sync>;

/// Configuration for an electrum client
///
/// Refer to [`Client::from_config`] and [`ClientType::from_config`].
///
/// [`Client::from_config`]: crate::Client::from_config
/// [`ClientType::from_config`]: crate::ClientType::from_config
#[derive(Clone)]
pub struct Config {
    /// Proxy socks5 configuration, default None
    socks5: Option<Socks5Config>,
    /// timeout in seconds, default None (depends on TcpStream default)
    timeout: Option<Duration>,
    /// number of retry if any error, default 1
    retry: u8,
    /// when ssl, validate the domain, default true
    validate_domain: bool,
    /// Optional authorization provider for dynamic token injection
    authorization_provider: Option<AuthProvider>,
}

// Custom Debug impl because AuthProvider doesn't implement Debug
impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("socks5", &self.socks5)
            .field("timeout", &self.timeout)
            .field("retry", &self.retry)
            .field("validate_domain", &self.validate_domain)
            .field(
                "authorization_provider",
                &self.authorization_provider.as_ref().map(|_| "<provider>"),
            )
            .finish()
    }
}

/// Configuration for Socks5
#[derive(Debug, Clone)]
pub struct Socks5Config {
    /// The address of the socks5 service
    pub addr: String,
    /// Optional credential for the service
    pub credentials: Option<Socks5Credential>,
}

/// Credential for the proxy
#[derive(Debug, Clone)]
pub struct Socks5Credential {
    pub username: String,
    pub password: String,
}

/// [Config] Builder
pub struct ConfigBuilder {
    config: Config,
}

impl ConfigBuilder {
    /// Create a builder with a default config, equivalent to [ConfigBuilder::default()]
    pub fn new() -> Self {
        ConfigBuilder {
            config: Config::default(),
        }
    }

    /// Set the socks5 config if Some, it accept an `Option` because it's easier for the caller to use
    /// in a method chain
    pub fn socks5(mut self, socks5_config: Option<Socks5Config>) -> Self {
        self.config.socks5 = socks5_config;
        self
    }

    /// Sets the timeout
    pub fn timeout(mut self, timeout: Option<Duration>) -> Self {
        self.config.timeout = timeout;
        self
    }

    /// Sets the retry attempts number
    pub fn retry(mut self, retry: u8) -> Self {
        self.config.retry = retry;
        self
    }

    /// Sets if the domain has to be validated
    pub fn validate_domain(mut self, validate_domain: bool) -> Self {
        self.config.validate_domain = validate_domain;
        self
    }

    /// Sets the authorization provider for dynamic token injection
    pub fn authorization_provider(mut self, provider: Option<AuthProvider>) -> Self {
        self.config.authorization_provider = provider;
        self
    }

    /// Return the config and consume the builder
    pub fn build(self) -> Config {
        self.config
    }
}

impl Default for ConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Socks5Config {
    /// Socks5Config constructor without credentials
    pub fn new(addr: impl ToString) -> Self {
        let addr = addr.to_string().replacen("socks5://", "", 1);
        Socks5Config {
            addr,
            credentials: None,
        }
    }

    /// Socks5Config constructor if we have credentials
    pub fn with_credentials(addr: impl ToString, username: String, password: String) -> Self {
        let mut config = Socks5Config::new(addr);
        config.credentials = Some(Socks5Credential { username, password });
        config
    }
}

impl Config {
    /// Get the configuration for `socks5`
    ///
    /// Set this with [`ConfigBuilder::socks5`]
    pub fn socks5(&self) -> &Option<Socks5Config> {
        &self.socks5
    }

    /// Get the configuration for `retry`
    ///
    /// Set this with [`ConfigBuilder::retry`]
    pub fn retry(&self) -> u8 {
        self.retry
    }

    /// Get the configuration for `timeout`
    ///
    /// Set this with [`ConfigBuilder::timeout`]
    pub fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    /// Get the configuration for `validate_domain`
    ///
    /// Set this with [`ConfigBuilder::validate_domain`]
    pub fn validate_domain(&self) -> bool {
        self.validate_domain
    }

    /// Get the configuration for `authorization_provider`
    ///
    /// Set this with [`ConfigBuilder::authorization_provider`]
    pub fn authorization_provider(&self) -> &Option<AuthProvider> {
        &self.authorization_provider
    }

    /// Convenience method for calling [`ConfigBuilder::new`]
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::new()
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            socks5: None,
            timeout: None,
            retry: 1,
            validate_domain: true,
            authorization_provider: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_authorization_provider_builder() {
        let token = "test-token-123".to_string();
        let provider = Arc::new(move || Some(format!("Bearer {}", token)));

        let config = ConfigBuilder::new()
            .authorization_provider(Some(provider.clone()))
            .build();

        assert!(config.authorization_provider().is_some());

        // Test that the provider returns the expected value
        if let Some(auth_provider) = config.authorization_provider() {
            assert_eq!(auth_provider(), Some("Bearer test-token-123".to_string()));
        }
    }

    #[test]
    fn test_authorization_provider_none() {
        let config = ConfigBuilder::new().build();

        assert!(config.authorization_provider().is_none());
    }

    #[test]
    fn test_authorization_provider_returns_none() {
        let provider = Arc::new(|| None);

        let config = ConfigBuilder::new()
            .authorization_provider(Some(provider))
            .build();

        assert!(config.authorization_provider().is_some());

        // Test that the provider returns None
        if let Some(auth_provider) = config.authorization_provider() {
            assert_eq!(auth_provider(), None);
        }
    }

    #[test]
    fn test_authorization_provider_dynamic_token() {
        use std::sync::RwLock;

        // Simulate a token that can be updated
        let token = Arc::new(RwLock::new("initial-token".to_string()));
        let token_clone = token.clone();

        let provider = Arc::new(move || Some(token_clone.read().unwrap().clone()));

        let config = ConfigBuilder::new()
            .authorization_provider(Some(provider.clone()))
            .build();

        // Initial token
        if let Some(auth_provider) = config.authorization_provider() {
            assert_eq!(auth_provider(), Some("initial-token".to_string()));
        }

        // Update the token
        *token.write().unwrap() = "refreshed-token".to_string();

        // Provider should return the new token
        if let Some(auth_provider) = config.authorization_provider() {
            assert_eq!(auth_provider(), Some("refreshed-token".to_string()));
        }
    }

    #[test]
    fn test_config_debug_with_provider() {
        let provider = Arc::new(|| Some("secret-token".to_string()));

        let config = ConfigBuilder::new()
            .authorization_provider(Some(provider))
            .build();

        let debug_str = format!("{:?}", config);

        // Should show <provider> instead of the actual function pointer
        assert!(debug_str.contains("<provider>"));
        // Should not leak the token value
        assert!(!debug_str.contains("secret-token"));
    }

    #[test]
    fn test_config_debug_without_provider() {
        let config = ConfigBuilder::new().build();

        let debug_str = format!("{:?}", config);

        // Should show None for authorization_provider
        assert!(debug_str.contains("authorization_provider"));
    }
}
