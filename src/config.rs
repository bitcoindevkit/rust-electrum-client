use crate::Error;
use std::time::Duration;

/// [Client] configuration options.
#[derive(Debug, Clone)]
pub struct Config {
    /// Proxy socks5 configuration, default None
    #[cfg(feature = "proxy")]
    socks5: Option<Socks5Config>,
    /// timeout in seconds, default None (depends on TcpStream default)
    timeout: Option<Duration>,
    /// number of retry if any error, default 1
    retry: u8,
    /// when ssl, validate the domain, default true
    #[cfg(any(feature = "openssl", feature = "rustls"))]
    validate_domain: bool,
}

/// Configuration for Socks5
#[cfg(feature = "proxy")]
#[derive(Debug, Clone)]
pub struct Socks5Config {
    /// The address of the socks5 service
    pub addr: String,
    /// Optional credential for the service
    pub credentials: Option<Socks5Credential>,
}

/// Credential for the proxy
#[cfg(feature = "proxy")]
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
    #[cfg(feature = "proxy")]
    pub fn socks5(mut self, socks5_config: Option<Socks5Config>) -> Result<Self, Error> {
        if socks5_config.is_some() && self.config.timeout.is_some() {
            return Err(Error::BothSocksAndTimeout);
        }
        self.config.socks5 = socks5_config;
        Ok(self)
    }

    /// Sets the timeout
    pub fn timeout(mut self, timeout: Option<u8>) -> Result<Self, Error> {
        #[cfg(feature = "proxy")]
        {
            if timeout.is_some() && self.config.socks5.is_some() {
                return Err(Error::BothSocksAndTimeout);
            }
        }
        self.config.timeout = timeout.map(|t| Duration::from_secs(t as u64));
        Ok(self)
    }

    /// Sets the retry attempts number
    pub fn retry(mut self, retry: u8) -> Self {
        self.config.retry = retry;
        self
    }

    /// Sets if the domain has to be validated
    #[cfg(any(feature = "openssl", feature = "rustls"))]
    pub fn validate_domain(mut self, validate_domain: bool) -> Self {
        self.config.validate_domain = validate_domain;
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

#[cfg(feature = "proxy")]
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
    /// Get the socks5 config option.
    #[cfg(feature = "proxy")]
    pub fn socks5(&self) -> &Option<Socks5Config> {
        &self.socks5
    }

    /// Get the retry config option.
    pub fn retry(&self) -> u8 {
        self.retry
    }

    /// Get the timeout config option.
    pub fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    /// Get the validate_domain config option.
    #[cfg(any(feature = "openssl", feature = "rustls"))]
    pub fn validate_domain(&self) -> bool {
        self.validate_domain
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            #[cfg(feature = "proxy")]
            socks5: None,
            timeout: None,
            retry: 1,
            #[cfg(any(feature = "openssl", feature = "rustls"))]
            validate_domain: true,
        }
    }
}
