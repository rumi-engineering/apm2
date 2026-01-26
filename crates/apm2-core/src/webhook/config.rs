//! Configuration for the webhook handler.

use secrecy::SecretString;
use thiserror::Error;

use super::rate_limit::RateLimitConfig;

/// Errors that can occur when building webhook configuration.
#[derive(Debug, Error)]
pub enum WebhookConfigError {
    /// The webhook secret is missing.
    #[error("webhook secret is required")]
    MissingSecret,

    /// The webhook secret is too short.
    #[error("webhook secret must be at least {min_length} bytes")]
    SecretTooShort {
        /// Minimum required length.
        min_length: usize,
    },
}

/// Configuration for the webhook handler.
///
/// # Example
///
/// ```rust
/// use apm2_core::webhook::WebhookConfig;
/// use secrecy::SecretString;
///
/// let config = WebhookConfig::builder()
///     .secret(SecretString::from(
///         "your-secret-must-be-at-least-32-bytes-long",
///     ))
///     .enabled(true)
///     .build()
///     .unwrap();
/// ```
#[derive(Clone)]
pub struct WebhookConfig {
    /// The shared secret for HMAC-SHA256 signature validation.
    pub(crate) secret: SecretString,

    /// Whether the webhook handler is enabled.
    pub(crate) enabled: bool,

    /// Rate limiting configuration.
    pub(crate) rate_limit: RateLimitConfig,
}

impl WebhookConfig {
    /// Minimum recommended length for the webhook secret (32 bytes).
    pub const MIN_SECRET_LENGTH: usize = 32;

    /// Creates a new builder for `WebhookConfig`.
    #[must_use]
    pub fn builder() -> WebhookConfigBuilder {
        WebhookConfigBuilder::default()
    }

    /// Returns whether the webhook handler is enabled.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Returns the rate limit configuration.
    #[must_use]
    pub const fn rate_limit(&self) -> &RateLimitConfig {
        &self.rate_limit
    }
}

/// Builder for `WebhookConfig`.
#[derive(Default)]
pub struct WebhookConfigBuilder {
    secret: Option<SecretString>,
    enabled: bool,
    rate_limit: Option<RateLimitConfig>,
    skip_secret_length_check: bool,
}

impl WebhookConfigBuilder {
    /// Sets the webhook secret.
    ///
    /// The secret should be at least 32 bytes of cryptographically random data.
    #[must_use]
    pub fn secret(mut self, secret: SecretString) -> Self {
        self.secret = Some(secret);
        self
    }

    /// Sets whether the webhook handler is enabled.
    ///
    /// Default is `false`.
    #[must_use]
    pub const fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Sets the rate limit configuration.
    ///
    /// Default is 60 requests per minute.
    #[must_use]
    pub const fn rate_limit(mut self, config: RateLimitConfig) -> Self {
        self.rate_limit = Some(config);
        self
    }

    /// Skips the secret length check.
    ///
    /// **Warning**: This should only be used for testing purposes.
    /// In production, use a secret of at least 32 bytes.
    #[cfg(test)]
    #[must_use]
    pub const fn skip_secret_length_check(mut self) -> Self {
        self.skip_secret_length_check = true;
        self
    }

    /// Builds the `WebhookConfig`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The secret is not set
    /// - The secret is shorter than 32 bytes (unless check is skipped)
    pub fn build(self) -> Result<WebhookConfig, WebhookConfigError> {
        let secret = self.secret.ok_or(WebhookConfigError::MissingSecret)?;

        // Validate secret length (security requirement)
        if !self.skip_secret_length_check {
            use secrecy::ExposeSecret;
            if secret.expose_secret().len() < WebhookConfig::MIN_SECRET_LENGTH {
                return Err(WebhookConfigError::SecretTooShort {
                    min_length: WebhookConfig::MIN_SECRET_LENGTH,
                });
            }
        }

        Ok(WebhookConfig {
            secret,
            enabled: self.enabled,
            rate_limit: self.rate_limit.unwrap_or_default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;

    fn valid_secret() -> SecretString {
        // 32+ bytes
        SecretString::from("this-is-a-32-byte-secret-value!!")
    }

    fn short_secret() -> SecretString {
        SecretString::from("short")
    }

    #[test]
    fn test_build_with_valid_secret() {
        let config = WebhookConfig::builder()
            .secret(valid_secret())
            .enabled(true)
            .build()
            .unwrap();

        assert!(config.is_enabled());
        assert_eq!(
            config.secret.expose_secret(),
            "this-is-a-32-byte-secret-value!!"
        );
    }

    #[test]
    fn test_build_missing_secret() {
        let result = WebhookConfig::builder().enabled(true).build();

        assert!(matches!(result, Err(WebhookConfigError::MissingSecret)));
    }

    #[test]
    fn test_build_short_secret() {
        let result = WebhookConfig::builder()
            .secret(short_secret())
            .enabled(true)
            .build();

        assert!(matches!(
            result,
            Err(WebhookConfigError::SecretTooShort { min_length: 32 })
        ));
    }

    #[test]
    fn test_build_skip_length_check() {
        let config = WebhookConfig::builder()
            .secret(short_secret())
            .enabled(true)
            .skip_secret_length_check()
            .build()
            .unwrap();

        assert!(config.is_enabled());
    }

    #[test]
    fn test_default_disabled() {
        let config = WebhookConfig::builder()
            .secret(valid_secret())
            .build()
            .unwrap();

        assert!(!config.is_enabled());
    }

    #[test]
    fn test_custom_rate_limit() {
        let rate_config = RateLimitConfig {
            max_requests: 100,
            window_secs: 120,
            ..Default::default()
        };

        let config = WebhookConfig::builder()
            .secret(valid_secret())
            .rate_limit(rate_config)
            .build()
            .unwrap();

        assert_eq!(config.rate_limit().max_requests, 100);
        assert_eq!(config.rate_limit().window_secs, 120);
    }

    #[test]
    fn test_default_rate_limit() {
        let config = WebhookConfig::builder()
            .secret(valid_secret())
            .build()
            .unwrap();

        // Default is 60 requests per 60 seconds
        assert_eq!(config.rate_limit().max_requests, 60);
        assert_eq!(config.rate_limit().window_secs, 60);
    }
}
