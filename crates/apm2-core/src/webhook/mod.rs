//! GitHub webhook handler for CI completion events.
//!
//! This module implements a secure webhook handler for receiving GitHub
//! `workflow_run.completed` events. It validates HMAC-SHA256 signatures,
//! parses payloads, and applies rate limiting.
//!
//! # Security Model
//!
//! The webhook handler enforces several security properties:
//!
//! - **Signature Validation**: All requests must have a valid HMAC-SHA256
//!   signature in the `X-Hub-Signature-256` header. The signature is validated
//!   using constant-time comparison to prevent timing attacks.
//!
//! - **Rate Limiting**: Requests are rate-limited per source IP to prevent
//!   abuse and denial of service.
//!
//! - **Feature Flag**: The endpoint can be disabled via the
//!   `WEBHOOK_HANDLER_ENABLED` feature flag.
//!
//! # Example
//!
//! ```rust,no_run
//! use apm2_core::webhook::{WebhookConfig, WebhookHandler};
//! use secrecy::SecretString;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = WebhookConfig::builder()
//!     .secret(SecretString::from("your-webhook-secret"))
//!     .enabled(true)
//!     .build()?;
//!
//! let handler = WebhookHandler::new(config);
//! // Use handler.router() to get the axum router
//! # Ok(())
//! # }
//! ```
//!
//! # Contracts
//!
//! - [CTR-WH001] Signature validation uses constant-time comparison.
//! - [CTR-WH002] Webhook secret is never logged or exposed in error messages.
//! - [CTR-WH003] Rate limiting is applied before signature validation.
//! - [CTR-WH004] Invalid payloads are rejected with 400 Bad Request.
//! - [CTR-WH005] Invalid signatures are rejected with 401 Unauthorized.
//! - [CTR-WH006] Rate limit exceeded returns 429 Too Many Requests.
//!
//! # Invariants
//!
//! - [INV-WH001] Feature flag state is immutable after handler construction.
//! - [INV-WH002] Rate limiter state is thread-safe.
//! - [INV-WH003] Cleanup is called periodically to bound memory usage.

mod config;
mod error;
pub mod event_emitter;
mod handler;
mod payload;
mod rate_limit;
mod signature;

#[cfg(test)]
mod tests;

pub use config::{WebhookConfig, WebhookConfigBuilder, WebhookConfigError};
pub use error::WebhookError;
pub use event_emitter::{CIEventEmitter, EmitResult};
pub use handler::WebhookHandler;
pub use payload::{WorkflowConclusion, WorkflowRunCompleted, WorkflowRunPayload};
pub use rate_limit::{RateLimitConfig, RateLimiter};
pub use signature::SignatureValidator;
