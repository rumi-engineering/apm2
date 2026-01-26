//! Axum handler for GitHub webhooks.
//!
//! This module implements the HTTP handler for the webhook endpoint.
//! It validates signatures, parses payloads, and applies rate limiting.
//!
//! # Request Body Limit
//!
//! The router enforces a 100KB request body limit to prevent memory exhaustion
//! from oversized payloads. This is configured via `DefaultBodyLimit` layer.
//!
//! # Event Emission
//!
//! After successful webhook validation, the handler emits a `CIWorkflowCompleted`
//! ledger event using the [`CIEventEmitter`]. Event emission is controlled by
//! the `CI_EVENTS_ENABLED` environment variable.

use std::net::IpAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{ConnectInfo, DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;

use super::config::WebhookConfig;
use super::error::WebhookError;
use super::event_emitter::{CIEventEmitter, EmitResult};
use super::payload::{WorkflowRunCompleted, WorkflowRunPayload};
use super::rate_limit::RateLimiter;
use super::signature::SignatureValidator;

/// Header name for the GitHub HMAC-SHA256 signature.
const SIGNATURE_HEADER: &str = "x-hub-signature-256";

/// Header name for the GitHub event type.
const EVENT_HEADER: &str = "x-github-event";

/// Header name for the GitHub delivery ID.
const DELIVERY_HEADER: &str = "x-github-delivery";

/// Maximum request body size in bytes (100KB).
///
/// This limit prevents memory exhaustion from oversized payloads.
/// GitHub webhook payloads are typically small (a few KB), so 100KB
/// provides ample headroom while limiting attack surface.
const MAX_BODY_SIZE: usize = 100 * 1024;

/// Shared state for the webhook handler.
struct WebhookState {
    /// Configuration for the webhook handler.
    config: WebhookConfig,

    /// Signature validator.
    validator: SignatureValidator,

    /// Rate limiter.
    rate_limiter: RateLimiter,

    /// Event emitter for CI workflow events.
    event_emitter: CIEventEmitter,
}

/// The webhook handler wraps configuration and provides an axum router.
pub struct WebhookHandler {
    state: Arc<WebhookState>,
}

impl WebhookHandler {
    /// Creates a new webhook handler with the given configuration.
    #[must_use]
    pub fn new(config: WebhookConfig) -> Self {
        Self::with_event_emitter(config, CIEventEmitter::new())
    }

    /// Creates a new webhook handler with a custom event emitter.
    ///
    /// This is useful for testing or when custom event stores are needed.
    #[must_use]
    pub fn with_event_emitter(config: WebhookConfig, event_emitter: CIEventEmitter) -> Self {
        let validator = SignatureValidator::new(config.secret.clone());
        let rate_limiter = RateLimiter::new(config.rate_limit.clone());

        Self {
            state: Arc::new(WebhookState {
                config,
                validator,
                rate_limiter,
                event_emitter,
            }),
        }
    }

    /// Returns an axum router for the webhook endpoint.
    ///
    /// The router handles `POST /webhooks/github` and expects to receive
    /// `ConnectInfo<SocketAddr>` for rate limiting by IP.
    ///
    /// # Security Features
    ///
    /// - **Body Size Limit**: Enforces a 100KB limit via `DefaultBodyLimit` to
    ///   prevent memory exhaustion from oversized payloads.
    /// - **Rate Limiting**: Applied per source IP before signature validation.
    /// - **Signature Validation**: HMAC-SHA256 with constant-time comparison.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use std::net::SocketAddr;
    ///
    /// use apm2_core::webhook::{WebhookConfig, WebhookHandler};
    /// use secrecy::SecretString;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let config = WebhookConfig::builder()
    ///     .secret(SecretString::from("your-32-byte-or-longer-secret!!"))
    ///     .enabled(true)
    ///     .build()?;
    ///
    /// let handler = WebhookHandler::new(config);
    /// let app = handler.router();
    ///
    /// // Add to your main app router
    /// // let app = Router::new().merge(handler.router());
    /// # Ok(())
    /// # }
    /// ```
    pub fn router(&self) -> Router {
        Router::new()
            .route("/webhooks/github", post(webhook_handler))
            .layer(DefaultBodyLimit::max(MAX_BODY_SIZE))
            .with_state(Arc::clone(&self.state))
    }

    /// Returns whether the handler is enabled.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.state.config.enabled
    }

    /// Returns a reference to the event emitter.
    ///
    /// This can be used to access the event store for querying persisted events.
    #[must_use]
    pub fn event_emitter(&self) -> &CIEventEmitter {
        &self.state.event_emitter
    }
}

/// The axum handler for GitHub webhooks.
///
/// This handler:
/// 1. Checks if the feature flag is enabled
/// 2. Applies rate limiting (before signature validation to prevent denial of
///    service)
/// 3. Validates the HMAC-SHA256 signature
/// 4. Parses and validates the payload
/// 5. Emits CI workflow event (with idempotency check)
/// 6. Returns appropriate status codes
async fn webhook_handler(
    State(state): State<Arc<WebhookState>>,
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, WebhookError> {
    let ip = addr.ip();
    let delivery_id = extract_header(&headers, DELIVERY_HEADER);
    let event_type = extract_header(&headers, EVENT_HEADER);

    // Log the incoming request (without sensitive data)
    tracing::info!(
        ip = %ip,
        delivery_id = ?delivery_id,
        event_type = ?event_type,
        body_size = body.len(),
        "webhook request received"
    );

    // 1. Check feature flag (CTR-WH006)
    if !state.config.enabled {
        tracing::debug!("webhook handler is disabled");
        return Err(WebhookError::Disabled);
    }

    // 2. Apply rate limiting (CTR-WH003 - before signature validation)
    state.rate_limiter.check(ip)?;

    // 3. Extract and validate signature (CTR-WH001, CTR-WH002)
    let signature = headers
        .get(SIGNATURE_HEADER)
        .ok_or(WebhookError::MissingSignature)?
        .to_str()
        .map_err(|_| WebhookError::InvalidSignatureFormat("non-ASCII characters".into()))?;

    state.validator.verify(&body, signature)?;

    // 4. Verify event type is workflow_run
    let event_type = event_type
        .ok_or_else(|| WebhookError::InvalidPayload("missing X-GitHub-Event header".into()))?;

    if event_type != "workflow_run" {
        return Err(WebhookError::UnsupportedEventType(event_type));
    }

    // 5. Parse and validate payload (CTR-WH004)
    let payload = WorkflowRunPayload::parse(&body)?;
    let completed = payload.into_completed()?;

    // 6. Log successful processing
    log_completed_event(&completed, ip, delivery_id.as_deref());

    // 7. Emit CI workflow event (with idempotency check)
    let delivery_id_value = delivery_id.unwrap_or_else(|| {
        // Generate a fallback delivery ID if GitHub doesn't provide one
        uuid::Uuid::new_v4().to_string()
    });

    match state
        .event_emitter
        .emit(&completed, true, &delivery_id_value)?
    {
        EmitResult::Emitted { event_id } => {
            tracing::debug!(event_id = %event_id, "CI event emitted");
        }
        EmitResult::Disabled => {
            tracing::debug!("CI events disabled, event not emitted");
        }
        EmitResult::Duplicate => {
            tracing::debug!("duplicate delivery, returning OK");
            // Return OK for idempotent duplicate handling
            return Ok(StatusCode::OK);
        }
    }

    // Return 202 Accepted (webhook received and will be processed)
    Ok(StatusCode::ACCEPTED)
}

/// Extracts a header value as a string.
fn extract_header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(String::from)
}

/// Logs a successful `workflow_run.completed` event.
fn log_completed_event(event: &WorkflowRunCompleted, ip: IpAddr, delivery_id: Option<&str>) {
    tracing::info!(
        delivery_id = ?delivery_id,
        ip = %ip,
        workflow_run_id = event.workflow_run_id,
        commit_sha = %event.commit_sha,
        branch = %event.branch,
        conclusion = %event.conclusion,
        pull_requests = ?event.pull_request_numbers,
        "workflow_run.completed event processed"
    );
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use axum::http::HeaderMap;
    use bytes::Bytes;
    use secrecy::SecretString;

    use super::*;

    fn test_config(enabled: bool) -> WebhookConfig {
        WebhookConfig::builder()
            .secret(SecretString::from("test-secret-key"))
            .enabled(enabled)
            .skip_secret_length_check()
            .build()
            .unwrap()
    }

    fn compute_signature(secret: &str, payload: &[u8]) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(payload);
        let result = mac.finalize();
        let bytes = result.into_bytes();

        format!(
            "sha256={}",
            bytes.iter().fold(String::new(), |mut acc, b| {
                use std::fmt::Write;
                let _ = write!(acc, "{b:02x}");
                acc
            })
        )
    }

    fn make_payload(action: &str, conclusion: &str) -> Vec<u8> {
        format!(
            r#"{{
                "action": "{action}",
                "workflow_run": {{
                    "id": 12345,
                    "head_sha": "abc123def456",
                    "head_branch": "feature/test",
                    "conclusion": "{conclusion}",
                    "pull_requests": [{{"number": 42}}]
                }}
            }}"#
        )
        .into_bytes()
    }

    fn make_headers(signature: Option<&str>, event_type: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("x-github-delivery", "test-delivery-123".parse().unwrap());

        if let Some(sig) = signature {
            headers.insert(SIGNATURE_HEADER, sig.parse().unwrap());
        }

        if let Some(event) = event_type {
            headers.insert(EVENT_HEADER, event.parse().unwrap());
        }

        headers
    }

    fn test_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345)
    }

    /// Test helper that directly calls the `webhook_handler` function.
    async fn call_handler(
        state: Arc<WebhookState>,
        headers: HeaderMap,
        body: Vec<u8>,
    ) -> Result<StatusCode, WebhookError> {
        webhook_handler(
            State(state),
            ConnectInfo(test_addr()),
            headers,
            Bytes::from(body),
        )
        .await
    }

    fn create_test_state(enabled: bool) -> Arc<WebhookState> {
        let config = test_config(enabled);
        let validator = SignatureValidator::new(config.secret.clone());
        let rate_limiter = RateLimiter::new(config.rate_limit.clone());
        let event_emitter = CIEventEmitter::new();

        Arc::new(WebhookState {
            config,
            validator,
            rate_limiter,
            event_emitter,
        })
    }

    #[tokio::test]
    async fn test_valid_request() {
        let state = create_test_state(true);
        let payload = make_payload("completed", "success");
        let signature = compute_signature("test-secret-key", &payload);
        let headers = make_headers(Some(&signature), Some("workflow_run"));

        let result = call_handler(state, headers, payload).await;
        assert_eq!(result.unwrap(), StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn test_disabled_handler() {
        let state = create_test_state(false);
        let payload = make_payload("completed", "success");
        let signature = compute_signature("test-secret-key", &payload);
        let headers = make_headers(Some(&signature), Some("workflow_run"));

        let result = call_handler(state, headers, payload).await;
        assert!(matches!(result, Err(WebhookError::Disabled)));
    }

    #[tokio::test]
    async fn test_missing_signature() {
        let state = create_test_state(true);
        let payload = make_payload("completed", "success");
        let headers = make_headers(None, Some("workflow_run"));

        let result = call_handler(state, headers, payload).await;
        assert!(matches!(result, Err(WebhookError::MissingSignature)));
    }

    #[tokio::test]
    async fn test_invalid_signature() {
        let state = create_test_state(true);
        let payload = make_payload("completed", "success");
        // Use wrong secret
        let signature = compute_signature("wrong-secret", &payload);
        let headers = make_headers(Some(&signature), Some("workflow_run"));

        let result = call_handler(state, headers, payload).await;
        assert!(matches!(result, Err(WebhookError::InvalidSignature)));
    }

    #[tokio::test]
    async fn test_invalid_payload() {
        let state = create_test_state(true);
        let payload = b"not valid json".to_vec();
        let signature = compute_signature("test-secret-key", &payload);
        let headers = make_headers(Some(&signature), Some("workflow_run"));

        let result = call_handler(state, headers, payload).await;
        assert!(matches!(result, Err(WebhookError::InvalidPayload(_))));
    }

    #[tokio::test]
    async fn test_unsupported_event_type() {
        let state = create_test_state(true);
        let payload = make_payload("completed", "success");
        let signature = compute_signature("test-secret-key", &payload);
        // Use wrong event type
        let headers = make_headers(Some(&signature), Some("push"));

        let result = call_handler(state, headers, payload).await;
        assert!(matches!(result, Err(WebhookError::UnsupportedEventType(_))));
    }

    #[tokio::test]
    async fn test_non_completed_action() {
        let state = create_test_state(true);
        let payload = make_payload("requested", "success");
        let signature = compute_signature("test-secret-key", &payload);
        let headers = make_headers(Some(&signature), Some("workflow_run"));

        let result = call_handler(state, headers, payload).await;
        assert!(matches!(result, Err(WebhookError::UnsupportedEventType(_))));
    }

    #[tokio::test]
    async fn test_failure_conclusion() {
        let state = create_test_state(true);
        let payload = make_payload("completed", "failure");
        let signature = compute_signature("test-secret-key", &payload);
        let headers = make_headers(Some(&signature), Some("workflow_run"));

        let result = call_handler(state, headers, payload).await;
        // Even failures are accepted - it's a valid event
        assert_eq!(result.unwrap(), StatusCode::ACCEPTED);
    }

    #[test]
    fn test_is_enabled() {
        let enabled_handler = WebhookHandler::new(test_config(true));
        assert!(enabled_handler.is_enabled());

        let disabled_handler = WebhookHandler::new(test_config(false));
        assert!(!disabled_handler.is_enabled());
    }

    #[test]
    fn test_router_creation() {
        let handler = WebhookHandler::new(test_config(true));
        let _router = handler.router();
        // Just verify router can be created without panic
    }
}
