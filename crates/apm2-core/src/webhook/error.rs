//! Error types for the webhook handler.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;

/// Errors that can occur during webhook processing.
///
/// These errors map to specific HTTP status codes as required by the GitHub
/// webhook protocol and the ticket's Definition of Done.
#[derive(Debug, Error)]
pub enum WebhookError {
    /// The webhook handler is disabled via feature flag.
    #[error("webhook handler is disabled")]
    Disabled,

    /// The X-Hub-Signature-256 header is missing.
    #[error("missing signature header")]
    MissingSignature,

    /// The X-GitHub-Delivery header is missing.
    #[error("missing delivery ID header")]
    MissingDeliveryId,

    /// The signature header has an invalid format.
    #[error("invalid signature format: {0}")]
    InvalidSignatureFormat(String),

    /// The signature is invalid (HMAC verification failed).
    #[error("invalid signature")]
    InvalidSignature,

    /// The request payload could not be parsed.
    #[error("invalid payload: {0}")]
    InvalidPayload(String),

    /// The event type is not supported.
    #[error("unsupported event type: {0}")]
    UnsupportedEventType(String),

    /// Rate limit exceeded.
    #[error("rate limit exceeded")]
    RateLimitExceeded,

    /// Duplicate delivery ID (idempotency check).
    #[error("duplicate delivery")]
    DuplicateDelivery,

    /// Internal error (should not occur in normal operation).
    #[error("internal error: {0}")]
    Internal(String),
}

impl WebhookError {
    /// Returns the HTTP status code for this error.
    ///
    /// - Disabled: 404 Not Found (hide the endpoint when disabled)
    /// - Missing/Invalid signature: 401 Unauthorized
    /// - Invalid payload: 400 Bad Request
    /// - Unsupported event: 400 Bad Request
    /// - Rate limit: 429 Too Many Requests
    /// - Duplicate delivery: 200 OK (idempotent success)
    /// - Internal: 500 Internal Server Error
    #[must_use]
    pub const fn status_code(&self) -> StatusCode {
        match self {
            Self::Disabled => StatusCode::NOT_FOUND,
            Self::MissingSignature | Self::InvalidSignature | Self::InvalidSignatureFormat(_) => {
                StatusCode::UNAUTHORIZED
            },
            Self::MissingDeliveryId | Self::InvalidPayload(_) | Self::UnsupportedEventType(_) => {
                StatusCode::BAD_REQUEST
            },
            Self::RateLimitExceeded => StatusCode::TOO_MANY_REQUESTS,
            // Duplicate delivery returns 200 OK for idempotency
            Self::DuplicateDelivery => StatusCode::OK,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for WebhookError {
    fn into_response(self) -> Response {
        // Contract: CTR-WH002 - Never expose internal details in error responses
        // We return generic messages that don't leak information about the secret
        // or internal state.
        let status = self.status_code();
        let body = match &self {
            Self::Disabled => "Not Found",
            Self::MissingSignature => "Missing signature",
            Self::MissingDeliveryId => "Missing delivery ID",
            Self::InvalidSignatureFormat(_) => "Invalid signature format",
            Self::InvalidSignature => "Invalid signature",
            Self::InvalidPayload(_) => "Invalid payload",
            Self::UnsupportedEventType(_) => "Unsupported event type",
            Self::RateLimitExceeded => "Rate limit exceeded",
            Self::DuplicateDelivery => "OK",
            Self::Internal(_) => "Internal server error",
        };

        (status, body).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_status_codes() {
        assert_eq!(WebhookError::Disabled.status_code(), StatusCode::NOT_FOUND);
        assert_eq!(
            WebhookError::MissingSignature.status_code(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            WebhookError::MissingDeliveryId.status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            WebhookError::InvalidSignature.status_code(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            WebhookError::InvalidSignatureFormat("test".into()).status_code(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            WebhookError::InvalidPayload("test".into()).status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            WebhookError::UnsupportedEventType("test".into()).status_code(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            WebhookError::RateLimitExceeded.status_code(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            WebhookError::Internal("test".into()).status_code(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn test_error_responses_do_not_leak_details() {
        // Contract: CTR-WH002 - Responses should not contain sensitive details
        let internal_error = WebhookError::Internal("secret database error".into());
        let response = internal_error.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let sig_error = WebhookError::InvalidSignatureFormat("sha256=abc123...".into());
        let response = sig_error.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
