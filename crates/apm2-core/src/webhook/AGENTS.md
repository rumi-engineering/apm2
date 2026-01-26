# webhook

> GitHub webhook handler for CI completion events with HMAC-SHA256 signature validation.

## Overview

The `webhook` module implements a secure HTTP endpoint for receiving GitHub `workflow_run.completed` webhooks. It provides:

- HMAC-SHA256 signature validation using the `X-Hub-Signature-256` header
- Payload parsing for `workflow_run.completed` events
- Per-IP rate limiting to prevent abuse
- Feature flag to enable/disable the endpoint

This module is part of RFC-0008's event-driven agent handoff system, where CI completion events trigger work item state transitions without requiring agent polling.

```
                            +-----------------+
  GitHub Actions            |  Webhook        |
  workflow_run.completed -->|  Handler        |
                            |  +-----------+  |
                            |  | Signature |  |
                            |  | Validator |  |
                            |  +-----------+  |
                            |  +-----------+  |
                            |  | Rate      |  |
                            |  | Limiter   |  |
                            |  +-----------+  |
                            +-----------------+
                                    |
                                    v
                            WorkflowRunCompleted
                            (processed event)
```

## Key Types

### `WebhookConfig`

```rust
pub struct WebhookConfig {
    secret: SecretString,      // HMAC-SHA256 secret
    enabled: bool,             // Feature flag
    rate_limit: RateLimitConfig,
}
```

Configuration for the webhook handler. Built using `WebhookConfig::builder()`.

### `WebhookHandler`

```rust
pub struct WebhookHandler {
    state: Arc<WebhookState>,
}
```

The main handler type. Provides `router()` to get an axum router for the `/webhooks/github` endpoint.

### `WorkflowRunCompleted`

```rust
pub struct WorkflowRunCompleted {
    pub workflow_run_id: u64,
    pub commit_sha: String,
    pub branch: String,
    pub conclusion: WorkflowConclusion,
    pub pull_request_numbers: Vec<u64>,
}
```

Normalized event data extracted from a valid `workflow_run.completed` webhook.

### `WorkflowConclusion`

```rust
pub enum WorkflowConclusion {
    Success,
    Failure,
    Cancelled,
    Skipped,
    TimedOut,
    ActionRequired,
    Stale,
    Neutral,
}
```

The possible conclusions of a GitHub Actions workflow run.

### `SignatureValidator`

```rust
pub struct SignatureValidator {
    secret: SecretString,
}
```

Validates HMAC-SHA256 signatures using constant-time comparison.

### `RateLimiter`

```rust
pub struct RateLimiter {
    config: RateLimitConfig,
    state: RwLock<HashMap<IpAddr, Vec<Instant>>>,
}
```

In-memory sliding window rate limiter, tracked per source IP.

## Invariants

- [INV-WH001] Feature flag state is immutable after handler construction.
- [INV-WH002] Rate limiter state is thread-safe (uses `RwLock`).

## Contracts

- [CTR-WH001] Signature validation uses constant-time comparison to prevent timing attacks.
- [CTR-WH002] Webhook secret is never logged or exposed in error messages.
- [CTR-WH003] Rate limiting is applied before signature validation.
- [CTR-WH004] Invalid payloads are rejected with 400 Bad Request.
- [CTR-WH005] Invalid signatures are rejected with 401 Unauthorized.
- [CTR-WH006] Rate limit exceeded returns 429 Too Many Requests.

## HTTP Status Codes

| Condition | Status Code | Description |
|-----------|-------------|-------------|
| Valid request | 202 Accepted | Webhook received and processed |
| Handler disabled | 404 Not Found | Hides endpoint existence |
| Missing signature | 401 Unauthorized | `X-Hub-Signature-256` required |
| Invalid signature | 401 Unauthorized | HMAC verification failed |
| Invalid payload | 400 Bad Request | JSON parse error or invalid structure |
| Unsupported event | 400 Bad Request | Not `workflow_run.completed` |
| Rate limited | 429 Too Many Requests | Exceeded rate limit |

## Public API

### Configuration

```rust
// Create webhook configuration
let config = WebhookConfig::builder()
    .secret(SecretString::from("your-32-byte-or-longer-secret!!"))
    .enabled(true)
    .rate_limit(RateLimitConfig {
        max_requests: 60,
        window_secs: 60,
    })
    .build()?;

// Create handler
let handler = WebhookHandler::new(config);

// Get axum router
let router = handler.router();
```

### Signature Validation

```rust
let validator = SignatureValidator::new(secret);
validator.verify(&payload_bytes, "sha256=abc123...")?;
```

### Rate Limiting

```rust
let limiter = RateLimiter::new(RateLimitConfig::default());
limiter.check(client_ip)?;
```

## Security Considerations

### Webhook Secret

The webhook secret MUST be:
- At least 32 bytes of cryptographically random data
- Stored securely (environment variable or secrets manager)
- Never logged or exposed in error messages
- Rotated periodically

### Timing Attack Prevention

Signature comparison uses the `subtle` crate's `ConstantTimeEq` trait to prevent timing attacks that could leak information about the secret.

### Rate Limiting

Rate limiting is applied BEFORE signature validation (CTR-WH003) to prevent attackers from using the endpoint for DoS attacks or signature oracle attacks.

The rate limiter includes automatic cleanup of stale entries (INV-WH003) to prevent memory exhaustion from IP address spoofing attacks. Cleanup runs probabilistically every N requests (configurable via `cleanup_interval`, default: 100).

### Request Body Limit

The router enforces a 100KB request body limit via `DefaultBodyLimit` to prevent memory exhaustion from oversized payloads. GitHub webhook payloads are typically a few KB, so this limit provides ample headroom.

### Load Balancer / Reverse Proxy Deployment

**IMPORTANT**: The rate limiter uses `ConnectInfo<SocketAddr>` to obtain the client IP address. This has implications for deployment:

#### Direct Exposure (Recommended for Simplicity)

If the webhook handler is exposed directly to the internet (no load balancer/reverse proxy):
- Rate limiting works correctly using the actual client IP
- No additional configuration needed

#### Behind a Load Balancer / Reverse Proxy

If deployed behind a load balancer, `ConnectInfo<SocketAddr>` will return the load balancer's IP address, causing:
1. **Shared rate limiting**: All clients share the same rate limit (the LB's IP), potentially causing legitimate requests to be rejected
2. **Ineffective rate limiting**: An attacker can exhaust the shared limit, causing DoS for all legitimate clients

**Mitigation Options**:

1. **Configure the load balancer to forward real client IP**: Most load balancers can add the `X-Forwarded-For` header. The application would need to be modified to read this header when running behind a trusted proxy.

2. **Use a dedicated IP allowlist**: If GitHub webhook IPs are known, configure the load balancer to allow only those IPs and disable rate limiting, relying on signature validation alone.

3. **Deploy directly**: Expose the webhook endpoint directly without a reverse proxy, using firewall rules to restrict access to GitHub's IP ranges.

**Current Implementation**: This handler currently uses `ConnectInfo<SocketAddr>` only. If you need `X-Forwarded-For` support, you must:
- Verify the request comes from a trusted proxy
- Parse and validate the `X-Forwarded-For` header carefully (it can be spoofed if not from a trusted proxy)
- Consider using the `axum-client-ip` crate or similar for robust client IP extraction

### Error Messages

Error responses contain generic messages that do not leak internal details (CTR-WH002). For example, signature failures always return "Invalid signature" regardless of whether the issue was format or verification.

## Examples

### Basic Usage

```rust
use apm2_core::webhook::{WebhookConfig, WebhookHandler};
use secrecy::SecretString;

let config = WebhookConfig::builder()
    .secret(SecretString::from("your-32-byte-or-longer-secret!!"))
    .enabled(true)
    .build()
    .unwrap();

let handler = WebhookHandler::new(config);

// Add to your axum app
let app = axum::Router::new()
    .merge(handler.router());
```

### Environment-Based Configuration

```rust
use std::env;
use secrecy::SecretString;

let secret = SecretString::from(
    env::var("GITHUB_WEBHOOK_SECRET")
        .expect("GITHUB_WEBHOOK_SECRET must be set")
);

let enabled = env::var("WEBHOOK_HANDLER_ENABLED")
    .map(|v| v == "true")
    .unwrap_or(false);

let config = WebhookConfig::builder()
    .secret(secret)
    .enabled(enabled)
    .build()
    .unwrap();
```

## Related Modules

- [`apm2_core::crypto`](../crypto/AGENTS.md) - Cryptographic primitives (used for hash chain)
- [`apm2_daemon`](../../../../apm2-daemon/AGENTS.md) - Daemon that hosts the webhook endpoint

## References

- [RFC-0008](../../../../../documents/rfcs/RFC-0008/) - Event-Driven Agent Handoff design
- [GitHub Webhooks Documentation](https://docs.github.com/en/webhooks)
- [Securing Webhooks](https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries)
- [workflow_run Event](https://docs.github.com/en/webhooks/webhook-events-and-payloads#workflow_run)
