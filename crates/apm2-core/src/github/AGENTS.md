# GitHub Module

> Tiered GitHub App access control for holonic agents with capability-bound, auditable token management.

## Overview

The GitHub module implements a tiered architecture that maps APM2 risk tiers (LOW/MED/HIGH per RFC-0015) to GitHub App permissions, providing controlled GitHub access for AI agents. The design follows the principle of least privilege with proportional containment.

```text
Risk Tier    GitHub App       Token TTL    Permissions
---------    ----------       ---------    -----------
LOW          Reader           1 hour       contents:read, metadata:read
MED          Developer        15 min       + pull_requests:write, checks:write
HIGH         Operator         2 min        + contents:write, admin:read, releases:write
```

## Key Types

### `RiskTier`

```rust
#[repr(u8)]
pub enum RiskTier {
    Low = 0,   // Read-only, sampled AAT
    Med = 1,   // PR/CI operations, conditional AAT
    High = 2,  // Full operator access, always requires AAT
}
```

**Invariants:**
- [INV-0101] Risk tiers are ordered: Low < Med < High
- [INV-0102] Higher tiers can use apps available to lower tiers (scope attenuation only)
- [INV-0103] TTL decreases monotonically as tier increases (containment proportionality)

**Contracts:**
- [CTR-0101] `from_str(v)` returns error for unknown tier names
- [CTR-0102] `default_ttl()` > `max_ttl()` of next higher tier

### `GitHubApp`

```rust
#[non_exhaustive]
pub enum GitHubApp {
    Reader,     // LOW+: read-only access
    Developer,  // MED+: PR/CI operations
    Operator,   // HIGH: write/admin operations
}
```

**Invariants:**
- [INV-0201] Each app has a fixed, immutable set of scopes
- [INV-0202] Apps form a strict hierarchy: Reader ⊂ Developer ⊂ Operator (in terms of allowed scopes)

**Contracts:**
- [CTR-0201] `allows_scope(s)` returns true iff scope `s` is in the app's scope set
- [CTR-0202] `min_tier()` returns the minimum tier required to use this app
- [CTR-0203] `from_name()` accepts both canonical ("apm2-reader") and short ("reader") forms

### `GitHubScope`

```rust
#[non_exhaustive]
pub enum GitHubScope {
    ContentsRead,
    MetadataRead,
    PullRequestsWrite,
    ChecksWrite,
    StatusesWrite,
    ContentsWrite,
    AdminRead,
    ReleasesWrite,
}
```

**Contracts:**
- [CTR-0301] `as_str()` returns the canonical GitHub API scope format (e.g., "contents:read")
- [CTR-0302] `from_str()` parses the canonical format; rejects unknown scopes
- [CTR-0303] `is_write()` returns true for all scopes ending in `:write`

### `GitHubLease`

```rust
#[non_exhaustive]
pub struct GitHubLease {
    pub lease_id: String,
    pub episode_id: String,
    pub github_app_id: String,
    pub installation_id: String,
    pub app: GitHubApp,
    pub risk_tier: RiskTier,
    pub scopes: Vec<GitHubScope>,
    pub token_hash: Vec<u8>,  // SHA-256, NEVER raw token
    pub state: GitHubLeaseState,
    pub issued_at: u64,
    pub expires_at: u64,
    pub capability_manifest_hash: Vec<u8>,
    pub issuer_signature: Vec<u8>,
    // ... revocation fields
}
```

**Invariants:**
- [INV-0401] `token_hash` is SHA-256; raw token is NEVER stored
- [INV-0402] `expires_at > issued_at` (enforced at construction)
- [INV-0403] `risk_tier.allowed_apps()` must contain `app`
- [INV-0404] All scopes must be allowed by `app`
- [INV-0405] State transitions: `Active -> {Revoked, Expired}` (no cycles)
- [INV-0406] `terminated_at` uses lease's `expires_at` for expiration (prevents pruning evasion)

**Contracts:**
- [CTR-0401] `new()` validates all invariants; returns error on violation
- [CTR-0402] `revoke()` fails on terminal leases
- [CTR-0403] `expire()` sets `terminated_at = expires_at` (not event timestamp)
- [CTR-0404] `is_expired_at(t)` returns true iff `state == Active && t >= expires_at`

### `GitHubLeaseState`

```rust
#[non_exhaustive]
pub enum GitHubLeaseState {
    Active,   // Token can be used
    Revoked,  // Voluntarily or forcibly revoked
    Expired,  // TTL elapsed
}
```

**Contracts:**
- [CTR-0501] `is_terminal()` returns true for `Revoked` and `Expired`
- [CTR-0502] `parse()` is case-insensitive

### `RevocationReason`

```rust
#[non_exhaustive]
pub enum RevocationReason {
    Voluntary,        // Holder released
    Expired,          // Natural expiration
    PolicyViolation,  // Rule breach detected
    KeyCompromise,    // Security incident
}
```

### `TokenProvider` (trait)

```rust
pub trait TokenProvider: Send + Sync {
    fn mint_token(&self, request: &TokenRequest) -> Result<TokenResponse, GitHubError>;
    fn name(&self) -> &'static str;
}
```

**Contracts:**
- [CTR-0601] `mint_token()` validates request before API calls
- [CTR-0602] Returns `TokenResponse` with `token_hash` (SHA-256 of raw token)
- [CTR-0603] Implementations must be thread-safe (`Send + Sync`)

**Implementations:**
- `MockTokenProvider`: For testing, generates predictable tokens without GitHub API calls
- `RateLimitedTokenProvider<P>`: Production wrapper that enforces per-episode token quotas
- `GitHubTokenProvider`: TODO - requires GitHub App credentials infrastructure

### `RateLimitedTokenProvider` (LAW-06 Compliance)

Prevents token churn attacks by enforcing per-episode issuance limits. This ensures
short TTLs provide meaningful containment—a compromised agent cannot maintain
indefinite access by rapidly requesting new tokens.

**Rate Limits by Tier:**
| Tier | Max Tokens/Episode | Rationale |
|------|-------------------|-----------|
| Low  | 10 | Read-only, 1hr TTL, low risk |
| Med  | 5  | Limited writes, 30min TTL |
| High | 3  | Privileged ops, 5min TTL, strictest |

**Contracts:**
- [CTR-0610] Higher risk tiers get fewer tokens (inverse proportionality)
- [CTR-0611] Limits are per-episode, not per-actor (episode is the trust boundary)
- [CTR-0612] `reset_episode()` must be called when episode completes to free memory

### `TokenRequest` / `TokenResponse`

```rust
pub struct TokenRequest {
    pub app: GitHubApp,
    pub installation_id: String,
    pub risk_tier: RiskTier,
    pub scopes: Vec<GitHubScope>,
    pub requested_ttl: Option<Duration>,
    pub episode_id: String,
}

pub struct TokenResponse {
    pub token: SecretString, // CTR-2604: wrapped to prevent accidental logging
    pub token_hash: Vec<u8>, // Safe for ledger
    pub expires_at: u64,
    pub scopes: Vec<GitHubScope>,
    pub app_id: String,
    pub installation_id: String,
}
```

**Contracts:**
- [CTR-0701] `TokenRequest::validate()` enforces tier-app and app-scope rules
- [CTR-0702] `effective_ttl()` returns min(requested_ttl, risk_tier.max_ttl())
- [CTR-0703] `TokenResponse::hash_token()` uses SHA-256

## Security Model

### Trust Boundaries

1. **Token Storage**: Raw tokens are NEVER stored in the ledger. Only SHA-256 hashes are persisted.

2. **Tier Enforcement**: Risk tier validation is performed at multiple points:
   - `TokenRequest::validate()` - before API call
   - `GitHubLease::new()` - at lease creation
   - Proto message creation (via field constraints)

3. **Scope Attenuation**: Agents can only request scopes allowed by their tier's maximum app. Escalation attempts are rejected.

4. **TTL Proportionality**: Higher-risk tiers get shorter TTLs for containment:
   - LOW: 1 hour (read-only, low risk)
   - HIGH: 2 minutes (full access, highest risk)

### Attack Mitigations

1. **Tier Escalation Attack**: Rejected by `validate_tier_app()` and lease validation
2. **Scope Escalation Attack**: Rejected by `validate_app_scopes()` and lease validation
3. **TTL Extension Attack**: Capped by `effective_ttl()` using `risk_tier.max_ttl()`
4. **Pruning Evasion Attack**: `terminated_at` set from `lease.expires_at`, not event payload
5. **Token Leakage**: Only hashes stored; raw tokens in-memory only

### Input Validation Limits

| Field | Max Length |
|-------|------------|
| `lease_id` | 128 bytes |
| `episode_id` | 128 bytes |
| `github_app_id` | 64 bytes |
| `installation_id` | 64 bytes |
| `actor_id` | 128 bytes |
| `repository` | 256 bytes |
| `api_endpoint` | 512 bytes |
| `scopes` (count) | 16 |

## Proto Events

The module uses three proto events for ledger integration:

1. **`GitHubLeaseIssued`**: Emitted when a token is minted
2. **`GitHubLeaseRevoked`**: Emitted when a lease is revoked
3. **`GitHubOperationRecorded`**: Emitted for each GitHub API call (audit trail)

See `proto/kernel_events.proto` for field definitions.

## Examples

### Requesting a Token

```rust
use apm2_core::github::{
    GitHubApp, GitHubScope, MockTokenProvider, RiskTier, TokenProvider, TokenRequest,
};
use std::time::Duration;

let provider = MockTokenProvider::new();

let request = TokenRequest::new(
    GitHubApp::Developer,
    "installation-12345".to_string(),
    RiskTier::Med,
    "episode-001".to_string(),
)
.with_scopes(vec![GitHubScope::ContentsRead, GitHubScope::PullRequestsWrite])
.with_ttl(Duration::from_secs(600));

// Validate before minting
request.validate()?;

// Mint token
let response = provider.mint_token(&request)?;

// token_hash is safe to store in ledger
let hash = response.token_hash; // 32 bytes, SHA-256
```

### Creating a Lease

```rust
use apm2_core::github::{GitHubApp, GitHubLease, GitHubScope, RiskTier};

let lease = GitHubLease::new(
    "lease-001".to_string(),
    "episode-001".to_string(),
    "app-12345".to_string(),
    "install-67890".to_string(),
    GitHubApp::Developer,
    RiskTier::Med,
    vec![GitHubScope::ContentsRead, GitHubScope::PullRequestsWrite],
    token_hash,           // from TokenResponse
    issued_at_nanos,
    expires_at_nanos,
    capability_manifest_hash,
    issuer_signature,
)?;

assert!(lease.is_active());
assert!(lease.allows_scope(GitHubScope::ContentsRead));
```

### Revoking a Lease

```rust
lease.revoke(
    RevocationReason::PolicyViolation,
    "admin-actor".to_string(),
    revoked_at_nanos,
)?;

assert!(lease.is_terminal());
```

## Related Modules

- [`apm2_core::lease`](../lease/AGENTS.md) - Core lease infrastructure (GateLease pattern)
- [`apm2_core::events`](../events/AGENTS.md) - Proto event types including GitHubLeaseEvent
- [`apm2_holon::resource::Lease`](../../../../apm2-holon/src/resource/lease.rs) - Holonic lease with scope/budget

## References

- [APM2 Rust Standards] [Security-Adjacent Rust](/documents/skills/rust-standards/references/34_security_adjacent_rust.md) - Input validation, trust boundaries
- [APM2 Rust Standards] [API Design](/documents/skills/rust-standards/references/18_api_design_and_semver.md) - `#[non_exhaustive]`, builder patterns
- RFC-0015: Forge Admission Cycle - GateLease architecture, Risk-Tiered AAT Selection Policy
- LAW-05: Dual-Axis Containment - Authority + Accountability
- LAW-14: Proportionality and Risk-Weighted Evidence
