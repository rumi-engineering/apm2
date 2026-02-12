# Session Module

> Session management for daemon-hosted episodes with IPC authentication and context firewall integration.

## Overview

The `session` module provides session management functionality for the daemon. A session represents a spawned episode's IPC context -- binding an ephemeral handle, work ID, role, lease, capability manifest, and optional PCAC policy. Sessions are registered when episodes are spawned and tracked through termination for crash recovery and status queries.

The module also implements CONSUME mode sessions with strict context firewall enforcement, where file reads are limited to an explicit allowlist from the context pack manifest.

## Key Types

### `SessionState`

```rust
pub struct SessionState {
    pub session_id: String,
    pub work_id: String,
    pub role: i32,
    pub ephemeral_handle: String,
    pub lease_id: String,           // SECURITY: redacted in Debug, skipped in serde
    pub policy_resolved_ref: String,
    pub capability_manifest_hash: Vec<u8>,
    pub episode_id: Option<String>,
    pub pcac_policy: Option<PcacPolicyKnobs>,
    pub pointer_only_waiver: Option<PointerOnlyWaiver>,
}
```

Session state for a spawned episode. Persisted for crash recovery.

**Invariants:**

- [INV-SS01] `lease_id` is redacted in `Debug` output and skipped during serialization to prevent credential leakage.
- [INV-SS02] Session state is persisted when `SpawnEpisode` succeeds.

### `EphemeralHandle`

```rust
pub struct EphemeralHandle(String);
```

Bearer token for session-scoped IPC. Format: `H-{uuid}`.

**Invariants:**

- [INV-SS03] Generated using UUID v4 (random).
- [INV-SS04] No embedded user data or secrets.

### `SessionRegistry` (trait)

```rust
pub trait SessionRegistry: Send + Sync {
    fn register_session(&self, session: SessionState) -> Result<Vec<SessionState>, SessionRegistryError>;
    fn remove_session(&self, session_id: &str) -> Result<Option<SessionState>, SessionRegistryError>;
    fn get_session(&self, session_id: &str) -> Option<SessionState>;
    fn get_session_by_handle(&self, handle: &str) -> Option<SessionState>;
    fn get_session_by_work_id(&self, work_id: &str) -> Option<SessionState>;
    fn mark_terminated(&self, session_id: &str, info: SessionTerminationInfo) -> Result<bool, SessionRegistryError>;
    fn get_termination_info(&self, session_id: &str) -> Option<SessionTerminationInfo>;
    fn get_terminated_session(&self, session_id: &str) -> Option<(SessionState, SessionTerminationInfo)>;
    fn update_episode_id(&self, session_id: &str, episode_id: String) -> Result<(), SessionRegistryError>;
    fn list_active_sessions(&self) -> Vec<SessionState>;
}
```

**Invariants:**

- [INV-SS05] Terminated sessions are preserved with TTL for post-termination status queries.
- [INV-SS06] Persistence failures are propagated (fail-closed).

**Contracts:**

- [CTR-SS01] `register_session()` returns evicted sessions so callers can clean up telemetry.
- [CTR-SS02] `update_episode_id()` writes back the episode binding after `SpawnEpisode` completes.

### `ConsumeSessionHandler`

CONSUME mode session handler with context firewall integration.

**Invariants:**

- [INV-SS07] Default-deny: all reads denied unless explicitly allowed by manifest.
- [INV-SS08] Context miss triggers session termination with `CONTEXT_MISS` rationale.
- [INV-SS09] Refinement attempts bounded to `MAX_REFINEMENT_ATTEMPTS` (10).

**Contracts:**

- [CTR-SS03] Emits `SessionTerminated` event on context miss.
- [CTR-SS04] Emits `ContextRefinementRequest` to coordinator for reissuance.

### `ConsumeSessionError`

```rust
pub enum ConsumeSessionError {
    ContextMiss { path: String, manifest_id: String, reason: String },
    MaxRefinementsExceeded { work_id: String, max: u32 },
    // ...
}
```

## Public API

- `SessionState`, `EphemeralHandle`, `SessionTerminationInfo`
- `SessionRegistry` (trait)
- `ConsumeSessionHandler`, `ConsumeSessionContext`, `ConsumeSessionError`
- `validate_tool_request`

## Related Modules

- [`apm2_daemon::episode`](../episode/AGENTS.md) -- Episode runtime managing the session's execution
- [`apm2_daemon::protocol`](../protocol/AGENTS.md) -- IPC dispatch queries session registry
- [`apm2_core::session`](../../../apm2-core/src/session/AGENTS.md) -- Core session types
- [`apm2_core::context`](../../../apm2-core/src/context/AGENTS.md) -- Context pack manifest and firewall

## References

- RFC-0015: Forge Admission Cycle -- context firewall
- RFC-0017: Daemon as Control Plane -- session-scoped IPC
- REQ-DCP-0004: Ephemeral handle as bearer token
- TCK-00211: CONSUME mode session handler
- TCK-00256: Session state persistence
- TCK-00266: Persistent session registry for crash recovery
- TCK-00384: Session registry security fixes
- TCK-00385: Termination tracking with TTL
