# Protocol Module

> Unix domain socket protocol stack: framing, handshake, dispatch, and session management.

## Overview

The `protocol` module implements the daemon's IPC protocol stack for CLI-to-daemon communication over Unix domain sockets. It provides the complete protocol layering from transport through application-level dispatch:

```text
+-------------------------------------------+
|           Application Messages             |  Protobuf (messages)
+-------------------------------------------+
|     Privileged / Session Dispatch          |  dispatch / session_dispatch
+-------------------------------------------+
|              Handshake                     |  Hello/HelloAck
+-------------------------------------------+
|               Framing                      |  Length-prefixed (4-byte BE)
+-------------------------------------------+
|            UDS Transport                   |  Unix socket (operator/session)
+-------------------------------------------+
```

### Dual-Socket Privilege Separation (TCK-00249)

The daemon uses two Unix sockets for privilege separation:

- **`operator.sock`** (mode 0600): Privileged operations (ClaimWork, SpawnEpisode, IssueCapability, Shutdown)
- **`session.sock`** (mode 0660): Session-scoped operations (RequestTool, EmitEvent, PublishEvidence, StreamTelemetry)

### Submodules

- `server` -- UDS server with connection management
- `socket_manager` -- Dual-socket manager for privilege separation
- `connection_handler` -- Hello/HelloAck handshake handler
- `framing` -- Length-prefixed frame codec
- `handshake` -- Version negotiation
- `messages` -- Protobuf message types (generated + helpers)
- `dispatch` -- Privileged endpoint dispatcher
- `session_dispatch` -- Session-scoped endpoint dispatcher
- `session_token` -- HMAC-based session token minting/validation
- `credentials` -- Peer credentials extraction (`SO_PEERCRED`)
- `pulse_topic` -- HEF topic grammar and wildcard matching
- `pulse_acl` -- HEF Pulse Plane subscription ACL
- `pulse_outbox` -- HEF Pulse publisher
- `resource_governance` -- Backpressure and drop policy for HEF
- `topic_derivation` -- Deterministic topic derivation for events

## Key Types

### `ProtocolServer`

```rust
pub struct ProtocolServer { /* listener, semaphore, config */ }
```

**Contracts:**

- [CTR-PR01] Removes stale socket file before binding.
- [CTR-PR02] Creates parent directory with mode 0700.
- [CTR-PR03] Socket permissions set to 0600.
- [CTR-PR04] Each connection handled in a separate spawned task.

### `SocketManager`

```rust
pub struct SocketManager { /* operator_listener, session_listener, config */ }
```

**Invariants:**

- [INV-PR01] Operator socket always has mode 0600.
- [INV-PR02] Session socket always has mode 0660.
- [INV-PR03] `is_privileged` determined solely by which socket accepted the connection.

### `PrivilegedDispatcher`

Privileged endpoint dispatcher for RFC-0017 control-plane IPC. Routes privileged messages to typed handlers.

**Contracts:**

- [CTR-PR05] Only accepts messages from operator socket connections.

**Invariants:**

- [INV-BRK-HEALTH-GATE-001] The `PrivilegedDispatcher` enforces a fail-closed admission health gate on all token issuance paths. The `admission_health_gate` (`AtomicBool`) starts `false` (fail-closed) and is continuously re-evaluated by the background health poller (10s interval in `main.rs`). The poller creates a daemon-level `FacBroker` and `BrokerHealthChecker`, performs a full TP001/TP002/TP003 health check on each cycle, and updates the gate: `true` on `Healthy`, `false` on `Failed`/`Degraded`/error. `validate_channel_boundary_and_issue_context_token_with_flow()` checks this gate before proceeding; if the gate is closed, it returns a `MissingChannelMetadata` defect citing `INV-BRK-HEALTH-GATE-001`. This is defense-in-depth alongside `FacBroker`'s per-session health gate.
- The `channel_boundary_dispatcher()` function in `session_dispatch.rs` returns the `&'static PrivilegedDispatcher` singleton. The background health poller updates its health gate every 10s; the singleton is shared across all session dispatch calls.

### `SessionDispatcher`

Session-scoped endpoint dispatcher for RFC-0017. Routes session requests after validating the session token.

**Invariants:**

- [INV-PR04] Session endpoints require valid `session_token`.
- [INV-PR05] Invalid/expired tokens return `SESSION_ERROR_INVALID`.
- [INV-PR06] Token validation uses constant-time HMAC comparison.
- [INV-PR11] In authoritative mode, fail-closed tiers (Tier2/3/4) MUST be denied if neither `AdmissionKernel` nor `LifecycleGate` is wired (TCK-00494 no-bypass invariant). No silent fallback to ungated effect-capable path.
- [INV-PR12] When `AdmissionKernel` is wired and `LifecycleGate` is absent, the `RequestTool` handler MUST invoke `kernel.plan()` and `kernel.execute()` for fail-closed tier requests in authoritative mode. The kernel MUST succeed before broker dispatch proceeds (TCK-00494 kernel invocation invariant).
- [INV-PR13] In authoritative mode, `EmitEvent` and `PublishEvidence` handlers enforce the same kernel/PCAC lifecycle guard as `RequestTool` (TCK-00498). Session endpoints are classified as `Tier2Plus` (fail-closed) since they perform authoritative state mutations (ledger writes, CAS writes).
- [INV-PR14] When `AdmissionKernel` is wired for `EmitEvent`/`PublishEvidence`, the kernel plan/execute lifecycle runs BEFORE the authoritative effect (ledger/CAS write). `AdmissionBundleV1` evidence is persisted before the effect; `AdmissionOutcomeIndexV1` is persisted after (TCK-00498).

**Contracts:**

- [CTR-PR06] Token is validated BEFORE any handler logic executes.
- [CTR-PR07] Messages use bounded decoding (CTR-1603).
- [CTR-PR08] Authority lifecycle guard fires after decode/validate/transport checks but BEFORE PCAC lifecycle and broker dispatch (TCK-00494). Requires at least one authority gate (`AdmissionKernel` or `LifecycleGate`) for fail-closed tier tool requests in authoritative mode.
- [CTR-PR09] When `AdmissionKernel` is wired without `LifecycleGate`, `handle_request_tool` invokes `kernel.plan()` then `kernel.execute()` with fresh clock/session state, denying on any error with `SessionErrorToolNotAllowed`. The kernel result (`AdmissionResultV1`) is persisted to the ledger as a `kernel_tool_actuation` event BEFORE broker dispatch — fail-closed if persistence fails (TCK-00494, SECURITY MAJOR 1 fix).
- [CTR-PR10] `handle_emit_event` and `handle_publish_evidence` invoke the shared `enforce_session_endpoint_kernel_lifecycle` helper after decode/validate checks but BEFORE the authoritative effect (ledger write / CAS write). The helper uses `Tier2Plus` risk tier, domain-separated BLAKE3 intent/effect digests, and enforces governance policy-root prerequisites for fail-closed tiers (TCK-00498, REQ-0026).
- [CTR-PR11] `enforce_fail_closed_anchor_circuit_before_effect` uses `kernel.probe_anti_rollback_health()` (non-mutating `verify_committed`) instead of `kernel.finalize_anti_rollback()` to test circuit health. This prevents the pre-effect probe from advancing the anchor watermark, which would cause the post-effect commit to use a stale pre-effect anchor (TCK-00502 MINOR-4).
- [CTR-PR12] All effect-capable handlers (`handle_emit_event`, `handle_publish_evidence`) call `kernel.resolve_post_effect_anchor()` AFTER the authoritative effect succeeds and BEFORE `kernel.finalize_anti_rollback()`. This ensures `finalize_anti_rollback` commits the post-effect anchor (reflecting the latest verified head), not the pre-plan anchor from the admission bundle (TCK-00502 MAJOR-2).

### `SessionToken`

```rust
pub struct SessionToken {
    pub session_id: String,
    pub lease_id: String,
    pub spawn_time_ns: u64,
    pub expires_at_ns: u64,
    pub mac: [u8; 32],  // HMAC-SHA256
}
```

**Invariants:**

- [INV-PR07] Domain separation with `apm2.session_token.v1:` prefix.
- [INV-PR08] Token validation uses constant-time comparison (CTR-WH001).

### `TokenMinter`

Mints session tokens with HMAC-SHA256.

### `FrameCodec`

Length-prefixed frame codec. 4-byte big-endian length prefix, max frame 16 MiB.

**Invariants:**

- [INV-PR09] Frame size validated BEFORE allocation (DoS prevention).
- [INV-PR10] Connection closes on any framing or parse error.

### `Hello` / `HelloAck` / `HelloNack`

Handshake messages for version negotiation.

### Protocol Messages (generated)

Protobuf-generated message types including `BoundedDecode` and `Canonicalize` traits. Key message families:

- **Privileged**: `ClaimWorkRequest/Response`, `SpawnEpisodeRequest/Response`, `ShutdownRequest/Response`, `IssueCapabilityRequest/Response`, `OpenWorkRequest/Response`, `PublishWorkContextEntryRequest/Response`, `PublishWorkLoopProfileRequest/Response`, `RecordWorkPrAssociationRequest/Response`
- **Session**: `RequestToolRequest/Response`, `EmitEventRequest/Response`, `PublishEvidenceRequest/Response`, `StreamTelemetryRequest/Response`
- **HEF Pulse**: `SubscribePulseRequest/Response`, `PulseEnvelopeV1`, `PulseEvent`
- **Process Mgmt**: `ListProcessesRequest/Response`, `StartProcessRequest/Response`
- **Consensus Query**: `ConsensusStatusRequest/Response`, `ConsensusValidatorsRequest/Response`

### `PulsePublisher`

Daemon-owned outbox for HEF Pulse Plane subscriptions.

### `PulseAclEvaluator`

ACL evaluation for Pulse Plane topic subscriptions.

### `TopicPattern` / `TopicDeriver`

Topic grammar, wildcard matching, and deterministic topic derivation.

**Multi-Topic Derivation (TCK-00642):**

Work graph edge events (`work_graph.edge.added/removed/waived`) produce **two** topics per event: one for `from_work_id` and one for `to_work_id`. The `derive_topics()` method handles this. `derive_topic()` returns `MultiTopicEventError` for these event types to prevent silent data loss of the secondary topic. Topic prefix is `work_graph.` (NOT `work.`) to avoid WorkReducer decoding collision (INV-TOPIC-005). Canonical event type strings use dotted notation (`work_graph.edge.added`, not `WorkEdgeAdded`).

## Public API

The module provides extensive re-exports. Key entries:

- Server: `ProtocolServer`, `Connection`, `ServerConfig`, `SocketManager`, `SocketType`
- Handshake: `Hello`, `HelloAck`, `HelloNack`, `ServerHandshake`, `ClientHandshake`
- Dispatch: `PrivilegedDispatcher`, `ConnectionContext`, `SessionDispatcher`
- Token: `SessionToken`, `TokenMinter`, `SessionTokenError`
- Framing: `FrameCodec`, `ProtocolError`, `ProtocolResult`
- Messages: All protobuf request/response types
- HEF: `PulsePublisher`, `PulseAclEvaluator`, `TopicPattern`, `SubscriptionRegistry`

## Related Modules

- [`apm2_daemon::session`](../session/AGENTS.md) -- Session state registry queried during dispatch
- [`apm2_daemon::episode`](../episode/AGENTS.md) -- Episode control via privileged dispatch
- [`apm2_daemon::pcac`](../pcac/AGENTS.md) -- PCAC lifecycle gate invoked during session dispatch
- [`apm2_daemon::hsi_contract`](../hsi_contract/AGENTS.md) -- Contract hash exchanged during handshake
- [`apm2_daemon AGENTS.md`](../../AGENTS.md) -- Crate-level architecture

## References

- RFC-0017: Daemon as Control Plane
- RFC-0018: Holonic Event Fabric (HEF) Phase 1
- DD-009: ProtocolServer-only control plane
- AD-DAEMON-002: Wire format specification
- AD-DAEMON-003: Protocol message types
- CTR-1603: Bounded message decoding
- CTR-WH001: Constant-time HMAC comparison
- TCK-00495: Consumption events carry `receipt_hash` and `admission_bundle_digest` for O(1) correlation; `RedundancyReceiptConsumption` extended with binding fields
- TCK-00635: `OpenWork` (IPC-PRIV-076) handler persists WorkSpec to CAS and emits a canonical `work.opened` event. PCAC lifecycle enforcement runs BEFORE any idempotency queries to prevent unauthorized callers from probing work_id existence (no existence oracle). **All pre-admission rejections use uniform `CapabilityRequestRejected` error codes** -- this includes protobuf decode failures, empty/invalid WorkSpec JSON, oversized IDs, UTF-8 validation failures, canonicalization failures, and missing peer credentials. No pre-PCAC path returns `InvalidArgument` or propagates `ProtocolError::Serialization`; the uniform error code prevents side-channel differentiation of rejection causes by unauthorized callers. Idempotent on `(work_id, spec_hash)` via bounded `LIMIT 1` query (not full event scan): same hash returns success with `already_existed=true`; different hash returns `WORK_ALREADY_EXISTS`. Actor ID derived from peer credentials (never client input). CAS must be configured (fail-closed). Race-safe: partial unique indices enforce at-most-one `work.opened` per `work_id` on BOTH tables: `idx_work_opened_unique ON ledger_events(work_id) WHERE event_type = 'work.opened'` (legacy) and `idx_canonical_work_opened_unique ON events(session_id) WHERE event_type = 'work.opened'` (canonical). UNIQUE constraint violations are caught in the handler, the persisted event is re-read, and idempotent success or `WORK_ALREADY_EXISTS` is returned.
- TCK-00638: RFC-0032 Phase 2 PublishWorkContextEntry handler (IPC-PRIV-077) -- CAS-first storage, `evidence.published` ledger anchor, deterministic `CTX-` entry ID derivation, `work_context` projection. **Invariant**: idempotent replay check runs AFTER PCAC lifecycle enforcement (join/revalidate/consume) so replayed requests are denied when the caller's lease has been revoked or policy state has changed. **Invariant (Intent Digest Binding)**: `effect_intent_digest` is computed over the canonical JSON bytes (post daemon-authoritative field overwrite of `entry_id`, `actor_id`, `created_at_ns`, `source_session_id`) rather than raw `request.entry_json`, fulfilling RFC-0027 Law 2 (Intent Equality) and Law 7 (Evidence Sufficiency).
- TCK-00645: RFC-0032 Phase 4 PublishWorkLoopProfile handler (IPC-PRIV-079) -- bounded+validated profile decode (`<=64KiB`, deny unknown fields), deterministic `WLP-` evidence ID from `(work_id, dedupe_key)`, CAS-first storage via `publish_work_loop_profile`, and `evidence.published` emission with category `WORK_LOOP_PROFILE`. **Invariant**: idempotency is enforced on `(work_id, dedupe_key)` by deterministic evidence identity replay lookup; duplicate requests return the originally anchored event/cas hash and do not emit duplicate ledger events.
- TCK-00639: RFC-0032 Phase 2 RecordWorkPrAssociation handler (IPC-PRIV-079) -- records a PR association for an existing work item by emitting a canonical `work.pr_associated` event. **Invariant (PCAC-Before-Idempotency)**: PCAC lifecycle enforcement (join/revalidate/consume) runs BEFORE any idempotency queries to prevent unauthorized callers from probing PR association existence. **Invariant (Strict Input Validation)**: `commit_sha` must be exactly 40 lowercase hexadecimal characters (byte-level validation); `pr_number` must be > 0; `pr_url` bounded to 2048 bytes. **Invariant (Actor-Lease Binding)**: Actor ownership and lease_id are verified using constant-time comparison (`subtle::ConstantTimeEq`) before any mutation. **Invariant (Idempotent on (work_id, pr_number, commit_sha))**: Duplicate requests with matching payload return `already_existed=true` without emitting duplicate events. Idempotency check decodes the stored JSON envelope (hex -> protobuf -> WorkEvent) to extract the PrAssociated variant fields. **Invariant (HTF Timestamps)**: Uses `get_htf_timestamp_ns()` (never `SystemTime::now`) for event timestamps. **Invariant (Optional LINKOUT)**: When `pr_url` is non-empty, a best-effort LINKOUT context entry is published via internal delegation to `handle_publish_work_context_entry`. LINKOUT failure does not block the primary PR association response. **Invariant (Fail-Closed)**: Missing PCAC gate, event emission failure, HTF timestamp failure, and all validation failures reject the request.
- TCK-00637: RFC-0032 Phase 2 ClaimWorkV2 handler (IPC-PRIV-078) -- claims existing work_id, issues leases, anchors authority bindings via CAS. **Invariant (Actor-Lease Binding)**: The handler verifies that `ctx.actor_id()` matches the `executor_actor_id` bound to the governing `lease_id` using constant-time comparison (`subtle::ConstantTimeEq`). This prevents authorization bypass where Actor B reuses a lease_id belonging to Actor A (lease_ids are not secret — they appear in audit logs and ledger events). **Invariant (CAS-First Ordering)**: CAS storage completes BEFORE any ledger events are emitted. This prevents orphaned `work_transitioned` events without corresponding `evidence.published` events when CAS store fails. **Invariant (Ledger Equivocation Prevention)**: UNIQUE indexes on `(work_id, previous_transition_count)` for `work_transitioned` events prevent duplicate state transitions from concurrent claims. Both legacy (`idx_work_transitioned_unique`) and canonical (`idx_canonical_work_transitioned_unique`) tables are protected. UNIQUE violations trigger idempotency recovery or FAILED_PRECONDITION. **Invariant (Lease+Claim Registration)**: The handler registers the issued lease in `LeaseValidator` (via `register_lease_with_executor`) and the claim in `WorkRegistry` (via `register_claim`) so that downstream handlers (`SpawnEpisode`, `DelegateSublease`, etc.) can resolve lease-to-work mappings and claim authority. On DuplicateWorkId from WorkRegistry, the handler recovers via idempotency instead of returning a phantom lease. **Invariant (Role-Indexed Claims)**: `WorkRegistry` is keyed by `(work_id, role)` to support multi-role workflows where Implementer and Reviewer each claim the same `work_id`. Both `StubWorkRegistry` AND `SqliteWorkRegistry` enforce `(work_id, role)` uniqueness. `get_claim_for_role(work_id, role)` returns role-specific claims; `get_claim(work_id)` returns the first registered claim for backward compatibility. **Invariant (Event Encoding)**: Uses legacy `emit_work_transitioned` (event_type `work_transitioned`) with JSON payload instead of `emit_session_event` with `work.transitioned`, because the projection bridge (`translate_signed_events`) normalizes `work_transitioned` JSON payloads into protobuf but passes `work.` events through as-is (expecting native protobuf). **Invariant (Bounded Idempotency)**: Idempotency checks use bounded SQL queries (`get_latest_work_transition_by_rationale`, `get_evidence_by_evidence_id`) with `json_extract + LIMIT 1` instead of O(N) full-history scans with per-row `serde_json::from_slice`. This prevents denial-of-service via memory exhaustion on work_ids with large event histories. **Invariant (Fail-Closed Idempotency)**: Recovered `lease_id` and `cas_hash` are explicitly validated as non-empty before returning idempotent success. Empty/missing fields trigger fail-closed error instead of hollow success. No `unwrap_or_default()` or `unwrap_or("")` on recovery paths. **Invariant (Actual Policy Hashes)**: `WorkAuthorityBindingsV1` records actual policy artifact hashes (`capability_manifest_hash`, `context_pack_hash`, `resolved_policy_hash`) from the resolved `PolicyResolution`, not synthetic PCAC-derived hashes. The handler fails closed if no actual policy resolution is available. **Invariant (Risk Tier)**: PCAC risk tier is derived from `resolve_risk_tier_for_lease` using the governing lease's policy resolution (fail-closed to Tier4 when lease/claim not found). **Invariant (Foundational History Replay)**: `get_events_by_work_id` returns ALL events for a work_id without LIMIT -- it is a foundational history replay method used by the projection bridge to rebuild state. Applying a LIMIT would silently drop recent events for work items exceeding the cap, permanently freezing observed state. `MAX_EVIDENCE_SCAN_ROWS` is intended only for bounded reverse-scan lookups (e.g., `get_event_by_evidence_identity`). **Invariant (Role-Scoped Policy Lookup)**: Policy resolution in ClaimWorkV2 uses `get_claim_for_role(work_id, role)` (role-scoped) instead of `get_claim(work_id)` (role-agnostic). This prevents cross-role policy confusion when multiple roles claim the same work_id, ensuring policy-resolution hashes in CAS evidence accurately represent the requesting role. **Invariant (PCAC Role-Scoped Claim Resolution)**: The PCAC helpers `resolve_risk_tier_for_lease`, `derive_privileged_pcac_revalidation_inputs`, and `enforce_privileged_pcac_lifecycle` use `get_claim_by_lease_id(work_id, lease_id)` instead of `get_claim(work_id)` for claim resolution. This resolves the exact claim whose `lease_id` matches, guaranteeing the correct role's policy is applied to PCAC risk tier and lifecycle checks. Falls back to role-agnostic `get_claim` only for legacy leases that pre-date multi-role registration. The `get_claim_by_lease_id` method iterates through the bounded set of roles (5 variants) to find a matching lease_id; `SqliteWorkRegistry` overrides with a direct SQL lookup by `(work_id, lease_id)`. **Invariant (Schema Migration)**: `SqliteWorkRegistry::init_schema` detects legacy `work_claims` tables (with `work_id TEXT PRIMARY KEY` and no `role` column) and migrates atomically: rename old table, create new table with composite `(work_id, role)` uniqueness, copy data with default `role=1` (Implementer), drop legacy backup. The migration is idempotent and runs within a single `BEGIN IMMEDIATE` transaction. **Invariant (Durability Chain Ordering)**: The write ordering in `handle_claim_work_v2` is: (1) CAS store, (2) `register_claim` in WorkRegistry, (3) `register_lease_with_executor` in LeaseValidator (verified via `get_lease_work_id`), (4) `emit_evidence_published`, (5) `emit_work_transitioned`. The `work_transitioned` event is emitted LAST -- only after ALL supporting data (CAS, claim, lease, evidence anchor) has been durably committed. This ensures that if any step fails before the state transition, the client can safely retry; and if `work_transitioned` fails after evidence.published, the idempotency path can reconstruct lease_id and authority_bindings_hash from the existing evidence anchor. **Invariant (Split-Brain and Concurrency Safety)**: In `handle_claim_work_v2_idempotency` Path 2 (partial durability recovery), the handler first checks for an existing `evidence.published` event with the deterministic `evidence_id`. If found, it extracts `lease_id`, `cas_hash`, and `actor_id`, emits the missing `work_transitioned` event when required, then returns idempotent success. If no evidence anchor exists, Path 2 uses age-guarded cleanup: claims younger than the timeout are treated as in-flight and retained, while claims older than the timeout are purged and retried. **Invariant (Lease Registration Verification)**: After calling `register_lease_with_executor` (which returns `()` and may silently fail), the handler verifies the lease was actually registered by calling `get_lease_work_id`. If verification fails, the handler aborts before `evidence.published` and `work_transitioned` to prevent partial commits. **Invariant (Role-Scoped Trait Default)**: The `WorkRegistry::get_claim_for_role` trait default returns `None` (fail-closed) instead of delegating to `get_claim` + filter. This prevents role-agnostic leakage in multi-role scenarios where `get_claim` returns the first registered claim (any role), missing claims for other roles entirely. Both `StubWorkRegistry` and `SqliteWorkRegistry` override with proper role-keyed lookups.
