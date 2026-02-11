# 42 — PCAC/AJC Integration (Implementor + Reviewer Guide)
## 1) What PCAC/AJC Is

PCAC is the guardrail that prevents authority-bearing side effects from running on stale,
unbound, or replayed authorization. A request must produce a single-use authority token (AJC),
prove that token is still valid just before execution, consume it exactly once, and only then
run the side effect. If any step fails, the handler denies before mutation.

## 2) Canonical 4-Step Lifecycle
Contract: `join -> revalidate -> consume -> effect`

### Step A: Join
What it does:
- Builds `AuthorityJoinInputV1` from identity, delegation, capability, freshness,
  stop/budget, and intent bindings.
- Mints `AuthorityJoinCertificateV1` (AJC).

Deny when:
- Required authority state is missing.
- Join bindings are malformed.
- Policy/evidence level is not admissible.

Code anchors:
- `crates/apm2-daemon/src/protocol/dispatch.rs:8750`
- `crates/apm2-daemon/src/protocol/session_dispatch.rs:6148`

### Step B: Revalidate
What it does:
- Re-checks the AJC against fresh authoritative inputs before execution.
- Tier2+ paths also enforce sovereignty/epoch constraints where configured.

Deny when:
- Freshness/revocation/ledger/clock inputs are stale, missing, or unreadable.
- Tier2+ sovereignty checks fail.

Code anchors:
- `crates/apm2-daemon/src/protocol/dispatch.rs:8781`
- `crates/apm2-daemon/src/protocol/session_dispatch.rs:7060`

### Step C: Consume
What it does:
- Enforces single-use semantics.
- Enforces consume-time intent equality.
- Returns consumed witness + consume record.

Deny when:
- Intent digest mismatch.
- Already consumed/replayed AJC.
- Consume prerequisites are missing.

Code anchors:
- `crates/apm2-daemon/src/protocol/dispatch.rs:8817`
- `crates/apm2-daemon/src/protocol/session_dispatch.rs:7163`

### Step D: Effect
What it does:
- Runs authoritative side effect only after successful consume.
- Persists lifecycle evidence on the effect event payload.

Deny when:
- Lifecycle evidence cannot be persisted (fail-closed).

Code anchors:
- `crates/apm2-daemon/src/protocol/dispatch.rs:14366`
- `crates/apm2-daemon/src/protocol/session_dispatch.rs:7271`

## 3) Seven Semantic Laws (Reviewer-Checkable)

From `crates/apm2-core/src/pcac/mod.rs:20` and RFC-0027 section 4.

1. Linear Consumption
- Rule: one AJC authorizes at most one side effect.
- Check: duplicate consume path denies; durable consume record exists before effect.

2. Intent Equality
- Rule: consume-time intent must equal join-time intent.
- Check: effect intent digest is recomputed and compared at consume boundary.

3. Freshness Dominance
- Rule: Tier2+ stale/missing/ambiguous freshness denies.
- Check: fresh authoritative inputs are read at execution stage; missing inputs deny.

4. Revocation Dominance
- Rule: revocation frontier advancement denies consume.
- Check: revalidate/consume use current revocation head and deny on drift.

5. Delegation Narrowing
- Rule: delegated authority must be strict-subset of parent.
- Check: parent lineage + scope are bound; widening attempts deny.

6. Boundary Monotonicity
- Rule: `join < revalidate <= consume <= effect`.
- Check: no authoritative mutation before successful consume.

7. Evidence Sufficiency
- Rule: authoritative outcomes require replay-resolvable lifecycle receipts.
- Check: lifecycle selectors are attached/persisted with the effect event.

## 4) Code Pattern for New Privileged Handlers

Use `PrivilegedPcacInputBuilder` + canonical lifecycle gate calls.

### 4.1 Build join input via builder

```rust
let pcac_builder =
    PrivilegedPcacInputBuilder::new(PrivilegedHandlerClass::DelegateSublease)
        .session_id(request.sublease_id.clone())
        .lease_id(request.parent_lease_id.clone())
        .boundary_intent_class(apm2_core::pcac::BoundaryIntentClass::Delegate)
        .identity_proof_hash(request_identity_proof_hash)
        .identity_evidence_level(IdentityEvidenceLevel::PointerOnly)
        .risk_tier(pcac_risk_tier);

let pcac_input = pcac_builder
    .capability_manifest_hash(capability_manifest_hash)
    .scope_witness_hash(scope_witness_hash)
    .freshness_policy_hash(freshness_policy_hash)
    .stop_budget_profile_digest(stop_budget_profile_digest)
    .effect_intent_digest(effect_intent_digest)
    .build(join_freshness_tick, join_time_envelope_ref, join_ledger_anchor, join_revocation_head);
```

Anchors:
- `crates/apm2-daemon/src/protocol/dispatch.rs:15926`
- `crates/apm2-daemon/src/protocol/dispatch.rs:16001`

### 4.2 Kernel call chain (canonical)

```rust
let certificate = gate
    .join_and_revalidate(
        &effective_join_input,
        join_time_envelope_ref,
        join_ledger_anchor,
        join_revocation_head,
        &pcac_policy,
    )
    ?;

gate.revalidate_before_execution(
    &certificate,
    current_time_envelope_ref,
    current_ledger_anchor,
    current_revocation_head,
    &pcac_policy,
)
?;

let (consumed_witness, consume_record) = gate
    .consume_before_effect(
        &certificate,
        effect_intent_digest,
        effective_join_input.boundary_intent_class,
        true,
        current_time_envelope_ref,
        current_revocation_head,
        &pcac_policy,
    )
    ?;
```

Anchors:
- `crates/apm2-daemon/src/protocol/dispatch.rs:8749`
- `crates/apm2-daemon/src/protocol/dispatch.rs:8817`

### 4.3 Persist lifecycle selectors on effect payload

```rust
if let (Some(artifacts), Some(payload_object)) = (
    pcac_lifecycle_artifacts.as_ref(),
    event_payload.as_object_mut(),
) {
    append_privileged_pcac_lifecycle_fields(payload_object, artifacts);
}
```

Anchor:
- `crates/apm2-daemon/src/protocol/dispatch.rs:16153`

## 5) Anti-Patterns: What PCAC Does NOT Solve

PCAC is an authority lifecycle control, not a whole-system substitute.

1. Ledger integrity
- Still requires chain verification and append durability.

2. Evidence production completeness
- Handler must still emit the required domain event/evidence fields.

3. Containment state management
- Stop/freeze enforcement wiring is separate from lifecycle admission.

4. Policy-root provenance
- Governance/policy-root derivation checks remain separate logic.

## 6) DelegateSublease Before/After (Concrete)

### Before: scattered admission checks only (still required)

```rust
if bool::from(parent_lease.changeset_digest.ct_eq(&[0u8; 32]))
    || bool::from(parent_lease.policy_hash.ct_eq(&[0u8; 32]))
{
    let deny_class = AuthorityDenyClass::InvalidDelegationChain;
    return Ok(PrivilegedResponse::error(
        PrivilegedErrorCode::CapabilityRequestRejected,
        format!(
            "sublease delegation denied: {deny_class} \
             (parent lease lineage bindings are missing)"
        ),
    ));
}

if expiry_millis >= parent_lease.expires_at {
    let deny_class = AuthorityDenyClass::InvalidDelegationChain;
    return Ok(PrivilegedResponse::error(
        PrivilegedErrorCode::CapabilityRequestRejected,
        format!(
            "sublease delegation denied: {deny_class} \
             (strict expiry narrowing violated: requested_expiry_ms={expiry_millis}, \
             parent_expires_at_ms={})",
            parent_lease.expires_at
        ),
    ));
}
```

Anchors:
- `crates/apm2-daemon/src/protocol/dispatch.rs:15890`
- `crates/apm2-daemon/src/protocol/dispatch.rs:15858`

### After: canonical PCAC lifecycle gate

```rust
let Some(pcac_gate) = self.pcac_lifecycle_gate.as_deref() else {
    return Ok(PrivilegedResponse::error(
        PrivilegedErrorCode::CapabilityRequestRejected,
        "PCAC authority gate not wired for DelegateSublease (fail-closed)",
    ));
};

let pcac_builder =
    PrivilegedPcacInputBuilder::new(PrivilegedHandlerClass::DelegateSublease)
        .session_id(request.sublease_id.clone())
        .lease_id(request.parent_lease_id.clone())
        .boundary_intent_class(apm2_core::pcac::BoundaryIntentClass::Delegate)
        .identity_proof_hash(request_identity_proof_hash)
        .identity_evidence_level(IdentityEvidenceLevel::PointerOnly)
        .risk_tier(pcac_risk_tier);

let pcac_lifecycle_artifacts = self.enforce_privileged_pcac_lifecycle(
    PrivilegedHandlerClass::DelegateSublease.operation_name(),
    pcac_gate,
    &pcac_input,
    &request.parent_lease_id,
    join_freshness_tick,
    join_time_envelope_ref,
    join_ledger_anchor,
    join_revocation_head,
    effect_intent_digest,
)?;
```

Anchors:
- `crates/apm2-daemon/src/protocol/dispatch.rs:15903`
- `crates/apm2-daemon/src/protocol/dispatch.rs:16016`

## 7) Security Reviewer Checklist for PCAC-Integrated Code

1. Handler has authority-bearing side effects.
If yes, AJC lifecycle must be present.

2. Missing lifecycle gate denies fail-closed.
No silent bypass path.

3. `PrivilegedPcacInputBuilder` is used for privileged handlers.
Manual ad-hoc join-input construction is a review smell unless justified.

4. All lifecycle stages are visible in code path.
`join -> revalidate -> consume -> effect`

5. Consume happens before authoritative mutation/event acceptance.

6. Intent digest equality is enforced at consume boundary.

7. Lifecycle artifacts are persisted with authoritative effect event.

8. Failure paths deny on missing freshness/revocation/policy/clock state.

9. Tier2+ freshness/revocation/sovereignty checks are present when applicable.

10. Replay/duplicate consume is denied durably.

### Standard finding text when missing lifecycle

- Severity: `MAJOR`
- Finding: "Handler has authority-bearing side effects but no AJC lifecycle
  (`join -> revalidate -> consume -> effect`)."
- Required remediation: use `PrivilegedPcacInputBuilder`, run canonical lifecycle calls before effect, and persist lifecycle selectors on authoritative payloads.
