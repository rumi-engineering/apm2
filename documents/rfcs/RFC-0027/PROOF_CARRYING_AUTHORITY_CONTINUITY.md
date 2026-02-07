# RFC-0027 - Proof-Carrying Authority Continuity (PCAC)
**Status:** DRAFT (2026-02-07)  
**Audience:** Daemon/runtime, security, governance, FAC, identity/freshness, and verification reviewers  
**Scope:** Cell-local enforcement is normative. Federation-ready contracts are specified without forcing immediate distributed rollout.  
**Normative precedence:** `containment/security > verification/correctness > liveness/progress` (INV-F-14)  
**Depends on:** RFC-0016 (HTF), RFC-0018 (HEF), RFC-0019 (FAC), RFC-0020 (HSI), RFC-0022 (PSI), active security policy/threat model artifacts

---

## 0. Executive Summary (Non-Normative)

APM2 currently hardens actuation through multiple local checks (token/session validation, scope checks, pre-actuation stop/budget checks, replay ordering checks, handler-specific identity bindings). This closes important holes, especially DoS and TOCTOU classes, but does not define a single foundational authority primitive.

This RFC introduces **Proof-Carrying Authority Continuity (PCAC)**:

1. Construct a canonical, typed authority join from identity, delegation, capability, freshness, stop/budget, and intent inputs.
2. Mint an **AuthorityJoinCertificateV1** (AJC) as a single-use authority witness at a specific HTF time authority point.
3. Require explicit revalidation and single consumption of that certificate before any side effect.
4. Bind outcomes into deterministic, replay-verifiable receipts.

The key shift is from endpoint-local guard logic to a reusable authority lifecycle contract:

`join -> revalidate -> consume -> effect`

This keeps current secure-actuation work usable, but makes it an implementation family of a deeper primitive instead of the primitive itself.

---

## 0.1 Why This RFC Exists (Normative Problem Framing)

Current hardening remains fragmented across multiple control points and handlers. The system lacks one canonical object proving:

- which authority was admissible,
- for which intent,
- under which freshness/revocation state,
- at which HTF time witness and ledger anchor,
- and whether that authority has already been consumed.

Without that object, regressions reappear as path-specific edge cases. At scale and under federation, this causes verifier complexity growth, waiver drift, and revocation/freshness ambiguity.

**Normative requirement:** any authority-bearing side effect MUST be gated by a single canonical authority lifecycle artifact with fail-closed semantics.

---

## 0.2 Compatibility Floors (Normative)

RFC-0027 MUST preserve and strengthen existing floors:

1. No ambient authority paths (SP-INV-001, LAW-05).
2. Proof-carrying authoritative effects only (SP-INV-002, INV-F-02, LAW-15).
3. Digest-first boundaries with canonicalization and bounded decoding (SP-INV-003/004, RFC-0020 §0.1).
4. Strict-subset delegation (SP-INV-005).
5. Freshness-as-policy with Tier2+ deny on stale/ambiguous authority (SP-INV-006, REQ-0018).
6. Idempotent/replay-safe side effects (LAW-11).
7. Deterministic replay and independent verification for high-risk outcomes (LAW-17, LAW-20).

Compatibility note:

- Existing pre-actuation gate, broker, and verifier components remain valid and are integrated as PCAC sub-mechanisms.
- No protocol-wide wire break is required for phase-1 rollout.

---

## 0.3 Objective Contracts (Normative)

| Objective ID | Baseline Capture | Quantitative Target | HTF Boundary | Owner / Decision Locus | Machine Predicate | Evidence Path |
|---|---|---|---|---|---|---|
| `OBJ-PCAC-01` Lifecycle completeness | `PCAC-BL-2026-02-07-LC` | `missing_lifecycle_stage_count == 0` | `HTF-BND-PCAC-PHASE1-CLOSE` | Security Council + Runtime Council | `jq -e '.missing_lifecycle_stage_count == 0 and .ordered_receipt_chain_pass == true and .unknown_state_count == 0' evidence/rfcs/RFC-0027/objectives/OBJ-PCAC-01/summary.json` | `evidence/rfcs/RFC-0027/objectives/OBJ-PCAC-01/` |
| `OBJ-PCAC-02` Single-consume durability | `PCAC-BL-2026-02-07-SC` | `duplicate_consume_accept_count == 0 and durable_consume_record_coverage == 1.0` | `HTF-BND-PCAC-PHASE1-CLOSE` | Security Council | `jq -e '.duplicate_consume_accept_count == 0 and .durable_consume_record_coverage == 1.0 and .unknown_state_count == 0' evidence/rfcs/RFC-0027/objectives/OBJ-PCAC-02/summary.json` | `evidence/rfcs/RFC-0027/objectives/OBJ-PCAC-02/` |
| `OBJ-PCAC-03` Tier2+ freshness safety | `PCAC-BL-2026-02-07-FR` | `tier2plus_stale_allow_count == 0` | `HTF-BND-PCAC-PHASE2-CLOSE` | Security Council + Identity/Freshness Lane | `jq -e '.tier2plus_stale_allow_count == 0 and .freshness_unknown_state_count == 0 and .unknown_state_count == 0' evidence/rfcs/RFC-0027/objectives/OBJ-PCAC-03/summary.json` | `evidence/rfcs/RFC-0027/objectives/OBJ-PCAC-03/` |
| `OBJ-PCAC-04` Delegation narrowing | `PCAC-BL-2026-02-07-DN` | `delegation_narrowing_violations == 0` | `HTF-BND-PCAC-PHASE2-CLOSE` | Security Council + Governance Council | `jq -e '.delegation_narrowing_violations == 0 and .unknown_state_count == 0' evidence/rfcs/RFC-0027/objectives/OBJ-PCAC-04/summary.json` | `evidence/rfcs/RFC-0027/objectives/OBJ-PCAC-04/` |
| `OBJ-PCAC-05` Intent equality | `PCAC-BL-2026-02-07-IE` | `intent_mismatch_allow_count == 0` | `HTF-BND-PCAC-PHASE1-CLOSE` | Runtime Council + Verification Council | `jq -e '.intent_mismatch_allow_count == 0 and .unknown_state_count == 0' evidence/rfcs/RFC-0027/objectives/OBJ-PCAC-05/summary.json` | `evidence/rfcs/RFC-0027/objectives/OBJ-PCAC-05/` |
| `OBJ-PCAC-06` Replay verifiability | `PCAC-BL-2026-02-07-RV` | `authoritative_outcomes_with_full_replay_contract == 1.0` | `HTF-BND-PCAC-PHASE2-CLOSE` | Verification Council | `jq -e '.authoritative_outcomes_with_full_replay_contract == 1.0 and .missing_selector_count == 0 and .unknown_state_count == 0' evidence/rfcs/RFC-0027/objectives/OBJ-PCAC-06/summary.json` | `evidence/rfcs/RFC-0027/objectives/OBJ-PCAC-06/` |

All objective predicates fail closed: missing fields, parse errors, stale boundaries, invalid signatures, or unknown states are automatic deny outcomes.

---

## 0.4 Discovery Method Binding (Non-Normative)

RFC-0027 was discovered using `documents/prompts/instruction.alien_security.v1.json` as a discovery method.
Normative contract text remains in Sections 1-16.
Discovery outputs required by the instruction are captured in Appendix C.
If discovery hypotheses conflict with normative invariants, normative sections take precedence until explicitly amended.

---

## 1. Problem Statement (Normative)

### 1.1 Observed Deficit

The daemon has strong local controls, but authority proof is distributed across independent checks and response fields.

Examples from current implementation surfaces:

- `crates/apm2-daemon/src/protocol/session_dispatch.rs`: `RequestTool` admission checks are composed locally across token/session/scope/freshness paths rather than carried by one authority lifecycle object.
- `crates/apm2-daemon/src/episode/preactuation.rs`: pre-actuation checks are strong but transitional waiver states still exist for some freshness/budget conditions.
- `crates/apm2-daemon/src/protocol/dispatch.rs`: privileged delegation/review handlers bind identity and lease material, but evidence level and freshness posture are not yet unified under one consume-time witness.

### 1.2 Consequence

- Security posture is harder to reason about compositionally.
- New handlers can drift from hardened patterns.
- Replay/verification tooling must reconstruct authority from heterogeneous artifacts.
- Federation and anti-entropy increase risk of stale-authority and revocation race defects.

### 1.3 Required Abstraction

A side effect should require a **single, canonical, one-time-consumable authority witness** with explicit revalidation semantics.

---

## 2. Design Principles (Normative)

1. **Semantics before syntax:** define laws first, API second.
2. **Minimality:** one primitive with small, orthogonal surfaces.
3. **Containment-first:** uncertain authority always fails closed.
4. **Digest-first:** authority objects are canonical, hash-bound, and replay-addressable.
5. **Scale invariance:** same lifecycle contract at one session and across federated cells.
6. **Compounding closure:** recurring local hardening should be compiled into shared primitives.

---

## 3. Core Abstraction (Normative)

### 3.1 `AuthorityJoinInputV1`

Canonical input set used to compute admissible authority:

- Subject bindings: `session_id`, optional `holon_id`.
- Intent binding: `intent_digest` (canonicalized request/effect intent).
- Capability bindings: `capability_manifest_hash`, scope witness hash(es).
- Delegation bindings: `lease_id`, optional `permeability_receipt_hash`.
- Identity bindings: `identity_proof_hash`, identity evidence level.
- Freshness bindings: `directory_head_hash`, freshness policy hash, witness tick/boundary.
- Stop/budget policy bindings: stop/budget profile digest at join time.
- Stop/budget receipt bindings: pre-actuation receipt hash(es) required before revalidate/consume.
- Risk tier and determinism class.
- HTF time witness bindings: `time_envelope_ref` and as-of `ledger_anchor`.

### 3.2 `AuthorityJoinCertificateV1` (AJC)

Single-use authority witness with copy-tolerant semantics: certificate bytes MAY be copied, but only one authoritative consume is admissible.

- `ajc_id`: content hash of canonical certificate bytes.
- `authority_join_hash`: digest over normalized join inputs.
- `intent_digest`.
- `risk_tier`.
- `issued_time_envelope_ref` (HTF authoritative issue witness).
- `as_of_ledger_anchor` (admission ledger anchor used at join time).
- `expires_at_tick` (policy/freshness cutoff in authoritative tick space).
- `revocation_head_hash` (or equivalent revocation frontier commitment).
- `identity_evidence_level` (`Verified` | `PointerOnly`).
- optional admission-capacity token binding.

### 3.3 `AuthorityJoinKernel`

Minimal kernel API:

- `join(input) -> Result<AuthorityJoinCertificateV1, AuthorityDenyV1>`
- `revalidate(ajc, current_time_envelope_ref, current_ledger_anchor, current_revocation_head_hash) -> Result<(), AuthorityDenyV1>`
- `consume(ajc, intent_digest, current_time_envelope_ref) -> Result<(AuthorityConsumedV1, AuthorityConsumeRecordV1), AuthorityDenyV1>`

### 3.4 Receipts

- `AuthorityJoinReceiptV1`
- `AuthorityRevalidateReceiptV1`
- `AuthorityConsumeReceiptV1`
- `AuthorityDenyReceiptV1`

All receipts MUST include canonicalizer + digest metadata, time authority bindings, and signer/seal bindings required by policy tier.

For authoritative acceptance, lifecycle receipts MUST additionally bind:

- `episode_envelope_hash` (capability/budget/stop/freshness pinset commitment surface),
- `view_commitment_hash` (ledger/context observation commitment),
- `time_envelope_ref` (HTF authority witness for receipt time semantics),
- one admissible receipt authentication shape:
  - direct: `authority_seal_hash`, OR
  - pointer/batched: `receipt_hash` + `authority_seal_hash` + `merkle_inclusion_proof` (required when batched), and `receipt_batch_root_hash` when batch descriptor path is used,
- delegated-path bindings when delegated authority is consumed:
  - `permeability_receipt_hash`,
  - `delegation_chain_hash`.

Missing any required authoritative binding MUST fail closed.

---

## 4. Semantic Laws (Normative)

1. **Linear Consumption Law:** each AJC authorizes at most one side effect.
2. **Intent Equality Law:** consume requires exact intent digest equality.
3. **Freshness Dominance Law:** Tier2+ consume denies on stale/missing/ambiguous freshness authority.
4. **Revocation Dominance Law:** if revocation frontier advances beyond AJC admissibility, consume denies.
5. **Delegation Narrowing Law:** delegated joins must be strict-subset of parent authority.
6. **Boundary Monotonicity Law:** ordering MUST satisfy monotone HTF progression (`time_envelope_ref` + authoritative tick/anchor): `join < revalidate <= consume <= effect`.
7. **Evidence Sufficiency Law:** authoritative outcomes require replay-resolvable authority lifecycle receipts.

---

## 5. Transitional Evidence Levels and Waiver Interaction (Normative)

To handle active transitional realities without silent drift:

- `IdentityEvidenceLevel::Verified`
  - proof dereference + cryptographic verify completed under policy.
- `IdentityEvidenceLevel::PointerOnly`
  - hash-shape commitment only; allowed only under explicit waiver policy.

Policy requirements:

1. Tier0/1 MAY admit `PointerOnly` under explicit waiver binding.
2. Tier2+ MUST default to deny on `PointerOnly` unless explicitly waived and receipt-bound.
3. Every `PointerOnly` admission MUST emit a machine-readable waiver-binding receipt.
4. Waiver expiry or invalidity MUST immediately revert to fail-closed behavior.

---

## 6. Protocol Flows (Normative)

### 6.1 `RequestTool` Flow (Phase 1 Mandatory)

1. Bounded decode + session/token validation.
2. Build `AuthorityJoinInputV1` from session state, capability/delegation/freshness policy bindings, and intent digest.
3. `join` AJC (deny if fail).
4. Execute pre-actuation checks and emit pre-actuation receipt(s).
5. Bind pre-actuation receipt digest(s) as revalidate/consume prerequisites.
6. `revalidate` before broker decision.
7. `revalidate` again before side effect execution.
8. `consume` immediately before execution, requiring prior pre-actuation receipt binding.
9. Emit `ToolActuation` + authority lifecycle receipts.

### 6.2 `DelegateSublease` Flow (Phase 2)

1. Validate parent lease and caller authority.
2. Build delegation-specific join input (`parent_lease_id`, `sublease_id`, `identity_proof_hash`, freshness witness).
3. `join` AJC.
4. `consume` only when authoritative sublease persistence succeeds.
5. Emit lifecycle receipts and sublease event bound to `ajc_id`.

### 6.3 `IngestReviewReceipt` Flow (Phase 2)

1. Validate lease/reviewer bindings and review intent.
2. Build join input from review payload + identity/freshness/delegation context.
3. `join` then `consume` only on successful authoritative ledger emission.

### 6.4 Replay Order Contract

For any side-effectful operation:

`AuthorityJoin < AuthorityRevalidate < AuthorityConsume <= EffectReceipt`

If pre-actuation checks apply to the effect class:

`AuthorityJoin < PreActuationCheck < AuthorityRevalidate < AuthorityConsume <= EffectReceipt`

`AuthorityConsume` MUST reference the prior pre-actuation receipt selector when pre-actuation is required by policy.

### 6.5 Authoritative Acceptance Binding (Phase 1 Mandatory)

For any authoritative side effect, replay/adjudication MUST be able to verify one of:

1. direct receipt authentication via `authority_seal_hash`, or
2. `ReceiptPointerV1` authentication (`receipt_hash` + `authority_seal_hash` + `merkle_inclusion_proof` when batched), with admissible ledger/fact-root anchoring where applicable.

Forwarded event bytes without one of the above are routing facts only and MUST NOT be treated as acceptance facts.

### 6.6 Sovereignty Composition for Tier2+ (Phase 2 Mandatory)

For Tier2+ authority-bearing operations, `revalidate` and `consume` MUST also verify:

1. fresh `SovereigntyEpochSealV1` evidence (or equivalent admissible sovereignty authority anchor),
2. known `principal_revocation_head_hash` status (no unknown/ambiguous revocation state),
3. active autonomy ceiling compatibility with requested risk tier,
4. no active sovereign freeze state for the target scope.

Missing, stale, parse-invalid, signature-invalid, or unknown sovereignty-state inputs MUST deny consume and trigger configured freeze policy action where applicable.

---

## 7. Threat Coverage Mapping (Normative)

| Threat Class | PCAC Control |
|---|---|
| Identity replay / stale identity | freshness+revocation-bound revalidate/consume gates |
| Delegation widening / confused deputy | join-time strict-subset checks + lineage binding |
| TOCTOU between check and effect | explicit revalidate and consume immediately pre-effect |
| Duplicate/replayed actuation | single-use AJC consumption law |
| Fact forgery / unverifiable claims | mandatory receipt lineage and replay-resolvable selectors |
| Availability pressure | bounded join inputs + capacity-partitioned admission families |
| Sovereignty uncertainty / revocation ambiguity (Tier2+) | sovereignty-anchored revalidate/consume checks with deny/freeze on uncertainty |

---

## 8. Verifier Economics and Scale Envelope (Normative)

### 8.1 Scale Target

PCAC contracts MUST remain operationally admissible under globally distributed, evidence-heavy operation where authority checks are frequent and adversarial pressure is expected.

### 8.2 Economics Constraints

1. Join/revalidate/consume checks MUST be bounded in decode and selection cost.
2. Repeated verifications SHOULD amortize via cacheable head/root commitments.
3. Receipt batching and seal strategies MAY optimize implementation, but MUST preserve semantic equivalence.
4. Anti-entropy replication MAY prioritize digest metadata first; authority admission MUST remain proof-bound.

### 8.3 Failure Posture

- Missing required authority witness fields: deny.
- Unknown enum/identity/freshness state in authority-critical path: deny.
- Non-resolvable replay selectors for authoritative transitions: deny.

### 8.4 Economics Verification Contract

1. Tier2+ authority verification SHOULD target `O(log n)` proof-checking work in receipt set size `n`.
2. For tiered receipt batch families, the verifier SHOULD target `<= 2` cryptographic proof checks per authoritative receipt admission.
3. Each deployment profile MUST define and enforce admissible p95 bounds for:
   - `join` operation
   - `revalidate` operation
   - `consume` operation
   - anti-entropy catch-up operation
4. Authority admission for Tier2+ MUST fail closed when declared verifier-economics bounds are exceeded and no explicit degraded-mode policy path is admissible.

---

## 9. Policy Surface (Normative)

Minimum policy knobs:

- `require_ajc_for_tool_actuation`
- `require_ajc_for_delegate_sublease`
- `require_ajc_for_ingest_review_receipt`
- tiered admission capacity limits
- `tier2plus_require_verified_identity_proof`
- explicit waiver allowlist for pointer-only evidence
- revalidate checkpoints (`before_broker`, `before_execute`)
- required HTF `time_envelope_ref` and ledger anchor binding
- digest/canonicalizer identifiers
- `tier2plus_require_sovereignty_epoch`
- `tier2plus_require_principal_revocation_head`
- `tier2plus_require_autonomy_ceiling_check`
- `freeze_on_sovereignty_uncertainty`
- `max_sovereignty_epoch_ledger_lag_by_risk_tier`

Policy defaults MUST be containment-safe; uncertainty defaults to deny for authority-bearing paths.

---

## 10. Rollout Plan (Normative Intent)

### Phase 0 - Contract and Schema Definition

- Define `AuthorityJoinInputV1`, `AuthorityJoinCertificateV1`, deny classes, and lifecycle receipts.
- Define replay-verification extensions for lifecycle ordering.

### Phase 1 - `RequestTool` Integration

- Introduce `AuthorityJoinKernel` in daemon runtime.
- Require join/revalidate/consume for `RequestTool` side effects.
- Keep current pre-actuation gate and broker controls, but bind them through PCAC lifecycle.

### Phase 2 - Privileged Path Integration

- Integrate PCAC into `DelegateSublease` and `IngestReviewReceipt` handlers.
- Replace path-specific ad-hoc authority bundles with shared join builders.

### Phase 3 - Waiver Retirement Path

- Promote identity proof verification to admission-default where required by policy tier.
- Retire transitional pointer-only behavior where policy and readiness permit.

### Phase 4 - Federation-Ready Implementation Families

- Add distributed admission family (lease/replication-backed) without semantic drift from kernel contract.
- Validate equivalence against in-process family via replay and conformance suites.

---

## 11. Verification and Evidence Plan (Normative)

### 11.1 Unit-Level

1. Join denial on missing required witnesses.
2. Revalidate denial on revocation frontier advancement.
3. Consume denial on intent mismatch.
4. Consume denial on second consume attempt.
5. Tier2+ denial on stale/ambiguous freshness witness.

### 11.2 Integration-Level

1. No side effect path executes without successful consume.
2. `RequestTool` replay ordering includes authority lifecycle entries.
3. Privileged sublease/review flows enforce lifecycle semantics.
4. Flood/pressure tests confirm bounded in-flight authority admission and deterministic deny behavior.

### 11.3 Replay / Adjudication-Level

1. Deterministic rerun reconstructs lifecycle and effect ordering.
2. Tier2+ authoritative outcomes satisfy verifier diversity policy.
3. Any missing lifecycle selector is fail-closed for authoritative acceptance.
4. Any missing envelope/view/seal-or-pointer binding is fail-closed for authoritative acceptance.

### 11.4 Suggested Evidence Families

- `EVID-PCAC-0001`: Kernel lifecycle law conformance tests.
- `EVID-PCAC-0002`: `RequestTool` end-to-end lifecycle and replay ordering.
- `EVID-PCAC-0003`: Privileged handler lifecycle integration.
- `EVID-PCAC-0004`: Waiver-bound pointer-only policy enforcement and expiry behavior.
- `EVID-PCAC-0005`: Scale and verifier-economics benchmark evidence.

---

## 12. Security and Correctness Invariants (Normative)

1. No authority-bearing side effect without consumed AJC.
2. AJC single-use enforcement is durable for authoritative mode.
3. Authority join hash binds identity, delegation, capability, freshness, stop/budget, and intent.
4. Tier2+ ambiguous freshness is always deny.
5. Delegation widening is always deny.
6. Replay-verifiable lifecycle receipts are mandatory for authoritative acceptance.
7. HTF `time_envelope_ref` authority is mandatory; wall-clock is non-authoritative.
8. Unknown/missing required authority state is fail-closed.
9. Transitional pointer-only evidence is explicit, policy-bounded, and waiver-bound.
10. Containment precedence cannot be overridden by liveness optimization.

---

## 13. Tradeoffs (Non-Normative)

### 13.1 Benefits

- Replaces repeated local hardening with one reusable primitive.
- Expands security coverage beyond DoS/TOCTOU into authority continuity.
- Reduces long-term review burden and drift across handlers.

### 13.2 Costs

- Adds hot-path lifecycle checks and receipt volume.
- Requires careful policy and waiver management during transition.
- Initial implementation complexity increases before simplification payoff accrues.

---

## 14. Decision Docket (Normative Resolution Pending)

1. Decision `D-PCAC-001` (due by `HTF-BND-PCAC-PHASE2-CLOSE`; calendar target: March 15, 2026): Tier2+ pointer-only evidence policy.
   Candidate A: retain waiver-limited admission.
   Candidate B: hard deny once CAS identity verification is uniformly available.
   Required evidence: waiver-volume trend, deny-rate impact, and operational incident correlation.
2. Decision `D-PCAC-002` (due by `HTF-BND-PCAC-PHASE1-CLOSE`; calendar target: March 8, 2026): durable consume implementation family.
   Candidate A: direct ledger-backed write-once consume index from first authoritative rollout.
   Candidate B: crash-safe WAL consume index with mandatory pre-effect durability barrier and ledger mirror before authoritative acceptance.
   Non-admissible option: local in-memory uniqueness only for authoritative mode.
   Required evidence: crash-replay outcomes, durability-barrier fault injection results, and duplicate-consume deny integrity.
3. Decision `D-PCAC-003` (due by `HTF-BND-PCAC-PHASE3-DESIGN`; calendar target: April 5, 2026): first federated implementation family default.
   Candidate A: in-process capacity-token family.
   Candidate B: distributed lease-backed admission family.
   Required evidence: equivalence replay results, failure-mode matrix, and operator cost envelope.
4. Decision `D-PCAC-004` (due by `HTF-BND-PCAC-PHASE3-CLOSE`; calendar target: April 19, 2026): dual-family verification promotion thresholds.
   Candidate A: promote by risk tier only.
   Candidate B: promote by risk tier plus workload volatility and incident precursors.
   Required evidence: false-accept/false-deny deltas and verifier-economics impact under load.

---

## 15. Acceptance Criteria (Normative)

1. `RequestTool` side effects require successful `join`, `revalidate`, and `consume`.
2. Replay verifier enforces lifecycle ordering before authoritative acceptance.
3. Tier2+ stale/ambiguous freshness authority causes deterministic deny.
4. Privileged delegation/review endpoints can be switched to lifecycle enforcement under policy flag without wire break.
5. Denial taxonomy includes machine-checkable subclasses for lifecycle failures.
6. Policy can explicitly manage verified vs pointer-only identity evidence by risk tier.
7. All authoritative lifecycle receipts are canonicalized, digest-bound, and signer/seal verifiable.
8. All authoritative lifecycle receipts bind `episode_envelope_hash` and `view_commitment_hash`.
9. Authoritative `consume` acceptance requires a durable consume record committed before effect acceptance.

### 15.1 Gate Registry (Normative)

| Gate ID | Owner / Decision Locus | HTF Boundary | Machine Predicate | Evidence Path |
|---|---|---|---|---|
| `GATE-PCAC-LIFECYCLE` | Security Council + Runtime Council | `HTF-BND-PCAC-PHASE1-CLOSE` | `jq -e '.missing_lifecycle_stage_count == 0 and .unknown_state_count == 0' evidence/rfcs/RFC-0027/gates/GATE-PCAC-LIFECYCLE/summary.json` | `evidence/rfcs/RFC-0027/gates/GATE-PCAC-LIFECYCLE/` |
| `GATE-PCAC-SINGLE-CONSUME` | Security Council | `HTF-BND-PCAC-PHASE1-CLOSE` | `jq -e '.duplicate_consume_accept_count == 0 and .durable_consume_record_coverage == 1.0 and .unknown_state_count == 0' evidence/rfcs/RFC-0027/gates/GATE-PCAC-SINGLE-CONSUME/summary.json` | `evidence/rfcs/RFC-0027/gates/GATE-PCAC-SINGLE-CONSUME/` |
| `GATE-PCAC-FRESHNESS` | Security Council + Identity/Freshness Lane | `HTF-BND-PCAC-PHASE2-CLOSE` | `jq -e '.tier2plus_stale_allow_count == 0 and .freshness_unknown_state_count == 0 and .unknown_state_count == 0' evidence/rfcs/RFC-0027/gates/GATE-PCAC-FRESHNESS/summary.json` | `evidence/rfcs/RFC-0027/gates/GATE-PCAC-FRESHNESS/` |
| `GATE-PCAC-REPLAY` | Verification Council | `HTF-BND-PCAC-PHASE2-CLOSE` | `jq -e '.authoritative_outcomes_with_full_replay_contract == 1.0 and .missing_selector_count == 0 and .unknown_state_count == 0' evidence/rfcs/RFC-0027/gates/GATE-PCAC-REPLAY/summary.json` | `evidence/rfcs/RFC-0027/gates/GATE-PCAC-REPLAY/` |

---

## 16. Falsification Criteria (Normative)

PCAC recommendation is falsified if any of the following occur in conformance evidence:

1. A side effect is accepted without replay-resolvable lifecycle receipts.
2. Duplicate consume succeeds for the same `ajc_id` in authoritative mode.
3. Tier2+ stale or ambiguous freshness input results in allow.
4. Measured verifier economics regress versus current baseline while maintaining equivalent threat coverage.
5. Crash-replay permits authoritative effect acceptance with missing durable consume record.

---

## Appendix A - Minimal API Sketch (Illustrative)

```rust
pub enum IdentityEvidenceLevel {
    Verified,
    PointerOnly,
}

pub struct AuthorityJoinInputV1<'a> {
    pub session_id: &'a str,
    pub intent_digest: [u8; 32],
    pub risk_tier: RiskTier,
    pub capability_manifest_hash: [u8; 32],
    pub identity_proof_hash: [u8; 32],
    pub identity_evidence_level: IdentityEvidenceLevel,
    pub freshness_witness_hash: [u8; 32],
    pub time_envelope_ref: TimeEnvelopeRef,
    pub as_of_ledger_anchor: [u8; 32],
}

pub struct AuthorityJoinCertificateV1 {
    pub ajc_id: [u8; 32],
    pub authority_join_hash: [u8; 32],
    pub intent_digest: [u8; 32],
    pub issued_time_envelope_ref: TimeEnvelopeRef,
    pub as_of_ledger_anchor: [u8; 32],
    pub expires_at_tick: u64,
    pub revocation_head_hash: [u8; 32],
}

pub struct AuthorityConsumeRecordV1 {
    pub ajc_id: [u8; 32],
    pub consumed_time_envelope_ref: TimeEnvelopeRef,
    pub consumed_at_tick: u64,
    pub effect_selector_digest: [u8; 32],
}

pub trait AuthorityJoinKernel {
    fn join(&self, input: &AuthorityJoinInputV1<'_>) -> Result<AuthorityJoinCertificateV1, AuthorityDenyV1>;
    fn revalidate(
        &self,
        cert: &AuthorityJoinCertificateV1,
        current_time_envelope_ref: TimeEnvelopeRef,
        current_ledger_anchor: [u8; 32],
        current_revocation_head_hash: [u8; 32],
    ) -> Result<(), AuthorityDenyV1>;
    fn consume(
        &self,
        cert: &AuthorityJoinCertificateV1,
        intent_digest: [u8; 32],
        current_time_envelope_ref: TimeEnvelopeRef,
    ) -> Result<(AuthorityConsumedV1, AuthorityConsumeRecordV1), AuthorityDenyV1>;
}
```

---

## Appendix B - Initial Integration Targets

- `crates/apm2-daemon/src/protocol/session_dispatch.rs` (`RequestTool` lifecycle wiring)
- `crates/apm2-daemon/src/episode/preactuation.rs` (stop/budget witness integration)
- `crates/apm2-daemon/src/protocol/dispatch.rs` (sublease/review privileged lifecycle adoption)
- `crates/apm2-daemon/src/identity/directory_proof.rs` (identity/freshness verification path coupling)

---

## Appendix C - Alien Security Discovery Record (Non-Normative)

### C.1 Deep Context Immersion

Key security invariants:

- `INV-F-02`, `INV-F-05`, `INV-F-08`, `INV-F-14`.
- `LAW-05`, `LAW-09`, `LAW-11`, `LAW-14`, `LAW-15`, `LAW-17`, `LAW-20`.

Key threats:

- identity replay and revocation ambiguity.
- delegation widening and confused deputy escalation.
- fact forgery and verifier-cost amplification.
- parser/availability pressure and recursive amplification.
- freshness ambiguity on higher-tier authority paths.

Ad-hoc mechanisms observed:

- `RequestTool` checks are strong but path-local in `crates/apm2-daemon/src/protocol/session_dispatch.rs`.
- pre-actuation stop/budget checks in `crates/apm2-daemon/src/episode/preactuation.rs` include transitional waiver realities.
- privileged authority-bearing handlers in `crates/apm2-daemon/src/protocol/dispatch.rs` bind identity/delegation but did not yet encode one shared consume-time witness contract.
- identity verification substrate exists in `crates/apm2-daemon/src/identity/directory_proof.rs`.

### C.2 Cross-Domain Invariant Survey

- Object-capability and linear logic: authority must be explicit and non-duplicative in effect semantics.
- BFT/commit-certificate design: authoritative state transitions require compact proof carriers.
- Queueing/backpressure theory: bounded admission is mandatory for adversarial availability resilience.

### C.3 Parallel Candidate Abstractions

1. Candidate A: Hierarchical Admission Guard
   Source discipline: queueing and backpressure control.
   Invariant: bounded in-flight authority admission.
2. Candidate B: Linear Capability Witness
   Source discipline: object-capability and linear/affine semantics.
   Invariant: successful consume is unique.
3. Candidate C: Authority Commit Certificate
   Source discipline: BFT and proof-carrying transitions.
   Invariant: side effects require certificate-bound lineage.

### C.4 Source Discipline and Transferable Invariant

- Transfer chosen: linear capability witness + commit-certificate lineage.
- Transferable invariant: copyable artifacts are acceptable, but authoritative effect admission is single-consume and replay-verifiable.

### C.5 Exabyte-Scale Security Posture Projection

With abstraction:

- containment improves via fail-closed lifecycle gates.
- verification improves through one replay contract (`join -> revalidate -> consume -> effect`).
- liveness tradeoff is controlled overhead offset by predictable verifier economics.

Without abstraction:

- endpoint-local hardening drift persists.
- replay adjudication remains heterogeneous and expensive.
- federation pressure increases stale-authority and revocation race exposure.

### C.6 Adversarial Security Challenge

Adversarial challenge set:

1. stale identity witness presented at consume time.
2. duplicate consume attempts against same `ajc_id`.
3. revoked delegation between join and consume.
4. verifier load-spike with adversarial receipt fanout.

Required outcomes:

- Tier2+ stale/ambiguous freshness always denies.
- duplicate consume always denies.
- revocation frontier advancement denies.
- bounds breach without degraded-mode authorization denies.

### C.7 Final Recommendation

- Name: Proof-Carrying Authority Continuity (PCAC).
- Semantic laws: linear consume, intent equality, freshness/revocation dominance, delegation narrowing, boundary monotonicity, evidence sufficiency.
- API family: `AuthorityJoinKernel` with `join`, `revalidate`, `consume`, and external `AuthorityConsumeRecordV1`.
- Staged adoption: `RequestTool` first, then privileged delegation/review handlers, then federated families.
- Falsification criteria: Section 16.

### C.8 Evidence and Codebase Anchors

- `documents/security/THREAT_MODEL.cac.json`
- `documents/security/SECURITY_POLICY.cac.json`
- `documents/work/waivers/WVR-0101.yaml`
- `documents/work/waivers/WVR-0102.yaml`
- `documents/work/waivers/WVR-0103.yaml`
- `crates/apm2-daemon/src/protocol/session_dispatch.rs`
- `crates/apm2-daemon/src/episode/preactuation.rs`
- `crates/apm2-daemon/src/protocol/dispatch.rs`
- `crates/apm2-daemon/src/identity/directory_proof.rs`
