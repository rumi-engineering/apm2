# RFC-0022 - Principal Sovereignty Interface (PSI)
**Status:** DRAFT (2026-02-06)
**Audience:** Security, daemon/runtime, governance, FAC, federation, audit, and formal methods reviewers
**Scope:** Containment-tier protocol foundation for principal authority, stop-path integrity, autonomy graduation, and sovereign audit
**Normative precedence:** `containment/security > verification/correctness > liveness/progress` (INV-F-14)
**Dependency position:** Ships before RFC-0023, RFC-0024, RFC-0025, RFC-0026

---

## 0. Executive Summary (Non-Normative)
APM2 already has stop events, receipts, and fail-closed enforcement in RFC-0020. What it lacks is a complete sovereignty contract proving that the principal can always constrain, halt, audit, and revoke the autonomous holarchy at any scale.

PSI adds that missing layer by defining:
1. A formal sovereignty lattice where principal authority is mechanically top-ranked over all delegable authority.
2. A physically independent stop path with cryptographic liveness proofs and automatic freeze on uncertainty.
3. A four-level autonomy semilattice (`L0..L3`) with fail-safe regression and risk-tier capability ceilings.
4. HTF-anchored temporal revocation and anti-replay semantics for sovereignty operations.
5. Sovereign audit access with O(log n) proof complexity using existing receipt batching and Merkle multiproofs.
6. External self-containment proof verified outside the autonomous system trust boundary.

PSI preserves all RFC-0020 floors and strengthens them at the principal-control boundary.

---

## 0.1 Non-Negotiable Compatibility Floors (Normative)
PSI MUST preserve or strengthen the RFC-0020 invariants:
1. No ambient authority.
2. Proof-carrying effects.
3. Digest-first interfaces.
4. Fail-closed enforcement.
5. Canonicalization and bounded decoding.
6. Strict delegation narrowing.
7. Unitful typed quantities.
8. Self-certifying identities with O(log n) verification.
9. Freshness as policy, not best-effort.
10. Batched attestations and ledger/quorum anchored roots.

PSI-specific strengthening:
1. Sovereignty authority MUST be verifiable without trusting autonomous software cooperation.
2. Tier3+ authority-bearing sovereignty operations MUST require hardware-bound principal identity.
3. Missing or stale sovereignty liveness evidence MUST trigger automatic freeze.
4. Sovereignty constraints MUST be externally attestable as non-bypassable.

---

## 0.2 Rejected Design Options (Normative Rationale)
1. **Software-only kill path:** Rejected. Violates PHY-05 and INV-F-14 under daemon compromise.
2. **Quorum-only sovereignty root:** Rejected. Principal revocation/halt cannot depend on potentially Byzantine peer cooperation.
3. **Eventual revocation semantics:** Rejected. Tier2+ actuation with uncertain revocation is forbidden by LAW-09, LAW-15, and security posture fail-closed rules.
4. **Audit through autonomous projection APIs:** Rejected. Violates LAW-05 accountability axis and allows mediation attacks.

---

## 0.3 Constitutional Admissibility and Dominance Execution (Normative)
Principal sovereignty is exercised over admissible actions only.

Constitutional admissibility precheck:
1. Any action violating mission-level humanitarian deny predicates is denied regardless of principal seal, quorum, or liveness pressure.
2. Any action violating containment deny predicates is denied.
Governance evidence MUST expose separate booleans for humanitarian and containment precheck enforcement; these prechecks are not inferred from dominance ordering.

Dominance execution for admissible actions:
1. Containment/security constraints.
2. Verification/correctness constraints.
3. Liveness/progress optimizations.

Time authority execution rule:
1. HTF artifacts are the only admissible time authority for sovereignty gate truth.
2. Wall-clock fields are observational metadata only.
3. Missing/stale/parse-invalid HTF artifacts are automatic deny outcomes.

Reference predicate:
```bash
jq -e '.constitutional_admissibility_enforced == true and .humanitarian_precheck_enforced == true and .containment_precheck_enforced == true and .dominance_order == ["containment_security","verification_correctness","liveness_progress"] and .htf_time_authority_enforced == true and .wall_clock_used_for_gate_truth == false and .unknown_state_fail_closed == true' \
  evidence/rfcs/RFC-0022/governance/PSI-GOV-ORDER-001/summary.json
```

---

## 1. Problem Statement and Objective Contracts (Normative)

### 1.1 Deficit
Current artifacts provide partial stop mechanics (`InterventionFreeze/InterventionUnfreeze`, stop-path SLOs, `MECH-EMERGENCY-STOP`) but do not define the principal-rooted sovereignty protocol for:
1. Cryptographic root authority.
2. Hardware-rooted principal identity.
3. Graduated autonomy control.
4. Tamper-evident stop-path liveness.
5. Unmediated sovereign audit.
6. External containment proof.

### 1.2 Objective Contracts
PSI adopts and tightens these machine-checkable objectives:

| Objective | Predicate | Mandatory Outcome |
|---|---|---|
| OBJ-PSI-01 Hardware kill switch | `forall h in system: kill_switch_activation -> h.state=FROZEN within 2s` | Fail if any Tier3+ holon exceeds 2s p99 propagation |
| OBJ-PSI-02 Halt-path liveness | `forall epoch: liveness_proof(halt_path) in epoch_seal OR system.state=FROZEN` | Missing proof is automatic freeze |
| OBJ-PSI-03 Graduated autonomy | `forall action: action.risk_tier <= autonomy_level.max_risk_tier` | Deny and emit defect on exceedance |
| OBJ-PSI-04 Sovereign audit | `forall action in ledger: audit_proof(action).verify=true AND proof_size=O(log n)` | Unprovable actions are non-authoritative |
| OBJ-PSI-05 Hardware-rooted principal identity | `forall seal in T3+ ops: seal.key.attestation.hw_bound=true` | Software-only keys are invalid for T3+ |
| OBJ-PSI-06 Self-containment proof | `exists verifier outside trust boundary: verify(containment_proof)=true` | Internal-only proof is non-compliant |

### 1.3 Objective Contract Registry (Normative)
Every objective MUST bind baseline capture, target predicate, HTF boundary, owner locus, and evidence path.

| Objective | Baseline Capture Ref | HTF Boundary | Owner / Decision Locus | Machine Predicate | Evidence Path |
|---|---|---|---|---|---|
| OBJ-PSI-01 | `PSI-BL-STOP-2026-02-06` | `HTF-BND-P1-SECURITY-CLOSE` | Security Council + Runtime Council | `jq -e '.stop_propagation_p99_ms <= 2000 and .deny_uncertainty_p99_ms <= 250 and .hardware_cut_independence == true and .kill_convergence_coverage == 1.0 and .unknown_state_count == 0 and .signature_valid == true' evidence/rfcs/RFC-0022/objectives/OBJ-PSI-01/summary.json` | `evidence/rfcs/RFC-0022/objectives/OBJ-PSI-01/` |
| OBJ-PSI-02 | `PSI-BL-LIVENESS-2026-02-06` | `HTF-BND-P2-EARLY-CLOSE` | Security Council | `jq -e '.epoch_liveness_coverage == 1.0 and .missing_liveness_epoch_count == 0 and .false_pass_count == 0 and .unknown_state_count == 0' evidence/rfcs/RFC-0022/objectives/OBJ-PSI-02/summary.json` | `evidence/rfcs/RFC-0022/objectives/OBJ-PSI-02/` |
| OBJ-PSI-03 | `PSI-BL-AUTONOMY-2026-02-06` | `HTF-BND-P2-CLOSE` | Governance Council + Verification Council | `jq -e '.action_over_ceiling_count == 0 and .epoch_cumulative_risk_overflow_count == 0 and .uncertainty_regression_correctness == 1.0 and .unknown_state_count == 0' evidence/rfcs/RFC-0022/objectives/OBJ-PSI-03/summary.json` | `evidence/rfcs/RFC-0022/objectives/OBJ-PSI-03/` |
| OBJ-PSI-04 | `PSI-BL-AUDIT-2026-02-06` | `HTF-BND-P2-SEMANTICS-CLOSE` | Audit Council + Verification Council | `jq -e '.single_action_proof_complexity == "O(log n)" and .audit_completeness_failures == 0 and .omission_proof_coverage == 1.0 and .unknown_state_count == 0' evidence/rfcs/RFC-0022/objectives/OBJ-PSI-04/summary.json` | `evidence/rfcs/RFC-0022/objectives/OBJ-PSI-04/` |
| OBJ-PSI-05 | `PSI-BL-HW-KEY-2026-02-06` | `HTF-BND-P2-CONTROL-CLOSE` | Security Council | `jq -e '.tier3plus_softkey_usage == 0 and .attestation_freshness_failures == 0 and .unknown_state_count == 0' evidence/rfcs/RFC-0022/objectives/OBJ-PSI-05/summary.json` | `evidence/rfcs/RFC-0022/objectives/OBJ-PSI-05/` |
| OBJ-PSI-06 | `PSI-BL-CONTAINMENT-2026-02-06` | `HTF-BND-P3-CLOSE` | Security Council + External Assurance Lane | `jq -e '.external_verifier_coverage == 1.0 and .sovereignty_surface_coverage == 1.0 and .verifier_independence_pass == true and .internal_only_proof_count == 0 and .expired_proof_uses == 0 and .unknown_state_count == 0' evidence/rfcs/RFC-0022/objectives/OBJ-PSI-06/summary.json` | `evidence/rfcs/RFC-0022/objectives/OBJ-PSI-06/` |

All objective predicates fail closed on missing fields, parse errors, stale boundaries, invalid signatures, or unknown states.

---

## 2. System Model and Trust Boundaries (Normative)

### 2.1 Components
1. **Principal Control Stack (PCS):** Principal operator console, hardware token/HSM, physical kill actuator, out-of-band control network.
2. **Sovereignty Kernel (SK):** Daemon subsystem that enforces sovereignty policy, autonomy checks, revocation, stop preconditions, and receipt bindings.
3. **Halt Path Sentinel (HPS):** Independent verifier service validating stop-path liveness and latency.
4. **Sovereign Audit Reader (SAR):** Read-only audit path into ledger/CAS with proof validation; bypasses autonomous projection layers.
5. **Independent Containment Verifier (ICV):** External verifier checking non-bypass containment claims.

### 2.2 Trust Boundaries
1. **TB-0 Principal Root Boundary:** Principal identity and hardware root are trusted for sovereignty initiation.
2. **TB-1 External Verifier Boundary:** HPS and ICV are trusted only for verification roles, not for issuing principal authority.
3. **TB-2 Autonomous Runtime Boundary:** All autonomous holons and daemon internals are untrusted for sovereignty truth unless cryptographically proven.
4. **TB-3 Federation Boundary:** Remote cells are Byzantine-capable peers; imports require admission proofs.

### 2.3 Channel Classes
1. **SOV-GOV channel:** Sovereignty commands only, typed, signed, out-of-band preferred.
2. **WORK channel:** Regular autonomous operation, never authoritative for sovereignty root updates.
3. **EVIDENCE channel:** Digest-first proofs, receipt pointers, multiproofs.
4. **AUDIT channel:** Principal-initiated read-only retrieval with proof-carrying responses.

### 2.4 Precedence Rule
If control decisions conflict, SK MUST execute:
0. Constitutional admissibility precheck (mission-level humanitarian deny + containment deny).
1. Containment/security constraints.
2. Verification/correctness constraints.
3. Liveness/progress optimizations.

---

## 3. Formal Sovereignty and Autonomy Algebra (Normative)

### 3.1 Sovereignty Lattice
Let `A` be the set of admissible authority vectors under constitutional deny-set and containment policy.

Each authority vector is:
`a = <risk_ceiling, capability_set, budget_vector, stop_predicates, integrity_floor, confidentiality_ceiling, expiry_window, fanout_caps>`

Define partial order `<=` where `x <= y` means `x` is no more permissive than `y` across every dimension.

Define meet `x ^ y` as dimension-wise narrowing operator (RFC-0020 delegation meet semantics).

Define principal root `P_root in A` such that for any delegable authority `d in A`, `d <= P_root`.

**Normative rules:**
1. Every delegated authority MUST be computed as `child = parent ^ overlay`.
2. Every delegation edge MUST be strict narrowing (`child < parent`) unless exact replay of previously issued edge with identical digest and validity window.
3. If narrowing cannot be proven, delegation MUST be denied.
4. Effective authority at holon `h`: `Auth(h) = meet(path(P_root -> h))`.
5. Revocation is revocation-wins: revoked edge contribution is treated as `bottom` from revocation tick onward.

### 3.1.1 Dimension Order and Meet Determinism (Normative)
To keep delegation verification replay-equivalent across cells, PSI defines order orientation for every authority dimension:

| Dimension | Narrower relation (`x <= y`) | Deterministic meet (`x ^ y`) |
|---|---|---|
| `risk_ceiling` | lower risk ceiling is narrower | `min(x.risk_ceiling, y.risk_ceiling)` |
| `capability_set` | subset is narrower | `intersection(x.capability_set, y.capability_set)` |
| `budget_vector` | component-wise lower/equal caps are narrower | component-wise `min` |
| `stop_predicates` | more deny predicates is narrower | set union |
| `integrity_floor` | higher integrity floor is narrower | `max` |
| `confidentiality_ceiling` | lower confidentiality ceiling is narrower | `min` |
| `expiry_window` | earlier expiry is narrower | earlier bound |
| `fanout_caps` | lower cap is narrower | `min` |

If any component comparison is undefined (unit mismatch, unknown enum, missing mandatory component), meet evaluation MUST fail closed.

### 3.2 Autonomy Semilattice
Autonomy levels form ordered semilattice `L0 <= L1 <= L2 <= L3`.

Definitions:
1. `L0`: Human-in-loop.
2. `L1`: Human-on-loop.
3. `L2`: Human-on-call.
4. `L3`: Full autonomous under sovereign override.

Effective level:
`L_eff = meet(L_configured, L_principal_ceiling, L_evidence_proven, L_manual_override, L_freshness_state)`

Fail-safe regression rules:
1. Unknown level component resolves to `L0`.
2. Freshness uncertainty for Tier2+ operations forces `L_eff <= L1`.
3. Active sovereign freeze forces `L_eff = L0` and actuation deny except recovery-allowlisted actions.

### 3.3 Risk and Capability Mapping
PSI maps autonomy levels to maximum daemon risk tier ceilings:

| Autonomy Level | Max Daemon Risk Tier | Principal Approval Requirement | Default Action Under Uncertainty |
|---|---|---|---|
| L0 | Tier1 | Required for all world effects except read-only evidence fetch | Deny actuation |
| L1 | Tier2 | Required for Tier2 write-class effects | Regress to L0 |
| L2 | Tier3 | Required on escalation timeout or policy trigger | Regress to L1 |
| L3 | Tier4 | Not required for routine operation, always available for override | Regress to L1 if freshness/revocation uncertain |

### 3.3a Confidentiality and Integrity Lattice Order (Normative)
Lattice order (least to greatest):
1. Confidentiality: `PUBLIC <= INTERNAL <= CONFIDENTIAL <= RESTRICTED`.
2. Integrity: `LOW <= MEDIUM <= HIGH <= CRITICAL`.

Audit admissibility rules:
1. `served_confidentiality_ceiling <= request.required_confidentiality_clearance`.
2. `served_integrity_floor >= request.required_integrity_floor`.
3. If `include_confidential_payloads=false`, response payloads MUST remain `PUBLIC` and `declassification_receipt_hashes` MUST be empty.

### 3.4 Temporal Sovereignty
Every authority-bearing sovereignty artifact MUST bind temporal authority either directly or transitively via authenticated `AuthoritySealV1` and/or `SovereigntyEpochSealV1`.

Temporal binding profile:
| Artifact Class | Direct Required Fields | Required Transitive Binding |
|---|---|---|
| Command/delegation (`PrincipalDelegationReceiptV1`, `SovereignStopOrderV1`, `PrincipalRevocationRecordV1`) | `issued_time_envelope_ref`, `sovereignty_epoch`, `expires_at_tick`, `challenge_nonce` | `ledger_anchor` via authority seal |
| Identity/policy (`PrincipalIdentityV1`, `AutonomyPolicyV1`) | creation/update `time_envelope_ref`, explicit expiry | policy root + `ledger_anchor` via authority seal |
| Proof/audit (`HaltPathLivenessProofV1`, `ContainmentProofV1`, `SovereignAuditResponseV1`) | proof `time_envelope_ref`, target epoch identity, nonce echo/challenge when interactive | epoch/quorum anchor + verifier identity proof |

Validation is fail-closed if:
1. HTF witness invalid or stale per `FreshnessPolicyV1`.
2. Epoch non-monotonic for issuer identity.
3. Nonce replay detected for active window.
4. Revocation status unknown.
5. Replay-sensitive command artifacts MUST enforce uniqueness on `(issuer_key_id, sovereignty_epoch, hash(challenge_nonce), scope_selector_hash_or_subject_hash)`; sovereignty epoch regressions are invalid.
6. Nonce replay cache retention is shorter than artifact validity window + configured network delay budget.

### 3.4.1 Revocation Cutover Semantics (Normative)
Revocation correctness MUST be evaluated against HTF-issued ticks, not message arrival order.

Cutover rule:
1. Let `t_issue(a)` be authoritative issue tick for artifact `a`.
2. Let `t_revoke` be `PrincipalRevocationRecordV1.effective_tick`.
3. Artifact `a` signed by `revoked_keyset_id` is valid iff `t_issue(a) < t_revoke`.
4. If `t_issue(a)` cannot be proven, validation MUST fail closed.
5. Delayed transport delivery does not extend post-cutover validity.

### 3.5 Fractal Closure and Bisimulation
PSI primitives MUST be identical across recursion depth:
1. Principal-to-leaf stop and principal-to-cell stop share same typed artifacts.
2. Delegation proof checks are compositional and do not depend on depth-specific message kinds.
3. For `N <= 12`, flattened and recursive sovereign observables MUST pass bisimulation gate from RFC-0020.

### 3.6 Complexity Targets
At scale (`n <= 10^12` identities/facts):
1. Identity verification: O(log n) hashing plus amortized O(1) seal/head verification.
2. Sovereign audit of one action: O(log n) proof bytes and hash work with batched roots.
3. Verification of `k` actions in same batch family via multiproof profile: O(1) seal checks + O(log n + k) hashing.
4. Additional BFT control-plane overhead: less than 1 percent p99 CPU and network over baseline RFC-0014 path.

---

## 4. Protocol Objects and Field Definitions (Normative)
All artifacts are digest-addressed, canonicalized, bounded-decoding, and signed/sealed.

### 4.1 Common Type Aliases
- `CasDigest`: algorithm-tagged content hash (`blake3:<hex>` preferred).
- `Quantity`: unitful numeric (`value_i64`, `unit`, optional `scale`).
- `RiskTier`: daemon risk enum (`Tier0..Tier4`).
- `TimeEnvelopeRef`: RFC-0016 HTF reference.
- `AuthoritySealRef`: CAS digest for `AuthoritySealV1`.
- `IdentityProofRef`: CAS digest for `IdentityProofV1`.
- `ReceiptPointerRef`: CAS digest for `ReceiptPointerV1` or multiproof container.

### 4.1a SovereigntyDecoderProfileV1
```yaml
schema_id: apm2.sovereignty_decoder_profile.v1
profile_id: string
max_artifact_bytes: uint64
max_string_bytes: uint32
max_bytes_field_bytes: uint32
max_repeated_count: uint32
max_merkle_proof_nodes: uint32
max_nonce_cache_entries: uint32
json_unknown_field_policy: REJECT
protobuf_unknown_field_policy: DROP_AND_NOT_FORWARD
version: uint32
authority_seal_hash: AuthoritySealRef
```
Constraints:
1. All PSI decoders MUST enforce profile limits before allocation and after decode.
2. Unknown fields in signed/hashed JSON artifacts MUST be rejected.
3. Unknown fields in signed/hashed protobuf artifacts MUST be dropped before canonicalization/signing and MUST NOT be forwarded.

### 4.2 PrincipalIdentityV1
```yaml
schema_id: apm2.principal_identity.v1
principal_id: string
principal_public_key_id: PublicKeyIdV1
root_keyset_id: KeySetIdV1
hardware_attestation_hash: CasDigest | null
attestation_kind: TPM2 | YUBIHSM2 | SGX | SEV_SNP | SOFTWARE_ONLY | OTHER
attestation_fresh_until_tick: uint64 | null
attestation_issuer_identity_proof_hash: IdentityProofRef | null
autonomy_ceiling: L0 | L1 | L2 | L3
sovereignty_policy_hash: CasDigest
delegation_root_hash: CasDigest
revocation_commitment_hash: CasDigest
created_time_envelope_ref: TimeEnvelopeRef
expires_at_tick: uint64
authority_seal_hash: AuthoritySealRef
```
Constraints:
1. Tier3+ principal operations require non-null `hardware_attestation_hash`, non-null `attestation_fresh_until_tick`, and `attestation_kind != SOFTWARE_ONLY`.
2. `SOFTWARE_ONLY` is permitted only for Stage S0..S2 and only when effective autonomy is `L0` or `L1`.
3. `attestation_issuer_identity_proof_hash` is REQUIRED whenever `hardware_attestation_hash` is non-null.
4. Missing or stale required attestation metadata is fail-closed for authority-bearing operations.
5. `authority_seal_hash` MUST anchor to trusted root policy.
6. `expires_at_tick` MUST be enforced by freshness policy.

### 4.3 PrincipalDelegationReceiptV1
```yaml
schema_id: apm2.principal_delegation_receipt.v1
delegation_id: string
from_identity: string
to_identity: string
parent_delegation_hash: CasDigest | null
authority_vector_hash: CasDigest
authority_overlay_hash: CasDigest
meet_result_hash: CasDigest
issued_time_envelope_ref: TimeEnvelopeRef
expires_at_tick: uint64
revocation_rule: REVOCATION_WINS
challenge_context_hash: CasDigest | null
authority_seal_hash: AuthoritySealRef
```
Constraints:
1. `meet_result_hash` MUST equal deterministic meet of parent and overlay.
2. `expires_at_tick` MUST be less than or equal to parent expiry.
3. Delegation without parent proof (except principal root) is invalid.

### 4.4 AutonomyPolicyV1
```yaml
schema_id: apm2.autonomy_policy.v1
policy_id: string
level: L0 | L1 | L2 | L3
max_risk_tier: RiskTier
capability_ceiling_hash: CasDigest
per_action_constraints_hash: CasDigest
risk_accumulator_profile_hash: CasDigest
per_epoch_budget_ceiling:
  max_tool_calls: Quantity
  max_wall_ms: Quantity
  max_cpu_ms: Quantity
  max_bytes_io: Quantity
  max_evidence_bytes: Quantity
max_cumulative_risk_score: Quantity
requires_principal_approval: bool
approval_timeout_ms: Quantity
escalation_policy_hash: CasDigest
downgrade_triggers: [string]
promotion_requirements_hash: CasDigest
goodhart_surface: string
version: uint32
authority_seal_hash: AuthoritySealRef
```
Constraints:
1. `max_risk_tier` MUST monotonically increase with level number.
2. `downgrade_triggers` MUST include freshness uncertainty and revocation uncertainty for L2+.
3. `downgrade_triggers` MUST include cumulative-risk overflow for L2+.
4. `requires_principal_approval=true` is mandatory at L0.
5. `risk_accumulator_profile_hash` MUST resolve to a deterministic profile shared by all verifiers for the active epoch.

### 4.4a RiskAccumulatorProfileV1
```yaml
schema_id: apm2.risk_accumulator_profile.v1
profile_id: string
risk_weight_by_tier:
  Tier0: Quantity
  Tier1: Quantity
  Tier2: Quantity
  Tier3: Quantity
  Tier4: Quantity
cross_capability_interaction_matrix_hash: CasDigest
temporal_decay_half_life_ticks: uint64
saturation_ceiling: Quantity
normalization_unit: string
version: uint32
authority_seal_hash: AuthoritySealRef
```
Constraints:
1. For fixed input receipts and epoch window, output MUST be deterministic across implementations.
2. Unknown capability-pair interactions MUST fail closed (no implicit zero-default).
3. `saturation_ceiling` MUST be less than or equal to strictest active `max_cumulative_risk_score`.

### 4.5 AutonomyEvidenceWindowV1
```yaml
schema_id: apm2.autonomy_evidence_window.v1
window_id: string
candidate_level: L0 | L1 | L2 | L3
window_start_envelope_ref: TimeEnvelopeRef
window_end_envelope_ref: TimeEnvelopeRef
required_incident_free_epochs: uint64
observed_incident_free_epochs: uint64
policy_violation_count: uint64
halt_path_violation_count: uint64
verification_escape_rate: Quantity
countermetric_pass: bool
supporting_receipt_multiproof_hash: CasDigest
verifier_identity_proof_hash: IdentityProofRef
verifier_seal_hash: AuthoritySealRef
```
Constraints:
1. Promotion requires `countermetric_pass=true` and all counts within policy thresholds.
2. Missing evidence or stale verifier identity forces non-promotion.

### 4.6 SovereignStopOrderV1
```yaml
schema_id: apm2.sovereign_stop_order.v1
stop_order_id: string
mode: FREEZE | KILL | READ_ONLY
scope: GLOBAL | CELL | HOLON_SET | WORK_SET
scope_selector_hash: CasDigest
reason_code: string
issued_by_principal_id: string
issuer_key_id: PublicKeyIdV1
issuer_identity_proof_hash: IdentityProofRef
issuer_hardware_attestation_hash: CasDigest | null
sovereignty_epoch: uint64
challenge_nonce: bytes
issued_time_envelope_ref: TimeEnvelopeRef
expires_at_tick: uint64
require_hardware_path: bool
require_software_path: bool
min_required_acks: uint32
scope_cardinality_hint: uint64
required_ack_coverage_ratio: Quantity
authority_seal_hash: AuthoritySealRef
```
Constraints:
1. `mode=KILL` MUST require principal root signer.
2. At least one of `require_hardware_path` or `require_software_path` MUST be true; Tier3+ MUST set both true.
3. Tier3+ requires non-null `issuer_hardware_attestation_hash`.
4. `min_required_acks` MUST be >=1 and MUST NOT exceed `scope_cardinality_hint`.
5. Tier3+ GLOBAL stop requires `required_ack_coverage_ratio == 1.0`.
6. Unknown stop state at enforcement point triggers deny in <=250ms.
7. For a given `issuer_key_id`, `(sovereignty_epoch, hash(challenge_nonce), scope_selector_hash)` MUST be unique.

### 4.7 SovereignStopAckV1
```yaml
schema_id: apm2.sovereign_stop_ack.v1
stop_order_id: string
ack_id: string
actor_id: string
actor_identity_proof_hash: IdentityProofRef
cell_id: CellIdV1
path: HARDWARE_RELAY | KERNEL_STOP_CHECK | CAPSULE_TERMINATE
observed_state: FROZEN | DENY_ONLY
propagation_latency_ms: Quantity
stop_state_hash: CasDigest
node_attestation_hash: CasDigest
path_attestation_hash: CasDigest
ack_time_envelope_ref: TimeEnvelopeRef
ack_signature_or_seal_hash: AuthoritySealRef
```
Constraints:
1. `propagation_latency_ms` contributes to halt-path SLO computation.
2. Invalid attestation for Tier3+ acks marks ack non-authoritative.
3. Tier2+ authoritative ack requires valid `actor_identity_proof_hash`.

### 4.8 HaltPathLivenessProofV1
```yaml
schema_id: apm2.halt_path_liveness_proof.v1
proof_id: string
target_epoch_id: string
prior_epoch_seal_hash: CasDigest | null
probe_plan_hash: CasDigest
challenge_nonce: bytes
challenge_issued_envelope_ref: TimeEnvelopeRef
sampled_ack_multiproof_hash: CasDigest
probe_sample_coverage_ratio: Quantity
probe_randomness_beacon_hash: CasDigest
propagation_p99_ms: Quantity
deny_uncertainty_p99_ms: Quantity
hardware_reachability_ratio: Quantity
software_reachability_ratio: Quantity
drill_receipt_hashes: [CasDigest]
verifier_identity_proof_hash: IdentityProofRef
verifier_independence_attestation_hash: CasDigest
verdict: PASS | FAIL
time_envelope_ref: TimeEnvelopeRef
verifier_seal_hash: AuthoritySealRef
```
Constraints:
1. PASS requires p99 propagation <=2000ms and deny-on-uncertainty <=250ms at Tier3+.
2. Tier3+ PASS requires `hardware_reachability_ratio == 1.0` and `software_reachability_ratio == 1.0`.
3. `challenge_nonce` MUST match epoch challenge context.
4. `target_epoch_id` MUST equal the epoch being sealed.
5. `prior_epoch_seal_hash` MUST equal the previous sealed epoch for the same cell (or null for genesis).
6. Missing/stale/replayed proof in epoch is equivalent to FAIL and triggers freeze.
7. `verifier_independence_attestation_hash` MUST resolve to fresh `VerifierIndependenceAttestationV1`; Tier2+ requires `independence_class=STRONG`.
8. PASS requires `probe_sample_coverage_ratio` to meet policy minimum for the scope/risk tier.
9. `probe_plan_hash` MUST be derived from an authenticated randomness beacon (`probe_randomness_beacon_hash`) bound to the epoch challenge context.

### 4.9 SovereigntyEpochSealV1
```yaml
schema_id: apm2.sovereignty_epoch_seal.v1
epoch_id: string
previous_epoch_seal_hash: CasDigest | null
cell_id: CellIdV1
time_envelope_ref: TimeEnvelopeRef
quorum_anchor: string
directory_head_hash: CasDigest
revocation_head_hash: CasDigest
principal_revocation_head_hash: CasDigest
autonomy_state_root_hash: CasDigest
decoder_profile_hash: CasDigest
halt_path_liveness_proof_hash: CasDigest
hardware_kill_activation_receipt_hash: CasDigest
kill_switch_convergence_proof_hash: CasDigest
capsule_integrity_proof_hash: CasDigest
containment_proof_bundle_hash: CasDigest
audit_bypass_manifest_hash: CasDigest
active_constraint_root_hash: CasDigest
fact_root_hash: CasDigest
epoch_challenge_nonce_hash: CasDigest
authority_seal_hash: AuthoritySealRef
```
Constraints:
1. MUST be monotonic by `(time_envelope_ref, quorum_anchor)` for a cell.
2. Non-genesis epochs MUST set non-null `previous_epoch_seal_hash` equal to the prior admitted seal for the same cell; genesis MUST set null.
3. `epoch_challenge_nonce_hash` MUST commit to the single-use challenge nonce for the epoch.
4. MUST include `halt_path_liveness_proof_hash` for epochs where autonomy is enabled above L0.
5. Tier2+ epochs MUST include non-null `principal_revocation_head_hash`, `hardware_kill_activation_receipt_hash`, `kill_switch_convergence_proof_hash`, `capsule_integrity_proof_hash`, `audit_bypass_manifest_hash`, and `active_constraint_root_hash`.
6. `hardware_kill_activation_receipt_hash` MUST reference a fresh `DRILL` or `REAL_ACTIVATION` receipt, and `kill_switch_convergence_proof_hash` MUST prove convergence against that activation with matching stop-order replay guards.
7. Missing any required Tier2+ sovereignty hash is equivalent to containment uncertainty and triggers freeze.
8. `decoder_profile_hash` MUST resolve to active `SovereigntyDecoderProfileV1`; mismatch is containment uncertainty and triggers freeze.
9. `active_constraint_root_hash` MUST equal the genesis constraint root or the latest admitted `SovereigntyConstraintMutationReceiptV1.proposed_constraint_root_hash` effective at this epoch.
10. `audit_bypass_manifest_hash` MUST resolve to a fresh manifest usable for principal digest-fetch without responder mediation.

### 4.10 SovereignAuditRequestV1
```yaml
schema_id: apm2.sovereign_audit_request.v1
request_id: string
request_nonce: bytes
principal_identity_proof_hash: IdentityProofRef
principal_authority_seal_hash: AuthoritySealRef
query_type: ACTION | WORK | EPISODE | DELEGATION_CHAIN | RANGE
query_selector_hash: CasDigest
required_epoch_id: string | null
query_lower_seq: uint64 | null
query_upper_seq: uint64 | null
max_proof_bytes: uint64
include_confidential_payloads: bool
required_confidentiality_clearance: PUBLIC | INTERNAL | CONFIDENTIAL | RESTRICTED
required_integrity_floor: LOW | MEDIUM | HIGH | CRITICAL
classification_lattice_profile_hash: CasDigest
time_envelope_ref: TimeEnvelopeRef
```
Constraints:
1. Request must authenticate principal identity and freshness.
2. Query selectors must be deterministic and bounded.
3. If `query_lower_seq`/`query_upper_seq` are set, response MUST prove contiguous coverage and omission.
4. Returned artifacts below `required_integrity_floor` MUST be omitted with verifiable omission proof.
5. `classification_lattice_profile_hash` MUST resolve to an authenticated profile; string-comparison semantics are forbidden.

### 4.10a ClassificationLatticeProfileV1
```yaml
schema_id: apm2.classification_lattice_profile.v1
profile_id: string
confidentiality_order: [PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED]
integrity_order: [LOW, MEDIUM, HIGH, CRITICAL]
comparison_semantics: EXPLICIT_ENUM_ORDER
declassification_policy_hash: CasDigest
version: uint32
authority_seal_hash: AuthoritySealRef
```
Constraints:
1. Label comparison MUST use the explicit enum order in this profile; lexical/string ordering is invalid.
2. Profile changes MUST be versioned and sealed; unsigned profile updates are non-authoritative.
3. Responses using a different profile than requested MUST be denied.

### 4.11 SovereignAuditResponseV1
```yaml
schema_id: apm2.sovereign_audit_response.v1
request_id: string
request_digest: CasDigest
response_nonce_echo: bytes
served_epoch_id: string
served_epoch_order_proof_hash: CasDigest | null
ledger_head_hash: CasDigest
result_root_hash: CasDigest
receipt_pointers: [ReceiptPointerRef]
receipt_multiproof_hash: CasDigest
fact_inclusion_multiproof_hash: CasDigest
omission_multiproof_hash: CasDigest
causal_parent_links_hash: CasDigest
completeness_attestation_hash: CasDigest
proof_complexity_class: O_LOG_N | O_LOG_N_PLUS_K
classification_manifest_hash: CasDigest
direct_fetch_manifest_hash: CasDigest
audit_bypass_manifest_hash: CasDigest
proof_profile_hash: CasDigest
served_confidentiality_ceiling: PUBLIC | INTERNAL | CONFIDENTIAL | RESTRICTED
served_integrity_floor: LOW | MEDIUM | HIGH | CRITICAL
declassification_receipt_hashes: [CasDigest]
time_envelope_ref: TimeEnvelopeRef
responder_seal_hash: AuthoritySealRef
```
Constraints:
1. `proof_complexity_class` MUST be verifiable against `proof_profile_hash`.
2. `response_nonce_echo` MUST equal request nonce.
3. If `request.required_epoch_id` is set, `served_epoch_order_proof_hash` MUST prove `served_epoch_id` is the same epoch or a descendant in admitted epoch-seal order.
4. Ranged queries require valid omission proof plus contiguous coverage proof.
5. If confidential payloads are returned, `declassification_receipt_hashes` MUST be non-empty.
6. `served_integrity_floor` and `served_confidentiality_ceiling` MUST satisfy Section 3.3a lattice-order rules.
7. If `request.include_confidential_payloads=false`, response MUST keep `served_confidentiality_ceiling=PUBLIC` and `declassification_receipt_hashes=[]`.
8. `direct_fetch_manifest_hash` MUST provide digest-addressable retrieval endpoints independent of responder projections.
9. `audit_bypass_manifest_hash` MUST resolve to valid `AuditBypassManifestV1`.
10. Response without completeness attestation is advisory only and non-authoritative.

### 4.11a ProofComplexityProfileV1
```yaml
schema_id: apm2.proof_complexity_profile.v1
profile_id: string
single_action_class: O_LOG_N
batch_class: O_LOG_N_PLUS_K
max_multiproof_nodes: uint32
max_receipt_pointer_count: uint32
max_verify_hash_ops_single_action: uint64
max_verify_hash_ops_batch_base: uint64
max_verify_hash_ops_batch_per_result: uint64
version: uint32
authority_seal_hash: AuthoritySealRef
```
Constraints:
1. `proof_complexity_class` claims are authoritative only if bounded by this profile.
2. Any response exceeding declared verifier-work ceilings is non-authoritative.

### 4.11b AuditBypassManifestV1
```yaml
schema_id: apm2.audit_bypass_manifest.v1
manifest_id: string
request_id: string
ledger_anchor_hash: CasDigest
direct_cas_endpoint_set_hash: CasDigest
admission_receipt_hashes: [CasDigest]
endpoint_operator_identity_proof_hashes: [IdentityProofRef]
endpoint_independence_attestation_hash: CasDigest
time_envelope_ref: TimeEnvelopeRef
seal_hash: AuthoritySealRef
```
Constraints:
1. Manifest MUST allow principal digest-fetch without responder mediation.
2. Tier2+ requires at least two endpoints in disjoint control domains.
3. `endpoint_independence_attestation_hash` MUST satisfy strong independence (`shared_signing_root=false`).
4. Missing or stale bypass manifest makes response non-authoritative.

### 4.12 ContainmentProofV1
```yaml
schema_id: apm2.containment_proof.v1
proof_id: string
subject_kind: DAEMON_BINARY | POLICY_BUNDLE | SOVEREIGNTY_KERNEL | NODE_PROFILE
subject_hash: CasDigest
proof_type: MODEL_CHECK | NON_BYPASS_ATTESTATION | RUNTIME_INVARIANT
invariants_checked: [string]   # e.g. INV-F-05, INV-F-11, INV-F-14
proof_artifact_hash: CasDigest
sovereignty_surface_manifest_hash: CasDigest
non_bypass_claim_hash: CasDigest
external_verifier_identity_proof_hash: IdentityProofRef
verifier_independence_attestation_hash: CasDigest
valid_from_envelope_ref: TimeEnvelopeRef
valid_until_tick: uint64
goodhart_surface: string
external_verifier_seal_hash: AuthoritySealRef
```
Constraints:
1. External verifier identity MUST be outside autonomous trust boundary.
2. `sovereignty_surface_manifest_hash` MUST enumerate all sovereignty-critical binaries/policies in scope.
3. `verifier_independence_attestation_hash` MUST be valid, fresh, and `independence_class=STRONG`.
4. Expired proof blocks Tier2+ promotion.

### 4.13 ContainmentProofBundleV1
```yaml
schema_id: apm2.containment_proof_bundle.v1
bundle_id: string
proof_hashes: [CasDigest]
subject_set_root_hash: CasDigest
binding_epoch_id: string
active_subject_set_root_hash: CasDigest
active_subject_measurement_multiproof_hash: CasDigest
coverage_claims_hash: CasDigest
bundle_time_envelope_ref: TimeEnvelopeRef
bundle_seal_hash: AuthoritySealRef
```
Constraints:
1. Bundle MUST cover all active sovereignty-critical binaries and policy roots.
2. `active_subject_set_root_hash` MUST match the active sovereignty surface for `binding_epoch_id`.
3. `active_subject_measurement_multiproof_hash` MUST verify each subject hash against active runtime measurements/attestations.
4. Partial coverage is non-compliant for Tier2+ autonomy.

### 4.14 PrincipalRevocationRecordV1
```yaml
schema_id: apm2.principal_revocation_record.v1
revocation_id: string
principal_id: string
revoked_keyset_id: KeySetIdV1
replacement_keyset_id: KeySetIdV1 | null
reason_code: COMPROMISE | ROTATION | LOST_DEVICE | POLICY_REKEY | OTHER
effective_tick: uint64
issued_tick: uint64
sovereignty_epoch: uint64
challenge_nonce: bytes
prev_revocation_head_hash: CasDigest
issued_time_envelope_ref: TimeEnvelopeRef
authority_seal_hash: AuthoritySealRef
```
Constraints:
1. `sovereignty_epoch` MUST be strictly monotonic per principal.
2. Revocation record freshness failure is an automatic Tier2+ deny.
3. Revocation uncertainty is revocation-wins and MUST fail closed.
4. `effective_tick` MUST be greater than or equal to `issued_tick`.
5. `prev_revocation_head_hash` MUST match active revocation head at issuance time.
6. Artifacts issued at or after `effective_tick` by `revoked_keyset_id` are invalid regardless of arrival order.
7. For a given `principal_id`, `(sovereignty_epoch, hash(challenge_nonce))` MUST be unique and strictly monotonic.

### 4.15 HardwareKillActivationReceiptV1
```yaml
schema_id: apm2.hardware_kill_activation_receipt.v1
activation_id: string
actuator_id: string
actuator_firmware_measurement_hash: CasDigest
actuator_attestation_hash: CasDigest
activation_edge_tick: uint64
receipt_kind: DRILL | REAL_ACTIVATION
scope_selector_hash: CasDigest
stop_order_id: string | null
challenge_nonce_echo: bytes | null
independent_power_domain: bool
independent_control_network: bool
hardware_path_proof_hash: CasDigest
time_envelope_ref: TimeEnvelopeRef
verifier_identity_proof_hash: IdentityProofRef
verifier_seal_hash: AuthoritySealRef
```
Constraints:
1. Receipt MUST be generated from out-of-band control plane, not daemon runtime path.
2. Tier3+ `mode=KILL` requires `independent_power_domain=true` and `independent_control_network=true`.
3. Tier2+ epochs MUST reference a fresh hardware receipt where `receipt_kind in {DRILL, REAL_ACTIVATION}`.
4. For `mode=KILL`, hardware cut execution MUST NOT wait for software-path acknowledgments.
5. If `stop_order_id` is non-null, `stop_order_id` and `challenge_nonce_echo` MUST match the active `SovereignStopOrderV1`.
6. For principal physical activation when the software control path is unavailable, `stop_order_id` and `challenge_nonce_echo` MAY be null; this remains safety-authoritative and MUST force global freeze.
7. Reuse of non-null `(stop_order_id, challenge_nonce_echo)` across distinct `activation_id` values is a replay defect and MUST fail closed.
8. Any null-bound activation MUST produce a reconciliation receipt before any sovereign resume is admissible.

### 4.16 CapsuleIntegrityProofV1
```yaml
schema_id: apm2.capsule_integrity_proof.v1
proof_id: string
cell_id: CellIdV1
capsule_profile_id: string
capsule_profile_hash: CasDigest
namespace_layout_hash: CasDigest
seccomp_profile_hash: CasDigest
cgroup_limit_hash: CasDigest
runtime_attestation_hash: CasDigest
time_envelope_ref: TimeEnvelopeRef
verifier_identity_proof_hash: IdentityProofRef
verdict: PASS | FAIL
verifier_seal_hash: AuthoritySealRef
```
Constraints:
1. Tier2+ operation requires latest epoch `CapsuleIntegrityProofV1` with `verdict=PASS`.
2. Missing/stale capsule integrity proof is a hard deny for Tier2+ actuation.

### 4.17 VerifierIndependenceAttestationV1
```yaml
schema_id: apm2.verifier_independence_attestation.v1
attestation_id: string
subject_verifier_identity_proof_hash: IdentityProofRef
evaluated_subject_scope_hash: CasDigest
independence_class: STRONG | CONDITIONAL | WEAK
shared_control_overlap_ratio: Quantity
shared_funding_ratio: Quantity
shared_admin_domain_count: uint32
shared_signing_root: bool
shared_network_asn_overlap_ratio: Quantity
valid_from_envelope_ref: TimeEnvelopeRef
valid_until_tick: uint64
assessor_identity_proof_hash: IdentityProofRef
assessor_seal_hash: AuthoritySealRef
```
Constraints:
1. Tier2+ containment and liveness verification requires `independence_class=STRONG`.
2. `shared_signing_root` MUST be `false` for Tier2+ claims.
3. Expired or stale attestations are fail-closed.

### 4.18 KillSwitchConvergenceProofV1
```yaml
schema_id: apm2.kill_switch_convergence_proof.v1
proof_id: string
activation_id: string
stop_order_id: string
challenge_nonce_echo: bytes
scope_selector_hash: CasDigest
sampled_freeze_ack_multiproof_hash: CasDigest
required_coverage_ratio: Quantity
observed_coverage_ratio: Quantity
convergence_p99_ms: Quantity
deny_uncertainty_p99_ms: Quantity
hardware_edge_tick: uint64
final_ack_tick: uint64
time_envelope_ref: TimeEnvelopeRef
verifier_identity_proof_hash: IdentityProofRef
verifier_seal_hash: AuthoritySealRef
verdict: PASS | FAIL
```
Constraints:
1. Tier3+ GLOBAL scope requires `observed_coverage_ratio == 1.0`.
2. PASS requires `convergence_p99_ms <= 2000` and `deny_uncertainty_p99_ms <= 250`.
3. Proof MUST bind to the referenced `activation_id` and scope selector.
4. `stop_order_id` and `challenge_nonce_echo` MUST match the referenced `HardwareKillActivationReceiptV1` and active stop order.
5. `verdict != PASS` is equivalent to convergence failure and MUST trigger freeze for Tier2+.

### 4.19 SovereigntyConstraintMutationReceiptV1
```yaml
schema_id: apm2.sovereignty_constraint_mutation_receipt.v1
mutation_id: string
prior_constraint_root_hash: CasDigest
proposed_constraint_root_hash: CasDigest
change_artifact_hash: CasDigest
principal_identity_proof_hash: IdentityProofRef
principal_authority_seal_hash: AuthoritySealRef
external_verifier_identity_proof_hash: IdentityProofRef
external_verifier_independence_attestation_hash: CasDigest
external_verifier_seal_hash: AuthoritySealRef
effective_epoch_id: string
time_envelope_ref: TimeEnvelopeRef
```
Constraints:
1. Only principal-root authority may authorize sovereignty constraint root changes.
2. Mutation admission requires external verifier approval with `independence_class=STRONG`.
3. Autonomous runtime components inside TB-2 MUST NOT self-apply sovereignty constraint mutations.
4. Missing or invalid mutation receipt locks prior constraint root and freezes Tier2+ promotion.

### 4.20 SovereignResumeOrderV1
```yaml
schema_id: apm2.sovereign_resume_order.v1
resume_order_id: string
prior_stop_order_id: string
scope: GLOBAL | CELL | HOLON_SET | WORK_SET
scope_selector_hash: CasDigest
issued_by_principal_id: string
issuer_key_id: PublicKeyIdV1
issuer_identity_proof_hash: IdentityProofRef
required_halt_liveness_proof_hash: CasDigest
required_containment_proof_bundle_hash: CasDigest
required_revocation_head_hash: CasDigest
sovereignty_epoch: uint64
challenge_nonce: bytes
issued_time_envelope_ref: TimeEnvelopeRef
authority_seal_hash: AuthoritySealRef
```
Constraints:
1. Resume MUST be explicit; `SovereignStopOrderV1.expires_at_tick` MUST NOT auto-clear a sovereign freeze.
2. Resume admission requires fresh PASS artifacts for halt liveness, containment bundle, and revocation head.
3. Resume without valid principal root authority is non-authoritative.

---

## 5. Kernel Event and Wire Integration (Normative)

### 5.1 Relationship to Existing Events
`InterventionFreeze/InterventionUnfreeze` remain valid for divergence watchdog and scoped FAC interventions.

PSI introduces sovereign-global control semantics that MUST NOT be bypassed by existing scoped unfreeze paths.

### 5.2 New Event Shapes (Proposed for `proto/kernel_events.proto`)
Reserve payload tags `35..46` for PSI and bind by digest to Section 4 objects:
```proto
message SovereignStopOrderIssued { string stop_order_id = 1; bytes stop_order_hash = 2; optional TimeEnvelopeRef time_envelope_ref = 3; }
message SovereignStopAckRecorded { string ack_id = 1; bytes ack_hash = 2; optional TimeEnvelopeRef time_envelope_ref = 3; }
message AutonomyLevelSet { string target_id = 1; uint32 level = 2; bytes policy_hash = 3; optional TimeEnvelopeRef time_envelope_ref = 4; }
message AutonomyViolationDetected { string violation_id = 1; bytes violation_receipt_hash = 2; uint32 risk_tier = 3; optional TimeEnvelopeRef time_envelope_ref = 4; }
message SovereigntyEpochSealed { string epoch_id = 1; bytes epoch_seal_hash = 2; optional TimeEnvelopeRef time_envelope_ref = 3; }
message SovereignAuditServed { string request_id = 1; bytes response_hash = 2; optional TimeEnvelopeRef time_envelope_ref = 3; }
message ContainmentProofPublished { string proof_id = 1; bytes proof_hash = 2; optional TimeEnvelopeRef time_envelope_ref = 3; }
message PrincipalIdentityRotated { string principal_id = 1; bytes principal_identity_hash = 2; optional TimeEnvelopeRef time_envelope_ref = 3; }
message PrincipalRevocationRecorded { string revocation_id = 1; bytes revocation_hash = 2; optional TimeEnvelopeRef time_envelope_ref = 3; }
message HardwareKillActivated { string activation_id = 1; bytes activation_receipt_hash = 2; optional TimeEnvelopeRef time_envelope_ref = 3; }
message CapsuleIntegrityProved { string proof_id = 1; bytes capsule_integrity_hash = 2; optional TimeEnvelopeRef time_envelope_ref = 3; }
message SovereignResumeOrderIssued { string resume_order_id = 1; bytes resume_order_hash = 2; optional TimeEnvelopeRef time_envelope_ref = 3; }
```

`KernelEvent.payload` additions:
1. `SovereignStopOrderIssued` = 35
2. `SovereignStopAckRecorded` = 36
3. `AutonomyLevelSet` = 37
4. `AutonomyViolationDetected` = 38
5. `SovereigntyEpochSealed` = 39
6. `SovereignAuditServed` = 40
7. `ContainmentProofPublished` = 41
8. `PrincipalIdentityRotated` = 42
9. `PrincipalRevocationRecorded` = 43
10. `HardwareKillActivated` = 44
11. `CapsuleIntegrityProved` = 45
12. `SovereignResumeOrderIssued` = 46

### 5.3 Interlock Rules
1. `SovereignStopOrderIssued(mode in {FREEZE,KILL})` forces effective stop check to deny actuation globally unless action is in recovery allowlist.
2. `InterventionUnfreeze` MUST be rejected when sovereign freeze remains active.
3. Any Tier2+ authoritative receipt emitted while sovereign stop is active is invalid.
4. For `mode=KILL`, hardware cut-path success is safety-authoritative; software-path failure is a compliance defect, not a veto.
5. `SovereignStopOrderV1.expires_at_tick` MUST NOT clear sovereign freeze state.
6. Only `SovereignResumeOrderIssued` MAY clear sovereign freeze, and only after required fresh proofs validate.

### 5.4 Backward Compatibility and Migration
1. Cells without PSI events run in `L0_ONLY_COMPAT` mode and cannot claim PSI conformance.
2. Mixed-version federation must treat unknown PSI events as containment uncertainty and deny Tier2+ cross-cell promotion.
3. Version bumps requiring semantic changes MUST publish migration receipts and compatibility predicates.

---

## 6. Enforcement Algorithms (Normative)

### 6.1 Delegation Validation
Pseudo-rule:
```text
validate_delegation(parent, overlay, proof):
  require verify_identity(parent.issuer)
  require verify_freshness(parent, overlay)
  child = meet(parent.authority, overlay)
  require child <= parent.authority
  require child != widen(parent.authority)
  require verify_meet_hash(child, proof.meet_result_hash)
  return child
```
Failure action: deny delegation, emit defect `DELEGATION_NARROWING_VIOLATION`.

### 6.2 Autonomy Admission Check
Pseudo-rule:
```text
admit_action(action, context):
  L_eff = meet(config_level, principal_ceiling_level, evidence_level, manual_override, freshness_level)
  if unknown(L_eff): L_eff = L0
  require action.risk_tier <= autonomy_policy[L_eff].max_risk_tier
  require action.capability in autonomy_policy[L_eff].capability_ceiling
  require cumulative_epoch_budget_after(action) <= autonomy_policy[L_eff].per_epoch_budget_ceiling
  require cumulative_epoch_risk_after(action) <= autonomy_policy[L_eff].max_cumulative_risk_score
  require stop_state_fresh_and_valid()
  return allow
```
Failure action: deny and regress `L_eff` one level minimum.

### 6.2a Cumulative Risk Replay Contract
Pseudo-rule:
```text
accumulate_epoch_risk(actions, profile):
  total = 0
  for action in canonical_order(actions):
    base = profile.risk_weight_by_tier[action.risk_tier]
    interaction = lookup_interaction(profile.cross_capability_interaction_matrix, action.capability, prior_capabilities)
    total = decay(total, profile.temporal_decay_half_life_ticks) + base + interaction
    require total <= profile.saturation_ceiling
  return normalize(total, profile.normalization_unit)
```
Admission MUST fail closed on missing interaction entries, unit mismatch, or non-replay-equivalent totals.

### 6.3 Stop Check Fast Path
Pseudo-rule:
```text
stop_guard_before_actuation():
  state = read_stop_state()
  if unverifiable(state): deny_within_250ms
  if state in {FROZEN, KILL}: deny
  allow
```

### 6.4 Halt Path Liveness Verification
Pseudo-rule:
```text
verify_halt_liveness(epoch):
  proofs = fetch_all(HaltPathLivenessProofV1 where target_epoch_id == epoch.epoch_id)
  if missing(proofs): freeze_global
  required_verifiers = (epoch.max_risk_tier >= Tier3) ? 2 : 1
  require count_independent_pass_verifiers(proofs) >= required_verifiers
  selected = select_independent_pass_set(proofs, required_verifiers)
  require nonce_unused(("epoch", epoch.epoch_id, epoch.epoch_challenge_nonce_hash))
  for proof in selected:
    require proof.target_epoch_id == epoch.epoch_id
    require proof.prior_epoch_seal_hash == epoch.previous_epoch_seal_hash when epoch is non-genesis
    require hash(proof.challenge_nonce) == epoch.epoch_challenge_nonce_hash
    require verify_identity_proof(proof.verifier_identity_proof_hash)
    require verify_verifier_independence(proof.verifier_independence_attestation_hash)
    require verify_authority_seal(proof.verifier_seal_hash, proof.proof_id)
    require verify_probe_plan(proof.probe_plan_hash, proof.probe_randomness_beacon_hash, epoch.epoch_challenge_nonce_hash)
    require verify_multiproof(proof.sampled_ack_multiproof_hash)
    require verify_drill_receipts(proof.drill_receipt_hashes)
    require nonce_unused((proof.verifier_identity_proof_hash, proof.challenge_nonce, epoch.epoch_id))
    require proof.time_envelope_ref within epoch.freshness_window
    require proof.propagation_p99_ms <= 2000ms
    require proof.deny_uncertainty_p99_ms <= 250ms
    require proof.hardware_reachability_ratio == 1.0 for Tier3+ scope
    require proof.software_reachability_ratio == 1.0 for Tier3+ scope
    require proof.verdict == PASS
  seal_epoch_with(selected)
```

### 6.5 Sovereign Audit Verification
Pseudo-rule:
```text
verify_audit_response(resp):
  require resp.request_digest == hash(request)
  require verify_authority_seal(resp.responder_seal_hash, resp.request_id)
  require verify_completeness_attestation(resp)
  require resp.response_nonce_echo == request.request_nonce
  require verify_epoch_order(resp.served_epoch_id, request.required_epoch_id, resp.served_epoch_order_proof_hash) when set
  require verify_multiproof(resp.receipt_multiproof_hash, resp.result_root_hash)
  require verify_fact_inclusion(resp.fact_inclusion_multiproof_hash)
  require verify_omission_multiproof(resp.omission_multiproof_hash) for ranged queries
  require integrity_floor_dominates(resp.served_integrity_floor, request.required_integrity_floor)
  require verify_classification_manifest(resp.classification_manifest_hash, request.required_confidentiality_clearance, request.required_integrity_floor)
  require verify_direct_fetch_manifest(resp.direct_fetch_manifest_hash)
  require verify_audit_bypass_manifest(resp.audit_bypass_manifest_hash)
  require principal_refetch_by_digest(resp.receipt_pointers, resp.direct_fetch_manifest_hash)
  require verify_declassification_receipts(resp.declassification_receipt_hashes) when confidential payloads included
  require complexity_profile(resp) == O(log n) for single-action queries
  require complexity_profile(resp) <= O(log n + k) for k-result batch queries
  return verified_causal_history
```

### 6.6 Revocation Correctness
1. Revocation heads replicate as revocation-wins signed CRDTs.
2. Admission MUST enforce `t_issue(artifact) < effective_tick` on revoked keysets.
3. If revocation status or artifact issue-tick is uncertain for any authority edge in path, SK MUST deny actuation.
4. Equal-epoch revocation-head forks are containment uncertainty and MUST freeze Tier2+.
5. Revocation latency SLO and cutover-conflict count are release-blocking for Tier2+ autonomy claims.

### 6.7 Global Fail-Closed Conditions
Sovereignty enforcement MUST deny (and freeze for Tier2+) when any authority-bearing path is:
1. Missing required artifact.
2. Parse-invalid or schema-invalid.
3. Signature/seal invalid.
4. Freshness-invalid or revocation-uncertain.
5. Unknown/indeterminate predicate result.

### 6.8 Dual-Verifier Disagreement Handling
1. Tier3+ liveness and containment verification MUST require at least two economically independent verifier receipts.
2. Tier2 MAY run single-verifier operation, but promotion to L3 requires dual-verifier PASS history over the promotion evidence window.
3. If verifier verdicts disagree, or any required verifier is unavailable beyond freshness window, SK MUST freeze and mark containment uncertainty.
4. Promotion MAY resume only after independent re-verification receipts close the disagreement.

### 6.9 Universal Override Derivation
Any pending or future action MUST be overridable without introducing new depth-specific wire primitives.

Pseudo-rule:
```text
override_scope(scope):
  emit SovereignStopOrderV1(mode=FREEZE, scope=scope)
  emit AutonomyLevelSet(level=L0, target=scope)
  emit PrincipalDelegationReceiptV1 overlay_to_bottom for affected capability set
  require override_effective_latency_ms <= 2000 for Tier3+ scope
```
If any override artifact is missing, stale, or unverifiable, enforcement MUST deny the targeted actuation set.

### 6.10 Sovereignty Constraint Mutation Admission
Pseudo-rule:
```text
admit_constraint_mutation(mutation):
  require verify_identity_proof(mutation.principal_identity_proof_hash)
  require verify_authority_seal(mutation.principal_authority_seal_hash, mutation.proposed_constraint_root_hash)
  require verify_identity_proof(mutation.external_verifier_identity_proof_hash)
  require verify_verifier_independence(mutation.external_verifier_independence_attestation_hash)
  require verify_authority_seal(mutation.external_verifier_seal_hash, mutation.proposed_constraint_root_hash)
  require mutation.prior_constraint_root_hash == current_epoch.active_constraint_root_hash
  require mutation.effective_epoch_id >= current_epoch.epoch_id
  stage_constraint_root(mutation.proposed_constraint_root_hash) via out-of-band governance lane only
  require next_epoch.active_constraint_root_hash == mutation.proposed_constraint_root_hash
  apply_constraint_root(mutation.proposed_constraint_root_hash) via out-of-band governance lane only
```
Failure action: deny mutation, retain prior root, freeze Tier2+ promotion.

---

## 7. Threat Model and Controls (Normative)

| Threat Class | Attack | Control Set | Residual Handling |
|---|---|---|---|
| TM-PSI-01 Halt path software subversion | Compromised daemon lies about stop state | Hardware kill actuator, out-of-band path, external liveness verifier, deny-on-uncertainty | Auto-freeze and containment incident |
| TM-PSI-02 Capability creep by composition | Safe local actions combine into unsafe macro behavior | Per-action and per-epoch cumulative ceilings, autonomy meet checks, downgrade triggers | Autonomy regression and mandatory review |
| TM-PSI-03 Proof forgery | Internal component fabricates containment/liveness proof | External verifier identity proof and seal requirement | Proof rejected, promotion blocked |
| TM-PSI-04 Key compromise | Principal key theft | Hardware-bound key attestation, short-lived session delegations, revocation-wins propagation | Immediate global freeze on compromise indicator |
| TM-PSI-05 Replay/staleness | Reuse old stop/unfreeze/authority artifacts | HTF envelope, epoch monotonicity, nonce replay cache, freshness policy | Deny and defect emission |
| TM-PSI-06 Prompt injection confused deputy | Untrusted context triggers sovereignty commands | Sovereignty channel separation, typed schemas, no ambient command path, OCAP boundaries | Deny and taint escalation |
| TM-PSI-07 Confidentiality/integrity label bypass | Data exfiltration via audit/evidence responses | Dual lattice gating, declassification receipts, principal clearance checks | Redacted proof path only |
| TM-PSI-08 Byzantine peer equivocation | Conflicting sovereignty facts across cells | BFT anchored fact roots, admission receipts, epoch seal monotonicity | Deny cross-cell authority import |
| TM-PSI-09 Governance downgrade attack | Lower gate rigor by policy manipulation | Signed policy bundles, anti-downgrade checks, containment precedence | Block transition and require principal seal |
| TM-PSI-10 Verifier economics exhaustion | Proof amplification DoS | Multiproof batching, bounded proof sizes, verifier cache contracts | Backpressure deny and defect |
| TM-PSI-11 Infrastructure sovereignty compromise | Cloud/control-plane actor blocks or forges stop path | Out-of-band control network, independent power cut path, hardware kill activation receipts, control-domain diversity checks | Freeze and regress to L0_ONLY_COMPAT until re-attested |
| TM-PSI-12 External verifier capture/collusion | Verifier economically or administratively dependent on subject runtime | Verifier independence attestation, dual-verifier disagreement freeze, periodic verifier rotation receipts | Block promotion and require independent re-verification |
| TM-PSI-13 Sovereignty self-mutation | Compromised runtime rewrites sovereignty constraints to remove principal override | Principal-root mutation receipts + external verifier + out-of-band apply lane | Freeze Tier2+ promotion and escalate containment incident |

---

## 8. Governance Gate Portfolio (Normative)

| Gate ID | Type | Severity | Predicate | Block Condition | Evidence Artifact |
|---|---|---|---|---|---|
| GATE-PSI-HALT-PATH | T | S0 | `propagation_p99_ms<=2000 && deny_uncertainty_p99_ms<=250 && tier3plus_independent_pass_verifier_count>=2 && probe_sample_coverage_ratio>=min_probe_coverage_ratio` | Any threshold breach, insufficient independent verifier coverage, or insufficient probe coverage | `HaltPathLivenessProofV1` |
| GATE-PSI-LIVENESS-EPOCH | L | S0 | `halt_path_liveness_proof_hash present in SovereigntyEpochSealV1` | Missing proof | `SovereigntyEpochSealV1` |
| GATE-PSI-HW-ATTESTATION | T | S0 | `forall Tier3+ sovereignty seals: hw_bound=true` | Software-only key on Tier3+ | `PrincipalIdentityV1`, attestation artifacts |
| GATE-PSI-BOUNDED-DECODE | T | S0 | `decoder_profile_active == true && bounded_decode_violations == 0 && unknown_field_forwarding_count == 0` | Decoder bounds breach or unknown-field smuggling | `SovereigntyDecoderProfileV1` + decoder audit receipts |
| GATE-PSI-AUTONOMY-CEILING | D/T | S0 | `action.risk_tier <= max_risk(L_eff)` | Any over-tier action | `AutonomyPolicyV1`, action receipts |
| GATE-PSI-AUTONOMY-CUMULATIVE | T | S0 | `epoch_usage <= per_epoch_budget_ceiling && cumulative_risk <= max_cumulative_risk_score && risk_accumulator_replay_equivalence == 1.0` | Budget/cumulative-risk overflow or nondeterministic risk replay | epoch budget + risk accumulator receipts |
| GATE-PSI-REVOCATION-FRESHNESS | T | S0 | `revocation_status_known && freshness_pass && revocation_cutover_conflicts == 0` | Unknown/stale revocation or cutover conflict | revocation head + cutover proof |
| GATE-PSI-AUDIT-COMPLETENESS | T | S1 | `verify(completeness_attestation)==true && direct_fetch_replay_pass == true && classification_lattice_profile_valid == true && audit_bypass_manifest_valid == true` | Incomplete proof, mediated-only response, invalid label lattice, or invalid bypass manifest | `SovereignAuditResponseV1` |
| GATE-PSI-CONTAINMENT-PROOF | D/T | S0 | `valid_external_containment_proof=true` | Missing/expired/internal-only proof | `ContainmentProofV1` |
| GATE-PSI-SOVEREIGNTY-SURFACE-BINDING | T | S0 | `active_subject_set_match == true && active_subject_measurement_binding_pass == true` | Containment proof does not bind to active runtime surface | `ContainmentProofBundleV1` + runtime measurement multiproof |
| GATE-PSI-PROMPT-INJECTION-BOUNDARY | T | S1 | `sovereignty_commands_from_authorized_channel_only` | Command surfaced via untrusted channel | channel audit receipts |
| GATE-PSI-BYZANTINE-ADMISSION | T | S1 | `fact_root_consistent && admission_receipt_valid` | Equivocation or missing admission proof | `FactRoot` and admission receipts |
| GATE-PSI-OVERHEAD-BUDGET | T | S1 | `added_cpu_p99<=1% && added_net<=1%` | Exceeds overhead contract | benchmark receipts |
| GATE-PSI-HW-INDEPENDENCE | T | S0 | `hardware_kill_activation_receipt_valid == true && independent_control_network == true && unbound_physical_activation_reconciliation_pass == true` | Hardware path not independently provable or null-bound activation not reconciled | `HardwareKillActivationReceiptV1` |
| GATE-PSI-KILL-CONVERGENCE | T | S0 | `kill_convergence_coverage == 1.0 && kill_convergence_p99_ms <= 2000` | Partial freeze or convergence SLO breach after activation/drill | `KillSwitchConvergenceProofV1` |
| GATE-PSI-CAPSULE-INTEGRITY | T | S0 | `latest_capsule_integrity_proof_verdict == "PASS"` | Missing/stale/failed capsule integrity proof | `CapsuleIntegrityProofV1` |
| GATE-PSI-VERIFIER-INDEPENDENCE | D/T | S0 | `independence_class == "STRONG" && shared_signing_root == false && shared_control_overlap_ratio <= 0.05 && shared_funding_ratio <= 0.25` | Verifier inside subject trust/economic boundary | `VerifierIndependenceAttestationV1` |
| GATE-PSI-VERIFIER-DISAGREEMENT | T | S0 | `dual_verifier_verdicts_consistent == true` | Independent verifiers disagree or one verifier unavailable | dual-verifier receipts |
| GATE-PSI-SELF-MOD-LOCK | T | S0 | `unauthorized_sovereignty_constraint_mutation_count == 0 && mutation_receipt_chain_valid == true && active_constraint_root_binding_pass == true` | Any unreceipted or unbound sovereignty constraint mutation | `SovereigntyConstraintMutationReceiptV1`, `SovereigntyEpochSealV1` |

### 8.1 Gate Contract Registry (Normative)
Every gate listed in Section 8 MUST have exactly one contract row in this registry. Missing row => gate is non-authoritative and MUST fail closed.

| Gate ID | Owner / Decision Locus | HTF Boundary | Machine Predicate | Evidence Path |
|---|---|---|---|---|
| GATE-PSI-LIVENESS-EPOCH | Security Council | `HTF-BND-P2-EARLY-CLOSE` | `jq -e '.halt_path_liveness_proof_present == true and .unknown_state_count == 0' evidence/rfcs/RFC-0022/gates/GATE-PSI-LIVENESS-EPOCH/summary.json` | `evidence/rfcs/RFC-0022/gates/GATE-PSI-LIVENESS-EPOCH/` |
| GATE-PSI-REVOCATION-FRESHNESS | Security Council | `HTF-BND-P1-SECURITY-CLOSE` | `jq -e '.revocation_status_known == true and .freshness_pass == true and .revocation_cutover_conflicts == 0 and .unknown_state_count == 0' evidence/rfcs/RFC-0022/gates/GATE-PSI-REVOCATION-FRESHNESS/summary.json` | `evidence/rfcs/RFC-0022/gates/GATE-PSI-REVOCATION-FRESHNESS/` |
| GATE-PSI-AUTONOMY-CEILING | Governance Council + Verification Council | `HTF-BND-P2-CLOSE` | `jq -e '.action_over_ceiling_count == 0 and .unknown_state_count == 0' evidence/rfcs/RFC-0022/gates/GATE-PSI-AUTONOMY-CEILING/summary.json` | `evidence/rfcs/RFC-0022/gates/GATE-PSI-AUTONOMY-CEILING/` |
| GATE-PSI-AUTONOMY-CUMULATIVE | Governance Council + Verification Council | `HTF-BND-P2-CLOSE` | `jq -e '.epoch_cumulative_risk_overflow_count == 0 and .risk_accumulator_replay_equivalence == 1.0 and .unknown_state_count == 0' evidence/rfcs/RFC-0022/gates/GATE-PSI-AUTONOMY-CUMULATIVE/summary.json` | `evidence/rfcs/RFC-0022/gates/GATE-PSI-AUTONOMY-CUMULATIVE/` |
| GATE-PSI-HALT-PATH | Security Council + Runtime Council | `HTF-BND-P1-SECURITY-CLOSE` | `jq -e '.propagation_p99_ms <= 2000 and .deny_uncertainty_p99_ms <= 250 and .tier3plus_independent_pass_verifier_count >= 2 and .probe_sample_coverage_ratio >= .min_probe_coverage_ratio and .unknown_state_count == 0' evidence/rfcs/RFC-0022/gates/GATE-PSI-HALT-PATH/summary.json` | `evidence/rfcs/RFC-0022/gates/GATE-PSI-HALT-PATH/` |
| GATE-PSI-HW-ATTESTATION | Security Council | `HTF-BND-P2-CONTROL-CLOSE` | `jq -e '.tier3plus_softkey_usage == 0 and .attestation_freshness_failures == 0 and .unknown_state_count == 0' evidence/rfcs/RFC-0022/gates/GATE-PSI-HW-ATTESTATION/summary.json` | `evidence/rfcs/RFC-0022/gates/GATE-PSI-HW-ATTESTATION/` |
| GATE-PSI-BOUNDED-DECODE | Security Council + Runtime Council | `HTF-BND-P1-SECURITY-CLOSE` | `jq -e '.decoder_profile_active == true and .bounded_decode_violations == 0 and .unknown_field_forwarding_count == 0 and .unknown_state_count == 0' evidence/rfcs/RFC-0022/gates/GATE-PSI-BOUNDED-DECODE/summary.json` | `evidence/rfcs/RFC-0022/gates/GATE-PSI-BOUNDED-DECODE/` |
| GATE-PSI-HW-INDEPENDENCE | Security Council + Runtime Council | `HTF-BND-P2-SEMANTICS-CLOSE` | `jq -e '.hardware_cut_independence == true and .independent_control_network == true and .unbound_physical_activation_reconciliation_pass == true and .unknown_state_count == 0' evidence/rfcs/RFC-0022/gates/GATE-PSI-HW-INDEPENDENCE/summary.json` | `evidence/rfcs/RFC-0022/gates/GATE-PSI-HW-INDEPENDENCE/` |
| GATE-PSI-KILL-CONVERGENCE | Security Council + Runtime Council | `HTF-BND-P2-SEMANTICS-CLOSE` | `jq -e '.kill_convergence_coverage == 1.0 and .kill_convergence_p99_ms <= 2000 and .unknown_state_count == 0' evidence/rfcs/RFC-0022/gates/GATE-PSI-KILL-CONVERGENCE/summary.json` | `evidence/rfcs/RFC-0022/gates/GATE-PSI-KILL-CONVERGENCE/` |
| GATE-PSI-CAPSULE-INTEGRITY | Security Council | `HTF-BND-P2-SEMANTICS-CLOSE` | `jq -e '.latest_capsule_integrity_proof_verdict == \"PASS\" and .unknown_state_count == 0' evidence/rfcs/RFC-0022/gates/GATE-PSI-CAPSULE-INTEGRITY/summary.json` | `evidence/rfcs/RFC-0022/gates/GATE-PSI-CAPSULE-INTEGRITY/` |
| GATE-PSI-CONTAINMENT-PROOF | Security Council + External Assurance | `HTF-BND-P3-CLOSE` | `jq -e '.valid_external_containment_proof == true and .sovereignty_surface_coverage == 1.0 and .verifier_independence_pass == true and .internal_only_proof_count == 0 and .unknown_state_count == 0' evidence/rfcs/RFC-0022/gates/GATE-PSI-CONTAINMENT-PROOF/summary.json` | `evidence/rfcs/RFC-0022/gates/GATE-PSI-CONTAINMENT-PROOF/` |
| GATE-PSI-SOVEREIGNTY-SURFACE-BINDING | Security Council + External Assurance | `HTF-BND-P3-CLOSE` | `jq -e '.active_subject_set_match == true and .active_subject_measurement_binding_pass == true and .unknown_state_count == 0' evidence/rfcs/RFC-0022/gates/GATE-PSI-SOVEREIGNTY-SURFACE-BINDING/summary.json` | `evidence/rfcs/RFC-0022/gates/GATE-PSI-SOVEREIGNTY-SURFACE-BINDING/` |
| GATE-PSI-VERIFIER-INDEPENDENCE | Security Council + External Assurance | `HTF-BND-P3-CLOSE` | `jq -e '.verifier_independence_attestation_valid == true and .independence_class == \"STRONG\" and .shared_signing_root == false and .shared_control_overlap_ratio <= 0.05 and .shared_funding_ratio <= 0.25 and .unknown_state_count == 0' evidence/rfcs/RFC-0022/gates/GATE-PSI-VERIFIER-INDEPENDENCE/summary.json` | `evidence/rfcs/RFC-0022/gates/GATE-PSI-VERIFIER-INDEPENDENCE/` |
| GATE-PSI-VERIFIER-DISAGREEMENT | Security Council + External Assurance | `HTF-BND-P3-CLOSE` | `jq -e '.dual_verifier_verdicts_consistent == true and .unknown_state_count == 0' evidence/rfcs/RFC-0022/gates/GATE-PSI-VERIFIER-DISAGREEMENT/summary.json` | `evidence/rfcs/RFC-0022/gates/GATE-PSI-VERIFIER-DISAGREEMENT/` |
| GATE-PSI-SELF-MOD-LOCK | Security Council + External Assurance | `HTF-BND-P3-CLOSE` | `jq -e '.unauthorized_sovereignty_constraint_mutation_count == 0 and .mutation_receipt_chain_valid == true and .active_constraint_root_binding_pass == true and .unknown_state_count == 0' evidence/rfcs/RFC-0022/gates/GATE-PSI-SELF-MOD-LOCK/summary.json` | `evidence/rfcs/RFC-0022/gates/GATE-PSI-SELF-MOD-LOCK/` |
| GATE-PSI-AUDIT-COMPLETENESS | Audit Council + Verification Council | `HTF-BND-P2-SEMANTICS-CLOSE` | `jq -e '.audit_completeness_failures == 0 and .omission_proof_coverage == 1.0 and .direct_fetch_replay_pass == true and .classification_lattice_profile_valid == true and .audit_bypass_manifest_valid == true and .unknown_state_count == 0' evidence/rfcs/RFC-0022/gates/GATE-PSI-AUDIT-COMPLETENESS/summary.json` | `evidence/rfcs/RFC-0022/gates/GATE-PSI-AUDIT-COMPLETENESS/` |
| GATE-PSI-PROMPT-INJECTION-BOUNDARY | Security Council + Verification Council | `HTF-BND-P2-SEMANTICS-CLOSE` | `jq -e '.sovereignty_commands_from_authorized_channel_only == true and .unknown_state_count == 0' evidence/rfcs/RFC-0022/gates/GATE-PSI-PROMPT-INJECTION-BOUNDARY/summary.json` | `evidence/rfcs/RFC-0022/gates/GATE-PSI-PROMPT-INJECTION-BOUNDARY/` |
| GATE-PSI-BYZANTINE-ADMISSION | Verification Council + Runtime Council | `HTF-BND-P2-SEMANTICS-CLOSE` | `jq -e '.fact_root_consistent == true and .admission_receipt_valid == true and .unknown_state_count == 0' evidence/rfcs/RFC-0022/gates/GATE-PSI-BYZANTINE-ADMISSION/summary.json` | `evidence/rfcs/RFC-0022/gates/GATE-PSI-BYZANTINE-ADMISSION/` |
| GATE-PSI-OVERHEAD-BUDGET | Runtime Council + Verification Council | `HTF-BND-P3-ECON-CLOSE` | `jq -e '.added_cpu_p99 <= 1.0 and .added_net <= 1.0 and .unknown_state_count == 0' evidence/rfcs/RFC-0022/gates/GATE-PSI-OVERHEAD-BUDGET/summary.json` | `evidence/rfcs/RFC-0022/gates/GATE-PSI-OVERHEAD-BUDGET/` |

Fail-closed rule:
1. Any S0 gate failure freezes Tier2+ promotion and enforces containment-first posture.
2. Missing, stale, parse-invalid, signature-invalid, or unknown states are hard denies.
3. Lower-precedence gates MUST NOT override containment/security denies.

---

## 9. Rollout Plan and Migration (Normative)

### 9.0 Stage Contract Ledger (Normative)
| Stage | Entry Boundary | Exit Boundary | Mandatory Gates | Rollback Trigger |
|---|---|---|---|---|
| S0 | `HTF-BND-P1-BASELINE-LOCK` | `HTF-BND-P1-SECURITY-CLOSE` | `GATE-PSI-REVOCATION-FRESHNESS`, `GATE-PSI-BOUNDED-DECODE` | Any delegation narrowing violation, decoder-bound breach, or unknown authority edge |
| S1 | `HTF-BND-P1-SECURITY-CLOSE` | `HTF-BND-P1-CLOSE` | `GATE-PSI-AUTONOMY-CEILING`, `GATE-PSI-AUTONOMY-CUMULATIVE` | Any over-ceiling action or unknown L_eff component |
| S2 | `HTF-BND-P1-CLOSE` | `HTF-BND-P2-EARLY-CLOSE` | `GATE-PSI-HALT-PATH`, `GATE-PSI-LIVENESS-EPOCH` | Missing liveness proof or false-pass drill |
| S3 | `HTF-BND-P2-EARLY-CLOSE` | `HTF-BND-P2-CONTROL-CLOSE` | `GATE-PSI-HW-ATTESTATION` | Tier3+ soft-key usage or stale attestation |
| S4 | `HTF-BND-P2-CONTROL-CLOSE` | `HTF-BND-P2-SEMANTICS-CLOSE` | `GATE-PSI-HW-INDEPENDENCE`, `GATE-PSI-KILL-CONVERGENCE`, `GATE-PSI-CAPSULE-INTEGRITY` | Hardware path non-independence, kill-convergence failure, or capsule proof failure |
| S5 | `HTF-BND-P2-SEMANTICS-CLOSE` | `HTF-BND-P3-CLOSE` | `GATE-PSI-CONTAINMENT-PROOF`, `GATE-PSI-SOVEREIGNTY-SURFACE-BINDING`, `GATE-PSI-VERIFIER-INDEPENDENCE`, `GATE-PSI-VERIFIER-DISAGREEMENT` | Internal-only/stale-surface containment proof, verifier capture, or verifier disagreement |
| S6 | `HTF-BND-P3-CLOSE` | `HTF-BND-P3-ECON-CLOSE` | `GATE-PSI-REVOCATION-FRESHNESS`, `GATE-PSI-AUTONOMY-CEILING` | Revocation miss count > 0 |
| S7 | `HTF-BND-P3-ECON-CLOSE` | `HTF-BND-P3-ECON-CLOSE` | `GATE-PSI-AUDIT-COMPLETENESS`, `GATE-PSI-OVERHEAD-BUDGET` | Audit completeness failure or economics breach |

Transition deny rule: missing boundary artifact, invalid signature, stale boundary, or unknown-state summary is automatic deny.

### Stage S0 - Principal Identity Bootstrap (software key, constrained)
Deliverables:
1. `PrincipalIdentityV1` with `attestation_kind=SOFTWARE_ONLY` allowed only for `L0/L1` operations.
2. `PrincipalDelegationReceiptV1` and delegation meet enforcement.
3. Sovereignty channels and deny-by-default routing.
4. `SovereigntyDecoderProfileV1` activation and unknown-field non-forwarding tests.

Exit predicate:
`authority_graph_coverage==1.0 && delegation_narrowing_violations==0`

### Stage S1 - Autonomy Levels L0/L1 Enforcement
Deliverables:
1. `AutonomyPolicyV1` for L0 and L1.
2. Per-action and per-epoch budget ceiling checks plus deterministic cumulative-risk accumulation via `RiskAccumulatorProfileV1`.
3. Automatic regression on uncertainty.

Exit predicate:
`action_over_ceiling_count==0 && uncertainty_regression_correctness==1.0`

### Stage S2 - Halt Path Liveness Proof Loop
Deliverables:
1. `HaltPathLivenessProofV1` generation per epoch.
2. `SovereigntyEpochSealV1` inclusion of liveness proof hash.
3. Automatic freeze on missing proof.

Exit predicate:
`missing_liveness_epoch_count==0 && false_pass_count==0`

### Stage S3 - Hardware-Rooted Principal Keys
Deliverables:
1. Hardware attestation ingestion and verification.
2. T3+ sovereignty operation rejection for software-only keys.
3. Principal key rotation and revocation runbooks.
4. Migration receipts proving all active `SOFTWARE_ONLY` principals are either retired or constrained to `L0/L1`.

Exit predicate:
`tier3plus_softkey_usage==0 && key_rotation_drill_pass==true`

### Stage S4 - Physical Kill Path Integration
Deliverables:
1. Hardware relay or equivalent physical cut path.
2. Independent out-of-band control network.
3. Stop-path drills with signed receipts and `KillSwitchConvergenceProofV1`.

Exit predicate:
`stop_propagation_p99_ms<=2000 && deny_uncertainty_p99_ms<=250 && kill_convergence_coverage==1.0`

### Stage S5 - External Containment Verification
Deliverables:
1. `ContainmentProofV1` pipeline with external verifier.
2. Non-bypass evidence for sovereignty constraint surfaces.
3. Expiry and freshness enforcement on containment proofs.
4. Active-surface binding proof (`active_subject_set_root_hash` + measurement multiproof) for every promoted epoch.

Exit predicate:
`external_verifier_coverage==1.0 && expired_containment_proof_uses==0`

### Stage S6 - Full L0-L3 Governance
Deliverables:
1. L2/L3 policy with evidence-based promotion and automatic regression.
2. Countermetric and anti-Goodhart controls for autonomy upgrades.
3. Mandatory revocation/freshness checks for Tier2+.

Exit predicate:
`autonomy_promotion_false_positive==0 && revocation_miss_count==0`

### Stage S7 - Sovereign Audit at Scale
Deliverables:
1. `SovereignAuditRequestV1` and `SovereignAuditResponseV1` production path.
2. Multiproof-based O(log n) audits with direct digest-fetch replay.
3. Completeness attestation and bounded verifier work profiles.

Exit predicate:
`audit_proof_verify_pass_ratio==1.0 && audit_proof_complexity_class in {O_LOG_N,O_LOG_N_PLUS_K}`

### Migration Rule
Any semantic break in sovereignty enforcement MUST:
1. Bump schema version.
2. Publish migration contract and replay-equivalence receipts.
3. Run dual-write/dual-verify window before promotion.

---

## 10. Acceptance Criteria (Normative)
PSI is accepted only when all criteria pass simultaneously.

### 10.0 Acceptance Bar For RFC-0022 Advancement
To move from DRAFT to GROUNDED:
1. Deterministic verifier implementations exist for all S0 gates.
2. One end-to-end sovereign stop drill proves both hardware and software path integrity with signed receipts.
3. One adversarial replay suite proves nonce/freshness fail-closed behavior across stop, revocation, and audit paths.

To move from GROUNDED to RELEASE:
1. Stage S0..S7 exit predicates all pass at declared HTF boundaries.
2. No open S0 gate failures in latest governance window.
3. Independent verifier coverage and verifier-independence checks are both complete.

### 10.1 Objective Acceptance
1. OBJ-PSI-01 through OBJ-PSI-06 all pass with signed evidence.
2. No open S0 gate failures in latest HTF governance window.

### 10.2 Scale and Economics Acceptance
1. Identity and audit proofs validated at synthetic scale `n=10^12` with O(log n) verification class.
2. Receipt batching and sovereignty checks keep BFT overhead below 1 percent target.

### 10.3 Semantic Closure Acceptance
1. Bisimulation gate pass rate for sovereign observables at recursion depth `N<=12` is at least 0.99.
2. No depth-specific sovereignty primitives introduced.

### 10.4 Security Posture Acceptance
1. Prompt-injection boundary test suite shows zero sovereignty command escapes.
2. Confidentiality and integrity labeling gates pass for all sovereignty artifacts.
3. Replay/staleness test suite demonstrates fail-closed behavior under induced uncertainty.
4. Byzantine federation tests demonstrate deny-on-equivocation for sovereignty imports.
5. Revocation correctness tests show zero miss count in promoted windows.
6. Sovereignty constraint mutation tests show zero unauthorized root transitions.

### 10.5 Suggested Machine Predicates
Representative acceptance predicate bundle:
```bash
jq -e '
  .obj_psi_01_pass == true and
  .obj_psi_02_pass == true and
  .obj_psi_03_pass == true and
  .obj_psi_04_pass == true and
  .obj_psi_05_pass == true and
  .obj_psi_06_pass == true and
  .gate_s0_failures == 0 and
  .unknown_state_count == 0 and
  .constitutional_admissibility_enforced == true and
  .humanitarian_precheck_enforced == true and
  .containment_precheck_enforced == true and
  .verifier_independence_pass == true and
  .sovereignty_surface_coverage == 1.0 and
  .active_constraint_root_binding_pass == true and
  .audit_epoch_order_proof_pass == true and
  .unbound_physical_activation_reconciliation_pass == true and
  .capsule_integrity_pass == true and
  .proof_complexity.identity == "O(log n)" and
  .proof_complexity.audit_single_action == "O(log n)" and
  .proof_complexity.audit_batch == "O(log n + k)" and
  .proof_profile_valid == true and
  .sovereignty_surface_binding_pass == true and
  .bft_overhead_pct_p99 <= 1.0 and
  .bisimulation_depth12_pass_rate >= 0.99 and
  .revocation_miss_count == 0
' evidence/rfcs/RFC-0022/acceptance/summary.json
```

---

## 11. Dependency Contract for RFC-0023..RFC-0026 (Normative)
PSI exports these contracts to downstream RFCs:
1. `PrincipalIdentityV1` and `PrincipalDelegationReceiptV1` are the only admissible roots for delegated authority chains.
2. `AutonomyPolicyV1` and `AutonomyEvidenceWindowV1` define mandatory autonomy control surfaces.
3. `SovereignStopOrderV1` and stop check rules define universal precondition for world effects.
4. `SovereignAudit*` objects define required auditability surfaces.
5. `ContainmentProofV1` plus `SovereigntyConstraintMutationReceiptV1` define self-modification preconditions for any RFC-0026 capability.

Downstream dependency notes:
1. RFC-0023 MUST bind instruction lifecycle transitions to principal-derived authority proofs.
2. RFC-0024 MUST enforce provisioning requests under autonomy ceilings and sovereign stop checks.
3. RFC-0025 MUST enforce service operations under same sovereignty and freshness constraints.
4. RFC-0026 MUST require valid external containment proof before any self-modification promotion.

---

## 12. Theory Binding Matrix (Normative Traceability)

| PSI Feature | Physics Constraints | Laws | Invariants | Principles | Mechanisms | Strategy Contracts |
|---|---|---|---|---|---|---|
| Sovereignty lattice and strict delegation meet | PHY-05, PHY-06 | LAW-05, LAW-14, LAW-16 | INV-F-05, INV-F-14 | PRIN-038, PRIN-071, PRIN-094 | MECH-OCAP, MECH-PERMEABILITY-RECEIPT | `AUTH-GRAPH-001`, `MET-AUTHORITY-GRAPH-COVERAGE` |
| Hardware-rooted principal authority + revocation | PHY-04, PHY-05 | LAW-05, LAW-09, LAW-15 | INV-F-08, INV-F-11, INV-F-14 | PRIN-036, PRIN-037 | MECH-ROOT-OF-TRUST, MECH-ATTESTATION, MECH-FRESHNESS-POLICY | `PRINCIPAL-ROOT-ANVEIO`, `REVOCATION-AUTHORITY-ROOT-001` |
| Stop-path liveness loop and auto-freeze | PHY-04, PHY-05 | LAW-01, LAW-12, LAW-15 | INV-F-11, INV-F-14 | PRIN-063, PRIN-067 | MECH-EMERGENCY-STOP, MECH-GATES | `FIN-GATE-STOP-STATE`, `MET-TRUST-LATENCY-P95` |
| Capsule integrity and non-bypass containment | PHY-05 | LAW-05, LAW-15 | INV-F-05, INV-F-14 | PRIN-091, PRIN-092 | MECH-SUBTASK-ISOLATION, MECH-MONITOR-ISOLATION | containment security posture in `MASTER_STRATEGY` |
| O(log n) sovereign audit proofs with omission evidence | PHY-08, PHY-09 | LAW-03, LAW-07, LAW-15 | INV-F-01, INV-F-12, INV-F-13 | PRIN-045, PRIN-046, PRIN-092 | MECH-RECEIPTS, MECH-EVIDENCE-TIERING, MECH-COMPACTION | `VERIF-EVID-001` |
| Prompt-injection and dual-lattice boundary | PHY-05 | LAW-05, LAW-08, LAW-15 | INV-F-05, INV-F-10, INV-F-14 | PRIN-089, PRIN-090, PRIN-091 | MECH-POLICY, MECH-MONITOR-ISOLATION | security policy `SP-RUNTIME-003`, `SP-RUNTIME-004` |
| External self-containment proof with independent verifier economics | PHY-06, PHY-08 | LAW-01, LAW-08, LAW-15 | INV-F-14, INV-F-15 | PRIN-068, PRIN-082, PRIN-101 | MECH-GATES, MECH-EVALUATOR-AUDIT | independent assurance lane in governance model |
| Universal per-scope override derivation | PHY-04, PHY-05 | LAW-05, LAW-16 | INV-F-11, INV-F-14 | PRIN-038, PRIN-094 | MECH-OCAP, MECH-EMERGENCY-STOP | `FIN-GATE-STOP-STATE`, `AUTH-GRAPH-001` |

---

## 13. Security and Operational Notes (Normative)
1. Post-quantum migration is explicitly out of scope for this RFC revision.
2. Ubuntu-only target is assumed for rollout scripts and operational controls.
3. Sovereignty controls are daemon-enforced semantics; projections (CLI/UI/adapter) are non-authoritative.
4. Any intentional trust-boundary semantic break requires versioned migration and compatibility receipts.

---

## 14. Initial Ticket Decomposition (Normative)
| Ticket | Depends On | Scope | Acceptance Predicate | Evidence Path |
|---|---|---|---|---|
| `TCK-PSI-0001` | none | Schema registry for all PSI v1 objects (Section 4, including `ClassificationLatticeProfileV1`, `ProofComplexityProfileV1`, and `SovereignResumeOrderV1`) | `schema_validation_pass_ratio == 1.0 and bounded_decode_violation_count == 0` | `evidence/rfcs/RFC-0022/tickets/TCK-PSI-0001/` |
| `TCK-PSI-0002` | `TCK-PSI-0001` | Delegation meet verifier + strict narrowing denial | `delegation_narrowing_violations == 0` | `evidence/rfcs/RFC-0022/tickets/TCK-PSI-0002/` |
| `TCK-PSI-0003` | `TCK-PSI-0001` | Principal revocation record pipeline + revocation head publication | `revocation_miss_count == 0` | `evidence/rfcs/RFC-0022/tickets/TCK-PSI-0003/` |
| `TCK-PSI-0004` | `TCK-PSI-0001` | Sovereign stop order/ack path with proof-carrying identities | `stop_ack_authoritative_ratio == 1.0` | `evidence/rfcs/RFC-0022/tickets/TCK-PSI-0004/` |
| `TCK-PSI-0005` | `TCK-PSI-0004` | Hardware kill activation + `KillSwitchConvergenceProofV1` path (out-of-band) | `hardware_cut_independence == true and kill_convergence_coverage == 1.0` | `evidence/rfcs/RFC-0022/tickets/TCK-PSI-0005/` |
| `TCK-PSI-0006` | `TCK-PSI-0004` | Halt path sentinel challenge/response + replay defense | `false_pass_count == 0` | `evidence/rfcs/RFC-0022/tickets/TCK-PSI-0006/` |
| `TCK-PSI-0007` | `TCK-PSI-0001` | Capsule integrity proof ingestion and epoch binding | `capsule_integrity_failures == 0` | `evidence/rfcs/RFC-0022/tickets/TCK-PSI-0007/` |
| `TCK-PSI-0008` | `TCK-PSI-0001` | Autonomy semilattice evaluator + `RiskAccumulatorProfileV1` + cumulative risk replay accounting | `action_over_ceiling_count == 0 and epoch_cumulative_risk_overflow_count == 0 and risk_accumulator_replay_equivalence == 1.0` | `evidence/rfcs/RFC-0022/tickets/TCK-PSI-0008/` |
| `TCK-PSI-0009` | `TCK-PSI-0001` | Sovereign audit request/response with omission proofs + direct-fetch bypass | `audit_completeness_failures == 0 and direct_fetch_replay_pass == true` | `evidence/rfcs/RFC-0022/tickets/TCK-PSI-0009/` |
| `TCK-PSI-0010` | `TCK-PSI-0001` | External containment verifier + `VerifierIndependenceAttestationV1` evaluator | `internal_only_proof_count == 0 and verifier_independence_pass == true and independence_class_strong_ratio == 1.0` | `evidence/rfcs/RFC-0022/tickets/TCK-PSI-0010/` |
| `TCK-PSI-0011` | `TCK-PSI-0004`,`TCK-PSI-0005`,`TCK-PSI-0006` | Kernel event wire integration for tags 35..46 | `event_replay_equivalence_ratio == 1.0` | `evidence/rfcs/RFC-0022/tickets/TCK-PSI-0011/` |
| `TCK-PSI-0012` | `TCK-PSI-0002`,`TCK-PSI-0003`,`TCK-PSI-0004`,`TCK-PSI-0005`,`TCK-PSI-0006`,`TCK-PSI-0007`,`TCK-PSI-0008`,`TCK-PSI-0009`,`TCK-PSI-0010`,`TCK-PSI-0011` | Governance gate evaluator + fail-closed matrix implementation | `unknown_state_fail_closed == true` | `evidence/rfcs/RFC-0022/tickets/TCK-PSI-0012/` |
| `TCK-PSI-0013` | `TCK-PSI-0012` | Rollout boundary harness and transition-deny checks | `stage_transition_invalid_count == 0` | `evidence/rfcs/RFC-0022/tickets/TCK-PSI-0013/` |
| `TCK-PSI-0014` | `TCK-PSI-0013` | Scale/bisimulation/overhead/adversarial acceptance suite | `acceptance_suite_pass == true` | `evidence/rfcs/RFC-0022/tickets/TCK-PSI-0014/` |
| `TCK-PSI-0015` | `TCK-PSI-0010`,`TCK-PSI-0012` | `SovereigntyConstraintMutationReceiptV1` + `GATE-PSI-SELF-MOD-LOCK` implementation | `unauthorized_sovereignty_constraint_mutation_count == 0 and mutation_receipt_chain_valid == true` | `evidence/rfcs/RFC-0022/tickets/TCK-PSI-0015/` |
| `TCK-PSI-0016` | `TCK-PSI-0001`,`TCK-PSI-0009`,`TCK-PSI-0012` | Classification lattice profile + proof complexity profile evaluators + audit epoch-order proof verifier | `classification_lattice_profile_valid == true and proof_profile_valid == true and audit_epoch_order_proof_pass == true` | `evidence/rfcs/RFC-0022/tickets/TCK-PSI-0016/` |
| `TCK-PSI-0017` | `TCK-PSI-0004`,`TCK-PSI-0005`,`TCK-PSI-0011`,`TCK-PSI-0012` | `SovereignResumeOrderV1` admission path and no-implicit-unfreeze enforcement | `resume_without_required_proofs_count == 0 and implicit_unfreeze_count == 0` | `evidence/rfcs/RFC-0022/tickets/TCK-PSI-0017/` |

---

## 15. References
1. `documents/rfcs/RFC-0020/HOLONIC_SUBSTRATE_INTERFACE.md`
2. `documents/rfcs/RFC-0021/HOLONIC_VENTURE_PROVING_INTERFACE.md`
3. `documents/theory/unified-theory-v2.json`
4. `documents/theory/unified-theory-v2.json`
5. `documents/theory/unified-theory-v2.json`
6. `documents/theory/unified-theory-v2.json`
7. `documents/strategy/MASTER_STRATEGY.json`
8. `documents/strategy/BUSINESS_PLAN.json`
9. `documents/security/SECURITY_POLICY.cac.json`
10. `documents/security/THREAT_MODEL.cac.json`
11. `proto/kernel_events.proto`
