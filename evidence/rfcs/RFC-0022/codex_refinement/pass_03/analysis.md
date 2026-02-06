### Change 1: Make The Sovereignty Lattice Mechanically Deterministic

**Rationale**: Section 3.1 defines an authority vector and a partial order but does not define orientation per dimension. Without that, two verifiers can compute different meet results and disagree on whether delegation is narrowing. That is a consensus and containment hazard.  
**Constraints preserved**: RFC-0020 strict narrowing floor, INV-F-05 least-privilege, INV-F-14 precedence, LAW-16 closure under composition.  
**Threat coverage**: Capability widening via semantic ambiguity, Byzantine disagreement on delegation validity.  
**Verification**: Property tests for meet commutativity/idempotence/monotonicity; replay-equivalence test over random delegation chains.

```diff
--- a/documents/rfcs/RFC-0022/PRINCIPAL_SOVEREIGNTY_INTERFACE.md
+++ b/documents/rfcs/RFC-0022/PRINCIPAL_SOVEREIGNTY_INTERFACE.md
@@
 5. Revocation is revocation-wins: revoked edge contribution is treated as `bottom` from revocation tick onward.
 
+### 3.1.1 Dimension Order and Meet Determinism (Normative)
+To keep delegation verification replay-equivalent across cells, PSI defines order orientation for every authority dimension:
+
+| Dimension | Narrower relation (`x <= y`) | Deterministic meet (`x ^ y`) |
+|---|---|---|
+| `risk_ceiling` | lower risk ceiling is narrower | `min(x.risk_ceiling, y.risk_ceiling)` |
+| `capability_set` | subset is narrower | `intersection(x.capability_set, y.capability_set)` |
+| `budget_vector` | component-wise lower/equal caps are narrower | component-wise `min` |
+| `stop_predicates` | more deny predicates is narrower | set union |
+| `integrity_floor` | higher integrity floor is narrower | `max` |
+| `confidentiality_ceiling` | lower confidentiality ceiling is narrower | `min` |
+| `expiry_window` | earlier expiry is narrower | earlier bound |
+| `fanout_caps` | lower cap is narrower | `min` |
+
+If any component comparison is undefined (unit mismatch, unknown enum, missing mandatory component), meet evaluation MUST fail closed.
+
 ### 3.2 Autonomy Semilattice
```

---

### Change 2: Add A Deterministic Cumulative-Risk Algebra

**Rationale**: TM-PSI-02 is only partially mechanized. `max_cumulative_risk_score` exists, but there is no deterministic definition of cumulative risk. This leaves a non-mechanical gap for capability creep by composition.  
**Constraints preserved**: OBJ-PSI-03, LAW-14 proportionality, INV-F-05 least-privilege, INV-F-15 machine-checkable promotion.  
**Threat coverage**: Gradual capability creep through many individually-valid actions.  
**Verification**: Replay test requiring identical cumulative score across independent implementations; adversarial sequence tests.

```diff
--- a/documents/rfcs/RFC-0022/PRINCIPAL_SOVEREIGNTY_INTERFACE.md
+++ b/documents/rfcs/RFC-0022/PRINCIPAL_SOVEREIGNTY_INTERFACE.md
@@
 schema_id: apm2.autonomy_policy.v1
 policy_id: string
 level: L0 | L1 | L2 | L3
 max_risk_tier: RiskTier
 capability_ceiling_hash: CasDigest
 per_action_constraints_hash: CasDigest
+risk_accumulator_profile_hash: CasDigest
 per_epoch_budget_ceiling:
@@
 Constraints:
 1. `max_risk_tier` MUST monotonically increase with level number.
 2. `downgrade_triggers` MUST include freshness uncertainty and revocation uncertainty for L2+.
 3. `downgrade_triggers` MUST include cumulative-risk overflow for L2+.
 4. `requires_principal_approval=true` is mandatory at L0.
+5. `risk_accumulator_profile_hash` MUST resolve to a deterministic profile shared by all verifiers for the active epoch.
+
+### 4.4a RiskAccumulatorProfileV1
+```yaml
+schema_id: apm2.risk_accumulator_profile.v1
+profile_id: string
+risk_weight_by_tier:
+  Tier0: Quantity
+  Tier1: Quantity
+  Tier2: Quantity
+  Tier3: Quantity
+  Tier4: Quantity
+cross_capability_interaction_matrix_hash: CasDigest
+temporal_decay_half_life_ticks: uint64
+saturation_ceiling: Quantity
+normalization_unit: string
+version: uint32
+authority_seal_hash: AuthoritySealRef
+```
+Constraints:
+1. For fixed input receipts and epoch window, output MUST be deterministic across implementations.
+2. Unknown capability-pair interactions MUST fail closed (no implicit zero-default).
+3. `saturation_ceiling` MUST be less than or equal to strictest active `max_cumulative_risk_score`.
@@
 Failure action: deny and regress `L_eff` one level minimum.
 
+### 6.2a Cumulative Risk Replay Contract
+Pseudo-rule:
+```text
+accumulate_epoch_risk(actions, profile):
+  total = 0
+  for action in canonical_order(actions):
+    base = profile.risk_weight_by_tier[action.risk_tier]
+    interaction = lookup_interaction(profile.cross_capability_interaction_matrix, action.capability, prior_capabilities)
+    total = decay(total, profile.temporal_decay_half_life_ticks) + base + interaction
+    require total <= profile.saturation_ceiling
+  return normalize(total, profile.normalization_unit)
+```
+Admission MUST fail closed on missing interaction entries, unit mismatch, or non-replay-equivalent totals.
@@
-| GATE-PSI-AUTONOMY-CUMULATIVE | T | S0 | `epoch_usage <= per_epoch_budget_ceiling` | Budget overflow | epoch budget receipts |
+| GATE-PSI-AUTONOMY-CUMULATIVE | T | S0 | `epoch_usage <= per_epoch_budget_ceiling && cumulative_risk <= max_cumulative_risk_score && risk_accumulator_replay_equivalence == 1.0` | Budget/cumulative-risk overflow or nondeterministic risk replay | epoch budget + risk accumulator receipts |
@@
-| GATE-PSI-AUTONOMY-CUMULATIVE | Governance Council + Verification Council | `HTF-BND-P2-CLOSE` | `jq -e '.epoch_cumulative_risk_overflow_count == 0 and .unknown_state_count == 0' evidence/rfcs/RFC-0022/gates/GATE-PSI-AUTONOMY-CUMULATIVE/summary.json` | `evidence/rfcs/RFC-0022/gates/GATE-PSI-AUTONOMY-CUMULATIVE/` |
+| GATE-PSI-AUTONOMY-CUMULATIVE | Governance Council + Verification Council | `HTF-BND-P2-CLOSE` | `jq -e '.epoch_cumulative_risk_overflow_count == 0 and .risk_accumulator_replay_equivalence == 1.0 and .unknown_state_count == 0' evidence/rfcs/RFC-0022/gates/GATE-PSI-AUTONOMY-CUMULATIVE/summary.json` | `evidence/rfcs/RFC-0022/gates/GATE-PSI-AUTONOMY-CUMULATIVE/` |
@@
 1. `AutonomyPolicyV1` for L0 and L1.
-2. Per-action and per-epoch budget ceiling checks.
+2. Per-action and per-epoch budget ceiling checks plus deterministic cumulative-risk accumulation via `RiskAccumulatorProfileV1`.
 3. Automatic regression on uncertainty.
@@
-| `TCK-PSI-0008` | `0001` | Autonomy semilattice evaluator + cumulative risk accounting | `action_over_ceiling_count == 0 and epoch_cumulative_risk_overflow_count == 0` | `evidence/rfcs/RFC-0022/tickets/TCK-PSI-0008/` |
+| `TCK-PSI-0008` | `0001` | Autonomy semilattice evaluator + `RiskAccumulatorProfileV1` + cumulative risk replay accounting | `action_over_ceiling_count == 0 and epoch_cumulative_risk_overflow_count == 0 and risk_accumulator_replay_equivalence == 1.0` | `evidence/rfcs/RFC-0022/tickets/TCK-PSI-0008/` |
```

---

### Change 3: Define Revocation Cutover Semantics For Race-Free Temporal Sovereignty

**Rationale**: Revocation currently requires freshness/monotonicity, but not explicit cutover semantics against HTF-issued ticks. This creates ambiguity under delay/reorder.  
**Constraints preserved**: OBJ-PSI-05, LAW-09 temporal pinning, INV-F-08 freshness, INV-F-14 fail-closed precedence.  
**Threat coverage**: Replay at revocation boundaries, partition race exploitation.  
**Verification**: Adversarial timeline suite with delayed delivery and out-of-order revocation propagation.

```diff
--- a/documents/rfcs/RFC-0022/PRINCIPAL_SOVEREIGNTY_INTERFACE.md
+++ b/documents/rfcs/RFC-0022/PRINCIPAL_SOVEREIGNTY_INTERFACE.md
@@
 5. `(issuer_key_id, sovereignty_epoch)` duplicates or regresses.
 6. Nonce replay cache retention is shorter than artifact validity window + configured network delay budget.
 
+### 3.4.1 Revocation Cutover Semantics (Normative)
+Revocation correctness MUST be evaluated against HTF-issued ticks, not message arrival order.
+
+Cutover rule:
+1. Let `t_issue(a)` be authoritative issue tick for artifact `a`.
+2. Let `t_revoke` be `PrincipalRevocationRecordV1.effective_tick`.
+3. Artifact `a` signed by `revoked_keyset_id` is valid iff `t_issue(a) < t_revoke`.
+4. If `t_issue(a)` cannot be proven, validation MUST fail closed.
+5. Delayed transport delivery does not extend post-cutover validity.
+
 ### 3.5 Fractal Closure and Bisimulation
@@
 reason_code: COMPROMISE | ROTATION | LOST_DEVICE | POLICY_REKEY | OTHER
 effective_tick: uint64
+issued_tick: uint64
 sovereignty_epoch: uint64
 challenge_nonce: bytes
+prev_revocation_head_hash: CasDigest
 issued_time_envelope_ref: TimeEnvelopeRef
 authority_seal_hash: AuthoritySealRef
@@
 1. `sovereignty_epoch` MUST be strictly monotonic per principal.
 2. Revocation record freshness failure is an automatic Tier2+ deny.
 3. Revocation uncertainty is revocation-wins and MUST fail closed.
+4. `effective_tick` MUST be greater than or equal to `issued_tick`.
+5. `prev_revocation_head_hash` MUST match active revocation head at issuance time.
+6. Artifacts issued at or after `effective_tick` by `revoked_keyset_id` are invalid regardless of arrival order.
@@
 ### 6.6 Revocation Correctness
 1. Revocation heads replicate as revocation-wins signed CRDTs.
-2. If revocation status uncertain for any authority edge in path, SK MUST deny associated actuation.
-3. Revocation latency SLO is tracked per epoch and is release-blocking for Tier2+ autonomy claims.
+2. Admission MUST enforce `t_issue(artifact) < effective_tick` on revoked keysets.
+3. If revocation status or artifact issue-tick is uncertain for any authority edge in path, SK MUST deny actuation.
+4. Equal-epoch revocation-head forks are containment uncertainty and MUST freeze Tier2+.
+5. Revocation latency SLO and cutover-conflict count are release-blocking for Tier2+ autonomy claims.
@@
-| GATE-PSI-REVOCATION-FRESHNESS | T | S0 | `revocation_status_known && freshness_pass` | Unknown or stale revocation | revocation head + proof |
+| GATE-PSI-REVOCATION-FRESHNESS | T | S0 | `revocation_status_known && freshness_pass && revocation_cutover_conflicts == 0` | Unknown/stale revocation or cutover conflict | revocation head + cutover proof |
@@
-| GATE-PSI-REVOCATION-FRESHNESS | Security Council | `HTF-BND-P1-SECURITY-CLOSE` | `jq -e '.revocation_status_known == true and .freshness_pass == true and .unknown_state_count == 0' evidence/rfcs/RFC-0022/gates/GATE-PSI-REVOCATION-FRESHNESS/summary.json` | `evidence/rfcs/RFC-0022/gates/GATE-PSI-REVOCATION-FRESHNESS/` |
+| GATE-PSI-REVOCATION-FRESHNESS | Security Council | `HTF-BND-P1-SECURITY-CLOSE` | `jq -e '.revocation_status_known == true and .freshness_pass == true and .revocation_cutover_conflicts == 0 and .unknown_state_count == 0' evidence/rfcs/RFC-0022/gates/GATE-PSI-REVOCATION-FRESHNESS/summary.json` | `evidence/rfcs/RFC-0022/gates/GATE-PSI-REVOCATION-FRESHNESS/` |
```

---

### Change 4: Operationalize Bounded-Decoding And Unknown-Field Rules

**Rationale**: RFC-0022 states bounded decoding, but does not define a machine-checkable decoder profile or a gate enforcing it.  
**Constraints preserved**: RFC-0020 canonicalization/bounded-decode floor, INV-F-05, INV-F-14.  
**Threat coverage**: Parser resource-exhaustion, unknown-field smuggling across sovereignty boundaries.  
**Verification**: Fuzz harness with pre-decode size bounds and unknown-field forwarding tests.

```diff
--- a/documents/rfcs/RFC-0022/PRINCIPAL_SOVEREIGNTY_INTERFACE.md
+++ b/documents/rfcs/RFC-0022/PRINCIPAL_SOVEREIGNTY_INTERFACE.md
@@
 ### 4.1 Common Type Aliases
@@
 - `ReceiptPointerRef`: CAS digest for `ReceiptPointerV1` or multiproof container.
 
+### 4.1a SovereigntyDecoderProfileV1
+```yaml
+schema_id: apm2.sovereignty_decoder_profile.v1
+profile_id: string
+max_artifact_bytes: uint64
+max_string_bytes: uint32
+max_bytes_field_bytes: uint32
+max_repeated_count: uint32
+max_merkle_proof_nodes: uint32
+max_nonce_cache_entries: uint32
+json_unknown_field_policy: REJECT
+protobuf_unknown_field_policy: DROP_AND_NOT_FORWARD
+version: uint32
+authority_seal_hash: AuthoritySealRef
+```
+Constraints:
+1. All PSI decoders MUST enforce profile limits before allocation and after decode.
+2. Unknown fields in signed/hashed JSON artifacts MUST be rejected.
+3. Unknown fields in signed/hashed protobuf artifacts MUST be dropped before canonicalization/signing and MUST NOT be forwarded.
@@
 autonomy_state_root_hash: CasDigest
+decoder_profile_hash: CasDigest
 halt_path_liveness_proof_hash: CasDigest
@@
 4. Missing any required Tier2+ sovereignty hash is equivalent to containment uncertainty and triggers freeze.
+5. `decoder_profile_hash` MUST resolve to active `SovereigntyDecoderProfileV1`; mismatch is containment uncertainty and triggers freeze.
@@
 | GATE-PSI-HW-ATTESTATION | T | S0 | `forall Tier3+ sovereignty seals: hw_bound=true` | Software-only key on Tier3+ | `PrincipalIdentityV1`, attestation artifacts |
+| GATE-PSI-BOUNDED-DECODE | T | S0 | `decoder_profile_active == true && bounded_decode_violations == 0 && unknown_field_forwarding_count == 0` | Decoder bounds breach or unknown-field smuggling | `SovereigntyDecoderProfileV1` + decoder audit receipts |
 | GATE-PSI-AUTONOMY-CEILING | D/T | S0 | `action.risk_tier <= max_risk(L_eff)` | Any over-tier action | `AutonomyPolicyV1`, action receipts |
@@
 | GATE-PSI-HW-ATTESTATION | Security Council | `HTF-BND-P2-CONTROL-CLOSE` | `jq -e '.tier3plus_softkey_usage == 0 and .attestation_freshness_failures == 0 and .unknown_state_count == 0' evidence/rfcs/RFC-0022/gates/GATE-PSI-HW-ATTESTATION/summary.json` | `evidence/rfcs/RFC-0022/gates/GATE-PSI-HW-ATTESTATION/` |
+| GATE-PSI-BOUNDED-DECODE | Security Council + Runtime Council | `HTF-BND-P1-SECURITY-CLOSE` | `jq -e '.decoder_profile_active == true and .bounded_decode_violations == 0 and .unknown_field_forwarding_count == 0 and .unknown_state_count == 0' evidence/rfcs/RFC-0022/gates/GATE-PSI-BOUNDED-DECODE/summary.json` | `evidence/rfcs/RFC-0022/gates/GATE-PSI-BOUNDED-DECODE/` |
 | GATE-PSI-HW-INDEPENDENCE | Security Council + Runtime Council | `HTF-BND-P2-SEMANTICS-CLOSE` | `jq -e '.hardware_cut_independence == true and .independent_control_network == true and .unknown_state_count == 0' evidence/rfcs/RFC-0022/gates/GATE-PSI-HW-INDEPENDENCE/summary.json` | `evidence/rfcs/RFC-0022/gates/GATE-PSI-HW-INDEPENDENCE/` |
@@
-| S0 | `HTF-BND-P1-BASELINE-LOCK` | `HTF-BND-P1-SECURITY-CLOSE` | `GATE-PSI-REVOCATION-FRESHNESS` | Any delegation narrowing violation or unknown authority edge |
+| S0 | `HTF-BND-P1-BASELINE-LOCK` | `HTF-BND-P1-SECURITY-CLOSE` | `GATE-PSI-REVOCATION-FRESHNESS`, `GATE-PSI-BOUNDED-DECODE` | Any delegation narrowing violation, decoder-bound breach, or unknown authority edge |
@@
 1. `PrincipalIdentityV1` with software key allowed only for `L0/L1` operations.
 2. `PrincipalDelegationReceiptV1` and delegation meet enforcement.
 3. Sovereignty channels and deny-by-default routing.
+4. `SovereigntyDecoderProfileV1` activation and unknown-field non-forwarding tests.
@@
 | `TCK-PSI-0001` | none | Schema registry for all PSI v1 objects (including 4.14-4.16) | `schema_validation_pass_ratio == 1.0` | `evidence/rfcs/RFC-0022/tickets/TCK-PSI-0001/` |
+| `TCK-PSI-0001` | none | Schema registry for all PSI v1 objects (including decoder profile + 4.14-4.18) | `schema_validation_pass_ratio == 1.0 and bounded_decode_violation_count == 0` | `evidence/rfcs/RFC-0022/tickets/TCK-PSI-0001/` |
```

---

### Change 5: Define Verifier Independence As A First-Class Artifact

**Rationale**: `verifier_independence_attestation_hash` is referenced but not formally typed, so GATE-PSI-VERIFIER-INDEPENDENCE is under-specified.  
**Constraints preserved**: OBJ-PSI-06, LAW-08 verifier economics, INV-F-15 terminal verifier integrity.  
**Threat coverage**: Verifier capture/collusion with subject runtime.  
**Verification**: Independence attestation verifier + threshold checks + expiry tests.

```diff
--- a/documents/rfcs/RFC-0022/PRINCIPAL_SOVEREIGNTY_INTERFACE.md
+++ b/documents/rfcs/RFC-0022/PRINCIPAL_SOVEREIGNTY_INTERFACE.md
@@
 Constraints:
 1. PASS requires p99 propagation <=2000ms and deny-on-uncertainty <=250ms at Tier3+.
@@
 6. Missing/stale/replayed proof in epoch is equivalent to FAIL and triggers freeze.
+7. `verifier_independence_attestation_hash` MUST resolve to fresh `VerifierIndependenceAttestationV1`; Tier2+ requires `independence_class=STRONG`.
@@
 Constraints:
 1. External verifier identity MUST be outside autonomous trust boundary.
 2. `sovereignty_surface_manifest_hash` MUST enumerate all sovereignty-critical binaries/policies in scope.
-3. `verifier_independence_attestation_hash` MUST be valid and fresh.
+3. `verifier_independence_attestation_hash` MUST be valid, fresh, and `independence_class=STRONG`.
 4. Expired proof blocks Tier2+ promotion.
@@
 ### 4.16 CapsuleIntegrityProofV1
@@
 2. Missing/stale capsule integrity proof is a hard deny for Tier2+ actuation.
 
+### 4.17 VerifierIndependenceAttestationV1
+```yaml
+schema_id: apm2.verifier_independence_attestation.v1
+attestation_id: string
+subject_verifier_identity_proof_hash: IdentityProofRef
+evaluated_subject_scope_hash: CasDigest
+independence_class: STRONG | CONDITIONAL | WEAK
+shared_control_overlap_ratio: Quantity
+shared_funding_ratio: Quantity
+shared_admin_domain_count: uint32
+shared_signing_root: bool
+shared_network_asn_overlap_ratio: Quantity
+valid_from_envelope_ref: TimeEnvelopeRef
+valid_until_tick: uint64
+assessor_identity_proof_hash: IdentityProofRef
+assessor_seal_hash: AuthoritySealRef
+```
+Constraints:
+1. Tier2+ containment and liveness verification requires `independence_class=STRONG`.
+2. `shared_signing_root` MUST be `false` for Tier2+ claims.
+3. Expired or stale attestations are fail-closed.
+
@@
-| GATE-PSI-VERIFIER-INDEPENDENCE | D/T | S0 | `verifier_independence_attestation_valid == true` | Verifier inside subject trust/economic boundary | verifier independence receipt |
+| GATE-PSI-VERIFIER-INDEPENDENCE | D/T | S0 | `independence_class == "STRONG" && shared_signing_root == false && shared_control_overlap_ratio <= 0.05 && shared_funding_ratio <= 0.25` | Verifier inside subject trust/economic boundary | `VerifierIndependenceAttestationV1` |
@@
-| GATE-PSI-VERIFIER-INDEPENDENCE | Security Council + External Assurance | `HTF-BND-P3-CLOSE` | `jq -e '.verifier_independence_attestation_valid == true and .unknown_state_count == 0' evidence/rfcs/RFC-0022/gates/GATE-PSI-VERIFIER-INDEPENDENCE/summary.json` | `evidence/rfcs/RFC-0022/gates/GATE-PSI-VERIFIER-INDEPENDENCE/` |
+| GATE-PSI-VERIFIER-INDEPENDENCE | Security Council + External Assurance | `HTF-BND-P3-CLOSE` | `jq -e '.verifier_independence_attestation_valid == true and .independence_class == "STRONG" and .shared_signing_root == false and .shared_control_overlap_ratio <= 0.05 and .shared_funding_ratio <= 0.25 and .unknown_state_count == 0' evidence/rfcs/RFC-0022/gates/GATE-PSI-VERIFIER-INDEPENDENCE/summary.json` | `evidence/rfcs/RFC-0022/gates/GATE-PSI-VERIFIER-INDEPENDENCE/` |
@@
-| `TCK-PSI-0010` | `0001` | External containment verifier + verifier-independence attestation | `internal_only_proof_count == 0 and verifier_independence_pass == true` | `evidence/rfcs/RFC-0022/tickets/TCK-PSI-0010/` |
+| `TCK-PSI-0010` | `0001` | External containment verifier + `VerifierIndependenceAttestationV1` evaluator | `internal_only_proof_count == 0 and verifier_independence_pass == true and independence_class_strong_ratio == 1.0` | `evidence/rfcs/RFC-0022/tickets/TCK-PSI-0010/` |
```

---

### Change 6: Add Direct Kill-Switch Convergence Proofs

**Rationale**: OBJ-PSI-01 requires system-wide freeze from physical action within SLO. Current text has activation receipts and liveness drills but no dedicated convergence proof object tied to activation edge.  
**Constraints preserved**: OBJ-PSI-01, INV-F-11 stop checks, LAW-01 loop closure, LAW-14 risk-proportional gate strength.  
**Threat coverage**: False confidence in hardware kill path; partial freeze while reporting healthy stop path.  
**Verification**: Drill/real activation suites with coverage ratio and p99 convergence checks.

```diff
--- a/documents/rfcs/RFC-0022/PRINCIPAL_SOVEREIGNTY_INTERFACE.md
+++ b/documents/rfcs/RFC-0022/PRINCIPAL_SOVEREIGNTY_INTERFACE.md
@@
-| OBJ-PSI-01 | `PSI-BL-STOP-2026-02-06` | `HTF-BND-P1-SECURITY-CLOSE` | Security Council + Runtime Council | `jq -e '.stop_propagation_p99_ms <= 2000 and .deny_uncertainty_p99_ms <= 250 and .hardware_cut_independence == true and .unknown_state_count == 0 and .signature_valid == true' evidence/rfcs/RFC-0022/objectives/OBJ-PSI-01/summary.json` | `evidence/rfcs/RFC-0022/objectives/OBJ-PSI-01/` |
+| OBJ-PSI-01 | `PSI-BL-STOP-2026-02-06` | `HTF-BND-P1-SECURITY-CLOSE` | Security Council + Runtime Council | `jq -e '.stop_propagation_p99_ms <= 2000 and .deny_uncertainty_p99_ms <= 250 and .hardware_cut_independence == true and .kill_convergence_coverage == 1.0 and .unknown_state_count == 0 and .signature_valid == true' evidence/rfcs/RFC-0022/objectives/OBJ-PSI-01/summary.json` | `evidence/rfcs/RFC-0022/objectives/OBJ-PSI-01/` |
@@
 halt_path_liveness_proof_hash: CasDigest
 hardware_kill_activation_receipt_hash: CasDigest
+kill_switch_convergence_proof_hash: CasDigest
 capsule_integrity_proof_hash: CasDigest
@@
-3. Tier2+ epochs MUST include non-null `principal_revocation_head_hash`, `hardware_kill_activation_receipt_hash`, and `capsule_integrity_proof_hash`; `hardware_kill_activation_receipt_hash` MUST reference a fresh `DRILL` or `REAL_ACTIVATION` receipt.
-4. Missing any required Tier2+ sovereignty hash is equivalent to containment uncertainty and triggers freeze.
+3. Tier2+ epochs MUST include non-null `principal_revocation_head_hash`, `hardware_kill_activation_receipt_hash`, `kill_switch_convergence_proof_hash`, and `capsule_integrity_proof_hash`.
+4. `hardware_kill_activation_receipt_hash` MUST reference a fresh `DRILL` or `REAL_ACTIVATION` receipt, and `kill_switch_convergence_proof_hash` MUST prove convergence against that activation.
+5. Missing any required Tier2+ sovereignty hash is equivalent to containment uncertainty and triggers freeze.
@@
+### 4.18 KillSwitchConvergenceProofV1
+```yaml
+schema_id: apm2.kill_switch_convergence_proof.v1
+proof_id: string
+activation_id: string
+scope_selector_hash: CasDigest
+sampled_freeze_ack_multiproof_hash: CasDigest
+required_coverage_ratio: Quantity
+observed_coverage_ratio: Quantity
+convergence_p99_ms: Quantity
+deny_uncertainty_p99_ms: Quantity
+hardware_edge_tick: uint64
+final_ack_tick: uint64
+time_envelope_ref: TimeEnvelopeRef
+verifier_identity_proof_hash: IdentityProofRef
+verifier_seal_hash: AuthoritySealRef
+```
+Constraints:
+1. Tier3+ GLOBAL scope requires `observed_coverage_ratio == 1.0`.
+2. PASS requires `convergence_p99_ms <= 2000` and `deny_uncertainty_p99_ms <= 250`.
+3. Proof MUST bind to the referenced `activation_id` and scope selector.
+
@@
 | GATE-PSI-HW-INDEPENDENCE | T | S0 | `hardware_kill_activation_receipt_valid == true && independent_control_network == true` | Hardware path not independently provable | `HardwareKillActivationReceiptV1` |
+| GATE-PSI-KILL-CONVERGENCE | T | S0 | `kill_convergence_coverage == 1.0 && kill_convergence_p99_ms <= 2000` | Partial freeze or convergence SLO breach after activation/drill | `KillSwitchConvergenceProofV1` |
 | GATE-PSI-CAPSULE-INTEGRITY | T | S0 | `latest_capsule_integrity_proof_verdict == "PASS"` | Missing/stale/failed capsule integrity proof | `CapsuleIntegrityProofV1` |
@@
 | GATE-PSI-HW-INDEPENDENCE | Security Council + Runtime Council | `HTF-BND-P2-SEMANTICS-CLOSE` | `jq -e '.hardware_cut_independence == true and .independent_control_network == true and .unknown_state_count == 0' evidence/rfcs/RFC-0022/gates/GATE-PSI-HW-INDEPENDENCE/summary.json` | `evidence/rfcs/RFC-0022/gates/GATE-PSI-HW-INDEPENDENCE/` |
+| GATE-PSI-KILL-CONVERGENCE | Security Council + Runtime Council | `HTF-BND-P2-SEMANTICS-CLOSE` | `jq -e '.kill_convergence_coverage == 1.0 and .kill_convergence_p99_ms <= 2000 and .unknown_state_count == 0' evidence/rfcs/RFC-0022/gates/GATE-PSI-KILL-CONVERGENCE/summary.json` | `evidence/rfcs/RFC-0022/gates/GATE-PSI-KILL-CONVERGENCE/` |
 | GATE-PSI-CAPSULE-INTEGRITY | Security Council | `HTF-BND-P2-SEMANTICS-CLOSE` | `jq -e '.latest_capsule_integrity_proof_verdict == \"PASS\" and .unknown_state_count == 0' evidence/rfcs/RFC-0022/gates/GATE-PSI-CAPSULE-INTEGRITY/summary.json` | `evidence/rfcs/RFC-0022/gates/GATE-PSI-CAPSULE-INTEGRITY/` |
@@
-| S4 | `HTF-BND-P2-CONTROL-CLOSE` | `HTF-BND-P2-SEMANTICS-CLOSE` | `GATE-PSI-HW-INDEPENDENCE`, `GATE-PSI-CAPSULE-INTEGRITY` | Hardware path non-independence or capsule proof failure |
+| S4 | `HTF-BND-P2-CONTROL-CLOSE` | `HTF-BND-P2-SEMANTICS-CLOSE` | `GATE-PSI-HW-INDEPENDENCE`, `GATE-PSI-KILL-CONVERGENCE`, `GATE-PSI-CAPSULE-INTEGRITY` | Hardware path non-independence, kill-convergence failure, or capsule proof failure |
@@
 1. Hardware relay or equivalent physical cut path.
 2. Independent out-of-band control network.
-3. Stop-path drills with signed receipts.
+3. Stop-path drills with signed receipts and `KillSwitchConvergenceProofV1`.
@@
-`stop_propagation_p99_ms<=2000 && deny_uncertainty_p99_ms<=250`
+`stop_propagation_p99_ms<=2000 && deny_uncertainty_p99_ms<=250 && kill_convergence_coverage==1.0`
@@
-| `TCK-PSI-0005` | `0004` | Hardware kill activation receipt path (out-of-band) | `hardware_cut_independence == true` | `evidence/rfcs/RFC-0022/tickets/TCK-PSI-0005/` |
+| `TCK-PSI-0005` | `0004` | Hardware kill activation + `KillSwitchConvergenceProofV1` path (out-of-band) | `hardware_cut_independence == true and kill_convergence_coverage == 1.0` | `evidence/rfcs/RFC-0022/tickets/TCK-PSI-0005/` |
```

---

### Change 7: Make Sovereign Audit Truly Unmediated And Label-Safe

**Rationale**: “Audit without mediation” is not fully mechanized while label fields are currently untyped strings. This weakens both lattice safety and bypass guarantees.  
**Constraints preserved**: OBJ-PSI-04, INV-F-12/13 auditability, LAW-05 dual-axis containment, LAW-15 measurement integrity.  
**Threat coverage**: Mediated/partial audit responses, string-based label confusion, covert declassification path.  
**Verification**: Direct-fetch replay test using digest pointers and independent endpoints; label-lattice conformance tests.

```diff
--- a/documents/rfcs/RFC-0022/PRINCIPAL_SOVEREIGNTY_INTERFACE.md
+++ b/documents/rfcs/RFC-0022/PRINCIPAL_SOVEREIGNTY_INTERFACE.md
@@
 include_confidential_payloads: bool
-required_confidentiality_clearance: string
-required_integrity_floor: string
+required_confidentiality_clearance: PUBLIC | INTERNAL | CONFIDENTIAL | RESTRICTED
+required_integrity_floor: LOW | MEDIUM | HIGH | CRITICAL
+classification_lattice_profile_hash: CasDigest
 time_envelope_ref: TimeEnvelopeRef
@@
 3. If `query_lower_seq`/`query_upper_seq` are set, response MUST prove contiguous coverage and omission.
 4. Returned artifacts below `required_integrity_floor` MUST be omitted with verifiable omission proof.
+5. `classification_lattice_profile_hash` MUST resolve to an authenticated profile; string-comparison semantics are forbidden.
@@
 proof_complexity_class: O_LOG_N | O_LOG_N_PLUS_K
 classification_manifest_hash: CasDigest
-served_integrity_floor: string
+direct_fetch_manifest_hash: CasDigest
+served_confidentiality_ceiling: PUBLIC | INTERNAL | CONFIDENTIAL | RESTRICTED
+served_integrity_floor: LOW | MEDIUM | HIGH | CRITICAL
 declassification_receipt_hashes: [CasDigest]
@@
 4. If confidential payloads are returned, `declassification_receipt_hashes` MUST be non-empty.
-5. `served_integrity_floor` MUST dominate request `required_integrity_floor`.
-6. Response without completeness attestation is advisory only and non-authoritative.
+5. `served_integrity_floor` MUST dominate request `required_integrity_floor` and `served_confidentiality_ceiling` MUST dominate request confidentiality clearance.
+6. `direct_fetch_manifest_hash` MUST provide digest-addressable retrieval endpoints independent of responder projections.
+7. Response without completeness attestation is advisory only and non-authoritative.
@@
 verify_audit_response(resp):
@@
   require verify_classification_manifest(resp.classification_manifest_hash, request.required_confidentiality_clearance, request.required_integrity_floor)
+  require verify_direct_fetch_manifest(resp.direct_fetch_manifest_hash)
+  require principal_refetch_by_digest(resp.receipt_pointers, resp.direct_fetch_manifest_hash)
   require verify_declassification_receipts(resp.declassification_receipt_hashes) when confidential payloads included
@@
-| GATE-PSI-AUDIT-COMPLETENESS | T | S1 | `verify(completeness_attestation)==true` | Incomplete causal proof | `SovereignAuditResponseV1` |
+| GATE-PSI-AUDIT-COMPLETENESS | T | S1 | `verify(completeness_attestation)==true && direct_fetch_replay_pass == true && classification_lattice_profile_valid == true` | Incomplete proof, mediated-only response, or invalid label lattice | `SovereignAuditResponseV1` |
@@
-| GATE-PSI-AUDIT-COMPLETENESS | Audit Council + Verification Council | `HTF-BND-P2-SEMANTICS-CLOSE` | `jq -e '.audit_completeness_failures == 0 and .omission_proof_coverage == 1.0 and .unknown_state_count == 0' evidence/rfcs/RFC-0022/gates/GATE-PSI-AUDIT-COMPLETENESS/summary.json` | `evidence/rfcs/RFC-0022/gates/GATE-PSI-AUDIT-COMPLETENESS/` |
+| GATE-PSI-AUDIT-COMPLETENESS | Audit Council + Verification Council | `HTF-BND-P2-SEMANTICS-CLOSE` | `jq -e '.audit_completeness_failures == 0 and .omission_proof_coverage == 1.0 and .direct_fetch_replay_pass == true and .classification_lattice_profile_valid == true and .unknown_state_count == 0' evidence/rfcs/RFC-0022/gates/GATE-PSI-AUDIT-COMPLETENESS/summary.json` | `evidence/rfcs/RFC-0022/gates/GATE-PSI-AUDIT-COMPLETENESS/` |
@@
 1. `SovereignAuditRequestV1` and `SovereignAuditResponseV1` production path.
-2. Multiproof-based O(log n) audits.
+2. Multiproof-based O(log n) audits with direct digest-fetch replay.
 3. Completeness attestation and bounded verifier work profiles.
@@
-| `TCK-PSI-0009` | `0001` | Sovereign audit request/response with omission proofs | `audit_completeness_failures == 0` | `evidence/rfcs/RFC-0022/tickets/TCK-PSI-0009/` |
+| `TCK-PSI-0009` | `0001` | Sovereign audit request/response with omission proofs + direct-fetch bypass | `audit_completeness_failures == 0 and direct_fetch_replay_pass == true` | `evidence/rfcs/RFC-0022/tickets/TCK-PSI-0009/` |
```

---

### Change 8: Explicitly Mechanize “Override Any Action” And Trace It To Theory

**Rationale**: The RFC implies override capability but does not define a direct mechanical derivation for per-scope override as a protocol operation.  
**Constraints preserved**: Seed requirement (“override any action”), INV-F-11 stop-first actuation checks, LAW-16 compositional closure.  
**Threat coverage**: Latent ambiguity where “override” is interpreted as operator workflow instead of protocol invariant.  
**Verification**: Override latency drill with deny-on-uncertainty and replayed authority derivation.

```diff
--- a/documents/rfcs/RFC-0022/PRINCIPAL_SOVEREIGNTY_INTERFACE.md
+++ b/documents/rfcs/RFC-0022/PRINCIPAL_SOVEREIGNTY_INTERFACE.md
@@
 ### 6.8 Dual-Verifier Disagreement Handling
 1. For Tier2+ liveness and containment proofs under dual-verifier mode, SK MUST require two economically independent verifier receipts.
 2. If verifier verdicts disagree, or one verifier is unavailable beyond freshness window, SK MUST freeze and mark containment uncertainty.
 3. Promotion MAY resume only after independent re-verification receipts close the disagreement.
+
+### 6.9 Universal Override Derivation
+Any pending or future action MUST be overridable without introducing new depth-specific wire primitives.
+
+Pseudo-rule:
+```text
+override_scope(scope):
+  emit SovereignStopOrderV1(mode=FREEZE, scope=scope)
+  emit AutonomyLevelSet(level=L0, target=scope)
+  emit PrincipalDelegationReceiptV1 overlay_to_bottom for affected capability set
+  require override_effective_latency_ms <= 2000 for Tier3+ scope
+```
+If any override artifact is missing, stale, or unverifiable, enforcement MUST deny the targeted actuation set.
@@
 | External self-containment proof with independent verifier economics | PHY-06, PHY-08 | LAW-01, LAW-08, LAW-15 | INV-F-14, INV-F-15 | PRIN-068, PRIN-082, PRIN-101 | MECH-GATES, MECH-EVALUATOR-AUDIT | independent assurance lane in governance model |
+| Universal per-scope override derivation | PHY-04, PHY-05 | LAW-05, LAW-16 | INV-F-11, INV-F-14 | PRIN-038, PRIN-094 | MECH-OCAP, MECH-EMERGENCY-STOP | `FIN-GATE-STOP-STATE`, `AUTH-GRAPH-001` |
```

---

### Remaining Gaps (after applying above diffs)

1. RFC-0022 directory packaging is still incomplete versus repo RFC conventions (`00_meta.yaml`, trust-boundary/governance/rollout/ticket YAML companions).  
2. `proto/kernel_events.proto` still needs the actual wire changes from Section 5 (and changelog/version bump), then replay-equivalence evidence regeneration.  
3. Evidence skeletons for new gates/objects (`GATE-PSI-BOUNDED-DECODE`, `GATE-PSI-KILL-CONVERGENCE`, new summary predicates) must be created before claiming RELEASE readiness.