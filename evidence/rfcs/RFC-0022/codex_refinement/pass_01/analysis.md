### Change 1: Add Constitutional Admissibility Layer Above Principal Authority

**Rationale**: The draft makes principal sovereignty top-ranked, but strategy-level humanitarian deny constraints are not explicitly executed before sovereignty checks. This creates ambiguity between `MASTER_STRATEGY.json` governance and PSI enforcement.  
**Constraints preserved**: Keeps RFC-0020 dominance order (`containment > verification > liveness`) for admissible actions; strengthens INV-F-14 by adding a pre-gate deny-set.  
**Threat coverage**: Governance capture, harmful-but-authorized directives, precedence confusion.  
**Verification**: Add a governance predicate enforcing constitutional precheck + HTF-only gate truth.

```diff
--- a/documents/rfcs/RFC-0022/PRINCIPAL_SOVEREIGNTY_INTERFACE.md
+++ b/documents/rfcs/RFC-0022/PRINCIPAL_SOVEREIGNTY_INTERFACE.md
@@
 ## 0.2 Rejected Design Options (Normative Rationale)
@@
 4. **Audit through autonomous projection APIs:** Rejected. Violates LAW-05 accountability axis and allows mediation attacks.
 
 ---
+
+## 0.3 Constitutional Admissibility and Dominance Execution (Normative)
+Principal sovereignty is exercised over admissible actions only.
+
+Constitutional admissibility precheck:
+1. Any action violating mission-level humanitarian deny predicates is denied regardless of principal seal, quorum, or liveness pressure.
+2. Any action violating containment deny predicates is denied.
+
+Dominance execution for admissible actions:
+1. Containment/security constraints.
+2. Verification/correctness constraints.
+3. Liveness/progress optimizations.
+
+Time authority execution rule:
+1. HTF artifacts are the only admissible time authority for sovereignty gate truth.
+2. Wall-clock fields are observational metadata only.
+3. Missing/stale/parse-invalid HTF artifacts are automatic deny outcomes.
+
+Reference predicate:
+```bash
+jq -e '.constitutional_admissibility_enforced == true and .dominance_order == ["containment_security","verification_correctness","liveness_progress"] and .htf_time_authority_enforced == true and .wall_clock_used_for_gate_truth == false and .unknown_state_fail_closed == true' \
+  evidence/rfcs/RFC-0022/governance/PSI-GOV-ORDER-001/summary.json
+```
+
+---
@@
 ### 2.4 Precedence Rule
-If control decisions conflict, SK MUST apply:
-1. Containment/security constraints.
-2. Verification/correctness constraints.
-3. Liveness/progress optimizations.
+If control decisions conflict, SK MUST execute:
+0. Constitutional admissibility precheck (mission-level humanitarian deny + containment deny).
+1. Containment/security constraints.
+2. Verification/correctness constraints.
+3. Liveness/progress optimizations.
```

---

### Change 2: Convert Objectives Into Full Contract Surface (Baseline/Boundary/Owner/Evidence)

**Rationale**: Current objective table has predicates but lacks baseline capture refs, owner locus, HTF boundary authority, and explicit evidence path per objective.  
**Constraints preserved**: LAW-01, LAW-09, INV-F-15 (machine-checkable promotion), RFC-0021-style contract rigor.  
**Threat coverage**: Narrative-only compliance claims, unverifiable “pass” assertions.  
**Verification**: Add objective contract registry table with executable predicates.

```diff
--- a/documents/rfcs/RFC-0022/PRINCIPAL_SOVEREIGNTY_INTERFACE.md
+++ b/documents/rfcs/RFC-0022/PRINCIPAL_SOVEREIGNTY_INTERFACE.md
@@
 ### 1.2 Objective Contracts
 PSI adopts and tightens these machine-checkable objectives:
@@
 | OBJ-PSI-06 Self-containment proof | `exists verifier outside trust boundary: verify(containment_proof)=true` | Internal-only proof is non-compliant |
+
+### 1.3 Objective Contract Registry (Normative)
+Every objective MUST bind baseline capture, target predicate, HTF boundary, owner locus, and evidence path.
+
+| Objective | Baseline Capture Ref | HTF Boundary | Owner / Decision Locus | Machine Predicate | Evidence Path |
+|---|---|---|---|---|---|
+| OBJ-PSI-01 | `PSI-BL-STOP-2026-02-06` | `HTF-BND-P1-SECURITY-CLOSE` | Security Council + Runtime Council | `jq -e '.stop_propagation_p99_ms <= 2000 and .deny_uncertainty_p99_ms <= 250 and .hardware_cut_independence == true and .unknown_state_count == 0 and .signature_valid == true' evidence/rfcs/RFC-0022/objectives/OBJ-PSI-01/summary.json` | `evidence/rfcs/RFC-0022/objectives/OBJ-PSI-01/` |
+| OBJ-PSI-02 | `PSI-BL-LIVENESS-2026-02-06` | `HTF-BND-P2-EARLY-CLOSE` | Security Council | `jq -e '.epoch_liveness_coverage == 1.0 and .missing_liveness_epoch_count == 0 and .false_pass_count == 0 and .unknown_state_count == 0' evidence/rfcs/RFC-0022/objectives/OBJ-PSI-02/summary.json` | `evidence/rfcs/RFC-0022/objectives/OBJ-PSI-02/` |
+| OBJ-PSI-03 | `PSI-BL-AUTONOMY-2026-02-06` | `HTF-BND-P2-CLOSE` | Governance Council + Verification Council | `jq -e '.action_over_ceiling_count == 0 and .epoch_cumulative_risk_overflow_count == 0 and .uncertainty_regression_correctness == 1.0 and .unknown_state_count == 0' evidence/rfcs/RFC-0022/objectives/OBJ-PSI-03/summary.json` | `evidence/rfcs/RFC-0022/objectives/OBJ-PSI-03/` |
+| OBJ-PSI-04 | `PSI-BL-AUDIT-2026-02-06` | `HTF-BND-P2-SEMANTICS-CLOSE` | Audit Council + Verification Council | `jq -e '.single_action_proof_complexity == "O(log n)" and .audit_completeness_failures == 0 and .omission_proof_coverage == 1.0 and .unknown_state_count == 0' evidence/rfcs/RFC-0022/objectives/OBJ-PSI-04/summary.json` | `evidence/rfcs/RFC-0022/objectives/OBJ-PSI-04/` |
+| OBJ-PSI-05 | `PSI-BL-HW-KEY-2026-02-06` | `HTF-BND-P2-CONTROL-CLOSE` | Security Council | `jq -e '.tier3plus_softkey_usage == 0 and .attestation_freshness_failures == 0 and .unknown_state_count == 0' evidence/rfcs/RFC-0022/objectives/OBJ-PSI-05/summary.json` | `evidence/rfcs/RFC-0022/objectives/OBJ-PSI-05/` |
+| OBJ-PSI-06 | `PSI-BL-CONTAINMENT-2026-02-06` | `HTF-BND-P3-CLOSE` | Security Council + External Assurance Lane | `jq -e '.external_verifier_coverage == 1.0 and .internal_only_proof_count == 0 and .expired_proof_uses == 0 and .unknown_state_count == 0' evidence/rfcs/RFC-0022/objectives/OBJ-PSI-06/summary.json` | `evidence/rfcs/RFC-0022/objectives/OBJ-PSI-06/` |
+
+All objective predicates fail closed on missing fields, parse errors, stale boundaries, invalid signatures, or unknown states.
 
 ---
```

---

### Change 3: Add Missing Wire Artifacts for Revocation, Hardware Kill Proof, and Capsule Integrity

**Rationale**: Revocation, physical kill independence, and principal-side capsule integrity are referenced but not fully protocolized as first-class artifacts.  
**Constraints preserved**: RFC-0020 proof-carrying effects, strict freshness, and auditability floors; INV-F-11 and INV-F-14.  
**Threat coverage**: Key compromise persistence, fake kill-path health, capsule tamper invisibility.  
**Verification**: Add new schemas + epoch seal bindings + gates.

```diff
--- a/documents/rfcs/RFC-0022/PRINCIPAL_SOVEREIGNTY_INTERFACE.md
+++ b/documents/rfcs/RFC-0022/PRINCIPAL_SOVEREIGNTY_INTERFACE.md
@@
 ### 4.9 SovereigntyEpochSealV1
 ```yaml
 schema_id: apm2.sovereignty_epoch_seal.v1
 epoch_id: string
 cell_id: CellIdV1
 time_envelope_ref: TimeEnvelopeRef
 quorum_anchor: string
 directory_head_hash: CasDigest
 revocation_head_hash: CasDigest
+principal_revocation_head_hash: CasDigest
 autonomy_state_root_hash: CasDigest
 halt_path_liveness_proof_hash: CasDigest
+hardware_kill_activation_receipt_hash: CasDigest
+capsule_integrity_proof_hash: CasDigest
+containment_proof_bundle_hash: CasDigest
 fact_root_hash: CasDigest
 authority_seal_hash: AuthoritySealRef
 ```
 Constraints:
 1. MUST be monotonic by `(time_envelope_ref, quorum_anchor)` for a cell.
 2. MUST include `halt_path_liveness_proof_hash` for epochs where autonomy is enabled above L0.
+3. Tier2+ epochs MUST include non-null `principal_revocation_head_hash`, `hardware_kill_activation_receipt_hash`, and `capsule_integrity_proof_hash`.
+4. Missing any required Tier2+ sovereignty hash is equivalent to containment uncertainty and triggers freeze.
@@
 ### 4.13 ContainmentProofBundleV1
@@
 Constraints:
 1. Bundle MUST cover all active sovereignty-critical binaries and policy roots.
 2. Partial coverage is non-compliant for Tier2+ autonomy.
+
+### 4.14 PrincipalRevocationRecordV1
+```yaml
+schema_id: apm2.principal_revocation_record.v1
+revocation_id: string
+principal_id: string
+revoked_keyset_id: KeySetIdV1
+replacement_keyset_id: KeySetIdV1 | null
+reason_code: COMPROMISE | ROTATION | LOST_DEVICE | POLICY_REKEY | OTHER
+effective_tick: uint64
+sovereignty_epoch: uint64
+challenge_nonce: bytes
+issued_time_envelope_ref: TimeEnvelopeRef
+authority_seal_hash: AuthoritySealRef
+```
+Constraints:
+1. `sovereignty_epoch` MUST be strictly monotonic per principal.
+2. Revocation record freshness failure is an automatic Tier2+ deny.
+3. Revocation uncertainty is revocation-wins and MUST fail closed.
+
+### 4.15 HardwareKillActivationReceiptV1
+```yaml
+schema_id: apm2.hardware_kill_activation_receipt.v1
+activation_id: string
+actuator_id: string
+actuator_firmware_measurement_hash: CasDigest
+actuator_attestation_hash: CasDigest
+activation_edge_tick: uint64
+scope_selector_hash: CasDigest
+independent_power_domain: bool
+independent_control_network: bool
+hardware_path_proof_hash: CasDigest
+time_envelope_ref: TimeEnvelopeRef
+verifier_identity_proof_hash: IdentityProofRef
+verifier_seal_hash: AuthoritySealRef
+```
+Constraints:
+1. Receipt MUST be generated from out-of-band control plane, not daemon runtime path.
+2. Tier3+ `mode=KILL` requires `independent_power_domain=true` and `independent_control_network=true`.
+3. Missing hardware receipt during active kill order is non-compliant and triggers freeze.
+
+### 4.16 CapsuleIntegrityProofV1
+```yaml
+schema_id: apm2.capsule_integrity_proof.v1
+proof_id: string
+cell_id: CellIdV1
+capsule_profile_id: string
+capsule_profile_hash: CasDigest
+namespace_layout_hash: CasDigest
+seccomp_profile_hash: CasDigest
+cgroup_limit_hash: CasDigest
+runtime_attestation_hash: CasDigest
+time_envelope_ref: TimeEnvelopeRef
+verifier_identity_proof_hash: IdentityProofRef
+verdict: PASS | FAIL
+verifier_seal_hash: AuthoritySealRef
+```
+Constraints:
+1. Tier2+ operation requires latest epoch `CapsuleIntegrityProofV1` with `verdict=PASS`.
+2. Missing/stale capsule integrity proof is a hard deny for Tier2+ actuation.
 
 ---
```

---

### Change 4: Tighten Schema-Level Freshness, Identity Proof-Carrying, and Audit Completeness

**Rationale**: Several sovereignty-critical objects are missing proof-carrying identity links, anti-replay coupling, and omission-proof fields.  
**Constraints preserved**: RFC-0020 self-certifying identity + freshness floors, LAW-09/LAW-15, INV-F-08/INV-F-11.  
**Threat coverage**: Replay, stale authority, partial audit omission, unproven stop acks.  
**Verification**: Extend schema constraints and gate predicates.

```diff
--- a/documents/rfcs/RFC-0022/PRINCIPAL_SOVEREIGNTY_INTERFACE.md
+++ b/documents/rfcs/RFC-0022/PRINCIPAL_SOVEREIGNTY_INTERFACE.md
@@
 ### 4.4 AutonomyPolicyV1
 ```yaml
@@
 per_epoch_budget_ceiling:
   max_tool_calls: Quantity
   max_wall_ms: Quantity
   max_cpu_ms: Quantity
   max_bytes_io: Quantity
   max_evidence_bytes: Quantity
+max_cumulative_risk_score: Quantity
@@
 Constraints:
 1. `max_risk_tier` MUST monotonically increase with level number.
 2. `downgrade_triggers` MUST include freshness uncertainty and revocation uncertainty for L2+.
+3. `downgrade_triggers` MUST include cumulative-risk overflow for L2+.
 3. `requires_principal_approval=true` is mandatory at L0.
@@
 ### 4.6 SovereignStopOrderV1
 ```yaml
@@
 issued_by_principal_id: string
 issuer_key_id: PublicKeyIdV1
+issuer_identity_proof_hash: IdentityProofRef
+issuer_hardware_attestation_hash: CasDigest | null
 sovereignty_epoch: uint64
 challenge_nonce: bytes
@@
 min_required_acks: uint32
+scope_cardinality_hint: uint64
+required_ack_coverage_ratio: Quantity
 authority_seal_hash: AuthoritySealRef
 ```
 Constraints:
 1. `mode=KILL` MUST require principal root signer.
-2. Tier3+ must set `require_hardware_path=true`.
-3. Unknown stop state at enforcement point triggers deny in <=250ms.
+2. At least one of `require_hardware_path` or `require_software_path` MUST be true; Tier3+ MUST set both true.
+3. Tier3+ requires non-null `issuer_hardware_attestation_hash`.
+4. `min_required_acks` MUST be >=1 and MUST NOT exceed `scope_cardinality_hint`.
+5. Tier3+ GLOBAL stop requires `required_ack_coverage_ratio == 1.0`.
+6. Unknown stop state at enforcement point triggers deny in <=250ms.
@@
 ### 4.7 SovereignStopAckV1
 ```yaml
@@
 actor_id: string
+actor_identity_proof_hash: IdentityProofRef
 cell_id: CellIdV1
@@
 node_attestation_hash: CasDigest
+path_attestation_hash: CasDigest
 ack_time_envelope_ref: TimeEnvelopeRef
 ack_signature_or_seal_hash: AuthoritySealRef
 ```
 Constraints:
 1. `propagation_latency_ms` contributes to halt-path SLO computation.
 2. Invalid attestation for Tier3+ acks marks ack non-authoritative.
+3. Tier2+ authoritative ack requires valid `actor_identity_proof_hash`.
@@
 ### 4.8 HaltPathLivenessProofV1
 ```yaml
@@
 proof_id: string
 epoch_seal_hash: CasDigest
 probe_plan_hash: CasDigest
+challenge_nonce: bytes
+challenge_issued_envelope_ref: TimeEnvelopeRef
 sampled_ack_multiproof_hash: CasDigest
@@
 verifier_identity_proof_hash: IdentityProofRef
+verifier_independence_attestation_hash: CasDigest
 verdict: PASS | FAIL
 time_envelope_ref: TimeEnvelopeRef
 verifier_seal_hash: AuthoritySealRef
 ```
 Constraints:
 1. PASS requires p99 propagation <=2000ms and deny-on-uncertainty <=250ms at Tier3+.
-2. Missing proof in epoch is equivalent to FAIL and triggers freeze.
+2. Tier3+ PASS requires `hardware_reachability_ratio == 1.0` and `software_reachability_ratio == 1.0`.
+3. `challenge_nonce` MUST match epoch challenge context and MUST be single-use.
+4. Missing/stale/replayed proof in epoch is equivalent to FAIL and triggers freeze.
@@
 ### 4.10 SovereignAuditRequestV1
 ```yaml
@@
 request_id: string
+request_nonce: bytes
 principal_identity_proof_hash: IdentityProofRef
 principal_authority_seal_hash: AuthoritySealRef
@@
 query_selector_hash: CasDigest
+required_epoch_id: string | null
+query_lower_seq: uint64 | null
+query_upper_seq: uint64 | null
 max_proof_bytes: uint64
 include_confidential_payloads: bool
@@
 Constraints:
 1. Request must authenticate principal identity and freshness.
 2. Query selectors must be deterministic and bounded.
+3. If `query_lower_seq`/`query_upper_seq` are set, response MUST prove contiguous coverage and omission.
@@
 ### 4.11 SovereignAuditResponseV1
 ```yaml
@@
 request_id: string
 request_digest: CasDigest
+response_nonce_echo: bytes
+served_epoch_id: string
+ledger_head_hash: CasDigest
 result_root_hash: CasDigest
 receipt_pointers: [ReceiptPointerRef]
 receipt_multiproof_hash: CasDigest
 fact_inclusion_multiproof_hash: CasDigest
+omission_multiproof_hash: CasDigest
 causal_parent_links_hash: CasDigest
 completeness_attestation_hash: CasDigest
 proof_complexity_class: O_LOG_N | O_LOG_N_PLUS_K
 classification_manifest_hash: CasDigest
+declassification_receipt_hashes: [CasDigest]
 time_envelope_ref: TimeEnvelopeRef
 responder_seal_hash: AuthoritySealRef
 ```
 Constraints:
 1. `proof_complexity_class` MUST be verifiable by profile metadata.
-2. Response without completeness attestation is advisory only and non-authoritative.
+2. `response_nonce_echo` MUST equal request nonce.
+3. Ranged queries require valid omission proof plus contiguous coverage proof.
+4. If confidential payloads are returned, `declassification_receipt_hashes` MUST be non-empty.
+5. Response without completeness attestation is advisory only and non-authoritative.
```

---

### Change 5: Make Kernel Event Integration Wire-Concrete (Tags + Payload Contracts)

**Rationale**: Section 5.2 is currently descriptive only; publication-quality RFC needs explicit tag allocation and payload hash bindings.  
**Constraints preserved**: RFC-0020 canonicalization/versioning and digest-first boundary semantics.  
**Threat coverage**: Event-shape drift, ambiguous implementations, cross-cell semantic mismatch.  
**Verification**: Deterministic proto tag tests + replay-equivalence receipts.

```diff
--- a/documents/rfcs/RFC-0022/PRINCIPAL_SOVEREIGNTY_INTERFACE.md
+++ b/documents/rfcs/RFC-0022/PRINCIPAL_SOVEREIGNTY_INTERFACE.md
@@
 ### 5.2 New Event Shapes (Proposed for `proto/kernel_events.proto`)
-Add events under `KernelEvent.payload` (new tags reserved by governance):
-1. `SovereignStopOrderIssued`
-2. `SovereignStopAckRecorded`
-3. `AutonomyLevelSet`
-4. `AutonomyViolationDetected`
-5. `SovereigntyEpochSealed`
-6. `SovereignAuditServed`
-7. `ContainmentProofPublished`
-8. `PrincipalIdentityRotated`
+Reserve payload tags `35..45` for PSI and bind by digest to Section 4 objects:
+```proto
+message SovereignStopOrderIssued { string stop_order_id = 1; bytes stop_order_hash = 2; optional TimeEnvelopeRef time_envelope_ref = 3; }
+message SovereignStopAckRecorded { string ack_id = 1; bytes ack_hash = 2; optional TimeEnvelopeRef time_envelope_ref = 3; }
+message AutonomyLevelSet { string target_id = 1; uint32 level = 2; bytes policy_hash = 3; optional TimeEnvelopeRef time_envelope_ref = 4; }
+message AutonomyViolationDetected { string violation_id = 1; bytes violation_receipt_hash = 2; uint32 risk_tier = 3; optional TimeEnvelopeRef time_envelope_ref = 4; }
+message SovereigntyEpochSealed { string epoch_id = 1; bytes epoch_seal_hash = 2; optional TimeEnvelopeRef time_envelope_ref = 3; }
+message SovereignAuditServed { string request_id = 1; bytes response_hash = 2; optional TimeEnvelopeRef time_envelope_ref = 3; }
+message ContainmentProofPublished { string proof_id = 1; bytes proof_hash = 2; optional TimeEnvelopeRef time_envelope_ref = 3; }
+message PrincipalIdentityRotated { string principal_id = 1; bytes principal_identity_hash = 2; optional TimeEnvelopeRef time_envelope_ref = 3; }
+message PrincipalRevocationRecorded { string revocation_id = 1; bytes revocation_hash = 2; optional TimeEnvelopeRef time_envelope_ref = 3; }
+message HardwareKillActivated { string activation_id = 1; bytes activation_receipt_hash = 2; optional TimeEnvelopeRef time_envelope_ref = 3; }
+message CapsuleIntegrityProved { string proof_id = 1; bytes capsule_integrity_hash = 2; optional TimeEnvelopeRef time_envelope_ref = 3; }
+```
+
+`KernelEvent.payload` additions:
+1. `SovereignStopOrderIssued` = 35
+2. `SovereignStopAckRecorded` = 36
+3. `AutonomyLevelSet` = 37
+4. `AutonomyViolationDetected` = 38
+5. `SovereigntyEpochSealed` = 39
+6. `SovereignAuditServed` = 40
+7. `ContainmentProofPublished` = 41
+8. `PrincipalIdentityRotated` = 42
+9. `PrincipalRevocationRecorded` = 43
+10. `HardwareKillActivated` = 44
+11. `CapsuleIntegrityProved` = 45
```

---

### Change 6: Correct and Harden Enforcement Algorithms (Field Mismatches + Missing Checks)

**Rationale**: There are schema/algorithm mismatches (`verifier_identity` vs `verifier_identity_proof_hash`, `per_epoch_budget` naming), and missing checks for challenge freshness, omission proofs, and cumulative risk.  
**Constraints preserved**: LAW-13 (typed/canonical), LAW-15, INV-F-05/08/11.  
**Threat coverage**: Replay, stale liveness proofs, audit truncation, composition-based capability creep.  
**Verification**: Unit tests for algorithm contracts + adversarial replay suites.

```diff
--- a/documents/rfcs/RFC-0022/PRINCIPAL_SOVEREIGNTY_INTERFACE.md
+++ b/documents/rfcs/RFC-0022/PRINCIPAL_SOVEREIGNTY_INTERFACE.md
@@
 ### 6.2 Autonomy Admission Check
@@
   require action.risk_tier <= autonomy_policy[L_eff].max_risk_tier
   require action.capability in autonomy_policy[L_eff].capability_ceiling
-  require cumulative_epoch_budget_after(action) <= autonomy_policy[L_eff].per_epoch_budget
+  require cumulative_epoch_budget_after(action) <= autonomy_policy[L_eff].per_epoch_budget_ceiling
+  require cumulative_epoch_risk_after(action) <= autonomy_policy[L_eff].max_cumulative_risk_score
   require stop_state_fresh_and_valid()
   return allow
@@
 ### 6.4 Halt Path Liveness Verification
@@
 verify_halt_liveness(epoch):
   proof = fetch(HaltPathLivenessProofV1)
   if missing(proof): freeze_global
-  require verify_external_verifier(proof.verifier_identity)
+  require verify_identity_proof(proof.verifier_identity_proof_hash)
+  require verify_verifier_independence(proof.verifier_independence_attestation_hash)
+  require proof.challenge_nonce == epoch.challenge_nonce
+  require nonce_unused(proof.challenge_nonce)
+  require proof.time_envelope_ref within epoch.freshness_window
   require proof.propagation_p99_ms <= 2000ms
   require proof.deny_uncertainty_p99_ms <= 250ms
+  require proof.hardware_reachability_ratio == 1.0 for Tier3+ scope
+  require proof.software_reachability_ratio == 1.0 for Tier3+ scope
   require proof.verdict == PASS
   seal_epoch_with(proof)
@@
 ### 6.5 Sovereign Audit Verification
@@
 verify_audit_response(resp):
   require verify_completeness_attestation(resp)
+  require resp.response_nonce_echo == request.request_nonce
+  require resp.served_epoch_id >= request.required_epoch_id when set
   require verify_multiproof(resp.receipt_multiproof_hash, resp.result_root_hash)
   require verify_fact_inclusion(resp.fact_inclusion_multiproof_hash)
-  require complexity_profile(resp) <= O(log n)
+  require verify_omission_multiproof(resp.omission_multiproof_hash) for ranged queries
+  require verify_declassification_receipts(resp.declassification_receipt_hashes) when confidential payloads included
+  require complexity_profile(resp) == O(log n) for single-action queries
+  require complexity_profile(resp) <= O(log n + k) for k-result batch queries
   return verified_causal_history
@@
 ### 6.6 Revocation Correctness
@@
 3. Revocation latency SLO is tracked per epoch and is release-blocking for Tier2+ autonomy claims.
+
+### 6.7 Global Fail-Closed Conditions
+Sovereignty enforcement MUST deny (and freeze for Tier2+) when any authority-bearing path is:
+1. Missing required artifact.
+2. Parse-invalid or schema-invalid.
+3. Signature/seal invalid.
+4. Freshness-invalid or revocation-uncertain.
+5. Unknown/indeterminate predicate result.
```

---

### Change 7: Add Missing Threat Classes for Infrastructure Sovereignty and Verifier Capture

**Rationale**: Threat model omits provider/control-plane compromise and verifier economic capture despite explicit seed and LAW-08 emphasis.  
**Constraints preserved**: LAW-05, LAW-08, INV-F-14, strategy infrastructure sovereignty posture.  
**Threat coverage**: Cloud operator subversion, verifier collusion, false-safe attestations.  
**Verification**: Add dedicated gates and chaos drills.

```diff
--- a/documents/rfcs/RFC-0022/PRINCIPAL_SOVEREIGNTY_INTERFACE.md
+++ b/documents/rfcs/RFC-0022/PRINCIPAL_SOVEREIGNTY_INTERFACE.md
@@
 | TM-PSI-09 Governance downgrade attack | Lower gate rigor by policy manipulation | Signed policy bundles, anti-downgrade checks, containment precedence | Block transition and require principal seal |
 | TM-PSI-10 Verifier economics exhaustion | Proof amplification DoS | Multiproof batching, bounded proof sizes, verifier cache contracts | Backpressure deny and defect |
+| TM-PSI-11 Infrastructure sovereignty compromise | Cloud/control-plane actor blocks or forges stop path | Out-of-band control network, independent power cut path, hardware kill activation receipts, control-domain diversity checks | Freeze and regress to L0_ONLY_COMPAT until re-attested |
+| TM-PSI-12 External verifier capture/collusion | Verifier economically or administratively dependent on subject runtime | Verifier independence attestation, dual-verifier disagreement freeze, periodic verifier rotation receipts | Block promotion and require independent re-verification |
```

---

### Change 8: Expand Gate Portfolio Into Executable Governance Contracts

**Rationale**: Current gates lack owner locus, HTF boundary linkage, and explicit evidence paths per gate.  
**Constraints preserved**: LAW-01 loop closure, LAW-15 measurement integrity, INV-F-15 promotion discipline.  
**Threat coverage**: Subjective gate operation, policy bypass, weak auditability of gate outcomes.  
**Verification**: Add gate registry with predicates and fail-closed conditions.

```diff
--- a/documents/rfcs/RFC-0022/PRINCIPAL_SOVEREIGNTY_INTERFACE.md
+++ b/documents/rfcs/RFC-0022/PRINCIPAL_SOVEREIGNTY_INTERFACE.md
@@
 ## 8. Governance Gate Portfolio (Normative)
@@
 | GATE-PSI-OVERHEAD-BUDGET | T | S1 | `added_cpu_p99<=1% && added_net<=1%` | Exceeds overhead contract | benchmark receipts |
+| GATE-PSI-HW-INDEPENDENCE | T | S0 | `hardware_kill_activation_receipt_valid == true && independent_control_network == true` | Hardware path not independently provable | `HardwareKillActivationReceiptV1` |
+| GATE-PSI-CAPSULE-INTEGRITY | T | S0 | `latest_capsule_integrity_proof_verdict == "PASS"` | Missing/stale/failed capsule integrity proof | `CapsuleIntegrityProofV1` |
+| GATE-PSI-VERIFIER-INDEPENDENCE | D/T | S0 | `verifier_independence_attestation_valid == true` | Verifier inside subject trust/economic boundary | verifier independence receipt |
 
-Fail-closed rule: any S0 gate failure freezes Tier2+ promotion and enforces containment-first posture.
+### 8.1 Gate Contract Registry (Normative)
+| Gate ID | Owner / Decision Locus | HTF Boundary | Machine Predicate | Evidence Path |
+|---|---|---|---|---|
+| GATE-PSI-HALT-PATH | Security Council + Runtime Council | `HTF-BND-P1-SECURITY-CLOSE` | `jq -e '.propagation_p99_ms <= 2000 and .deny_uncertainty_p99_ms <= 250 and .unknown_state_count == 0' evidence/rfcs/RFC-0022/gates/GATE-PSI-HALT-PATH/summary.json` | `evidence/rfcs/RFC-0022/gates/GATE-PSI-HALT-PATH/` |
+| GATE-PSI-HW-ATTESTATION | Security Council | `HTF-BND-P2-CONTROL-CLOSE` | `jq -e '.tier3plus_softkey_usage == 0 and .attestation_freshness_failures == 0 and .unknown_state_count == 0' evidence/rfcs/RFC-0022/gates/GATE-PSI-HW-ATTESTATION/summary.json` | `evidence/rfcs/RFC-0022/gates/GATE-PSI-HW-ATTESTATION/` |
+| GATE-PSI-CONTAINMENT-PROOF | Security Council + External Assurance | `HTF-BND-P3-CLOSE` | `jq -e '.valid_external_containment_proof == true and .internal_only_proof_count == 0 and .unknown_state_count == 0' evidence/rfcs/RFC-0022/gates/GATE-PSI-CONTAINMENT-PROOF/summary.json` | `evidence/rfcs/RFC-0022/gates/GATE-PSI-CONTAINMENT-PROOF/` |
+| GATE-PSI-AUDIT-COMPLETENESS | Audit Council + Verification Council | `HTF-BND-P2-SEMANTICS-CLOSE` | `jq -e '.audit_completeness_failures == 0 and .omission_proof_coverage == 1.0 and .unknown_state_count == 0' evidence/rfcs/RFC-0022/gates/GATE-PSI-AUDIT-COMPLETENESS/summary.json` | `evidence/rfcs/RFC-0022/gates/GATE-PSI-AUDIT-COMPLETENESS/` |
+
+Fail-closed rule:
+1. Any S0 gate failure freezes Tier2+ promotion and enforces containment-first posture.
+2. Missing, stale, parse-invalid, signature-invalid, or unknown states are hard denies.
+3. Lower-precedence gates MUST NOT override containment/security denies.
```

---

### Change 9: Add HTF-Bound Stage Contract Ledger and Rollback Rules to Rollout

**Rationale**: Stage list is good but not fully operationalized with entry/exit boundary authority, mandatory gates, and rollback triggers.  
**Constraints preserved**: LAW-09 (time-scoped authority), INV-F-14 dominance.  
**Threat coverage**: Silent progression with incomplete controls, unclear rollback under uncertainty.  
**Verification**: Stage transitions become machine-checkable.

```diff
--- a/documents/rfcs/RFC-0022/PRINCIPAL_SOVEREIGNTY_INTERFACE.md
+++ b/documents/rfcs/RFC-0022/PRINCIPAL_SOVEREIGNTY_INTERFACE.md
@@
 ## 9. Rollout Plan and Migration (Normative)
+
+### 9.0 Stage Contract Ledger (Normative)
+| Stage | Entry Boundary | Exit Boundary | Mandatory Gates | Rollback Trigger |
+|---|---|---|---|---|
+| S0 | `HTF-BND-P1-BASELINE-LOCK` | `HTF-BND-P1-SECURITY-CLOSE` | `GATE-PSI-REVOCATION-FRESHNESS` | Any delegation narrowing violation or unknown authority edge |
+| S1 | `HTF-BND-P1-SECURITY-CLOSE` | `HTF-BND-P1-CLOSE` | `GATE-PSI-AUTONOMY-CEILING`, `GATE-PSI-AUTONOMY-CUMULATIVE` | Any over-ceiling action or unknown L_eff component |
+| S2 | `HTF-BND-P1-CLOSE` | `HTF-BND-P2-EARLY-CLOSE` | `GATE-PSI-HALT-PATH`, `GATE-PSI-LIVENESS-EPOCH` | Missing liveness proof or false-pass drill |
+| S3 | `HTF-BND-P2-EARLY-CLOSE` | `HTF-BND-P2-CONTROL-CLOSE` | `GATE-PSI-HW-ATTESTATION` | Tier3+ soft-key usage or stale attestation |
+| S4 | `HTF-BND-P2-CONTROL-CLOSE` | `HTF-BND-P2-CONTROL-CLOSE` | `GATE-PSI-HW-INDEPENDENCE`, `GATE-PSI-CAPSULE-INTEGRITY` | Hardware path non-independence or capsule proof failure |
+| S5 | `HTF-BND-P2-CONTROL-CLOSE` | `HTF-BND-P2-SEMANTICS-CLOSE` | `GATE-PSI-CONTAINMENT-PROOF`, `GATE-PSI-VERIFIER-INDEPENDENCE` | Internal-only containment proof or verifier capture |
+| S6 | `HTF-BND-P2-SEMANTICS-CLOSE` | `HTF-BND-P3-CLOSE` | `GATE-PSI-REVOCATION-FRESHNESS`, `GATE-PSI-AUTONOMY-CEILING` | Revocation miss count > 0 |
+| S7 | `HTF-BND-P3-CLOSE` | `HTF-BND-P3-CLOSE` | `GATE-PSI-AUDIT-COMPLETENESS`, `GATE-PSI-OVERHEAD-BUDGET` | Audit completeness failure or economics breach |
+
+Transition deny rule: missing boundary artifact, invalid signature, stale boundary, or unknown-state summary is automatic deny.
 
 ### Stage S0 - Principal Identity Bootstrap (software key, constrained)
```

---

### Change 10: Strengthen Acceptance Bar (Unknown-State Fail-Closed + Complexity Split)

**Rationale**: Acceptance section should explicitly define advancement bar and disallow hidden unknown-state acceptance; also distinguish single-action `O(log n)` from batch `O(log n + k)`.  
**Constraints preserved**: INV-F-15, LAW-07, LAW-15.  
**Threat coverage**: Acceptance with partial evidence, complexity overclaims, stale governance acceptance.  
**Verification**: Expand acceptance predicates.

```diff
--- a/documents/rfcs/RFC-0022/PRINCIPAL_SOVEREIGNTY_INTERFACE.md
+++ b/documents/rfcs/RFC-0022/PRINCIPAL_SOVEREIGNTY_INTERFACE.md
@@
 ## 10. Acceptance Criteria (Normative)
 PSI is accepted only when all criteria pass simultaneously.
+
+### 10.0 Acceptance Bar For RFC-0022 Advancement
+To move from DRAFT to GROUNDED:
+1. Deterministic verifier implementations exist for all S0 gates.
+2. One end-to-end sovereign stop drill proves both hardware and software path integrity with signed receipts.
+3. One adversarial replay suite proves nonce/freshness fail-closed behavior across stop, revocation, and audit paths.
+
+To move from GROUNDED to RELEASE:
+1. Stage S0..S7 exit predicates all pass at declared HTF boundaries.
+2. No open S0 gate failures in latest governance window.
+3. Independent verifier coverage and verifier-independence checks are both complete.
@@
 ### 10.5 Suggested Machine Predicates
 Representative acceptance predicate bundle:
 ```bash
 jq -e '
@@
   .obj_psi_05_pass == true and
   .obj_psi_06_pass == true and
   .gate_s0_failures == 0 and
+  .unknown_state_count == 0 and
+  .constitutional_admissibility_enforced == true and
+  .verifier_independence_pass == true and
+  .capsule_integrity_pass == true and
   .proof_complexity.identity == "O(log n)" and
-  .proof_complexity.audit == "O(log n)" and
+  .proof_complexity.audit_single_action == "O(log n)" and
+  .proof_complexity.audit_batch == "O(log n + k)" and
   .bft_overhead_pct_p99 <= 1.0 and
   .bisimulation_depth12_pass_rate >= 0.99 and
   .revocation_miss_count == 0
 ' evidence/rfcs/RFC-0022/acceptance/summary.json
 ```
```

---

### Change 11: Replace Coarse Ticket Seed With Dependency-Ordered Atomic Decomposition

**Rationale**: Current ticket list is useful but too coarse for implementation planning and audit mapping.  
**Constraints preserved**: LAW-01 loop closure, INV-F-02 gate receipt discipline.  
**Threat coverage**: Partial implementations that appear complete, untestable integration coupling.  
**Verification**: Each ticket gets acceptance predicate + evidence path + dependency edge.

```diff
--- a/documents/rfcs/RFC-0022/PRINCIPAL_SOVEREIGNTY_INTERFACE.md
+++ b/documents/rfcs/RFC-0022/PRINCIPAL_SOVEREIGNTY_INTERFACE.md
@@
-## 14. Initial Ticket Seed (Normative)
-1. `TCK-PSI-0001`: Define and validate schemas for sections 4.2 through 4.13.
-2. `TCK-PSI-0002`: Implement delegation meet verifier and strict narrowing denial path.
-3. `TCK-PSI-0003`: Implement autonomy semilattice evaluator and regression triggers.
-4. `TCK-PSI-0004`: Add sovereign stop events and pre-actuation stop guard enforcement.
-5. `TCK-PSI-0005`: Implement halt path sentinel and epoch liveness proof integration.
-6. `TCK-PSI-0006`: Integrate hardware attestation checks for Tier3+ sovereignty operations.
-7. `TCK-PSI-0007`: Implement sovereign audit request/response with multiproof verification.
-8. `TCK-PSI-0008`: Build external containment verifier pipeline and proof publication.
-9. `TCK-PSI-0009`: Add gate portfolio evaluators and fail-closed governance bindings.
-10. `TCK-PSI-0010`: Run scale, bisimulation, and overhead acceptance suite.
+## 14. Initial Ticket Decomposition (Normative)
+| Ticket | Depends On | Scope | Acceptance Predicate | Evidence Path |
+|---|---|---|---|---|
+| `TCK-PSI-0001` | none | Schema registry for all PSI v1 objects (including 4.14-4.16) | `schema_validation_pass_ratio == 1.0` | `evidence/rfcs/RFC-0022/tickets/TCK-PSI-0001/` |
+| `TCK-PSI-0002` | `0001` | Delegation meet verifier + strict narrowing denial | `delegation_narrowing_violations == 0` | `evidence/rfcs/RFC-0022/tickets/TCK-PSI-0002/` |
+| `TCK-PSI-0003` | `0001` | Principal revocation record pipeline + revocation head publication | `revocation_miss_count == 0` | `evidence/rfcs/RFC-0022/tickets/TCK-PSI-0003/` |
+| `TCK-PSI-0004` | `0001` | Sovereign stop order/ack path with proof-carrying identities | `stop_ack_authoritative_ratio == 1.0` | `evidence/rfcs/RFC-0022/tickets/TCK-PSI-0004/` |
+| `TCK-PSI-0005` | `0004` | Hardware kill activation receipt path (out-of-band) | `hardware_cut_independence == true` | `evidence/rfcs/RFC-0022/tickets/TCK-PSI-0005/` |
+| `TCK-PSI-0006` | `0004` | Halt path sentinel challenge/response + replay defense | `false_pass_count == 0` | `evidence/rfcs/RFC-0022/tickets/TCK-PSI-0006/` |
+| `TCK-PSI-0007` | `0001` | Capsule integrity proof ingestion and epoch binding | `capsule_integrity_failures == 0` | `evidence/rfcs/RFC-0022/tickets/TCK-PSI-0007/` |
+| `TCK-PSI-0008` | `0001` | Autonomy semilattice evaluator + cumulative risk accounting | `action_over_ceiling_count == 0 and epoch_cumulative_risk_overflow_count == 0` | `evidence/rfcs/RFC-0022/tickets/TCK-PSI-0008/` |
+| `TCK-PSI-0009` | `0001` | Sovereign audit request/response with omission proofs | `audit_completeness_failures == 0` | `evidence/rfcs/RFC-0022/tickets/TCK-PSI-0009/` |
+| `TCK-PSI-0010` | `0001` | External containment verifier + verifier-independence attestation | `internal_only_proof_count == 0 and verifier_independence_pass == true` | `evidence/rfcs/RFC-0022/tickets/TCK-PSI-0010/` |
+| `TCK-PSI-0011` | `0004`,`0005`,`0006` | Kernel event wire integration for tags 35..45 | `event_replay_equivalence_ratio == 1.0` | `evidence/rfcs/RFC-0022/tickets/TCK-PSI-0011/` |
+| `TCK-PSI-0012` | `0002`..`0011` | Governance gate evaluator + fail-closed matrix implementation | `unknown_state_fail_closed == true` | `evidence/rfcs/RFC-0022/tickets/TCK-PSI-0012/` |
+| `TCK-PSI-0013` | `0012` | Rollout boundary harness and transition-deny checks | `stage_transition_invalid_count == 0` | `evidence/rfcs/RFC-0022/tickets/TCK-PSI-0013/` |
+| `TCK-PSI-0014` | `0013` | Scale/bisimulation/overhead/adversarial acceptance suite | `acceptance_suite_pass == true` | `evidence/rfcs/RFC-0022/tickets/TCK-PSI-0014/` |
```

---

### Change 12: Expand Theory Traceability With Physics + Strategy Binding

**Rationale**: Current matrix binds laws/invariants/principles but omits explicit physics and strategy contract linkage; this weakens “physics over theory over strategy” traceability chain.  
**Constraints preserved**: Unified theory foundational ordering; strategy contract alignment without overriding theory.  
**Threat coverage**: Drift between RFC semantics and strategic governance contracts.  
**Verification**: Matrix-based traceability audits.

```diff
--- a/documents/rfcs/RFC-0022/PRINCIPAL_SOVEREIGNTY_INTERFACE.md
+++ b/documents/rfcs/RFC-0022/PRINCIPAL_SOVEREIGNTY_INTERFACE.md
@@
 ## 12. Theory Binding Matrix (Normative Traceability)
 
-| PSI Feature | Laws | Invariants | Principles | Mechanisms |
-|---|---|---|---|---|
-| Sovereignty lattice and strict delegation meet | LAW-05, LAW-14, LAW-16 | INV-F-05, INV-F-14 | PRIN-038, PRIN-071, PRIN-094 | MECH-OCAP, MECH-PERMEABILITY-RECEIPT |
-| Hardware-rooted principal authority | LAW-05, LAW-15 | INV-F-11, INV-F-14 | PRIN-036, PRIN-037 | MECH-ROOT-OF-TRUST, MECH-ATTESTATION |
-| Stop-path liveness loop and auto-freeze | LAW-01, LAW-12, LAW-15 | INV-F-11, INV-F-14 | PRIN-063, PRIN-067 | MECH-EMERGENCY-STOP, MECH-GATES |
-| Temporal revocation correctness | LAW-09, LAW-15 | INV-F-08, INV-F-14 | PRIN-030, PRIN-050 | MECH-FRESHNESS-POLICY, MECH-ANTI-ENTROPY |
-| O(log n) sovereign audit proofs | LAW-03, LAW-07, LAW-15 | INV-F-01, INV-F-12, INV-F-13 | PRIN-045, PRIN-046, PRIN-092 | MECH-RECEIPTS, MECH-EVIDENCE-TIERING |
-| Prompt-injection and label-safe sovereignty boundary | LAW-05, LAW-08, LAW-15 | INV-F-05, INV-F-10, INV-F-14 | PRIN-089, PRIN-090, PRIN-091 | MECH-POLICY, MECH-MONITOR-ISOLATION |
-| External self-containment proof | LAW-01, LAW-08, LAW-15 | INV-F-14, INV-F-15 | PRIN-068, PRIN-082, PRIN-101 | MECH-GATES, MECH-EVALUATOR-AUDIT |
+| PSI Feature | Physics Constraints | Laws | Invariants | Principles | Mechanisms | Strategy Contracts |
+|---|---|---|---|---|---|---|
+| Sovereignty lattice and strict delegation meet | PHY-05, PHY-06 | LAW-05, LAW-14, LAW-16 | INV-F-05, INV-F-14 | PRIN-038, PRIN-071, PRIN-094 | MECH-OCAP, MECH-PERMEABILITY-RECEIPT | `AUTH-GRAPH-001`, `MET-AUTHORITY-GRAPH-COVERAGE` |
+| Hardware-rooted principal authority + revocation | PHY-04, PHY-05 | LAW-05, LAW-09, LAW-15 | INV-F-08, INV-F-11, INV-F-14 | PRIN-036, PRIN-037 | MECH-ROOT-OF-TRUST, MECH-ATTESTATION, MECH-FRESHNESS-POLICY | `PRINCIPAL-ROOT-ANVEIO`, `REVOCATION-AUTHORITY-ROOT-001` |
+| Stop-path liveness loop and auto-freeze | PHY-04, PHY-05 | LAW-01, LAW-12, LAW-15 | INV-F-11, INV-F-14 | PRIN-063, PRIN-067 | MECH-EMERGENCY-STOP, MECH-GATES | `FIN-GATE-STOP-STATE`, `MET-TRUST-LATENCY-P95` |
+| Capsule integrity and non-bypass containment | PHY-05 | LAW-05, LAW-15 | INV-F-05, INV-F-14 | PRIN-091, PRIN-092 | MECH-SUBTASK-ISOLATION, MECH-MONITOR-ISOLATION | containment security posture in `MASTER_STRATEGY` |
+| O(log n) sovereign audit proofs with omission evidence | PHY-08, PHY-09 | LAW-03, LAW-07, LAW-15 | INV-F-01, INV-F-12, INV-F-13 | PRIN-045, PRIN-046, PRIN-092 | MECH-RECEIPTS, MECH-EVIDENCE-TIERING, MECH-COMPACTION | `VERIF-EVID-001` |
+| Prompt-injection and dual-lattice boundary | PHY-05 | LAW-05, LAW-08, LAW-15 | INV-F-05, INV-F-10, INV-F-14 | PRIN-089, PRIN-090, PRIN-091 | MECH-POLICY, MECH-MONITOR-ISOLATION | security policy `SP-RUNTIME-003`, `SP-RUNTIME-004` |
+| External self-containment proof with independent verifier economics | PHY-06, PHY-08 | LAW-01, LAW-08, LAW-15 | INV-F-14, INV-F-15 | PRIN-068, PRIN-082, PRIN-101 | MECH-GATES, MECH-EVALUATOR-AUDIT | independent assurance lane in governance model |
```

---

### Remaining Gaps (Post-Patch)

1. The RFC still references implementation artifacts under `evidence/rfcs/RFC-0022/...` that do not yet exist; those evidence schemas and directory contracts should be created in the implementation phase.  
2. If this RFC is expected to follow split-RFC structure (`03_trust_boundaries.yaml`, `06_ticket_decomposition.yaml`, `09_governance_and_gates.yaml`) like adjacent RFCs, that decomposition should be added as a follow-up package.  
3. Post-quantum migration is intentionally out of scope; if release horizon extends, add a crypto-agility annex before final freeze.