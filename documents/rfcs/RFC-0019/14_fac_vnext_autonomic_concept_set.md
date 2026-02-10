# RFC-0019 Addendum - FAC vNext Autonomic Concept Set (Revision 14, PCAC-Profiled)

Status: Draft (concept synthesis, PCAC-profiled)
Supersedes: `documents/rfcs/RFC-0019/13_fac_vnext_autonomic_concept_set.md`
Primary objective: re-specify FAC vNext concepts as profile constraints over RFC-0027 lifecycle semantics (`join -> revalidate -> consume -> effect`).

## 1. Scope

In scope:
- Refactoring `C14-*` concepts onto PCAC stage predicates.
- Explicit lifecycle-stage and fail-closed contracts for FAC promotion logic.
- Unified gate sequence alignment across chapter 14, chapter 15, chapter 16, and split profile RFCs.
- Autonomic defect response loops for constrained CVE closure and RoleSpec speciation.

Out of scope:
- Replacing RFC-0027 lifecycle semantics.
- Ticket decomposition.

## 2. Imported Baseline and IDs

Imported baseline:
- `PCAC-SNAPSHOT-BASELINE-ID` from `documents/rfcs/RFC-0019/17_pcac_implementation_contract_snapshot.md`

Imported profile IDs:
- `PCAC-PROFILE-SECURITY-v1`
- `PCAC-PROFILE-EFFICIENCY-v1`

RFC-0027 remains canonical for lifecycle semantics.

## 3. Lifecycle Predicate Model (normative)

Authoritative FAC transition admissibility is defined as:

`fac_pcac_admit = pcac_join_valid && pcac_revalidate_valid && pcac_consume_valid && pcac_effect_guarded`

Cross-cutting required truths:

`pcac_single_consume_enforced && pcac_intent_digest_equal && pcac_revocation_dominant && pcac_replay_complete`

Fail-closed rule:
- any missing, stale, ambiguous, or unverifiable predicate state is `false`.

## 4. Reference Normalization Contract

All references in this chapter are fully qualified:
- requirement: `RFC-0027::REQ-0004`
- evidence: `RFC-0027::EVID-0003`

Every evidence reference includes owning RFC and canonical file path.

## 5. FAC Control Planes (normative)

FAC vNext is modeled as four coupled planes:
- `Kernel plane`: authority continuity (`RFC-0027` predicates).
- `Boundary plane`: external flow safety (capability + taint + classification + declassification).
- `Economics plane`: constrained optimization with hard safety interlocks.
- `Autonomic plane`: defect-driven adaptation with rollback and independent reverification.

Promotion theorem:
- `promotable = kernel_pass && boundary_pass && economics_pass && autonomic_pass`

## 6. C14 Concept Mapping to PCAC Stages

### `C14-01` WorkObject authority source closure

Stage coverage:
- primary: `join`
- secondary: `consume`

Core claim:
- authoritative lifecycle decisions derive from ledger/CAS `WorkObject` projection only.

Predicate:
- `c14_01_pass = pcac_join_valid && pcac_consume_valid && authority_source == ledger_projection`

Requirement anchors:
- `RFC-0027::REQ-0001`, `RFC-0027::REQ-0005`, `RFC-0027::REQ-0007`
- companion: `RFC-0018::REQ-HEF-0012`, `RFC-0018::REQ-HEF-0013`, `RFC-0019::REQ-0008`

Evidence anchors:
- `RFC-0027::EVID-0001` (`documents/rfcs/RFC-0027/evidence_artifacts/EVID-0001.yaml`)
- `RFC-0018::EVID-HEF-0013` (`documents/rfcs/RFC-0018/evidence_artifacts/EVID-HEF-0013.yaml`)

### `C14-02` Delegation meet containment and no-bypass actuation

Stage coverage:
- primary: `join`
- secondary: `consume`, `effect`

Predicate:
- `c14_02_pass = pcac_join_valid && pcac_consume_valid && delegation_meet_exact && no_bypass_path`

Requirement anchors:
- `RFC-0027::REQ-0004`, `RFC-0027::REQ-0009`, `RFC-0027::REQ-0013`
- companion: `RFC-0020::REQ-0027`, `RFC-0020::REQ-0028`, `RFC-0020::REQ-0029`, `RFC-0020::REQ-0030`

Evidence anchors:
- `RFC-0027::EVID-0003` (`documents/rfcs/RFC-0027/evidence_artifacts/EVID-0003.yaml`)
- `RFC-0020::EVID-0030` (`documents/rfcs/RFC-0020/evidence_artifacts/EVID-0030.yaml`)

### `C14-03` Temporal authority closure

Stage coverage:
- primary: `revalidate`
- secondary: `consume`

Predicate:
- `c14_03_pass = pcac_revalidate_valid && pcac_consume_valid && wall_time_invariant`

Requirement anchors:
- `RFC-0027::REQ-0003`, `RFC-0027::REQ-0008`, `RFC-0027::REQ-0010`
- companion: `RFC-0016::REQ-HTF-0003`, `RFC-0020::REQ-0018`, `RFC-0020::REQ-0019`

Evidence anchors:
- `RFC-0027::EVID-0008` (`documents/rfcs/RFC-0027/evidence_artifacts/EVID-0008.yaml`)
- `RFC-0018::EVID-HEF-0016` (`documents/rfcs/RFC-0018/evidence_artifacts/EVID-HEF-0016.yaml`)

### `C14-04` Projection non-interference gate

Stage coverage:
- primary: `effect`
- secondary: `consume` and replay verification

Predicate:
- `c14_04_pass = pcac_effect_guarded && trace_hash(projection=A) == trace_hash(projection=B)`

Requirement anchors:
- `RFC-0027::REQ-0006`, `RFC-0027::REQ-0007`
- companion: `RFC-0019::REQ-0006`, `RFC-0019::REQ-0007`, `RFC-0018::REQ-HEF-0016`

Evidence anchors:
- `RFC-0027::EVID-0006` (`documents/rfcs/RFC-0027/evidence_artifacts/EVID-0006.yaml`)
- `RFC-0019::EVID-0007` (`documents/rfcs/RFC-0019/evidence_artifacts/EVID-0007.yaml`)

### `C14-05` Verifier independence and uncertainty-qualified promotion

Stage coverage:
- primary: `consume`
- secondary: `revalidate`

Predicate:
- `c14_05_pass = pcac_consume_valid && independent_verifier_families >= policy.min && uncertainty_annotations_present`

Requirement anchors:
- `RFC-0027::REQ-0011`, `RFC-0027::REQ-0014`, `RFC-0027::REQ-0016`
- companion: `RFC-0020::REQ-0034`, `RFC-0020::REQ-0035`

Evidence anchors:
- `RFC-0027::EVID-0005` (`documents/rfcs/RFC-0027/evidence_artifacts/EVID-0005.yaml`)
- `RFC-0027::EVID-0010` (`documents/rfcs/RFC-0027/evidence_artifacts/EVID-0010.yaml`)

### `C14-06` Evidence economics thermostat

Stage coverage:
- primary: lifecycle-wide (`join`, `revalidate`, `consume`, `effect`)
- secondary: replay/recovery overlays

Predicate:
- `c14_06_pass = pcac_replay_complete && control_plane_budget_respected && selector_coverage_high_risk == 1.0`

Requirement anchors:
- `RFC-0027::REQ-0011`, `RFC-0027::REQ-0012`, `RFC-0027::REQ-0016`
- companion: `RFC-0018::REQ-HEF-0018`, `RFC-0019::REQ-0010`, `RFC-0020::REQ-0035`

Evidence anchors:
- `RFC-0027::EVID-0005` (`documents/rfcs/RFC-0027/evidence_artifacts/EVID-0005.yaml`)
- `RFC-0018::EVID-HEF-0019` (`documents/rfcs/RFC-0018/evidence_artifacts/EVID-HEF-0019.yaml`)

### `C14-07` Defect-driven RoleSpec speciation under PCAC deny taxonomy

Stage coverage:
- primary: policy plane across all stages
- secondary: `consume` deny correctness

Predicate:
- `c14_07_pass = specialization_gain && pcac_consume_deny_correctness_not_worse && rollback_on_regression`

Requirement anchors:
- `RFC-0027::REQ-0012`, `RFC-0027::REQ-0014`, `RFC-0027::REQ-0017`
- companion: `RFC-0019::REQ-0012`, `RFC-0019::REQ-0014`, `RFC-0019::REQ-0016`

Evidence anchors:
- `RFC-0027::EVID-0009` (`documents/rfcs/RFC-0027/evidence_artifacts/EVID-0009.yaml`)
- `RFC-0019::EVID-0012` (`documents/rfcs/RFC-0019/evidence_artifacts/EVID-0012.yaml`)

### `C14-08` Revocation shockwave and resurrection resistance

Stage coverage:
- primary: `revalidate`
- secondary: `consume`

Predicate:
- `c14_08_pass = pcac_revocation_dominant && post_revocation_consume_accept_rate_tier2plus == 0`

Requirement anchors:
- `RFC-0027::REQ-0008`, `RFC-0027::REQ-0003`, `RFC-0027::REQ-0010`
- companion: `RFC-0020::REQ-0018`, `RFC-0020::REQ-0019`, `RFC-0020::REQ-0035`

Evidence anchors:
- `RFC-0027::EVID-0008` (`documents/rfcs/RFC-0027/evidence_artifacts/EVID-0008.yaml`)
- `RFC-0020::EVID-0035` (`documents/rfcs/RFC-0020/evidence_artifacts/EVID-0035.yaml`)

### `C14-09` Boundary flow safety closure for external FAC surfaces

Stage coverage:
- primary: `effect`
- secondary: `join` and `consume`

Predicate:
- `c14_09_pass = capability_allow && taint_allow && classification_allow && declass_receipt_valid && pcac_projection_isolation_valid`

Requirement anchors:
- `RFC-0020::REQ-0029`, `RFC-0020::REQ-0030`, `RFC-0020::REQ-0032`, `RFC-0020::REQ-0034`
- companion: `RFC-0028::REQ-0004`, `RFC-0028::REQ-0006`, `RFC-0028::REQ-0008`

Evidence anchors:
- `RFC-0028::EVID-0004` (`documents/rfcs/RFC-0028/evidence_artifacts/EVID-0004.yaml`)
- `RFC-0028::EVID-0008` (`documents/rfcs/RFC-0028/evidence_artifacts/EVID-0008.yaml`)
- `RFC-0021::EVID-0007` (`documents/rfcs/RFC-0021/evidence_artifacts/EVID-0007.yaml`)

### `C14-10` Constrained CVE detection and autonomous remediation loop

Stage coverage:
- primary: policy/control plane
- secondary: `consume` and `effect` safety interlocks

Predicate:
- `c14_10_pass = vuln_class_allowlisted && canary_non_regression && independent_rerun_pass && rollback_contract_bound`

Requirement anchors:
- `RFC-0027::REQ-0014`, `RFC-0027::REQ-0016`
- companion: `RFC-0028::REQ-0006`, `RFC-0029::REQ-0006`, `RFC-0019::REQ-0014`

Evidence anchors:
- `RFC-0027::EVID-0010` (`documents/rfcs/RFC-0027/evidence_artifacts/EVID-0010.yaml`)
- `RFC-0029::EVID-0006` (`documents/rfcs/RFC-0029/evidence_artifacts/EVID-0006.yaml`)

## 7. Interface Contract Snapshot (spec-level)

Minimum profile object set for FAC vNext:
- `AuthorityKernelDecisionV1`
- `BoundaryFlowPolicyV1`
- `ProjectionDiffProofV1`
- `DelegationMeetComputationReceiptV1`
- `AutonomicRemediationContractV1`
- `EconomicsConstraintProfileV1`
- `RecoverabilityProfileV1`
- `RoleSpecSpeciationRecordV1`

Each object MUST be digest-addressable and receipt-linked.

## 8. Unified Gate Sequence

- Gate 1: `GATE-PCAC-SNAPSHOT-VALIDITY`
- Gate 2: `GATE-SIO28-LIFECYCLE` + `GATE-SIO28-BOUNDARY-FLOW`
- Gate 3: `GATE-SIO28-DELEGATION-MEET-EXACTNESS`
- Gate 4: `GATE-SIO28-PROJECTION-ISOLATION`
- Gate 5: `GATE-SIO28-PROJECTION-COMPROMISE-CONTAINMENT`
- Gate 6: `GATE-SIO28-PROJECTION-NONINTERFERENCE`
- Gate 7: `GATE-SIO28-VERIFIER-INDEPENDENCE`
- Gate 8: `GATE-EIO29-BOUNDS` + `GATE-EIO29-INTERLOCK`
- Gate 9: `GATE-EIO29-PROJECTION-ISOLATION-INTERLOCK`
- Gate 10: `GATE-EIO29-PROJECTION-SINK-CONTINUITY`
- Gate 11: `GATE-EIO29-QUEUE-STABILITY`
- Gate 12: `GATE-EIO29-REDUNDANCY-RECOVERABILITY`
- Gate 13: `GATE-EIO29-RECONSTRUCTION-ADMISSIBILITY`
- Gate 14: `GATE-FAC-AUTOREMEDIATION-CANARY`
- Gate 15: `GATE-FAC-AUTOREMEDIATION-INDEPENDENT-RERUN`
- Gate 16: `GATE-SIO-PROFILE-SYNC` + `GATE-EIO-PROFILE-SYNC`

All gates fail closed.

## 9. Test Portfolio (minimum)

- Lifecycle conformance: every authority-bearing external flow emits ordered stage receipts.
- Missing-stage deny: any missing lifecycle stage denies effect acceptance.
- Delegation widening denial at recursion depth `>= 4`.
- Delegation meet exactness across independent verifier recomputation.
- Wall-time perturbation invariance at Tier2+.
- Revocation frontier advance denies stale consumes.
- Projection mode non-interference on authoritative trace hash.
- Projection compromise containment with trust-root pinning and quarantine/replay-safe recovery.
- Boundary taint/classification deny on policy violations.
- Digest-first budget conformance and selector coverage `== 1.0` for high-risk claims.
- Adversarial queue-pressure preserves stop/revocation critical-path SLOs.
- Projection-sink independence: projection state mutation cannot change authoritative FAC decisions.
- 30-day projection sink outage continuity with bounded deferred replay convergence.
- Mandatory-tier erasure+BFT reconstruction admissibility under corruption/loss drills.
- Constrained autopatch canary + rollback behavior under synthetic CVE drills.

## 10. Summary

Revision 14 now treats FAC as a PCAC-profiled autonomic controller. RFC-0027 owns lifecycle semantics; this chapter binds FAC constraints, external-boundary safety, economics interlocks, and constrained autonomous remediation into a single fail-closed promotion model.
