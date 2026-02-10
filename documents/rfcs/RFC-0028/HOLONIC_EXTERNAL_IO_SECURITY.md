# RFC-0028 - Holonic External I/O Security Profile over PCAC

Status: DRAFT (profile-definition phase)
Profile ID: `PCAC-PROFILE-SECURITY-v1`
Primary objective: define fail-closed security constraints for external I/O over RFC-0027 lifecycle semantics without redefining PCAC.

## 1. Normative Import Set

Canonical lifecycle semantics:
- `RFC-0027::REQ-0001 .. RFC-0027::REQ-0018`
- source path: `documents/rfcs/RFC-0027/PROOF_CARRYING_AUTHORITY_CONTINUITY.md`

Imported baseline contract:
- `PCAC-SNAPSHOT-BASELINE-ID`
- source path: `documents/rfcs/RFC-0019/17_pcac_implementation_contract_snapshot.md`

Companion constraints:
- `RFC-0020::REQ-0002`, `RFC-0020::REQ-0003`, `RFC-0020::REQ-0004`
- `RFC-0020::REQ-0018`, `RFC-0020::REQ-0019`, `RFC-0020::REQ-0027`, `RFC-0020::REQ-0028`, `RFC-0020::REQ-0029`, `RFC-0020::REQ-0030`, `RFC-0020::REQ-0032`, `RFC-0020::REQ-0034`, `RFC-0020::REQ-0035`
- `RFC-0016::REQ-HTF-0003`, `RFC-0016::REQ-HTF-0007`
- `RFC-0021::REQ-0013`
- `RFC-0019::REQ-0007`

Import safety rule:
- unresolved or semantically ambiguous imported constraints are non-admissible for promotion-critical paths.

## 2. Formal Security Model

### 2.1 State and Transition Objects

Security state tuple:
- `S = (join_state, revalidate_state, consume_state, effect_state, revocation_frontier, delegation_state, boundary_flow_state, projection_state, crypto_state, time_authority_state, drift_state)`

Required lifecycle order:
- `join -> revalidate -> consume -> effect`

Fail-closed verdict rule:
- if any required field is missing, stale, unknown, or unverifiable, decision is `deny`.

### 2.2 Core Security Predicates

A profile-conformant authority-bearing external flow MUST satisfy:
- `pcac_join_valid`
- `pcac_revalidate_valid`
- `pcac_consume_valid`
- `pcac_effect_guarded`
- `pcac_single_consume_enforced`
- `pcac_intent_digest_equal`
- `pcac_revocation_dominant`
- `pcac_replay_complete`
- `delegation_meet_exact_valid`
- `boundary_flow_admissible`
- `pcac_trade_secret_mode_valid`
- `pcac_projection_isolation_valid`
- `projection_compromise_contained`
- `time_authority_envelope_valid`
- `promotion_temporal_ambiguity == false`

Security theorem (profile level):
- authoritative external effect is admissible iff all predicates above are true.

### 2.3 Shared Temporal Contract Ownership

Temporal predicates consumed by this security profile are shared contracts:
- `TP-EIO29-001` (`time_authority_envelope_valid`)
- `TP-EIO29-008` (`promotion_temporal_ambiguity == false`)

Ownership rule:
- canonical semantic anchor: RFC-0016 temporal substrate semantics.
- canonical profile-contract ownership: RFC-0019 snapshot/matrix temporal contract surfaces.
- RFC-0029 section 3 is an execution/evaluation profile mirror for temporal-economics composition, not the sole ownership source for security admission.

### 2.4 Cross-Profile Temporal Predicate Arbitration

Security-plane temporal evaluation MUST bind to the same canonical evaluator tuple used by cross-profile consumers:
- `(evaluator_id, predicate_id, contract_digest_set, canonicalizer_tuple, time_authority_ref, window_ref, verdict, deny_reason)`

Arbitration outcomes for shared predicates (`TP-EIO29-001`, `TP-EIO29-008`):
- `ARBITRATION_AGREED_ALLOW`
- `ARBITRATION_AGREED_DENY`
- `ARBITRATION_DISAGREEMENT_TRANSIENT`
- `ARBITRATION_DISAGREEMENT_PERSISTENT`

Required behavior:
- `ARBITRATION_AGREED_ALLOW`: continue gate flow.
- `ARBITRATION_AGREED_DENY`: fail-closed deny.
- `ARBITRATION_DISAGREEMENT_TRANSIENT`: enter freeze (`S3`), require adjudication receipt before `temporal_arbitration_deadline_window_ref`.
- `ARBITRATION_DISAGREEMENT_PERSISTENT`: fail-closed deny plus mandatory evaluator/policy rebaseline workflow.

This arbitration is predicate-level and precedes mode-ladder arbitration.

## 3. Lifecycle Threat Algebra and Invariants

Threat algebra:
- `T_flow = T_join union T_revalidate union T_consume union T_effect`
- admissibility requires `forall t in T_flow, mitigated(t) == true`.

Mandatory invariants:
- `INV-SIO28-01`: `consume_count(ajc_id) <= 1`
- `INV-SIO28-02`: `consume.intent_digest == effect.intent_digest`
- `INV-SIO28-03`: revocation dominance at revalidate and consume
- `INV-SIO28-04`: no-bypass effect path
- `INV-SIO28-05`: temporal ambiguity denial (shared temporal contracts `TP-EIO29-001` and `TP-EIO29-008` satisfied)
- `INV-SIO28-06`: projection surface never becomes authority input
- `INV-SIO28-07`: delegation is exact meet, never widening
- `INV-SIO28-08`: disclosure-control policy constraints are non-regressible hard constraints (mode is phase-qualified; default posture: trade-secret-only)

## 4. Delegation Meet Exactness Contract

Delegation authority vectors:
- parent `A`
- overlay `O`
- delegated `D`

Exact meet contract:
- `D == meet(A, O)` across all constrained dimensions:
  - capabilities
  - scope
  - risk tier ceiling
  - budgets
  - stop predicates
  - expiry
  - taint floor
  - confidentiality ceiling
  - required sanitizers
  
Restriction order and meet operators (promotion-critical canonical form):
- capabilities: set intersection under subset order.
- scope: set intersection under subset order.
- risk tier ceiling: numeric minimum under `<=`.
- budgets: per-budget numeric minimum under `<=`.
- stop predicates: conjunction of normalized predicate clauses.
- expiry: minimum expiry tick under `<=`.
- taint floor: maximum taint floor under `>=` (higher floor is more restrictive).
- confidentiality ceiling: minimum admissible disclosure class under `<=`.
- required sanitizers: set union under subset order (cannot remove required sanitizer constraints).

Lineage integrity is not a lattice dimension:
- `delegation_lineage_hash` is validated as an independent chain-integrity predicate (`lineage_chain_integrity_valid`), not via meet algebra.

Delegation satisfiability requirement:
- `delegation_satisfiable(D) == true` is mandatory for promotion-critical delegation.
- satisfiability proof MUST demonstrate at least one non-empty admissible workset under `D` (capability + scope + budget + temporal validity + stop predicates).
- meet outputs that are algebraically valid but vacuously restrictive (`admissible_workset == empty`) are non-admissible.

Depth and computation bounds:
- `delegation_depth(D) <= delegation_max_depth` is mandatory for promotable delegation chains.
- satisfiability evaluation MUST complete within `delegation_satisfiability_budget_ticks`.
- depth overflow or satisfiability-budget exhaustion is non-admissible.

Determinism contract:
- `delegation_meet_exact_v1` must return identical output for identical canonical inputs across verifier implementations.
- promotion-critical arithmetic MUST be integer/tick-space only; floating-point arithmetic is non-admissible.
- canonical equality is byte-for-byte equality of canonicalized payload bytes (not semantic equivalence-only).
- hash-equality is admissible only when hash domain separation includes `schema_id` and `schema_major`; collision ambiguity is fail-closed deny.

Falsification obligations:
- widening attempt at any depth is deny.
- independent verifier disagreement is deny.
- non-computable field is deny.
- lineage chain integrity mismatch is deny.
- vacuous delegation admitted as promotable is deny.
- delegation depth above `delegation_max_depth` admitted as promotable is deny.
- satisfiability-budget exhaustion treated as allow is deny.

## 5. Cryptography and Trust Surface Precision

### 5.1 Signature Algorithm Agility and Downgrade Resistance

Mandatory object:
- `CryptoAgilityPolicyV1` with algorithm allowlist by epoch and risk tier.

Rules:
- authority-bearing paths may use only algorithms explicitly admissible for active policy epoch.
- downgrade from stronger to weaker algorithm requires explicit signed policy transition and must be non-promotable for Tier2+ unless independent security adjudication clears it.
- unknown algorithm identifiers are deny.

### 5.2 Key Rotation and Identity Continuity

Mandatory continuity evidence:
- overlap signatures between retiring and new keyset.
- keyset descriptor digest and validity window bound to temporal authority.

Unsafe rotation indicators:
- abrupt key replacement without overlap evidence.
- key epoch mismatch in authority receipts.

Any unsafe indicator denies promotion-critical operations.

### 5.3 Key Compromise Response and Retroactive Trust Invalidation

Compromise windows (tick-space):
- `W_detect`, `W_revoke`, `W_reseal`

Required behavior:
- detect within `W_detect`
- revoke within `W_revoke`
- reseal mandatory artifacts within `W_reseal`

Retroactive invalidation:
- receipts signed solely by compromised keys after compromise epoch are non-trusted.
- receipts before compromise epoch require corroboration by independent non-compromised verifier evidence for continued use in promotion-critical decisions.

### 5.4 Post-Compromise Recovery Guarantees

Recovery admission requires:
- fresh policy root
- reverified authority chain
- replay over affected windows
- explicit `PostCompromiseRecoveryReceiptV1`

Any missing component is fail-closed deny.

## 6. Boundary Flow Safety and Leakage Budget

Boundary admissibility:
- `boundary_admit = capability_allow and taint_allow and classification_allow and declass_receipt_valid`

Redundancy-purpose declassification:
- `declass_reason = REDUNDANCY_PURPOSE` is admissible only for coded redundancy fragments required by recoverability policy.
- redundancy-purpose declassification MUST carry `redundancy_declassification_receipt` and MUST NOT expose authority-bearing plaintext semantics beyond required fragment metadata.
- unknown or unscoped redundancy declassification intent is fail-closed deny.

Information leakage budget:
- `L_boundary(window_ref) <= L_boundary_max(risk_tier)`

Typed leakage contract:
- `L_boundary` unit: `leakage_bits` (integer upper bound on permitted boundary leakage per window).
- leakage estimators MUST declare estimator family and confidence metadata in signed receipts.
- unknown estimator semantics or unit ambiguity is fail-closed deny.

Timing side-channel containment:
- authority-critical gate outcomes exposed to projection surfaces MUST be release-bucketed to fixed tick boundaries.
- promotion-critical denial/allow timing variance above `timing_channel_budget_ticks` is treated as leakage-budget violation.
- timing-channel violations emit structured defects and quarantine affected projection paths until mitigated.

Leakage overrun behavior:
- emit structured defect
- quarantine affected boundary channel
- block promotion-critical paths until declassification adjudication receipts are admitted.

## 7. Projection Authority Isolation and Compromise Containment

### 7.1 Isolation Contract

Principal classes:
- `agent_runtime`
- `projection_worker`

Forbidden direct capability classes for production `agent_runtime`:
- `github_api:*`
- `gh_cli:*`
- `forge_org_admin:*`
- `forge_repo_admin:*`

Profile binding:
- this profile is explicitly bound to the implemented GitHub projection surface.
- additional sink families require explicit policy extension and evidence admission before becoming promotion-admissible.

Isolation predicates:
- `agent_direct_projection_forbidden`
- `projection_write_admit`
- `pcac_projection_isolation_valid`

Stage policy:
- `GH-DIRECT-STAGE-0` dev compatibility only
- `GH-DIRECT-STAGE-1` production deny-by-default
- `GH-DIRECT-STAGE-2` hard deny for production direct GitHub actuation

Unknown stage state fails closed to `GH-DIRECT-STAGE-2`.

### 7.2 Compromise Containment Contract

Projection compromise detection:
- `projection_compromise_detected = observed_projection_digest != expected_projection_digest_from_ledger`

Containment predicate:
- `projection_compromise_contained = projection_compromise_detected -> (trust_root_pinned and projection_channel_quarantined and authoritative_flow_continues)`

### 7.3 Sink Identity, Rotation, and DNS Hijack Handling

Mandatory object:
- `SinkIdentitySnapshotV1` with endpoint and key binding proofs.

Rules:
- sink identity changes require signed snapshot transition.
- key rotation requires overlap and epoch continuity checks.
- DNS binding mismatch or endpoint digest mismatch triggers immediate quarantine and deny for projection effects.

## 8. Federation and Split-Brain Security Semantics

### 8.1 Partition-Tolerance Truth Table

| Topology | Revocation certainty | Delegation certainty | Security Outcome |
|---|---|---|---|
| Local quorum intact, remote lag | high local, uncertain remote | local only | local allow with remote import restrictions |
| Split-brain truth planes | conflicting | conflicting | freeze + deny promotion |
| Revocation channel partitioned | low | uncertain | deny consume for affected scopes |
| Projection-only partition | unaffected | unaffected | truth-plane continues, projection effects quarantined as needed |

### 8.2 Revocation-Wins Merge Rule

For conflicting frontier claims `rf_a`, `rf_b`:
- merged frontier `rf_merge(scope) = max(rf_a(scope), rf_b(scope))`

No authority admission is permitted while merged frontier is unresolved for relevant scope.

## 9. Degradation and Halt Security Policy

Security mode ladder:
- `S0` nominal
- `S1` constrained degrade
- `S2` continuity-only
- `S3` fail-closed freeze
- `S4` emergency halt

Security-specific constraints:
- no mode may permit bypass of `pcac_consume_valid` or boundary-flow checks.
- freeze duration bounded by `max_fail_closed_freeze_windows`.
- freeze budget exhaustion escalates to `S4` and blocks promotion.
- `S3` MAY permit bounded evidence-regeneration/time-authority-recovery workflows that cannot authorize new external effects.

Halt/deadlock distinction:
- halt is explicit policy state.
- deadlock is lack of progress without explicit halt and must emit dedicated defect signal.

Cross-profile joint-state rule:
- effective operating state is joint tuple `(S_i, D_j)`.
- arbitration uses typed dominance comparator (`mode_dominance_select`) over `(profile_id, mode_symbol, severity_class)` tuples; unresolved comparator state is fail-closed deny.
- security constraints always dominate when policies conflict.
- canonical joint-state arbitration contract is maintained in RFC-0019 cross-RFC gate-order contract; this 2-profile projection is a specialization of the RFC-0019 multi-profile composition algebra.

## 10. Human and Organizational Failure Modes

Modeled mistakes:
- wrong boundary ID
- stale policy deployment
- incorrect sink identity mapping
- accidental use of display-clock data as authority input
- malformed degradation policy changes

Mandatory UX constraints:
- authority fields accept only typed HTF references and signed object digests.
- display-clock values are visually and semantically isolated from authority input controls.
- risky policy updates require semantic diff preview and explicit dual approval.

## 11. Evidence Quality Requirements

Security claims require:
- adversarial tests with declared statistical power and sample plan
- reproducibility across hardware/runtime classes
- freshness SLAs with auto-expiry

Evidence freshness behavior:
- stale security evidence transitions gate to `BLOCKED` and denies promotion.

## 12. Inter-RFC Semantic Drift Contract

Normative compatibility surfaces:
- RFC-0016 temporal semantics
- RFC-0019 snapshot and gate-order contracts
- RFC-0028 security predicates and gates
- RFC-0029 temporal and economics interlock predicates

Semantic diff classes:
- `NON_SEMANTIC`
- `SEMANTIC_SAFE`
- `SEMANTIC_RISKY`
- `AMBIGUOUS`

Policy:
- `SEMANTIC_RISKY` and `AMBIGUOUS` are non-promotable.
- ambiguity must be adjudicated before `semantic_drift_deadline_window_ref`; timeout is fail-closed deny.

## 13. RFC-0028 Requirement Profile (Stable Namespace)

- `RFC-0028::REQ-0001` intent typing and acceptance-fact separation.
- `RFC-0028::REQ-0002` identity/freshness/revocation closure.
- `RFC-0028::REQ-0003` delegation meet exactness and no-bypass closure.
- `RFC-0028::REQ-0004` context integrity and dual-lattice flow safety.
- `RFC-0028::REQ-0005` portable reverification and deterministic replay.
- `RFC-0028::REQ-0006` downgrade resistance and adversarial economics fail-closed posture.
- `RFC-0028::REQ-0007` disclosure-control policy interlock (default trade-secret-only posture).
- `RFC-0028::REQ-0008` direct GitHub authority elimination for production agent runtimes.
- `RFC-0028::REQ-0009` projection compromise detection and containment.

This revision tightens semantics while preserving requirement IDs.

## 14. Gate Registry and CAC Contract Binding

### 14.1 Gate Registry

- `GATE-SIO28-SNAPSHOT`
  - blocks on snapshot drift.
- `GATE-SIO28-TIME-AUTHORITY`
  - enforces shared temporal contracts `TP-EIO29-001` and `TP-EIO29-008` (deny-on-ambiguity).
- `GATE-SIO28-LIFECYCLE`
  - blocks on lifecycle predicate failure.
- `GATE-SIO28-DELEGATION-MEET-EXACTNESS`
  - blocks on meet mismatch, verifier disagreement, or unsatisfiable delegation output.
- `GATE-SIO28-CONSUME`
  - blocks on intent mismatch, duplicate consume, or prerequisite bypass.
- `GATE-SIO28-REVOCATION`
  - blocks on stale/revoked authority acceptance; permits only authority-reduction stop/revoke fallback under local emergency monotonic-time proof when full envelope validity is unavailable.
- `GATE-SIO28-EFFECT`
  - blocks on acceptance-fact incompleteness.
- `GATE-SIO28-BOUNDARY-FLOW`
  - blocks on capability/taint/classification/declassification failures.
- `GATE-SIO28-PROJECTION-NONINTERFERENCE`
  - blocks on authoritative trace divergence under equivalent authoritative inputs.
- `GATE-SIO28-VERIFIER-INDEPENDENCE`
  - blocks on unacceptable shared-failure dependency correlation.
- `GATE-SIO28-TRADE-SECRET`
  - blocks on trade-secret control regression.
- `GATE-SIO28-PROJECTION-ISOLATION`
  - blocks on direct GitHub authority reintroduction.
- `GATE-SIO28-PROJECTION-COMPROMISE-CONTAINMENT`
  - blocks on missing/invalid compromise containment evidence.
- `GATE-SIO28-CRYPTO-AGILITY`
  - blocks on algorithm downgrade risk or stale key-epoch policy.
- `GATE-SIO28-POST-COMPROMISE-RECOVERY`
  - blocks on incomplete re-proof after key compromise.
- `GATE-SIO28-OPERATOR-SAFETY`
  - blocks on unresolved operator-error class findings for promotion-critical paths.
- `GATE-SIO28-EVIDENCE-QUALITY`
  - blocks on insufficient statistical power, reproducibility, or evidence freshness.
- `GATE-SIO28-SEMANTIC-DRIFT`
  - blocks on `SEMANTIC_RISKY` or `AMBIGUOUS` cross-RFC drift.

All gates are fail-closed.

### 14.2 CAC Contract Registry (Security Plane)

Each `GATE-SIO28-*` gate MUST declare `required_cac_inputs[]` and validate each input as:
- `(kind, schema_id, schema_major, canonicalizer_id, canonicalizer_version, digest, signature_set, window_or_ttl_ref)`

`required_cac_inputs[]` MUST resolve through CAC schema registry artifacts (`kind = schema.definition`) and must be bound to the same canonicalization vectors used by the active snapshot (`PCAC-SNAPSHOT-BASELINE-ID`).

| Gate | `required_cac_inputs[]` (`kind -> schema_id`) | Digest and canonicalizer binding |
|---|---|---|
| `GATE-SIO28-SNAPSHOT` | `snapshot.report -> apm2.pcac_snapshot_report.v1` | `snapshot_digest` MUST cover all required object digests and carry `canonicalizer_id`/`canonicalizer_version`. |
| `GATE-SIO28-TIME-AUTHORITY` | `time.envelope -> apm2.time_authority_envelope.v1`, `temporal.evaluator -> apm2.temporal_predicate_evaluator.v1`, `temporal.disagreement.receipt -> apm2.temporal_disagreement_receipt.v1`, `temporal.arbitration.receipt -> apm2.temporal_arbitration_receipt.v1` | `contract_digest_set` MUST include envelope + evaluator digests; disagreement/arbitration receipts MUST be digest-bound to the same predicate bundle and canonicalizer tuple. |
| `GATE-SIO28-LIFECYCLE` | `authority.kernel.decision -> apm2.authority_kernel_decision.v1` | lifecycle receipt digest set MUST bind join/revalidate/consume/effect receipts to one canonicalizer tuple. |
| `GATE-SIO28-DELEGATION-MEET-EXACTNESS` | `delegation.meet.receipt -> apm2.delegation_meet_computation_receipt.v1`, `delegation.satisfiability.receipt -> apm2.delegation_satisfiability_receipt.v1` | meet input/output digests MUST be verifier-recomputable under identical canonicalization vectors; satisfiability receipt MUST prove non-empty admissible workset. |
| `GATE-SIO28-CONSUME` | `authority.kernel.decision -> apm2.authority_kernel_decision.v1` | consume digest MUST equal effect intent digest in the same `contract_digest_set`. |
| `GATE-SIO28-REVOCATION` | `time.envelope -> apm2.time_authority_envelope.v1`, `revocation.frontier.snapshot -> apm2.revocation_frontier_snapshot.v1`, `local.time.emergency.receipt? -> apm2.local_monotonic_emergency_time_receipt.v1` | revocation frontier digest MUST be fresh for referenced HTF window; local emergency receipt is required only when full envelope validity is unavailable. Fallback is admissible only for authority-reduction stop/revoke actions and MUST deny any authority-expansion path. |
| `GATE-SIO28-EFFECT` | `authority.kernel.decision -> apm2.authority_kernel_decision.v1` | acceptance-fact digest set MUST be complete; missing digest entry denies. |
| `GATE-SIO28-BOUNDARY-FLOW` | `boundary.flow.policy -> apm2.boundary_flow_policy.v1` | flow policy digest MUST match admitted policy root digest and canonicalizer tuple. |
| `GATE-SIO28-PROJECTION-NONINTERFERENCE` | `projection.diff.proof -> apm2.projection_diff_proof.v1` | projected and authoritative trace digests MUST be computed from the same canonicalizer vectors. |
| `GATE-SIO28-VERIFIER-INDEPENDENCE` | `verifier.independence.profile -> apm2.verifier_independence_profile.v1` | independence profile digest MUST bind dependency graph hash + correlation thresholds. |
| `GATE-SIO28-TRADE-SECRET` | `trade.secret.policy -> apm2.trade_secret_policy_profile.v1` | trade-secret policy digest MUST match active policy epoch root. |
| `GATE-SIO28-PROJECTION-ISOLATION` | `projection.isolation.policy -> apm2.projection_isolation_policy.v1` | capability-surface digest and policy digest MUST cohere under one canonicalizer tuple. |
| `GATE-SIO28-PROJECTION-COMPROMISE-CONTAINMENT` | `projection.compromise.signal -> apm2.projection_compromise_signal.v1`, `source.trust.snapshot -> apm2.source_trust_snapshot.v1`, `sink.identity.snapshot -> apm2.sink_identity_snapshot.v1` | compromise signal digest MUST chain to trust snapshot digest and sink identity digest. |
| `GATE-SIO28-CRYPTO-AGILITY` | `crypto.agility.policy -> apm2.crypto_agility_policy.v1` | algorithm allowlist digest and keyset digest MUST match active epoch under current time authority envelope. |
| `GATE-SIO28-POST-COMPROMISE-RECOVERY` | `post_compromise.recovery.receipt -> apm2.post_compromise_recovery_receipt.v1`, `source.trust.snapshot -> apm2.source_trust_snapshot.v1` | recovery receipt digest MUST prove re-sealed roots and replay coverage for affected windows. |
| `GATE-SIO28-OPERATOR-SAFETY` | `operator.safety.guard -> apm2.operator_safety_guard_profile.v1` | safety guard digest MUST bind UI authority-field constraints and policy diff approvals. |
| `GATE-SIO28-EVIDENCE-QUALITY` | `evidence.quality.profile -> apm2.evidence_quality_profile.v1`, `evidence.freshness.sla -> apm2.evidence_freshness_sla.v1` | statistical power + freshness SLA digests MUST be current for promoted evidence class. |
| `GATE-SIO28-SEMANTIC-DRIFT` | `semantic.diff.report -> apm2.semantic_diff_report.v1` | semantic diff digest MUST be signed and canonicalized with active vectors before gate eval. |

### 14.3 CAC Validation Order and Defect Handling

For each gate, CAC validation order is mandatory:
1. resolve schema (`schema_id`, `schema_major`) from CAC registry;
2. verify canonicalizer tuple compatibility (`canonicalizer_id`, `canonicalizer_version`, `canonicalizer_vectors_ref`);
3. verify signature set and HTF freshness binding;
4. verify `contract_digest_set` completeness and digest equality constraints;
5. execute gate predicate logic.

Defect classes:
- `CAC_SCHEMA_UNRESOLVED`
- `CAC_SCHEMA_VERSION_INCOMPATIBLE`
- `CAC_CANONICALIZER_UNRESOLVED`
- `CAC_CANONICALIZER_VECTOR_MISMATCH`
- `CAC_DIGEST_SET_INCOMPLETE`
- `CAC_DIGEST_MISMATCH`
- `CAC_SIGNATURE_INVALID`
- `CAC_INPUT_STALE`
- `CAC_VALIDATION_ORDER_VIOLATION`

Any defect class above in a promotion-critical path MUST deny the gate immediately.

Tier behavior:
- Tier0/Tier1: deny gate and emit `cac.defect_record.v1`.
- Tier2+: deny gate, transition to `S3` fail-closed freeze, and block promotion until adjudication finishes before `cac_adjudication_deadline_window_ref`; missed deadline escalates to `S4` emergency halt.

## 15. Evidence Registry

Local profile evidence:
- `RFC-0028::EVID-0001` (`documents/rfcs/RFC-0028/evidence_artifacts/EVID-0001.yaml`)
- `RFC-0028::EVID-0002` (`documents/rfcs/RFC-0028/evidence_artifacts/EVID-0002.yaml`)
- `RFC-0028::EVID-0003` (`documents/rfcs/RFC-0028/evidence_artifacts/EVID-0003.yaml`)
- `RFC-0028::EVID-0004` (`documents/rfcs/RFC-0028/evidence_artifacts/EVID-0004.yaml`)
- `RFC-0028::EVID-0005` (`documents/rfcs/RFC-0028/evidence_artifacts/EVID-0005.yaml`)
- `RFC-0028::EVID-0006` (`documents/rfcs/RFC-0028/evidence_artifacts/EVID-0006.yaml`)
- `RFC-0028::EVID-0007` (`documents/rfcs/RFC-0028/evidence_artifacts/EVID-0007.yaml`)
- `RFC-0028::EVID-0008` (`documents/rfcs/RFC-0028/evidence_artifacts/EVID-0008.yaml`)
- `RFC-0028::EVID-0009` (`documents/rfcs/RFC-0028/evidence_artifacts/EVID-0009.yaml`)

Imported anchor evidence:
- `RFC-0027::EVID-0001` (`documents/rfcs/RFC-0027/evidence_artifacts/EVID-0001.yaml`)
- `RFC-0027::EVID-0008` (`documents/rfcs/RFC-0027/evidence_artifacts/EVID-0008.yaml`)
- `RFC-0027::EVID-0010` (`documents/rfcs/RFC-0027/evidence_artifacts/EVID-0010.yaml`)

## 16. Unified Gate Sequence Binding

This profile maps to unified Gate 2 (security plane):
- Gate 1: snapshot validity (`GATE-PCAC-SNAPSHOT-VALIDITY`)
- Gate 2: security profile conformance (`GATE-SIO28-*`, this RFC)
- Gate 3: efficiency profile conformance (`GATE-EIO29-*`, RFC-0029)
- Gate 4: joint adversarial replay/revocation drills
- Gate 5: promotion readiness with uncertainty and independent verifier evidence

## 17. Theory and Principle Lineage

| Contract Surface | Law Anchors | Principle Anchors |
|---|---|---|
| Authority continuity and proof-carrying effects | `LAW-01`, `LAW-15`, `LAW-20` | `PRIN-092`, `PRIN-105` |
| Dual-axis containment and projection isolation | `LAW-05`, `LAW-16` | `PRIN-100`, `PRIN-107` |
| Revocation and split-brain handling | `LAW-18`, `LAW-10` | `PRIN-124`, `PRIN-049` |
| Temporal fail-closed posture | `LAW-09`, `LAW-15` | `PRIN-108`, `PRIN-122` |
| Verifier independence | `LAW-17`, `LAW-14` | `PRIN-121`, `PRIN-094` |
| Trade-secret interlock | `LAW-05`, `LAW-14`, `LAW-15` | `PRIN-106` |

## 18. Explicit Non-Goals and Boundaries

### 18.1 Non-Goals

- no promotion on ambiguous temporal authority.
- no direct production GitHub authority for FAC agent runtimes.
- no guarantee of safe promotion under unresolved split-brain revocation conflicts.
- no acceptance of unsigned or unverifiable authority-critical claims.

### 18.2 Probabilistic vs Absolute Security Claims

Absolute:
- unknown or ambiguous authority-critical states fail closed.
- delegation widening is never admissible.

Probabilistic:
- detection latency and adversarial stress outcomes are probabilistic and must be reported with confidence and freshness metadata.

### 18.3 Supported Envelope (Current Phase)

- only tested federation and adversary envelopes are promotable.
- claims beyond tested envelope are non-authoritative until new evidence receipts are admitted.

## 19. Canonical Ownership Boundary

- RFC-0027 owns lifecycle semantics.
- RFC-0028 owns security profile constraints over lifecycle semantics.
- RFC-0029 owns efficiency profile constraints and temporal economics execution policy.
- RFC-0016 owns canonical temporal authority semantics.
- RFC-0019 owns shared profile temporal contract surfaces and cross-RFC gate-order binding for promotion-critical admission.

Integration mirror policy:
- RFC-0019 chapter 15 is derived mirror only.
- `GATE-SIO-PROFILE-SYNC` enforces one-way sync from RFC-0028 to RFC-0019 chapter 15.

## 20. Assumptions and Defaults

- pre-live status allows semantic tightening without backward-compatibility overhead unless concrete dependencies require compatibility.
- dominance order remains `containment/security > verification/correctness > liveness/progress`.
- unknown or unevaluable security state is fail-closed deny.
