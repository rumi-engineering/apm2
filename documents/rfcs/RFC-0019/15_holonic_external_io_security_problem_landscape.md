# RFC-0019 Addendum - Holonic External I/O Security Problem Landscape (PCAC-Profiled)

Status: Draft (problem-definition phase)
Primary objective: define external I/O security problems as lifecycle-stage defects over RFC-0027 PCAC states (`join -> revalidate -> consume -> effect`).

## 1. Baseline Import and Contracts

Imported baseline:
- `PCAC-SNAPSHOT-BASELINE-ID` (`documents/rfcs/RFC-0019/17_pcac_implementation_contract_snapshot.md`)

Imported profile ID:
- `PCAC-PROFILE-SECURITY-v1`

Canonical lifecycle substrate:
- `RFC-0027::REQ-0001` through `RFC-0027::REQ-0018`
- canonical path: `documents/rfcs/RFC-0027/PROOF_CARRYING_AUTHORITY_CONTINUITY.md`

Canonical profile source:
- `documents/rfcs/RFC-0028/HOLONIC_EXTERNAL_IO_SECURITY.md`

Derivation mode:
- one-way derivation from RFC-0028 into this RFC-0019 integration chapter.
- this chapter MUST NOT introduce profile semantics not present in RFC-0028.

Profile sync gate:
- `GATE-SIO-PROFILE-SYNC`
  - block condition: semantic drift between RFC-0028 canonical profile and this derived integration chapter.
  - minimum evidence: normalized profile-map diff artifact bound to current `PCAC-SNAPSHOT-BASELINE-ID`.

## 2. Security Stage Model

### Join-time threat family

- identity bootstrap forgery
- canonicalization downgrade/coercion
- session progression bypass

Primary anchors:
- `RFC-0027::REQ-0001`, `RFC-0027::REQ-0004`, `RFC-0027::REQ-0007`
- companion: `RFC-0020::REQ-0002`, `RFC-0020::REQ-0003`

### Revalidate-time threat family

- stale freshness authority
- revocation lag and sovereignty ambiguity
- anti-entropy induced stale acceptance

Primary anchors:
- `RFC-0027::REQ-0003`, `RFC-0027::REQ-0008`, `RFC-0027::REQ-0010`
- companion: `RFC-0020::REQ-0018`, `RFC-0020::REQ-0019`, `RFC-0016::REQ-HTF-0003`

### Consume-time threat family

- intent mismatch acceptance
- duplicate consume acceptance
- no-bypass and pre-actuation prerequisite bypass

Primary anchors:
- `RFC-0027::REQ-0002`, `RFC-0027::REQ-0005`, `RFC-0027::REQ-0009`, `RFC-0027::REQ-0018`
- companion: `RFC-0020::REQ-0027`, `RFC-0020::REQ-0030`

### Effect-time threat family

- idempotency/projection safety drift
- acceptance-fact incompleteness
- egress confidentiality downgrade without receipt
- public projection compromise propagation risk

Primary anchors:
- `RFC-0027::REQ-0006`, `RFC-0027::REQ-0007`
- companion: `RFC-0020::REQ-0032`, `RFC-0020::REQ-0034`, `RFC-0018::REQ-HEF-0018`

## 3. SIO Problem Remap to Lifecycle Stages

Each problem binds one primary stage and one secondary stage.

### 3.1 Row-Level Hyperproperty Tag Registry (normative)

Each row in the SIO remap table MUST reference one or more `HP-SIO-R*` tags.

| Hyperproperty Tag | Predicate Class | Falsification Trigger | Evidence Family | Fail-Closed Rule |
|---|---|---|---|---|
| `HP-SIO-R01` | projection non-interference | authoritative trace divergence for equivalent lifecycle inputs | projection differential replay receipts | unresolved verdict denies |
| `HP-SIO-R02` | downgrade monotonicity | malformed/unknown parser path enlarges acceptance set | canonicalizer variance corpus + parser receipts | unknown parser/canonicalizer state denies |
| `HP-SIO-R03` | delegation lattice closure | delegated vector strictly broader than `meet(parent, overlay)` or independent verifier recomputation disagrees on meet output | delegation meet diff reports + deterministic recomputation receipts + recursion tests | non-computable/ambiguous meet denies |
| `HP-SIO-R04` | boundary lattice continuity | admitted flow violates taint floor/classification ceiling without receipt | boundary-flow gate receipts + declassification receipts | missing lattice metadata denies |
| `HP-SIO-R05` | revocation monotonicity | stale/revoked authority accepted after frontier advance | revocation frontier replay receipts | stale/ambiguous revocation denies |
| `HP-SIO-R06` | portable reverification completeness | acceptance claim cannot be independently replayed from bundle | bundle completeness reports + third-party replay receipts | incomplete bundle denies |
| `HP-SIO-R07` | no-bypass actuation closure | side effect occurs without broker/capability/context-firewall chain | actuation path audit + no-bypass negative tests | any missing mediation check denies |
| `HP-SIO-R08` | projection authority isolation | production agent runtime can directly invoke `gh`/GitHub API actuation | capability-surface diffs + projection-worker receipt chains + direct-call deny traces | unknown stage/surface state denies |
| `HP-SIO-R09` | projection compromise non-propagation | compromised projection state alters authoritative lifecycle outcome | divergence detector traces + trust-root snapshots + quarantine receipts | unresolved compromise verdict denies |

| Problem | Primary Stage | Secondary Stage | Hyperproperty Tag(s) | Failure Signal | PCAC Requirement Anchor | Companion Requirement Anchor |
|---|---|---|---|---|---|---|
| `SIO-001` boundary intent typing ambiguity | `join` | `consume` | `HP-SIO-R04` | `SIO-SIG-001` | `RFC-0027::REQ-0001` | `RFC-0020::REQ-0034` |
| `SIO-002` identity bootstrap portability gap | `join` | `revalidate` | `HP-SIO-R02`, `HP-SIO-R06` | `SIO-SIG-002` | `RFC-0027::REQ-0007` | `RFC-0020::REQ-0002` |
| `SIO-003` freshness authority incompleteness | `revalidate` | `consume` | `HP-SIO-R05` | `SIO-SIG-003` | `RFC-0027::REQ-0003` | `RFC-0020::REQ-0018` |
| `SIO-004` delegation meet discontinuity | `join` | `consume` | `HP-SIO-R03` | `SIO-SIG-004` | `RFC-0027::REQ-0004` | `RFC-0020::REQ-0027` |
| `SIO-005` session-state progression drift | `join` | `revalidate` | `HP-SIO-R02` | `SIO-SIG-005` | `RFC-0027::REQ-0001` | `RFC-0020::REQ-0003` |
| `SIO-006` decode/canonicalization downgrade | `join` | `revalidate` | `HP-SIO-R02` | `SIO-SIG-006` | `RFC-0027::REQ-0007` | `RFC-0020::REQ-0003` |
| `SIO-007` context firewall and TOCTOU gap | `consume` | `effect` | `HP-SIO-R07`, `HP-SIO-R04` | `SIO-SIG-007` | `RFC-0027::REQ-0009` | `RFC-0020::REQ-0029` |
| `SIO-008` dual-lattice propagation discontinuity | `consume` | `effect` | `HP-SIO-R04` | `SIO-SIG-008` | `RFC-0027::REQ-0007` | `RFC-0020::REQ-0032` |
| `SIO-009` declassification contract ambiguity | `effect` | `consume` | `HP-SIO-R04` | `SIO-SIG-009` | `RFC-0027::REQ-0007` | `RFC-0020::REQ-0032` |
| `SIO-010` heterogeneous no-bypass actuation risk | `consume` | `effect` | `HP-SIO-R07` | `SIO-SIG-010` | `RFC-0027::REQ-0009` | `RFC-0020::REQ-0030` |
| `SIO-011` revocation shock/resurrection risk | `revalidate` | `consume` | `HP-SIO-R05` | `SIO-SIG-011` | `RFC-0027::REQ-0008` | `RFC-0020::REQ-0019` |
| `SIO-012` evidence portability/reverification gap | `effect` | `consume` | `HP-SIO-R06` | `SIO-SIG-012` | `RFC-0027::REQ-0006` | `RFC-0020::REQ-0034` |
| `SIO-013` incident propagation/containment race | `revalidate` | `effect` | `HP-SIO-R05`, `HP-SIO-R07` | `SIO-SIG-013` | `RFC-0027::REQ-0010` | `RFC-0020::REQ-0035` |
| `SIO-014` version negotiation downgrade risk | `join` | `consume` | `HP-SIO-R02` | `SIO-SIG-014` | `RFC-0027::REQ-0007` | `RFC-0020::REQ-0002` |
| `SIO-015` boundary abuse economics as security defect | `revalidate` | `consume` | `HP-SIO-R05`, `HP-SIO-R07` | `SIO-SIG-015` | `RFC-0027::REQ-0011` | `RFC-0020::REQ-0035` |
| `SIO-016` direct GitHub projection authority leakage | `consume` | `effect` | `HP-SIO-R08`, `HP-SIO-R07` | `SIO-SIG-016` | `RFC-0027::REQ-0009` | `RFC-0028::REQ-0008` |
| `SIO-017` public projection compromise propagation | `effect` | `revalidate` | `HP-SIO-R09`, `HP-SIO-R01` | `SIO-SIG-017` | `RFC-0027::REQ-0006` | `RFC-0028::REQ-0009` |

## 4. Fail-Closed Security Profile Rules

For every authority-bearing external flow:

- `pcac_join_valid`
- `pcac_revalidate_valid`
- `pcac_consume_valid`
- `delegation_meet_exact_valid`
- `pcac_effect_guarded`
- `pcac_single_consume_enforced`
- `pcac_intent_digest_equal`
- `pcac_revocation_dominant`
- `pcac_replay_complete`
- `pcac_projection_isolation_valid`
- `projection_compromise_contained`
- `time_authority_envelope_valid == true`
- `promotion_temporal_ambiguity == false`

Any false/unknown value denies admission and emits corresponding `SIO-SIG-*`.
Temporal authority checks in this chapter align with `TP-EIO29-001` and `TP-EIO29-008` contract IDs.

## 5. Security Evidence Binding (path-qualified)

- `RFC-0027::EVID-0001` (`documents/rfcs/RFC-0027/evidence_artifacts/EVID-0001.yaml`)
- `RFC-0027::EVID-0002` (`documents/rfcs/RFC-0027/evidence_artifacts/EVID-0002.yaml`)
- `RFC-0027::EVID-0003` (`documents/rfcs/RFC-0027/evidence_artifacts/EVID-0003.yaml`)
- `RFC-0027::EVID-0006` (`documents/rfcs/RFC-0027/evidence_artifacts/EVID-0006.yaml`)
- `RFC-0027::EVID-0008` (`documents/rfcs/RFC-0027/evidence_artifacts/EVID-0008.yaml`)
- `RFC-0027::EVID-0010` (`documents/rfcs/RFC-0027/evidence_artifacts/EVID-0010.yaml`)
- `RFC-0028::EVID-0008` (`documents/rfcs/RFC-0028/evidence_artifacts/EVID-0008.yaml`)
- `RFC-0028::EVID-0009` (`documents/rfcs/RFC-0028/evidence_artifacts/EVID-0009.yaml`)

## 6. Profile Gates (security)

- `GATE-SIO-PCAC-SNAPSHOT`
  - blocks on snapshot drift or missing predicate evidence.
- `GATE-SIO-TIME-AUTHORITY`
  - blocks on stale/unsigned/missing/invalid `TimeAuthorityEnvelopeV1`, boundary mismatch, authority-clock mismatch, or unresolved temporal windows.
- `GATE-SIO-LIFECYCLE-COMPLETE`
  - blocks when any required lifecycle stage receipt is missing.
- `GATE-SIO28-DELEGATION-MEET-EXACTNESS`
  - blocks when delegated authority vector differs from exact meet, canonical digests mismatch, or independent verifier recomputation disagrees.
- `GATE-SIO-CONSUME-CORRECTNESS`
  - blocks on intent mismatch acceptance, duplicate consume acceptance, or no-bypass violation.
- `GATE-SIO-REVOCATION-DOMINANCE`
  - blocks on stale/revoked authority consume acceptance.
- `GATE-SIO-EFFECT-SAFETY`
  - blocks on effect-level acceptance-fact incompleteness or declassification violation.
- `GATE-SIO-PROJECTION-ISOLATION`
  - blocks when any production agent RoleSpec contains direct GitHub API/`gh` capability classes or when projection-worker receipt chain is missing.
- `GATE-SIO-PROJECTION-COMPROMISE-CONTAINMENT`
  - blocks when projection divergence detection, quarantine action, trust-root pinning, or recovery receipts are missing/invalid.

All gates fail closed.
Temporal authority rationale: `GATE-SIO-TIME-AUTHORITY` MUST execute before lifecycle/effect/projection gates that consume timing semantics.
Gate-name mapping to canonical profile gates is one-to-one (`GATE-SIO-*` in this mirror corresponds to `GATE-SIO28-*` in RFC-0028).

## 7. Security Profile Tests

- Lifecycle conformance: all authority-bearing external flows emit complete ordered stage receipts.
- Missing stage deny: missing stage receipt forces deny.
- Delegation widening test: recursion depth `>= 4` must deny.
- Delegation meet exactness test: deterministic independent recomputation must match canonical meet digest for admitted delegations.
- Time-authority denial test: missing/stale/invalid-signature/wrong-boundary envelopes deny before security lifecycle gating.
- Wall-time perturbation test: Tier2+ outcomes invariant for fixed HTF/ledger inputs.
- Revocation frontier test: revoked authority cannot be consumed after frontier advance.
- Projection toggle test: projection mode toggle does not alter authoritative trace hash.
- Direct GitHub deny test: any `agent_runtime` attempt at direct `gh` or GitHub API actuation is denied and emits `SIO-SIG-016`.
- Projection compromise drill: compromised projection surface cannot alter authoritative lifecycle outcomes and is quarantined with replay-safe recovery.

## 8. Unified Gate Sequence Binding

This chapter implements Gate 2 of the unified sequence:
- Gate 1 snapshot validity (chapter 17)
- Gate 2 security profile conformance (this chapter), including projection-compromise containment.
- Gate 3 efficiency profile conformance (chapter 16)
- Gate 4 joint replay/revocation drills
- Gate 5 promotion readiness with uncertainty and independent verifier evidence
