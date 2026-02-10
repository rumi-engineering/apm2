# RFC-0023: Instruction Lifecycle & Deployment Protocol — Seed

## Required context files

Read all of these before generating output:

- documents/theory/unified-theory-v2.json
- documents/theory/unified-theory-v2.json
- documents/theory/unified-theory-v2.json
- documents/theory/unified-theory-v2.json
- documents/strategy/MASTER_STRATEGY.json
- documents/rfcs/RFC-0020/HOLONIC_SUBSTRATE_INTERFACE.md
- documents/rfcs/RFC-0021/HOLONIC_VENTURE_PROVING_INTERFACE.md
- documents/rfcs/RFC-0022/PRINCIPAL_SOVEREIGNTY_INTERFACE.md
- proto/kernel_events.proto

## Why this RFC matters

Instructions — policies, directives, configurations, behavioral constraints — are the governance layer that shapes what agents do. Today these are scattered, implicitly versioned, and resolved through ad-hoc mechanisms. This RFC must formalize the full lifecycle: how instructions are born, signed, deployed, resolved at runtime, composed under holonic recursion, rolled back, and retired. The key insight is that instruction management is itself a distributed systems problem with consistency, availability, and partition tolerance tradeoffs. Draw from CRDTs, content-addressed storage, capability-based security, and formal verification of policy languages to build something that scales to civilizational coordination.

## Priority innovation vectors

- **Instruction CRDTs**: conflict-free replicated instruction sets that converge deterministically under concurrent updates from multiple principals at different hierarchy levels.
- **Content-addressed policy graphs**: instructions as a Merkle DAG where lineage is cryptographically verifiable and forks are detectable.
- **Categorical composition**: model instruction scoping as a functor from the holon hierarchy to the instruction lattice, ensuring composition preserves semantics.
- **Atomic rollback via checkpoints**: leverage CAS to make rollback a pointer swap rather than a state reconstruction, achieving O(1) rollback latency.
- **Runtime resolution as proof search**: deterministic instruction resolution that produces a verifiable proof of which instructions apply and why.

## Problem (PHY-03, PHY-05, INV-F-02)

Three instruction specs exist (AEP, BSP, RFC-0021 refinement) as static JSON files under documents/prompts/. The CAC schema (cac.instruction_spec.v1) validates their structure. RFC-0011 (CAC v1) defines the context-as-code pipeline. The schema_registry module exists in apm2-core.

But there is no normative protocol for how instruction specs are versioned, deployed, resolved at runtime, signed by the principal, rolled back, or retired. The instruction specs are the system's DNA — they govern what every agent does. Without lifecycle governance, the system has no way to:

1. Prove which instruction spec version was active during a given episode
2. Prevent an agent from loading a tampered or outdated instruction spec
3. Roll back a bad instruction spec deployment without losing evidence
4. Track dependencies between instruction specs (BSP references AEP axioms)
5. Ensure the principal has approved every active instruction spec

This is a verification-tier concern (INV-F-02: no authoritative state transition without required gate receipt). Instruction deployment IS a state transition.

## What already exists

| Artifact | Provides | Gap |
|---|---|---|
| cac.instruction_spec.v1.schema.json | Structural validation | No lifecycle states, no deployment protocol |
| schema_registry module in apm2-core | Schema registration infrastructure | Not wired to instruction spec deployment |
| CAC v1 (RFC-0011) | Context compilation pipeline | Compiles context, doesn't deploy/version instruction specs |
| EpisodeEnvelopeV1 (HSI §3) | Immutable execution commitment | Contains instruction_spec_ref field but no normative binding |
| Evidence CAS (BLAKE3) | Content-addressed storage | Instruction specs aren't CAS-addressed today |

## Machine-checkable objectives

**OBJ-ILD-01**: CAS-addressed instruction specs: Every instruction spec must be identified by its BLAKE3 content hash. Name+version are convenience aliases.
- Predicate: `∀ spec: spec.id = blake3(canonical(spec.payload))`

**OBJ-ILD-02**: Principal-signed promotion: No instruction spec enters ACTIVE state without principal's AuthoritySealV1.
- Predicate: `∀ spec ∈ ACTIVE: ∃ seal ∈ spec.promotion_receipt: seal.principal = true`

**OBJ-ILD-03**: Episode binding: Every EpisodeEnvelopeV1 must reference the exact CAS digest of every instruction spec that governed it.
- Predicate: `∀ episode: episode.instruction_spec_refs ⊂ CAS ∧ ∀ ref: verify(ref) = true`

**OBJ-ILD-04**: Dependency closure: If instruction spec A references axioms from spec B, the deployment of A must require B to be in ACTIVE state at a compatible version.
- Predicate: `∀ spec: spec.dependencies ⊂ registry.active_specs`

**OBJ-ILD-05**: Rollback without evidence loss: Rolling back an instruction spec must not invalidate evidence produced under the previous version. Evidence retains its original spec binding.
- Predicate: `∀ evidence ∈ ledger: rollback(spec) → evidence.spec_ref unchanged`

**OBJ-ILD-06**: Runtime resolution is deterministic: Given an episode's time envelope and holon identity, the set of active instruction specs must be uniquely determined.
- Predicate: `∀ (time, holon): resolve(time, holon) = deterministic_set`

## Protocol objects (seed schemas)

These are starting points — refine, extend, or restructure as your analysis requires.

```
InstructionSpecRegistryEntryV1 {
    content_digest: CasDigest,
    schema_ref: str,
    schema_version: SemVer,
    kind: str,
    name: str,
    version: SemVer,
    lifecycle_state: SpecLifecycleState,
    dependencies: Vec<SpecDependencyV1>,
    promotion_receipt: Option<SpecPromotionReceiptV1>,
    retirement_receipt: Option<SpecRetirementReceiptV1>,
    created_at: TimeEnvelopeRef,
    state_transitions: Vec<SpecTransitionReceiptV1>,
}

SpecLifecycleState { DRAFT | STAGED | ACTIVE | DEPRECATED | RETIRED }

SpecDependencyV1 {
    spec_kind: str,
    version_constraint: VersionConstraint,
    required_axiom_ids: Vec<str>,
    binding_type: DependencyBinding,
}

SpecPromotionReceiptV1 {
    spec_digest: CasDigest,
    from_state: SpecLifecycleState,
    to_state: SpecLifecycleState,
    principal_seal: AuthoritySealV1,
    validation_evidence: Vec<CasDigest>,
    promoted_at: TimeEnvelopeRef,
}

SpecResolutionContextV1 {
    holon_id: HolonIdV1,
    time_envelope: TimeEnvelopeRef,
    requested_kinds: Vec<str>,
}

SpecResolutionResultV1 {
    context: SpecResolutionContextV1,
    resolved_specs: Vec<(str, CasDigest)>,
    resolution_proof: CasDigest,
}

SpecRollbackReceiptV1 {
    spec_digest: CasDigest,
    rollback_to: CasDigest,
    reason: str,
    principal_seal: AuthoritySealV1,
    evidence_preservation_attestation: CasDigest,
    rolled_back_at: TimeEnvelopeRef,
}
```

## Trust boundaries and threat model

Trust boundary: The instruction registry is a kernel-level service. Agents are UNTRUSTED consumers — they request resolution but cannot modify registry state. Only the principal (via AuthoritySealV1) and the kernel (for lifecycle bookkeeping) write to the registry.

Threats:
1. **Instruction tampering (PHY-05)**: Agent modifies an instruction spec after promotion. Mitigation: CAS-addressing — any modification changes the digest, breaking all references.
2. **Stale instruction resolution (PHY-03)**: Agent operates under an outdated spec. Mitigation: deterministic resolution bound to time envelopes; episodes commit their spec refs.
3. **Dependency confusion**: Spec A claims to depend on Spec B but actually uses a different version. Mitigation: dependency closure check at promotion time; axiom-level granularity in dependency tracking.
4. **Rollback-induced evidence orphaning**: Evidence produced under Spec v2 becomes uninterpretable after rollback to v1. Mitigation: evidence retains its original spec binding (OBJ-ILD-05); the spec version is part of the evidence's immutable metadata.

## Theory bindings

- LAW-01 (Loop Closure): Spec lifecycle is a gated promotion loop (DRAFT -> STAGED -> ACTIVE -> DEPRECATED -> RETIRED)
- LAW-03 (Monotone Ledger): Spec transitions are append-only; previous states are never overwritten
- LAW-09 (Temporal Pinning): Spec resolution is pinned to time envelopes, not wall-clock
- LAW-13 (Semantic Contracting): Each spec is a semantic contract; resolution is contract fulfillment
- INV-F-01 (Append-only truth): The spec registry is an append-only ledger
- INV-F-02 (No transition without gate receipt): Promotion requires principal seal + validation evidence
- INV-F-08 (Freshness is explicit): Spec resolution carries a freshness proof

## Rollout

- S0: CAS-address all existing instruction specs; create InstructionSpecRegistryEntryV1 for each
- S1: Wire registry into EpisodeEnvelopeV1 — every episode records its resolved specs
- S2: Principal-signed promotion gate — no spec reaches ACTIVE without seal
- S3: Dependency closure validation at promotion time
- S4: Deterministic runtime resolution with proof generation
- S5: Rollback protocol with evidence preservation attestation
- S6: Multi-holon resolution — federated registry heads with consensus
