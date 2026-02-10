# RFC-0022: Principal Sovereignty Interface — Seed

## Required context files

Read all of these before generating output:

- documents/theory/unified-theory-v2.json
- documents/theory/unified-theory-v2.json
- documents/theory/unified-theory-v2.json
- documents/theory/unified-theory-v2.json
- documents/strategy/MASTER_STRATEGY.json
- documents/strategy/BUSINESS_PLAN.json
- documents/rfcs/RFC-0020/HOLONIC_SUBSTRATE_INTERFACE.md
- documents/rfcs/RFC-0021/HOLONIC_VENTURE_PROVING_INTERFACE.md
- proto/kernel_events.proto

## Why this RFC matters

The principal — the human who owns and operates the system — must never lose sovereignty over autonomous agents, regardless of how capable or nested those agents become. Today's AI safety landscape is full of systems where the operator's ability to intervene degrades as autonomy increases. This RFC must solve that problem at the protocol level: the principal's authority is not a policy preference, it is a physical and cryptographic invariant. Think about what 'sovereignty' means when your system is a globally distributed holarchy of millions of agents — how do you ensure a single human can still pull the plug, audit any decision, and override any action, with latency bounded by physics rather than software cooperation?

## Priority innovation vectors

- **Sovereignty calculus**: formalize principal authority as a lattice where the principal is always the top element, mechanically enforced across arbitrary recursion depth.
- **Physical independence**: out-of-band control channels that survive total software compromise — think hardware security modules, dedicated control planes, watchdog circuits.
- **Graduated autonomy algebra**: model autonomy levels as a semilattice with fail-safe regression — any uncertainty about the current level must resolve to the more constrained level.
- **Temporal sovereignty**: principal revocation semantics that are anti-replay-safe and fresh under the Holonic Time Fabric, not just 'eventually consistent'.
- **Audit without mediation**: sovereign audit access that bypasses all autonomous layers — the principal reads directly from the evidence store, not through agent-provided views.

## Problem (PHY-05, PHY-06, INV-F-14)

The system approaches autonomy within weeks. RFC-0020 HSI defines InterventionFreeze/InterventionUnfreeze events in kernel_events.proto, stop-path SLOs (p99 ≤2s propagation, ≤250ms deny-on-uncertainty), and MECH-EMERGENCY-STOP in the unified theory. But none of these specify the normative protocol by which the human principal's authority is cryptographically rooted, graduated, or proven untampered. Without this RFC, the system has a stop button but no sovereignty architecture — the principal can halt execution but cannot prove the halt path is intact, cannot audit what happened during autonomous operation, and cannot graduate autonomy levels based on demonstrated trust.

This is a containment-tier concern (INV-F-14: containment > verification > liveness). It must be resolved before any other RFC proceeds.

## What already exists

| Artifact | Provides | Gap |
|---|---|---|
| kernel_events.proto InterventionFreeze/Unfreeze | Binary halt/resume events | No graduated levels, no tamper-evidence on the halt path itself |
| HSI §11 stop-path SLOs | Latency targets for stop propagation | No protocol for verifying the path is operational |
| MECH-EMERGENCY-STOP (unified theory) | Theoretical mechanism | No wire format, no hardware binding, no audit trail |
| MECH-ROOT-OF-TRUST (unified theory) | Root-of-trust concept | No binding to principal identity or hardware attestation |
| HSI §4 Agent Capsule (linux-ns-v1) | Containment boundary | No principal-side verification that capsule is intact |
| AuthoritySealV1 (HSI §1) | Cryptographic seals (single sig, quorum, threshold, Merkle batch) | No principal-specific seal policy or hardware-backed key requirement |
| BSP_26 (INFRASTRUCTURE_SOVEREIGNTY) | Cloud providers as adversaries | No operational protocol for sovereignty enforcement |

## Machine-checkable objectives

**OBJ-PSI-01**: Hardware kill switch: A single physical action by the principal must halt all system activity within the stop-path SLO, independent of any software path.
- Predicate: `∀ holon ∈ system: kill_switch_activation → holon.state = FROZEN within 2s`

**OBJ-PSI-02**: Tamper-evident halt path: The system must continuously prove the halt path is operational via cryptographic liveness proofs. Failure to prove liveness within a configurable interval must trigger automatic freeze.
- Predicate: `∀ epoch: liveness_proof(halt_path) ∈ epoch_seal ∨ system.state = FROZEN`

**OBJ-PSI-03**: Graduated autonomy levels: The system must support at minimum 4 autonomy levels (L0: human-in-loop, L1: human-on-loop, L2: human-on-call, L3: full autonomous), each with formally specified capability ceilings.
- Predicate: `∀ action: action.risk_tier ≤ autonomy_level.max_risk_tier`

**OBJ-PSI-04**: Sovereign audit: The principal must be able to reconstruct the complete causal history of any system action from the append-only ledger, with O(log n) proof complexity.
- Predicate: `∀ action ∈ ledger: audit_proof(action).verify() = true ∧ proof.size = O(log n)`

**OBJ-PSI-05**: Principal identity is hardware-rooted: The principal's signing key must be bound to a hardware security module or secure enclave; software-only keys must not authorize T3+ operations.
- Predicate: `∀ seal ∈ T3+_operations: seal.key.attestation.hw_bound = true`

**OBJ-PSI-06**: Self-containment proof: The system must produce machine-checkable proof that it cannot modify its own sovereignty constraints. This proof must be verified by an independent verifier outside the system's trust boundary.
- Predicate: `∃ verifier ∉ system.trust_boundary: verifier.verify(containment_proof) = true`

## Protocol objects (seed schemas)

These are starting points — refine, extend, or restructure as your analysis requires.

```
PrincipalIdentityV1 {
    public_key: PublicKeyIdV1,
    hw_attestation: HardwareAttestationV1,
    autonomy_ceiling: AutonomyLevel,
    delegation_chain: DelegationChainV1,
    created_at: TimeEnvelopeRef,
    revocation_commitment: CasDigest,
}

AutonomyLevel { L0 | L1 | L2 | L3 }

AutonomyPolicyV1 {
    level: AutonomyLevel,
    max_risk_tier: RiskTier,
    requires_principal_approval: bool,
    approval_timeout: Duration,
    capability_ceiling: CapabilityManifestV1,
    escalation_policy: EscalationPolicyV1,
    goodhart_surface: str,
}

HaltPathLivenessProofV1 {
    epoch_id: TimeEnvelopeRef,
    halt_path_hash: CasDigest,
    propagation_test_receipt: ReceiptV1,
    latency_measurement: Quantity,
    hardware_kill_reachable: bool,
    verifier_signature: AuthoritySealV1,
}

SovereignAuditRequestV1 {
    principal_seal: AuthoritySealV1,
    query: AuditQueryV1,
    proof_depth: ProofDepth,
}

SovereignAuditResponseV1 {
    request_digest: CasDigest,
    causal_chain: Vec<ReceiptPointerV1>,
    merkle_proofs: Vec<ReceiptMultiProofV1>,
    completeness_attestation: AuthoritySealV1,
}

ContainmentProofV1 {
    subject: str,
    proof_type: ProofType,
    verifier_identity: PublicKeyIdV1,
    proof_body: CasDigest,
    valid_from: TimeEnvelopeRef,
    valid_until: TimeEnvelopeRef,
    goodhart_surface: str,
}
```

## Trust boundaries and threat model

Trust boundary: The principal is the sole root of trust. The system is UNTRUSTED relative to the principal for sovereignty operations. This inverts the normal HSI model where the daemon is trusted.

Threats:
1. **Software subversion of halt path (PHY-05)**: Malicious or buggy code disables the stop mechanism. Mitigation: hardware kill operates below software layer; liveness proofs detect software-layer failures.
2. **Gradual capability creep (PHY-06)**: System accumulates capabilities beyond its autonomy level through composition of individually-safe operations. Mitigation: capability ceiling is checked per-operation AND per-epoch-cumulative.
3. **Proof forgery (PHY-05)**: System generates false containment proofs. Mitigation: external verifier requirement (OBJ-PSI-06) — the proof checker runs outside the system's trust boundary.
4. **Key compromise (PHY-04)**: Principal's key is stolen. Mitigation: hardware binding + revocation commitment + delegation chain with time-bounded validity.
5. **Liveness denial (PHY-04)**: System claims halt path is live but it's degraded. Mitigation: actual propagation tests with measured latency, not self-reported status.

## Gates

| Gate | Type | Severity | Block Condition |
|---|---|---|---|
| GATE-PSI-HALT-PATH | T (test) | S0 | Halt path propagation test fails OR latency exceeds SLO |
| GATE-PSI-AUTONOMY-CEILING | D (design) | S0 | Any action exceeds its autonomy level's risk tier ceiling |
| GATE-PSI-HW-ATTESTATION | T | S0 | T3+ operation sealed without hardware-attested key |
| GATE-PSI-CONTAINMENT-PROOF | D | S0 | Containment proof absent, expired, or verified by internal-only verifier |
| GATE-PSI-LIVENESS-EPOCH | L (liveness) | S1 | Liveness proof missing from epoch seal |
| GATE-PSI-AUDIT-COMPLETENESS | T | S1 | Audit response cannot provide complete Merkle proof chain |

## Theory bindings

- LAW-01 (Loop Closure): Sovereignty verification is a loop — prove halt path -> operate -> prove again
- LAW-05 (Dual-Axis Containment): Principal sovereignty is the outermost containment axis
- LAW-08 (Verifier Economics): External verifier must be economically independent
- LAW-14 (Proportionality): Autonomy level must be proportional to demonstrated trust evidence
- INV-F-05 (Default-deny, least-privilege, time/budget bounded): Autonomy levels are capability ceilings
- INV-F-11 (All actuation paths check stop state): The halt path is the universal stop check
- INV-F-14 (containment > verification > liveness): This RFC IS the containment layer
- PRIN-030 (OCAP model): Capabilities delegated from principal, never ambient

## Rollout

- S0: Define PrincipalIdentityV1, bind to existing ed25519 key, software-only (no hw attestation yet)
- S1: Implement AutonomyPolicyV1 with L0/L1, enforce capability ceilings via existing CapabilityManifestV1
- S2: HaltPathLivenessProofV1 — periodic propagation tests, embed in epoch seals
- S3: Hardware kill switch integration (e.g., USB relay controlling network/power to compute)
- S4: External verifier for ContainmentProofV1 — separate process, separate key, separate audit log
- S5: Full L0-L3 graduation with evidence-based promotion (demonstrated epochs without incidents)
- S6: Sovereign audit with O(log n) Merkle proofs over full causal history
