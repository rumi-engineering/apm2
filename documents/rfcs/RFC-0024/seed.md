# RFC-0024: Autonomous Resource Provisioning — Seed

## Required context files

Read all of these before generating output:

- documents/theory/unified-theory-v2.json
- documents/theory/unified-theory-v2.json
- documents/theory/unified-theory-v2.json
- documents/theory/unified-theory-v2.json
- documents/strategy/MASTER_STRATEGY.json
- documents/strategy/BUSINESS_PLAN.json
- documents/rfcs/RFC-0020/HOLONIC_SUBSTRATE_INTERFACE.md
- documents/rfcs/RFC-0022/PRINCIPAL_SOVEREIGNTY_INTERFACE.md
- documents/rfcs/RFC-0023/INSTRUCTION_LIFECYCLE.md
- proto/kernel_events.proto

## Why this RFC matters

When a new holon enters the system — whether it's a fresh agent spawned to fix a bug or an entire organizational branch joining the holarchy — it needs resources: identity, capabilities, budgets, context, trust. Today's cloud provisioning models are built around implicit trust and coarse-grained IAM policies. This RFC must invent a provisioning protocol native to holonic recursion: trust bootstrap that composes, capability delegation that narrows monotonically, resource envelopes that respect physical cost floors, and teardown that preserves evidence while revoking authority atomically. The hard problem is making this work at arbitrary nesting depth without the provisioning overhead exploding.

## Priority innovation vectors

- **Trust bootstrap as a protocol**: formalize the trust establishment handshake using ideas from key exchange protocols, capability bootstrapping, and verifiable delay functions for rate-limiting Sybil attacks.
- **Recursive provisioning**: provisioning a holon that itself provisions sub-holons, with capability narrowing composed transitively — draw from the authority lattice in RFC-0020.
- **Resource topology awareness**: budget allocation that accounts for physical locality, network topology, and data gravity rather than treating resources as fungible.
- **Deprovisioning as first-class evidence**: teardown that produces a signed receipt proving all capabilities were revoked, all state was archived, and no dangling references remain.
- **Identity at scale**: self-certifying identities with O(log n) verification for 10^12 holons using Merkle-based directory commitments.

## Problem (PHY-04, PHY-08, INV-F-05)

The unified theory defines MECH-RELAY-HOLON, MECH-FEDERATION, MECH-HOLON-MESH-PROTOCOL, and MECH-HOLON-DIRECTORY. HSI §2 specifies federation with cells, relays, and anti-entropy with Byzantine stance. HSI §8 defines HolonIdV1, CellIdV1, HolonCertificate, CellCertificate. HSI §10 stages S7/S7.5/S8 cover federation read-only through relay holons.

But there is no normative protocol for bootstrapping trust on a new machine, provisioning it as a functioning holon, delegating capabilities to it, managing its resource budget, or securely tearing it down. The system can theoretically federate, but it cannot grow. This RFC bridges the gap between "federation exists" and "the system can assimilate a new compute node and make it do useful work."

This is critical for BSP_26 (INFRASTRUCTURE_SOVEREIGNTY) — the system must provision its own infrastructure rather than depending on cloud provider managed services.

## What already exists

| Artifact | Provides | Gap |
|---|---|---|
| HSI §2 Federation model | Cells, relays, anti-entropy | No trust bootstrap, no provisioning workflow |
| HolonIdV1, CellIdV1 | Self-certifying identities | No attestation of the physical machine's integrity |
| HolonCertificate, CellCertificate | Certificate types defined | No issuance protocol |
| CapabilityManifestV1 (HSI §3) | Capability delegation framework | Not applied to machine provisioning |
| MECH-HOLON-DIRECTORY | Directory concept | No synchronization protocol for provisioned machines |
| BSP_26 | Infrastructure sovereignty axiom | No operational binding |
| BSP_28 | Capital constraint ($180k) | No cost modeling for provisioning |
| apm2d_runtime_v1.proto SpawnEpisode | Spawn mechanism | Spawns episodes, not machines |

## Machine-checkable objectives

**OBJ-ARP-01**: Trust bootstrap is bilateral: A new machine must prove its integrity to the existing system AND the system must prove its authority to the new machine. Unilateral trust is forbidden.
- Predicate: `∀ provision: ∃ (machine_attestation, system_authority_proof): both.verified = true`

**OBJ-ARP-02**: Capability inheritance follows OCAP: A provisioned holon's capabilities must be a strict subset of the provisioning holon's capabilities. No capability amplification during delegation.
- Predicate: `∀ child_holon: child_holon.capabilities ⊂ parent_holon.capabilities`

**OBJ-ARP-03**: Resource budgets are bounded and metered: Every provisioned holon must have explicit compute, storage, network, and cost budgets. Budget exhaustion triggers graceful teardown, not crash.
- Predicate: `∀ holon: holon.budget.remaining ≥ 0 ∨ holon.state = TEARDOWN`

**OBJ-ARP-04**: Teardown is evidence-preserving: Deprovisioning a holon must first replicate all ledger entries and evidence to a surviving cell. Loss of evidence is an S0 defect.
- Predicate: `∀ teardown: pre_teardown_evidence ⊆ surviving_cells.evidence`

**OBJ-ARP-05**: Provisioning is idempotent: Re-running the provisioning protocol on an already-provisioned machine must produce the same result (INV-F-06). Partial provisioning failures must be resumable.
- Predicate: `∀ machine: provision(provision(machine)) = provision(machine)`

**OBJ-ARP-06**: Jurisdiction compliance: No machine may be provisioned in an excluded jurisdiction (BSP_27). IP geolocation alone is insufficient; the provisioning protocol must verify physical hosting location through provider attestation.
- Predicate: `∀ machine: machine.jurisdiction ∉ {CCP, RU, DPRK, US_EXEC} ∧ jurisdiction.attestation.verified = true`

## Protocol objects (seed schemas)

These are starting points — refine, extend, or restructure as your analysis requires.

```
MachineAttestationV1 {
    machine_id: PublicKeyIdV1,
    platform_report: PlatformReportV1,
    tpm_quote: Option<TpmQuoteV1>,
    jurisdiction_attestation: JurisdictionAttestationV1,
    network_addresses: Vec<NetworkAddress>,
    resource_capacity: ResourceCapacityV1,
    attestation_seal: AuthoritySealV1,
}

ProvisioningRequestV1 {
    requesting_holon: HolonIdV1,
    machine_attestation: MachineAttestationV1,
    requested_role: HolonRole,
    requested_capabilities: CapabilityManifestV1,
    resource_budget: ResourceBudgetV1,
    principal_authorization: AuthoritySealV1,
}

ProvisioningReceiptV1 {
    request_digest: CasDigest,
    assigned_holon_id: HolonIdV1,
    assigned_cell_id: CellIdV1,
    issued_certificate: HolonCertificate,
    capability_manifest: CapabilityManifestV1,
    resource_budget: ResourceBudgetV1,
    parent_holon: HolonIdV1,
    provisioned_at: TimeEnvelopeRef,
    principal_seal: AuthoritySealV1,
}

ResourceBudgetV1 {
    compute_cpu_seconds: Quantity,
    compute_gpu_seconds: Quantity,
    storage_bytes: Quantity,
    network_egress_bytes: Quantity,
    cost_usd_cents: Quantity,
    valid_until: TimeEnvelopeRef,
    on_exhaustion: ExhaustionPolicy,
}

ResourceMeteringEventV1 {
    holon_id: HolonIdV1,
    epoch: TimeEnvelopeRef,
    consumed: ResourceBudgetV1,
    remaining: ResourceBudgetV1,
    metering_seal: AuthoritySealV1,
}

TeardownRequestV1 {
    holon_id: HolonIdV1,
    reason: TeardownReason,
    evidence_replication_target: CellIdV1,
    principal_seal: Option<AuthoritySealV1>,
}

TeardownReceiptV1 {
    holon_id: HolonIdV1,
    evidence_replicated: bool,
    evidence_digest: CasDigest,
    resources_released: ResourceBudgetV1,
    torn_down_at: TimeEnvelopeRef,
    replication_proof: ReceiptMultiProofV1,
}

HolonRole { BUILD_WORKER | PENTEST_SANDBOX | SERVICE_HOST | RELAY | GENERAL_COMPUTE }
```

## Trust boundaries and threat model

Trust boundary: The provisioning protocol straddles two trust domains — the existing system (trusted, after RFC-0022 sovereignty) and the new machine (UNTRUSTED until attested and provisioned). The machine transitions from UNTRUSTED to CONSTRAINED-TRUSTED upon successful provisioning, with capabilities strictly bounded by the provisioning receipt.

Threats:
1. **Rogue machine injection (PHY-05)**: Adversary presents a compromised machine for provisioning. Mitigation: bilateral attestation, principal must approve every new machine, capability ceiling strictly bounded.
2. **Resource exhaustion attack (PHY-04)**: Provisioned holon consumes resources beyond budget. Mitigation: metering is external to the provisioned holon; budget enforcement at the parent.
3. **Evidence loss during teardown (PHY-04)**: Machine fails before evidence replication completes. Mitigation: evidence replication is a precondition of teardown completion; teardown is a two-phase protocol.
4. **Jurisdiction evasion (BSP_27)**: Machine claims to be in an allowed jurisdiction but isn't. Mitigation: provider attestation + network-path analysis, not just IP geolocation.
5. **Capability amplification (PHY-05)**: Child holon somehow gains more capabilities than parent granted. Mitigation: OCAP strict subset rule, verified at every capability check.

## Theory bindings

- LAW-05 (Dual-Axis Containment): Provisioned holons are contained along both integrity and authority axes
- LAW-11 (Idempotent Actuation): Provisioning is idempotent (OBJ-ARP-05)
- LAW-12 (Bounded Search): Resource budgets are termination envelopes for provisioned work
- LAW-16 (Closure Under Composition): Provisioned holons compose holonically — a provisioned holon can provision sub-holons (with strictly reduced capabilities)
- INV-F-01 (Append-only truth): Provisioning and teardown receipts are append-only
- INV-F-05 (Default-deny, least-privilege, time-bounded): Every provisioned capability is time-bounded
- INV-F-12 (Compaction preserves auditability): Evidence compaction during teardown preserves audit trail
- PRIN-030 (OCAP): No ambient authority for provisioned machines

## Rollout

- S0: Define MachineAttestationV1, implement for local-machine-only (same host, different namespace)
- S1: Provisioning protocol for BUILD_WORKER role — spawn build agents on a second machine
- S2: Resource budgeting and metering — track CPU/storage/network per provisioned holon
- S3: Teardown protocol with evidence replication — two-phase commit
- S4: Jurisdiction verification — integrate provider attestation
- S5: Multi-role provisioning (PENTEST_SANDBOX, SERVICE_HOST)
- S6: Recursive provisioning — provisioned holons can provision sub-holons
- S7: RELAY role — provisioned machine acts as federation relay (HSI S8 prerequisite)
- S8: Cost optimization — budget-aware scheduling across provisioned fleet
