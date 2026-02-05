# 27 — Distributed Security (Sybil, Eclipse, and Holonic Identity)

[CONTRACT: CTR-2701] Sybil-Resistant Admission Control.
- REJECT IF: discovery or handshake logic accepts new peers into the active set without an identity-weighting or reputation-tracking mechanism.
- ENFORCE BY:
  - Validated `ActorID` cryptographic binding.
  - Costly entry barrier (Proof-of-Work, Stake, or signed delegation from a trusted Holarchy root).
  - Multi-stage handshake that verifies peer "liveness" before allocating significant session resources.
[PROVENANCE] documents/security/THREAT_MODEL.cac.json: Discovery mechanisms are high-risk entry points for Sybil attacks.

[INVARIANT: INV-2701] Identity-Bound Resource Quotas.
- REJECT IF: resource consumption (tasks, memory, bandwidth, storage) is tracked globally or per-connection without being keyed by a verified `ActorID`.
- REJECT IF: a single `ActorID` (or group of related IDs) can exceed a predefined percentage of the holon's capacity without an elevated trust score.
- ENFORCE BY:
  - Use `DashMap<ActorID, QuotaState>` to track cross-connection resource usage.
  - Enforce limits at the ingress point of every major subsystem (routing, replication, command execution).
[PROVENANCE] documents/security/THREAT_MODEL.cac.json: Bounded work issuance and admission control prevent the network from becoming an involuntary compute sink.

[HAZARD: RSK-2701] Eclipse-Prone Peer Selection (Homogeneity).
- TRIGGER: Peer sets populated primarily from a single IP subnet, cloud provider, or geographic region.
- FAILURE MODE: An attacker with network-level proximity (or control over a specific ASN) can flood the peer set so the victim sees only attacker-controlled holons.
- REJECT IF: Peer selection/maintenance logic lacks explicit "Diversity Enforcement."
- ENFORCE BY:
  - Cap active connections from the same `/24` (IPv4) or `/48` (IPv6) subnet.
  - Implement "Outbound Peer Diversity": prioritize connections to seeds from diverse Autonomous Systems (ASNs).
  - Use a "Reputation-Weighted" peer bucket system where no single identity group can occupy >20% of the active routing table.
[PROVENANCE] documents/security/THREAT_MODEL.cac.json: Sybil and eclipse attacks flood the peer set to isolate victims.

[CONTRACT: CTR-2702] Deterministic Holonic Identity Continuity.
- REJECT IF: `ActorID` rotation or key update logic permits "split-brain" identities or allows an old key to retain authority after revocation.
- ENFORCE BY:
  - Monotonic sequence numbers in identity update manifests.
  - Explicit revocation evidence that is replicated with higher priority than standard state.
[PROVENANCE] documents/security/THREAT_MODEL.cac.json: Identity threats dominate; revocation must handle long-lived partitions.

[CONTRACT: CTR-2703] Cryptographically Bound ActorID.
- REJECT IF: `ActorId` is represented as a raw primitive (e.g., `String`, `Uuid`, `u64`) in public APIs, signature payloads, or ledger events.
- ENFORCE BY:
  - Define `ActorId` as a newtype wrapping the BLAKE3 hash of the actor's `VerifyingKey` (e.g., `struct ActorId([u8; 32])`).
  - Construction of `ActorId` MUST be bound to a validated cryptographic key at the type level.
  - All protocols MUST use this bound type to prevent identity spoofing and non-repudiation of the identity string itself.
[PROVENANCE] SEC-AUDIT-001: Weak ActorID binding; RFC-0010.

[HAZARD: RSK-2702] Capability Amplification via Recursive Delegation.
- TRIGGER: A sub-holon inducing a parent to perform actions using the parent's higher-trust credentials (Confused Deputy).
- REJECT IF: Delegation tokens are not attenuated (scoped to specific purpose, time, and target).
- ENFORCE BY:
  - Bound tokens to specific `CapabilityScope`.
  - Verify that every relayed command includes the full delegation chain for audit.
[PROVENANCE] documents/security/THREAT_MODEL.cac.json: Authorization threats in holarchies are typically delegation bugs.

## References (Normative Anchors)

- documents/security/THREAT_MODEL.cac.json: Distributed holonic threat posture.
- RFC-0010: Identity and ActorID specification.
- RFC-0014: Capability-based authorization protocol.
