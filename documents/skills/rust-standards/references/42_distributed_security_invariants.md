# 27 — Distributed security (Sybil, Eclipse, Holonic identity)

This chapter is project-specific guidance for distributed/holonic threats.
It should be read alongside `documents/security/THREAT_MODEL.cac.json`.

---

[CONTRACT: CTR-2701] Sybil-resistant admission control.
- REJECT IF: discovery/handshake logic accepts new peers into an active set without identity weighting or an entry-cost mechanism.
- ENFORCE BY:
  - Validate peer identity material before allocating significant resources.
  - Use a multi-stage handshake: cheap liveness first; expensive verification later.
  - Apply admission control keyed to a verified identity signal (not just connection count).
[PROVENANCE] `documents/security/THREAT_MODEL.cac.json`: Discovery is a high-risk entry point for Sybil pressure.

[INVARIANT: INV-2701] Identity-bound resource quotas.
- REJECT IF: resource consumption (tasks, memory, bandwidth, storage) is tracked only globally or per-connection.
- REJECT IF: a single identity can exceed a defined fraction of system capacity without elevated trust.
- ENFORCE BY:
  - Track quotas keyed by a **verified identity handle** (e.g., validated actor id + verified key digest).
  - Enforce limits at ingress of every major subsystem (routing, replication, command execution).
  - Implementation can use `Mutex<HashMap<..>>` or a concurrent map; introducing a new concurrency crate is a dependency change (M12).
[PROVENANCE] `documents/security/THREAT_MODEL.cac.json`: Bounded work issuance prevents involuntary compute sink attacks.

[HAZARD: RSK-2701] Eclipse-prone peer selection (homogeneity).
- TRIGGER: peer sets populated primarily from a single IP subnet, cloud provider, or geographic region.
- FAILURE MODE: attacker floods the peer set so the victim sees only attacker-controlled holons.
- REJECT IF: peer selection/maintenance logic lacks explicit diversity enforcement.
- ENFORCE BY:
  - cap active connections from the same `/24` (IPv4) or `/48` (IPv6) subnet,
  - prioritize seeds from diverse ASNs (avoid single-provider monoculture),
  - ensure no identity bucket occupies >20% of the active routing table.
[PROVENANCE] `documents/security/THREAT_MODEL.cac.json`: eclipse attacks isolate victims via peer-set flooding.

[CONTRACT: CTR-2702] Deterministic holonic identity continuity.
- REJECT IF: identity rotation/key update logic permits split-brain identities or allows an old key to retain authority after revocation.
- ENFORCE BY:
  - monotonic sequence numbers in identity update manifests,
  - explicit revocation evidence replicated with higher priority than ordinary state.
[PROVENANCE] `documents/security/THREAT_MODEL.cac.json`: identity threats dominate; revocation must survive partitions.

[CONTRACT: CTR-2703] ActorId representation and validation (migration-aware).
- Short term (current APM2 code reality):
  - Actor IDs may exist as strings, but **must be validated and canonicalized at the boundary** (length + allowed character set + non-flag prefix).
  - REJECT IF: unvalidated `actor_id: String` crosses a trust boundary (network/IPC/file) into core logic.
- Long term (target posture):
  - prefer a strongly typed `ActorId` newtype bound to cryptographic identity material (e.g., digest of verifying key),
  - avoid “identity by display name” in signature payloads and ledger events.
- ENFORCE BY:
  - centralize actor-id parsing/validation; do not duplicate ad-hoc regexes,
  - never use `actor_id` directly as a filesystem path segment or a shell argv component.
[PROVENANCE] APM2 already enforces actor-id validation to prevent path traversal and flag confusion (see `crates/apm2-core/src/crypto/keys.rs`); security posture targets cryptographic binding (see RFC-0010).

[HAZARD: RSK-2702] Capability amplification via recursive delegation (confused deputy).
- TRIGGER: a sub-holon induces a parent to perform actions using the parent's higher-trust credentials.
- REJECT IF: delegation tokens are not attenuated (scoped to purpose, time, and target).
- ENFORCE BY:
  - bind tokens to a `CapabilityScope`,
  - verify every relayed command includes the full delegation chain for audit.
[PROVENANCE] `documents/security/THREAT_MODEL.cac.json`: authorization threats in holarchies are typically delegation bugs.

## References (Normative Anchors)

- `documents/security/THREAT_MODEL.cac.json`: distributed holonic threat posture.
- RFC-0010: identity and ActorId specification.
- RFC-0014: capability-based authorization protocol.
