# RFC-0018 Change Summary (TSC finalize)

## Files changed/created and why
- `documents/rfcs/RFC-0018/01_problem_and_imports.yaml` — added evidence-backed gap for missing topic/CAS allowlists in CapabilityManifest.
- `documents/rfcs/RFC-0018/02_design_decisions.yaml` — removed non-pulse rows from HEF truth-plane table, added layering note, tightened tool profile mapping, CAS auth layering, and projection semantics.
- `documents/rfcs/RFC-0018/03_trust_boundaries.yaml` — clarified daemon-side CAS allowlist enforcement and marked NEW WORK REQUIRED (TCK-00314).
- `documents/rfcs/RFC-0018/04_contracts_and_versioning.yaml` — made changeset_digest non-circular (omit field from hash input), expanded artifact rules.
- `documents/rfcs/RFC-0018/05_rollout_and_ops.yaml` — kept RFC-0017 prerequisites explicit in rollout guardrails.
- `documents/rfcs/RFC-0018/06_ticket_decomposition.yaml` — added TCK-00315 (ListFiles/Search tool surface) and corrected TCK-00314 layering.
- `documents/rfcs/RFC-0018/07_test_and_evidence.yaml` — clarified local projection sink semantics; added ChangeSetBundle determinism unit test.
- `documents/rfcs/RFC-0018/08_risks_and_open_questions.yaml` — added tool-surface risk and digest option open question.
- `documents/rfcs/RFC-0018/09_governance_and_gates.yaml` — aligned GATE-HEF-FAC-V0 evidence categories with security evidence IDs.
- `documents/rfcs/RFC-0018/EVIDENCE_APPENDIX.md` — added evidence for tool protocol surfaces and RequestTool stub; added BLAKE3 evidence.
- `documents/rfcs/RFC-0018/requirements/REQ-HEF-0003.yaml` — enforced exact-topic allowlists (no wildcards for session.sock).
- `documents/rfcs/RFC-0018/requirements/REQ-HEF-0005.yaml` — required CAS hash allowlists for FAC artifacts.
- `documents/rfcs/RFC-0018/requirements/REQ-HEF-0010.yaml` — enumerated minimal reviewer tool profile and NEW WORK REQUIRED navigation tool surface.
- `documents/rfcs/RFC-0018/requirements/REQ-HEF-0011.yaml` — expanded ReviewBlocked reason codes.
- `documents/rfcs/RFC-0018/evidence_artifacts/EVID-HEF-0002.yaml` — expanded red-team scope to include CAS allowlist denials.
- `documents/rfcs/RFC-0018/evidence_artifacts/EVID-HEF-0009.yaml` — added no-GitHub constraints.
- `documents/rfcs/RFC-0018/evidence_artifacts/EVID-HEF-0010.yaml` — added no-GitHub constraints.
- `documents/rfcs/RFC-0018/evidence_artifacts/EVID-HEF-0011.yaml` — added no-GitHub constraints.
- `documents/rfcs/RFC-0018/evidence_artifacts/EVID-HEF-0012.yaml` — added local projection sink constraint.
- `schemas/apm2/changeset_bundle_v1.yaml` — schema stub with non-circular digest rule and commit/tree restriction.
- `schemas/apm2/review_artifact_bundle_v1.yaml` — schema stub for review artifacts.
- `schemas/apm2/review_blocked_v1.yaml` — schema stub with expanded reason codes.

## NEW WORK REQUIRED gaps (evidence-backed)
- KernelEvent payload list lacks ChangeSetPublished/ReviewReceiptRecorded/ReviewBlockedRecorded events: `proto/kernel_events.proto:73-93`. Tickets: `TCK-00310`, `TCK-00311`, `TCK-00312`.
- EvidenceEvent only includes EvidencePublished and GateReceiptGenerated: `proto/kernel_events.proto:436-466`. Ticket: `TCK-00312`.
- PolicyResolvedForChangeSet includes changeset_digest but no CAS diff/bundle reference: `proto/kernel_events.proto:726-744`. Ticket: `TCK-00310`.
- ChangeSet risk-tier input tracks file paths/counts only (no file contents/diff): `crates/apm2-core/src/fac/risk_tier.rs:292-313`. Ticket: `TCK-00310`.
- Episode PinnedSnapshot provides repo/lockfile/policy hashes (not a diff bundle): `crates/apm2-daemon/src/episode/snapshot.rs:88-104`. Ticket: `TCK-00311`.
- CapabilityManifest lacks pulse topic allowlists and CAS hash allowlists: `crates/apm2-daemon/src/episode/capability.rs:511-526`. Ticket: `TCK-00314`.
- ToolRequest variants do not include ListFiles/Search navigation tools: `proto/tool_protocol.proto:41-51`. Ticket: `TCK-00315`.
- RequestTool handler is stubbed pending tool broker implementation: `crates/apm2-daemon/src/protocol/session_dispatch.rs:303-351`. Ticket: `RFC-0017:TCK-00260`.

## FAC v0 autonomy: required vs optional
Required for autonomous FAC v0:
- ChangeSetBundleV1 in CAS with ledger-anchored changeset_digest and ChangeSetPublished event (BLAKE3-256 over canonical bundle bytes with digest omitted).
- Workspace snapshot/apply semantics with ReviewBlocked on failure (reason codes + CAS logs).
- ReviewReceiptRecorded ledger event referencing ReviewArtifactBundleV1 (review text + tool logs in CAS).
- End-to-end FAC v0 harness producing evidence for GATE-HEF-FAC-V0 (no GitHub reads for truth; projection validated via local sink/receipt).

Optional / deferred:
- ProjectionReceipt remains projection-only (not a truth source) and is not required to gate v0 autonomy.
- Semantic graph packs, review scoring, durable broker, and multi-host HEF remain future work.
