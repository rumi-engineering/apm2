# Defects in Holonic Agent Systems: An Evidence-First Textbook
## Defect Theory, Taxonomy, Schemas, Gates, and Closed-Loop Remediation for Agent-Native Networks
**v1.0 (draft)** — 2026-01-26

> Normative keywords (MUST, SHOULD, MAY) are interpreted as described in RFC 2119.


# VOLUME 2 — Taxonomy: Domains, Stages, Surfaces, Severity

## 2.1 Orthogonal Classification
Classification MUST be orthogonal:
- domain: nature of failure,
- stage: where detected,
- surface: which interface boundary failed,
- severity: stop-the-line impact and blast radius,
- reproducibility: determinism class.

Orthogonality prevents the taxonomy from collapsing into incident-specific labels.

## 2.2 Broad Domains
Domains are designed for longevity:
- CONTEXT: missing/misleading information; stale docs; overscoped work; unnecessary tool calls.
- ENGINEERING: incorrect mechanisms; missing abstractions; unsafe code; nondeterminism.
- VERIFICATION: weak or flaky verifiers; missing gates; incorrect oracles; false positives/negatives.
- SECURITY_CAPABILITY: capability overgrant/undergrant; policy bypass; SoD violations; distracted agents.
- PRODUCT_VALUE: objectives not met; features mis-specified; misleading affordances.
- OPERATIONS: runtime instability; rollout failure; observability gaps; incident response failure.
- ECONOMICS: wasted compute; poor budget allocation; redundant work; non-optimal throughput.

## 2.3 Stages and Escapes
A defect detected in a later stage implies an escape from earlier verifiers. Stage analysis focuses on why the defect was not detected earlier and which verifier must be strengthened. The system SHOULD treat “detected at runtime” as a failure of upstream refinement and verification, unless the property is inherently runtime-only.

## 2.4 Surfaces and Contracts
Surfaces correspond to contracts:
- CLI: output, exit codes, structured mode, UX affordances.
- DAEMON_API: protocol semantics and idempotency.
- LEDGER/EVIDENCE: immutability, addressing, retention, replay.
- POLICY/CAPABILITY: grants, leases, SoD, audit.
- PRIMITIVE: invariant-preserving operators and their APIs.
- TEMPLATE/DOCS: refinement scaffolding and discoverability.
- INFRA/OBSERVABILITY: deployment, monitoring, telemetry contracts.

A surface defect is a contract defect until proven otherwise.

## 2.5 Severity and Blast Radius
Severity is defined by propagation potential, not by local inconvenience. In holonic networks, capability and verification defects often outrank correctness defects because they allow systemic drift. A stop-the-line defect is any defect that breaks fail-closed posture, enables privilege escalation, corrupts evidence/ledger integrity, or allows unbounded exploration.
