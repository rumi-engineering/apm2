# Defects in Holonic Agent Systems: An Evidence-First Textbook
## Defect Theory, Taxonomy, Schemas, Gates, and Closed-Loop Remediation for Agent-Native Networks
**v1.0 (draft)** — 2026-01-26

> Normative keywords (MUST, SHOULD, MAY) are interpreted as described in RFC 2119.


# VOLUME 5 — Containment and Safety: Capabilities, SoD, Context Firewalls

## 5.1 Default-Deny Capability Model
Holons MUST operate under least privilege: explicit capabilities, short leases, and bounded budgets. Any implicit authority channel is a security defect. Capability sets are first-class artifacts referenced in defect records and gate receipts.

## 5.2 Separation of Duties (SoD)
Authoring, reviewing, approving, and promoting are distinct roles. The system MUST enforce SoD mechanically at merge and at promotion gates. “Same principal can both propose and approve” is always a SECURITY_CAPABILITY defect, regardless of whether abuse occurred.

SoD should be enforced by identity lineage rules: a holon MUST NOT approve artifacts originating from itself or its controlled sub-holons.

## 5.3 Context Firewalls
A ContextPack is an allowlist for reads and tool usage. Runtime MUST deny reads outside the pack unless the plan explicitly authorizes escalation. Any escalation MUST emit a defect record with the precise missing context reference. Context firewalls prevent derailment by irrelevant inputs and reduce accidental leakage of stale or misleading documentation.

## 5.4 Attention Budgets and Termination
Holons MUST terminate when they exceed attention budgets or encounter irreconcilable ambiguity. Crash-only behavior is a correctness and safety measure: it avoids partial completion under corrupted context. Terminations must produce DefectRecords if caused by missing context, missing contracts, or capability constraints.

## 5.5 Release Safety and Rollback
Release processes are verifiers. Promotion MUST be gated by evidence: GateRun receipts, dogfood results, and runtime guardrail checks. Rollback mechanisms MUST be tested and are themselves defect surfaces. Any manual rollback is a defect unless policy explicitly allows it under emergency modes with recorded evidence.
