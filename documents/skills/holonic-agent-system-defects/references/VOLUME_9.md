# Defects in Holonic Agent Systems: An Evidence-First Textbook
## Defect Theory, Taxonomy, Schemas, Gates, and Closed-Loop Remediation for Agent-Native Networks
**v1.0 (draft)** — 2026-01-26

> Normative keywords (MUST, SHOULD, MAY) are interpreted as described in RFC 2119.


# VOLUME 9 — Appendices: Checklists, Invariants, Reference Formats

## 9.1 Minimal Invariants (Non-Negotiable)
- Evidence integrity: content addressing, retention, replay.
- Fail-closed gates: no merge/promotion without required receipts.
- Capability least privilege and SoD enforcement.
- ContextPack enforcement and budget adherence.
- Deterministic structured outputs for automation surfaces.
- Regression prevention for every fix.

## 9.2 Defect-Handling Checklists
### Intake checklist
- Contains expected vs observed statement.
- Contains repro recipe or explicitly classified as observability defect.
- Contains evidence references.
- Links to intent/contract references.
- Fingerprint computed.

### Remediation checklist
- Choose remediation class correctly.
- Add or fix verifier.
- Update contract/spec/template if needed.
- Provide closure evidence.

## 9.3 Reference Schemas
See `schemas/taxonomy.yaml` and `schemas/defect_record_schema.yaml`. Schemas are normative; changes must be versioned. Schema evolution is additive-only in place; breaking changes require new schema IDs.

## 9.4 Inefficiency Catalog (Defects as Waste)
Inefficiency defects include:
- any additional context discovery tool call beyond the ContextPack for a **scoped implementation task** (**Research tasks** and **Verification tools** used for active inference are exempt),
- repeated CI failures due to flake or missing determinism,
- redundant compilation of identical artifacts without caching,
- ambiguous CLI output requiring interpretation,
- repeated review cycles due to missing proof obligations,
- unbounded exploration without leases/stop rules,
- missing or delayed observability preventing fast triage.

Inefficiency defects are prioritized by cumulative cost and by their amplification effect on downstream stages.
