# Defects in Holonic Agent Systems: An Evidence-First Textbook
## Defect Theory, Taxonomy, Schemas, Gates, and Closed-Loop Remediation for Agent-Native Networks
**v1.0 (draft)** — 2026-01-26

> Normative keywords (MUST, SHOULD, MAY) are interpreted as described in RFC 2119.


# VOLUME 6 — Remediation: Plans, ChangeSets, and Closure Rules

## 6.1 Remediation as Compilation
Remediation converts DefectRecords into RemediationPlans, which compile into bounded tickets and change sets. A plan MUST specify:
- the contract or predicate to be restored or introduced,
- the verifier to prevent recurrence,
- the smallest safe change set sequence,
- the evidence required for closure.

## 6.2 Remediation Classes
Remediation must choose among:
- Implementation patch: fix code/config.
- Primitive creation/extension: create invariant-preserving operator to eliminate a class of defects.
- Verifier strengthening: add/fix gate, stabilize oracle, add negative tests.
- Refinement update: update PRD/RFC/ticket templates to emit required constraints.
- Policy/capability fix: adjust permissions, SoD, leases.
- UX/contract fix: change CLI output/contracts with golden tests.

Misrouting remediation (e.g., patching symptoms when a primitive is missing) is itself a defect.

## 6.3 Closure Criteria
A defect is closed only when:
- a verifier exists that fails on the original counterexample,
- the verifier passes on the fixed state,
- evidence receipts are captured and referenced,
- the relevant contract/intent references are updated when applicable.

“Works on my machine” is a defect. Closure is evidence-backed.

## 6.4 Economic Closure
Defects may be purely economic: redundant compute, unnecessary tool calls, excessive context. Economic defects close when the system demonstrates reduced resource consumption under equal or stronger verifier coverage. Economic closure requires measurement harnesses and reproducible benchmarks.

## 6.5 Preventing Regression
All fixes MUST include regression prevention: tests, gates, or policies. Regression monitoring windows are specified per severity. If recurrence occurs within the monitoring window, the defect is reopened and severity escalated.
