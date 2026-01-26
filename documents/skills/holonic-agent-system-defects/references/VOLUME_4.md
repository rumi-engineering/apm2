# Defects in Holonic Agent Systems: An Evidence-First Textbook
## Defect Theory, Taxonomy, Schemas, Gates, and Closed-Loop Remediation for Agent-Native Networks
**v1.0 (draft)** — 2026-01-26

> Normative keywords (MUST, SHOULD, MAY) are interpreted as described in RFC 2119.


# VOLUME 4 — Triage and Root Cause: Causal Graphs and Uncertainty

## 4.1 Intake and Enrichment
Defect intake MUST be canonical and machine readable. Free-form channels MAY exist but MUST be mapped into DefectRecords. Intake enrichers attach upstream references, compute fingerprints, extract repro steps from logs, and link evidence. Intake MUST reject defects lacking minimal reproducibility unless the defect is explicitly an observability/verification defect.

## 4.2 Classification Agents
Classification uses deterministic rules first; probabilistic inference is advisory. Misclassification is corrected by appending new analysis, never rewriting history. Classification drift is monitored by tracking changes in classifier outputs and by validating against known canonical examples.

## 4.3 Root Cause as Causal Edge Set
Root cause is represented as a set of causal edges from the defect to candidate upstream failures:
- missing intent predicate,
- weak contract,
- missing refinement decision,
- missing primitive,
- incorrect implementation,
- missing or flaky verifier,
- capability overgrant/undergrant,
- context pack insufficiency.

A causal edge is valid only with supporting evidence references.

## 4.4 Uncertainty Handling
Defects are assigned reproducibility classes. FLAKY defects default to VERIFICATION domain until stabilized; remediation focuses on eliminating nondeterminism and improving evidence capture. Probabilistic defects MUST record confidence and sampling conditions. Unknown-class defects are prioritized by severity and blast radius until classified.

## 4.5 Dedupe and Recurrence
Duplicate defects are merged into a single canonical record with multiple occurrences. Recurrence is measured by occurrence counts and time-to-recurrence, not by subjective severity. A rapidly recurring defect is treated as systemic and triggers primitive/verifier upgrades.
