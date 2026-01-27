# Defects in Holonic Agent Systems — Substrate: Schemas, Ledger, Evidence, Fingerprints

## 1. Schema Discipline
DefectRecords MUST conform to a versioned schema. Schema evolution MUST be additive-only; breaking changes require new schema IDs. Stable enumerations prevent drift and enable automated remediation routing.

## 2. Ledger Discipline
Defects MUST be events in a ledger DAG. The ledger binds: intent → refinement → change set → verifier run → evidence → runtime observation. Immutable history enables replay and prevents authority forks.

## 3. Evidence Discipline
EvidenceBundles MUST be content-addressed and sufficient to validate defect claims. Replay determinism class MUST be recorded. Non-replayable defects are treated as verification defects until stabilized.

## 4. Fingerprinting
Fingerprints enable dedupe and clustering. Strict and semantic fingerprints SHOULD be computed to support recurrence analysis without large-scale rollout data.
