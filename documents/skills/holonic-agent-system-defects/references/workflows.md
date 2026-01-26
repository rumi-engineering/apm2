# Defects in Holonic Agent Systems — Detection, Triage, and Remediation

## 1. Detection: Gates, Dogfood, Runtime Oracles
### 1.1 GateRuns and Receipts
All verification is performed via GateRuns producing receipts. Approvals/denials are state transitions backed by receipts. Comment-only state is a defect. CI failures are defects by definition and trigger DefectRecords or merged occurrences.

### 1.2 Dogfood Holons
Dogfood holons execute executable scenarios against release candidates and releases and emit DefectRecords with evidence. Dogfood is required to detect UX and integration defects not captured by CI.

### 1.3 Runtime Observations
Runtime telemetry and incidents are structured counterexamples linked to releases and intents. Observability gaps are defects; any failure without sufficient diagnosis evidence must be recorded as a verification defect.

## 2. Triage and Root Cause
### 2.1 Intake
Defect intake is canonical and machine readable. Records lacking minimal reproducibility are rejected unless classified as observability defects. Enrichment attaches links and evidence and computes fingerprints.

### 2.2 Root Cause Graph
Root cause is represented as causal edges to upstream failures: missing intent, weak contract, missing refinement decision, missing primitive, incorrect implementation, missing/flaky verifier, capability drift, context pack insufficiency.

### 2.3 Uncertainty
Flaky outcomes are verification defects until stabilized. Probabilistic defects record confidence and sampling conditions.

## 3. Remediation and Closure
### 3.1 Remediation as Compilation
DefectRecords compile into RemediationPlans and bounded change sets. Plans specify restored contracts/predicates, verifiers, and closure evidence.

### 3.2 Correct Remediation Class
Choose among patch, primitive, verifier, refinement update, policy fix, UX contract fix. Patching symptoms when a primitive is missing is a defect.

### 3.3 Closure Rules
A defect closes only with a new or strengthened verifier that would have failed on the original counterexample and now passes, with receipts and evidence captured.

### 3.4 Economic Closure
Economic defects close when measured waste decreases under equal or stronger verifier coverage.
