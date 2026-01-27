# Defects in Holonic Agent Systems: An Evidence-First Textbook
## Defect Theory, Taxonomy, Schemas, Gates, and Closed-Loop Remediation for Agent-Native Networks
**v1.0 (draft)** — 2026-01-26

> Normative keywords (MUST, SHOULD, MAY) are interpreted as described in RFC 2119.


# VOLUME 3 — Detection: Oracles, Gates, Dogfood, Runtime

## 3.1 Verifiers as Capital
Verifiers are assets that reduce future work. Every verifier MUST output structured counterexamples. A verifier with high cost and low discrimination is an economics defect; it must be replaced or augmented with cheaper, higher-signal checks. Verifier design is a core engineering discipline in holonic systems.

## 3.2 GateRuns and Receipts
A GateRun is a deterministic execution of verifiers over a change set. GateRuns MUST produce receipts (content-addressed, signed) that prove which verifiers ran, against which inputs, with which outputs. Comment-only approvals are defects; all approvals/denials MUST be state transitions backed by receipts.

All CI failures are defects. CI may fail due to code, flakiness, environment drift, or missing contracts; all cases consume resources and must be corrected.

## 3.3 Dogfood Holons as High-Signal UAT
Dogfood holons execute scenario suites against releases and release candidates. Scenarios are executable specifications with required evidence outputs. Dogfood is the bridge between “passes CI” and “works operationally,” and it converts usability failures (misleading output, confusing workflows, missing affordances) into structured counterexamples.

Dogfood MUST run in a sealed environment and emit only evidence, not sideband state. Trusted tunnels are treated as elevated-risk channels and must be explicitly authorized by policy.

## 3.4 Runtime Telemetry as Verifier Stream
Production telemetry is a verifier stream for properties not simulable in CI: SLOs, cost envelopes, performance under real data distributions, and operational reliability. Runtime defects MUST be captured as DefectRecords with links to releases and intents and with sufficient evidence to enable triage. Observability gaps are themselves defects: any incident without enough telemetry to diagnose is a verification defect.

## 3.5 The Context Discovery Ban (Operational Form)
If an agent must perform tool calls primarily to discover missing context, the planning stage failed. The system MUST record such occurrences as CONTEXT defects with inefficiency annotations. The target state is precompiled context so that work execution is predominantly actuation, not exploration.
