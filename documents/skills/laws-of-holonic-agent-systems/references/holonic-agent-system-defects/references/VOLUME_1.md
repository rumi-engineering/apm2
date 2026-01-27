# Defects in Holonic Agent Systems: An Evidence-First Textbook
## Defect Theory, Taxonomy, Schemas, Gates, and Closed-Loop Remediation for Agent-Native Networks
**v1.0 (draft)** — 2026-01-26

> Normative keywords (MUST, SHOULD, MAY) are interpreted as described in RFC 2119.


# VOLUME 1 — Substrate: Schemas, Ledger, and Evidence

## 1.1 The DefectRecord Contract
Defect analysis requires a stable, machine-readable schema. The schema MUST be strict enough to support deterministic deduplication and clustering while remaining extensible. Fields that MUST be stable identifiers: intent references, contract references, release references, gate run references, evidence references, actor identity, and fingerprint.

A DefectRecord MUST contain:
- a single statement of falsified intent/contract (expected vs observed),
- minimal reproduction recipe (commands over prose),
- content-addressed evidence references,
- links into upstream planning artifacts (PRD/RFC/ticket/PR),
- classification fields (domain, stage, surface, severity).

## 1.2 Ledger DAG and Causality
A defect system MUST be event-sourced: defects, findings, gate runs, releases, and incidents are events appended to a ledger. Events MUST be causally linked, forming a DAG of truth. Causality enables:
- immutable provenance of defect discovery and remediation,
- replay of the exact verifier that produced a counterexample,
- safe merging of distributed defect streams.

To optimize performance, the system SHOULD support **Sub-Episode Checkpointing** (recording intermediate tool outputs) for fine-grained recovery and **Canonical State Snapshots** to prune historical replay requirements.

## 1.3 EvidenceBundles and Replay Semantics
EvidenceBundles are content-addressed collections of artifacts sufficient to validate a claim. Evidence includes: command transcripts, environment snapshots, configuration hashes, logs, traces, and output hashes. Replay semantics MUST specify determinism class:
- deterministic replay (same inputs ⇒ same outcome),
- probabilistic replay (bounded randomness with confidence),
- non-replayable (explicitly documented boundary and surrogate evidence).

Non-replayable defects are permitted but MUST be treated as verification defects until stabilized.

## 1.4 Normalization and Fingerprinting
A fingerprint is a deterministic hash over normalized fields used to merge duplicates. Normalization MUST remove irrelevant variance (timestamps, random IDs, ordering noise) while preserving causal uniqueness. The system SHOULD compute multiple fingerprints:
- strict fingerprint (exact repro and environment),
- semantic fingerprint (same surface + same failure signature).

Fingerprints drive recurrence metrics and remediation prioritization without requiring large-scale statistical rollouts.

## 1.5 ContextPacks as Evidence and as Inputs
A ContextPack is a compiled, bounded set of context artifacts required to execute work. ContextPacks MUST be:
- bounded by a ContextBudget,
- content-addressed and referenced from tickets/PRs,
- enforceable at runtime (deny-by-default reads outside the pack),
- sufficient for Zero-Tool Ideal completion.

Any discrepancy between ContextPack contents and actual reads performed MUST be recorded as a context defect.
