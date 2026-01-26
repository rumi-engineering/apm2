# Defects in Holonic Agent Systems: An Evidence-First Textbook
## Defect Theory, Taxonomy, Schemas, Gates, and Closed-Loop Remediation for Agent-Native Networks
**v1.0 (draft)** — 2026-01-26

> Normative keywords (MUST, SHOULD, MAY) are interpreted as described in RFC 2119.


# VOLUME 7 — Learning Loop: Primitives, Refinement, Verifier Portfolio

## 7.1 Primitives as System Memory
Primitives are invariant-preserving operators with explicit contracts and packaged evidence. A primitive exists to eliminate repeated defect classes by construction. Primitives MUST be discoverable (registry), testable (proof obligations), and composable (small stable APIs). Duplicate cousin abstractions are defects.

## 7.2 Refinement Compiler Upgrades
Defects update the refinement compiler: PRD/RFC/ticket generation rules evolve to preempt counterexamples. Context defects produce ContextPack rules and budget constraints. Engineering defects produce required primitive usage and proof obligations. Verification defects produce new gates and stabilization work. Security defects produce capability and SoD constraints.

## 7.3 Verifier Portfolio Optimization
A verifier portfolio is optimized for signal per unit cost. The system MUST track:
- verifier cost (time, compute, flake rate),
- verifier value (prevented recurrences, earlier detection),
- portfolio coverage by domain/surface/stage.

Low-value verifiers are replaced by cheaper, sharper checks or by primitives that eliminate the need to verify certain properties repeatedly.

## 7.4 Recurrence-Driven Roadmaps
Roadmaps are derived from clustered defects: the largest recurrence clusters define where primitives and verifiers should be invested. This replaces anecdotal prioritization with counterexample economics. The roadmap itself is governed: it must cite defect cluster fingerprints and evidence counts.

## 7.5 Zero-Tool Ideal Convergence
The system converges toward ZTI by migrating context discovery from execution to compilation for **scoped implementation tasks**. Every “tool call for context” in these tasks is a measured inefficiency defect (**Research tasks** are exempt), enabling the compiler to learn which contexts to preload in future packs.
