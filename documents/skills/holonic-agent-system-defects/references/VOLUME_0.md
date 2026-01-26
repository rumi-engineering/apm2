# Defects in Holonic Agent Systems: An Evidence-First Textbook
## Defect Theory, Taxonomy, Schemas, Gates, and Closed-Loop Remediation for Agent-Native Networks
**v1.0 (draft)** — 2026-01-26

> Normative keywords (MUST, SHOULD, MAY) are interpreted as described in RFC 2119.


# VOLUME 0 — Normative Model and Vocabulary

## 0.1 Defect as Counterexample
A defect is an evidence-backed counterexample that falsifies an intent predicate or a contract under a verifier. A defect is not limited to functional incorrectness; any avoidable work, avoidable risk, avoidable ambiguity, or avoidable non-determinism is a defect. A defect record MUST be replayable in principle; if full replay is impossible, the defect record MUST capture the exact boundary of non-replayability and the minimum evidence needed to confirm recurrence.

Defects subsume:
- inefficiency defects (avoidable tool calls, redundant compute, excessive context),
- process defects (missing receipts, missing gates, unbounded exploration),
- operations defects (SLO violations, rollback failures, non-observable failures),
- security/capability defects (overgrant, confused deputy, SoD violations),
- product value defects (wrong objective, misleading affordances).

## 0.2 Holons, Boundaries, and Channel Classes
A holon is a bounded agent whose internal state is ephemeral. Holons interact only via sensory states (inputs) and active states (outputs) across explicit channels. Channels MUST be classified (discovery, handshake, work, evidence) and governed by leases and budgets. Any implicit channel (e.g., ad hoc repository browsing, unbounded web search, undocumented sideband state) is a defect surface.

## 0.3 Intent, Contract, Verifier, Evidence
Intent is a predicate over system state and/or traces. Contracts are normative interface constraints (CLI output, daemon API semantics, schema shape, policy rules). Verifiers are procedures that produce Pass or Fail(counterexample). Evidence is the replayable artifact set bound to a verifier outcome. An autonomous SDLC is a refinement compiler that maps intents into verifiers and change sets, then uses counterexamples to strengthen both.

## 0.4 The Zero-Tool Ideal (ZTI)
The Zero-Tool Ideal states: an implementing holon SHOULD complete its assigned work without additional tool calls to discover context. This applies to the **execution of scoped implementation tasks**. All necessary context SHOULD be preloaded via a ContextPack that fits a declared ContextBudget. 

Any non-zero tool calls used primarily to discover missing context in a scoped task MUST be recorded as an inefficiency defect. ZTI is not a ban on tools; it is a design goal that forces the system to treat context as a compiled artifact, not an emergent byproduct. 

**Exemptions:**
1. **Research & Exploration:** ZTI does NOT apply to holons whose defined mission is research, discovery, or mapping. In these cases, exploration is the primary value-add.
2. **Verification Tools:** Tools (tests, compilers, linters) used for active inference are exempt from this inefficiency count.

## 0.5 Universal Defect Principle
Every failure of a verifier is a defect. A CI failure is always a defect, even if the underlying code is correct, because it still consumed avoidable cycle time and indicates weak specification, weak determinism, or weak gating. 

Manual intervention required to reconcile state or interpret ambiguous output is generally a defect. However, in high-entropy states where environmental complexity exceeds a holon's requisite variety, an explicit request for **Human-as-Oracle** adjudication is treated as a **Specification Gap** (Engineering domain). This event is used to refine the upstream compiler rather than penalize the implementation holon.
