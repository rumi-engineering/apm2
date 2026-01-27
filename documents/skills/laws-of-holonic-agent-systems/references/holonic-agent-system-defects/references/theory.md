# Defects in Holonic Agent Systems — Theory and Core Principles

## Principle
A *defect* is any evidence-backed counterexample that causes the system to expend avoidable work or accept avoidable risk.
This includes inefficiencies, ambiguity, verifier weakness, and unnecessary tool calls.

## 1. Definition and Scope
A defect is an evidence-backed counterexample that causes avoidable work or avoidable risk. Defects include functional failures, verifier failures, process failures, and inefficiencies. Every CI failure is a defect. Every tool call executed to discover missing context is a defect. Every ambiguity that forces interpretation is a defect. The defect system exists to convert counterexamples into stable operators (primitives), stronger verifiers (gates), and tighter refinement rules.

## 2. Holonic Constraints (Why Defects Differ Here)
Holons are bounded, ephemeral, crash-only actors whose internal state is non-durable. Durable truth exists only as an append-only ledger of evidence-carrying events. Therefore: defect handling MUST be event-sourced, replayable, and contract-driven. Free-form narratives are not sufficient; all actionable defect data MUST be machine readable, linkable to upstream intents, and associated with evidence.

## 3. Core Objects
- **Intent**: predicate over system state/traces; carries priority and risk tier.
- **Contract**: normative interface constraint (CLI output, daemon API, schema, policy).
- **Verifier**: procedure producing Pass or Fail(counterexample).
- **EvidenceBundle**: content-addressed artifacts bound to verifier execution.
- **Counterexample**: minimal falsifying instance produced by a verifier or observation stream.
- **DefectRecord**: schema-conformant counterexample linked to intents, contracts, and evidence.
- **RemediationPlan**: compiled mapping from defect to bounded change sets and verifier upgrades.
- **Primitive**: invariant-preserving operator with a small stable API and packaged evidence.

## 4. Universal Defect Principle
Every verifier failure is a defect. A CI failure is always a defect. A flaky test is a verification defect. An incident lacking sufficient telemetry is a verification defect. A release requiring manual rollback is an operations defect. 

The **Zero-Tool Ideal (ZTI)** mandates that implementation should be actuation, not exploration. This applies to **scoped implementation tasks**. 

**Research Exemption:** ZTI does NOT apply to holons whose primary mission is **Research, Discovery, or Mapping**. In research contexts, tool-based exploration is the core work product.

Any tool call executed primarily to discover missing context in a scoped task is a **context defect**. However, tool calls used for **verification** (tests, linters, compilers) are exempt from ZTI inefficiency counts as they represent active inference.

In high-entropy states where environmental complexity exceeds a holon's requisite variety, the holon MAY request a **Human-as-Oracle** intervention. This is classified as a **Specification Gap** (Engineering domain) that updates the refinement compiler, rather than a defect of the agent itself.

## 5. Containment: Capability Integrity, SoD, Context Firewalls
### 5.1 Capability Model
Default-deny, least privilege, short leases, bounded budgets. Any implicit authority channel is a defect. Capability sets must be referenced in defect records.

### 5.2 Separation of Duties
Authoring, reviewing, approving, and promoting are disjoint roles enforced mechanically. Self-approval is always a defect.

### 5.3 Context Firewalls
Deny-by-default access outside ContextPacks prevents derailment and reduces information hazards. Any escalation is a defect unless explicitly authorized.

## 6. Learning Loop: Flywheel Mechanics
Defect clusters drive investments: recurrent defects become primitives and refinement rules; verifier portfolios are optimized for signal per cost; ZTI converges by moving context discovery into compilation. The roadmap is derived from recurrence clusters and evidence counts, not opinion.
