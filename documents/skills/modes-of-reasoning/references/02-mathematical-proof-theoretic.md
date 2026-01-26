# Mathematical / Proof-Theoretic Reasoning

**Category:** Formal and Mathematical Reasoning

## What it is

Deduction where the **proof object** matters (what counts as a proof, how it's constructed).

## What it outputs

- Formal proofs (sometimes machine-checkable)
- Proof transformations
- Derivability results

## How it differs

More structured than everyday deduction; emphasizes *derivability* and proof structure. The proof itself is a first-class artifact, not just the conclusion.

## Best for

- Formal methods
- Theorem proving
- Certified reasoning pipelines
- Building verified software components

## Common failure mode

Proving the wrong theorem (spec mismatch) or proving something irrelevant to outcomes. The proof may be correct but disconnected from what actually matters.

## Related modes

- [Deductive reasoning](01-deductive-reasoning.md) — the underlying inference pattern
- [Constructive reasoning](03-constructive-intuitionistic.md) — proofs that correspond to algorithms
- [Type-theoretic reasoning](07-type-theoretic.md) — propositions as types
