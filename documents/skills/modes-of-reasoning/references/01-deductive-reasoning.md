# Deductive Reasoning (Classical Logical Inference)

**Category:** Formal and Mathematical Reasoning

## What it is

If the premises are true and the inference rules are valid, the conclusion **must** be true.

## What it outputs

- Valid entailments
- Proofs/derivations
- Contradictions/counterexamples (via refutation)

## How it differs

**Truth-preserving** and typically **monotonic**; it makes explicit what's already implicit. Unlike ampliative reasoning modes (induction, abduction), deduction cannot generate new knowledge beyond what the premises contain.

## Best for

- Spec checking
- Compliance logic
- Crisp "must/shall" implications
- Formal arguments
- Verification of requirements

## Common failure mode

Garbage-in (false premises) or missing premises that matter in reality. A valid deductive argument with false premises produces unreliable conclusions.

## Related modes

- [Mathematical / proof-theoretic reasoning](02-mathematical-proof-theoretic.md) — more structured, emphasizes proof objects
- [Constraint / satisfiability reasoning](06-constraint-satisfiability.md) — solve-by-consistency approach
- [Type-theoretic reasoning](07-type-theoretic.md) — integrated into construction
