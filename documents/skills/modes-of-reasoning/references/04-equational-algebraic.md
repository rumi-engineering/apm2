# Equational / Algebraic Reasoning (Rewrite-Based)

**Category:** Formal and Mathematical Reasoning

## What it is

Transform expressions using equalities and rewrite rules while preserving meaning.

## What it outputs

- Equivalent forms
- Normal forms
- Simplifications
- Invariants

## How it differs

Deduction specialized to **symbol manipulation**; often the everyday workhorse in math/CS. Focuses on term rewriting rather than logical derivation.

## Best for

- Refactoring
- Optimization proofs
- Dimensional reasoning scaffolds
- Invariant manipulation
- Algebraic simplification

## Common failure mode

Unsound rewrite rules or implicit domain restrictions (division by zero, overflow). Rules that work "most of the time" can fail silently at boundaries.

## Related modes

- [Deductive reasoning](01-deductive-reasoning.md) — underlying logical framework
- [Constraint / satisfiability reasoning](06-constraint-satisfiability.md) — can use equational constraints
