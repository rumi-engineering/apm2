# Type-Theoretic Reasoning

**Category:** Formal and Mathematical Reasoning

## What it is

Use types (including dependent/refinement types) to enforce invariants; "propositions as types" in some systems.

## What it outputs

- Type derivations
- Well-typed programs
- Compositional guarantees
- API contracts

## How it differs

Reasoning is integrated into construction; great for modular correctness. Types encode properties and the type checker verifies them automatically during development.

## Best for

- API design
- Correctness-by-construction
- Safe composition of large systems
- Preventing entire classes of bugs statically

## Common failure mode

Fighting the type system instead of clarifying the spec it encodes. If the types are fighting you, the problem may be unclear requirements, not the type system.

## Related modes

- [Constructive reasoning](03-constructive-intuitionistic.md) — Curry-Howard correspondence
- [Mathematical / proof-theoretic reasoning](02-mathematical-proof-theoretic.md) — types as proofs
- [Constraint / satisfiability reasoning](06-constraint-satisfiability.md) — type checking as constraint solving
