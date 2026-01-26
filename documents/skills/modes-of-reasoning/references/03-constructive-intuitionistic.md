# Constructive (Intuitionistic) Reasoning

**Category:** Formal and Mathematical Reasoning

## What it is

A proof of existence must provide a **construction/witness**; some classical principles (like excluded middle) are restricted.

## What it outputs

- Proofs that often correspond to **algorithms** ("proofs as programs")
- Constructive witnesses for existence claims
- Computationally meaningful derivations

## How it differs

Stronger link between "proved" and "computable." You can't just prove something exists by contradiction—you must show how to construct it.

## Best for

- Verified software
- Protocol design
- Constructive mathematics
- "Show me the witness" requirements
- Extraction of programs from proofs

## Common failure mode

Over-constraining when classical reasoning is acceptable and simpler. Not every proof needs to be constructive; sometimes proof by contradiction is fine.

## Related modes

- [Mathematical / proof-theoretic reasoning](02-mathematical-proof-theoretic.md) — broader proof theory
- [Type-theoretic reasoning](07-type-theoretic.md) — Curry-Howard correspondence
