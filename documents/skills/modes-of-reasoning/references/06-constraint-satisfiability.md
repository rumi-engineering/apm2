# Constraint / Satisfiability Reasoning (SAT/SMT/CSP)

**Category:** Formal and Mathematical Reasoning

## What it is

Encode requirements as constraints and solve for assignments that satisfy them (or prove none exist).

## What it outputs

- A satisfying assignment
- **Unsat** certificate
- Minimal unsat cores
- Counterexamples

## How it differs

It can implement deduction, but the "mode" is **solve-by-consistency** rather than argument-by-argument inference. You declare what must hold and let the solver find (or refute) solutions.

## Best for

- Scheduling
- Configuration
- Verification
- Policy enforcement
- Feasibility checks
- Resource allocation

## Common failure mode

Poor encoding (missed constraints) → false confidence. If you don't encode all the real requirements, "satisfiable" doesn't mean the solution actually works.

## Related modes

- [Deductive reasoning](01-deductive-reasoning.md) — what constraints implement
- [Model-theoretic reasoning](05-model-theoretic-semantic.md) — semantic foundation
- [Optimization reasoning](48-optimization.md) — constraints + objective functions
