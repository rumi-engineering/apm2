# Counterexample-Guided Reasoning (CEGAR-style)

**Category:** Formal and Mathematical Reasoning

## What it is

Propose an abstraction; check; if a counterexample appears, refine the abstraction and repeat.

## What it outputs

- Either a proof of property or a concrete counterexample
- Refined models
- Successively tighter abstractions

## How it differs

It's a *loop* blending deduction + model checking + refinement, built for scalability. Instead of getting verification right the first time, you iteratively improve.

## Best for

- Verification
- Security properties
- Systems where full modeling is too expensive
- Scalable formal analysis

## Common failure mode

Endless refinement loops if the abstraction boundary is poorly chosen. Some abstractions never converge to a useful granularity.

## Related modes

- [Model-theoretic reasoning](05-model-theoretic-semantic.md) — countermodels drive refinement
- [Constraint / satisfiability reasoning](06-constraint-satisfiability.md) — often used in the checking step
- [Belief revision](33-belief-revision.md) — conceptually similar iterative refinement
