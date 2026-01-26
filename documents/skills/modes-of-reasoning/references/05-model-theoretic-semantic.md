# Model-Theoretic / Semantic Reasoning

**Category:** Formal and Mathematical Reasoning

## What it is

Reason by constructing/analyzing **models** that satisfy a theory (true in all models vs some).

## What it outputs

- Satisfiable/unsatisfiable verdicts
- Countermodels
- Interpretations
- Semantic entailment results

## How it differs

Complements proof-theory: instead of "derive," you "build a world where it holds/doesn't." Focuses on what structures make statements true rather than how to derive them.

## Best for

- Consistency checks
- Finding hidden assumptions
- Generating counterexamples
- Understanding what a specification actually allows

## Common failure mode

Model doesn't match the intended semantics of the real system. The mathematical model may satisfy your theory while diverging from reality in important ways.

## Related modes

- [Mathematical / proof-theoretic reasoning](02-mathematical-proof-theoretic.md) — complementary approach
- [Constraint / satisfiability reasoning](06-constraint-satisfiability.md) — computational model finding
- [Counterexample-guided reasoning](08-counterexample-guided.md) — uses countermodels for refinement
