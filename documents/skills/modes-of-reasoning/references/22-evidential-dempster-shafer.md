# Evidential Reasoning (Dempster-Shafer / Belief Functions)

**Category:** Reasoning Under Uncertainty

## What it is

Allocate "mass" to sets of possibilities; combine evidence into belief/plausibility intervals.

## What it outputs

- Belief + plausibility ranges
- Fused evidence from multiple sources
- Explicit representation of ignorance

## How it differs

Can represent partial support for sets (not point hypotheses) more directly than standard probability. Distinguishes between "no evidence for X" and "evidence against X."

## Best for

- Multi-source fusion
- Ambiguous evidence
- Partial identification
- Sensor fusion

## Common failure mode

Misusing combination rules when sources aren't independent. Dempster's rule assumes independence; violations can produce counterintuitive results.

## Related modes

- [Bayesian reasoning](11-bayesian-probabilistic.md) — alternative framework
- [Imprecise probability](21-imprecise-probability.md) — related representation of uncertainty
- [Fuzzy logic](25-fuzzy-logic.md) — addresses vagueness, not uncertainty
