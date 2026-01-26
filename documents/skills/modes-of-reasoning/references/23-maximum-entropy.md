# Maximum-Entropy / Information-Theoretic Reasoning

**Category:** Reasoning Under Uncertainty

## What it is

Choose distributions satisfying known constraints while assuming as little else as possible (maximize entropy).

## What it outputs

- Principled default distributions
- Minimally committed priors under constraints
- Objective baseline models

## How it differs

"Least-committal completion" rather than explanation. Doesn't claim the world is maximally random, just that we shouldn't assume more structure than we have evidence for.

## Best for

- Baselines
- Priors under constraints
- Principled defaults in modeling
- Information-theoretic analysis

## Common failure mode

Constraints are wrong/underspecified → outputs look "objective" but aren't. The maximum-entropy distribution is only as good as the constraints you provide.

## Related modes

- [Bayesian reasoning](11-bayesian-probabilistic.md) — uses max-ent for prior selection
- [Simplicity / compression reasoning](17-simplicity-compression.md) — related parsimony principle
- [Imprecise probability](21-imprecise-probability.md) — alternative when constraints are weak
