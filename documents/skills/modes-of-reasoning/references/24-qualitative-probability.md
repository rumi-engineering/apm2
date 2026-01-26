# Qualitative Probability / Ranking-Function Reasoning (Spohn-style)

**Category:** Reasoning Under Uncertainty

## What it is

Replace numeric probabilities with ordinal "degree of disbelief" ranks; update by shifting ranks.

## What it outputs

- Ordered plausibility levels
- Belief dynamics without precise probabilities
- Ranked hypotheses

## How it differs

More structured than defaults, less numeric than Bayes; useful when only **ordering** is defensible. You can say A is more plausible than B without quantifying how much.

## Best for

- Early-stage hypothesis ranking
- Reasoning with weak quantification
- Domains where precise probabilities aren't available

## Common failure mode

Losing important magnitude information when magnitude actually matters. Sometimes the difference between 10% and 1% is crucial.

## Related modes

- [Bayesian reasoning](11-bayesian-probabilistic.md) — full numeric probabilities
- [Default / typicality reasoning](31-default-typicality.md) — binary rather than ranked
- [Imprecise probability](21-imprecise-probability.md) — intervals instead of ranks
