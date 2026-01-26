# Rough Set Reasoning (Lower/Upper Approximations)

**Category:** Reasoning Under Vagueness

## What it is

Approximate a concept by what is definitely in vs possibly in, given limited features/indiscernibility.

## What it outputs

- Lower/upper bounds on classifications
- Boundary regions
- Feature-based approximations

## How it differs

Membership arises from **granularity of observation**, not degrees of truth. With better features, the boundary region shrinks.

## Best for

- Interpretability-focused classification
- Feature-limited domains
- Decision tables
- Rule extraction

## Common failure mode

Overconfidence about what's "definitely" in/out when features are weak. The approximation quality depends entirely on feature quality.

## Related modes

- [Fuzzy logic](25-fuzzy-logic.md) — degree-based rather than bound-based
- [Imprecise probability](21-imprecise-probability.md) — bounds on probabilities
- [Prototype / similarity-based reasoning](28-prototype-similarity-based.md) — different approach to categorization
