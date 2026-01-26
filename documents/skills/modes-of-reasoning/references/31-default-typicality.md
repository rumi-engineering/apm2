# Default / Typicality Reasoning

**Category:** Reasoning with Inconsistency, Defaults, and Change

## What it is

Use "normally/typically" rules overridden by more specific info.

## What it outputs

- Typical conclusions
- Exception handling
- Default assumptions

## How it differs

Often categorical (default applies/doesn't) rather than numeric probabilities. Simpler than full Bayesian reasoning but less expressive.

## Best for

- Ontologies
- Rule engines
- SOPs with carve-outs
- Configuration management

## Common failure mode

Defaults become "facts" and stop being questioned. Over time, people forget that defaults are assumptions.

## Related modes

- [Non-monotonic reasoning](30-non-monotonic.md) — general framework
- [Defeasible reasoning](32-defeasible.md) — explicit defeat relations
- [Bayesian reasoning](11-bayesian-probabilistic.md) — probabilistic alternative
