# Diagnostic Reasoning (Effects → Causes Under Constraints)

**Category:** Causal, Counterfactual, Explanatory, and Dynamic Reasoning

## What it is

Infer hidden faults/causes from symptoms using a fault/causal model plus uncertainty handling.

## What it outputs

- Ranked causes
- Next-best tests
- Triage plans
- Differential diagnoses

## How it differs

Often abduction + Bayesian/likelihood updates, constrained by explicit fault models. Structured approach to "what's wrong and what should we check next."

## Best for

- Incident response
- Troubleshooting
- Quality triage
- Medical diagnosis
- Technical support

## Common failure mode

Premature closure (locking onto one cause too early). Confirming your first hypothesis before adequately ruling out alternatives.

## Related modes

- [Abductive reasoning](13-abductive.md) — underlying inference pattern
- [Mechanistic reasoning](40-mechanistic.md) — provides fault models
- [Value-of-information reasoning](52-value-of-information.md) — prioritizes tests
