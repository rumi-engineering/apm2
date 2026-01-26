# Causal Discovery (Learning Causal Structure)

**Category:** Causal, Counterfactual, Explanatory, and Dynamic Reasoning

## What it is

Infer causal graph structure from data + assumptions (and ideally interventions).

## What it outputs

- Candidate causal graphs
- Equivalence classes
- Hypotheses for experimentation
- Structural constraints

## How it differs

Causal inference assumes (some) structure; discovery tries to learn it. It's the problem of figuring out what causes what, not just estimating effects.

## Best for

- Early-stage domains with unclear mechanisms
- Prioritizing experiments
- Hypothesis generation about causal structure
- Scientific exploration

## Common failure mode

Overtrusting discovery outputs without validating assumptions (faithfulness, no hidden confounding, etc.). Discovered structures are hypotheses, not facts.

## Related modes

- [Causal inference](37-causal-inference.md) — uses discovered structure
- [Abductive reasoning](13-abductive.md) — hypothesis generation generally
- [Experimental design](69-experimental-design.md) — validates causal hypotheses
