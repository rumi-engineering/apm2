# Causal Inference (Interventions vs Observations)

**Category:** Causal, Counterfactual, Explanatory, and Dynamic Reasoning

## What it is

Identify causal relations and predict effects of interventions (distinguish P(Y|X) vs P(Y|do(X))).

## What it outputs

- Causal effect estimates
- Intervention predictions
- Adjustment sets
- Identifiability results

## How it differs

Correlation alone can't resolve confounding or direction; causal reasoning encodes structure assumptions. Knowing that X and Y correlate doesn't tell you if changing X will change Y.

## Best for

- Product impact
- Policy evaluation
- Root-cause analysis that must guide action
- Treatment effect estimation

## Common failure mode

Hidden confounders; unjustified causal assumptions. Causal conclusions are only as good as the causal model.

## Related modes

- [Causal discovery](38-causal-discovery.md) — learning causal structure
- [Counterfactual reasoning](39-counterfactual.md) — "what would have happened"
- [Statistical reasoning](10-statistical-frequentist.md) — correlation without causation
