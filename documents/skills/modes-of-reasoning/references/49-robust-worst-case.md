# Robust / Worst-Case Reasoning (Minimax, Safety Margins)

**Category:** Practical Reasoning

## What it is

Choose actions that perform acceptably under worst plausible conditions or adversaries.

## What it outputs

- Conservative policies
- Guarantees
- Buffer sizing
- Worst-case bounds

## How it differs

Expected-value optimizes averages; robust optimizes guarantees. Better for situations where the downside is unacceptable.

## Best for

- Safety-critical systems
- Security
- Compliance
- Tail-risk control
- Adversarial environments

## Common failure mode

Overconservatism (leaving too much value on the table). Preparing for every possible worst case can be paralyzing.

## Related modes

- [Decision-theoretic reasoning](45-decision-theoretic.md) — expected value alternative
- [Minimax regret reasoning](50-minimax-regret.md) — regret-based robustness
- [Imprecise probability](21-imprecise-probability.md) — uncertainty about uncertainty
