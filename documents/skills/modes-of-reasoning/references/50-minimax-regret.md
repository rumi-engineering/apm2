# Minimax Regret Reasoning

**Category:** Practical Reasoning

## What it is

Choose the action minimizing worst-case *regret* (difference from best action in hindsight).

## What it outputs

- Regret-robust choices
- Hedged decisions
- Compromise strategies

## How it differs

More compromise-oriented than strict worst-case utility; useful under ambiguity. You're not optimizing for the worst outcome, but for minimizing how much you'd kick yourself.

## Best for

- Strategy under deep uncertainty
- Irreversible decisions
- Portfolio construction
- Technology choices

## Common failure mode

Regret framing that ignores asymmetric catastrophic outcomes. Minimizing regret may not be appropriate when some outcomes are catastrophic.

## Related modes

- [Robust / worst-case reasoning](49-robust-worst-case.md) — worst-case utility
- [Decision-theoretic reasoning](45-decision-theoretic.md) — expected utility
- [Imprecise probability](21-imprecise-probability.md) — deep uncertainty
