# Hybrid Reasoning Patterns

High-quality real-world work usually looks like one of these composites:

## Science / Product Experimentation

```
abduction → deduction → experimental design → statistical test → belief revision → calibration
```

**Flow:** Generate hypotheses about what might be true, derive testable predictions, design experiments to test them, analyze results statistically, update beliefs based on evidence, and track how well-calibrated your predictions are over time.

## Incident Response

```
abductive diagnosis + mechanistic model + tests (VoI) + satisficing under time pressure + postmortem counterfactuals
```

**Flow:** Form initial hypotheses about what's wrong, use understanding of system mechanics to guide investigation, prioritize tests by value-of-information, make decisions that are "good enough" given time constraints, and analyze counterfactuals in retrospective.

## Policy / Governance

```
causal inference ("what happens if…") + decision theory (tradeoffs) + moral reasoning (constraints) + argumentation (stakeholder conflict) + rhetoric (adoption) + assurance case (traceable evidence)
```

**Flow:** Understand causal effects of policy options, weigh tradeoffs explicitly, apply ethical constraints, navigate competing stakeholder arguments, communicate persuasively for adoption, and document reasoning traceably.

## Engineering / Safety

```
constraints + proof/verification + robust reasoning + red-teaming + safety case + continuous monitoring + calibration loops
```

**Flow:** Define constraints that must hold, verify they hold formally where possible, design for worst-case scenarios, actively try to break your own designs, document safety arguments with evidence, monitor in production, and update calibration based on real-world performance.

## Strategy Under Uncertainty

```
reference-class forecasting + scenario simulation + minimax regret/robust + negotiation/game theory + sensemaking updates
```

**Flow:** Ground predictions in base rates from similar past situations, simulate possible scenarios, choose strategies that minimize worst-case regret, account for how other actors will respond strategically, and continuously update your frame as new information arrives.

## Mode Selection Heuristics

When facing a new problem, ask:

1. **Do I need certainty or exploration?** — Certainty → formal/deductive modes; Exploration → ampliative modes
2. **Is the world cooperative or adversarial?** — Cooperative → decision theory; Adversarial → game theory + red-team
3. **Am I reasoning about facts or values?** — Facts → causal/statistical; Values → deontic/moral + argumentation
4. **Do I need buy-in from others?** — Yes → add rhetorical and negotiation modes
5. **Is time pressure high?** — Yes → satisficing + heuristics; No → optimization + thorough analysis
6. **How uncertain am I about my uncertainty?** — Very → imprecise probability + robust reasoning; Moderately → Bayesian
