---
name: modes-of-reasoning
description: Reference taxonomy of reasoning modes for selecting appropriate inference patterns, uncertainty representations, problem-solving methods, and domain styles. Use when choosing how to reason about a problem, designing hybrid reasoning workflows, or understanding why reasoning approaches conflict.
user-invocable: true
argument-hint: "[<mode-number> | <keyword> | recommend <problem-type> | empty]"
---

# Modes of Reasoning

A practical taxonomy of reasoning modes. For background on how these modes relate and when to combine them, see [introduction](references/introduction.md).

## Invocation

```
/modes-of-reasoning                     # Browse full table
/modes-of-reasoning 13                  # Look up mode #13 (abductive)
/modes-of-reasoning bayesian            # Search by keyword
/modes-of-reasoning recommend diagnosis # Get recommendations for a problem type
```

## Argument Handling

Parse `$ARGUMENTS`:

- **Empty or omitted** → Display the quick reference table below
- **Number (1-80)** → Read and return the corresponding reference file
- **`recommend <problem-type>`** → Suggest relevant modes for the problem type (e.g., forecasting, debugging, governance, strategy)
- **Keyword** → Search mode names/descriptions and return matching entries

## Quick Reference Table

| # | Mode | Category | Reference |
|---|------|----------|-----------|
| 1 | Deductive reasoning | Formal | [deductive-reasoning.md](references/01-deductive-reasoning.md) |
| 2 | Mathematical / proof-theoretic reasoning | Formal | [mathematical-proof-theoretic.md](references/02-mathematical-proof-theoretic.md) |
| 3 | Constructive (intuitionistic) reasoning | Formal | [constructive-intuitionistic.md](references/03-constructive-intuitionistic.md) |
| 4 | Equational / algebraic reasoning | Formal | [equational-algebraic.md](references/04-equational-algebraic.md) |
| 5 | Model-theoretic / semantic reasoning | Formal | [model-theoretic-semantic.md](references/05-model-theoretic-semantic.md) |
| 6 | Constraint / satisfiability reasoning | Formal | [constraint-satisfiability.md](references/06-constraint-satisfiability.md) |
| 7 | Type-theoretic reasoning | Formal | [type-theoretic.md](references/07-type-theoretic.md) |
| 8 | Counterexample-guided reasoning | Formal | [counterexample-guided.md](references/08-counterexample-guided.md) |
| 9 | Inductive reasoning | Ampliative | [inductive.md](references/09-inductive.md) |
| 10 | Statistical reasoning (frequentist) | Ampliative | [statistical-frequentist.md](references/10-statistical-frequentist.md) |
| 11 | Bayesian probabilistic reasoning | Ampliative | [bayesian-probabilistic.md](references/11-bayesian-probabilistic.md) |
| 12 | Likelihood-based reasoning | Ampliative | [likelihood-based.md](references/12-likelihood-based.md) |
| 13 | Abductive reasoning | Ampliative | [abductive.md](references/13-abductive.md) |
| 14 | Analogical reasoning | Ampliative | [analogical.md](references/14-analogical.md) |
| 15 | Case-based reasoning | Ampliative | [case-based.md](references/15-case-based.md) |
| 16 | Explanation-based learning | Ampliative | [explanation-based-learning.md](references/16-explanation-based-learning.md) |
| 17 | Simplicity / compression reasoning | Ampliative | [simplicity-compression.md](references/17-simplicity-compression.md) |
| 18 | Reference-class / outside view reasoning | Ampliative | [reference-class-outside-view.md](references/18-reference-class-outside-view.md) |
| 19 | Fermi / order-of-magnitude reasoning | Ampliative | [fermi-order-of-magnitude.md](references/19-fermi-order-of-magnitude.md) |
| 20 | Probabilistic logic | Uncertainty | [probabilistic-logic.md](references/20-probabilistic-logic.md) |
| 21 | Imprecise probability / interval probability | Uncertainty | [imprecise-probability.md](references/21-imprecise-probability.md) |
| 22 | Evidential reasoning (Dempster-Shafer) | Uncertainty | [evidential-dempster-shafer.md](references/22-evidential-dempster-shafer.md) |
| 23 | Maximum-entropy reasoning | Uncertainty | [maximum-entropy.md](references/23-maximum-entropy.md) |
| 24 | Qualitative probability / ranking-function | Uncertainty | [qualitative-probability.md](references/24-qualitative-probability.md) |
| 25 | Fuzzy reasoning / fuzzy logic | Vagueness | [fuzzy-logic.md](references/25-fuzzy-logic.md) |
| 26 | Many-valued and partial logics | Vagueness | [many-valued-partial-logics.md](references/26-many-valued-partial-logics.md) |
| 27 | Rough set reasoning | Vagueness | [rough-set.md](references/27-rough-set.md) |
| 28 | Prototype / similarity-based category reasoning | Vagueness | [prototype-similarity-based.md](references/28-prototype-similarity-based.md) |
| 29 | Qualitative reasoning | Vagueness | [qualitative.md](references/29-qualitative.md) |
| 30 | Non-monotonic reasoning | Inconsistency & Defaults | [non-monotonic.md](references/30-non-monotonic.md) |
| 31 | Default / typicality reasoning | Inconsistency & Defaults | [default-typicality.md](references/31-default-typicality.md) |
| 32 | Defeasible reasoning | Inconsistency & Defaults | [defeasible.md](references/32-defeasible.md) |
| 33 | Belief revision and belief update | Inconsistency & Defaults | [belief-revision.md](references/33-belief-revision.md) |
| 34 | Paraconsistent reasoning | Inconsistency & Defaults | [paraconsistent.md](references/34-paraconsistent.md) |
| 35 | Argumentation theory | Inconsistency & Defaults | [argumentation-theory.md](references/35-argumentation-theory.md) |
| 36 | Assurance-case / safety-case reasoning | Inconsistency & Defaults | [assurance-case.md](references/36-assurance-case.md) |
| 37 | Causal inference | Causal & Explanatory | [causal-inference.md](references/37-causal-inference.md) |
| 38 | Causal discovery | Causal & Explanatory | [causal-discovery.md](references/38-causal-discovery.md) |
| 39 | Counterfactual reasoning | Causal & Explanatory | [counterfactual.md](references/39-counterfactual.md) |
| 40 | Mechanistic reasoning | Causal & Explanatory | [mechanistic.md](references/40-mechanistic.md) |
| 41 | Diagnostic reasoning | Causal & Explanatory | [diagnostic.md](references/41-diagnostic.md) |
| 42 | Model-based / simulation reasoning | Causal & Explanatory | [model-based-simulation.md](references/42-model-based-simulation.md) |
| 43 | Systems thinking | Causal & Explanatory | [systems-thinking.md](references/43-systems-thinking.md) |
| 44 | Means-end / instrumental reasoning | Practical | [means-end-instrumental.md](references/44-means-end-instrumental.md) |
| 45 | Decision-theoretic reasoning | Practical | [decision-theoretic.md](references/45-decision-theoretic.md) |
| 46 | Multi-criteria decision analysis (MCDA) | Practical | [multi-criteria-decision-analysis.md](references/46-multi-criteria-decision-analysis.md) |
| 47 | Planning / policy reasoning | Practical | [planning-policy.md](references/47-planning-policy.md) |
| 48 | Optimization reasoning | Practical | [optimization.md](references/48-optimization.md) |
| 49 | Robust / worst-case reasoning | Practical | [robust-worst-case.md](references/49-robust-worst-case.md) |
| 50 | Minimax regret reasoning | Practical | [minimax-regret.md](references/50-minimax-regret.md) |
| 51 | Satisficing | Practical | [satisficing.md](references/51-satisficing.md) |
| 52 | Value-of-information reasoning | Practical | [value-of-information.md](references/52-value-of-information.md) |
| 53 | Heuristic reasoning | Practical | [heuristic.md](references/53-heuristic.md) |
| 54 | Search-based / algorithmic reasoning | Practical | [search-based-algorithmic.md](references/54-search-based-algorithmic.md) |
| 55 | Game-theoretic / strategic reasoning | Strategic & Social | [game-theoretic-strategic.md](references/55-game-theoretic-strategic.md) |
| 56 | Theory-of-mind / mental-state reasoning | Strategic & Social | [theory-of-mind.md](references/56-theory-of-mind.md) |
| 57 | Negotiation and coalition reasoning | Strategic & Social | [negotiation-coalition.md](references/57-negotiation-coalition.md) |
| 58 | Mechanism design / incentive engineering | Strategic & Social | [mechanism-design.md](references/58-mechanism-design.md) |
| 59 | Dialectical reasoning | Dialectical & Rhetorical | [dialectical.md](references/59-dialectical.md) |
| 60 | Rhetorical reasoning | Dialectical & Rhetorical | [rhetorical.md](references/60-rhetorical.md) |
| 61 | Hermeneutic / interpretive reasoning | Dialectical & Rhetorical | [hermeneutic-interpretive.md](references/61-hermeneutic-interpretive.md) |
| 62 | Narrative reasoning / causal storytelling | Dialectical & Rhetorical | [narrative-causal-storytelling.md](references/62-narrative-causal-storytelling.md) |
| 63 | Sensemaking / frame-building reasoning | Dialectical & Rhetorical | [sensemaking-frame-building.md](references/63-sensemaking-frame-building.md) |
| 64 | Modal reasoning | Modal & Temporal | [modal.md](references/64-modal.md) |
| 65 | Deontic reasoning | Modal & Temporal | [deontic.md](references/65-deontic.md) |
| 66 | Temporal reasoning | Modal & Temporal | [temporal.md](references/66-temporal.md) |
| 67 | Spatial and diagrammatic reasoning | Modal & Temporal | [spatial-diagrammatic.md](references/67-spatial-diagrammatic.md) |
| 68 | Scientific reasoning | Domain-Specific | [scientific.md](references/68-scientific.md) |
| 69 | Experimental design reasoning | Domain-Specific | [experimental-design.md](references/69-experimental-design.md) |
| 70 | Engineering design reasoning | Domain-Specific | [engineering-design.md](references/70-engineering-design.md) |
| 71 | Legal reasoning | Domain-Specific | [legal.md](references/71-legal.md) |
| 72 | Moral / ethical reasoning | Domain-Specific | [moral-ethical.md](references/72-moral-ethical.md) |
| 73 | Historical / investigative reasoning | Domain-Specific | [historical-investigative.md](references/73-historical-investigative.md) |
| 74 | Clinical / operational troubleshooting | Domain-Specific | [clinical-operational-troubleshooting.md](references/74-clinical-operational-troubleshooting.md) |
| 75 | Meta-reasoning | Meta-Level | [meta-reasoning.md](references/75-meta-reasoning.md) |
| 76 | Calibration and epistemic humility | Meta-Level | [calibration-epistemic-humility.md](references/76-calibration-epistemic-humility.md) |
| 77 | Reflective equilibrium | Meta-Level | [reflective-equilibrium.md](references/77-reflective-equilibrium.md) |
| 78 | Transcendental reasoning | Meta-Level | [transcendental.md](references/78-transcendental.md) |
| 79 | Adversarial / red-team reasoning | Meta-Level | [adversarial-red-team.md](references/79-adversarial-red-team.md) |
| 80 | Debiasing / epistemic hygiene reasoning | Meta-Level | [debiasing-epistemic-hygiene.md](references/80-debiasing-epistemic-hygiene.md) |

## Hybrid Reasoning Patterns

For common composites and "wiring diagrams" showing how to combine modes, see [hybrid-patterns.md](references/hybrid-patterns.md).
