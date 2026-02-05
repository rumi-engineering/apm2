---
name: modes-of-reasoning
description: Reference taxonomy of reasoning modes for selecting appropriate inference patterns, uncertainty representations, problem-solving methods, and domain styles. Use when choosing how to reason about a problem, designing hybrid reasoning workflows, or understanding why reasoning approaches conflict.
user-invocable: true
argument-hint: "[<mode-number> | <keyword> | recommend <problem-type> | empty]"
---

# Modes of Reasoning

A practical taxonomy of 81 reasoning modes stored as CAC assets. For background on how these modes relate and when to combine them, see `assets/selector.json`.

## Asset References

- **Glossary**: `documents/theory/glossary/glossary.json` - REQUIRED READING: APM2 terminology and ontology
- **Mode assets**: `assets/{NN}-{name}.json` (e.g., `assets/58-mechanism-design.json`)
- **Selector asset**: `assets/selector.json` - contains axes, patterns, and heuristics for mode selection
- **Stable IDs**: `dcp://apm2.agents/mor/mode/{name}@1`

## Invocation

```
/modes-of-reasoning                     # Browse mode selector
/modes-of-reasoning 13                  # Look up mode #13 (abductive)
/modes-of-reasoning bayesian            # Search by keyword
/modes-of-reasoning recommend diagnosis # Get recommendations for a problem type
```

## Argument Handling

Parse `$ARGUMENTS`:

- **Empty or omitted** → Load `assets/selector.json` and display quick reference table
- **Number (1-80)** → Read and return the corresponding mode asset
- **`recommend <problem-type>`** → Use selector heuristics and patterns to suggest relevant modes
- **Keyword** → Search mode names/cores and return matching entries

## Quick Reference Table

| # | Mode | Category | Asset |
|---|------|----------|----------|
| 1 | Deductive reasoning | formal | `01-deductive-reasoning.json` |
| 2 | Mathematical / proof-theoretic | formal | `02-mathematical-proof-theoretic.json` |
| 3 | Constructive (intuitionistic) | formal | `03-constructive-intuitionistic.json` |
| 4 | Equational / algebraic | formal | `04-equational-algebraic.json` |
| 5 | Model-theoretic / semantic | formal | `05-model-theoretic-semantic.json` |
| 6 | Constraint / satisfiability | formal | `06-constraint-satisfiability.json` |
| 7 | Type-theoretic | formal | `07-type-theoretic.json` |
| 8 | Counterexample-guided | formal | `08-counterexample-guided.json` |
| 9 | Inductive | ampliative | `09-inductive.json` |
| 10 | Statistical (frequentist) | probabilistic | `10-statistical-frequentist.json` |
| 11 | Bayesian probabilistic | probabilistic | `11-bayesian-probabilistic.json` |
| 12 | Likelihood-based | probabilistic | `12-likelihood-based.json` |
| 13 | Abductive | ampliative | `13-abductive.json` |
| 14 | Analogical | ampliative | `14-analogical.json` |
| 15 | Case-based | ampliative | `15-case-based.json` |
| 16 | Explanation-based learning | ampliative | `16-explanation-based-learning.json` |
| 17 | Simplicity / compression | ampliative | `17-simplicity-compression.json` |
| 18 | Reference-class / outside view | ampliative | `18-reference-class-outside-view.json` |
| 19 | Fermi / order-of-magnitude | ampliative | `19-fermi-order-of-magnitude.json` |
| 20 | Probabilistic logic | probabilistic | `20-probabilistic-logic.json` |
| 21 | Imprecise probability | uncertain | `21-imprecise-probability.json` |
| 22 | Evidential (Dempster-Shafer) | uncertain | `22-evidential-dempster-shafer.json` |
| 23 | Maximum-entropy | probabilistic | `23-maximum-entropy.json` |
| 24 | Qualitative probability | probabilistic | `24-qualitative-probability.json` |
| 25 | Fuzzy logic | uncertain | `25-fuzzy-logic.json` |
| 26 | Many-valued / partial logics | uncertain | `26-many-valued-partial-logics.json` |
| 27 | Rough set | uncertain | `27-rough-set.json` |
| 28 | Prototype / similarity-based | ampliative | `28-prototype-similarity-based.json` |
| 29 | Qualitative | causal | `29-qualitative.json` |
| 30 | Non-monotonic | nonmonotonic | `30-non-monotonic.json` |
| 31 | Default / typicality | nonmonotonic | `31-default-typicality.json` |
| 32 | Defeasible | nonmonotonic | `32-defeasible.json` |
| 33 | Belief revision | nonmonotonic | `33-belief-revision.json` |
| 34 | Paraconsistent | nonmonotonic | `34-paraconsistent.json` |
| 35 | Argumentation theory | argumentation | `35-argumentation-theory.json` |
| 36 | Assurance-case / safety-case | argumentation | `36-assurance-case.json` |
| 37 | Causal inference | causal | `37-causal-inference.json` |
| 38 | Causal discovery | causal | `38-causal-discovery.json` |
| 39 | Counterfactual | causal | `39-counterfactual.json` |
| 40 | Mechanistic | causal | `40-mechanistic.json` |
| 41 | Diagnostic | causal | `41-diagnostic.json` |
| 42 | Model-based / simulation | causal | `42-model-based-simulation.json` |
| 43 | Systems thinking | causal | `43-systems-thinking.json` |
| 44 | Means-end / instrumental | decision | `44-means-end-instrumental.json` |
| 45 | Decision-theoretic | decision | `45-decision-theoretic.json` |
| 46 | Multi-criteria decision analysis | decision | `46-multi-criteria-decision-analysis.json` |
| 47 | Planning / policy | decision | `47-planning-policy.json` |
| 48 | Optimization | search | `48-optimization.json` |
| 49 | Robust / worst-case | decision | `49-robust-worst-case.json` |
| 50 | Minimax regret | decision | `50-minimax-regret.json` |
| 51 | Satisficing | decision | `51-satisficing.json` |
| 52 | Value-of-information | decision | `52-value-of-information.json` |
| 53 | Heuristic | search | `53-heuristic.json` |
| 54 | Search-based / algorithmic | search | `54-search-based-algorithmic.json` |
| 55 | Game-theoretic / strategic | strategic | `55-game-theoretic-strategic.json` |
| 56 | Theory-of-mind | strategic | `56-theory-of-mind.json` |
| 57 | Negotiation / coalition | strategic | `57-negotiation-coalition.json` |
| 58 | Mechanism design | strategic | `58-mechanism-design.json` |
| 59 | Dialectical | argumentation | `59-dialectical.json` |
| 60 | Rhetorical | argumentation | `60-rhetorical.json` |
| 61 | Hermeneutic / interpretive | domain | `61-hermeneutic-interpretive.json` |
| 62 | Narrative / causal storytelling | argumentation | `62-narrative-causal-storytelling.json` |
| 63 | Sensemaking / frame-building | domain | `63-sensemaking-frame-building.json` |
| 64 | Modal | formal | `64-modal.json` |
| 65 | Deontic | domain | `65-deontic.json` |
| 66 | Temporal | formal | `66-temporal.json` |
| 67 | Spatial / diagrammatic | domain | `67-spatial-diagrammatic.json` |
| 68 | Scientific | domain | `68-scientific.json` |
| 69 | Experimental design | domain | `69-experimental-design.json` |
| 70 | Engineering design | domain | `70-engineering-design.json` |
| 71 | Legal | domain | `71-legal.json` |
| 72 | Moral / ethical | domain | `72-moral-ethical.json` |
| 73 | Historical / investigative | domain | `73-historical-investigative.json` |
| 74 | Clinical / operational troubleshooting | domain | `74-clinical-operational-troubleshooting.json` |
| 75 | Meta-reasoning | meta | `75-meta-reasoning.json` |
| 76 | Calibration / epistemic humility | meta | `76-calibration-epistemic-humility.json` |
| 77 | Reflective equilibrium | meta | `77-reflective-equilibrium.json` |
| 78 | Transcendental | meta | `78-transcendental.json` |
| 79 | Adversarial / red-team | meta | `79-adversarial-red-team.json` |
| 80 | Debiasing / epistemic hygiene | meta | `80-debiasing-epistemic-hygiene.json` |
| 81 | Autopoietic / recursive self-maintenance | meta | `81-autopoietic-recursive.json` |

## Hybrid Reasoning Patterns

The selector asset contains common patterns for combining modes:

- **science_experimentation**: [13, 1, 69, 10, 33, 76] - abduction → deduction → experimental design → stats → belief revision → calibration
- **incident_response**: [74, 13, 40, 52, 39] - clinical + abduction + mechanistic + VoI + counterfactual
- **policy_governance**: [37, 45, 72, 35, 60, 36] - causal + decision + moral + argumentation + rhetoric + assurance
- **engineering_safety**: [6, 8, 49, 79, 36, 76] - constraints + counterexample + robust + red-team + assurance + calibration
- **strategy_uncertainty**: [18, 42, 50, 55, 63] - reference-class + simulation + minimax-regret + game-theory + sensemaking

## Mode Selection Heuristics

Use the selector's heuristics to choose modes based on:

- **Certainty vs exploration** - formal modes for certainty, ampliative for exploration
- **Cooperative vs adversarial** - decision theory vs game theory + red-team
- **Facts vs values** - causal/statistical vs deontic/moral + argumentation
- **Time pressure** - satisficing + heuristics vs optimization + thorough analysis
- **Uncertainty depth** - imprecise probability + robust vs Bayesian
