# Introduction to Modes of Reasoning

No single taxonomy is "the" official list, because people use **"mode of reasoning"** to mean (at least) four different things:

* an **inference pattern** (e.g., deduction vs. abduction),
* a **representation of uncertainty/vagueness** (e.g., probability vs. fuzzy membership),
* a **problem-solving method** (e.g., planning, constraint solving, optimization),
* or a **domain style** (e.g., scientific, legal, moral reasoning).

Real-world reasoning is therefore almost always *hybrid* (e.g., science routinely cycles: **abduction → deduction → statistical testing → belief revision**).

## How to use this map in real work

Most disagreements about "the right reasoning" come from mixing up these axes:

| Axis | One pole | Other pole | Why it matters |
|------|----------|------------|----------------|
| **Ampliative vs. non-ampliative** | *Deduction*: conclusion contained in premises | *Induction/Abduction/Analogy*: goes beyond premises | Discovery/learning requires ampliative moves; assurance requires non-ampliative checks. |
| **Monotonic vs. non-monotonic** | Adding info never retracts conclusions | Adding info can retract conclusions | Common-sense & policy reasoning are usually non-monotonic; pure math proofs are monotonic. |
| **Uncertainty vs. vagueness** | Uncertainty about crisp facts (probability) | Vagueness in predicates (fuzzy/rough) | Prevents category mistakes like treating "tall" as probabilistic rather than vague. |
| **Descriptive vs. normative** | What *is* (facts, causes) | What *ought* (values, duties, constraints) | Decisions fail when value tradeoffs are smuggled in as "facts." |
| **Belief vs. action** | What to believe / accept | What to do / choose | Separating belief updates from decision criteria improves clarity and accountability. |
| **Single-agent vs. multi-agent** | World as uncertainty/noise | Other agents strategically respond | Strategy, negotiation, security, and markets require game/ToM reasoning. |
| **Truth vs. adoption** | Accuracy / validity oriented | Audience / coordination oriented | Many org failures are rhetorical (alignment) rather than logical. |

## Practical rule: use multiple modes intentionally

* If you need **reliability/assurance** (safety, compliance, verification): lean on **deduction, proof, constraints**.
* If you need **learning/prediction** (forecasting, measurement): lean on **statistics/Bayesian**, with calibration.
* If you need **explanations/diagnosis** (root cause, incident response): lean on **abduction + causal + mechanistic**.
* If you need **choices under tradeoffs** (strategy, portfolio): lean on **decision theory + satisficing + robust**.
* If you need **buy-in** (policy adoption, change management): add **argumentation + rhetoric**.

## Reference structure

Each mode in this taxonomy is documented with:

* **What it is** — the core move
* **What it outputs** — proof, probability, hypothesis, plan, argument, etc.
* **How it differs** — especially from "nearby" modes
* **Best for** — where it tends to win
* **Common failure mode** — what to watch for
