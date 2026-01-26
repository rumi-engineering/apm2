# Document 1: Mathematical Foundations of Agent-Native Software

## Chapter 1. LLMs as Stochastic Conditional Transducers

A large language model can be treated as a conditional distribution (p_\theta(y \mid x)) over token sequences (y) given an input context (x). In agent-native systems, this distribution is used iteratively: the agent repeatedly samples (or decodes) actions conditioned on an evolving “history” that is only partially visible (due to context limits) and partially externalized (due to tool calls and durable state).

Two properties matter operationally:

1. **Stochasticity and epistemic uncertainty.** Even at temperature (0), decoding is not equivalent to logical entailment. The model approximates a conditional distribution, not a proof system. Correctness must therefore be anchored to external verifiers (tests, linters, schemas, proofs, oracles) rather than internal confidence.

2. **Context sensitivity.** The same latent policy (p_\theta) yields materially different outputs under small perturbations of (x). This implies that “agent behavior” is a function of prompt construction and retrieval policy at least as much as it is a function of model weights.

The practical conclusion is that agent-native software is engineered by controlling the *information presented to the model* and the *verification mechanisms* surrounding it, rather than relying on stable internal cognition.

## Chapter 2. Finite Context as a Bandwidth-Limited Channel

A context window of size (W) tokens imposes a hard upper bound on the information that can be directly conditioned upon. This is naturally modeled as a communication channel with capacity proportional to (W), where the prompt designer and retrieval system must encode the relevant state into (W) symbols.

Key notions:

* **Entropy and compressibility.** If the minimal description length of the task-relevant state exceeds (W), then any context must be a lossy compression. Lossy compression introduces ambiguity; ambiguity increases error probability.

* **Sufficient statistics.** The goal of external memory and summarization is to compute a representation (s = f(h)) from full history (h) such that (s) is sufficient for decision-making: (p(a \mid h) \approx p(a \mid s)). In practice, true sufficiency is unattainable; systems approximate sufficiency by designing invariants, schemas, and evidence artifacts that reduce decision uncertainty.

* **Information bottleneck.** For a given task, one wants a representation (s) that maximizes mutual information with the “correct action” while minimizing size: maximize (I(s; a^*)) subject to a size constraint (|s| \le W). This justifies prioritizing structured artifacts (IDs, hashes, schemas, diffs) over prose.

Operational consequence: treat the context window as a scarce resource; optimize the state encoding (retrieval + summarization) as a primary engineering discipline, not an afterthought.

## Chapter 3. External Memory as Lossy Compression with Error Bounds

Agents require persistent state beyond (W). External memory (files, databases, ledgers, artifact stores) serves as an extension. However, any *selected* subset of external memory that is re-injected into context is a lossy view.

Three error modes arise from lossy views:

1. **Omission error:** relevant state not included; agent acts inconsistently with global state.
2. **Staleness error:** included state is outdated relative to the true current state.
3. **Hallucinated linkage:** agent infers relationships not supported by the included data.

A rigorous approach is to store state as **verifiable references** (content hashes, stable IDs, schema-validated objects) and inject *references plus minimal expansions* into the context. This shifts the burden from “trust the text” to “verify the reference.”

A useful abstraction: external memory provides an oracle (M) that can be queried by tools; the agent’s prompt includes *indices* and *proof hints* that enable bounded retrieval. The mathematical goal is minimizing decision regret under bounded queries.

## Chapter 4. Tool Calls as a Partially Observable Control Problem

An agent interacting with tools can be modeled as a partially observable Markov decision process (POMDP):

* Hidden environment state (S_t)
* Observations (O_t) (tool outputs, repository state, logs)
* Actions (A_t) (tool invocations, edits, proposals)
* Transition (S_{t+1} \sim T(S_t, A_t))

The LLM’s context provides a finite history window, so the agent must maintain a belief state (b_t \approx p(S_t \mid O_{\le t})) via external artifacts (plans, manifests, evidence). Tool calls are not “side operations”; they are the primary mechanism for state estimation (observing) and actuation (changing the environment).

Stability requires:

* **Observability:** the system must provide measurements sufficient to detect failure and drift.
* **Controllability:** actions must reliably move state toward desired invariants.
* **Closed-loop verification:** every actuation must be followed by measurement and acceptance tests; otherwise the loop is open and diverges.

Operational consequence: design tools and outputs as sensors and actuators in a control loop, with explicit state, bounded noise, and robust verification.

## Chapter 5. Cost Models: Tokens, Latency, and Risk as Objective Functions

Agent-native work optimizes multiple costs:

* Token cost (C_T) (prompt + output volume)
* Tool cost (C_U) (runtime, compute, I/O)
* Latency cost (C_L)
* Error cost (C_E) (rework, defects)
* Security risk cost (C_S) (exposure, misuse)

A system’s architecture determines feasible trade-offs. For example, compressing context reduces (C_T) but can increase (C_E) via omission errors; adding verifiers increases (C_U) and (C_L) but reduces (C_E) and (C_S). Engineering is the selection of mechanisms that minimize expected total cost under constraints.

A key implication: optimizing “agent throughput” is not maximizing raw generation speed; it is minimizing expected rework by investing in representations, verification, and boundary control.
