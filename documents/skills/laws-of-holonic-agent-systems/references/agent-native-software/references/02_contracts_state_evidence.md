# Document 2: Contracts, State, and Evidence in Agent-Native Systems

## Chapter 1. Contracts as the Primary Interface Between Cognition and Execution

In agent-native systems, “understanding” is unstable because it is a function of bounded context. Contracts provide stability: they are externalized, machine-validated constraints that remain true regardless of the agent’s internal narrative.

Mathematically, a contract is a predicate (P(x)) over system states or artifacts. Correctness becomes: produce outputs (y) such that (P(y)) holds, and validate mechanically that (P) is satisfied. This shifts work from interpretive reasoning to satisfiability under explicit constraints.

Two contract layers are typically required:

* **Structural contracts:** schema validity, typing, canonical formats.
* **Semantic contracts:** invariants, pre/postconditions, allowed transitions, safety properties.

Agent-native systems elevate structural contracts because they are cheap and deterministic, and because they reduce ambiguity in the finite context channel.

## Chapter 2. State Models: Event Sourcing, Partial Orders, and Causality

A durable state representation is required to coordinate agents. Event sourcing represents state as an append-only sequence of events; current state is a projection (reduction) of those events.

In distributed or concurrent settings, “sequence” generalizes to a partial order:

* Events have causal relationships ((→)) rather than a single total order.
* Concurrency requires reasoning about commutativity and conflicts.

A key mathematical distinction:

* If operations are **monotone** (only add information) and **commutative**, convergence is tractable (see CRDT theory).
* If operations are non-commutative (e.g., “set X to value”), then coordination requires additional mechanisms (locks, leases, consensus, or conflict resolution policies).

Operational consequence: when designing agent-facing state transitions, prefer monotone, commutative updates (append facts, add evidence, add edges) over destructive updates. This reduces coordination complexity and improves robustness under retries.

## Chapter 3. Evidence as Cryptographic Commitments and Reproducibility Anchors

Because LLM outputs are not proof, agent-native systems treat claims as untrusted until bound to evidence. Evidence is not prose; it is a reproducible artifact linked by cryptographic commitment.

A minimal evidence model includes:

* **Content addressing:** hash of artifact contents.
* **Provenance:** how it was produced (toolchain, version, inputs).
* **Verification procedures:** deterministic steps to re-check validity.

This creates a separation between:

* **Claims** (human/agent-readable assertions)
* **Evidence** (machine-verifiable artifacts)

The mathematical role of evidence is to reduce uncertainty: a verified artifact collapses ambiguity in the agent’s belief state and prevents hallucinated linkage.

## Chapter 4. Determinism Envelopes and Replay

Absolute determinism is rare in real systems; instead, define a **determinism envelope**: a set of outputs and transformations that are deterministic given explicit inputs and environment constraints.

Replayability requires:

* Capturing the *effective inputs* (including versions, environment, seeds where relevant).
* Using canonical encodings to avoid spurious diffs.
* Treating nondeterminism as a first-class output dimension (explicitly labeled variability), not as accidental noise.

From a mathematical standpoint, replayability is a function from a recorded input state to an output state: (y = F(x)). If (F) is not deterministic, the system must record the randomness source (r) so that (y = F(x, r)) is re-evaluable.

Operational consequence: design pipelines as compositions of pure transformations wherever possible; isolate nondeterministic components behind explicit boundaries and record their degrees of freedom.

## Chapter 5. Schema Evolution as Compatibility Constraints

Since agents and tools evolve, schemas must evolve. Schema evolution is a compatibility problem: ensure that old readers can consume new writers or vice versa, depending on policy.

The core principle is to treat schema changes as transformations in a type system. Backward compatibility means new schema is a refinement of old schema; forward compatibility means old schema can be interpreted in the new system. Breaking changes must be explicitly gated.

For bounded-context agents, schema stability reduces cognitive overhead and parsing errors. Therefore, schema evolution should be slow, versioned, and validated through automated compatibility checks.
