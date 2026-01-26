# Inference Trace

**Definition:** A content-addressed record of the exact interaction between a holon's envelope and its internal probabilistic engine (LLM).

**The Replay Mandate:**
To satisfy the requirement for **Deterministic Reconstruction** in an agent-native system, the "result" of a task is insufficient as evidence. The system must capture the *Inference Trace*—the inputs, model identity, parameters (seed, temperature), and the precise stream of tokens that generated the proposal.

## Components
- **Inference Bundle:** A hash-linked collection containing the prompt, the model response, and metadata.
- **Trace Receipt:** A ledger entry proving that a specific inference trace resulted in a committed artifact.

## Why this matters
Without an Inference Trace, "replaying" a ledger is only a replay of *results*, not a replay of *actions*. In a high-assurance system, we must be able to audit *how* a decision was reached, even if the model that reached it is non-deterministic.

## See Also
- **Evidence**: The higher-level proof derived from traces.
- **Ledger**: The storage medium for trace hashes.
