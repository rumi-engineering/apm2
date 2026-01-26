# Commitment Filter

**Definition:** The mechanism within a holon's Markov Blanket that determines which internal states become public, durable evidence.

**Resolving the Seclusion Paradox:**
The "Principle of Seclusion" (internal state is opaque) and the "Crash-Only Corollary" (state must be recoverable) appear to conflict. The **Commitment Filter** resolves this by defining two classes of state:
1. **Private State:** Ephemeral, high-entropy, internal reasoning and scratchpads. Opaque to the universe.
2. **Committed State (Checkpoints):** Intentional snapshots of progress, intent-to-act, or tool outputs written to the Ledger.

The Markov Blanket is not a static wall; it is a *selective filter*.

## Lifecycle
- **Refinement:** The agent works in private seclusion.
- **Commitment:** The envelope "lifts" a state snapshot into the Ledger as a `SubEpisodeCheckpoint`.
- **Recovery:** Upon failure, a new holon instance is initialized using only the *Committed State*.

## See Also
- **Holon**: The boundary owner.
- **Checkpointing**: The action of committing state.
- **Ledger**: The destination of committed state.
