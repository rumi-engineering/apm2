# Checkpointing

The act of emitting intermediate events (intent-to-act, observation results) to the **Ledger** during an **Episode** to enable fine-grained recovery.

Checkpointing ensures that in a **Crash-Only** environment, a replacement **Holon** can resume from the exact tool call that failed, rather than restarting the entire task, thereby minimizing lost work and token waste.
