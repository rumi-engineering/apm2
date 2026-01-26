# Snapshot

A verified, canonical, and signed projection of the **Ledger** at a specific event index.

Snapshots serve as a new starting point (`E[0]`) for state reconciliation, allowing **Holons** to compute current state without replaying the entire history of the DAG. Every snapshot must maintain a hash-link to the archived history it summarizes to preserve the chain of causality.
