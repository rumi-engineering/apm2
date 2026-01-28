# Snapshot

A **Snapshot** is a verified, canonical, and signed *derived* projection of the **Ledger** at a specific anchor (ledger head/checkpoint), used to reduce replay cost while preserving auditability.

Snapshots serve as a new starting point (`E[0]`) for reconciliation, allowing holons to compute current state without replaying the entire history. To remain monotone, a snapshot does not replace history; it is published as a derived artifact that hash-links the history it summarizes.

## Required Properties

- **View Commitment** to a ledger head/checkpoint
- **Provenance links**: hash-links to the summarized history/range
- **Equivalence scope**: what "replay-equivalent" means (which projections/queries were tested)
- **Loss profile**: any discarded information is explicitly declared

## Mapping to Git (Concrete)

Snapshots are analogous to "pinning a repo state" in Git:

- A Git **tag** or **commit** can serve as a human-friendly anchor for source state.
- The system should still record the resolved commit/tree IDs (digests), since branch names and `HEAD` are not stable commitments.
