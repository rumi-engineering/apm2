# Merge Receipt

**Definition:** A cryptographically signed record that proves a ChangeSet was integrated into the trunk, binding the approval decision to the exact input and output states.

**Purpose:**
-   **Non-Repudiation:** Proves *who* merged it, *why* (referenced approvals), and *what* gates passed.
-   **Decoupling:** Replaces "GitHub PR Merged" as the authoritative truth. GitHub becomes just a display adapter.
-   **Atomicity:** The receipt is emitted only if the merge transition (State A -> State B) is valid and authorized.

## Content
-   `prev_state_hash`: Git tree hash before merge.
-   `new_state_hash`: Git tree hash after merge.
-   `changeset_id`: The ID of the work being merged.
-   `gate_receipts`: List of signed `GatePassed` events (AAT, Lint, Security).
-   `approver_signature`: Ed25519 signature of the Holon/User authorizing the merge.

**Context:**
The final artifact of a successful `Work Lifecycle`.
