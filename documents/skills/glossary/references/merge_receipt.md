# Merge Receipt

**Definition:** A cryptographically signed record that proves a ChangeSet was integrated into the trunk, binding the approval decision to the exact input and output states.

**Purpose:**
-   **Non-Repudiation:** Proves *who* merged it, *why* (referenced approvals), and *what* gates passed.
-   **Decoupling:** Replaces "GitHub PR Merged" as the authoritative truth. GitHub becomes just a display adapter.
-   **Atomicity:** The receipt is emitted only if the merge transition (State A -> State B) is valid and authorized.

## Content
-   `inputs`: digests identifying what was merged (ChangeSet digest + pinned base state).
-   `outputs`: digests identifying the promoted trunk state.
-   `gate_receipts`: signed gate receipts bound to evidence bundles (terminal verifiers + any advisory checks).
-   `policy_version`: which policy permitted the promotion.
-   `attestation`: runner/toolchain/environment identity for the merge operation (at least image/toolchain digests).
-   `approver_signature`: Ed25519 signature(s) authorizing the promotion.

## Mapping to Git (Concrete)

In a Git-backed workflow, a merge receipt typically binds:

- **Base**: a pinned commit/tree selector representing trunk *before* promotion.
- **Result**: the new trunk commit/tree selector *after* promotion.
- **Algorithm**: Git object IDs may be SHA-1 or SHA-256; store `(algo, object_id)` instead of assuming one.

Notes:

- GitHub "merged" state (PR UI) is a projection; the receipt is the authority.
- `HEAD` is not a commitment; receipts should record the resolved commit/tree IDs.

## See Also

- **Git Digest Conventions**: commit vs tree vs `HEAD`, SHA-1 vs SHA-256.
- **Attestation**: how merge operations are bound to an environment/toolchain.

**Context:**
The final artifact of a successful `Work Lifecycle`.
