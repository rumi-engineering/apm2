# Git Digest Conventions

This document defines how APM2 refers to Git state in a way that is stable, auditable, and compatible with an append-only ledger model.

## Core Rule: Never Commit to `HEAD` as a Symbol

- `HEAD` is a moving reference that depends on checkout state.
- Branch names are also moving references.

When a receipt/view/snapshot needs to pin repository state, it MUST record resolved object IDs (digests), not symbolic names.

## Objects and What They Mean

- **commit**: history node; includes parent pointers + tree pointer
- **tree**: directory snapshot; content-addresses paths -> blobs/trees
- **blob**: file contents
- **tag**: named reference (annotated tags are objects; lightweight tags are refs)

For "exact filesystem contents" semantics, pin the **tree** (and optionally specific blobs).

## Hash Algorithms

Git repos may use:

- **SHA-1** object IDs (40 hex chars)
- **SHA-256** object IDs (64 hex chars)

APM2 receipts MUST record `(algo, object_id)` instead of assuming SHA-1.

## Recommended Pins in APM2 Artifacts

- **Pinned commit**: resolved commit ID (e.g., `git rev-parse HEAD`)
- **Pinned tree**: resolved tree ID (e.g., `git rev-parse HEAD^{tree}`)
- **Dirty state**: uncommitted changes must be represented separately as a content-addressed **Workspace Delta**, not implied by `HEAD`.

## Mapping to APM2 Abstractions

- **View Commitment**: carries a pinned `(algo, commit/tree)` selector plus a ledger head/checkpoint commitment.
- **ContextPack**: may include stable IDs for repo artifacts and selectors that pin commit/tree; may reference a Workspace Delta when execution proceeds with local edits.
- **Merge Receipt**: binds inputs->output digests; in Git-backed flows it records base/result commit/tree selectors.

In schema terms, these pins use **GitObjectRef** (`schemas/apm2/git_object_ref.schema.json`) and are typically embedded in **ViewCommitment** payloads.

## Practical Commands (Illustrative)

- Resolve commit: `git rev-parse HEAD`
- Resolve tree: `git rev-parse HEAD^{tree}`
- Detect dirty state: `git status --porcelain`
- Capture delta: `git diff` (or `git diff --cached` for staged)

These are typically executed via the kernel's `GitOperation` tool for policy mediation and auditability.
