# ContextPack

A **ContextPack** is a pre-compiled, content-addressed, and bounded *view* of the artifacts (files, schemas, policies, evidence) required for a **Holon** to execute a specific task under a fixed context window budget `W`.

ContextPacks are the primary mechanism for achieving the **Zero-Tool Ideal (ZTI)**. They enforce Markov-blanket integrity by serving as a read allowlist: execution is predominantly actuation rather than discovery.

## What Makes a Pack "Verifiable"

A ContextPack is not "the ledger." It is a bounded view synchronized to authority by a **View Commitment**:

- commits the pack to a **ledger head/checkpoint** (truth synchronization by hash, not by full history inclusion)
- carries **Selectors** for omitted-but-referenced facts so consumers can deterministically zoom-in and verify

## Current Implementation (APM2)

Today, the ContextPack compiler in `apm2_core::cac` produces a deterministic manifest and a stable mapping from `stable_id -> content_hash` (deep-pinned dependency closure). This gives content-addressed integrity and reproducibility even before ledger-head commitments are wired through end-to-end.

## Mapping to Git (Concrete)

When a pack must describe repository state, it should include selectors that pin:

- the **commit** being reasoned against (resolved ID, not the symbolic `HEAD`)
- optionally the **tree** ID for exact filesystem snapshot semantics
- any uncommitted workspace deltas as separate, content-addressed artifacts (the workspace is a projection, not authority)

## See Also

- **View Commitment**: how bounded packs stay synchronized with an unbounded ledger.
- **Selector**: how omitted referenced facts remain addressable.
- **Git Digest Conventions**: how to represent commit/tree/blob IDs safely.
- **Workspace Delta**: how dirty working state is represented and bound to verification.
- **Content Resolver**: how packs and stable IDs become scoped bytes.
