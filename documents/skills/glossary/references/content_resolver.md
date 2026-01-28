# Content Resolver

A **Content Resolver** is an abstraction that resolves `(stable_id, content_hash)` into bytes, enabling scoped, hermetic reads without granting ambient filesystem access.

In APM2, this is the key bridge between:

- **addressability** (stable IDs and hashes) and
- **actual retrieval mechanisms** (CAS, filesystem, Git working tree, remote stores)

## Why It Exists

Agents operate under bounded context and least authority. If an agent can read arbitrary paths, "ContextPacks" become advisory. A resolver makes "what can be read" explicit and checkable.

## APM2 Implementation Hook

The CAC export pipeline defines:

- `apm2_core::cac::export::ContentResolver` (`crates/apm2-core/src/cac/export.rs`)

Conceptually:

- inputs: `stable_id` + expected `content_hash`
- output: bytes, or failure if the content is missing/mismatched

## Integration Path

- **ContextPack compilation** produces a deterministic manifest that deep-pins `stable_id -> content_hash`.
- A kernel/adapter provides a resolver implementation:
  - **CAS resolver**: fetch by hash from CAS
  - **Git resolver**: map stable IDs to repo paths in a pinned commit/tree and verify hashes
  - **Filesystem resolver**: restricted to a workspace root + policy allowlist
- Tool mediation:
  - In strict consumption flows, prefer `ArtifactFetch` by `stable_id`/hash (tool protocol: `apm2.tool.v1.ArtifactFetch`) over raw `FileRead`.
  - Use `ToolRequest.consumption_mode = true` to force hermetic policy paths (deny-by-default outside the pack/allowlist).
  - For actuation (editing), the workspace is a projection; writes are allowed only within the leased scope and must be captured as patch/diff artifacts for audit.

## Dirty Working State

A resolver must define behavior when the workspace is dirty:

- If bytes do not match the expected `content_hash`, treat it as a **Workspace Delta** situation.
- The system should require either:
  - pinning the new bytes by publishing them (content-addressed), or
  - recording a patch/diff artifact that is explicitly applied to a pinned base commit/tree.

## Governance/Agency Notes

- **Executor agents** get enough bytes to act without needing broad filesystem access.
- **Policy/security** gets an enforcement surface (stable IDs/hashes) instead of trying to reason about arbitrary paths.
- **Auditors/gates** can replay verification because inputs are pinned by digest and retrieval is explicit.
- **Humans** get reviewable diffs/manifests instead of implicit "it worked on my machine" states.

## See Also

- **DCP Index**: stable ID registry for content hash resolution.
- **ContextPack**: the bounded view that carries `stable_id -> content_hash`.
- **Selector**: typed pointers used in views/receipts.
- **Workspace Delta**: how dirty state is represented without breaking auditability.
