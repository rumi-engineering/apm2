# Workspace Delta (Dirty State)

A **Workspace Delta** is a content-addressed representation of local, uncommitted changes relative to a pinned base state (usually a Git commit/tree).

It allows implementation agents to maintain an internal dirty working state while keeping the factory's notion of truth auditable and replayable.

## What It Is (and Is Not)

- It **is** a bounded, explicit patch/diff (or patch-set) whose bytes are hashed and stored as an artifact.
- It **is not** "whatever happens to be on disk right now" (that is a projection and not stable authority).

## Why It Matters

Agents naturally work with dirty state (staged edits, partial changes, experiments). The ledger/receipts must be able to:

- reconstruct what was actually tested/verified/merged
- prevent "truth drift" where verification ran on an unrecorded workspace state

## Minimal Shape

A Workspace Delta should include:

- **base selector**: the pinned repo state it applies to (commit/tree with algo)
- **patch content hash**: hash of the patch bytes (stored in CAS)
- **apply semantics**: format and application rules (git diff, unified diff, etc)
- **scope**: optional allowlist of paths touched (for policy enforcement)

## Example Encoding

```json
{
  "schema": "apm2.workspace_delta.v1",
  "schema_version": "1.0.0",
  "base": {
    "commit": { "algo": "sha1", "object_kind": "commit", "object_id": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef" }
  },
  "patch_format": "git_unified_diff",
  "patch_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "paths_touched": ["src/lib.rs"],
  "staged": false
}
```

## Mapping to Git

- Base: resolved `commit` and/or `tree`
- Patch: output of `git diff` (unstaged) and/or `git diff --cached` (staged)
- Cleanliness signal: `git status --porcelain`

## Mapping to APM2 Flows

- **ContextPack**: may reference a Workspace Delta when execution intentionally proceeds on a dirty workspace.
- **View Commitment**: includes `workspace_delta_hash` so a bounded view is committed to the exact working state.
- **Gate runs**: receipts should bind to (base pin + workspace delta) and store the patch as evidence so verification can be replayed.
- **Merge**: promotion should be based on an admitted ChangeSet/patch-set, not implicit workspace state.

## Policy and Least Authority

Workspace deltas are a governance boundary:

- producing a delta (diff) is typically read-only
- applying a delta is write authority and must be scoped (intent-bound where possible)

## See Also

- **Git Digest Conventions**: how base pins are represented.
- **View Commitment**: how the system binds bounded views to authority.
- **Selector**: the pointer primitive used for base pins and patch hashes.
