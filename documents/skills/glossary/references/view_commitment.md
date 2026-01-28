# View Commitment

A **View Commitment** is the cryptographic binding that makes a *bounded view* (a **ContextPack**, **Snapshot**, or **Summary Receipt**) provably synchronized with authoritative truth without requiring the full history to fit in an agent's context window.

It resolves the "Truth/View" gap by defining synchronization as **commitment + addressability**, not "everything is in-window."

## What It Commits To

A View Commitment is a small, machine-checkable header that binds the view to:

- **Ledger anchor**: a ledger head or checkpoint identifier (e.g., last `EventRecord` hash + `seq_id`, or a canonical snapshot event hash).
- **Pinned world state** (episode substrate): digests identifying the repo/deps/policy/toolchain/model versions the work is reasoning against.
- **Selectors**: typed pointers (hashes, IDs, ranges) that make omitted referenced facts retrievable/auditable on demand.

## Suggested Machine Representation (Example)

```json
{
  "schema": "apm2.view_commitment.v1",
  "ledger_anchor": {
    "anchor_kind": "ledger_event",
    "seq_id": 12345,
    "event_hash": "0123abcd0123abcd0123abcd0123abcd0123abcd0123abcd0123abcd0123abcd"
  },
  "pins": {
    "git_commit": {
      "algo": "sha1",
      "object_kind": "commit",
      "object_id": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    },
    "git_tree": {
      "algo": "sha1",
      "object_kind": "tree",
      "object_id": "cafe1234cafe1234cafe1234cafe1234cafe1234"
    },
    "policy_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "toolchain_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  },
  "selectors": [
    { "kind": "ledger_event", "seq_id": 12000, "event_hash": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" },
    { "kind": "cas", "content_hash": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" }
  ]
}
```

## Mapping to Git (Concrete)

When the pinned world state includes a Git repository:

- **Git "HEAD" (symbolic)**: `HEAD` is a moving reference (depends on checkout); do not treat `HEAD` itself as a commitment.
- **Pinned commit**: record the *resolved* commit ID (e.g., output of `git rev-parse HEAD`) as the stable anchor.
- **Pinned tree**: for "exact filesystem contents" semantics, record the tree ID (e.g., `git rev-parse HEAD^{tree}`) and optionally relevant blob IDs.
- **Algorithm**: Git object IDs may be SHA-1 or SHA-256 depending on repo config; store `(algo, object_id)` rather than assuming one hash family.

## Integration Path (Concrete)

- **Ledger anchor** maps to the `EventRecord` hash chain head (practically `(seq_id, event_hash)`).
- **Pinned repo state** maps to Git object selectors (commit/tree) captured via policy-mediated git operations (e.g., `git rev-parse`).
- **Selectors** map to:
  - **CAS/Evidence**: content hashes fetched via `ArtifactFetch`
  - **DCP**: stable IDs resolved via the DCP index (projection) and checked against expected hashes
  - **Ledger**: event hashes/seq IDs fetched via ledger read tools
- **Dirty state** is represented by a **Workspace Delta** (a content-addressed patch artifact) and referenced from the commitment (never implied by whatever is on disk).

## Related Terms

- **ContextPack**: a bounded view used for execution.
- **Snapshot**: a derived acceleration/projection with replay-equivalence evidence.
- **Summary Receipt**: a derived, lossy view with zoom-in selectors.
- **Selector**: the addressability primitive carried by the view.
- **Git Digest Conventions**: commit vs tree vs `HEAD`, SHA-1 vs SHA-256.
- **Workspace Delta**: how dirty working state is bound to the view without relying on ambient disk.
