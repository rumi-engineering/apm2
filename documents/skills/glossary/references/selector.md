# Selector

A **Selector** is a typed, deterministic pointer that makes omitted referenced facts **addressable** for later retrieval and audit.

Selectors are how bounded views (finite token window `W`) remain synchronized with an unbounded monotone ledger: the view can omit history, but it must not break referential integrity.

## Properties

- **Deterministic**: the selector identifies content/records by stable ID and/or hash.
- **Typed**: consumers know what they are selecting (ledger event, evidence artifact, Git object, etc.).
- **Auditable**: resolution of a selector is a tool-mediated read that can be logged and policy-checked.
- **Not Authority**: a selector enables *addressability*, but does not grant the capability to read it (policy/OCAP still applies).

## Common Selector Forms

- **Ledger event selector**: `(event_hash)` or `(seq_id)` or `(range: [a..b], range_root_hash)`.
- **Evidence/CAS selector**: `(content_hash)` (e.g., BLAKE3 hex) plus optional kind/classification.
- **DCP selector**: `(stable_id, content_hash)` as produced by the ContextPack compiler.
- **Git selector**: `(algo, object_id, kind)` where `kind in {commit, tree, blob, tag}`.

## Example Encodings

```json
{ "kind": "ledger_event", "seq_id": 12345, "event_hash": "0123abcd0123abcd0123abcd0123abcd0123abcd0123abcd0123abcd0123abcd" }
```

```json
{ "kind": "cas", "content_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
```

```json
{ "kind": "dcp", "stable_id": "org:doc:readme", "content_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" }
```

```json
{ "kind": "git_object", "algo": "sha1", "object_kind": "commit", "object_id": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef" }
```

## Used By

- **Summary Receipts**: to support deterministic zoom-in from lossy summaries.
- **ContextPacks**: to allow on-demand retrieval of omitted but referenced facts.
- **Compaction/Snapshots**: to preserve provenance while reducing replay cost.
