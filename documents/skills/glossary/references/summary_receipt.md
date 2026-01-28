# Summary Receipt

A **Summary Receipt** is a derived, lossy artifact that summarizes other evidence/events while preserving verifiability via deterministic pointers ("zoom-in selectors").

Summary receipts are admissible for planning and triage, but are not equivalent to raw evidence. Any gate that requires exactness must zoom-in to the referenced evidence (or fail-closed).

## Required Contents (Conceptual)

- **derivation method/version**: how the summary was produced (so consumers can interpret it)
- **loss profile**: what information may be discarded or approximated
- **evidence selectors**: hashes/IDs/ranges pointing to the underlying facts/artifacts
- **view commitment**: binds the summary to a ledger head/checkpoint and pinned world state

## Example Encodings

```json
{
  "schema": "apm2.summary_receipt.v1",
  "schema_version": "1.0.0",
  "derivation": { "method": "summary-v1", "version": "1.0.0" },
  "loss_profile": { "drops": ["full_logs"], "keeps": ["test_failures", "file_paths"] },
  "view_commitment": {
    "schema": "apm2.view_commitment.v1",
    "schema_version": "1.0.0",
    "ledger_anchor": {
      "anchor_kind": "ledger_event",
      "seq_id": 12345,
      "event_hash": "0123abcd0123abcd0123abcd0123abcd0123abcd0123abcd0123abcd0123abcd"
    },
    "selectors": []
  },
  "selectors": [{ "kind": "cas", "content_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }]
}
```

## Common Uses

- compressing long histories into bounded agent context windows
- routing work across holons via typed interfaces
- building indices/manifests while retaining auditability

## See Also

- **Selector**: the pointer primitive used for zoom-in.
- **View Commitment**: keeps bounded views synchronized with authoritative truth.
- **Terminal Verifier**: when exactness is required, gates zoom in to terminal-verifier evidence.
