# Determinism Envelope

The Idea Compiler must treat LLM outputs as *untrusted suggestions* until they are parsed into a structured IR, validated, and canonicalized.

## Canonicalization rules

- YAML outputs must use stable key ordering and consistent indentation.
- Lists must be stably sorted where ordering is not semantically meaningful.
- Strings that are the result of free-text generation are permitted only in whitelisted fields.

## Atomic writes

- Write new outputs to a temporary path.
- Validate schemas and lint predicates.
- `fsync` the file and parent directory.
- Atomically rename into place.

## Diff classification

When a re-run produces output differences, the compiler classifies diffs:

- **Structural:** schema changes, reordered IDs, path changes, added/removed requirements/tickets.
- **Free-text:** changes in whitelisted narrative fields with no structural impact.

Structural diffs require explicit acceptance before applying.

## Retry policy

If a stage output fails validation:

1. Retry with stricter prompting constraints and smaller context.
2. If still failing, switch to a fallback route *only if explicitly configured*.
3. Otherwise fail closed with a typed finding.
