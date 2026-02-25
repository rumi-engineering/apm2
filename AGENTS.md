# AGENTS — Behavior Registry

## CRITICAL PRINCIPLES 

This rule always applies: you are responsible for maintaining the standards and patterns of this code base. You must never apply a band-aid solution. Always think deeply about the root cause and take the time to identify the root cause solution. Read @documents/prompts/instruction.alien_coding.v1.json.

All Rust module behavior context lives in `AGENTS.json` files co-located with
source code. Each file conforms to the `apm2.agents_context.v1` schema and maps
stable behavior IDs (`BEH-<NAMESPACE>-<NNN>`) back to the RFC system specs that
mandate them.

**Schema:** [`documents/schemas/apm2.agents_context.v1.schema.json`](documents/schemas/apm2.agents_context.v1.schema.json)
(This root `AGENTS.md` is the only Markdown file — module behavior files are always `AGENTS.json`.)

## Load all AGENTS.json files

```bash
find crates -name 'AGENTS.json' | sort
```

Read every file into a single merged array:

```bash
find crates -name 'AGENTS.json' -exec cat {} \; | jq -s '[.[].behaviors[]]'
```

## Query with jq

**List all behavior IDs and titles across the codebase:**
```bash
find crates -name 'AGENTS.json' -exec cat {} \; \
  | jq -rs '[.[].behaviors[] | {id, title}] | sort_by(.id)[]'
```

**Find all `safety` behaviors:**
```bash
find crates -name 'AGENTS.json' -exec cat {} \; \
  | jq -rs '[.[].behaviors[] | select(.kind == "safety")] | sort_by(.id)[]'
```

**Find behaviors traced to a specific RFC (e.g. RFC-0019):**
```bash
find crates -name 'AGENTS.json' -exec cat {} \; \
  | jq -rs '[.[].behaviors[] | select(.rfc[] == "RFC-0019")] | sort_by(.id)[]'
```

**Look up a behavior by ID:**
```bash
find crates -name 'AGENTS.json' -exec cat {} \; \
  | jq -rs '[.[].behaviors[] | select(.id == "BEH-CORE-FAC-021")] | .[0]'
```

**List all modules and their behavior counts:**
```bash
find crates -name 'AGENTS.json' -exec cat {} \; \
  | jq -rs '[.[] | {module, count: (.behaviors | length)}] | sort_by(.module)[]'
```

**Find all behaviors for a given module namespace (e.g. DAEMON):**
```bash
find crates -name 'AGENTS.json' -exec cat {} \; \
  | jq -rs '[.[].behaviors[] | select(.id | startswith("BEH-DAEMON-"))] | sort_by(.id)[]'
```

**Count by kind across the whole codebase:**
```bash
find crates -name 'AGENTS.json' -exec cat {} \; \
  | jq -rs '[.[].behaviors[].kind] | group_by(.) | map({kind: .[0], count: length})[]'
```

## Behavior ID format

```
BEH-{NAMESPACE}-{NNN}
     ^^^^^^^^^^ uppercase module tag (e.g. CORE-FAC, DAEMON-GATE, CLI-FAC-REV)
                 ^^^ zero-padded sequence number
```

Behavior IDs are referenced in code comments in place of inline prose:
```rust
// [BEH-CORE-FAC-021] safe_rmtree aborts immediately on symlink detection
```

## Kinds

| Kind | Meaning |
|------|---------|
| `invariant` | Property that must always hold |
| `safety` | Thing that must never happen |
| `requirement` | Functional capability mandated by an RFC |
| `capability` | What this module is authorized to do (OCAP boundary) |
