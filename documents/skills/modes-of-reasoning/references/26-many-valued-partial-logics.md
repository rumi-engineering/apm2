# Many-Valued and Partial Logics (True/False/Unknown/Undefined)

**Category:** Reasoning Under Vagueness

## What it is

More than two truth values; explicitly represent "unknown" or "undefined."

## What it outputs

- Inferences that track indeterminacy rather than forcing a binary choice
- Three-valued (or more) truth assignments
- Explicit handling of gaps

## How it differs

Often targets **incompleteness** more than vagueness. Useful when some propositions genuinely have no truth value (yet).

## Best for

- Databases with nulls
- Partial specs
- Missingness-aware reasoning
- Presupposition failures

## Common failure mode

Conflating "unknown" with "false." Just because we don't know something is true doesn't mean it's false.

## Related modes

- [Fuzzy logic](25-fuzzy-logic.md) — continuous degrees rather than discrete values
- [Paraconsistent reasoning](34-paraconsistent.md) — handles contradictions
- [Default reasoning](31-default-typicality.md) — assumes truth in absence of info
