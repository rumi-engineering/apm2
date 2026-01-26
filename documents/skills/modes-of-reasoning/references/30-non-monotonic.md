# Non-Monotonic Reasoning (Commonsense with Exceptions)

**Category:** Reasoning with Inconsistency, Defaults, and Change

## What it is

Adding information can retract previous conclusions ("birds fly" until "penguin").

## What it outputs

- Default conclusions with explicit revision behavior
- Tentative inferences
- Exception-aware reasoning

## How it differs

Classical deduction is monotonic; most real knowledge bases aren't. In real life, learning more can change what you believe.

## Best for

- Rule systems with exceptions
- Policies
- "Normally" knowledge
- Commonsense reasoning

## Common failure mode

Unclear priority rules → inconsistent or surprising behavior. When defaults conflict, you need clear resolution rules.

## Related modes

- [Deductive reasoning](01-deductive-reasoning.md) — monotonic baseline
- [Default / typicality reasoning](31-default-typicality.md) — specific non-monotonic mechanism
- [Belief revision](33-belief-revision.md) — principles for updating
