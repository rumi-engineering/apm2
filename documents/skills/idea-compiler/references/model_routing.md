# Model Routing

The Idea Compiler routes each stage to a specific model provider and version using a governed routing profile.

## Routing profile shape (conceptual)

- `profile_id` and `profile_version`
- stage routes: `CCP_Build`, `Impact_Map`, `RFC_Frame`, `Ticket_Emit`, `Skill_Sync`, `Refactor_Radar`
- each route specifies: provider, model, version/build tag, max tokens, temperature policy, and safety mode

## Canary mode

In canary mode the compiler runs a stage twice:
- route A (current)
- route B (candidate)

Outputs are parsed into structured IR and compared. If the diff is material, the compiler emits a finding and requires explicit acceptance to adopt route B.

## Security constraints

- Prompts must be classification-aware; secrets are prohibited.
- Provider selection must be explicit; no implicit fallback.
- Network access must be default-deny unless the stage explicitly declares it.
