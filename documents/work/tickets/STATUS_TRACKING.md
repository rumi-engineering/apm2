# Ticket Status Tracking

Ticket status is derived dynamically from git state, not stored in YAML files.

## Status Values

| Status | Detection |
|--------|-----------|
| PENDING | No branch `ticket/*/TCK-XXXXX` exists |
| IN_PROGRESS | Branch exists, PR not merged |
| COMPLETED | PR merged for ticket branch |

## How It Works

1. `cargo xtask start-ticket` queries git branches and GitHub PRs
2. Tickets with merged PRs are marked COMPLETED
3. Tickets with existing branches are marked IN_PROGRESS
4. Remaining tickets are PENDING (if dependencies are met)

## Implementation Details

The status determination is handled by `xtask/src/ticket_status.rs`:

- `get_completed_tickets()` - Queries GitHub for merged PRs with ticket branch patterns
- `get_in_progress_tickets()` - Lists all ticket branches (local and remote), filtering out completed ones

## Benefits

- No manual status updates required
- Single source of truth (git state)
- Status cannot become inconsistent
- Works offline (with reduced functionality - completed tickets may show as pending)

## Branch Naming Convention

Ticket branches follow the pattern: `ticket/{RFC_ID}/{TICKET_ID}`

Example: `ticket/RFC-0002/TCK-00030`

## Migration Notes

Previously, ticket status was stored in the `status` field of ticket YAML files. This was removed because:

1. Status updates were error-prone and often forgotten
2. `start-ticket` would pick up already-completed tickets
3. Multiple sources of truth led to inconsistencies

The git state is now the authoritative source for ticket status.
