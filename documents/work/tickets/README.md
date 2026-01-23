# Work Tickets

This directory contains work tickets for RFC implementation decomposition.

## Ticket Creation Guidelines

1. **ID Format**: Use `TCK-NNNNN` format (e.g., `TCK-00001`)
2. **File Naming**: `TCK-NNNNN.yaml` and `TCK-NNNNN.md`
3. **Schema**: Follow `standards/schemas/04_ticket_meta.schema.yaml`

## Ticket Structure

Each ticket should contain:

- `ticket_id`: Unique identifier (TCK-NNNNN)
- `title`: Brief description of the work
- `binds`: Links to PRD/RFC and requirements/evidence
- `definition_of_done`: Specific evidence_ids for completion
- `dependencies`: Other tickets that must complete first

## Workflow

1. Create tickets during RFC decomposition
2. Link tickets to PRD/RFC requirements
3. Track implementation progress
4. Verify evidence artifacts on completion

## Related Documents

- PRD: `documents/prds/PRD-0001/`
- RFC: `documents/rfcs/RFC-0001/`
- Standards: `standards/`
