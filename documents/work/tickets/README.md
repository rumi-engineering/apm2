# Work Tickets

This directory contains work tickets for RFC implementation decomposition.

## Ticket Creation Guidelines

1. **ID Format**: Use `TICKET-NNNN` format (e.g., `TICKET-0001`)
2. **File Naming**: `TICKET-NNNN.yaml`
3. **Schema**: Follow `standards/schemas/04_ticket_meta.schema.yaml`

## Ticket Structure

Each ticket should contain:

- `ticket_id`: Unique identifier
- `title`: Brief description of the work
- `requirement_refs`: Links to requirements being implemented
- `evidence_refs`: Links to evidence artifacts being produced
- `acceptance_criteria`: Specific criteria for completion
- `dependencies`: Other tickets that must complete first

## Workflow

1. Create tickets during RFC decomposition
2. Link tickets to PRD requirements
3. Track implementation progress
4. Verify evidence artifacts on completion

## Related Documents

- PRD: `documents/prds/AIP-0001/`
- RFC: `documents/rfcs/AIP-0001/` (when created)
- Standards: `standards/`
