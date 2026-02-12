# Work Tickets

This directory contains work tickets for RFC implementation decomposition.

## Ticket Format

Each ticket is a single YAML file (`TCK-NNNNN.yaml`) containing all metadata, scope, plan, and criteria. There are no separate markdown files.

## Ticket Creation Guidelines

1. **ID Format**: Use `TCK-NNNNN` format (e.g., `TCK-00001`)
2. **File Naming**: `TCK-NNNNN.yaml` (single file per ticket)
3. **Schema**: Follow `standards/schemas/04_ticket_meta.schema.yaml`

## Ticket Structure

Each ticket YAML contains:

- `ticket`: ID and title
- `binds`: Links to PRD/RFC requirements and evidence artifacts
- `custody`: Agent roles and responsibility domains
- `dependencies`: Other tickets that must complete first
- `scope`: `in_scope` and `out_of_scope` arrays
- `plan`: Implementation steps (optional)
- `definition_of_done`: Evidence IDs and acceptance criteria
- `notes`: Security posture and other notes

## Workflow

1. Create tickets during RFC decomposition
2. Link tickets to PRD/RFC requirements
3. Track implementation progress
4. Verify evidence artifacts on completion

## Related Documents

- PRD: `documents/prds/PRD-0001/`
- RFC: `documents/rfcs/RFC-0001/`
- Standards: `standards/`
- Template: `documents/work/templates/ENGINEERING_TICKET_TEMPLATE.yaml`
