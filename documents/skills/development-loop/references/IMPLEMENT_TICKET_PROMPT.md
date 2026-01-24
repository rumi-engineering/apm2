You are implementing ticket $TICKET_ID for $RFC_ID in the apm2 Rust project.

The context above includes AGENTS.md, RFC meta/design, ticket details, and requirements.

## Your Task

1. Read the ticket definition:
   - `documents/work/tickets/$TICKET_ID.yaml` (metadata, requirements, dependencies)
   - `documents/work/tickets/$TICKET_ID.md` (detailed scope and plan)

2. Read all referenced requirements in `binds.requirements[]`

3. Implement ONLY what is in `scope.in_scope`. Do NOT implement `scope.out_of_scope`.

4. Satisfy all criteria in `definition_of_done.criteria[]`

5. Write tests first, then implement

6. Verify, sync, and commit:
   ```bash
   cargo xtask commit "<description>"
   ```

7. Push and run AI reviews:
   ```bash
   cargo xtask push
   ```
