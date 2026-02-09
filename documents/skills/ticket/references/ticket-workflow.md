title: Ticket Workflow Decision Tree

decision_tree:
  entrypoint: INIT_AND_CLASSIFY
  nodes[1]:
    - id: INIT_AND_CLASSIFY
      purpose: "Initialize worktree and choose the correct workflow path."
      context_files[6]:
        - path: documents/README.md
        - path: documents/skills/README.md
          purpose: "Root-level module index, documentation discovery, and repository-wide constraints."
        - path: documents/skills/rust-standards/SKILL.md
          purpose: "Rust quality guidance; choose relevant sections later."
        - path: documents/security/AGENTS.cac.json
          purpose: "Security documentation index and quick reference."
        - path: documents/security/SECURITY_POLICY.cac.json
          purpose: "Security invariants and modes."
        - path: documents/theory/agent_native_architecture.json
          purpose: "Core philosophy, architecture, and constraints."
      steps[5]:
        - id: READ_BASELINE_CONTEXT
          action: "Read the context files listed above and note global constraints."
        - id: NOTE_ARGUMENT_SUBSTITUTION
          action: "If this runner does not interpolate $1 in references, replace $1 manually with the ticket ID or omit it to auto-select the next unblocked ticket."
        - id: FIND_WORKTREE
          action: command
          run: "git worktree list | grep $1"
          capture_as: worktree_match
        - id: CREATE_OR_ENTER_WORKTREE
          action: |
            If worktree_match is non-empty, extract the path and cd into it.
            If worktree_match is empty, create a new worktree:
              git worktree add /home/ubuntu/Projects/apm2-$1 -b ticket/<RFC_ID>/$1
            Then cd into the worktree path.
          capture_as: worktree_path
        - id: READ_TICKET_YAML
          action: command
          run: "cat documents/work/tickets/$1.yaml"
          capture_as: ticket_yaml
        - id: EXTRACT_CONTEXT
          action: parse_text
          from: ticket_yaml
          extract[4]:
            - TICKET_ID
            - RFC_ID
            - PR_URL
            - WORKTREE_PATH
      decisions[3]:
        - id: NO_TICKET_AVAILABLE
          if: "start_ticket_output indicates no unblocked tickets or no ticket selected"
          then:
            next_reference: references/no-ticket-available.md
        - id: EXISTING_PR
          if: "PR_URL is present"
          then:
            next_reference: references/follow-up-existing-pr.md
        - id: NEW_TICKET
          if: "PR_URL is empty"
          then:
            next_reference: references/new-ticket-flow.md
