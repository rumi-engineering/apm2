title: New Ticket Flow (No Existing PR)

decision_tree:
  entrypoint: NEW_TICKET_FLOW
  nodes[1]:
    - id: NEW_TICKET_FLOW
      purpose: "Implement a ticket from scratch and open a new PR."
      steps[12]:
        - id: NOTE_VARIABLE_SUBSTITUTION
          action: "References do not interpolate variables; replace <TICKET_ID> and <RFC_ID> with values extracted from start-ticket output."
        - id: READ_TICKET_CONTEXT
          action: "Read the ticket definition and any bound requirements. Capture scope, constraints, and definition of done."
          context_files[3]:
            - path: "documents/work/tickets/<TICKET_ID>.yaml"
              purpose: "Ticket metadata, scope, plan, criteria."
            - path: "documents/work/tickets/<TICKET_ID>.md"
              purpose: "Expanded notes, edge cases, and acceptance criteria (if present)."
            - path: "documents/rfcs/<RFC_ID>/06_ticket_decomposition.yaml"
              purpose: "Ticket scope and dependencies (if RFC exists)."
        - id: READ_LOCAL_INVARIANTS
          action: "Read the root README.md to identify the AGENTS.md files for each touched module. Read those AGENTS.md files, mod.rs, and relevant tests to understand local invariants."
        - id: SELECT_RELEVANT_RUST_FRAMEWORKS
          action: "Based on the planned changes, select the Rust domains that matter (ownership, lifetimes, async, unsafe, API design, errors, performance, security) and read the relevant rust-textbook sections."
        - id: PLAN_TESTS
          action: "Define a test strategy covering happy paths, edge cases, and failure modes that are relevant to this change."
        - id: IMPLEMENT
          action: "Implement the change with the chosen frameworks and local invariants in mind."
        - id: UPDATE_DOCS
          action: "Update documentation and AGENTS.md if public behavior or module invariants change."
        - id: UPDATE_AGENTS_DOCS
          action: "Update all relevant AGENTS.md files to reflect the latest changes and invariants before committing."
        - id: VERIFY_AND_COMMIT
          action: command
          run: "cargo xtask commit \"<message>\""
        - id: PUSH_CREATE_PR
          action: command
          run: "cargo xtask push"
        - id: MONITOR_STATUS
          action: command
          run: "timeout 30s cargo xtask check"
        - id: OPTIONAL_WATCH
          action: command
          run: "timeout 30s cargo xtask check --watch | tail -40"
      decisions[2]:
        - id: REVIEW_DENIED
          if: "status indicates review denied or changes requested"
          then:
            next_reference: references/review-denial-remediation.md
        - id: MERGED
          if: "status indicates merged"
          then:
            next_reference: references/post-merge-cleanup.md
