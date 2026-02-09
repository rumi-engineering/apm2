title: New Ticket Flow (No Existing PR)

decision_tree:
  entrypoint: NEW_TICKET_FLOW
  nodes[1]:
    - id: NEW_TICKET_FLOW
      purpose: "Implement a ticket from scratch and open a new PR."
      steps[12]:
        - id: NOTE_VARIABLE_SUBSTITUTION
          action: "References do not interpolate variables; replace <TICKET_ID> and <RFC_ID> with values extracted from the ticket YAML."
        - id: READ_TICKET_CONTEXT
          action: "Read ticket definition and requirements."
          context_files[2]:
            - path: "documents/work/tickets/<TICKET_ID>.yaml"
            - path: "documents/rfcs/<RFC_ID>/06_ticket_decomposition.yaml"
        - id: READ_LOCAL_INVARIANTS
          action: "Read AGENTS.md and relevant code/tests for touched modules."
        - id: WRITE_IMPLEMENTATION_CONTRACT
          action: "Create ephemeral implementation contract (kept in working context only, NOT persisted to repo)."
          purpose: "Forces upfront analysis of scope, security boundaries, and test requirements before any code is written."
          output_format:
            scope_checklist:
              description: "Extract ALL deliverables to ensure nothing is missed."
              items:
                - "List ALL deliverables from ticket YAML (parse every field)"
                - "List ALL requirements from RFC 06_ticket_decomposition.yaml"
                - "Mark any explicitly out-of-scope items"
                - "Check off each item as implemented (track in working context)"
            security_boundaries:
              description: "Identify security controls BEFORE implementation, not after."
              items:
                - "List ALL SCP boundaries touched (Identity, Ledger, Tool Execution, Filesystem, Network)"
                - "For each boundary: cite required Rust Standards controls with CTR-XXXX references"
                - "List ALL new Vec/HashMap/HashSet with their MAX_* constants and enforcement points"
                - "Identify any untrusted input requiring streaming deserializers"
            negative_tests:
              description: "Plan adversarial tests alongside happy-path tests."
              items:
                - "DoS test case: specific oversized input scenario with expected rejection"
                - "Boundary test case: path traversal or injection attempt with expected rejection"
                - "Idempotency test case: replay scenario demonstrating no duplicate effects"
                - "Malformed input test case: invalid structure with expected error"
            protocol_alignment:
              description: "Ensure implementation matches RFC specification exactly."
              items:
                - "Quote the RFC requirement being implemented (verbatim)"
                - "Note code location that will satisfy each requirement"
                - "Flag any RFC changes needed (bidirectional sync)"
          validation: "Contract MUST be completed before proceeding to CONSULT_RUST_STANDARDS."
          persistence: "EPHEMERAL - kept in agent working context only, never written to repository."
        - id: CONSULT_RUST_STANDARDS
          action: "Read relevant sections of the `documents/skills/rust-standards/` documents based on the planned changes (e.g., API design, Errors, Security)."
        - id: PLAN_TESTS
          action: "Define a test strategy covering happy paths, edge cases, and failure modes. Review the Hazard Catalog (RS-39) for relevant test vectors."
        - id: IMPLEMENT
          action: "Implement the change following Rust Standards quality guidelines."
        - id: UPDATE_DOCS_AND_AGENTS
          action: "Update documentation and AGENTS.md if public behavior or module invariants change."
        - id: FIX_FORMATTING_AND_LINT
          action: command
          run: "cargo fmt --all && cargo clippy --fix --allow-dirty --all-targets --all-features -- -D warnings && cargo fmt --all --check"
        - id: VERIFY_AND_COMMIT
          action: command
          run: "git add -A && git commit -m \"Initial implementation of <TICKET_ID>\""
        - id: PUSH_CREATE_PR
          action: command
          run: "apm2 fac push"
        - id: FINISH
          action: "Task complete. The ticket-queue will monitor for review feedback."
      decisions: []
