title: Follow Up on Existing PR

decision_tree:
  entrypoint: FOLLOW_UP_EXISTING_PR
  nodes[1]:
    - id: FOLLOW_UP_EXISTING_PR
      purpose: "Continue work on an existing PR, addressing the latest feedback and improvements."
      steps[12]:
        - id: NOTE_VARIABLE_SUBSTITUTION
          action: "References do not interpolate variables; replace <TICKET_ID>, <RFC_ID>, and <PR_URL> with values extracted from the ticket YAML."
        - id: READ_TICKET_CONTEXT
          action: "Read ticket definition and requirements."
          context_files[2]:
            - path: "documents/work/tickets/<TICKET_ID>.yaml"
            - path: "documents/rfcs/<RFC_ID>/06_ticket_decomposition.yaml"
        - id: READ_LOCAL_INVARIANTS
          action: "Read AGENTS.md and relevant code/tests for touched modules."
        - id: WRITE_IMPLEMENTATION_CONTRACT
          action: "Create ephemeral implementation contract for follow-up work (kept in working context only, NOT persisted to repo)."
          purpose: "Forces upfront analysis of remaining scope, security gaps, and test requirements before addressing feedback."
          output_format:
            scope_checklist:
              description: "Verify ALL original deliverables plus feedback items."
              items:
                - "List ALL original deliverables from ticket YAML"
                - "List ALL requirements from RFC 06_ticket_decomposition.yaml"
                - "List ALL items from review feedback requiring implementation"
                - "Mark any items already completed in previous iterations"
                - "Check off each remaining item as addressed"
            security_boundaries:
              description: "Re-verify security controls, especially for feedback-driven changes."
              items:
                - "List ALL SCP boundaries touched (original + feedback-driven)"
                - "For each boundary: cite required Rust Standards controls with CTR-XXXX references"
                - "List ALL new Vec/HashMap/HashSet with their MAX_* constants and enforcement points"
                - "Verify streaming deserializers for any new untrusted input paths"
            negative_tests:
              description: "Ensure adversarial tests cover feedback-driven changes."
              items:
                - "DoS test case: any new oversized input vectors from changes"
                - "Boundary test case: any new traversal/injection surfaces"
                - "Idempotency test case: verify replay safety preserved"
                - "Malformed input test case: any new parsing paths"
            protocol_alignment:
              description: "Verify feedback-driven changes still match RFC specification."
              items:
                - "Quote any RFC requirements affected by feedback"
                - "Confirm code changes maintain RFC alignment"
                - "Flag any RFC updates needed due to implementation learnings"
          validation: "Contract MUST be completed before proceeding to FETCH_LATEST_FEEDBACK."
          persistence: "EPHEMERAL - kept in agent working context only, never written to repository."
        - id: FETCH_LATEST_FEEDBACK
          action: command
          run: "gh pr view <PR_URL> --json reviews,reviewThreads --jq '{latest_review: (.reviews[-1].body // \"N/A\"), unresolved_threads: [.reviewThreads[]? | select(.isResolved == false) | {path: .path, body: .comments[-1].body}]}'"
          capture_as: latest_feedback
        - id: READ_PR_DIFF
          action: command
          run: "gh pr diff <PR_URL>"
          capture_as: diff_content
        - id: CONSULT_RUST_STANDARDS
          action: "Read relevant sections of the `documents/skills/rust-standards/` documents based on the feedback and planned changes."
        - id: IMPLEMENT_AND_TEST
          action: "Address the latest feedback and improve correctness. Follow Rust Standards quality guidelines."
        - id: UPDATE_DOCS_AND_AGENTS
          action: "Update documentation and AGENTS.md files to reflect changes and new invariants."
        - id: FIX_FORMATTING_AND_LINT
          action: command
          run: "cargo fmt --all && cargo clippy --fix --allow-dirty --all-targets --all-features -- -D warnings && cargo fmt --all --check"
        - id: VERIFY_AND_COMMIT
          action: command
          run: "git add -A && git commit -m \"Addressing review feedback and improving implementation\""
        - id: PUSH_CHANGES
          action: command
          run: "apm2 fac push"
        - id: FINISH
          action: "Task complete. The ticket-queue will monitor for further updates."
      decisions: []
