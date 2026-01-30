title: One-Off Workflow (Ad-Hoc Ticket Creation)

purpose: |
  This workflow supports cases where work needs to be done outside the normal
  ticket queue. It allows an agent to:
  1. Set up a clean worktree for the work
  2. Identify or create the appropriate RFC
  3. Create an ad-hoc ticket
  4. Proceed with implementation

  Use this workflow when:
  - Fixing an urgent bug not covered by existing tickets
  - Implementing a small improvement discovered during other work
  - Addressing technical debt identified by reviewers

decision_tree:
  entrypoint: SETUP_WORKTREE
  nodes[1]:
    - id: SETUP_WORKTREE
      purpose: "Set up an isolated worktree for the ad-hoc work."
      steps[6]:
        - id: IDENTIFY_WORK_SCOPE
          action: "Describe the work to be done in 1-2 sentences. This will become the ticket title."
        - id: CHECK_EXISTING_TICKETS
          action: command
          run: "ls documents/work/tickets/TCK-*.yaml | xargs -I{} sh -c 'echo \"--- {} ---\"; head -10 {}' | grep -A5 'title:'"
          purpose: "Verify this work isn't already covered by an existing ticket."
        - id: IDENTIFY_RFC
          action: |
            Determine which RFC this work relates to:
            - If fixing a bug in existing RFC work, use that RFC's ID
            - If unrelated to any RFC, leave rfc_id empty in the ticket
            - If this warrants a new RFC, stop and use `rfc-council create` first
        - id: GENERATE_TICKET_ID
          action: command
          run: "ls documents/work/tickets/TCK-*.yaml | sort | tail -1 | rg -o 'TCK-[0-9]+' | awk -F- '{printf \"TCK-%05d\", $2+1}'"
          capture_as: new_ticket_id
          purpose: "Generate the next sequential ticket ID."
        - id: CREATE_WORKTREE
          action: command
          run: "cargo xtask start-ticket <new_ticket_id> --dry-run"
          purpose: "Preview worktree creation (will fail because ticket doesn't exist yet)."
        - id: CREATE_TICKET_FILE
          action: |
            Create a minimal ticket YAML at documents/work/tickets/<new_ticket_id>.yaml:
            ```yaml
            acceptance_criteria:
              - criterion: <describe the acceptance criterion>
                verification: <how to verify>
            implementation:
              summary: |
                <1-2 sentence description>
              files_to_modify:
                - path: <file path>
                  changes: |
                    <description of changes>
            notes: |
              Ad-hoc ticket created via one-off workflow.
            schema_version: "2026-01-26"
            template_version: "2026-01-26"
            test_requirements:
              - test_id: UT-<ticket_number>-01
                description: <test description>
                verification_command: <cargo test command>
            ticket:
              depends_on: []
              id: <new_ticket_id>
              requirement_ids: []
              rfc_id: <RFC-XXXX or empty>
              status: READY
              title: <ticket title>
            ```
      decisions[2]:
        - id: TICKET_EXISTS
          if: "Work is already covered by an existing ticket"
          then:
            action: "Use the existing ticket instead. Run: cargo xtask start-ticket TCK-XXXXX"
        - id: PROCEED_TO_IMPLEMENTATION
          if: "Ticket file created and validated"
          then:
            next_reference: references/new-ticket-flow.md

post_completion:
  action: |
    After completing implementation via the normal new-ticket-flow:
    1. Commit the ticket YAML along with the code changes
    2. Create PR with the ticket ID in the title
    3. Reference the one-off nature in the PR description

example:
  scenario: "Fix a typo in README.md discovered during code review"
  steps:
    - "Run list-ticket-ids to verify no existing ticket covers this"
    - "Generate new ticket ID: TCK-00279"
    - "Create minimal ticket YAML with title 'Fix README typo'"
    - "Run cargo xtask start-ticket TCK-00279"
    - "Make the fix, commit, push, create PR"
