title: Stop — All Tickets Merged

decision_tree:
  entrypoint: STOP
  nodes[1]:
    - id: STOP
      purpose: "Terminate when tickets for RFC are merged."
      steps[4]:
        - id: VERIFY_COMPLETION
          action: command
          run: "bash -lc 'set -euo pipefail; latest=$(gh pr list --state merged --limit 10 --json headRefName --jq ".[].headRefName" | rg -o "TCK-[0-9]{5}" | sort -r | head -n 1); missing=$(rg -l "rfc_id: \"<TARGET_RFC>\"" documents/work/tickets/ | rg -o "TCK-[0-9]{5}" | awk -v latest=\"$latest\" \"$1 > latest\" | sort); if [ -n \"$missing\" ]; then echo \"MISSING_TICKETS:\"; echo \"$missing\"; exit 1; fi; echo \"DONE\"'"
          capture_as: verify_output
        - id: EMIT_TICKET_MERGE_LEDGER
          action: "Output TicketMergeLedger."
        - id: OUTPUT_DONE
          action: "Output 'Done'."
        - id: STOP
          action: "Stop workflow."
      decisions[0]: []