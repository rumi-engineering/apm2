title: Ticket Queue — Loop

decision_tree:
  entrypoint: SNAPSHOT_AND_CLASSIFY
  nodes[1]:
    - id: SNAPSHOT_AND_CLASSIFY
      purpose: "Compute state via High-Water Mark. Dispatch work."
      steps[8]:
        - id: NOTE_VARIABLE_SUBSTITUTION
          action: "Replace $1 with <TARGET_RFC>."
        - id: FIND_HIGH_WATER_MARK
          action: command
          run: "gh pr list --state merged --limit 20 --json headRefName --jq '.[].headRefName' | rg -o \"TCK-[0-9]{5}\" | sort -r | head -n 1"
          capture_as: latest_merged_tck
        - id: LIST_OPEN_PRS
          action: command
          run: "gh pr list --state open --limit 50 --json headRefName --jq '.[].headRefName' | rg -o \"TCK-[0-9]{5}\" | sort -u"
          capture_as: in_progress_ticket_ids
        - id: IDENTIFY_IN_PROGRESS
          action: "If in_progress_ticket_ids non-empty, pick lowest ID."
        - id: DISCOVER_NEXT_FOR_RFC
          action: command
          run: |
            all_tcks=$(rg -l 'rfc_id: "<TARGET_RFC>"' documents/work/tickets/ | rg -o "TCK-[0-9]{5}" | sort)
            merged_tcks=$(gh pr list --state merged --limit 100 --json headRefName --jq '.[].headRefName' | rg -o "TCK-[0-9]{5}" | sort -u)
            unmerged=$(echo "$all_tcks" | grep -vFf <(echo "$merged_tcks"))
            for tck in $unmerged; do
              deps=$(rg "tickets:" -A 10 "documents/work/tickets/$tck.yaml" | grep -o "TCK-[0-9]\{5\}")
              blocked=0
              for d in $deps; do
                if ! echo "$merged_tcks" | grep -q "$d"; then blocked=1; break; fi
              done
              if [ $blocked -eq 0 ]; then echo "$tck"; exit 0; fi
            done
          capture_as: next_tck_for_rfc
        - id: VERIFY_UNBLOCKED
          action: "Check `dependencies.tickets` in `documents/work/tickets/<next_tck_for_rfc>.yaml`."
        - id: ROUTE
          action: "Route to next step."
      decisions[4]:
        - id: MONITOR
          if: "in_progress_ticket_ids non-empty"
          then:
            next_reference: references/process-in-progress-ticket.md
        - id: START
          if: "in_progress_ticket_ids empty AND next_tck_for_rfc non-empty"
          then:
            next_reference: references/start-and-process-next-ticket.md
        - id: STOP
          if: "in_progress_ticket_ids empty AND next_tck_for_rfc empty"
          then:
            next_reference: references/stop-all-tickets-merged.md
        - id: UNKNOWN
          if: "otherwise"
          then:
            next_reference: references/stop-blocked-unknown-state.md