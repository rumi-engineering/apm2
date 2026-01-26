# PRD Review Commands

commands[4]:
  - name: create
    command: "/prd-review create PRD-XXXX"
    purpose: "Draft a new PRD from template."
  - name: refine
    command: "/prd-review refine PRD-XXXX"
    purpose: "Run gates and iteratively improve the PRD."
  - name: review
    command: "/prd-review review PRD-XXXX"
    purpose: "Run gates and emit findings/evidence (no edits)."
  - name: implicit-review
    command: "/prd-review PRD-XXXX"
    purpose: "Select mode interactively for the given PRD."
