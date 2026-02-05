title: Agent Instruction Authoring Standard
standard:
  id: AGENT-INSTRUCTION-AUTHORING
  version: 1.0.0
  status: ACTIVE
  last_updated: "2026-01-25"
  applies_to[3]:
    - "documents/skills/**/SKILL.md"
    - "documents/skills/**/references/*.md"
    - "documents/reviews/*.md"

purpose: |
  Define a durable, low-ambiguity format and quality bar for writing instructions to autonomous agents.
  The format MUST be cold-start safe and structured as a decision tree using nested TOON syntax.

normative_language:
  keywords[3]:
    - MUST
    - SHOULD
    - MAY
  meaning:
    MUST: "Mandatory requirement; violating it is a correctness defect in the instruction set."
    SHOULD: "Strong default; deviate only with explicit justification in the document."
    MAY: "Optional; use when helpful."

principles[7]:
  - id: COLD_START_SAFE
    rule: "Assume the agent has read nothing else. The first page must orient the agent and define scope."
  - id: DECISION_TREE_OVER_NARRATIVE
    rule: "Instructions MUST be a routed decision tree with explicit branches and stop conditions."
  - id: PROGRESSIVE_DISCLOSURE
    rule: "Keep SKILL.md small; route detail and branching logic into references/."
  - id: OPEN_ENDED_FOR_JUDGMENT
    rule: "For judgment-heavy work (design, review, refactor), instruct the agent to select and apply relevant frameworks rather than follow a brittle checklist."
  - id: COMMAND_EXACTNESS
    rule: "When prescribing commands, include exact flags/args/timeouts and expected outcomes."
  - id: EVIDENCE_OVER_CLAIMS
    rule: "Prefer explicit inputs/outputs/artifacts and evidence requirements over narrative assertions."
  - id: NO_HIDDEN_MAGIC
    rule: "Do not rely on implicit variable interpolation, unstated context, or undefined tool behavior."

required_package_shape:
  skill_dir:
    must_include[2]:
      - "SKILL.md"
      - "references/"
    may_include[3]:
      - "templates/"
      - "examples/"
      - "scripts/"

skill_md_contract:
  frontmatter:
    must_include[2]:
      - name
      - description
    should_include[1]:
      - argument-hint
  body:
    must_include[6]:
      - orientation
      - title
      - protocol
      - variables
      - references
      - decision_tree

orientation_rules:
  must_cover[5]:
    - "role (who the agent is in this workflow)"
    - "mission objective (what done means)"
    - "scope boundaries (what is in scope vs out of scope for the agent)"
    - "quality bar (expected diligence and rigor)"
    - "review posture (assume independent third-party review; act accordingly)"

protocol_rules:
  must_include[4]:
    - "protocol.id"
    - "protocol.version"
    - "protocol.inputs[...]"
    - "protocol.outputs[...]"

variables_rules:
  default_argument_binding:
    preferred: "$1"
    avoid: "$ARGUMENTS"
    rationale: |
      $ARGUMENTS may include additional, spaced instructions when invoked by a parent agent,
      which can pollute argument parsing and cause unsafe or confusing behavior.
  reference_interpolation_warning:
    rule: "Assume references/ files DO NOT interpolate variables at runtime."
    required_pattern:
      - "Use placeholders like <TICKET_ID>, <PR_URL>, <OWNER>, <REPO>, <PR_NUMBER>."
      - "Add a NOTE_VARIABLE_SUBSTITUTION step near the top of reference flows."

references_rules:
  purpose: |
    references/ is the only place branching workflows and deep detail should live.
    This avoids contradictions by preventing duplicated truth in multiple places.
  branching_rule:
    MUST: "All branching decisions MUST route to a references/ file (or a specific anchor in one)."
    MUST_NOT: "Do not encode complex branching inline in SKILL.md."

decision_tree_rules:
  entrypoint:
    must_include: "decision_tree.entrypoint"
  nodes:
    must_be_true[3]:
      - "Each node has a stable id."
      - "Each node has a purpose that explains why it exists."
      - "Each node declares next steps via next/next_reference/stop."
  stop_conditions:
    must_be_true[2]:
      - "Stop conditions are explicit."
      - "Stop conditions specify required output and termination behavior."

command_rules:
  must_be_true[6]:
    - "Commands include exact flags and arguments."
    - "Commands include wrappers required for safety (e.g., timeout)."
    - "Commands are idempotent by default, or explicitly marked non-idempotent."
    - "Commands that can hang MUST include timeouts."
    - "Commands with side effects MUST be labeled as such."
    - "Frequently reused commands SHOULD live in references/commands.md to prevent drift."

context_files_rules:
  must_be_true[3]:
    - "When a step requires understanding, list the concrete file paths to read."
    - "Each context file must include a short purpose statement."
    - "Prefer minimal context (progressive disclosure) over bulk loading."

open_ended_analysis_rules:
  use_when[4]:
    - "designing an implementation"
    - "reviewing code changes"
    - "assessing risk or tradeoffs"
    - "refactoring complex subsystems"
  required_shape:
    steps[4]:
      - "Analyze the change surface and risk areas."
      - "Select applicable frameworks/modules based on the change."
      - "Apply them and record what was applied and why."
      - "Emit findings or decisions grounded in evidence."

anti_patterns[9]:
  - "Long narrative procedures with implicit branching."
  - "Duplicating the same command in multiple files with slight differences."
  - "Contradictory instructions across SKILL.md and references/."
  - "References to 'relevant docs' without concrete paths."
  - "Assuming CI status or external systems are the agent's responsibility unless explicitly required."
  - "Using $ARGUMENTS when the invocation might include multiple spaced parameters."
  - "Assuming variable interpolation in references/."
  - "Prescriptive checklists for judgment-heavy work without allowing framework selection."
  - "Undefined stop behavior (what to output and when to terminate)."

author_self_review:
  checklist[10]:
    - "A cold-start agent can execute this with no other context."
    - "SKILL.md contains a clear orientation and scope boundaries."
    - "Decision tree entrypoint routes to references/ for branching."
    - "References use placeholders (<...>) and include NOTE_VARIABLE_SUBSTITUTION."
    - "Commands include exact flags/args and required timeouts."
    - "Context files are concrete paths with purposes."
    - "No duplicated truth (commands/branches) across files."
    - "Stop conditions are explicit and testable."
    - "Judgment-heavy steps instruct framework selection and recording."
    - "All referenced paths exist or are explicitly optional."

templates:
  skill_md_minimal: |
    ---
    name: <skill-name>
    description: <when to use; what it does; what it does NOT do>
    argument-hint: "[<arg1> | empty]"
    ---

    orientation: "<cold-start role + mission + scope + quality bar>"

    title: <human title>
    protocol:
      id: <ID>
      version: <semver>
      type: executable_specification
      inputs[1]:
        - <ARG1>
      outputs[2]:
        - <artifact1>
        - <artifact2>

    variables:
      <ARG1>: "$1"

    references[3]:
      - path: "@documents/theory/glossary/glossary.json"
        purpose: "REQUIRED READING: APM2 terminology and ontology."
      - path: references/<workflow>.md
        purpose: "Primary decision tree."
      - path: references/commands.md
        purpose: "Command reference with flags and examples."

    decision_tree:
      entrypoint: WORKFLOW
      nodes[1]:
        - id: WORKFLOW
          action: invoke_reference
          reference: references/<workflow>.md

  reference_flow_minimal: |
    title: <Flow Name>

    decision_tree:
      entrypoint: <NODE_ID>
      nodes[1]:
        - id: <NODE_ID>
          purpose: "<why this flow exists>"
          steps[2]:
            - id: NOTE_VARIABLE_SUBSTITUTION
              action: "References do not interpolate variables; replace <...> placeholders before running commands."
            - id: DO_THE_THING
              action: "<open-ended or prescriptive step>"
          decisions[1]:
            - id: BRANCH
              if: "<condition>"
              then:
                next_reference: references/<other-flow>.md

  commands_reference_minimal: |
    title: Command Reference

    commands[2]:
      - name: <command-name>
        command: "<exact command with flags>"
        purpose: "<why/when>"
      - name: <command-name-2>
        command: "<exact command with flags>"
        purpose: "<why/when>"
