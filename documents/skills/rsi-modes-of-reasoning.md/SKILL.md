---
name: rsi-modes-of-reasoning
description: Recursive Skill Improvement for modes-of-reasoning reference files. Improves density, clarity, and actionability of reasoning mode documentation.
user-invocable: true
argument-hint: "[<mode-number> | <mode-name> | <file-path> | empty]"
---

## Invocation

```
/rsi-modes-of-reasoning              # Agent selects a universally-applicable mode to improve
/rsi-modes-of-reasoning 13           # Improve mode #13 (abductive reasoning)
/rsi-modes-of-reasoning bayesian     # Improve the Bayesian probabilistic reasoning reference
/rsi-modes-of-reasoning 80-debiasing # Improve by partial filename match
```

## Argument Handling

Parse `$ARGUMENTS`:

- **Mode number (1-80)** → Map to `references/{NN}-*.md` and set as TARGET_FILE
- **Mode name or keyword** → Search `references/` for matching file and set as TARGET_FILE
- **File path** → Use directly as TARGET_FILE
- **Empty** → Agent selects from universally-applicable candidates (see A2 below)

---

A) Select the target mode + file (exactly one)
    A1) If the user provided a mode number, mode name, or file path:
        - Map it to the exact reference file in `documents/skills/modes-of-reasoning/references/` and set TARGET_FILE to that.
        - Go to B.
    A2) Else (no target specified):
        - Read these files first:
          1) `documents/skills/modes-of-reasoning/SKILL.md`
          2) `documents/skills/modes-of-reasoning/references/introduction.md`
          3) `documents/skills/modes-of-reasoning/references/hybrid-patterns.md`
        - Pick your "favorite" mode *because it is universally applicable across domains* (not because it's trendy).
        - Constrain your choice to one of these broad candidates unless you have a strong reason: `75-meta-reasoning`, `80-debiasing-epistemic-hygiene`, `13-abductive`, `45-decision-theoretic`, `36-assurance-case`.
        - Decide using this tie-breaker order:
          (1) applies to most problem types, (2) reduces common failures across other modes, (3) yields concrete artifacts/checklists, (4) minimizes misuse.
        - Set TARGET_FILE to the chosen mode's reference file.
        - Briefly justify the selection in 3 bullets (max 1 line each).
        - Go to B.

B) Read + diagnose the current TARGET_FILE
    B1) Read TARGET_FILE completely.
    B2) Score it (1–5) on each axis, with 1-line justification each:
        - Density (every line earns its keep)
        - Clarity (unambiguous, actionable)
        - Distinctions (not confused with neighbors)
        - Misuse-resistance (guards against common failure mode)
        - Artifact-orientation (outputs are concrete)
    B3) If any score is 4–5 AND improvements would mostly be style nits:
        - Pick a different universally applicable mode (return to A2, pick next best candidate).
      Else:
        - Proceed to C.

C) Decide what to change (keep it a "reference card", not a textbook)
    C1) Preserve the existing headings (at minimum): "What it is", "What it outputs", "How it differs", "Best for", "Common failure mode", "Related modes".
    C2) You MAY add up to 3 new subsections ONLY if they increase density (no filler). Prefer:
        - "Procedure (decision steps)"
        - "Quick checklist"
        - "Micro-example" (5–10 lines)
    C3) Enforce density rules while editing:
        - Every bullet must be (a) a concrete criterion, (b) a concrete step, or (c) a concrete artifact/test.
        - Remove vague verbs ("consider", "think about") unless paired with a specific question or test.
        - Prefer compact contrasts ("X vs Y") and minimal definitions.
        - Add at least 2 "common confusions" with nearby modes and how to tell them apart.
        - Add mitigations for the stated "Common failure mode" (at least 3 mitigations, each testable/actionable).

D) Implement the edit
    D1) Edit only TARGET_FILE.
    D2) Keep links consistent with existing filenames in `documents/skills/modes-of-reasoning/references/`.
    D3) Aim for ~1.5×–2.5× the original length, but ONLY if each added line adds new information.

E) Self-review gate (must pass before finalizing)
    E1) Re-read the edited file once end-to-end.
    E2) Verify:
        - The "What it outputs" section lists artifacts that the "Procedure" actually produces.
        - The "How it differs" section has crisp boundaries with at least 3 nearby modes.
        - The "Common failure mode" has concrete mitigations and a detection signal.
        - No duplicated bullets, no generic pep-talks, no unexplained jargon.
    E3) If any check fails, revise until it passes.

F) Output (what you must produce)
    F1) Provide a patch/diff editing only TARGET_FILE.
    F2) Provide a brief changelog (5 bullets max) describing what improved and why.
    F3) If you selected the mode yourself (A2), include the 3-bullet justification from A2 before the diff.
