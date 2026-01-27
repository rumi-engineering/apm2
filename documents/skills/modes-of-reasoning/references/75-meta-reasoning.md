# Meta-Reasoning (Strategy Selection for Thinking)

**Category:** Meta-Level and Reflective Modes

## What it is

Second-order reasoning that selects, monitors, and adjusts first-order reasoning processes. The core questions:

1. **Mode selection:** Which reasoning mode(s) should I apply to this problem?
2. **Effort allocation:** How much time/depth should I invest before committing?
3. **Stopping criteria:** When do I have enough to decide? When is more analysis wasteful?
4. **Quality monitoring:** Is my current reasoning on track, or should I switch approaches?

Meta-reasoning is the "operating system" for all other reasoning modes. Every problem requires at least an implicit meta-reasoning step ("how should I think about this?")—making it explicit improves consistency and reduces mode mismatch.

**Core principle:** The fastest path to a good answer is often choosing the right reasoning mode upfront. A mismatched mode wastes effort (optimizing when you should satisfice) or produces wrong-shaped outputs (generating hypotheses when you need proofs). Meta-reasoning is cheap (~2 minutes); mode-mismatch recovery is expensive.

## What it outputs

| Artifact | Description | Produced by step |
|----------|-------------|------------------|
| **Problem characterization** | Classification of problem type (belief/action, cooperative/adversarial, certainty/exploration) | Step 1 |
| **Mode selection rationale** | Which mode(s) to use and why they fit this problem type | Step 2 |
| **Time/effort budget** | Max time for analysis before decision, with diminishing-returns threshold | Step 3 |
| **Stopping rule** | Specific condition that triggers "enough analysis" (e.g., confidence >=80%, 3 alternatives evaluated) | Step 3 |
| **Progress checkpoints** | Scheduled moments to assess "is this approach working?" | Step 4 |
| **Mode-switch trigger** | What signals would cause abandoning current approach for another | Step 5 |
| **Retrospective note** | 1-sentence record of whether mode selection worked for future reference | Step 6 |

### Artifact templates

**Problem characterization (Step 1):**
```
Problem: [1-sentence description]
Type: [belief | action | both]
Environment: [cooperative | adversarial | mixed]
Need: [certainty/assurance | exploration/learning | explanation/diagnosis | choice/tradeoffs]
Time pressure: [high (<1h) | medium (hours-days) | low (weeks+)]
Stakes: [low (easily reversible) | medium | high (costly to reverse)]
```

**Mode selection card (Step 2-5):**
```
Primary mode: [mode name] because [1-sentence fit rationale]
Backup mode: [mode name] if [trigger condition]
Time budget: [X minutes/hours], meta-reasoning used [Y minutes]
Stopping rule: [specific condition]
Checkpoints: [schedule, e.g., "15m, 30m, 45m"]
Switch trigger: [specific signal → specific action]
```

## Procedure (decision steps)

1. **Characterize the problem type** — Before selecting a mode, classify the problem:
   - Is this about *belief* (what's true) or *action* (what to do)?
   - Is the world *cooperative* (physics, nature) or *adversarial* (competitors, security)?
   - Do I need *certainty* (assurance) or *exploration* (discovery)?
   - Is time pressure *high* (satisfice) or *low* (optimize)?
   - *Test:* Can you state the problem type in one sentence?
   - *Output:* 1-sentence problem characterization.

2. **Select candidate modes** — Based on characterization, identify 2-3 modes that could apply (see Mode Selection Heuristics below). Don't commit to one yet.
   - *Technique:* Use the heuristics table. Match problem characteristics to recommended modes.
   - *Test:* Can you articulate why each candidate fits the problem type?
   - *Output:* List of 2-3 candidate modes with fit rationale for each.

3. **Set effort budget and stopping rule** — Before starting analysis, decide:
   - Max time/depth for this decision (proportional to stakes and reversibility)
   - What "done" looks like: confidence threshold, number of alternatives evaluated, or diminishing-returns signal
   - *Test:* Would you recognize "good enough" if you saw it?
   - *Output:* Written time budget + stopping criterion.

4. **Execute primary mode with checkpoints** — Apply the chosen mode, but schedule check-ins (e.g., every 15 min, every major step):
   - Is this mode producing useful output?
   - Am I making progress toward the stopping criterion?
   - Should I switch modes or escalate effort?
   - *Output:* Brief checkpoint log (even if just mental).

5. **Evaluate mode-switch triggers** — Know in advance what would cause you to abandon the current approach:
   - Mode produces no progress after 2 checkpoints → switch to alternative
   - New information fundamentally changes problem characterization → restart from step 1
   - Hitting time budget without reaching stopping rule → either extend with justification or satisfice
   - *Output:* Mode-switch trigger written before analysis begins.

6. **Close the loop** — After decision, briefly note: Did the mode selection work? What would you do differently? This feeds future meta-reasoning.
   - *Output:* 1-sentence retrospective note.

## Mode Selection Heuristics

| Problem characteristic | Likely modes | Avoid |
|------------------------|--------------|-------|
| Need certainty / assurance | Deductive, proof, constraint, assurance-case | Heuristics, abduction alone |
| Need learning / prediction | Bayesian, statistical, calibration | Pure deduction (no new info) |
| Need explanation / diagnosis | Abduction, causal, mechanistic | Induction (finds patterns, not causes) |
| Need action under tradeoffs | Decision theory, MCDA, satisficing | Epistemic modes that only update beliefs |
| Adversarial environment | Game theory, red-team, robust/worst-case | Naive expected-value optimization |
| Time pressure high | Satisficing, heuristics, reference-class | Optimization, full Bayesian elicitation |
| Ambiguity about problem framing | Sensemaking, dialectical | Jumping to analysis before framing |
| Multiple stakeholders with conflicts | Argumentation, negotiation, rhetoric | Single-agent decision theory |
| Safety-critical system | Assurance-case, robust, red-team | Heuristics, informal reasoning |
| Don't know what I don't know | Reference-class + VoI reasoning | Overconfident single-mode commitment |

## Stuck Diagnostic (when no mode obviously fits)

If you've spent >3 minutes on mode selection without converging, work through this decision tree:

```
Can you state the problem in one sentence?
  │
  ├─ NO → Use SENSEMAKING first. You're not ready for mode selection.
  │        Ask: "What's actually going on here?" until you can state it.
  │
  └─ YES → Is the problem about WHAT'S TRUE or WHAT TO DO?
            │
            ├─ WHAT'S TRUE (belief) →
            │    │
            │    ├─ Do you have data/evidence? → Statistical / Bayesian
            │    ├─ Do you need to explain something? → Abductive / Causal
            │    └─ Do you need certainty/proof? → Deductive / Assurance-case
            │
            └─ WHAT TO DO (action) →
                 │
                 ├─ Are others responding strategically? → Game theory / Negotiation
                 ├─ Are tradeoffs explicit? → Decision theory / MCDA
                 ├─ Is time pressure high? → Satisficing / Heuristics
                 └─ Is failure catastrophic? → Robust / Worst-case / Red-team
```

**If still stuck after the tree:**
1. Ask: "What would a competent practitioner in this domain do by default?" Use that.
2. If no domain default: Start with **reference-class forecasting** (ground in base rates) + **satisficing** (make a "good enough" call). This combination works for most problems and rarely catastrophically fails.
3. Document your uncertainty: "I'm not confident in mode selection; using [X] as default with [Y] as backup if [trigger]."

## Quick checklist

- [ ] Problem characterized (belief vs. action, cooperative vs. adversarial, certainty vs. exploration)
- [ ] >=2 candidate modes identified with fit rationale
- [ ] Time budget set (proportional to stakes)
- [ ] Stopping rule specified (confidence threshold, alternatives evaluated, or diminishing-returns signal)
- [ ] Mode-switch trigger defined
- [ ] Checkpoint schedule established
- [ ] Retrospective note planned

## Protocol Selection Flowchart

```
Is this a familiar problem type you've solved before?
  │
  ├─ YES → Use domain default (see Domain Defaults below)
  │         • Skip explicit mode selection
  │         • 30-second "does this still fit?" check
  │         • No formal artifacts needed
  │
  └─ NO → Are the stakes high (costly if wrong, hard to reverse)?
           │
           ├─ NO → Abbreviated protocol (2 min)
           │        • 1-sentence problem characterization
           │        • 1 primary mode + 1 backup
           │        • Implicit stopping rule
           │        • No written artifacts
           │
           └─ YES → Full protocol (5-10 min)
                    • Written problem characterization (use template)
                    • 2-3 candidate modes with fit rationale
                    • Explicit time budget and stopping rule
                    • Mode-switch trigger documented
                    • Checkpoint schedule for long analyses
```

**Rule of thumb:** Meta-reasoning should consume <5% of your total analysis budget. If you have 1 hour for a decision, meta-reasoning gets 3 minutes.

## Domain Defaults Reference Card

For familiar problem types, skip mode selection and use these defaults:

| Domain | Default mode ladder | Switch to... if... |
|--------|--------------------|--------------------|
| **Debugging / incident response** | Diagnostic → Mechanistic → Abductive | Causal if root-cause not in code |
| **Estimation / forecasting** | Reference-class → Fermi → Bayesian | Robust/worst-case if downside matters more |
| **Code review / verification** | Deductive → Constraint → Counterexample | Heuristic if time-boxed |
| **Architecture decisions** | Decision-theoretic → Satisficing → MCDA | Game-theoretic if multiple stakeholders |
| **Hiring / evaluation** | Reference-class → Calibration → Debiasing | Satisficing under time pressure |
| **Incident postmortem** | Counterfactual → Causal → Mechanistic | Debiasing to check hindsight bias |
| **Strategic planning** | Scenario/simulation → Robust → Game-theoretic | Sensemaking if environment ambiguous |
| **Safety analysis** | Assurance-case → Red-team → Robust | Mechanistic for specific failure modes |
| **Research / exploration** | Abductive → Statistical → Bayesian | Sensemaking if problem unclear |
| **Negotiation / conflict** | Game-theoretic → Negotiation → Argumentation | Theory-of-mind if motives unclear |

**Using the ladder:** Start with the first mode. If it's not producing useful output after 1-2 checkpoints, move to the next. The ladder is a sensible default, not a mandate.

## Micro-example

**Situation:** Customer reports intermittent login failures. You have 1 hour to diagnose.

| Step | Action | Output |
|------|--------|--------|
| 1. Characterize | Belief problem (what's causing this?), cooperative (no adversary), need explanation, high time pressure | "Diagnosis under time pressure" |
| 2. Candidate modes | (a) Abductive reasoning, (b) Diagnostic/troubleshooting, (c) Mechanistic | (b) Diagnostic best fits—structured triage |
| 3. Budget/stopping | 45 min max, done when: root cause identified OR top 3 hypotheses ranked with evidence | Time = 45m, stop = root cause or ranked hypotheses |
| 4. Execute | Apply diagnostic mode: reproduce → hypothesize → test → narrow. Checkpoint at 15m and 30m. | 15m: 3 hypotheses; 30m: 1 ruled out |
| 5. Mode-switch trigger | If no hypothesis gains traction by 30m, escalate to mechanistic (trace code paths) | Written trigger: "30m → mechanistic" |
| 6. Outcome | Root cause found at 35m (session cookie race condition). Retro: diagnostic mode worked; checkpoints helped. | Retro note logged |

## How it differs

| Mode | Meta-reasoning differs because... |
|------|-----------------------------------|
| [Sensemaking](63-sensemaking-frame-building.md) | Sensemaking establishes *what the problem is*; meta-reasoning selects *how to reason about it*. Sensemaking asks "What's going on?" Meta-reasoning asks "How should I think about what's going on?" Sensemaking precedes meta-reasoning: first frame, then choose mode. |
| [Calibration](76-calibration-epistemic-humility.md) | Calibration tracks accuracy of judgments over time (retrospective); meta-reasoning decides which judgment process to use for a single problem (prospective). Calibration answers "Am I good at this type of reasoning?" Meta-reasoning answers "Which type of reasoning should I use now?" |
| [Debiasing](80-debiasing-epistemic-hygiene.md) | Debiasing audits the *output* of reasoning for predictable errors; meta-reasoning selects the *input* (which mode to apply). Both are meta-level, but debiasing is a constraint layer, meta-reasoning is a selection layer. Debiasing asks "Is this output trustworthy?" Meta-reasoning asks "Which process should produce the output?" |
| [Value-of-information](52-value-of-information.md) | VoI decides whether to *gather more data* before deciding; meta-reasoning decides *how to reason* with current data. VoI is one input to meta-reasoning's stopping rule. VoI asks "Should I get more info?" Meta-reasoning asks "How should I process the info I have?" |
| [Heuristic reasoning](53-heuristic.md) | Heuristics are a specific mode (fast-and-frugal); meta-reasoning decides *when* to use heuristics vs. slower modes. Heuristics are a tool; meta-reasoning selects tools. |
| [Planning reasoning](47-planning-policy.md) | Planning constructs a sequence of *actions* toward a goal; meta-reasoning constructs a sequence of *reasoning steps*. Planning is for action; meta-reasoning is for thinking. Meta-reasoning is "planning for thinking." |

**Common confusions:**

1. *Meta-reasoning vs. overthinking:* Meta-reasoning is brief and bounded—a 2-minute mode selection, not a 2-hour philosophy seminar. If meta-reasoning takes longer than 10% of your analysis budget, you're doing it wrong.
   - **Boundary test:** Did mode selection take <5% of total analysis time? If yes, meta-reasoning. If no, overthinking.

2. *Meta-reasoning vs. debiasing:* Meta-reasoning asks "which tool?" Debiasing asks "is this tool's output trustworthy?" Use meta-reasoning first to choose the mode, then apply debiasing to check its output.
   - **Boundary test:** Meta-reasoning: "Should I use abduction or causal inference here?" Debiasing: "Did I anchor my hypothesis on the first idea I heard?"

3. *Meta-reasoning vs. planning:* Planning reasoning constructs a sequence of actions toward a goal. Meta-reasoning constructs a sequence of reasoning *steps*—it's planning for thinking, not planning for doing.
   - **Boundary test:** Planning: "What actions achieve my goal?" Meta-reasoning: "What reasoning modes should I apply to decide what actions to take?"

4. *Meta-reasoning vs. sensemaking:* Sensemaking figures out what the situation is. Meta-reasoning figures out how to think about it. If you don't know what's going on, start with sensemaking. If you know what's going on but don't know how to analyze it, use meta-reasoning.
   - **Boundary test:** Sensemaking: "What's happening here?" Meta-reasoning: "Now that I know what's happening, how should I analyze it?"

5. *Meta-reasoning vs. calibration:* Calibration tracks your accuracy over many past judgments. Meta-reasoning selects a reasoning mode for the current problem. Calibration is retrospective ("how good am I at this?"); meta-reasoning is prospective ("what should I do now?").
   - **Boundary test:** Calibration: "My 80%-confidence predictions were right 65% of the time." Meta-reasoning: "For this problem, should I use statistical reasoning or heuristics?"

6. *Meta-reasoning vs. reflective equilibrium:* Reflective equilibrium adjusts beliefs and principles for coherence across your entire belief system. Meta-reasoning selects a reasoning mode for a specific problem without requiring full belief-system coherence.
   - **Boundary test:** Reflective equilibrium: "Do my intuitions about this case fit my general principles?" Meta-reasoning: "Which reasoning mode fits this problem type?"

## Best for

- **High-stakes decisions** — where mode mismatch is costly (choosing deduction when you need abduction, or vice versa)
- **Novel problems** — where no default reasoning mode obviously applies
- **Multi-phase analysis** — where different stages require different modes (e.g., abduction → deduction → statistical testing)
- **Team reasoning** — aligning a group on how to approach a problem before diving in
- **AI system design** — explicitly programming reasoning mode selection
- **Teaching reasoning** — making implicit mode choices explicit for learners
- **Post-failure analysis** — "did we use the wrong reasoning approach?" is a meta-reasoning question
- **Resource-constrained decisions** — when you can't afford to try every mode

## Common failure mode

**Meta-infinite regress:** Spending so much time deciding how to reason that you never actually reason about the object-level problem. "Thinking about thinking about thinking."

### Detection signals

- Time spent on mode selection exceeds 10-15% of total analysis budget
- You've considered more than 5 candidate modes without selecting one
- Discussion of "how to approach this" has lasted longer than initial analysis would take
- You're researching meta-reasoning frameworks instead of applying a reasonable mode
- Second-guessing mode choice after every checkpoint
- The phrase "but what if we should use a different approach?" keeps recurring

### Mitigations

1. **Time-box meta-reasoning strictly** — Set a hard limit: mode selection gets 5% of total time budget. If you have 1 hour for a decision, meta-reasoning gets 3 minutes, max. Then commit.
   - *Test:* Is your meta-reasoning timer running?

2. **Default mode ladder** — Pre-commit to a fallback sequence if uncertain: (1) What would a competent practitioner in this domain do by default? Start there. (2) If no domain default, use satisficing + reference-class. (3) Upgrade to more sophisticated modes only if default clearly fails.
   - *Test:* Do you have a default mode for this domain?

3. **"Good enough" mode selection** — Apply satisficing to meta-reasoning itself. The goal isn't finding the optimal reasoning mode—it's finding a mode that will work. 80% of mode selections are obvious; don't over-engineer the 80%.
   - *Test:* Would a reasonable colleague agree this mode fits? If yes, stop deliberating.

4. **Checkpoint commitment** — At checkpoints, ask "is this mode working?" not "was this the optimal mode?" Switching modes costs time; only switch if current mode is *failing*, not merely *suboptimal*.
   - *Test:* Is the current mode producing useful output? If yes, continue.

5. **Avoid meta-meta-reasoning** — Never ask "how should I decide how to reason?" That's the regress. Meta-reasoning is one level up; stop there. If you find yourself reasoning about meta-reasoning, default to the mode ladder.
   - *Test:* Are you thinking about the problem, or thinking about thinking about thinking?

## Anti-patterns to avoid

| Anti-pattern | What it looks like | Fix |
|--------------|-------------------|-----|
| **Analysis paralysis** | Can't pick a mode; keep researching frameworks | Time-box + default mode ladder |
| **Mode perfectionism** | "We need the exact right approach" | Apply satisficing to mode selection |
| **Checkpoint anxiety** | Questioning mode choice every 5 minutes | Pre-commit to checkpoint schedule; only evaluate at checkpoints |
| **Regress spiral** | "How should I decide how to reason?" | Stop at one level of meta; use default ladder |
| **Mode rigidity** | Never switching even when mode clearly failing | Pre-define mode-switch triggers |
| **Implicit meta-reasoning** | Using default mode without considering fit | Spend 2 min on explicit characterization |
| **Mode tourism** | Trying every mode to "be thorough" | Commit to 1 primary + 1 backup; more modes = more confusion |
| **Premature switching** | Abandoning mode before giving it a fair trial | Require 2+ checkpoints before switching |

## When meta-reasoning backfires

Meta-reasoning has costs. Watch for these failure patterns:

1. **False precision** — Treating mode selection as an optimization problem when any reasonable mode would work. *Fix:* Most problems have multiple adequate approaches; "good enough" mode selection is usually sufficient.

2. **Mode-switching churn** — Switching modes at every checkpoint, never committing long enough to get results. *Fix:* Require 2 checkpoints showing "no progress" before switching; switching has costs.

3. **Sophistication bias** — Choosing complex modes (Bayesian, game-theoretic) when simple modes (heuristics, reference-class) would suffice. *Fix:* Start with simplest mode that could work; upgrade only if it fails.

4. **Meta-level escape** — Using meta-reasoning to avoid the hard work of object-level reasoning. "I can't solve this problem, but I can discuss which mode to use." *Fix:* Time-box meta-reasoning; force object-level commitment.

5. **Paralysis by framework** — Researching "the best meta-reasoning framework" instead of applying a reasonable one. *Fix:* Use this document as-is; any framework is better than no decision.

**Rule of thumb:** If explicit meta-reasoning doesn't visibly improve your mode choices, skip it. For routine problems in familiar domains, implicit meta-reasoning (domain defaults) is faster and usually correct.

## Mode-switch decision matrix

When to switch vs. persist with your current mode:

| Signal | Persist | Switch | Escalate |
|--------|---------|--------|----------|
| Mode producing partial output | ✓ Continue | | |
| Mode producing no output after 2 checkpoints | | ✓ Backup mode | |
| Problem characterization was wrong | | | ✓ Restart from Step 1 |
| New information changes problem type | | | ✓ Re-characterize |
| Time budget exhausted, stopping rule not met | | ✓ Satisfice with best-so-far | |
| Mode produces output but it's wrong-shaped | | ✓ Different mode | |
| You're confused about what mode is doing | | ✓ Simpler mode | |
| Stakeholders disagree on mode choice | | | ✓ Sensemaking first |

## Related modes

- [Sensemaking / frame-building](63-sensemaking-frame-building.md) — establishes problem framing before mode selection
- [Value-of-information reasoning](52-value-of-information.md) — decides whether to gather more info (input to stopping rules)
- [Calibration and epistemic humility](76-calibration-epistemic-humility.md) — tracks long-run reasoning quality
- [Debiasing / epistemic hygiene](80-debiasing-epistemic-hygiene.md) — audits mode outputs for bias
- [Satisficing](51-satisficing.md) — "good enough" mode choice when optimization is costly
- [Heuristic reasoning](53-heuristic.md) — fast reasoning mode that meta-reasoning may select under time pressure
- [Planning / policy reasoning](47-planning-policy.md) — planning for actions (vs. meta-reasoning: planning for thinking)
- [Reflective equilibrium](77-reflective-equilibrium.md) — adjusting beliefs and principles for coherence
