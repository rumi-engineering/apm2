# Debiasing / Epistemic Hygiene Reasoning

**Category:** Meta-Level and Reflective Modes

## What it is

A meta-discipline applying specific checks *before* committing to conclusions: base-rate anchoring, alternative-hypothesis generation, premortem analysis, and active disconfirmation search. Not a new inference pattern—a constraint layer that intercepts and stress-tests outputs from other reasoning modes.

The key insight: Cognitive biases are *predictable* errors, not random noise. Because they're predictable, they're correctable—if you know where to look. Debiasing operationalizes decades of cognitive science into actionable pre-commitment checks.

Debiasing applies to outputs from *any* other reasoning mode: before accepting an abductive hypothesis, a Bayesian update, a decision-theoretic recommendation, or a causal inference—run the debiasing checklist.

**Core principle:** Your conclusion is only as trustworthy as your adversarial audit of it. The checklist is not bureaucracy—it's the minimum viable process for catching the errors you're blind to by default.

## What it outputs

| Artifact | Description | Produced by step |
|----------|-------------|------------------|
| **Base-rate anchor** | Reference-class frequency before inside-view adjustment | Step 1 |
| **Alternative-hypothesis list** | >=3 competing explanations with relative plausibility | Step 2 |
| **Premortem report** | "Assume we failed—why?" with top 3 causes ranked by likelihood | Step 3 |
| **Disconfirmation tests** | Specific observations that would falsify the favored view | Step 4 |
| **Cognitive-load flag** | Assessment of reasoning conditions (rushed/tired/invested = provisional) | Step 5 |
| **Bias audit log** | Explicit check for anchoring/availability/confirmation with pass/fail + rationale | Step 6 |
| **Residual uncertainty statement** | What remains uncertain and why, even after debiasing | Step 7 |

## Procedure (decision steps)

1. **Anchor on base rate** — Before analyzing specifics, ask: "What's the reference-class frequency for outcomes like this?" Write it down *before* considering inside-view details.
   - *Technique:* Find 3+ similar past cases; what % succeeded/failed?
   - *Test:* Would you bet at this base rate? If not, adjust.
   - *Output:* "Base rate for [reference class] is X% (source: Y)."

2. **Generate alternatives** — List >=3 hypotheses that could explain the same evidence. Assign rough plausibility to each. Include at least one that contradicts your favored view.
   - *Technique:* "What would a smart skeptic believe? What if the opposite were true?"
   - *Test:* Are alternatives genuine competitors or strawmen?
   - *Output:* Numbered list with plausibility estimates (e.g., H1: 50%, H2: 30%, H3: 20%).

3. **Run premortem** — Assume the decision failed spectacularly. Brainstorm top 3 reasons it could fail. Rank by likelihood. Identify which are addressable now.
   - *Technique:* "It's one year later and this was a disaster. Write the postmortem headline."
   - *Test:* Did you include internal/controllable failure causes, not just external/uncontrollable ones?
   - *Output:* Top 3 failure causes with "addressable now?" flag.

4. **Seek disconfirmation** — For your favored conclusion, specify 2-3 observations that would change your mind. Actively look for them.
   - *Technique:* "What would I need to see to abandon this position?"
   - *Test:* Have you actually searched for disconfirming evidence, or just specified it hypothetically?
   - *Output:* Disconfirmation tests + search results.

5. **Check cognitive load** — If rushed, tired, or emotionally invested, flag the judgment as provisional and schedule re-evaluation under better conditions.
   - *Signals:* Deadline pressure, <6 hours sleep, strong emotional reaction to outcome, personal stake in being right.
   - *Test:* "Would I make this same judgment after a good night's sleep with no deadline?"
   - *Output:* Cognitive-load flag (green/yellow/red) + scheduled re-evaluation if yellow/red.

6. **Audit for specific biases** — Check the Big Three explicitly:
   - **Anchoring:** "Am I weighting the first number/estimate I heard too heavily?"
   - **Availability:** "Am I overweighting recent, vivid, or emotionally charged information?"
   - **Confirmation:** "Am I seeking/interpreting evidence to confirm my existing belief?"
   - *Test:* For each, articulate what you'd expect to see if you *were* biased—then check.
   - *Output:* 3-item audit with pass/fail + rationale.

7. **Document residual uncertainty** — Record what you're still uncertain about and why. Distinguish "uncertainty I can reduce with more info" from "irreducible uncertainty."
   - *Test:* Would gathering more information change the decision? If yes, is it worth the cost?
   - *Output:* Uncertainty statement with "reducible vs. irreducible" classification.

## Quick checklist (pre-decision gate)

- [ ] Base rate written *before* inside-view analysis (source cited)
- [ ] >=3 alternative hypotheses listed with plausibility estimates
- [ ] Premortem completed (top 3 failure causes, >=1 internal/controllable)
- [ ] >=2 disconfirming observations specified AND actively searched for
- [ ] Anchoring / availability / confirmation bias explicitly checked (3-item audit)
- [ ] Cognitive-load flag set (green/yellow/red)
- [ ] Residual uncertainty documented (reducible vs. irreducible)

## Bias Reference Card

| Bias | Definition | Detection question | Fix |
|------|------------|-------------------|-----|
| **Anchoring** | Over-relying on first information received | "Did my estimate move enough from the first number I heard?" | Estimate independently before seeing anchors; use multiple reference points |
| **Availability** | Overweighting easily recalled (recent/vivid) examples | "Am I thinking of this because it's likely or because it's memorable?" | Seek base rates; ask "what am I *not* thinking of?" |
| **Confirmation** | Seeking/interpreting evidence to support existing beliefs | "Would I accept this evidence if it supported the opposite conclusion?" | Actively seek disconfirmation; steelman the opposing view |
| **Overconfidence** | Excessive certainty in own judgments | "What's my track record on similar judgments?" | Calibration training; widen confidence intervals |
| **Hindsight** | "I knew it all along" after learning outcome | "Would I have predicted this *before* knowing the outcome?" | Pre-register predictions; reconstruct pre-outcome state |
| **Sunk cost** | Continuing because of past investment, not future value | "Would I start this if I hadn't already invested?" | Evaluate from fresh start; ignore sunk costs |
| **Planning fallacy** | Underestimating time/cost/risk for future tasks | "How long did similar past projects actually take?" | Use reference-class forecasting; add buffer |
| **Groupthink** | Conforming to group consensus without critical evaluation | "Have I heard genuine disagreement, or just alignment?" | Anonymous voting; assign devil's advocate |
| **Authority bias** | Over-deferring to senior/expert opinion | "Would I accept this reasoning from a junior person?" | Evaluate argument independent of source |
| **Status quo bias** | Preferring current state over alternatives | "Would I choose this option if starting fresh?" | Frame as active choice, not default |
| **Narrative fallacy** | Imposing coherent story on random/complex events | "Is this compelling because it's true, or because it's a good story?" | Demand mechanism + data; distrust "just so" explanations |
| **Conjunction fallacy** | Judging A∧B more likely than A alone (Linda problem) | "Am I adding detail that lowers probability but increases vividness?" | Check: P(A∧B) ≤ P(A); strip away vivid details and re-estimate |
| **Affect heuristic** | Letting emotional reaction drive probability/utility estimates | "Am I scared of this *because* it's likely, or does it just feel scary?" | Separate probability estimate from consequence evaluation |
| **Scope insensitivity** | Caring similarly about 10 vs. 10,000 affected | "Would I pay 10× more to help 10× more people?" | Use explicit quantification; convert to per-unit impact |

## Micro-example

**Situation:** Team proposes a new caching layer to fix performance.

| Step | Action | Output |
|------|--------|--------|
| 1. Base rate | "What % of caching projects actually solve the performance problem?" Historical data: ~40% hit root cause | Base rate: 40% (source: internal project retrospectives) |
| 2. Alternatives | (a) Caching helps: 40%, (b) N+1 query is real bottleneck: 35%, (c) GC pauses dominate: 20%, (d) Network latency: 5% | 4 hypotheses with plausibility |
| 3. Premortem | "Cache deployed, latency unchanged—why?" Didn't profile first (internal); cache hit rate low (internal); wrong layer cached (internal) | 3 causes, all addressable now |
| 4. Disconfirmation | Profile shows cache-hit rate <50% or latency unchanged after deployment = abandon caching hypothesis. **Searched:** ran profiler | Profiler showed N+1 queries, not cache misses |
| 5. Cognitive load | Team is not under deadline pressure; no emotional investment | Green flag |
| 6. Bias audit | Anchoring: first suggestion was caching = possible anchor; Availability: recent success with caching = possible; Confirmation: team likes caching = yes | 2/3 flags raised |
| 7. Decision | Profile showed N+1 queries dominate. Caching deprioritized; fix queries first | Alternative hypothesis (b) now favored |

## How it differs

| Mode | Debiasing differs because... |
|------|------------------------------|
| [Meta-reasoning](75-meta-reasoning.md) | Meta-reasoning selects *which* mode to use; debiasing audits *any* mode's output for predictable errors. Meta-reasoning: "What tool should I use?" Debiasing: "Is this tool's output trustworthy?" |
| [Calibration](76-calibration-epistemic-humility.md) | Calibration measures accuracy over many judgments (long-run tracking); debiasing applies corrective checks to a single judgment (point intervention). You need both: calibration tells you *how* biased you typically are; debiasing catches biases *now*. |
| [Red-teaming](79-adversarial-red-team.md) | Red-teaming assumes an external adversary attacking your system; debiasing assumes your own cognition is the adversary. Red-teaming: "How would an attacker break this?" Debiasing: "How is my own mind breaking this?" |
| [Heuristic reasoning](53-heuristic.md) | Heuristics are the fast-and-frugal shortcuts (System 1); debiasing is the slow audit that catches their errors (System 2). Heuristics are the defendant; debiasing is the prosecutor. |
| [Abductive reasoning](13-abductive.md) | Abduction generates hypotheses; debiasing prevents "story bias" from selecting the most narratively appealing rather than best-supported hypothesis. Apply debiasing *after* abduction, before committing. |
| [Bayesian reasoning](11-bayesian-probabilistic.md) | Bayesian reasoning is the normative standard for belief updating; debiasing catches departures from that standard (base-rate neglect, conservatism, representativeness). Debiasing ensures your actual updates approximate Bayesian updates. |
| [Reference-class forecasting](18-reference-class-outside-view.md) | Reference-class forecasting is *one technique* used in debiasing (step 1: anchor on base rate). Debiasing is the broader discipline; reference-class is a specific tool within it. |

**Common confusions:**

1. *Debiasing vs. calibration:* Calibration tracks long-run accuracy; debiasing intervenes on a single decision. You can be well-calibrated on average but still need debiasing on any specific high-stakes call.
   - **Boundary test:** Calibration answers "Over my last 50 predictions at 80% confidence, how many were correct?" Debiasing answers "For *this* decision, did I anchor on the first estimate I heard?"

2. *Debiasing vs. red-teaming:* Red-teaming asks "how would an attacker break this?" Debiasing asks "how is my own reasoning broken?" Both are adversarial audits, but the threat model differs: external adversary vs. internal cognitive failure.
   - **Boundary test:** Red-teaming requires simulating an adversary's goals and capabilities. Debiasing requires auditing your own cognition against a known list of biases.

3. *Debiasing vs. critical thinking:* "Critical thinking" is a vague umbrella term. Debiasing is specific: it targets *predictable* cognitive errors with *named* corrective procedures. Saying "think critically" is not debiasing; running the 7-step checklist is.
   - **Boundary test:** Can you name the specific bias you're checking for? If yes, debiasing. If no, vague "critical thinking."

4. *Debiasing vs. decision-theoretic reasoning:* Decision theory tells you how to choose given probabilities and utilities; debiasing audits whether your probability/utility estimates are trustworthy inputs. Decision theory is the formula; debiasing is the data-quality check.
   - **Boundary test:** Decision theory asks "Given P(X)=0.7 and U(X)=100, what should I choose?" Debiasing asks "Is 0.7 anchored on a bad first estimate?"

5. *Debiasing vs. scientific reasoning:* Science uses structured methods (experiments, peer review) that include debiasing elements, but debiasing is applicable to any judgment—including non-empirical ones (hiring, strategy, ethics). Science is a domain; debiasing is a meta-process.
   - **Boundary test:** Scientific reasoning requires hypothesis testing with data. Debiasing applies even when no experiment is possible (one-shot hiring decision).

6. *Debiasing vs. assurance-case reasoning:* Assurance cases construct traceable evidence chains for claims; debiasing audits the *judgment quality* behind those claims. Assurance cases don't automatically check whether the evidence weighting is biased.
   - **Boundary test:** Assurance-case asks "Is this claim supported by traceable evidence?" Debiasing asks "Did I weight that evidence fairly, or did availability bias inflate recent incidents?"

7. *Debiasing vs. reflective equilibrium:* Reflective equilibrium adjusts beliefs and principles for coherence across your belief system. Debiasing checks individual judgments for cognitive errors without requiring full belief-system coherence.
   - **Boundary test:** Reflective equilibrium asks "Do my intuitions and principles fit together?" Debiasing asks "Did I anchor this specific estimate on irrelevant information?"

## Best for

- **High-stakes one-shot decisions** — where you can't rely on averaging over many trials (e.g., acquisition, major pivot, key hire)
- **Forecasting & estimation** — where base-rate neglect and overconfidence dominate errors (project timelines, market sizing)
- **Incident postmortems** — where hindsight bias distorts root-cause analysis ("we should have known")
- **Investment / resource allocation** — where confirmation bias anchors on early signals (sunk cost, pet projects)
- **Leadership reviews** — where authority gradients suppress disconfirmation (CEO's strategy goes unchallenged)
- **Hiring decisions** — where first impressions anchor subsequent evaluation (halo effect from interview)
- **Strategic planning** — where optimism bias and planning fallacy inflate projections (5-year plans)
- **Code review** — where availability bias favors recently seen patterns (over-applying last bug's fix)
- **Hypothesis selection** — after abduction generates candidates, before committing to investigation (story bias)
- **Policy debate** — where motivated reasoning and groupthink distort cost-benefit analysis

## Common failure mode

**Ritualized checklists that don't change conclusions.** Going through the motions—writing "base rate: N/A" or "alternatives: none convincing"—without genuine consideration. The checklist becomes a box-ticking exercise that provides false assurance.

### Detection signals

- Checklist items are copy-pasted from previous decisions
- Alternative hypotheses are strawmen dismissed in one sentence
- Premortem lists only external/uncontrollable causes ("market conditions," "bad luck")
- No decision was ever reversed or modified by the checklist
- Time spent on debiasing < 5 minutes for high-stakes decisions
- Disconfirmation tests are hypothetical only (never actually searched for)
- The same person always plays devil's advocate (role becomes theatrical)
- Base rates are "estimated" without consulting actual data

### Mitigations

1. **Require at least one judgment change per quarter** — Track whether debiasing ever shifted a decision. If never, the process is theatrical. Set a quota: if 0 reversals in Q, the process needs repair.
   - *Test:* When did debiasing last change a decision?

2. **Rotate devil's advocate** — Assign someone to argue for the second-best alternative; rotate the role so it's not always the same skeptic. The advocate must present the strongest case they can, not a strawman.
   - *Test:* Could the advocate's case convince an outsider?

3. **Blind elicitation** — Collect individual base-rate estimates before group discussion to prevent anchoring on the first speaker or the senior person. Reveal estimates simultaneously.
   - *Test:* Did everyone commit to their estimate before seeing others'?

4. **Time-box but enforce** — Debiasing should take 10-15 min, not 2 hours—but those 10 min must happen *before* commitment, not after. Schedule debiasing as a required meeting segment, not an optional add-on.
   - *Test:* Is debiasing on the calendar before the decision meeting?

5. **Require evidence of disconfirmation search** — Specifying disconfirming observations isn't enough; you must actually look for them. Document what you searched and what you found.
   - *Test:* Can you show the search results?

6. **Audit the audits** — Periodically review past debiasing artifacts: Were base rates accurate? Did premortems predict actual failures? Did disconfirmation tests catch errors? Learn from the gaps.
   - *Test:* What's your debiasing hit rate?

## Anti-patterns to avoid

| Anti-pattern | What it looks like | Fix |
|--------------|-------------------|-----|
| **Box-ticking** | Checklist completed in <2 min for complex decision | Minimum time threshold; require written rationale |
| **Strawman alternatives** | "Alternatives: (b) do nothing, (c) do something stupid" | Alternatives must be positions a smart person could hold |
| **External-only premortem** | Failure causes are all outside your control | Require >=1 internal/controllable cause per premortem |
| **Hypothetical disconfirmation** | "I would change my mind if X" but never search for X | Require evidence of actual search |
| **Seniority anchoring** | Senior person speaks first, others anchor on their view | Blind elicitation; junior speaks first |
| **Debiasing theater** | Process exists for appearance, not effect | Track decision reversals; require periodic audits |
| **Confirmation by exhaustion** | "We looked everywhere and found nothing against it" | Specify what disconfirmation *would* look like before searching |
| **One-and-done** | Debiasing applied once at decision point, never revisited | Schedule re-evaluation for long-running decisions |

## When debiasing backfires

Debiasing is not free. Costs to watch for:

1. **Analysis paralysis** — Endless alternative-generation prevents timely decisions. *Fix:* Time-box strictly; satisfice on meta-questions.

2. **False humility** — Excessive uncertainty when action is needed. *Fix:* Debiasing produces better judgments, not perfect ones; decide anyway.

3. **Process overhead** — Debiasing overhead exceeds decision stakes. *Fix:* Scale effort to stakes; skip formal debiasing for low-stakes calls.

4. **Skepticism spiral** — Doubting everything, including valid evidence. *Fix:* Debiasing targets *predictable* errors, not all beliefs.

**Rule of thumb:** Apply full debiasing protocol to top 20% of decisions by stakes/irreversibility. For routine decisions, use abbreviated checklist: base rate + one alternative + one disconfirmation test.

## Protocol selection flowchart

```
Is this decision reversible within 1 week at low cost?
  │
  ├─ YES → Abbreviated protocol (3 min)
  │         • Base rate from 1 reference class
  │         • 1 alternative hypothesis
  │         • 1 disconfirmation test
  │         • Skip premortem, skip bias audit
  │
  └─ NO → Is the decision ≥10% of budget, headcount, or strategic priority?
           │
           ├─ YES → Full protocol (15 min) + External review
           │         • All 7 steps
           │         • Rotate devil's advocate
           │         • Require written artifacts
           │         • Schedule 30-day re-evaluation
           │
           └─ NO → Standard protocol (10 min)
                   • All 7 steps
                   • Can self-administer
                   • Written checklist, not full artifacts
```

## Organizational prerequisites

Debiasing fails in cultures that punish dissent or reward false certainty. Before expecting checklists to work, verify:

| Prerequisite | Test | Failure signal |
|--------------|------|----------------|
| **Psychological safety** | Can a junior person publicly disagree with a senior's estimate? | Last 3 disagreements were penalized or ignored |
| **Outcome vs. process evaluation** | Are people evaluated on reasoning quality, not just results? | Good luck rewarded; bad decisions with good outcomes praised |
| **Falsifiability norm** | Do proposals include "I would change my mind if X"? | No proposal in last quarter included falsification criteria |
| **Uncertainty tolerance** | Can people say "I don't know" without losing credibility? | Hedged statements are criticized as "lacking conviction" |
| **Update culture** | Is changing your mind based on evidence celebrated or punished? | Changing positions is labeled "flip-flopping" |

If ≥2 prerequisites fail, fix the culture before expecting checklists to work. Debiasing is a process; it requires an environment that rewards accurate beliefs over confident-sounding beliefs.

## Related modes

- [Heuristic reasoning](53-heuristic.md) — the System 1 shortcuts debiasing corrects
- [Calibration and epistemic humility](76-calibration-epistemic-humility.md) — long-run accuracy tracking that validates debiasing effectiveness
- [Adversarial / red-team reasoning](79-adversarial-red-team.md) — structured external criticism (vs. debiasing's internal audit)
- [Meta-reasoning](75-meta-reasoning.md) — choosing reasoning modes (debiasing audits their outputs)
- [Reference-class forecasting](18-reference-class-outside-view.md) — base-rate anchoring technique used in step 1
- [Abductive reasoning](13-abductive.md) — hypothesis generation that debiasing stress-tests for story bias
- [Bayesian probabilistic reasoning](11-bayesian-probabilistic.md) — normative standard that debiasing helps approximate
- [Decision-theoretic reasoning](45-decision-theoretic.md) — decisions that benefit from pre-commitment debiasing
- [Satisficing](51-satisficing.md) — "good enough" reasoning that applies to debiasing effort itself
- [Assurance-case reasoning](36-assurance-case.md) — evidence chains that benefit from bias audit on evidence weighting
- [Reflective equilibrium](77-reflective-equilibrium.md) — belief-system coherence (vs. debiasing's point-judgment audit)
