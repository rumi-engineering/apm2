# Debiasing / Epistemic Hygiene Reasoning

**Category:** Meta-Level and Reflective Modes

## What it is

A meta-discipline applying specific checks *before* committing to conclusions: base-rate anchoring, alternative-hypothesis generation, premortem analysis, and active disconfirmation search. Not a new inference pattern—a constraint layer that intercepts and stress-tests outputs from other reasoning modes.

The core move: "Before I act on this conclusion, what predictable errors might I be making?" Debiasing treats your own cognition as a known-flawed instrument and applies systematic corrections.

Unlike reasoning modes that produce conclusions, debiasing *audits* conclusions. It's the quality-control gate between thinking and deciding.

## What it outputs

| Artifact | Description | Produced by step |
|----------|-------------|------------------|
| **Base-rate anchor** | Reference-class frequency before inside-view adjustment | Step 1 |
| **Alternative-hypothesis list** | ≥3 competing explanations with relative plausibility | Step 2 |
| **Premortem report** | "Assume we failed—why?" with top 3 causes | Step 3 |
| **Disconfirmation tests** | Specific observations that would falsify the favored view | Step 4 |
| **Cognitive-load flag** | Whether judgment was made under impaired conditions | Step 5 |
| **Bias audit log** | List of checked biases with pass/fail + rationale | Step 6 |
| **Residual uncertainty log** | What remains uncertain and why | Step 7 |

## Procedure (decision steps)

1. **Anchor on base rate** — Before analyzing specifics, ask: "What's the reference-class frequency for outcomes like this?" Write it down.
   - *Technique:* Identify the broadest reasonable reference class (e.g., "software projects" before "our team's projects"), then narrow with justification.
   - *Test:* Would a stranger with only statistical knowledge predict close to your base rate?
   - *Output:* "Base rate for [reference class]: X%"

2. **Generate alternatives** — List ≥3 hypotheses that could explain the same evidence. Assign rough plausibility to each.
   - *Technique:* Include at least one "mundane" alternative (coincidence, measurement error) and one "uncomfortable" alternative (systemic cause you'd rather not consider).
   - *Test:* Is there an alternative you'd prefer not to be true? You should have listed it.
   - *Output:* Numbered list with plausibility estimates.

3. **Run premortem** — Assume the decision failed. Brainstorm top 3 reasons it could fail. Identify which are addressable now.
   - *Technique:* Frame as "It's 6 months later and this was a disaster. What happened?"
   - *Test:* Are any failure modes within your control but not yet addressed?
   - *Output:* "Premortem causes: (1) ..., (2) ..., (3) ..."

4. **Seek disconfirmation** — For your favored conclusion, specify 2-3 observations that would change your mind. Actively look for them.
   - *Technique:* Ask "What would my harshest critic point to as evidence against this?"
   - *Test:* Did you actually look, or just list disconfirmation in theory?
   - *Output:* "Would revise if: (a) ..., (b) ..."

5. **Check cognitive load** — If rushed, tired, or emotionally invested, flag the judgment as provisional and schedule re-evaluation.
   - *Signals:* Time pressure, sleep deprivation, personal stake, recent emotional event, pressure from authority.
   - *Output:* "Cognitive-load flag: [clear | impaired: reason]"

6. **Audit for anchoring/availability/confirmation** — Explicitly ask: "Am I weighting first info too heavily (anchoring)? Recent/vivid info (availability)? Info that confirms my prior (confirmation)?"
   - *Anchoring test:* What was the first number/estimate you heard? Is your final estimate suspiciously close?
   - *Availability test:* Can you recall a vivid counterexample to your conclusion? If not, why not?
   - *Confirmation test:* What evidence would the opposition cite? Did you engage with it?
   - *Output:* "Bias check: anchoring [pass/fail], availability [pass/fail], confirmation [pass/fail]"

7. **Document residual uncertainty** — Record what you're still uncertain about and why.
   - *Output:* "Remaining uncertainty: ..."

## Quick checklist (pre-decision gate)

- [ ] Base rate written before inside-view analysis
- [ ] ≥3 alternative hypotheses listed (including one you'd prefer not be true)
- [ ] Premortem completed (top 3 failure causes, at least one addressable)
- [ ] ≥2 disconfirming observations specified AND actively sought
- [ ] Cognitive-load flag set if impaired conditions
- [ ] Anchoring / availability / confirmation bias explicitly checked
- [ ] Residual uncertainty documented

## Micro-example

**Situation:** Team proposes a new caching layer to fix performance.

| Step | Action | Output |
|------|--------|--------|
| 1. Base rate | "What % of caching projects actually solve the performance problem?" → Historical data: ~40% hit root cause. | Base rate: 40% |
| 2. Alternatives | (a) Caching helps, (b) N+1 query is real bottleneck, (c) GC pauses dominate, (d) Problem is network latency not compute | 4 hypotheses |
| 3. Premortem | "Cache deployed, latency unchanged—why?" → Didn't profile first; cache hit rate low; wrong layer cached. | 3 failure modes |
| 4. Disconfirmation | Profile shows cache-hit rate <50%, or latency unchanged after deployment → abandon caching hypothesis. | 2 disconfirming observations |
| 5. Cognitive load | Team is under deadline pressure → flag as provisional. | Flag: impaired (deadline) |
| 6. Bias audit | Anchoring: first idea was caching (from similar past fix) → check. Confirmation: only looked at cache-supporting logs → fail. | Anchoring: watch, Confirmation: fail |
| 7. Decision | Profile first to test alternatives, then re-evaluate. Revisit after deadline pressure clears. | Action + conditions |

## How it differs

| Mode | Debiasing differs because... |
|------|------------------------------|
| [Meta-reasoning](75-meta-reasoning.md) | Meta-reasoning selects *which* mode to use; debiasing audits *any* mode's output for predictable errors. Meta-reasoning is upstream (mode selection); debiasing is downstream (output validation). |
| [Calibration](76-calibration-epistemic-humility.md) | Calibration measures accuracy over many judgments retrospectively; debiasing applies corrective checks to a single judgment prospectively. Calibration tracks whether you're well-calibrated over time; debiasing intervenes on this specific decision. |
| [Red-teaming](79-adversarial-red-team.md) | Red-teaming assumes an external adversary attacking your system; debiasing assumes your own cognition is the adversary. Red-teaming asks "how would an attacker exploit this?"; debiasing asks "how is my thinking exploiting itself?" |
| [Heuristic reasoning](53-heuristic.md) | Heuristics are the System 1 shortcuts debiasing corrects—fast, automatic, often useful but systematically wrong in predictable ways. Debiasing is the System 2 audit layer. |
| [Abductive reasoning](13-abductive.md) | Abduction generates hypotheses; debiasing forces you to generate *multiple* hypotheses and seek disconfirmation for your favorite. Abduction can fall into story bias; debiasing counters it. |
| [Reflective equilibrium](77-reflective-equilibrium.md) | Reflective equilibrium seeks coherence among beliefs and principles; debiasing seeks accuracy by correcting known cognitive errors. Both are meta-level, but different goals: coherence vs. accuracy. |

**Common confusions:**

1. *Debiasing vs. calibration:* Calibration tracks long-run accuracy ("Am I right 80% of the time when I say 80%?"); debiasing intervenes on a single decision ("Am I making a predictable error right now?"). You can be well-calibrated on average but still need debiasing on any specific high-stakes call.

2. *Debiasing vs. red-teaming:* Red-teaming asks "how would an attacker break this?" Debiasing asks "how is my own reasoning broken?" Both are adversarial but the threat model differs. Use red-teaming for security/robustness; use debiasing for all decisions.

3. *Debiasing vs. skepticism:* Skepticism suspends judgment indefinitely; debiasing applies specific corrections and then commits. The goal isn't doubt for doubt's sake—it's structured doubt that terminates in better decisions.

## Best for

- **High-stakes one-shot decisions** — where you can't rely on averaging over many trials
- **Forecasting and estimation** — where base-rate neglect and overconfidence dominate errors
- **Incident postmortems** — where hindsight bias distorts root-cause analysis
- **Investment / resource allocation** — where confirmation bias anchors on early signals
- **Leadership reviews** — where authority gradients suppress disconfirmation
- **Hiring and promotion** — where first impressions and halo effects dominate
- **Strategic planning** — where motivated reasoning distorts threat assessment
- **Medical diagnosis** — where availability bias overweights recent cases

## Common failure mode

**Ritualized checklists that don't change conclusions.** Going through the motions—writing "base rate: N/A" or "alternatives: none convincing"—without genuine consideration.

### Detection signals

- Checklist items are copy-pasted from previous decisions
- Alternative hypotheses are strawmen dismissed in one sentence
- Premortem lists only external/uncontrollable causes
- No decision was ever reversed or modified by the checklist
- Disconfirmation step says "looked and found nothing" without specifying what was looked for
- Same person always fills out the checklist (no independent perspectives)
- Checklist completed after decision already made (post-hoc rationalization)

### Mitigations

1. **Require at least one judgment change per quarter** — Track whether debiasing ever shifted a decision. If never, the process is theatrical.
   - *Test:* In the last 3 months, what decision did debiasing change?

2. **Rotate devil's advocate** — Assign someone to argue for the second-best alternative; rotate the role so it's not always the same skeptic.
   - *Test:* Who argued against the winning hypothesis this time?

3. **Blind elicitation** — Collect individual base-rate estimates before group discussion to prevent anchoring on the first speaker.
   - *Test:* Did everyone write their estimate before discussion?

4. **Time-box but enforce** — Debiasing should take 10-15 min, not 2 hours—but those 10 min must happen before commitment, not after.
   - *Test:* Was the checklist completed before or after the decision?

5. **Require specificity** — Reject vague entries. "Alternatives: none convincing" is not acceptable; must list 3 specific alternatives with specific reasons for lower plausibility.
   - *Test:* Could someone reconstruct your reasoning from the checklist?

6. **Track disconfirmation hit rate** — If you never find disconfirming evidence, either you're very good or you're not really looking. Check by random audit.
   - *Test:* In the last 10 decisions, how many times did disconfirmation search find something?

7. **Separate checklist-filler from decision-maker** — Have one person complete debiasing, another make the decision. The decision-maker must respond to each flag.
   - *Test:* Did the decision-maker explicitly address each debiasing finding?

## Anti-patterns to avoid

| Anti-pattern | What it looks like | Fix |
|--------------|-------------------|-----|
| **Checkbox theater** | Checklist completed in 2 minutes with no substance | Set minimum time (10 min) and require specific entries |
| **Strawman alternatives** | "Alternative: maybe it's aliens" (easily dismissed) | Require at least one alternative you'd prefer not be true |
| **Hindsight premortem** | Premortem written after outcome known | Time-stamp and lock before decision |
| **Motivated disconfirmation** | "Looked for disconfirmation, found none" with no specifics | Specify exactly what you looked for and where |
| **Authority override** | Senior person dismisses checklist findings without engagement | Require written response to each flag |
| **One-time event** | Debiasing applied once, never tracked | Aggregate and review quarterly |
| **Post-hoc rationalization** | Checklist filled out after decision to justify it | Hard rule: checklist before decision, or decision reverts |

## Bias quick-reference

| Bias | What it is | Debiasing countermeasure |
|------|-----------|-------------------------|
| **Anchoring** | Over-relying on first information received | Elicit estimates before sharing; adjust deliberately from base rate |
| **Availability** | Overweighting vivid/recent examples | Ask "What's the base rate?" before recalling examples |
| **Confirmation** | Seeking evidence that supports existing beliefs | Force disconfirmation search; assign devil's advocate |
| **Hindsight** | "I knew it all along" after learning outcome | Pre-commit to predictions; lock before outcome |
| **Overconfidence** | Certainty exceeds accuracy | Track calibration; widen confidence intervals |
| **Planning fallacy** | Underestimating time/cost/risk | Use reference-class forecasting; add buffer |
| **Sunk cost** | Continuing due to past investment | Ask "If starting fresh, would I choose this?" |
| **Fundamental attribution** | Blaming individuals over systems | Ask "What system produced this outcome?" |
| **Halo effect** | One positive trait colors all judgments | Evaluate dimensions independently |
| **Groupthink** | Conformity suppresses dissent | Anonymous input; rotate devil's advocate |

## Related modes

- [Heuristic reasoning](53-heuristic.md) — the System 1 shortcuts debiasing corrects
- [Calibration and epistemic humility](76-calibration-epistemic-humility.md) — long-run accuracy tracking that validates debiasing effectiveness
- [Adversarial / red-team reasoning](79-adversarial-red-team.md) — structured external criticism (vs. debiasing's internal audit)
- [Meta-reasoning](75-meta-reasoning.md) — choosing reasoning modes (debiasing audits their outputs)
- [Reference-class forecasting](18-reference-class-outside-view.md) — base-rate anchoring technique used in step 1
- [Abductive reasoning](13-abductive.md) — hypothesis generation that debiasing forces to be plural
- [Reflective equilibrium](77-reflective-equilibrium.md) — seeking coherence (vs. debiasing's accuracy focus)
- [Decision-theoretic reasoning](45-decision-theoretic.md) — optimal choice under uncertainty (debiasing audits its inputs)
