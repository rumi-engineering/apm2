# Bayesian Probabilistic Reasoning (Credences + Updating)

**Category:** Ampliative Reasoning

## What it is

Represent degrees of belief as probabilities and update them systematically with evidence using Bayes' rule:

```
P(H|E) = P(E|H) × P(H) / P(E)
```

In plain terms: **Posterior = (Likelihood × Prior) / Evidence**

The core move: "Given what I believed before (prior) and how well the hypothesis predicts the evidence (likelihood), what should I believe now (posterior)?"

Bayesian reasoning is the *normative standard* for belief updating under uncertainty. It provides a principled way to combine prior knowledge with new data, handle uncertain evidence, and maintain coherent beliefs. Unlike frequentist methods, Bayesian reasoning directly answers "how confident should I be in this hypothesis?" rather than "what would happen across many repetitions?"

## What it outputs

| Artifact | Description | Produced by step |
|----------|-------------|------------------|
| **Prior distribution** | Explicit statement of beliefs before seeing new evidence | Step 1 |
| **Likelihood model** | P(E|H) for each hypothesis—how well does H predict the observed evidence? | Step 2 |
| **Posterior distribution** | Updated beliefs after incorporating evidence | Step 3 |
| **Credible intervals** | Ranges containing specified probability mass (e.g., 90% CI) | Step 4 |
| **Sensitivity analysis** | How posterior changes if prior or likelihood changes | Step 5 |
| **Decision-relevant summary** | Point estimates or probability thresholds for action | Step 6 |

## Procedure (decision steps)

1. **Specify the prior** — What did you believe before seeing this evidence? Be explicit:
   - Where does the prior come from? (base rates, expert judgment, previous posteriors)
   - What range of values or hypotheses are plausible?
   - *Test:* Would a reasonable person accept this prior as a starting point, even if they'd adjust it?
   - *Output:* Written prior with source and rationale.
   - *Warning:* "I have no prior" is almost never true—you're implicitly assuming something. Make it explicit.

2. **Construct the likelihood model** — For each hypothesis under consideration, ask: "If H were true, how likely would we see evidence E?"
   - P(E|H) is the likelihood—not the probability of H, but the probability of the evidence *given* H
   - Compare: P(E|H1) vs P(E|H2) vs P(E|H3)
   - *Test:* If you observed this evidence and H were true, would you be surprised?
   - *Output:* Likelihood values or ratios for competing hypotheses.

3. **Apply Bayes' rule** — Compute the posterior:
   - P(H|E) ∝ P(E|H) × P(H)
   - For discrete hypotheses: normalize so probabilities sum to 1
   - For continuous parameters: integrate over the parameter space
   - *Sanity check:* Does the posterior make sense? Higher likelihood hypotheses should get more posterior mass than prior mass.
   - *Output:* Posterior distribution or point estimate.

4. **Construct credible intervals** — Report uncertainty, not just point estimates:
   - 90% credible interval: "There's a 90% probability the true value is in this range"
   - This is a direct probability statement about the hypothesis, unlike frequentist confidence intervals
   - *Output:* Credible intervals at relevant levels (50%, 90%, 95%).

5. **Test sensitivity** — How robust is the posterior to assumptions?
   - Vary the prior: What if prior was twice as high? Half as high?
   - Vary the likelihood model: What if evidence is weaker than assumed?
   - *Flag:* If posterior is highly sensitive to prior, you need more data before acting.
   - *Output:* Sensitivity analysis showing which inputs drive the conclusion.

6. **Extract decision-relevant summaries** — Translate posterior into actionable terms:
   - "P(success) = 0.72" for go/no-go decisions
   - "Expected value = $X" for resource allocation
   - "P(H1) > P(H2) by factor of 5" for hypothesis comparison
   - *Output:* Summary tailored to the decision at hand.

7. **Update iteratively** — As new evidence arrives, today's posterior becomes tomorrow's prior. Track the chain of updates.
   - *Output:* Updated beliefs with audit trail.

## Quick checklist

- [ ] Prior explicitly stated with source (not implicit or "uninformative")
- [ ] Likelihood model specified: P(E|H) for each hypothesis
- [ ] Posterior computed or estimated
- [ ] Credible intervals reported (not just point estimates)
- [ ] Sensitivity analysis performed on prior and likelihood
- [ ] Comparison to base rates checked (if available)
- [ ] Decision-relevant summary extracted
- [ ] Confidence level appropriate to evidence strength

## Micro-example

**Situation:** A new test claims to detect a rare disease (1% prevalence). Test sensitivity is 95% (true positive rate), specificity is 90% (true negative rate). A patient tests positive. What's the probability they have the disease?

| Step | Action | Output |
|------|--------|--------|
| 1. Prior | P(disease) = 0.01 (base rate) | Prior = 1% |
| 2. Likelihood | P(positive \| disease) = 0.95; P(positive \| no disease) = 0.10 | Likelihoods specified |
| 3. Bayes | P(disease \| positive) = (0.95 × 0.01) / [(0.95 × 0.01) + (0.10 × 0.99)] = 0.0095 / 0.1085 ≈ 0.088 | Posterior ≈ 8.8% |
| 4. Interpret | Despite positive test, only 8.8% chance of disease (base rate dominates) | Counterintuitive result |
| 5. Sensitivity | If prevalence were 10%, posterior would be ≈51%. Prior matters hugely here. | Sensitivity to prior |
| 6. Decision | Recommend confirmatory test before treatment; single positive test is insufficient | Action |

**Key insight:** The low base rate (1%) means most positive tests are false positives. Without Bayesian reasoning, one might assume "95% accurate test + positive result = 95% chance of disease."

## How it differs

| Mode | Bayesian reasoning differs because... |
|------|---------------------------------------|
| [Statistical reasoning (frequentist)](10-statistical-frequentist.md) | Frequentist methods report what would happen over repeated sampling; Bayesian methods report probability of hypotheses given data. Frequentist: "If H0 were true, 5% of experiments would see this result." Bayesian: "Given this result, P(H0) = X." |
| [Likelihood-based reasoning](12-likelihood-based.md) | Likelihood reasoning compares P(E\|H) across hypotheses but doesn't commit to priors. Bayesian reasoning adds priors to get full posteriors. Likelihood answers "which hypothesis better predicts the data?"; Bayesian answers "which hypothesis should I believe?" |
| [Reference-class forecasting](18-reference-class-outside-view.md) | Reference-class reasoning provides base rates (priors) for Bayesian analysis. It's an input, not a competitor. Reference class = where to get P(H); Bayes = how to update P(H) with evidence. |
| [Decision-theoretic reasoning](45-decision-theoretic.md) | Decision theory uses posterior probabilities to choose actions. Bayesian reasoning produces the posteriors; decision theory consumes them. Bayesian answers "what should I believe?"; decision theory answers "what should I do?" |
| [Inductive reasoning](09-inductive.md) | Induction generalizes patterns informally. Bayesian reasoning formalizes how to update beliefs with evidence. Induction is the intuitive version; Bayes is the rigorous version. |

**Common confusions:**

1. *Bayesian vs. having opinions:* Everyone has beliefs; Bayesian reasoning requires making them explicit and updating them coherently. The discipline is in the *process*, not just the *having* of beliefs.

2. *Prior = bias:* Priors are not illegitimate biases to eliminate. They encode genuine prior knowledge. The goal is to make them explicit and update them rationally, not to have no priors. "Objective" analyses have implicit priors; Bayesian analyses have explicit ones.

3. *Bayesian = subjective = arbitrary:* Priors can come from data (base rates, meta-analyses), not just gut feelings. And even subjective priors are constrained by coherence requirements and updated by evidence. Different reasonable priors often converge with enough data.

4. *P(H|E) vs P(E|H):* The most common error. Likelihood P(E|H) is not posterior P(H|E). "If the defendant were guilty, we'd see this evidence" ≠ "Given this evidence, the defendant is guilty." The base rate matters.

## Best for

- **Medical diagnosis** — Updating disease probability with test results
- **Forecasting** — Combining base rates with specific case information
- **A/B testing interpretation** — Posterior probability that treatment works
- **Fraud detection** — Updating suspicion with behavioral signals
- **Reliability estimation** — Updating failure rate estimates with operational data
- **Legal reasoning** — Evaluating evidence strength (though courts often misapply)
- **Scientific inference** — Updating theory confidence with experimental results
- **Risk assessment** — Combining historical rates with current indicators
- **Sequential learning** — Continuously updating beliefs as data arrives

## Common failure mode

**Prior neglect / base rate blindness:** Ignoring or underweighting the prior probability, especially when evidence is vivid or emotionally salient. The classic error: confusing P(E|H) with P(H|E).

### Detection signals

- High confidence despite rare base rate ("the test was positive, so they probably have it")
- No explicit prior stated before analysis
- Prior described as "uninformative" without justification
- Posterior tracks likelihood exactly (prior had no effect)
- Dramatic belief update from a single piece of evidence
- Inability to state what prior would change the conclusion

### Mitigations

1. **State prior first** — Write down P(H) before looking at evidence. This prevents likelihood from anchoring your prior. If you can't state a prior, you're not ready for Bayesian analysis.
   - *Test:* Did you commit to a prior before computing the posterior?

2. **Base rate check** — For any hypothesis, ask: "What's the reference-class frequency?" Use [reference-class forecasting](18-reference-class-outside-view.md) to anchor priors in data, not intuition.
   - *Test:* Can you cite the base rate source?

3. **Prior sensitivity analysis** — Compute posteriors under multiple priors (optimistic, pessimistic, neutral). If conclusions change dramatically, get more data before acting.
   - *Test:* What prior would flip your conclusion? Is that prior unreasonable?

4. **Likelihood ratio sanity check** — Before computing, ask: "Is the evidence really that much more likely under H1 than H2?" Overestimating likelihood ratios inflates posteriors.
   - *Test:* Would you bet at these likelihood ratios?

5. **Explicit P(E|H) vs P(H|E) distinction** — When presenting results, always separate: "The evidence is consistent with H" (likelihood) from "H is probably true" (posterior). Use different sentences.
   - *Test:* Have you confused "evidence supports H" with "H is true"?

6. **Update incrementally** — Large jumps in posterior from single observations should trigger skepticism. Either the evidence is extraordinary (rare) or you're overweighting.
   - *Test:* Is this update proportional to the evidence strength?

## Anti-patterns to avoid

| Anti-pattern | What it looks like | Fix |
|--------------|-------------------|-----|
| **Implicit prior** | "I'm just looking at the data objectively" | State prior explicitly; "uninformative" is still a prior |
| **Base rate neglect** | Positive test → probably positive | Always multiply by P(H), not just P(E\|H) |
| **Likelihood as posterior** | "The data strongly support H, so P(H) is high" | P(E\|H) ≠ P(H\|E); compute properly |
| **Confidence from vivid evidence** | One dramatic case updates belief massively | Weight by likelihood ratio, not emotional salience |
| **Ignoring uncertainty** | Reporting point estimates without intervals | Always report credible intervals |
| **Prior hacking** | Adjusting prior after seeing data to get desired posterior | Commit to prior before analysis |
| **Overconfident priors** | P(H) = 0.95 based on "intuition" | Calibrate priors against base rates; use sensitivity analysis |

## When to prefer alternatives

| Situation | Preferred alternative | Why |
|-----------|----------------------|-----|
| No credible prior available | [Likelihood-based reasoning](12-likelihood-based.md) | Compare hypotheses without committing to priors |
| Need frequentist guarantees | [Statistical reasoning](10-statistical-frequentist.md) | Error rate control across experiments |
| Hypothesis generation (not evaluation) | [Abductive reasoning](13-abductive.md) | Bayes scores hypotheses; abduction generates them |
| Deep uncertainty about model | [Imprecise probability](21-imprecise-probability.md) | Represent uncertainty about the uncertainty |
| Limited data, need action | [Reference-class forecasting](18-reference-class-outside-view.md) | Base rates may be more robust than model-based posteriors |

## Related modes

- [Statistical reasoning (frequentist)](10-statistical-frequentist.md) — alternative framework with different interpretation
- [Likelihood-based reasoning](12-likelihood-based.md) — comparative evidence without full priors
- [Reference-class forecasting](18-reference-class-outside-view.md) — base rates as prior source
- [Decision-theoretic reasoning](45-decision-theoretic.md) — uses posteriors to make decisions
- [Probabilistic logic](20-probabilistic-logic.md) — Bayesian + logical structure for complex domains
- [Calibration and epistemic humility](76-calibration-epistemic-humility.md) — tracking accuracy of Bayesian predictions
- [Debiasing / epistemic hygiene](80-debiasing-epistemic-hygiene.md) — corrects for base rate neglect and overconfidence
- [Inductive reasoning](09-inductive.md) — informal predecessor to Bayesian updating
