# Document 4: Security and Adversarial Robustness in Agent Tool-Call Loops

## Chapter 1. Threat Models for Bounded-Cognition Actors

Agent-native systems must assume:

* Adversarial inputs (prompt injection, malicious diffs, poisoned logs)
* Compromised or misbehaving agents
* Tool outputs that can be manipulated (network, filesystem, forge metadata)

Because an LLM’s reasoning is mediated by a bounded context, adversaries target the representation: they attempt to force omission of relevant constraints or inclusion of misleading constraints.

Security engineering becomes representation engineering: ensure the context always contains the minimal set of invariants and that untrusted content is clearly labeled and isolated.

## Chapter 2. Capability Security as a Formal Discipline

Capability-based security is grounded in the idea that the set of actions available is the set of capabilities held. The security goal is to ensure:

* Capabilities are unforgeable
* Capabilities are narrowly scoped
* Capability usage is auditable and attributable

For agents, this is particularly important because the policy (p_θ(a | x)) can propose dangerous actions. If the system never grants the capability, the action cannot be executed. This is the preferred failure mode: safe impossibility rather than post-hoc detection.

## Chapter 3. Sandboxing and Information Flow Control

Sandboxing is a means of constraining the environment’s transition function (T) so that certain state transitions are impossible. Information flow control constrains what observations are available to the agent.

These mechanisms reduce both:

* **Actuation risk** (agent cannot do harm)
* **Confusion risk** (agent cannot observe secrets or sensitive channels, reducing leak probability)

A critical concept is the “ambient authority” problem: any implicit privilege that an agent can exploit due to environment configuration. Eliminate ambient authority by externalizing privileges into explicit, time-bounded capabilities.

## Chapter 4. Verification and Attestation as Security Primitives

Verification is a correctness primitive and a security primitive. If the system can attest that an output artifact was produced under a specific toolchain, with specific inputs, under specific policy versions, then downstream holons can accept the artifact without re-trusting upstream cognition.

Attestation reduces the trust required in intermediate agents. This is essential for scaling holarchies: trust must be transitive through evidence, not through personalities or narratives.

## Chapter 5. Governance as an Adaptive Control System

Governance mechanisms (gates, policies, waivers) can be modeled as a control loop that manages risk while preserving throughput:

* Sensors: findings, defect rates, incident telemetry
* Controller: policy adjustment, gate thresholds
* Plant: development workflow and tool execution
* Feedback: measured outcomes

The stability objective is to avoid oscillation:

* Overly strict policies cause throughput collapse and bypass attempts.
* Overly lax policies cause defect and risk accumulation.

A mature system uses staged enforcement and measurable criteria to ratchet posture without halting work. The mathematical principle is to tune “gain” (strictness) based on observability and controllability: enforce only what can be verified reliably and cheaply; expand enforcement as verification becomes more automated.
