---
name: holonic-principles
description: Reference collection of 99 "Alien Engineering" principles for APM2, covering truth substrate, bounded authority, overload stability, and determinism. Use when designing system invariants, evaluating architectural tradeoffs, or ensuring fail-closed security.
user-invocable: true
argument-hint: "[<principle-number> | <keyword> | empty]"
---

# Holonic Principles

A practical taxonomy of 99 "Alien Engineering" principles stored as a consolidated CAC asset. These principles guide the design and operation of APM2, from Phase-1 recursive improvement to Phase-5 planetary impact.

## Asset References

- **Principle bundle**: `assets/principles.json` - contains all 99 principles and metadata
- **Stable IDs**: `dcp://apm2.agents/holon/principle/{name}@1`

## Invocation

```
/holonic-principles                     # Browse principle selector
/holonic-principles 1                   # Look up principle #1 (Landauer)
/holonic-principles authority           # Search by keyword
```

## Argument Handling

Parse `$ARGUMENTS`:

- **Empty or omitted** → Load `assets/principles.json` and display summary table
- **Number (1-99)** → Extract and return the corresponding principle from the bundle
- **Keyword** → Search principle names/titles within the bundle and return matching entries

## Primary Categories

- **Truth Substrate**: [45, 46, 47, 49, 92, 95]
- **Bounded Authority**: [38, 39, 89, 90, 91, 94]
- **Queueing & Overload Stability**: [9, 25, 26, 27, 28, 29, 53, 54, 55, 56, 57]
- **Determinism & Replay**: [31, 58, 68, 69, 70, 71]

## Quick Reference

The full list of 99 principles is available in `assets/principles.json`.
| # | Principle |
|---|-----------|
| 1 | Landauer’s principle |
| 2 | Roofline model |
| 3 | Arithmetic intensity predicts compute‑bound vs bandwidth‑bound regimes |
| 4 | GEMM tiling/blocking |
| 5 | Communication‑avoiding algorithms |
| 6 | Amdahl + Gustafson |
| 7 | Work–span model |
| 8 | Batching |
| 9 | Tail latency is usually queueing, not kernel speed |
| 10 | Stochastic rounding + mixed precision |
| 11 | Quantization-aware training/inference |
| 12 | Structured sparsity is only real if hardware exploits it |
| 13 | Kernel fusion |
| 14 | IO-aware attention |
| 15 | KV-cache is a physical resource |
| 16 | Speculative decoding |
| 17 | Continuous batching |
| 18 | Parallelism modes are topology optimization |
| 19 | Collectives are topology-sensitive |
| 20 | NUMA locality |
| 21 | Memory tiers |
| 22 | PCIe host↔device transfers are expensive |
| 23 | RDMA/kernel-bypass IO |
| 24 | Network topology shapes bisection bandwidth |
| 25 | Congestion control + AQM |
| 26 | Pacing + jitter control + deadline scheduling |
| 27 | Little’s law |
| 28 | Model predictive control (MPC) |
| 29 | Feedback loops oscillate under delayed/noisy observation |
| 30 | Time synchronization limits tracing and ordering |
| 31 | Record/replay debugging |
| 32 | OS scheduler + cgroups |
| 33 | eBPF |
| 34 | Containers share a kernel |
| 35 | Side channels are unavoidable |
| 36 | Secure boot + measured boot |
| 37 | Remote attestation |
| 38 | Capability-based security |
| 39 | Zero-trust service identity |
| 40 | mTLS + automated rotation |
| 41 | Post-quantum migration |
| 42 | Harvest-now-decrypt-later |
| 43 | Secrets should be short-lived and scoped |
| 44 | Supply-chain provenance |
| 45 | Content-addressed storage |
| 46 | Merkle trees + hash chaining |
| 47 | Event sourcing |
| 48 | Idempotency keys + deduplication |
| 49 | Consensus keeps one truth |
| 50 | Vector clocks + causal consistency |
| 51 | CRDTs |
| 52 | Actor model |
| 53 | Backpressure |
| 54 | Circuit breakers |
| 55 | Bulkheads/compartmentalization |
| 56 | Graceful degradation |
| 57 | Fair scheduling + weighted queuing |
| 58 | Deterministic builds + hermetic environments |
| 59 | Declarative reconciliation loops |
| 60 | Configuration drift is inevitable |
| 61 | Bare metal provisioning |
| 62 | Failure domains define correlated risk |
| 63 | SLOs + error budgets |
| 64 | Burn-rate alerting |
| 65 | Tracing with correlation IDs |
| 66 | Sampling + aggregation |
| 67 | Chaos engineering |
| 68 | TLA+/model checking |
| 69 | Type/effect systems |
| 70 | Refinement types/contracts |
| 71 | Lattice theory + monotone frameworks |
| 72 | Fixed-point semantics |
| 73 | Category theory |
| 74 | Monads/algebraic effects |
| 75 | Convex optimization |
| 76 | Bayesian inference |
| 77 | Stochastic processes |
| 78 | MDPs |
| 79 | POMDPs |
| 80 | Hierarchical RL |
| 81 | Skill discovery + option libraries |
| 82 | SAT/SMT |
| 83 | Distributed constraint optimization + auctions |
| 84 | Game theory |
| 85 | Mechanism design |
| 86 | Causal inference |
| 87 | Robust statistics |
| 88 | Adversarial ML |
| 89 | Prompt injection is confused deputy |
| 90 | Typed tool schemas + structured outputs |
| 91 | Sandboxing with deny-by-default scopes |
| 92 | Evidence-carrying actions |
| 93 | Policy-as-code with signed bundles |
| 94 | Risk classes + autonomy levels |
| 95 | Work graphs as DAGs |
| 96 | Cognitive memory hierarchy |
| 97 | RAG is cache coherence |
| 98 | Differential testing + continuous red-teaming |
| 99 | Sociotechnical incident response |