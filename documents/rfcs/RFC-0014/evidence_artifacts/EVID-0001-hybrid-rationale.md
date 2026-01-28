# EVID-0001: OPT-HYBRID Design Rationale

## Status
PENDING - To be completed during implementation

## Purpose
Document the analysis and decision rationale for selecting OPT-HYBRID as the
consensus approach for APM2's distributed truth substrate.

## Analysis Summary

### Options Evaluated

| Option | Description | Pros | Cons |
|--------|-------------|------|------|
| OPT-SEQ | Single-writer sequencer | Simple, low latency | SPOF, no fault tolerance |
| OPT-RAFT | Raft for all events | Strong ordering | CFT only; not BFT |
| OPT-HYBRID | BFT control + CRDT data | Best of both worlds | More complex implementation |
| OPT-FED | Federated signed chains | High availability | Weak ordering, complex merge |

### Decision Criteria

1. **LAW-03 Alignment**: Monotone ledger for control plane
2. **LAW-10 Alignment**: Anti-entropy for data plane
3. **PHY-04 Alignment**: Reserve consensus for small control planes
4. **Fault Tolerance**: Must tolerate node failures
5. **Performance**: Must not degrade user experience
6. **Operational Complexity**: Must be manageable

### Selected: OPT-HYBRID

OPT-HYBRID was selected because:

1. Control plane events (authority operations) are low-volume and require
   strict total ordering - fit for BFT consensus (HotStuff/PBFT)

2. Data plane events (observations, telemetry) are high-volume and naturally
   commutative - CRDT/anti-entropy is more efficient than consensus

3. The existing LeaseScope namespace model maps naturally to quorum
   partitioning for future sharding

4. Aligns with holonic laws and unified theory principles

## Evidence
- [ ] Benchmark comparison of options (pending)
- [ ] Prototype implementations (pending)
- [ ] Review meeting notes (pending)

## References
- documents/skills/laws-of-holonic-agent-systems/references/unified-theory.md (PHY-04)
- documents/skills/laws-of-holonic-agent-systems/references/law_03.md
- documents/skills/laws-of-holonic-agent-systems/references/law_10.md
