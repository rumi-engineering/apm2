# TCK-00186: BFT Library Evaluation Spike

**Ticket**: TCK-00186
**RFC**: RFC-0014 (Distributed Consensus and Replication Layer)
**Date**: 2026-01-29
**Status**: COMPLETE

## Executive Summary

This spike evaluates BFT consensus libraries and protocols for APM2's distributed consensus layer. Given APM2's use case (small validator sets of 4-7 nodes, infrequent control-plane state changes), we recommend **HotStuff** with a **custom implementation** that integrates directly with APM2's existing ledger and cryptographic infrastructure.

---

## Section 1: Library Evaluation

### 1.1 Evaluation Criteria

| Criterion | Weight | Description |
|-----------|--------|-------------|
| Rust Native | HIGH | Must be Rust or have high-quality Rust bindings |
| API Compatibility | HIGH | Must integrate with `LedgerBackend` trait |
| Byzantine Fault Tolerance | REQUIRED | Must tolerate f Byzantine faults with 3f+1 nodes |
| Maintenance | MEDIUM | Active development and community |
| Testing Infrastructure | MEDIUM | Deterministic simulation or Jepsen-style testing |
| Licensing | MEDIUM | Apache 2.0 or MIT preferred |

### 1.2 Library Analysis

#### 1.2.1 tendermint-rs

**Repository**: https://github.com/informalsystems/tendermint-rs
**License**: Apache 2.0
**Maturity**: Production (used by Cosmos ecosystem)

| Aspect | Assessment |
|--------|------------|
| Protocol | Tendermint BFT (PBFT variant with proposer rotation) |
| Rust Quality | Excellent - idiomatic async Rust |
| Dependencies | Heavy - full Tendermint stack (ABCI, light client, RPC) |
| Integration Effort | HIGH - designed for blockchain, not embedded consensus |
| Testing | Good - property-based testing, model checking |

**Pros**:
- Battle-tested in production (Cosmos, Celestia)
- Formal verification efforts (Apalache, TLA+)
- Strong safety guarantees with evidence of equivocation

**Cons**:
- Designed for blockchain applications, not embedded consensus
- ABCI interface adds complexity for single-process deployment
- Heavy dependency footprint (~50 transitive dependencies)
- Proposer-based (not pipelined like HotStuff)

**Verdict**: NOT RECOMMENDED - Too heavyweight for APM2's needs. Would require extracting consensus core from full stack.

#### 1.2.2 narwhal/bullshark

**Repository**: https://github.com/MystenLabs/sui (narwhal component)
**License**: Apache 2.0
**Maturity**: Production (Sui blockchain)

| Aspect | Assessment |
|--------|------------|
| Protocol | DAG-based BFT (Narwhal mempool + Bullshark consensus) |
| Rust Quality | Good - async Rust with tokio |
| Dependencies | Heavy - full Sui infrastructure |
| Integration Effort | VERY HIGH - DAG-based, fundamentally different model |
| Testing | Extensive - property testing, network simulation |

**Pros**:
- High throughput design
- Production proven in Sui
- Sophisticated mempool management

**Cons**:
- DAG-based consensus is overkill for APM2's low-frequency control plane
- Cannot be extracted from Sui codebase cleanly
- Different trust model (permissionless vs APM2's permissioned holarchy)

**Verdict**: NOT RECOMMENDED - Architecture mismatch. DAG-based consensus designed for high-throughput blockchain, not low-frequency control plane.

#### 1.2.3 aptos-core (Jolteon/DiemBFT)

**Repository**: https://github.com/aptos-labs/aptos-core
**License**: Apache 2.0
**Maturity**: Production (Aptos blockchain)

| Aspect | Assessment |
|--------|------------|
| Protocol | Jolteon (HotStuff variant with 2-chain rule) |
| Rust Quality | Good - enterprise quality |
| Dependencies | VERY Heavy - full blockchain stack |
| Integration Effort | VERY HIGH - tightly coupled to Aptos runtime |
| Testing | Extensive - formal methods, simulation |

**Pros**:
- HotStuff lineage with optimizations
- Formal verification of core protocol
- Pipelined consensus

**Cons**:
- Monolithic codebase, consensus not extractable
- Requires Aptos-specific types throughout
- Move VM integration assumptions

**Verdict**: NOT RECOMMENDED - Cannot extract consensus layer without massive refactoring.

#### 1.2.4 libhotstuff

**Repository**: https://github.com/hot-stuff/libhotstuff
**License**: MIT
**Maturity**: Research prototype

| Aspect | Assessment |
|--------|------------|
| Protocol | Basic HotStuff |
| Rust Quality | N/A - C++ implementation |
| Dependencies | Moderate - libevent, OpenSSL |
| Integration Effort | HIGH - would need Rust bindings |
| Testing | Limited - research quality |

**Pros**:
- Clean HotStuff implementation
- Reference for protocol correctness

**Cons**:
- C++ only, no Rust bindings
- Research prototype, not production ready
- Limited testing infrastructure

**Verdict**: NOT RECOMMENDED - Wrong language, research quality only.

#### 1.2.5 Custom Implementation

| Aspect | Assessment |
|--------|------------|
| Protocol | Chained HotStuff |
| Rust Quality | Native - matches APM2 codebase style |
| Dependencies | Minimal - ed25519-dalek, blake3, tokio (already in tree) |
| Integration Effort | MEDIUM - direct LedgerBackend integration |
| Testing | Custom - deterministic simulation with existing test harness |

**Pros**:
- Direct integration with APM2's `LedgerBackend` trait
- Reuse existing Ed25519 and BLAKE3 infrastructure
- No external consensus dependencies
- Tailored to small validator sets (4-7 nodes)
- Can implement exactly what's needed, no more

**Cons**:
- Development effort (~2-3 weeks for core protocol)
- No existing formal verification (rely on HotStuff paper proofs)
- Maintenance burden on APM2 team

**Verdict**: RECOMMENDED - Best fit for APM2's requirements.

### 1.3 Library Evaluation Summary

| Library | BFT | Rust | Extractable | Integration | Verdict |
|---------|-----|------|-------------|-------------|---------|
| tendermint-rs | PBFT | Native | No | High | Not recommended |
| narwhal | DAG-BFT | Native | No | Very High | Not recommended |
| aptos-core | HotStuff | Native | No | Very High | Not recommended |
| libhotstuff | HotStuff | C++ | N/A | High | Not recommended |
| **Custom** | HotStuff | Native | N/A | Medium | **RECOMMENDED** |

---

## Section 2: Protocol Selection (HotStuff vs PBFT)

### 2.1 Protocol Comparison

| Property | PBFT | HotStuff |
|----------|------|----------|
| Message Complexity | O(n^2) per view | O(n) per view |
| Communication Rounds | 3 (pre-prepare, prepare, commit) | 3 phases pipelined |
| View Change | O(n^3) messages | O(n) messages |
| Responsiveness | Partially responsive | Optimistically responsive |
| Pipelining | No | Yes (chained HotStuff) |
| Implementation Complexity | Moderate | Lower (linear message flow) |

### 2.2 APM2 Use Case Analysis

**Characteristics of APM2 Control Plane**:
- Small validator set: 4-7 nodes (f=1 to f=2)
- Low frequency: ~1-10 proposals per minute (promotions, capability grants)
- Latency tolerance: 100ms-1s acceptable for control plane
- Network: Typically co-located datacenter or close geo-regions

**HotStuff Advantages for APM2**:

1. **Linear Message Complexity**: Even with 7 nodes, PBFT's O(n^2) is manageable (49 messages vs 7). However, HotStuff's O(n) is cleaner and scales if APM2 expands validator sets.

2. **Simple View Change**: PBFT's view change is notoriously complex (O(n^3) messages). HotStuff's view change is just another proposal round. This reduces implementation bugs.

3. **Pipelining**: Chained HotStuff allows overlapping consensus rounds. While APM2's low frequency doesn't require this for throughput, it simplifies the state machine.

4. **Quorum Certificate Reuse**: HotStuff's QC structure maps directly to APM2's `QuorumCertificate` design in RFC-0014.

**PBFT Advantages**:

1. **Proven Track Record**: More production deployments historically (Hyperledger Fabric, etc.)
2. **Lower Latency per Decision**: 2 round trips vs HotStuff's 3 phases (though pipelining amortizes this)
3. **More Reference Implementations**: Easier to compare against

### 2.3 Protocol Selection: HotStuff

**Decision**: Use Chained HotStuff for APM2 v1.

**Rationale**:
1. Simpler view change logic reduces implementation bugs
2. Linear message flow is easier to reason about and test
3. QC structure aligns with RFC-0014's `QuorumCertificate` design
4. Pipelining provides headroom if proposal rate increases
5. O(n) complexity future-proofs for larger validator sets

---

## Section 3: Recommendation

### 3.1 Final Decision

| Question | Resolution |
|----------|------------|
| **Q-0001**: Library selection | Custom implementation |
| **Q-0002**: Protocol variant | Chained HotStuff |

### 3.2 Rationale Summary

**Custom Implementation** because:
- No existing Rust BFT library is extractable without massive dependencies
- APM2 already has Ed25519, BLAKE3, and async infrastructure
- Direct integration with `LedgerBackend` trait
- Tailored to small, permissioned validator sets

**Chained HotStuff** because:
- Simpler implementation than PBFT (especially view change)
- Linear message complexity O(n) vs O(n^2)
- QC structure matches RFC-0014 design
- Pipelining provides throughput headroom

### 3.3 Implementation Plan

1. **Phase 1**: Core protocol types (TCK-00186 - this ticket)
   - Message types: `Proposal`, `Vote`, `QuorumCertificate`, `NewView`
   - State machine: `HotStuffState`
   - Error types and validation

2. **Phase 2**: Protocol logic (future ticket)
   - Leader election and view management
   - Vote collection and QC aggregation
   - Commit rule (3-chain)

3. **Phase 3**: Network integration (future ticket)
   - Wire protocol (protobuf)
   - Integration with `Network` module
   - Peer message routing

---

## Section 4: Message Types (EVID-0007)

### 4.1 Core Message Types

```
+------------------+     +------------------+     +------------------+
|    Proposal      |     |      Vote        |     |QuorumCertificate |
+------------------+     +------------------+     +------------------+
| epoch: u64       |     | epoch: u64       |     | epoch: u64       |
| round: u64       |     | round: u64       |     | round: u64       |
| proposer_id      |     | voter_id         |     | block_hash       |
| block_hash       |     | block_hash       |     | signatures[]     |
| parent_qc        |     | signature        |     +------------------+
| payload_hash     |     +------------------+
| signature        |
+------------------+
```

### 4.2 Message Definitions

#### Proposal
```rust
struct Proposal {
    /// Current epoch (reconfiguration counter)
    epoch: u64,
    /// Round number within epoch
    round: u64,
    /// Proposer's validator ID (32-byte public key hash)
    proposer_id: ValidatorId,
    /// BLAKE3 hash of the proposed block
    block_hash: [u8; 32],
    /// QC for parent block (proves parent was certified)
    parent_qc: QuorumCertificate,
    /// BLAKE3 hash of the payload (event batch)
    payload_hash: [u8; 32],
    /// Ed25519 signature over (epoch, round, block_hash, payload_hash)
    signature: Signature,
}
```

#### Vote
```rust
struct Vote {
    /// Current epoch
    epoch: u64,
    /// Round being voted on
    round: u64,
    /// Voter's validator ID
    voter_id: ValidatorId,
    /// Hash of the block being voted for
    block_hash: [u8; 32],
    /// Ed25519 signature over (epoch, round, block_hash)
    signature: Signature,
}
```

#### QuorumCertificate
```rust
struct QuorumCertificate {
    /// Epoch of the certified block
    epoch: u64,
    /// Round of the certified block
    round: u64,
    /// Hash of the certified block
    block_hash: [u8; 32],
    /// Aggregated signatures (2f+1 votes)
    signatures: Vec<(ValidatorId, Signature)>,
}
```

#### NewView
```rust
struct NewView {
    /// New epoch (if reconfiguration) or current epoch
    epoch: u64,
    /// New round number
    round: u64,
    /// Leader's validator ID
    leader_id: ValidatorId,
    /// Highest QC known to the leader
    high_qc: QuorumCertificate,
    /// Ed25519 signature
    signature: Signature,
}
```

### 4.3 Validation Rules

| Message | Validation |
|---------|------------|
| Proposal | epoch matches local, round > last_voted_round, parent_qc valid, signature valid |
| Vote | epoch matches, round matches proposal, signature valid, voter in validator set |
| QC | 2f+1 valid signatures, all for same (epoch, round, block_hash) |
| NewView | round > current round, high_qc valid, leader matches round-robin |

---

## Section 5: State Machine (EVID-0007)

### 5.1 States

```
                    ┌─────────────────────────────────────────────────┐
                    │                                                 │
                    ▼                                                 │
              ┌──────────┐                                           │
     ┌───────▶│  IDLE    │◀──────────────────────────────┐          │
     │        └────┬─────┘                               │          │
     │             │                                     │          │
     │             │ receive Proposal                    │          │
     │             ▼                                     │          │
     │        ┌──────────┐                               │          │
     │        │ VOTING   │                               │          │
     │        └────┬─────┘                               │          │
     │             │                                     │          │
     │             │ collect 2f+1 votes                  │          │
     │             ▼                                     │          │
     │        ┌──────────┐                               │          │
     │        │CERTIFIED │ ─── QC formed ───────────────┤          │
     │        └────┬─────┘                               │          │
     │             │                                     │          │
     │             │ 3-chain commit rule satisfied       │          │
     │             ▼                                     │          │
     │        ┌──────────┐                               │          │
     └────────│COMMITTED │                               │          │
              └────┬─────┘                               │          │
                   │                                     │          │
                   │ timeout (no progress)              │          │
                   └────────────────────────────────────┘          │
                                                                    │
                   │ view change trigger                            │
                   ▼                                                │
              ┌──────────┐                                          │
              │VIEW_CHNG │──────────────────────────────────────────┘
              └──────────┘
                  NewView received
```

### 5.2 State Transitions

| Current State | Event | Next State | Action |
|---------------|-------|------------|--------|
| IDLE | Proposal received | VOTING | Validate proposal, broadcast Vote |
| VOTING | 2f+1 Votes collected | CERTIFIED | Form QC, advance round |
| CERTIFIED | 3-chain rule satisfied | COMMITTED | Commit block to ledger |
| COMMITTED | Next proposal | IDLE | Process next round |
| Any | Timeout | VIEW_CHANGE | Broadcast NewView |
| VIEW_CHANGE | NewView from new leader | IDLE | Adopt high_qc, resume |

### 5.3 HotStuff 3-Chain Commit Rule

```
B0 ◀─── B1 ◀─── B2 ◀─── B3
        │       │       │
       QC1     QC2     QC3 (current)

Commit B0 when:
- B0 ← B1 ← B2 ← B3 forms a chain
- QC1 certifies B1 extends B0
- QC2 certifies B2 extends B1
- QC3 certifies B3 extends B2
- B1.round = B0.round + 1 (consecutive)
- B2.round = B1.round + 1 (consecutive)
```

The 3-chain rule ensures that once a block is committed, no conflicting block can be certified (safety).

### 5.4 Pipelining

In Chained HotStuff, each phase (prepare, pre-commit, commit) is combined into a single voting round. The QC for round n serves as:
- **Prepare certificate** for block in round n
- **Pre-commit certificate** for block in round n-1
- **Commit certificate** for block in round n-2

This reduces latency and simplifies the protocol.

---

## Section 6: Safety and Liveness Proofs (EVID-0008)

### 6.1 Primary Reference

**Paper**: "HotStuff: BFT Consensus with Linearity and Responsiveness"
**Authors**: Maofan Yin, Dahlia Malkhi, Michael K. Reiter, Guy Golan Gueta, Ittai Abraham
**Published**: PODC 2019
**DOI**: 10.1145/3293611.3331591

### 6.2 Safety Theorem

**Theorem 2 (Safety)**: If two honest replicas commit blocks B and B' for the same height, then B = B'.

**Proof Sketch** (from paper):
1. Assume B and B' are committed at height h with B ≠ B'
2. B committed means there exists QC chain: QC(B) → QC(B1) → QC(B2)
3. B' committed means there exists QC chain: QC(B') → QC(B1') → QC(B2')
4. By quorum intersection (2f+1 of 3f+1), some honest replica voted for both
5. Honest replicas only vote once per round → contradiction
6. Therefore B = B'

**Theorem Number**: Theorem 2, Section 4.1 of HotStuff paper

### 6.3 Liveness Theorem

**Theorem 3 (Liveness)**: After GST, if the leader is honest, a decision is reached in O(n) messages.

**Proof Sketch**:
1. After GST, message delays are bounded by Δ
2. Honest leader proposes and collects 2f+1 votes within timeout
3. QC is formed and broadcast
4. Next honest leader extends the chain
5. After 3 consecutive honest leaders, commit occurs

**Assumptions**:
- Partial synchrony: Eventually (after GST), message delay ≤ Δ
- At most f < n/3 Byzantine validators
- Eventually honest leader (round-robin guarantees this)

**Theorem Number**: Theorem 3, Section 4.2 of HotStuff paper

### 6.4 APM2 Instantiation Mapping

| HotStuff Concept | APM2 Implementation |
|------------------|---------------------|
| Replica | Validator node (T1 key holder) |
| Block | Control-plane event batch |
| QC | `QuorumCertificate` struct |
| View | `(epoch, round)` pair |
| Signature | Ed25519 over canonical message |
| Hash | BLAKE3 |
| 2f+1 | `quorum_threshold` in `GenesisConfig` |
| 3f+1 | `validator_count` in consensus config |

### 6.5 Additional Proof References

1. **Tendermint Safety**: Buchman, Kwon, Milosevic. "The latest gossip on BFT consensus." arXiv:1807.04938 (2018)
   - Theorem 1 (Agreement), Theorem 2 (Termination)
   - Useful for comparison, similar safety argument

2. **PBFT Original**: Castro, Liskov. "Practical Byzantine Fault Tolerance." OSDI 1999
   - Theorem 1 (Safety), Theorem 2 (Liveness)
   - Foundation for all modern BFT protocols

3. **Casper FFG**: Buterin, Griffith. "Casper the Friendly Finality Gadget." arXiv:1710.09437 (2017)
   - Accountable safety (slashing for equivocation)
   - Relevant for future APM2 equivocation handling

### 6.6 Formal Verification Status

| Artifact | Status | Reference |
|----------|--------|-----------|
| HotStuff TLA+ spec | Available | https://github.com/hot-stuff/hotstuff-tla |
| Tendermint TLA+ | Verified | Informal Systems |
| APM2 custom | Not yet | Future ticket for model checking |

### 6.7 Security Properties Mapping

| RFC Property | Proof Reference |
|--------------|-----------------|
| SEC-PROP-0001 (Safety) | HotStuff Theorem 2 |
| SEC-PROP-0002 (Liveness) | HotStuff Theorem 3 |
| INV-0001 (Quorum ≥ 2f+1) | HotStuff Definition 1 |
| INV-0002 (No double vote) | Honest replica assumption |

---

## Appendix A: Decision Log

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-01-29 | Custom implementation over library | No extractable Rust BFT library available |
| 2026-01-29 | HotStuff over PBFT | Simpler view change, linear complexity |
| 2026-01-29 | Chained variant | Pipelining simplifies state machine |

## Appendix B: References

1. Yin et al. "HotStuff: BFT Consensus with Linearity and Responsiveness." PODC 2019.
2. Castro, Liskov. "Practical Byzantine Fault Tolerance." OSDI 1999.
3. Buchman et al. "The latest gossip on BFT consensus." arXiv:1807.04938.
4. RFC-0014: Distributed Consensus and Replication Layer for APM2.

## Appendix C: Glossary

| Term | Definition |
|------|------------|
| QC | Quorum Certificate - aggregation of 2f+1 valid signatures |
| GST | Global Stabilization Time - when network becomes synchronous |
| f | Maximum number of Byzantine (faulty) validators tolerated |
| 3f+1 | Minimum total validators for f-fault tolerance |
| View | A round of consensus with a designated leader |
| Epoch | A configuration period (validator set change increments epoch) |
