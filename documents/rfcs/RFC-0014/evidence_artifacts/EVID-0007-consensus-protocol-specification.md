# EVID-0007: Consensus Protocol Specification

## Status
DRAFT (spike output required before implementation)

## Scope
Local-quorum BFT consensus (HotStuff or PBFT variant) for control-plane events only.
Data-plane events remain CRDT/anti-entropy.

## Message Types (minimum set)
- **PrePrepare**: proposer announces candidate event
- **Prepare**: validator votes for proposal
- **Commit**: validator signals finalization
- **ViewChange**: validator triggers leader change
- **NewView**: new leader establishes quorum view
- **QC (QuorumCertificate)**: 2f+1 signatures over event hash

## Common Fields (per message)
- `epoch`: u64
- `round`: u64
- `proposer_id` / `validator_id`
- `event_hash` + `prev_hash`
- `qc` (optional for Prepare/Commit)
- `signature` (Ed25519)
- `timestamp` (HLC + wall time)

## State Machine (outline)
1. **Propose**: leader emits PrePrepare for `(epoch, round, event_hash)`.
2. **Prepare**: validators verify and broadcast Prepare; collect 2f+1.
3. **Commit**: upon PrepareQC, broadcast Commit; collect 2f+1.
4. **Finalize**: on CommitQC, append authority event with QC.
5. **ViewChange**: timeout or leader failure triggers ViewChange.
6. **NewView**: leader aggregates ViewChange, issues NewView with highest QC.

## Quorum Thresholds
- **Safety**: ≥ 2f+1 signatures for PrepareQC and CommitQC.
- **Liveness**: requires partial synchrony and < f Byzantine validators.

## Timing Assumptions
- Safety: asynchronous network (no timing assumptions).
- Liveness: partial synchrony after GST; timeouts backed by HLC.

## Mapping to Ledger
- Finalized authority events MUST include `QuorumCertificate` attached.
- Event ordering uses `consensus_epoch` + `consensus_round` + `seq_id`.

## Open Design Choice
Protocol variant (HotStuff vs PBFT) resolved by DCS-007a spike.

## References
- RFC-0014 DD-0001, DD-0007
- EVID-0008 (proof references)
