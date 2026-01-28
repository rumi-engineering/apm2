# EVID-0011: Key Rotation Security Analysis

## Status
DRAFT (analysis outline complete)

## Scope
Validator (T1) key rotation for local-quorum BFT consensus.

## Security Goals
- Limit future exposure after compromise.
- Preserve historical verification.
- Avoid ambiguous validation during rotation.

## Model
- **KeyRotated** events are authority events with QC.
- Rotation is effective at **next epoch boundary**.
- Messages in current epoch must be signed by key active at epoch start.

## Threats Considered
- **Key theft**: attacker signs future messages -> mitigated by rotation + revocation.
- **Replay**: old messages used to frame validator -> mitigated by epoch/round scoping.
- **Split-brain**: concurrent rotations -> mitigated by QC requirement.

## Latency Targets
- Propagation: < 2 consensus rounds (target) for KeyRotated visibility.
- Revocation: < 1 epoch for removal.

## Evidence To Add
- Rotation propagation test logs.
- Example KeyRotated event with QC.
