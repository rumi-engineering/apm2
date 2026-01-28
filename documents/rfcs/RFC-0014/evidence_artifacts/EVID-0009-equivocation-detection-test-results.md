# EVID-0009: Equivocation Detection Test Results

## Status
DRAFT (test specs defined; execution pending)

## Purpose
Define test cases demonstrating detection of equivocation and replay-safe slashing.

## Test Cases
1. **Double-signing in same epoch/round**
   - Input: two conflicting proposals signed by same validator for `(epoch, round)`.
   - Expect: equivocation proof generated; validator removed from set.

2. **Replay framing attempt**
   - Input: conflicting messages from a prior epoch reintroduced.
   - Expect: proof rejected due to epoch/nonce mismatch.

3. **Key rotation boundary**
   - Input: KeyRotated event during active round; old key messages continue.
   - Expect: old key remains valid for current epoch; new key effective next epoch.

## Evidence Artifacts
- Proof format includes `(validator_id, epoch, round, nonce)` tuple.
- Slashing record appended as authority event with QC.

## Next Steps
- Run TEST-BZ-001 and TEST-BZ-004 in CI harness.
- Attach logs and proof samples to this file.
