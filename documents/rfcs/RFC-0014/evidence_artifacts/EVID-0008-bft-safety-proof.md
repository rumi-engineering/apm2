# EVID-0008: BFT Safety Proof References

## Status
DRAFT (references mapped; formal proof inherited from published literature)

## Purpose
Provide proof references for Safety (Agreement) and Liveness (Termination)
for the chosen BFT protocol variant at local-quorum scale.

## References (to be finalized by DCS-007a)
- **HotStuff**: Yin et al., HotStuff: BFT Consensus with Linearity and Responsiveness.
- **PBFT**: Castro & Liskov, Practical Byzantine Fault Tolerance.

## RFC Mapping
- **Safety**: `SEC-PROP-0001` maps to Agreement property in HotStuff/PBFT.
- **Liveness**: `SEC-PROP-0002` maps to liveness under partial synchrony.

## Instantiation Notes
- Quorum threshold: 2f+1 of 3f+1 validators.
- Validator signatures: Ed25519.
- QuorumCertificate structure: RFC DD-0007.

## Acceptance Criteria Mapping
- DCS-007b: state machine implements proof assumptions.
- DCS-008: QC generation matches proof conditions.

## To Complete in Spike
- Choose protocol variant and list exact theorem numbers.
- Provide short mapping from RFC message types to paper’s message model.
