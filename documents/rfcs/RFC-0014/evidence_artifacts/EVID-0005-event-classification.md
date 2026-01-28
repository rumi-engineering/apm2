# EVID-0005: Event Classification Matrix

## Status
COMPLETE

## Purpose
Complete classification of all kernel events by ordering guarantee and merge operator.

## Classification

### Total Order Events (BFT Consensus Required)

These events change authority state and must be totally ordered:

| Event Type | Category | Rationale |
|------------|----------|-----------|
| LeaseIssued | Lease | Grants work authority |
| LeaseRenewed | Lease | Extends authority |
| LeaseReleased | Lease | Revokes authority |
| LeaseExpired | Lease | Time-based revocation |
| LeaseConflict | Lease | Requires adjudication |
| PolicyLoaded | Policy | Changes security posture |
| PolicyViolation | Policy | Security event |
| KeyRotated | Key | Changes signer identity |
| WorkOpened | Work | Creates workflow |
| WorkTransitioned | Work | State machine transition |
| WorkCompleted | Work | Final state transition |
| WorkAborted | Work | Final state transition |
| WorkPrAssociated | Work | Links external artifact |
| CapabilityRequired | Capability | Authority negotiation |
| CapabilityGranted | Capability | Capability issuance |
| CapabilityDelegated | Capability | Delegation chain link |
| CapabilityRevoked | Capability | Authority revocation |
| AdjudicationRequested | Adjudication | Governance action |
| AdjudicationVote | Adjudication | Governance action |
| AdjudicationResolved | Adjudication | Governance action |
| AdjudicationTimeout | Adjudication | Governance action |
| ToolRequested | Tool | Authority decision request |
| ToolDecided | Tool | Policy decision |
| GateReceiptGenerated | Evidence | Authoritative receipt |
| MergeReceiptGenerated | Evidence | Authoritative merge receipt |
| SessionStarted | Session | Creates actor context |
| SessionTerminated | Session | Ends actor context |
| SessionQuarantined | Session | Security action |

### Eventual Consistency Events (Anti-Entropy)

These events are observations and can use CRDT merge:

| Event Type | Merge Operator | Rationale |
|------------|---------------|-----------|
| SessionProgress | LastWriterWins | Latest progress wins |
| ToolExecuted | LastWriterWins | Latest result wins |
| BudgetExceeded | LastWriterWins | Latest reading wins |
| EvidencePublished | SetUnion | Accumulate evidence (StrictlyOrderedEvidence may require TotalOrder) |
| SessionCrashDetected | SetUnion | Record all crashes |
| SessionRestartScheduled | SetUnion | Record all restarts |

## Merge Operator Definitions

### LastWriterWins (LWW)
```
merge(a, b) = if HLC(a) >= HLC(b) then a else b
```

### SetUnion
```
merge(a, b) = a ∪ b (deduplicated by content hash)
```

### NoMerge (for total order events)
```
merge(a, b) = ERROR if a.hash != b.hash (conflict = defect)
```
Conflicts emit DefectRecorded events for auditability.

## References
- proto/kernel_events.proto
- 02_design_decisions.yaml#DD-0005
