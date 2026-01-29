# APM2 Consensus Layer Operations Runbook

This runbook provides incident response procedures for the APM2 distributed
consensus layer. It covers alert handling, diagnostics, and recovery procedures.

**RFC Reference**: RFC-0014 - Distributed Consensus and Replication Layer
**Ticket**: TCK-00193 - Operational Monitoring and Alerting

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Alert Response Procedures](#alert-response-procedures)
   - [ConsensusNoLeader](#consensusnoleader)
   - [ConsensusQuorumLost](#consensusquorumlost)
   - [HighFinalizationLatency](#highfinalizationlatency)
   - [ByzantineFaultDetected](#byzantinefaultdetected)
   - [AntiEntropyDivergence](#antientropydivergence)
   - [ConsensusStalled](#consensusstalled)
   - [HighProposalRejectionRate](#highproposalrejectionrate)
   - [SchemaRegistryEmpty](#schemaregistryempty)
3. [Diagnostic Commands](#diagnostic-commands)
4. [Recovery Procedures](#recovery-procedures)
5. [Escalation Paths](#escalation-paths)

---

## Architecture Overview

The APM2 consensus layer uses a hybrid architecture:

- **Control Plane**: HotStuff/PBFT BFT consensus for authority events (leases,
  capabilities, key rotations)
- **Data Plane**: CRDT/anti-entropy for observations (telemetry, evidence)

### Key Components

| Component | Description | Metrics Prefix |
|-----------|-------------|----------------|
| BFT Consensus | Chained HotStuff for total ordering | `apm2_consensus_*` |
| Anti-Entropy | Merkle tree sync for eventual consistency | `apm2_antientropy_*` |
| Schema Registry | Distributed schema governance | `apm2_schema_registry_*` |
| Byzantine Detection | Equivocation and forgery detection | `apm2_byzantine_*` |

### Normal Operating Parameters

| Metric | Target | Warning | Critical |
|--------|--------|---------|----------|
| Finalization latency p99 | < 500ms | > 500ms | > 2s |
| Leader elections/min | < 2 | > 5 | > 10 |
| Active validators | = quorum_size + f | < quorum_size + 1 | < quorum_size |
| Proposal success rate | > 99% | < 95% | < 90% |
| Anti-entropy conflicts/hour | < 50 | > 100 | > 500 |

---

## Alert Response Procedures

### ConsensusNoLeader

**Severity**: Warning
**Description**: Frequent leader elections indicate consensus instability.

#### Symptoms
- More than 5 leader elections in 1 minute
- Increased finalization latency
- Intermittent proposal timeouts

#### Investigation Steps

1. **Check network connectivity**
   ```bash
   # From each validator node
   apm2 consensus status --verbose
   apm2 consensus validators
   ```

2. **Check for validator crashes**
   ```bash
   # Review recent restarts
   journalctl -u apm2d --since "1 hour ago" | grep -i "restart\|crash\|panic"
   ```

3. **Verify clock synchronization**
   ```bash
   # Check NTP status
   timedatectl status
   chronyc tracking
   ```

4. **Review timeout configuration**
   ```bash
   # Check if timeouts are appropriate for network latency
   apm2 consensus metrics
   ```

#### Resolution

1. If network latency is high, consider increasing `round_timeout` in config
2. If a specific validator is crashing, review its logs and fix the root cause
3. If clock skew is detected, ensure NTP is running on all nodes

#### Escalation
- If leader elections continue after 15 minutes, escalate to on-call engineer
- If quorum is at risk, escalate immediately

---

### ConsensusQuorumLost

**Severity**: CRITICAL
**Description**: Insufficient validators for consensus. Cluster is STALLED.

#### Symptoms
- `active_validators < quorum_size`
- No new blocks committed
- All control plane operations blocked

#### Immediate Actions

1. **Assess validator status**
   ```bash
   apm2 consensus status
   apm2 consensus validators --active-only
   ```

2. **Identify down validators**
   ```bash
   # Check which validators are unreachable
   for node in node1 node2 node3 node4; do
     ping -c 1 $node || echo "$node unreachable"
   done
   ```

3. **Check validator processes**
   ```bash
   # On each validator
   systemctl status apm2d
   journalctl -u apm2d -n 100
   ```

#### Resolution Priority Order

1. **Restart crashed validators**
   ```bash
   systemctl restart apm2d
   ```

2. **Fix network issues** (firewall, DNS, routing)

3. **Replace hardware** if node is unrecoverable

4. **Add emergency validator** (requires governance approval)
   ```bash
   apm2 consensus add-validator --id NEW_ID --address ADDR --key-file KEY
   ```

#### Escalation
- Escalate to incident commander immediately
- Page all validator operators
- Prepare communication for users if outage exceeds 5 minutes

---

### HighFinalizationLatency

**Severity**: Warning
**Description**: Consensus finalization exceeds 500ms p99 target.

#### Symptoms
- p99 latency > 500ms sustained for 5+ minutes
- User-perceived slowness in control plane operations

#### Investigation Steps

1. **Check network latency between validators**
   ```bash
   # Measure RTT to other validators
   for peer in peer1 peer2 peer3; do
     ping -c 10 $peer | tail -1
   done
   ```

2. **Check validator load**
   ```bash
   # CPU, memory, disk I/O
   top -bn1 | head -20
   iostat -x 1 5
   ```

3. **Check payload sizes**
   ```bash
   # Review recent proposal sizes
   apm2 consensus metrics --period 300
   ```

#### Resolution

1. If network latency is high:
   - Check for network congestion
   - Consider moving validators closer geographically

2. If validators are overloaded:
   - Add resources (CPU, memory)
   - Review and optimize heavy operations

3. If payloads are large:
   - Review batching configuration
   - Consider splitting large transactions

---

### ByzantineFaultDetected

**Severity**: CRITICAL (Security)
**Description**: A validator is exhibiting malicious or faulty behavior.

#### Symptoms
- Byzantine evidence counter increased
- Fault types: equivocation, invalid_signature, quorum_forgery, replay

#### CRITICAL: Do Not Dismiss Without Investigation

#### Immediate Actions

1. **Preserve evidence**
   ```bash
   apm2 consensus byzantine-evidence list > /secure/evidence-$(date +%s).json
   ```

2. **Identify the faulty validator**
   ```bash
   apm2 consensus byzantine-evidence list --json | jq '.evidence[] | .validator_id'
   ```

3. **Assess fault severity**
   - **Equivocation**: Validator signed conflicting messages - MAY BE COMPROMISED
   - **Invalid Signature**: Could be key compromise or software bug
   - **Quorum Forgery**: Attempted to forge consensus - LIKELY MALICIOUS
   - **Replay**: Old messages being replayed - Could be attack or misconfiguration

#### Response by Fault Type

**For Equivocation or Quorum Forgery:**
1. Immediately remove validator from quorum
   ```bash
   apm2 consensus remove-validator --id VALIDATOR_ID
   ```
2. Revoke validator's keys
3. Conduct forensic investigation
4. Notify security team

**For Invalid Signature:**
1. Check if validator's clock is synchronized
2. Check for key file corruption
3. If persistent, rotate validator keys

**For Replay:**
1. Check for network issues causing retransmission
2. Verify replay cache is functioning
3. If malicious, remove validator

#### Escalation
- Notify security team immediately for any Byzantine evidence
- Involve incident commander for quorum-affecting decisions
- Document all actions for post-incident review

---

### AntiEntropyDivergence

**Severity**: Warning
**Description**: High rate of merge conflicts during anti-entropy sync.

#### Symptoms
- More than 100 conflicts per hour
- Data inconsistencies between nodes
- Increased sync traffic

#### Investigation Steps

1. **Check for recent partitions**
   ```bash
   apm2 consensus status --verbose
   # Look for nodes that recently rejoined
   ```

2. **Check clock skew** (affects LWW resolution)
   ```bash
   chronyc sources -v
   ```

3. **Review conflict resolution types**
   ```bash
   apm2 consensus metrics | grep conflicts
   ```

#### Resolution

1. If due to partition recovery:
   - This is normal, monitor for decrease
   - Conflicts should drop after initial sync

2. If clock skew is detected:
   - Fix NTP configuration
   - Consider using HLC instead of wall clock

3. If conflicts are persistent:
   - Review application logic for concurrent updates
   - Consider stronger consistency for affected data

---

### ConsensusStalled

**Severity**: Warning
**Description**: No proposals committed despite having quorum.

#### Investigation Steps

1. **Check if there's pending work**
   ```bash
   apm2 consensus status
   # If no pending transactions, this may be normal idle state
   ```

2. **Check leader health**
   ```bash
   apm2 consensus validators | grep "leader"
   ```

3. **Check for vote delivery issues**
   ```bash
   journalctl -u apm2d | grep -i "vote\|timeout"
   ```

#### Resolution

1. If leader is unhealthy, trigger leader election:
   ```bash
   apm2 consensus transfer-leadership --to HEALTHY_NODE
   ```

2. If votes aren't reaching quorum, check network connectivity

---

### HighProposalRejectionRate

**Severity**: Warning
**Description**: More than 10% of proposals being rejected.

#### Investigation Steps

1. **Check rejection reasons in logs**
   ```bash
   journalctl -u apm2d | grep -i "rejected\|invalid"
   ```

2. **Check leader state**
   ```bash
   apm2 consensus status --verbose
   ```

#### Resolution

1. If leader is proposing invalid blocks:
   - Check leader's state consistency
   - Consider restarting leader node

2. If safety rule violations:
   - This may indicate leader has stale state
   - Force leader rotation

---

### SchemaRegistryEmpty

**Severity**: Warning
**Description**: No schemas registered on node.

#### Investigation Steps

1. **Check node startup logs**
   ```bash
   journalctl -u apm2d | grep -i "schema"
   ```

2. **Check database integrity**
   ```bash
   apm2 ledger verify-chain
   ```

#### Resolution

1. Restart the node to trigger schema registration
   ```bash
   systemctl restart apm2d
   ```

2. If schemas still missing, sync from peer
   ```bash
   apm2 schema handshake --peer HEALTHY_PEER
   ```

---

## Diagnostic Commands

### Quick Health Check
```bash
# Overall cluster status
apm2 consensus status

# Validator list and health
apm2 consensus validators

# Recent Byzantine evidence
apm2 consensus byzantine-evidence list --limit 10

# Metrics summary
apm2 consensus metrics
```

### Detailed Diagnostics
```bash
# Verify hash chain integrity
apm2 ledger verify-chain --namespace kernel

# Compare ledger with peer
apm2 ledger diff --peer peer1:9090 --namespace kernel

# List registered schemas
apm2 schema list
```

### Network Diagnostics
```bash
# Check peer connectivity
for peer in $(apm2 consensus validators --json | jq -r '.validators[].address'); do
  nc -zv $peer 9090 2>&1 | head -1
done
```

---

## Recovery Procedures

### Node Recovery After Crash

1. Check for corruption
   ```bash
   apm2 ledger verify-chain
   ```

2. If corrupted, restore from backup
   ```bash
   cp /backup/ledger.db $APM2_DATA_DIR/ledger.db
   ```

3. Sync from peers
   ```bash
   systemctl start apm2d
   # Node will automatically sync via anti-entropy
   ```

### Validator Key Rotation

1. Generate new key
   ```bash
   apm2 consensus keygen --output /secure/new-validator-key.pem
   ```

2. Submit rotation proposal (requires governance)
   ```bash
   apm2 consensus rotate-key --key-file /secure/new-validator-key.pem
   ```

3. Wait for quorum approval

### Adding New Validator (Emergency)

Requires governance approval (3-of-5 T0 signatures).

```bash
# Generate invitation token
apm2 consensus invite --id NEW_VALIDATOR --role validator

# On new node
apm2 consensus join --token <invitation_token>
```

---

## Escalation Paths

| Severity | Response Time | Escalation |
|----------|---------------|------------|
| Warning | < 1 hour | On-call engineer |
| Critical | < 15 minutes | On-call + Incident Commander |
| Byzantine | Immediate | Security Team + Incident Commander |

### Contacts

- **On-Call Engineer**: Check PagerDuty rotation
- **Incident Commander**: @incident-commander Slack channel
- **Security Team**: security@yourorg.com (for Byzantine faults)

### Communication Templates

**For Quorum Loss:**
> Subject: [INCIDENT] APM2 Consensus Quorum Lost
>
> Impact: Control plane operations are blocked.
> Start time: [TIME]
> Status: Investigating
> Next update: In 15 minutes

**For Byzantine Fault:**
> Subject: [SECURITY] Byzantine Fault Detected in APM2 Cluster
>
> A validator has exhibited malicious behavior (type: [FAULT_TYPE]).
> Preserving evidence and removing validator from quorum.
> Security team has been notified.
