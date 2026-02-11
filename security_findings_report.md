## Security Review: FAIL

Reviewed SHA: b8460c4940d675714e4dabcd14dac8a83c437a27

### **BLOCKER FINDINGS**

#### 1. Denial of Service (DoS) via O(N) Ledger Hash Chain Verification
**Threat:** The `SqliteLedgerEventEmitter::derive_event_chain_hash` implementation (and its use in `derive_pcac_ledger_anchor`) performs a full table scan and re-hashes every event in the ledger on every request requiring a PCAC anchor.
**Exploit Path:** As the ledger grows, the CPU and I/O cost of every tool request increases linearly. An attacker can induce ledger growth (e.g., by triggering many events) until the cost of hashing the entire ledger on each request exceeds the available resources, leading to daemon throughput collapse.
**Blast Radius:** System-wide availability failure.
**Remediation:** Implement incremental hash verification or cache the validated chain tip. The ledger anchor should only require hashing new events since the last validated checkpoint.

#### 2. Blocking Migration during Initialization
**Threat:** `SqliteLedgerEventEmitter::backfill_hash_chain` runs on every daemon startup where `init_schema` is called. It iterates through the entire ledger, re-hashing every row and performing individual `UPDATE` statements in autocommit mode (no explicit transaction).
**Exploit Path:** On a production system with a large ledger, this will cause the daemon to block for an extended period during startup, leading to a self-inflicted Denial of Service.
**Blast Radius:** Daemon availability.
**Remediation:** Wrap the backfill loop in a single SQLite transaction and only perform backfill for rows that lack a valid hash (e.g., `WHERE event_hash = 'legacy-uninitialized'`). Ideally, use a one-time migration flag to avoid re-scanning the entire table on every startup.

### **MAJOR FINDINGS**

#### 1. Variable-Time Comparison of Cryptographic Digests
**Threat:** `SessionDispatcher::tool_decision_policy_verified` compares `policy_hash` using the standard `==` operator (`*policy_hash == admitted_policy_root_digest`).
**Exploit Path:** Standard array comparison in Rust short-circuits on the first mismatch, creating a timing side-channel. While the risk is mitigated by the difficulty of exploiting it over IPC/network, it violates the project's standard for constant-time cryptographic comparisons.
**Remediation:** Use `subtle::ConstantTimeEq` (e.g., `bool::from(policy_hash.ct_eq(&admitted_policy_root_digest))`) for all digest comparisons.

#### 2. Migration-Time History Forgery (Blessing)
**Threat:** `backfill_hash_chain` blindly re-hashes existing history on startup. If an attacker with database access modifies legacy events (which were not signed with a `prev_hash` binding) while the daemon is offline, the next startup will compute a valid hash chain over the tampered state.
**Exploit Path:** Attacker modifies a legacy ledger event, then restarts the daemon. The backfill logic generates a valid hash chain that now includes the attacker's changes. Any subsequent new-style signed events will then cryptographically bind to this tampered (but now hashed) history.
**Remediation:** Legacy history should be hashed against a known-good checkpoint, or the backfill should be a manual, high-assurance operation rather than an automatic startup routine.

### **MINOR FINDINGS**

#### 1. Unbounded Deserialization (DoS) in `extract_boundary_flow_hints`
The `extract_boundary_flow_hints` function deserializes `request_arguments` into a `serde_json::Value` before extracting hints. This can lead to excessive memory pressure for large or deeply nested JSON payloads.
**Remediation:** Deserialize directly into the `BoundaryFlowHints` struct.

#### 2. Unsigned Ledger Events
`SqliteLeaseValidator` inserts `gate_lease_issued` events with a dummy signature (`vec![0u8; 64]`). While these are part of the hash chain, they lack individual authenticity proofs.
**Remediation:** Ensure all events in the hash chain are signed by the daemon's authority key.

### **NITS**

#### 1. Domain Prefix Inconsistency
The default `LedgerEventEmitter::derive_event_chain_hash` uses `apm2-ledger-chain-default-v1` whereas `SqliteLedgerEventEmitter` uses `apm2-ledger-event-hash-v1`. While harmless since the latter overrides the former, it creates confusion in the protocol surface.

### **WAIVED FINDINGS**
None.
