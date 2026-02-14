# TCK-00511: FAC Worker — Queue consumer with RFC-0028 authorization + RFC-0029 admission gating

You are implementing `apm2 fac worker` — a queue consumer command. Work in `/home/ubuntu/Projects/apm2-worktrees/TCK-00511`.

## CRITICAL INSTRUCTION
START WRITING CODE IMMEDIATELY. Do NOT research for more than 2 minutes. All API signatures you need are in this prompt. Do NOT read more than 5 files before you start writing code.

## What to Build

### 1. CLI Subcommand: `apm2 fac worker`

Add a `Worker` variant to `FacSubcommand` in `crates/apm2-cli/src/commands/fac.rs`:

```rust
/// Run the FAC queue worker (default-mode executor).
///
/// Scans the pending queue, validates RFC-0028 tokens and RFC-0029
/// admission, claims jobs atomically, executes under lane containment,
/// and emits authoritative receipts.
Worker(WorkerArgs),
```

Add `WorkerArgs`:
```rust
#[derive(Debug, clap::Args)]
pub struct WorkerArgs {
    /// Process one job and exit (default: continuous loop).
    #[arg(long)]
    pub once: bool,

    /// Poll interval in seconds for continuous mode.
    #[arg(long, default_value = "5")]
    pub poll_interval_secs: u64,

    /// Maximum jobs to process before exiting (0 = unlimited).
    #[arg(long, default_value = "0")]
    pub max_jobs: u64,
}
```

Wire it in the `match &cmd.subcommand` block:
```rust
FacSubcommand::Worker(args) => run_fac_worker(args, json_output),
```

### 2. Core Worker Logic — new file `crates/apm2-cli/src/commands/fac_worker.rs`

Create this file with:
- `pub fn run_fac_worker(args: &WorkerArgs, json_output: bool) -> i32`
- Queue scanning, validation, claim, execution, receipt emission

### 3. Queue Directory Layout

The worker scans `~/.apm2/queue/pending/` for `*.json` job spec files. The directory structure:
- `~/.apm2/queue/pending/` — incoming jobs (worker reads from here)
- `~/.apm2/queue/claimed/` — atomically renamed from pending (worker owns)
- `~/.apm2/queue/completed/` — finished jobs moved here with receipt
- `~/.apm2/queue/denied/` — RFC-0028/0029 validation failures
- `~/.apm2/queue/quarantined/` — malformed/untrusted input

### 4. Worker Processing Pipeline (per job)

```
scan_pending_queue()
  → deterministic_order() (sort by priority ASC, enqueue_time ASC, job_id ASC)
  → for each job_spec file:
      1. bounded_deserialize(file, 64KB limit) → FacJobSpecV1
         - On fail → move to quarantined/ + write quarantine receipt
      2. validate_job_spec_digest(spec)
         - Recompute digest, compare to spec.job_spec_digest
         - On fail → move to quarantined/ + write quarantine receipt
      3. validate_rfc0028_token(spec)
         - Extract spec.actuation.channel_context_token
         - If None → move to denied/ + write denial receipt (reason: "missing_channel_context_token")
         - decode_channel_context_token(token, broker_verifying_key, lease_id, current_time, request_id)
         - On decode fail → move to denied/ + write denial receipt
      4. evaluate_rfc0029_admission(spec, broker)
         - Build QueueAdmissionRequest from spec + broker state
         - Call evaluate_queue_admission(request, scheduler_state, verifier)
         - If verdict != Allow → move to denied/ + write denial receipt with admission trace
      5. atomic_claim(spec)
         - fs::rename(pending/job.json, claimed/job.json) — atomic on same filesystem
         - If rename fails (ENOENT = claimed by another worker) → skip, continue
      6. acquire_lane_lease(spec)
         - Parse spec.lane_requirements.lane_profile_hash
         - Use LaneManager::try_lock() to find available lane
         - If no lane available → move back to pending/ + continue
      7. execute_job(spec, lane_guard)
         - Run the actual job under lane containment
         - For "gates" kind: delegate to existing run_gates logic
      8. emit_receipt(spec, result)
         - Build GateReceipt via GateReceiptBuilder
         - Sign with broker signer
         - Write receipt JSON to completed/ directory
         - Move claimed/job.json → completed/job.json
```

### 5. Key API Signatures You MUST Use

#### FacJobSpecV1 (crates/apm2-core/src/fac/job_spec.rs)
```rust
pub struct FacJobSpecV1 {
    pub schema: String,          // "apm2.fac.job_spec.v1"
    pub job_id: String,
    pub job_spec_digest: String, // content-addressable digest
    pub kind: String,            // "gates", "warm", etc.
    pub queue_lane: String,      // RFC-0029 lane
    pub priority: u32,           // 0=highest
    pub enqueue_time: String,    // ISO 8601
    pub actuation: Actuation,    // RFC-0028 authorization block
    pub source: JobSource,
    // ... more fields
}

pub struct Actuation {
    pub lease_id: String,
    pub request_id: String,      // MUST equal job_spec_digest
    pub channel_context_token: Option<String>, // base64-encoded RFC-0028 token
    pub decoded_source: Option<String>,
}

pub fn deserialize_job_spec(bytes: &[u8]) -> Result<FacJobSpecV1, JobSpecError>  // bounded at 64KB
pub fn validate_job_spec(spec: &FacJobSpecV1) -> Result<(), JobSpecError>
impl FacJobSpecV1 { pub fn compute_digest(&self) -> Result<String, JobSpecError> }
```

#### Token Decode (crates/apm2-core/src/channel/enforcement.rs)
```rust
pub fn decode_channel_context_token(
    token: &str,
    daemon_verifying_key: &VerifyingKey,
    expected_lease_id: &str,
    current_time_secs: u64,
    expected_request_id: &str,
) -> Result<ChannelBoundaryCheck, ChannelContextTokenError>
```

#### Queue Admission (crates/apm2-core/src/economics/queue_admission.rs)
```rust
pub fn evaluate_queue_admission(
    request: &QueueAdmissionRequest,
    scheduler: &QueueSchedulerState,
    verifier: Option<&dyn SignatureVerifier>,
) -> QueueAdmissionDecision

pub struct QueueAdmissionRequest {
    pub lane: QueueLane,
    pub envelope: Option<TimeAuthorityEnvelopeV1>,
    pub eval_window: HtfEvaluationWindow,
    pub freshness_horizon: Option<FreshnessHorizonRef>,
    pub revocation_frontier: Option<RevocationFrontierSnapshot>,
    pub convergence_horizon: Option<ConvergenceHorizonRef>,
    pub convergence_receipts: Vec<ConvergenceReceipt>,
    pub required_authority_sets: Vec<Hash>,
    pub cost: u64,
    pub current_tick: u64,
}

pub struct QueueAdmissionDecision {
    pub verdict: QueueAdmissionVerdict,
    pub trace: QueueAdmissionTrace,
}

pub enum QueueAdmissionVerdict { Allow, Deny }

pub struct QueueSchedulerState { /* use QueueSchedulerState::new() */ }

pub enum QueueLane { StopRevoke = 0, Control = 1, Critical = 2, High = 3, Normal = 4, Low = 5 }
```

#### Lane Manager (crates/apm2-core/src/fac/lane.rs)
```rust
pub struct LaneManager { /* fac_root: PathBuf */ }
impl LaneManager {
    pub fn new(fac_root: PathBuf) -> Result<Self, LaneError>
    pub fn from_default_home() -> Result<Self, LaneError>
    pub fn try_lock(&self, lane_id: &str) -> Result<Option<LaneLockGuard>, LaneError>
    pub fn acquire_lock(&self, lane_id: &str) -> Result<LaneLockGuard, LaneError>
    pub fn default_lane_ids() -> Vec<String>
    pub fn ensure_directories(&self) -> Result<(), LaneError>
}
```

#### Receipt Builder (crates/apm2-core/src/fac/receipt.rs)
```rust
pub struct GateReceiptBuilder { /* ... */ }
impl GateReceiptBuilder {
    pub fn new(gate_name: impl Into<String>, outcome: impl Into<String>,
               evidence_hash: impl Into<String>, pipeline_id: impl Into<String>) -> Self
    pub fn executor_actor_id(mut self, actor_id: impl Into<String>) -> Self
    pub fn payload_kind(mut self, kind: impl Into<String>) -> Self
    pub fn job_spec_digest(mut self, digest: impl Into<String>) -> Self
    pub fn build_and_sign(self, signer: &Signer) -> GateReceipt
}
```

#### Broker (crates/apm2-core/src/fac/broker.rs)
```rust
pub struct FacBroker { /* ... */ }
impl FacBroker {
    pub fn new() -> Self
    pub fn verifying_key(&self) -> VerifyingKey
    pub fn check_health(&self) -> Result<BrokerHealthReport, BrokerError>
    pub fn evaluate_admission_health_gate(&mut self) -> Result<(), BrokerError>
    pub fn build_evaluation_window(&self, lane: QueueLane, ...) -> Result<HtfEvaluationWindow, BrokerError>
    pub fn issue_time_authority_envelope_default_ttl(&mut self, ...) -> Result<TimeAuthorityEnvelopeV1, BrokerError>
}
```

#### Crypto Signer (crates/apm2-core/src/crypto.rs)
```rust
pub struct Signer { /* ed25519 */ }
impl Signer {
    pub fn generate() -> Self
    pub fn verifying_key(&self) -> VerifyingKey
}
```

### 6. Module Registration

In `crates/apm2-cli/src/commands/mod.rs`, add:
```rust
pub mod fac_worker;
```

In `crates/apm2-cli/src/commands/fac.rs`, add at top:
```rust
use super::fac_worker::run_fac_worker;
```

### 7. Tests

Create `crates/apm2-cli/tests/tck_00511_fac_worker.rs` with these integration tests:

1. **test_worker_denies_missing_token** — Job spec with `channel_context_token: None` → moved to denied/, denial receipt written
2. **test_worker_denies_invalid_token** — Job spec with garbage token → moved to denied/
3. **test_worker_quarantines_malformed_spec** — Invalid JSON → moved to quarantined/
4. **test_worker_quarantines_digest_mismatch** — Tampered digest → moved to quarantined/
5. **test_worker_denies_rfc0029_admission_failure** — Admission verdict=Deny → moved to denied/ with trace
6. **test_worker_claims_atomically** — Successful claim → pending/job.json moved to claimed/
7. **test_worker_deterministic_ordering** — Multiple jobs sorted by priority then enqueue_time then job_id
8. **test_worker_once_mode** — `--once` processes exactly one job and exits
9. **test_worker_no_double_execution** — Concurrent claim attempt (file already claimed) → skip gracefully

For each test:
- Use `tempdir` for `APM2_HOME`
- Create fake job specs with `FacJobSpecV1Builder`
- Verify file moves and receipt contents
- Assert no secrets in receipts/logs

### 8. Security Requirements (FAIL-CLOSED)
- All queue reads bounded to 64KB (`deserialize_job_spec` already enforces this)
- Token decode failures → DENY + receipt (never skip validation)
- Admission failures → DENY + receipt (never default to allow)
- `job_spec_digest` mismatch → QUARANTINE (attacker may have tampered)
- No secrets (tokens, keys) appear in receipts or log output
- Atomic rename prevents double-execution across concurrent workers

## Pre-commit Checklist (MANDATORY — do ALL of these before committing)

1. `cargo fmt --all`
2. `cargo clippy --workspace --all-targets --all-features -- -D warnings` (fix ALL warnings)
3. `cargo doc --workspace --no-deps` (fix any doc warnings)
4. `cargo test -p apm2-cli` (run CLI tests)
5. `cargo test -p apm2-core` (run core tests)

You MUST pass ALL CI checks. Do NOT skip any of these steps.

## Commit Message Format
```
TCK-00511: FAC Worker: queue consumer with RFC-0028 auth + RFC-0029 admission

- Add `apm2 fac worker` command (--once and continuous modes)
- Queue scanning with deterministic ordering (priority/time/id)
- RFC-0028 channel context token validation (fail-closed)
- RFC-0029 queue admission gating via evaluate_queue_admission
- Atomic claim via rename, lane lease acquisition
- Denial/quarantine receipts for all failure paths
- Integration tests for all validation and deny paths
```
