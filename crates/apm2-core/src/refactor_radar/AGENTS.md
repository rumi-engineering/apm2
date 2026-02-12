# Refactor Radar Module

> Aggregates codebase signals (hotspots, duplication, complexity) into bounded, prioritized maintenance recommendations with circuit-breaker protection.

## Overview

The `apm2_core::refactor_radar` module analyzes a repository to identify areas that may benefit from refactoring. It collects signals from three independent collectors, aggregates them by severity, and produces a bounded list of prioritized recommendations. A circuit breaker prevents recommendation overload when the maintenance backlog is already high.

```text
+-------------------+     +-------------------+     +-------------------+
| HotspotCollector  |     | DuplicationCollect|     | ComplexityCollect |
| (git log churn)   |     | (git ls-files)    |     | (git ls-files)    |
+--------+----------+     +--------+----------+     +--------+----------+
         |                         |                         |
         v                         v                         v
    HotspotSignal           DuplicationSignal         ComplexitySignal
         |                         |                         |
         +------------+------------+
                      |
               +------v------+
               |    Radar    |
               | (aggregate, |
               |  prioritize,|
               |  bound)     |
               +------+------+
                      |
               +------v------+
               | CircuitBreak|---> Tripped? Return empty recommendations
               +------+------+
                      |
               RadarResult { recommendations, circuit_breaker, ... }
```

Design principles:

- **Bounded Output**: Recommendations are capped at `max_recommendations` to prevent overwhelming developers.
- **Circuit Breaker**: When open maintenance tickets exceed `backlog_threshold`, new recommendations are suspended.
- **Graceful Degradation**: Individual collector failures do not abort the radar run; other collectors continue.
- **Security**: Git command arguments are hardcoded (not user-controlled), paths from git output are validated, and file reads are bounded.

## Key Types

### `RadarConfig`

```rust
#[derive(Debug, Clone)]
pub struct RadarConfig {
    pub window: Duration,            // Default: 7 days
    pub max_recommendations: usize,  // Default: 10
    pub backlog_threshold: usize,    // Default: 20
    pub ignore_breaker: bool,        // Default: false
    pub min_churn: usize,            // Default: 5
    pub similarity_threshold: u8,    // Default: 70
    pub max_lines: usize,            // Default: 500
}
```

**Contracts:**

- [CTR-RR01] All configuration fields have sensible defaults via `Default` impl.
- [CTR-RR02] `ignore_breaker` allows overriding the circuit breaker for forced analysis.

### `Radar`

```rust
pub struct Radar {
    config: RadarConfig,
}
```

**Contracts:**

- [CTR-RR03] `new(config)` is `const` and performs no validation at construction time.
- [CTR-RR04] `run(repo_root)` requires the path to exist; returns `RadarError::RepoNotFound` otherwise.

### `RadarResult`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RadarResult {
    pub circuit_breaker: CircuitBreaker,
    pub recommendations: Vec<Recommendation>,
    pub total_signals: usize,
    pub config_summary: ConfigSummary,
}
```

**Invariants:**

- [INV-RR01] `recommendations.len()` never exceeds `config.max_recommendations`.
- [INV-RR02] `recommendations` are sorted by priority (1 = highest severity).
- [INV-RR03] When `circuit_breaker.is_blocking()` is `true`, `recommendations` is empty.

### `CircuitBreaker`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CircuitBreaker {
    pub status: CircuitBreakerStatus,
    pub current_backlog: usize,
    pub threshold: usize,
    pub ignored: bool,
}
```

**Invariants:**

- [INV-RR04] `status` is `Tripped` when `current_backlog > threshold`; `Ok` otherwise.
- [INV-RR05] `is_blocking()` returns `true` only when `status` is `Tripped` AND `ignored` is `false`.

### `CircuitBreakerStatus`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CircuitBreakerStatus {
    Ok,
    Tripped,
}
```

### `Recommendation`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recommendation {
    pub priority: usize,
    pub signal_type: String,
    pub source_path: PathBuf,
    pub severity: Severity,
    pub rationale: String,
    pub suggested_action: String,
    pub suggested_ticket: SuggestedTicket,
}
```

**Invariants:**

- [INV-RR06] `priority` starts at 1 and is strictly sequential.
- [INV-RR07] `signal_type` is one of `"hotspot"`, `"duplication"`, or `"complexity"`.

### `SuggestedTicket`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuggestedTicket {
    pub title: String,
    pub ticket_type: String,
}
```

### `ConfigSummary`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigSummary {
    pub window_days: u64,
    pub max_recommendations: usize,
    pub backlog_threshold: usize,
}
```

### `RadarError`

```rust
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RadarError {
    RepoNotFound { path: String },
    SignalError(SignalError),
    IoError { reason: String },
}
```

### `Severity` (from `signals` submodule)

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,      // value: 1
    Medium,   // value: 2
    High,     // value: 3
    Critical, // value: 4
}
```

**Contracts:**

- [CTR-RR05] `value()` returns a numeric score for sorting (higher = more severe).
- [CTR-RR06] `Severity` implements `Ord` with `Low < Medium < High < Critical`.

### `Signal`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "signal_type", rename_all = "snake_case")]
pub enum Signal {
    Hotspot(HotspotSignal),
    Duplication(DuplicationSignal),
    Complexity(ComplexitySignal),
}
```

**Contracts:**

- [CTR-RR07] `source_path()`, `severity()`, `evidence()`, `suggested_action()`, and `signal_type()` delegate to the inner signal variant.

### `HotspotSignal`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HotspotSignal {
    pub source_path: PathBuf,
    pub churn_count: usize,
    pub severity: Severity,
    pub evidence: String,
    pub suggested_action: String,
}
```

**Invariants:**

- [INV-RR08] Severity thresholds: `churn >= 30` = Critical, `>= 20` = High, `>= 10` = Medium, else Low.

### `DuplicationSignal`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DuplicationSignal {
    pub source_path: PathBuf,
    pub similar_files: Vec<PathBuf>,
    pub similarity_percent: u8,
    pub severity: Severity,
    pub evidence: String,
    pub suggested_action: String,
}
```

**Invariants:**

- [INV-RR09] Severity thresholds: `similarity >= 90 || count >= 4` = Critical, `>= 80 || count >= 3` = High, `>= 70` = Medium, else Low.

### `ComplexitySignal`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComplexitySignal {
    pub source_path: PathBuf,
    pub line_count: usize,
    pub severity: Severity,
    pub evidence: String,
    pub suggested_action: String,
}
```

**Invariants:**

- [INV-RR10] Severity thresholds (ratio = lines / threshold): `ratio >= 3.0` = Critical, `>= 2.0` = High, `>= 1.5` = Medium, else Low.

### `SignalError`

```rust
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SignalError {
    GitCommandFailed { reason: String },
    InvalidPath { path: String, reason: String },
    PathTraversal { path: String },
    IoError { reason: String },
}
```

## Public API

### `Radar::new(config) -> Self`

Creates a new radar with the given configuration. `const`-compatible.

### `Radar::run(repo_root) -> Result<RadarResult, RadarError>`

Runs the full radar analysis: checks circuit breaker, collects signals from all collectors, aggregates by severity, and returns bounded recommendations.

### `HotspotCollector::new(window, min_churn) -> Self`

Creates a hotspot collector that analyzes `git log` for file churn within the given time window.

### `HotspotCollector::collect(repo_root) -> Result<Vec<HotspotSignal>, SignalError>`

Collects hotspot signals by streaming `git log --name-only` output and counting file modifications.

### `DuplicationCollector::new(similarity_threshold) -> Self`

Creates a duplication collector with the given similarity threshold (0-100).

### `DuplicationCollector::collect(repo_root) -> Result<Vec<DuplicationSignal>, SignalError>`

Collects duplication signals by grouping `git ls-files *.rs` output by filename and flagging same-named files in different directories.

### `ComplexityCollector::new(max_lines) -> Self`

Creates a complexity collector that flags files exceeding `max_lines`.

### `ComplexityCollector::collect(repo_root) -> Result<Vec<ComplexitySignal>, SignalError>`

Collects complexity signals by counting lines in each Rust source file tracked by git.

### Constants

- `DEFAULT_MAX_RECOMMENDATIONS: usize = 10`
- `DEFAULT_BACKLOG_THRESHOLD: usize = 20`

## Examples

### Running the Radar

```rust
use std::path::Path;
use std::time::Duration;
use apm2_core::refactor_radar::{Radar, RadarConfig};

let config = RadarConfig {
    window: Duration::from_secs(7 * 86400),
    max_recommendations: 10,
    backlog_threshold: 20,
    ..Default::default()
};

let radar = Radar::new(config);
let result = radar.run(Path::new("/repo/root"))?;

if result.circuit_breaker.is_blocking() {
    println!(
        "Recommendations suspended: {} open tickets (threshold: {})",
        result.circuit_breaker.current_backlog,
        result.circuit_breaker.threshold
    );
} else {
    for rec in &result.recommendations {
        println!(
            "#{} [{:?}] {}: {}",
            rec.priority, rec.severity,
            rec.source_path.display(), rec.rationale
        );
    }
}
```

### Ignoring the Circuit Breaker

```rust
use apm2_core::refactor_radar::{Radar, RadarConfig};

let config = RadarConfig {
    ignore_breaker: true,
    ..Default::default()
};

let radar = Radar::new(config);
let result = radar.run(std::path::Path::new("/repo/root"))?;

// Recommendations are produced even if backlog is high
assert!(!result.circuit_breaker.is_blocking());
```

## Related Modules

- [`apm2_core::work`](../work/AGENTS.md) - Work item lifecycle; maintenance tickets counted by the circuit breaker
- [`apm2_core::ticket_emitter`](../ticket_emitter/AGENTS.md) - Generates tickets; radar suggests new maintenance tickets
- [`apm2_core::evidence`](../evidence/AGENTS.md) - Evidence publishing; radar results can feed evidence bundles

## References

- [RFC-0019: Automated FAC v0](/documents/rfcs/RFC-0019/) - Factory pipeline context for radar integration
- [APM2 Rust Standards - Security-Adjacent Rust](/documents/skills/rust-standards/references/34_security_adjacent_rust.md) - Path validation and command injection prevention
- [APM2 Rust Standards - Testing Evidence and CI](/documents/skills/rust-standards/references/20_testing_evidence_and_ci.md) - Property-based testing patterns for signal collectors
