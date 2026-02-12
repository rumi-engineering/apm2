# Model Router Module

> Multi-model routing with configurable YAML profiles, fail-closed fallback semantics, and canary comparison mode for A/B testing.

## Overview

The `apm2_core::model_router` module provides the foundation for routing pipeline stages to appropriate AI providers in the APM2 system. It separates routing logic from execution logic, enabling flexible multi-model orchestration through version-controlled YAML profiles.

The module is organized into three submodules:

1. **`profile`** -- YAML parsing, schema validation, and stage-to-provider configuration mapping
2. **`router`** -- Core routing logic with fail-closed semantics and provider availability checking
3. **`canary`** -- A/B testing mode that executes the same input through two routing configurations and generates diff reports

```text
RoutingProfile (YAML)
       |
       v
ModelRouter<A: ProviderAvailability>
       |
       +--- route_stage(stage) --> RouteResult
       |         |
       |         +--- primary provider available --> direct route
       |         +--- primary unavailable --> stage fallback --> global fallback
       |         +--- all unavailable --> RouterError (fail-closed)
       |
       +--- route_stages([stages]) --> Vec<(stage, Result<RouteResult>)>

CanaryRunner<E: StageExecutor>
       |
       +--- run_stage(stage, input) --> StageCanaryResult
       +--- run_all(inputs) --> CanaryReport
                |
                +--- DiffSummary (lines added/removed/modified)
                +--- CanarySummary (totals, timing diff)
```

### Design Principles

- **Fail-closed**: If a provider is unavailable and no fallback is configured, the router returns an error rather than silently degrading.
- **Canary mode is opt-in**: Runs both routes sequentially to compare outputs.
- **Routing profiles are version-controlled**: YAML files enable reproducible configurations across environments.
- **Immutable after construction**: Routers do not mutate their profile after creation.

## Key Types

### `RoutingProfile`

```rust
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RoutingProfile {
    pub profile_id: String,
    pub description: String,
    pub version: String,
    pub stages: HashMap<String, ProviderConfig>,
    pub fallback: Option<GlobalFallback>,
    pub canary: Option<CanaryConfig>,
}
```

**Invariants:**

- [INV-MR01] Profile IDs match `^[a-z][a-z0-9_-]*$` and are at most 64 characters.
- [INV-MR02] All stage configurations have a valid provider.
- [INV-MR03] Parsed profiles are immutable after loading.
- [INV-MR04] Timeout values are within `1000..=600_000` ms.

**Contracts:**

- [CTR-MR01] `validate()` rejects empty stages, invalid profile IDs, out-of-range timeouts, and excessive retry counts.
- [CTR-MR02] `get_stage_config(stage)` returns `None` for undefined stages.
- [CTR-MR03] `stage_names()` returns a sorted list.

### `ProviderConfig`

```rust
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProviderConfig {
    pub provider: String,
    pub model: Option<String>,
    pub endpoint: Option<String>,
    pub timeout_ms: u64,
    pub retry_policy: RetryPolicy,
    pub stage_fallback: Option<StageFallback>,
}
```

### `RetryPolicy`

```rust
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetryPolicy {
    pub max_retries: u32,        // default: 3, max: 10
    pub initial_delay_ms: u64,   // default: 1000
    pub backoff_multiplier: f64, // default: 2.0
}
```

**Contracts:**

- [CTR-MR04] `max_retries` is bounded to `MAX_ALLOWED_RETRIES` (10).

### `StageFallback`

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageFallback {
    pub provider: String,
    pub model: Option<String>,
    pub timeout_ms: u64,
}
```

### `GlobalFallback`

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GlobalFallback {
    pub provider: String,
    pub model: Option<String>,
    pub timeout_ms: u64,
    pub reason: Option<String>,
}
```

### `ModelRouter<A: ProviderAvailability>`

```rust
#[derive(Debug)]
pub struct ModelRouter<A: ProviderAvailability = DefaultProviderAvailability> {
    profile: RoutingProfile,
    availability: A,
}
```

**Invariants:**

- [INV-MR05] Router is immutable after construction.
- [INV-MR06] Fail-closed: no implicit fallbacks; undefined stages return `StageNotFound`.
- [INV-MR07] Provider availability is checked before routing.

**Contracts:**

- [CTR-MR05] `route_stage(stage)` follows the fallback chain: primary -> stage fallback -> global fallback -> error.
- [CTR-MR06] `ProviderStatus::Unknown` is treated as available (optimistic).

### `ProviderAvailability` (trait)

```rust
pub trait ProviderAvailability: Send + Sync {
    fn check_availability(&self, provider: &str, endpoint: Option<&str>) -> ProviderStatus;
}
```

### `ProviderStatus`

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderStatus {
    Available,
    Unavailable(String),
    Unknown,
}
```

### `RouteResult`

```rust
#[derive(Debug, Clone)]
pub struct RouteResult {
    pub config: ProviderConfig,
    pub is_fallback: bool,
    pub fallback_reason: Option<String>,
}
```

### `CanaryRunner<E: StageExecutor>`

```rust
pub struct CanaryRunner<E: StageExecutor> {
    primary_router: ModelRouter<DefaultProviderAvailability>,
    comparison_router: ModelRouter<DefaultProviderAvailability>,
    canary_config: CanaryConfig,
    executor: E,
}
```

**Invariants:**

- [INV-MR08] Both routes are executed sequentially (not parallel).
- [INV-MR09] Timing is captured independently for each route.
- [INV-MR10] Diffs are generated only if `output_diffs` is enabled in canary config.

### `StageExecutor` (trait)

```rust
pub trait StageExecutor: Send + Sync {
    fn execute(&self, stage: &str, config: &ProviderConfig, input: &str) -> Result<String, String>;
}
```

### `CanaryReport`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanaryReport {
    pub report_id: String,
    pub primary_profile_id: String,
    pub comparison_profile_id: String,
    pub generated_at: DateTime<Utc>,
    pub stages: Vec<StageCanaryResult>,
    pub summary: CanarySummary,
}
```

### `CanarySummary`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanarySummary {
    pub total_stages: usize,
    pub identical_stages: usize,
    pub different_stages: usize,
    pub primary_failures: usize,
    pub comparison_failures: usize,
    pub avg_timing_diff: Duration,
}
```

### `StageCanaryResult`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageCanaryResult {
    pub stage: String,
    pub primary: RouteExecution,
    pub comparison: RouteExecution,
    pub diff: DiffSummary,
}
```

### `DiffSummary`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffSummary {
    pub lines_added: usize,
    pub lines_removed: usize,
    pub lines_modified: usize,
    pub identical: bool,
    pub entries: Vec<DiffEntry>,
}
```

### `DiffType`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiffType {
    Added,
    Removed,
    Modified,
}
```

### Error Types

- `RouterError` -- Stage not found, provider unavailable, no fallback, fallback unavailable.
- `ProfileError` -- File read errors, YAML parse errors, validation failures, path traversal.
- `CanaryError` -- Routing errors, canary not configured, execution failures.

## Public API

### Profile Loading

- `load_profile(path) -> Result<RoutingProfile, ProfileError>` -- Loads from a YAML file with size bounds and path validation.
- `load_profile_by_id(repo_root, profile_id) -> Result<RoutingProfile, ProfileError>` -- Loads from the standard profiles directory.

### Router

- `ModelRouter::from_file(path) -> Result<Self, RouterError>` -- Creates from a file path.
- `ModelRouter::from_profile_id(repo_root, profile_id) -> Result<Self, RouterError>` -- Creates from a profile ID.
- `ModelRouter::from_profile(profile) -> Self` -- Creates from an existing profile.
- `ModelRouter::with_availability(profile, availability) -> Self` -- Creates with a custom availability checker.
- `ModelRouter::route_stage(stage) -> Result<RouteResult, RouterError>` -- Routes a single stage.
- `ModelRouter::route_stages(stages) -> Vec<(&str, Result<RouteResult, RouterError>)>` -- Routes multiple stages.
- `ModelRouter::has_stage(stage) -> bool` -- Checks if a stage is defined.
- `ModelRouter::stage_names() -> Vec<&str>` -- Returns all stage names.
- `ModelRouter::profile() -> &RoutingProfile` -- Returns the loaded profile.
- `ModelRouter::profile_id() -> &str` -- Returns the profile ID.

### Canary

- `create_canary_runner(repo_root, primary_id, comparison_id, executor) -> Result<CanaryRunner<E>, CanaryError>` -- Creates a canary runner from profile IDs.
- `CanaryRunner::new(primary, comparison, config, executor) -> Self` -- Creates from existing profiles.
- `CanaryRunner::run_stage(stage, input) -> Result<StageCanaryResult, CanaryError>` -- Runs canary for one stage.
- `CanaryRunner::run_all(inputs) -> CanaryReport` -- Runs canary for all configured stages.

## Examples

### Loading a Profile and Routing

```rust
use std::path::Path;
use apm2_core::model_router::{ModelRouter, load_profile};

let profile = load_profile(Path::new("profiles/local.yaml")).unwrap();
let router = ModelRouter::from_profile(profile);

let result = router.route_stage("impact_map").unwrap();
println!("Provider: {}", result.config.provider);
if result.is_fallback {
    println!("Fallback reason: {:?}", result.fallback_reason);
}
```

### Running a Canary Comparison

```rust
use std::collections::HashMap;
use apm2_core::model_router::{MockStageExecutor, create_canary_runner};

let runner = create_canary_runner(
    Path::new("/repo"),
    "local",
    "production",
    MockStageExecutor,
).unwrap();

let mut inputs = HashMap::new();
inputs.insert("impact_map".to_string(), "input data".to_string());

let report = runner.run_all(&inputs);
println!("Stages compared: {}", report.summary.total_stages);
println!("Identical: {}", report.summary.identical_stages);
```

## Related Modules

- [`apm2_core::run_manifest`](../run_manifest/AGENTS.md) -- Captures routing decisions in signed execution manifests
- [`apm2_core::config`](../config/AGENTS.md) -- System configuration referencing routing profiles

## References

- [SEC-ROUTER-001] Profile file reads are bounded to 1 MB to prevent DoS
- [SEC-ROUTER-002] Path traversal is prevented in profile paths via component analysis
- [SEC-ROUTER-003] Profile IDs are validated against `^[a-z][a-z0-9_-]*$`
- [25 -- API Design, stdlib Quality](/documents/skills/rust-standards/references/25_api_design_stdlib_quality.md) -- trait design for `ProviderAvailability` and `StageExecutor`
