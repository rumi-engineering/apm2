# Capsule Module

> Agent process containment boundary with linux-ns-v1 capsule profiles, workspace confinement, and admission gating (RFC-0020 Section 4).

## Overview

The `apm2_core::capsule` module implements the encapsulation boundary for agent processes in the APM2 kernel. It defines the `linux-ns-v1` capsule profile specification -- a content-addressed containment policy that enforces defense-in-depth through multiple security layers:

1. **Namespace isolation** -- Linux user, mount, pid, and net namespaces (all mandatory for linux-ns-v1)
2. **Syscall filtering** -- seccomp-bpf via `SeccompProfileLevel`
3. **Resource limits** -- cgroup controls for CPU, memory, PIDs, and I/O
4. **Network isolation** -- deny-by-default egress with explicit route grants
5. **Workspace confinement** -- lexical path traversal rejection (symlink-safe runtime resolution deferred to TCK-00375)
6. **Environment scrubbing** -- no inherited credentials or host secrets

```text
CapsuleProfileBuilder
       |
       v
CapsuleProfile (content-addressed by BLAKE3 hash)
       |
       v
AdmissionGate::check(profile, tier)
       |
       +--- Ok(()) --> profile admitted for this tier
       +--- Err(AdmissionError) --> rejected
                |
                +--- Tier3+ requires admitted profile hash
                +--- Deny-by-default egress enforced
                +--- All namespaces required for linux-ns-v1

WorkspaceConfinement (fail-closed by construction)
       |
       +--- new(root) --> validates root path
       +--- contains(path) --> validates relative path is confined
       +--- validate_workspace_path(path, confinement) --> resolved PathBuf
```

### Tier Enforcement

- **Tier3+**: MUST execute inside an admitted capsule profile (hard fail)
- **Tier1-Tier2**: Capsule profile is optional but recommended
- **Tier0**: Development mode; capsule is informational only

**Note**: Runtime enforcement is validated in unit tests only. Integration into the daemon actuation path is deferred to TCK-00375 (context firewall) and TCK-00376 (no-bypass path ratchet).

## Key Types

### `CapsuleProfile`

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapsuleProfile {
    pub profile_id: String,
    pub namespaces: NamespaceConfig,
    pub seccomp_level: SeccompProfileLevel,
    pub cgroup_limits: CgroupLimits,
    pub egress_policy: EgressPolicy,
    pub allowed_executables: Vec<String>,
    pub scrub_environment: bool,
    pub readonly_rootfs: bool,
    pub tmpfs_tmp: bool,
    pub profile_hash: [u8; 32],
}
```

**Invariants:**

- [INV-CP01] Capsule profiles are content-addressed: `profile_hash` is computed from a deterministic `HashInput` via BLAKE3.
- [INV-CP02] Deny-by-default egress is mandatory: `egress_policy.deny_by_default` must be `true`.
- [INV-CP03] Escape attempts produce `CapsuleViolation` events.
- [INV-CP04] Tier3+ actuation without an admitted capsule is rejected.

**Contracts:**

- [CTR-CP01] `profile_id` must be non-empty and <= `MAX_PROFILE_ID_LENGTH` (256 bytes).
- [CTR-CP02] All four core namespaces (user, mount, pid, net) must be enabled for linux-ns-v1.
- [CTR-CP03] Seccomp level must be at least `Restricted` for linux-ns-v1.
- [CTR-CP04] Cgroup `memory_limit_bytes`, `pids_max`, and `cpu_quota_us` must all be non-zero.
- [CTR-CP05] Egress routes are bounded to `MAX_EGRESS_ROUTES` (256).
- [CTR-CP06] Allowed executables are bounded to `MAX_ALLOWED_EXECUTABLES` (64).

### `CapsuleProfileBuilder`

```rust
pub struct CapsuleProfileBuilder { /* ... */ }
```

Builder for constructing `CapsuleProfile` instances. Validates all invariants at `build()` time.

**Contracts:**

- [CTR-CP07] `build()` computes the content hash and validates all profile invariants before returning.
- [CTR-CP08] `new(profile_id)` requires a non-empty profile ID.

### `NamespaceConfig`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NamespaceConfig {
    pub user: bool,
    pub mount: bool,
    pub pid: bool,
    pub net: bool,
    pub ipc: bool,
    pub uts: bool,
    pub cgroup: bool,
}
```

**Contracts:**

- [CTR-CP09] `NamespaceConfig::isolated()` returns a config with all namespaces enabled.
- [CTR-CP10] For linux-ns-v1, `user`, `mount`, `pid`, and `net` are mandatory.

### `CgroupLimits`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CgroupLimits {
    pub memory_limit_bytes: u64,
    pub pids_max: u32,
    pub cpu_quota_us: u64,
    pub cpu_period_us: u64,
    pub io_weight: u16,
}
```

**Contracts:**

- [CTR-CP11] `default_restricted()` returns sensible defaults with all fields non-zero.
- [CTR-CP12] `io_weight` must be in the range `1..=10000`.

### `EgressPolicy`

```rust
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EgressPolicy {
    pub deny_by_default: bool,
    pub allowed_routes: Vec<EgressRoute>,
}
```

**Invariants:**

- [INV-CP05] `deny_by_default` must be `true` (fail-closed network security model).

**Contracts:**

- [CTR-CP13] `deny_all()` returns a policy with `deny_by_default: true` and empty `allowed_routes`.
- [CTR-CP14] Allowed routes are bounded to `MAX_EGRESS_ROUTES` (256).

### `EgressRoute`

```rust
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EgressRoute {
    pub host: String,
    pub port: u16,
    pub protocol: String,
}
```

### `AdmissionGate`

```rust
pub struct AdmissionGate { /* ... */ }
```

**Invariants:**

- [INV-CP06] Tier3+ admission is pinned to exact content hash, not profile ID string.

**Contracts:**

- [CTR-CP15] `check(profile, tier)` returns `Ok(())` for Tier0-Tier2 and validates against the admitted hash set for Tier3+.
- [CTR-CP16] `check()` returns `Err(AdmissionError)` with `ProfileNotAdmitted` for Tier3+ profiles whose hash is not in the admitted set.

### `WorkspaceConfinement`

```rust
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct WorkspaceConfinement {
    root: PathBuf,
}
```

**Invariants:**

- [INV-CP07] Fail-closed by construction: the only public constructor is `new()`, which validates the root path.
- [INV-CP08] Deserialization runs the same validation as `new()` (prevents serde bypass of blocked-root checks).
- [INV-CP09] Blocked system directories (`/`, `/etc`, `/var`, `/proc`, etc.) are rejected at construction time.
- [INV-CP10] `ParentDir` (`..`) and `CurDir` (`.`) components in workspace root paths are rejected.

**Contracts:**

- [CTR-CP17] `new(root)` returns `Err` for empty, relative, blocked, or traversal-containing paths.
- [CTR-CP18] `contains(path)` validates that a relative path is safely confined within the workspace root.
- [CTR-CP19] Deserialization of blocked roots (e.g., `"/etc"`) returns an error.

### `WorkspaceConfinementError`

```rust
#[non_exhaustive]
pub enum WorkspaceConfinementError {
    PathTraversal { path: String },
    SymlinkDetected { path: String },
    AbsolutePath { path: String },
    PathTooDeep { depth: usize, max: usize },
    PathTooLong { actual: usize, max: usize },
    BlockedRoot { root: String },
    EmptyRoot,
    NotAbsolute { root: String },
    ForbiddenComponent { component: String },
}
```

### Error Types

- `CapsuleProfileError` -- Profile construction and validation errors.
- `AdmissionError` -- Admission gate check failures.
- `ViolationKind` -- Taxonomy of capsule violation types.

## Public API

### Profile Construction

- `CapsuleProfileBuilder::new(profile_id) -> Self` -- Creates a new builder.
- `CapsuleProfileBuilder::namespaces(config) -> Self` -- Sets namespace configuration.
- `CapsuleProfileBuilder::cgroup_limits(limits) -> Self` -- Sets cgroup limits.
- `CapsuleProfileBuilder::egress_policy(policy) -> Self` -- Sets egress policy.
- `CapsuleProfileBuilder::build() -> Result<CapsuleProfile, CapsuleProfileError>` -- Validates and builds the profile.

### Static Constructors

- `NamespaceConfig::isolated() -> NamespaceConfig` -- All namespaces enabled.
- `CgroupLimits::default_restricted() -> CgroupLimits` -- Sensible restricted defaults.
- `EgressPolicy::deny_all() -> EgressPolicy` -- Deny all egress.

### Admission

- `AdmissionGate::check(profile, tier) -> Result<(), AdmissionError>` -- Checks profile admission for a risk tier.

### Workspace Confinement

- `WorkspaceConfinement::new(root) -> Result<Self, WorkspaceConfinementError>` -- Creates a validated confinement.
- `WorkspaceConfinement::root() -> &Path` -- Returns the workspace root.
- `WorkspaceConfinement::contains(path) -> Result<PathBuf, WorkspaceConfinementError>` -- Validates a relative path.
- `validate_workspace_path(path, confinement) -> Result<PathBuf, WorkspaceConfinementError>` -- Validates a path against a confinement.
- `validate_absolute_within_root(resolved_path, workspace_root) -> Result<(), WorkspaceConfinementError>` -- Post-resolution absolute path check.

### Constants

- `MAX_PROFILE_ID_LENGTH: usize = 256`
- `MAX_EGRESS_ROUTES: usize = 256`
- `MAX_ALLOWED_EXECUTABLES: usize = 64`
- `MAX_WORKSPACE_PATH_DEPTH: usize = 64`

## Examples

### Building a Capsule Profile

```rust
use apm2_core::capsule::{
    CapsuleProfileBuilder, CgroupLimits, EgressPolicy, NamespaceConfig,
};

let profile = CapsuleProfileBuilder::new("linux-ns-v1")
    .namespaces(NamespaceConfig::isolated())
    .cgroup_limits(CgroupLimits::default_restricted())
    .egress_policy(EgressPolicy::deny_all())
    .build()
    .expect("valid capsule profile");

assert!(profile.egress_policy.deny_by_default);
assert!(profile.namespaces.user);
assert!(profile.namespaces.mount);
assert!(profile.namespaces.pid);
```

### Workspace Path Validation

```rust
use std::path::Path;
use apm2_core::capsule::{WorkspaceConfinement, validate_workspace_path};

let ws = WorkspaceConfinement::new("/home/agent/workspace")
    .expect("valid workspace root");

// Valid relative path
let resolved = validate_workspace_path(Path::new("src/main.rs"), &ws).unwrap();
assert_eq!(resolved, Path::new("/home/agent/workspace/src/main.rs"));

// Path traversal rejected
assert!(validate_workspace_path(Path::new("../../../etc/passwd"), &ws).is_err());
```

## Related Modules

- [`apm2_core::adapter::seccomp`](../adapter/AGENTS.md) -- `SeccompProfileLevel` enum used by capsule profiles
- [`apm2_core::crypto`](../crypto/AGENTS.md) -- BLAKE3 hashing for content-addressed profile hashes
- [`apm2_core::config`](../config/AGENTS.md) -- System configuration that references capsule profiles

## References

- RFC-0020: Holonic Substrate Interface (HSI) -- Section 4 defines capsule containment
- RFC-0028: Holonic External I/O Security Profile over PCAC -- REQ-0028 capsule containment with no ambient authority
- [15 -- Errors, Panics, Diagnostics](/documents/skills/rust-standards/references/15_errors_panics_diagnostics.md) -- error type design patterns
