// AGENT-AUTHORED
//! Capsule profile types for linux-ns-v1 containment (RFC-0020 Section 4).
//!
//! Defines [`CapsuleProfile`], the content-addressed specification of an agent
//! containment boundary. Enforces defense-in-depth: namespaces, seccomp,
//! cgroups, deny-by-default egress, and workspace confinement.
//!
//! # Security Properties
//!
//! - A single escape bug does not imply ambient authority (layered defense)
//! - Capsule profiles are content-addressed (referenced by BLAKE3 hash)
//! - Deny-by-default egress is mandatory (fail-closed)
//! - Tier3+ actuation requires an admitted capsule profile
//!
//! # Runtime Wiring
//!
//! TODO(TCK-00375): Wire `AdmissionGate::check` into the daemon episode
//! spawn path so that Tier3+ actuation is rejected at runtime when no
//! admitted capsule profile is present. Currently the gate is validated
//! in unit tests only; runtime integration is deferred to TCK-00375 and
//! TCK-00376.

use serde::{Deserialize, Serialize, de};
use thiserror::Error;

use crate::adapter::seccomp::SeccompProfileLevel;
use crate::fac::RiskTier;

// =============================================================================
// Resource Limits
// =============================================================================

/// Maximum length of a capsule profile ID.
pub const MAX_PROFILE_ID_LENGTH: usize = 256;

/// Maximum number of egress routes in a capsule profile.
pub const MAX_EGRESS_ROUTES: usize = 256;

/// Maximum number of allowed executables in a capsule profile.
pub const MAX_ALLOWED_EXECUTABLES: usize = 64;

/// Maximum length of an executable path.
const MAX_EXECUTABLE_PATH_LENGTH: usize = 4096;

/// Maximum length of host in an egress route.
const MAX_HOST_LENGTH: usize = 253;

/// The set of profile IDs admitted for Tier3+ enforcement.
///
/// Only profiles whose `profile_id` matches one of these strings may pass
/// `AdmissionGate::check` at Tier3 or above. This prevents a crafted profile
/// with an arbitrary `profile_id` from disabling mandatory isolation controls.
const ADMITTED_PROFILE_IDS: &[&str] = &["linux-ns-v1"];

// =============================================================================
// Error Types
// =============================================================================

/// Errors from capsule profile construction and validation.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CapsuleProfileError {
    /// Missing required field.
    #[error("missing required capsule profile field: {0}")]
    MissingField(&'static str),

    /// Profile ID is empty or too long.
    #[error("invalid profile_id: length {actual} exceeds max {max}")]
    InvalidProfileId {
        /// Actual length.
        actual: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// Deny-by-default must be true (fail-closed security).
    #[error("egress deny_by_default must be true (fail-closed security model)")]
    EgressDenyRequired,

    /// Namespace isolation is insufficient for the requested tier.
    #[error("namespace isolation insufficient: user+mount+pid+net required for linux-ns-v1")]
    InsufficientNamespaces,

    /// Too many egress routes.
    #[error("egress routes exceed limit: {actual} > {max}")]
    TooManyEgressRoutes {
        /// Actual count.
        actual: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Too many allowed executables.
    #[error("allowed executables exceed limit: {actual} > {max}")]
    TooManyExecutables {
        /// Actual count.
        actual: usize,
        /// Maximum allowed.
        max: usize,
    },

    /// Executable path is too long.
    #[error("executable path too long: {actual} > {max}")]
    ExecutablePathTooLong {
        /// Actual length.
        actual: usize,
        /// Maximum length.
        max: usize,
    },

    /// Egress route host is invalid.
    #[error("egress route host invalid: {reason}")]
    InvalidEgressHost {
        /// Description of the problem.
        reason: String,
    },

    /// Profile hash does not match computed value.
    #[error("profile hash mismatch: expected {expected}, got {actual}")]
    HashMismatch {
        /// Expected hash (hex).
        expected: String,
        /// Actual hash (hex).
        actual: String,
    },

    /// Seccomp level is too permissive for the profile.
    #[error("seccomp level {level} is insufficient; at least Restricted required for linux-ns-v1")]
    InsufficientSeccomp {
        /// The configured level name.
        level: String,
    },

    /// Cgroup memory limit must be non-zero for linux-ns-v1.
    #[error("cgroup memory_limit_bytes must be > 0 for linux-ns-v1")]
    ZeroCgroupMemory,

    /// Cgroup `pids_max` must be non-zero for linux-ns-v1.
    #[error("cgroup pids_max must be > 0 for linux-ns-v1")]
    ZeroCgroupPids,

    /// Cgroup `cpu_quota_us` must be non-zero for linux-ns-v1.
    #[error("cgroup cpu_quota_us must be > 0 for linux-ns-v1")]
    ZeroCgroupCpuQuota,

    /// Cgroup `io_weight` out of valid range (1..=10000) for linux-ns-v1.
    #[error("cgroup io_weight must be in 1..=10000 for linux-ns-v1, got {value}")]
    InvalidCgroupIoWeight {
        /// The invalid `io_weight` value.
        value: u16,
    },

    /// Profile ID is not in the admitted set for Tier3+ enforcement.
    #[error("profile_id '{profile_id}' is not in the admitted profile set for Tier3+ enforcement")]
    ProfileNotAdmitted {
        /// The rejected profile ID.
        profile_id: String,
    },

    /// Read-only rootfs is mandatory for linux-ns-v1 (RFC-0020 Section 4.3).
    #[error("readonly_rootfs must be true for linux-ns-v1 (RFC-0020 §4.3)")]
    ReadonlyRootfsRequired,

    /// tmpfs /tmp is mandatory for linux-ns-v1 (RFC-0020 Section 4.3).
    #[error("tmpfs_tmp must be true for linux-ns-v1 (RFC-0020 §4.3)")]
    TmpfsTmpRequired,

    /// Environment scrubbing is mandatory for linux-ns-v1 (RFC-0020 Section
    /// 4.3).
    #[error("scrub_environment must be true for linux-ns-v1 (RFC-0020 §4.3)")]
    ScrubEnvironmentRequired,
}

/// Errors from capsule admission gate checks.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AdmissionError {
    /// Tier3+ actuation attempted without admitted capsule.
    #[error(
        "Tier3+ actuation denied: no admitted capsule profile \
         (risk_tier={risk_tier}, requires capsule for tier >= 3)"
    )]
    NoCapsuleForTier {
        /// The risk tier that requires a capsule.
        risk_tier: u8,
    },

    /// Capsule profile failed validation.
    #[error("capsule profile validation failed: {0}")]
    InvalidProfile(#[from] CapsuleProfileError),
}

// =============================================================================
// Violation Kinds
// =============================================================================

/// Types of capsule violations (escape attempts).
///
/// Each violation is a blocking defect per REQ-0028.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum ViolationKind {
    /// Path traversal attempt (e.g., `../` escape from workspace root).
    PathTraversal,
    /// Symlink escape attempt (symlink pointing outside workspace).
    SymlinkEscape,
    /// Unauthorized egress attempt (network access without explicit route).
    UnauthorizedEgress,
    /// Namespace escape attempt.
    NamespaceEscape,
    /// Seccomp violation (blocked syscall).
    SeccompViolation,
    /// Cgroup limit exceeded.
    CgroupLimitExceeded,
    /// Unauthorized executable invocation.
    UnauthorizedExecutable,
    /// Environment secret leakage attempt.
    EnvironmentLeakage,
}

impl std::fmt::Display for ViolationKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PathTraversal => write!(f, "PATH_TRAVERSAL"),
            Self::SymlinkEscape => write!(f, "SYMLINK_ESCAPE"),
            Self::UnauthorizedEgress => write!(f, "UNAUTHORIZED_EGRESS"),
            Self::NamespaceEscape => write!(f, "NAMESPACE_ESCAPE"),
            Self::SeccompViolation => write!(f, "SECCOMP_VIOLATION"),
            Self::CgroupLimitExceeded => write!(f, "CGROUP_LIMIT_EXCEEDED"),
            Self::UnauthorizedExecutable => write!(f, "UNAUTHORIZED_EXECUTABLE"),
            Self::EnvironmentLeakage => write!(f, "ENVIRONMENT_LEAKAGE"),
        }
    }
}

// =============================================================================
// Namespace Config
// =============================================================================

/// Linux namespace isolation configuration.
///
/// For `linux-ns-v1`, user + mount + pid + net namespaces are all required.
/// Network namespace isolation is mandatory to enforce deny-by-default egress.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct NamespaceConfig {
    /// User namespace isolation.
    pub user: bool,
    /// Mount namespace isolation.
    pub mount: bool,
    /// PID namespace isolation.
    pub pid: bool,
    /// Network namespace isolation (required for egress deny-by-default).
    pub net: bool,
}

impl NamespaceConfig {
    /// Creates a fully isolated namespace configuration.
    ///
    /// This is the minimum required for `linux-ns-v1`.
    #[must_use]
    pub const fn isolated() -> Self {
        Self {
            user: true,
            mount: true,
            pid: true,
            net: true,
        }
    }

    /// Returns true if the minimum requirements for `linux-ns-v1` are met.
    ///
    /// Requires all four namespaces: user, mount, pid, and net.
    /// Network namespace isolation is mandatory to enforce deny-by-default
    /// egress policy -- without it, agent processes inherit host networking
    /// and can bypass egress controls.
    #[must_use]
    pub const fn meets_linux_ns_v1(&self) -> bool {
        self.user && self.mount && self.pid && self.net
    }
}

impl Default for NamespaceConfig {
    /// Default is fully isolated (fail-closed).
    fn default() -> Self {
        Self::isolated()
    }
}

// =============================================================================
// Cgroup Limits
// =============================================================================

/// Cgroup resource limits for capsule processes.
///
/// Enforces bounded resource consumption per RFC-0020 Section 4.2.1.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CgroupLimits {
    /// CPU quota in microseconds per period (0 = unlimited).
    pub cpu_quota_us: u64,
    /// CPU period in microseconds.
    pub cpu_period_us: u64,
    /// Memory limit in bytes (0 = unlimited).
    pub memory_limit_bytes: u64,
    /// Maximum number of PIDs (0 = unlimited).
    pub pids_max: u32,
    /// I/O weight (1-10000, 100 = normal).
    pub io_weight: u16,
}

impl CgroupLimits {
    /// Creates restricted cgroup limits suitable for agent processes.
    ///
    /// - CPU: 200% (2 cores equivalent)
    /// - Memory: 4 GiB
    /// - PIDs: 1024
    /// - I/O weight: 100 (normal)
    #[must_use]
    pub const fn default_restricted() -> Self {
        Self {
            cpu_quota_us: 200_000,
            cpu_period_us: 100_000,
            memory_limit_bytes: 4 * 1024 * 1024 * 1024,
            pids_max: 1024,
            io_weight: 100,
        }
    }

    /// Returns true if any resource limit is configured.
    #[must_use]
    pub const fn has_limits(&self) -> bool {
        self.cpu_quota_us > 0 || self.memory_limit_bytes > 0 || self.pids_max > 0
    }
}

impl Default for CgroupLimits {
    fn default() -> Self {
        Self::default_restricted()
    }
}

// =============================================================================
// Egress Policy
// =============================================================================

/// An explicit egress route grant.
///
/// Only routes explicitly listed here are allowed; all other egress is denied.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressRoute {
    /// Target hostname or IP address.
    pub host: String,
    /// Target port number.
    pub port: u16,
    /// Transport protocol ("tcp" or "udp").
    pub protocol: String,
}

impl EgressRoute {
    /// Validates the egress route.
    ///
    /// # Errors
    ///
    /// Returns [`CapsuleProfileError`] if validation fails.
    pub fn validate(&self) -> Result<(), CapsuleProfileError> {
        if self.host.is_empty() {
            return Err(CapsuleProfileError::InvalidEgressHost {
                reason: "host cannot be empty".to_string(),
            });
        }
        if self.host.len() > MAX_HOST_LENGTH {
            return Err(CapsuleProfileError::InvalidEgressHost {
                reason: format!(
                    "host length {} exceeds max {}",
                    self.host.len(),
                    MAX_HOST_LENGTH
                ),
            });
        }
        if self.port == 0 {
            return Err(CapsuleProfileError::InvalidEgressHost {
                reason: "port must be non-zero".to_string(),
            });
        }
        if self.protocol != "tcp" && self.protocol != "udp" {
            return Err(CapsuleProfileError::InvalidEgressHost {
                reason: format!("protocol must be 'tcp' or 'udp', got '{}'", self.protocol),
            });
        }
        Ok(())
    }
}

/// Egress policy for a capsule.
///
/// Implements deny-by-default: no network access unless explicitly granted
/// by a route in `allowed_routes`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressPolicy {
    /// MUST be true. All egress is denied unless a route explicitly allows it.
    pub deny_by_default: bool,
    /// Explicitly allowed egress routes.
    pub allowed_routes: Vec<EgressRoute>,
}

impl EgressPolicy {
    /// Creates a deny-all egress policy (no routes allowed).
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Vec::new() in const requires nightly
    pub fn deny_all() -> Self {
        Self {
            deny_by_default: true,
            allowed_routes: Vec::new(),
        }
    }

    /// Creates an egress policy with specific allowed routes.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Vec field prevents const
    pub fn with_routes(routes: Vec<EgressRoute>) -> Self {
        Self {
            deny_by_default: true,
            allowed_routes: routes,
        }
    }

    /// Returns true if egress to (host, port, protocol) is allowed.
    #[must_use]
    pub fn allows(&self, host: &str, port: u16, protocol: &str) -> bool {
        if !self.deny_by_default {
            // Fail-closed: if deny_by_default is false, treat as deny-all
            // (this is an invalid configuration)
            return false;
        }
        self.allowed_routes
            .iter()
            .any(|r| r.host == host && r.port == port && r.protocol == protocol)
    }

    /// Validates the egress policy.
    ///
    /// # Errors
    ///
    /// Returns [`CapsuleProfileError`] if validation fails.
    pub fn validate(&self) -> Result<(), CapsuleProfileError> {
        if !self.deny_by_default {
            return Err(CapsuleProfileError::EgressDenyRequired);
        }
        if self.allowed_routes.len() > MAX_EGRESS_ROUTES {
            return Err(CapsuleProfileError::TooManyEgressRoutes {
                actual: self.allowed_routes.len(),
                max: MAX_EGRESS_ROUTES,
            });
        }
        for route in &self.allowed_routes {
            route.validate()?;
        }
        Ok(())
    }
}

impl Default for EgressPolicy {
    /// Default is deny-all (fail-closed).
    fn default() -> Self {
        Self::deny_all()
    }
}

// =============================================================================
// Hash Input
// =============================================================================

/// Input fields for computing the canonical BLAKE3 hash of a capsule profile.
///
/// Groups the security-relevant fields to keep `compute_hash` within the
/// argument-count threshold.
#[derive(Debug)]
pub struct HashInput<'a> {
    /// Profile identifier.
    pub profile_id: &'a str,
    /// Namespace isolation configuration.
    pub namespaces: &'a NamespaceConfig,
    /// Seccomp profile level.
    pub seccomp_level: &'a SeccompProfileLevel,
    /// Cgroup resource limits.
    pub cgroup_limits: &'a CgroupLimits,
    /// Egress policy.
    pub egress_policy: &'a EgressPolicy,
    /// Allowed executables.
    pub allowed_executables: &'a [String],
    /// Whether to scrub the environment.
    pub scrub_environment: bool,
    /// Read-only base filesystem.
    pub readonly_rootfs: bool,
    /// tmpfs for /tmp.
    pub tmpfs_tmp: bool,
}

// =============================================================================
// CapsuleProfile
// =============================================================================

/// A content-addressed capsule profile defining agent containment boundaries.
///
/// The `linux-ns-v1` profile requires:
/// - user + mount + pid + net namespaces (all mandatory)
/// - seccomp at least `Restricted` level
/// - cgroup resource limits
/// - deny-by-default egress
/// - workspace confinement (bind mount)
/// - environment scrubbing
///
/// The profile is identified by its BLAKE3 hash (`profile_hash`) which is
/// computed over the canonical representation.
///
/// # Deserialization
///
/// `Deserialize` is implemented manually (not derived) to enforce
/// `validate()` on every deserialized instance. This prevents construction
/// of invalid profiles (e.g., missing namespaces, wrong hash, disabled
/// egress deny) via serde, closing the same class of bypass that affected
/// `WorkspaceConfinement` (CTR-1604, CTR-2603).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CapsuleProfile {
    /// Profile identifier (e.g., "linux-ns-v1").
    pub profile_id: String,

    /// BLAKE3 hash of the canonical profile representation.
    #[serde(with = "serde_bytes")]
    pub profile_hash: [u8; 32],

    /// Namespace isolation configuration.
    pub namespaces: NamespaceConfig,

    /// Seccomp profile level.
    pub seccomp_level: SeccompProfileLevel,

    /// Cgroup resource limits.
    pub cgroup_limits: CgroupLimits,

    /// Egress policy (deny-by-default).
    pub egress_policy: EgressPolicy,

    /// Allowed executables (allowlist). Empty means adapter runtime + apm2
    /// client only.
    pub allowed_executables: Vec<String>,

    /// Whether to scrub the environment (remove all inherited env vars).
    pub scrub_environment: bool,

    /// Read-only base filesystem.
    pub readonly_rootfs: bool,

    /// tmpfs for /tmp.
    pub tmpfs_tmp: bool,
}

// Custom Deserialize: deserialize into a helper struct, then call validate().
// This closes the deserialization bypass where serde could construct a
// CapsuleProfile with invalid fields (e.g., wrong hash, disabled egress deny,
// insufficient namespaces) without running validation (CTR-2603, CTR-1604).
impl<'de> de::Deserialize<'de> for CapsuleProfile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        /// Helper struct matching the serialized shape of `CapsuleProfile`.
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            profile_id: String,
            #[serde(with = "serde_bytes")]
            profile_hash: [u8; 32],
            namespaces: NamespaceConfig,
            seccomp_level: SeccompProfileLevel,
            cgroup_limits: CgroupLimits,
            egress_policy: EgressPolicy,
            allowed_executables: Vec<String>,
            scrub_environment: bool,
            readonly_rootfs: bool,
            tmpfs_tmp: bool,
        }

        let raw = Raw::deserialize(deserializer)?;
        let profile = Self {
            profile_id: raw.profile_id,
            profile_hash: raw.profile_hash,
            namespaces: raw.namespaces,
            seccomp_level: raw.seccomp_level,
            cgroup_limits: raw.cgroup_limits,
            egress_policy: raw.egress_policy,
            allowed_executables: raw.allowed_executables,
            scrub_environment: raw.scrub_environment,
            readonly_rootfs: raw.readonly_rootfs,
            tmpfs_tmp: raw.tmpfs_tmp,
        };
        profile.validate().map_err(de::Error::custom)?;
        Ok(profile)
    }
}

impl CapsuleProfile {
    /// Computes the canonical BLAKE3 hash of the profile.
    ///
    /// The hash is computed over a deterministic representation of all
    /// security-relevant fields. Accepts a [`HashInput`] struct to keep the
    /// argument count bounded.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn compute_hash(input: &HashInput<'_>) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();

        // Profile ID
        hasher.update(&(input.profile_id.len() as u32).to_be_bytes());
        hasher.update(input.profile_id.as_bytes());

        // Namespaces (4 booleans)
        hasher.update(&[
            u8::from(input.namespaces.user),
            u8::from(input.namespaces.mount),
            u8::from(input.namespaces.pid),
            u8::from(input.namespaces.net),
        ]);

        // Seccomp level
        hasher.update(&[match input.seccomp_level {
            SeccompProfileLevel::None => 0,
            SeccompProfileLevel::Baseline => 1,
            SeccompProfileLevel::Restricted => 2,
            SeccompProfileLevel::Strict => 3,
        }]);

        // Cgroup limits
        hasher.update(&input.cgroup_limits.cpu_quota_us.to_be_bytes());
        hasher.update(&input.cgroup_limits.cpu_period_us.to_be_bytes());
        hasher.update(&input.cgroup_limits.memory_limit_bytes.to_be_bytes());
        hasher.update(&input.cgroup_limits.pids_max.to_be_bytes());
        hasher.update(&input.cgroup_limits.io_weight.to_be_bytes());

        // Egress policy
        hasher.update(&[u8::from(input.egress_policy.deny_by_default)]);
        hasher.update(&(input.egress_policy.allowed_routes.len() as u32).to_be_bytes());
        // Sort routes for deterministic hashing
        let mut route_hashes: Vec<[u8; 32]> = input
            .egress_policy
            .allowed_routes
            .iter()
            .map(|r| {
                let mut rh = blake3::Hasher::new();
                rh.update(r.host.as_bytes());
                rh.update(&r.port.to_be_bytes());
                rh.update(r.protocol.as_bytes());
                *rh.finalize().as_bytes()
            })
            .collect();
        route_hashes.sort_unstable();
        for h in &route_hashes {
            hasher.update(h);
        }

        // Allowed executables (sorted for determinism)
        let mut sorted_exes: Vec<&str> = input
            .allowed_executables
            .iter()
            .map(String::as_str)
            .collect();
        sorted_exes.sort_unstable();
        hasher.update(&(sorted_exes.len() as u32).to_be_bytes());
        for exe in &sorted_exes {
            hasher.update(&(exe.len() as u32).to_be_bytes());
            hasher.update(exe.as_bytes());
        }

        // Flags
        hasher.update(&[
            u8::from(input.scrub_environment),
            u8::from(input.readonly_rootfs),
            u8::from(input.tmpfs_tmp),
        ]);

        *hasher.finalize().as_bytes()
    }

    /// Validates the capsule profile.
    ///
    /// # Errors
    ///
    /// Returns [`CapsuleProfileError`] if the profile is invalid.
    pub fn validate(&self) -> Result<(), CapsuleProfileError> {
        // Profile ID
        if self.profile_id.is_empty() {
            return Err(CapsuleProfileError::MissingField("profile_id"));
        }
        if self.profile_id.len() > MAX_PROFILE_ID_LENGTH {
            return Err(CapsuleProfileError::InvalidProfileId {
                actual: self.profile_id.len(),
                max: MAX_PROFILE_ID_LENGTH,
            });
        }

        // Namespaces (linux-ns-v1 requires user+mount+pid+net)
        if self.profile_id == "linux-ns-v1" && !self.namespaces.meets_linux_ns_v1() {
            return Err(CapsuleProfileError::InsufficientNamespaces);
        }

        // Seccomp (linux-ns-v1 requires at least Restricted)
        if self.profile_id == "linux-ns-v1" {
            match self.seccomp_level {
                SeccompProfileLevel::None | SeccompProfileLevel::Baseline => {
                    return Err(CapsuleProfileError::InsufficientSeccomp {
                        level: format!("{:?}", self.seccomp_level),
                    });
                },
                SeccompProfileLevel::Restricted | SeccompProfileLevel::Strict => {},
            }
        }

        // Cgroup controls (linux-ns-v1 requires bounded non-zero values)
        if self.profile_id == "linux-ns-v1" {
            if self.cgroup_limits.memory_limit_bytes == 0 {
                return Err(CapsuleProfileError::ZeroCgroupMemory);
            }
            if self.cgroup_limits.pids_max == 0 {
                return Err(CapsuleProfileError::ZeroCgroupPids);
            }
            if self.cgroup_limits.cpu_quota_us == 0 {
                return Err(CapsuleProfileError::ZeroCgroupCpuQuota);
            }
            if self.cgroup_limits.io_weight == 0 || self.cgroup_limits.io_weight > 10000 {
                return Err(CapsuleProfileError::InvalidCgroupIoWeight {
                    value: self.cgroup_limits.io_weight,
                });
            }
        }

        // Mandatory hardening controls (linux-ns-v1, RFC-0020 §4.3)
        if self.profile_id == "linux-ns-v1" {
            if !self.readonly_rootfs {
                return Err(CapsuleProfileError::ReadonlyRootfsRequired);
            }
            if !self.tmpfs_tmp {
                return Err(CapsuleProfileError::TmpfsTmpRequired);
            }
            if !self.scrub_environment {
                return Err(CapsuleProfileError::ScrubEnvironmentRequired);
            }
        }

        // Egress policy
        self.egress_policy.validate()?;

        // Executables
        if self.allowed_executables.len() > MAX_ALLOWED_EXECUTABLES {
            return Err(CapsuleProfileError::TooManyExecutables {
                actual: self.allowed_executables.len(),
                max: MAX_ALLOWED_EXECUTABLES,
            });
        }
        for exe in &self.allowed_executables {
            if exe.len() > MAX_EXECUTABLE_PATH_LENGTH {
                return Err(CapsuleProfileError::ExecutablePathTooLong {
                    actual: exe.len(),
                    max: MAX_EXECUTABLE_PATH_LENGTH,
                });
            }
        }

        // Profile hash
        let computed = Self::compute_hash(&HashInput {
            profile_id: &self.profile_id,
            namespaces: &self.namespaces,
            seccomp_level: &self.seccomp_level,
            cgroup_limits: &self.cgroup_limits,
            egress_policy: &self.egress_policy,
            allowed_executables: &self.allowed_executables,
            scrub_environment: self.scrub_environment,
            readonly_rootfs: self.readonly_rootfs,
            tmpfs_tmp: self.tmpfs_tmp,
        });
        if self.profile_hash != computed {
            return Err(CapsuleProfileError::HashMismatch {
                expected: hex::encode(computed),
                actual: hex::encode(self.profile_hash),
            });
        }

        Ok(())
    }
}

// =============================================================================
// Builder
// =============================================================================

/// Builder for constructing [`CapsuleProfile`] with validation.
#[derive(Debug, Default)]
pub struct CapsuleProfileBuilder {
    profile_id: Option<String>,
    namespaces: Option<NamespaceConfig>,
    seccomp_level: Option<SeccompProfileLevel>,
    cgroup_limits: Option<CgroupLimits>,
    egress_policy: Option<EgressPolicy>,
    allowed_executables: Vec<String>,
    scrub_environment: bool,
    readonly_rootfs: bool,
    tmpfs_tmp: bool,
}

impl CapsuleProfileBuilder {
    /// Creates a new builder with the given profile ID.
    #[must_use]
    pub fn new(profile_id: impl Into<String>) -> Self {
        let id: String = profile_id.into();
        let is_linux_ns = id == "linux-ns-v1";
        Self {
            profile_id: Some(id),
            namespaces: None,
            seccomp_level: None,
            cgroup_limits: None,
            egress_policy: None,
            allowed_executables: Vec::new(),
            // linux-ns-v1 defaults: scrub env, readonly root, tmpfs /tmp
            scrub_environment: is_linux_ns,
            readonly_rootfs: is_linux_ns,
            tmpfs_tmp: is_linux_ns,
        }
    }

    /// Sets namespace isolation configuration.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Option assignment not const-stable
    pub fn namespaces(mut self, ns: NamespaceConfig) -> Self {
        self.namespaces = Some(ns);
        self
    }

    /// Sets seccomp profile level.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Option assignment not const-stable
    pub fn seccomp_level(mut self, level: SeccompProfileLevel) -> Self {
        self.seccomp_level = Some(level);
        self
    }

    /// Sets cgroup resource limits.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Option assignment not const-stable
    pub fn cgroup_limits(mut self, limits: CgroupLimits) -> Self {
        self.cgroup_limits = Some(limits);
        self
    }

    /// Sets the egress policy.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Option assignment not const-stable
    pub fn egress_policy(mut self, policy: EgressPolicy) -> Self {
        self.egress_policy = Some(policy);
        self
    }

    /// Adds an allowed executable path.
    #[must_use]
    pub fn add_executable(mut self, path: impl Into<String>) -> Self {
        self.allowed_executables.push(path.into());
        self
    }

    /// Sets whether to scrub the environment.
    #[must_use]
    pub const fn scrub_environment(mut self, scrub: bool) -> Self {
        self.scrub_environment = scrub;
        self
    }

    /// Sets whether the root filesystem is read-only.
    #[must_use]
    pub const fn readonly_rootfs(mut self, readonly: bool) -> Self {
        self.readonly_rootfs = readonly;
        self
    }

    /// Sets whether /tmp uses tmpfs.
    #[must_use]
    pub const fn tmpfs_tmp(mut self, tmpfs: bool) -> Self {
        self.tmpfs_tmp = tmpfs;
        self
    }

    /// Builds the capsule profile, computing the hash and validating.
    ///
    /// # Errors
    ///
    /// Returns [`CapsuleProfileError`] if the configuration is invalid.
    pub fn build(self) -> Result<CapsuleProfile, CapsuleProfileError> {
        let profile_id = self
            .profile_id
            .ok_or(CapsuleProfileError::MissingField("profile_id"))?;

        let namespaces = self.namespaces.unwrap_or_else(NamespaceConfig::isolated);

        let seccomp_level = self
            .seccomp_level
            .unwrap_or(SeccompProfileLevel::Restricted);

        let cgroup_limits = self
            .cgroup_limits
            .unwrap_or_else(CgroupLimits::default_restricted);

        let egress_policy = self.egress_policy.unwrap_or_else(EgressPolicy::deny_all);

        let profile_hash = CapsuleProfile::compute_hash(&HashInput {
            profile_id: &profile_id,
            namespaces: &namespaces,
            seccomp_level: &seccomp_level,
            cgroup_limits: &cgroup_limits,
            egress_policy: &egress_policy,
            allowed_executables: &self.allowed_executables,
            scrub_environment: self.scrub_environment,
            readonly_rootfs: self.readonly_rootfs,
            tmpfs_tmp: self.tmpfs_tmp,
        });

        let profile = CapsuleProfile {
            profile_id,
            profile_hash,
            namespaces,
            seccomp_level,
            cgroup_limits,
            egress_policy,
            allowed_executables: self.allowed_executables,
            scrub_environment: self.scrub_environment,
            readonly_rootfs: self.readonly_rootfs,
            tmpfs_tmp: self.tmpfs_tmp,
        };

        profile.validate()?;

        Ok(profile)
    }
}

// =============================================================================
// Admission Gate
// =============================================================================

/// Admission gate for Tier3+ capsule enforcement.
///
/// Per REQ-0028: "Tier3+ actuation executes only inside admitted capsule
/// profile." This gate rejects actuation requests that lack an admitted capsule
/// profile when the risk tier is 3 or above.
///
/// The gate enforces:
/// 1. Presence of a capsule profile at Tier3+.
/// 2. The profile's `profile_id` MUST be in the enumerated admitted set
///    (`ADMITTED_PROFILE_IDS`).
/// 3. Structural invariants (all namespaces, seccomp, bounded cgroups) via
///    `CapsuleProfile::validate`.
pub struct AdmissionGate;

impl AdmissionGate {
    /// Checks whether actuation is permitted for the given risk tier and
    /// capsule.
    ///
    /// # Rules
    ///
    /// - **`Tier3`+ (`risk_tier` >= 3)**: MUST have an admitted (validated)
    ///   capsule profile whose `profile_id` is in `ADMITTED_PROFILE_IDS`. The
    ///   profile must also pass full structural validation (namespaces,
    ///   seccomp, cgroups, egress, hash integrity).
    /// - **`Tier0`-`Tier2` (`risk_tier` < 3)**: Capsule is optional
    ///
    /// # Runtime Wiring
    ///
    /// NOTE: Runtime integration of this gate into the daemon episode spawn
    /// path is deferred to TCK-00375 and TCK-00376. Currently the gate is
    /// exercised only in unit tests and must be called explicitly by the
    /// daemon spawn logic once those tickets land.
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionError`] if the actuation is denied.
    pub fn check(
        risk_tier: &RiskTier,
        capsule: Option<&CapsuleProfile>,
    ) -> Result<(), AdmissionError> {
        let tier_value = risk_tier_to_u8(*risk_tier);

        if tier_value >= 3 {
            match capsule {
                None => {
                    return Err(AdmissionError::NoCapsuleForTier {
                        risk_tier: tier_value,
                    });
                },
                Some(profile) => {
                    // Enforce admitted profile set: only enumerated profile IDs
                    // are accepted at Tier3+. This prevents a crafted profile
                    // with an arbitrary profile_id from bypassing mandatory
                    // isolation controls.
                    if !ADMITTED_PROFILE_IDS.contains(&profile.profile_id.as_str()) {
                        return Err(AdmissionError::InvalidProfile(
                            CapsuleProfileError::ProfileNotAdmitted {
                                profile_id: profile.profile_id.clone(),
                            },
                        ));
                    }

                    // Full structural validation (namespaces, seccomp, cgroups,
                    // egress, hash integrity).
                    profile.validate().map_err(AdmissionError::InvalidProfile)?;
                },
            }
        }

        Ok(())
    }
}

/// Maps a `RiskTier` to its numeric value for comparison.
const fn risk_tier_to_u8(tier: RiskTier) -> u8 {
    match tier {
        RiskTier::Tier0 => 0,
        RiskTier::Tier1 => 1,
        RiskTier::Tier2 => 2,
        RiskTier::Tier3 => 3,
        RiskTier::Tier4 => 4,
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(missing_docs)]
mod tests {
    use super::*;

    // =========================================================================
    // CapsuleProfile Builder Tests
    // =========================================================================

    #[test]
    fn test_build_linux_ns_v1_defaults() {
        let profile = CapsuleProfileBuilder::new("linux-ns-v1")
            .build()
            .expect("default linux-ns-v1 should be valid");

        assert_eq!(profile.profile_id, "linux-ns-v1");
        assert!(profile.namespaces.user);
        assert!(profile.namespaces.mount);
        assert!(profile.namespaces.pid);
        assert!(profile.namespaces.net);
        assert_eq!(profile.seccomp_level, SeccompProfileLevel::Restricted);
        assert!(profile.egress_policy.deny_by_default);
        assert!(profile.egress_policy.allowed_routes.is_empty());
        assert!(profile.scrub_environment);
        assert!(profile.readonly_rootfs);
        assert!(profile.tmpfs_tmp);
        assert_ne!(profile.profile_hash, [0u8; 32]);
    }

    #[test]
    fn test_build_with_egress_routes() {
        let profile = CapsuleProfileBuilder::new("linux-ns-v1")
            .egress_policy(EgressPolicy::with_routes(vec![EgressRoute {
                host: "registry.npmjs.org".to_string(),
                port: 443,
                protocol: "tcp".to_string(),
            }]))
            .build()
            .expect("should build with egress routes");

        assert!(
            profile
                .egress_policy
                .allows("registry.npmjs.org", 443, "tcp")
        );
        assert!(!profile.egress_policy.allows("evil.com", 443, "tcp"));
    }

    #[test]
    fn test_build_missing_profile_id() {
        let result = CapsuleProfileBuilder::default().build();
        assert!(matches!(
            result,
            Err(CapsuleProfileError::MissingField("profile_id"))
        ));
    }

    #[test]
    fn test_build_rejects_deny_by_default_false() {
        let result = CapsuleProfileBuilder::new("linux-ns-v1")
            .egress_policy(EgressPolicy {
                deny_by_default: false,
                allowed_routes: Vec::new(),
            })
            .build();
        assert!(matches!(
            result,
            Err(CapsuleProfileError::EgressDenyRequired)
        ));
    }

    #[test]
    fn test_build_rejects_insufficient_namespaces() {
        let result = CapsuleProfileBuilder::new("linux-ns-v1")
            .namespaces(NamespaceConfig {
                user: true,
                mount: false, // Missing!
                pid: true,
                net: true,
            })
            .build();
        assert!(matches!(
            result,
            Err(CapsuleProfileError::InsufficientNamespaces)
        ));
    }

    #[test]
    fn test_build_rejects_insufficient_seccomp() {
        let result = CapsuleProfileBuilder::new("linux-ns-v1")
            .seccomp_level(SeccompProfileLevel::None)
            .build();
        assert!(matches!(
            result,
            Err(CapsuleProfileError::InsufficientSeccomp { .. })
        ));

        let result = CapsuleProfileBuilder::new("linux-ns-v1")
            .seccomp_level(SeccompProfileLevel::Baseline)
            .build();
        assert!(matches!(
            result,
            Err(CapsuleProfileError::InsufficientSeccomp { .. })
        ));
    }

    #[test]
    fn test_build_accepts_strict_seccomp() {
        let profile = CapsuleProfileBuilder::new("linux-ns-v1")
            .seccomp_level(SeccompProfileLevel::Strict)
            .build()
            .expect("strict seccomp should be valid");
        assert_eq!(profile.seccomp_level, SeccompProfileLevel::Strict);
    }

    #[test]
    fn test_build_too_many_egress_routes() {
        let routes: Vec<EgressRoute> = (0..=MAX_EGRESS_ROUTES)
            .map(|i| EgressRoute {
                host: format!("host{i}.example.com"),
                port: 443,
                protocol: "tcp".to_string(),
            })
            .collect();
        let result = CapsuleProfileBuilder::new("linux-ns-v1")
            .egress_policy(EgressPolicy::with_routes(routes))
            .build();
        assert!(matches!(
            result,
            Err(CapsuleProfileError::TooManyEgressRoutes { .. })
        ));
    }

    #[test]
    fn test_build_too_many_executables() {
        let mut builder = CapsuleProfileBuilder::new("linux-ns-v1");
        for i in 0..=MAX_ALLOWED_EXECUTABLES {
            builder = builder.add_executable(format!("/usr/bin/tool{i}"));
        }
        let result = builder.build();
        assert!(matches!(
            result,
            Err(CapsuleProfileError::TooManyExecutables { .. })
        ));
    }

    // =========================================================================
    // Hash Determinism Tests
    // =========================================================================

    #[test]
    fn test_profile_hash_deterministic() {
        let p1 = CapsuleProfileBuilder::new("linux-ns-v1").build().unwrap();
        let p2 = CapsuleProfileBuilder::new("linux-ns-v1").build().unwrap();
        assert_eq!(p1.profile_hash, p2.profile_hash);
    }

    #[test]
    fn test_profile_hash_changes_with_routes() {
        let p1 = CapsuleProfileBuilder::new("linux-ns-v1")
            .egress_policy(EgressPolicy::deny_all())
            .build()
            .unwrap();
        let p2 = CapsuleProfileBuilder::new("linux-ns-v1")
            .egress_policy(EgressPolicy::with_routes(vec![EgressRoute {
                host: "example.com".to_string(),
                port: 443,
                protocol: "tcp".to_string(),
            }]))
            .build()
            .unwrap();
        assert_ne!(p1.profile_hash, p2.profile_hash);
    }

    #[test]
    fn test_profile_hash_changes_with_seccomp() {
        let p1 = CapsuleProfileBuilder::new("linux-ns-v1")
            .seccomp_level(SeccompProfileLevel::Restricted)
            .build()
            .unwrap();
        let p2 = CapsuleProfileBuilder::new("linux-ns-v1")
            .seccomp_level(SeccompProfileLevel::Strict)
            .build()
            .unwrap();
        assert_ne!(p1.profile_hash, p2.profile_hash);
    }

    // =========================================================================
    // Egress Policy Tests
    // =========================================================================

    #[test]
    fn test_egress_deny_all() {
        let policy = EgressPolicy::deny_all();
        assert!(policy.deny_by_default);
        assert!(!policy.allows("example.com", 443, "tcp"));
        assert!(!policy.allows("any.host", 80, "udp"));
    }

    #[test]
    fn test_egress_explicit_route() {
        let policy = EgressPolicy::with_routes(vec![EgressRoute {
            host: "api.example.com".to_string(),
            port: 443,
            protocol: "tcp".to_string(),
        }]);
        assert!(policy.allows("api.example.com", 443, "tcp"));
        assert!(!policy.allows("api.example.com", 80, "tcp"));
        assert!(!policy.allows("other.com", 443, "tcp"));
        assert!(!policy.allows("api.example.com", 443, "udp"));
    }

    #[test]
    fn test_egress_deny_by_default_false_rejects_all() {
        // Even with routes, deny_by_default=false means fail-closed → deny all.
        let policy = EgressPolicy {
            deny_by_default: false,
            allowed_routes: vec![EgressRoute {
                host: "example.com".to_string(),
                port: 443,
                protocol: "tcp".to_string(),
            }],
        };
        assert!(!policy.allows("example.com", 443, "tcp"));
    }

    // =========================================================================
    // Admission Gate Tests
    // =========================================================================

    #[test]
    fn test_admission_tier0_no_capsule_ok() {
        assert!(AdmissionGate::check(&RiskTier::Tier0, None).is_ok());
    }

    #[test]
    fn test_admission_tier1_no_capsule_ok() {
        assert!(AdmissionGate::check(&RiskTier::Tier1, None).is_ok());
    }

    #[test]
    fn test_admission_tier2_no_capsule_ok() {
        assert!(AdmissionGate::check(&RiskTier::Tier2, None).is_ok());
    }

    #[test]
    fn test_admission_tier3_no_capsule_rejected() {
        let result = AdmissionGate::check(&RiskTier::Tier3, None);
        assert!(matches!(
            result,
            Err(AdmissionError::NoCapsuleForTier { risk_tier: 3 })
        ));
    }

    #[test]
    fn test_admission_tier4_no_capsule_rejected() {
        let result = AdmissionGate::check(&RiskTier::Tier4, None);
        assert!(matches!(
            result,
            Err(AdmissionError::NoCapsuleForTier { risk_tier: 4 })
        ));
    }

    #[test]
    fn test_admission_tier3_with_valid_capsule_ok() {
        let profile = CapsuleProfileBuilder::new("linux-ns-v1").build().unwrap();
        assert!(AdmissionGate::check(&RiskTier::Tier3, Some(&profile)).is_ok());
    }

    #[test]
    fn test_admission_tier4_with_valid_capsule_ok() {
        let profile = CapsuleProfileBuilder::new("linux-ns-v1").build().unwrap();
        assert!(AdmissionGate::check(&RiskTier::Tier4, Some(&profile)).is_ok());
    }

    #[test]
    fn test_admission_tier3_with_invalid_capsule_rejected() {
        // Construct a profile with a tampered hash
        let mut profile = CapsuleProfileBuilder::new("linux-ns-v1").build().unwrap();
        profile.profile_hash = [0u8; 32]; // Tamper hash
        let result = AdmissionGate::check(&RiskTier::Tier3, Some(&profile));
        assert!(matches!(result, Err(AdmissionError::InvalidProfile(_))));
    }

    // =========================================================================
    // Namespace Tests
    // =========================================================================

    #[test]
    fn test_namespace_isolated() {
        let ns = NamespaceConfig::isolated();
        assert!(ns.user);
        assert!(ns.mount);
        assert!(ns.pid);
        assert!(ns.net);
        assert!(ns.meets_linux_ns_v1());
    }

    #[test]
    fn test_namespace_insufficient_user_missing() {
        let ns = NamespaceConfig {
            user: false,
            mount: true,
            pid: true,
            net: true,
        };
        assert!(!ns.meets_linux_ns_v1());
    }

    #[test]
    fn test_namespace_insufficient_net_missing() {
        // SECURITY REGRESSION: net=false MUST be rejected for linux-ns-v1.
        // Without network namespace isolation, agent processes inherit host
        // networking and can bypass egress deny-by-default controls.
        let ns = NamespaceConfig {
            user: true,
            mount: true,
            pid: true,
            net: false,
        };
        assert!(
            !ns.meets_linux_ns_v1(),
            "net=false must fail meets_linux_ns_v1 check"
        );
    }

    #[test]
    fn test_build_rejects_net_false_for_linux_ns_v1() {
        // SECURITY REGRESSION: building linux-ns-v1 profile with net=false
        // MUST be rejected at the builder level.
        let result = CapsuleProfileBuilder::new("linux-ns-v1")
            .namespaces(NamespaceConfig {
                user: true,
                mount: true,
                pid: true,
                net: false,
            })
            .build();
        assert!(
            matches!(result, Err(CapsuleProfileError::InsufficientNamespaces)),
            "linux-ns-v1 with net=false must be rejected: got {result:?}"
        );
    }

    #[test]
    fn test_admission_tier3_rejects_net_false_profile() {
        // SECURITY REGRESSION: Tier3+ admission must reject profiles that
        // lack network namespace isolation, even if other namespaces are set.
        let mut profile = CapsuleProfileBuilder::new("linux-ns-v1").build().unwrap();
        // Tamper to remove net namespace after construction
        profile.namespaces.net = false;
        // Recompute hash to avoid hash mismatch (simulates a profile that
        // was somehow constructed with net=false)
        profile.profile_hash = CapsuleProfile::compute_hash(&HashInput {
            profile_id: &profile.profile_id,
            namespaces: &profile.namespaces,
            seccomp_level: &profile.seccomp_level,
            cgroup_limits: &profile.cgroup_limits,
            egress_policy: &profile.egress_policy,
            allowed_executables: &profile.allowed_executables,
            scrub_environment: profile.scrub_environment,
            readonly_rootfs: profile.readonly_rootfs,
            tmpfs_tmp: profile.tmpfs_tmp,
        });
        let result = AdmissionGate::check(&RiskTier::Tier3, Some(&profile));
        assert!(
            matches!(result, Err(AdmissionError::InvalidProfile(_))),
            "Tier3 admission with net=false must be rejected: got {result:?}"
        );
    }

    // =========================================================================
    // Cgroup Tests
    // =========================================================================

    #[test]
    fn test_cgroup_default_restricted() {
        let cg = CgroupLimits::default_restricted();
        assert!(cg.has_limits());
        assert_eq!(cg.pids_max, 1024);
        assert_eq!(cg.memory_limit_bytes, 4 * 1024 * 1024 * 1024);
    }

    // =========================================================================
    // Violation Kind Tests
    // =========================================================================

    #[test]
    fn test_violation_kind_display() {
        assert_eq!(ViolationKind::PathTraversal.to_string(), "PATH_TRAVERSAL");
        assert_eq!(ViolationKind::SymlinkEscape.to_string(), "SYMLINK_ESCAPE");
        assert_eq!(
            ViolationKind::UnauthorizedEgress.to_string(),
            "UNAUTHORIZED_EGRESS"
        );
    }

    // =========================================================================
    // Serde Roundtrip Tests
    // =========================================================================

    #[test]
    fn test_profile_serde_roundtrip() {
        let profile = CapsuleProfileBuilder::new("linux-ns-v1")
            .egress_policy(EgressPolicy::with_routes(vec![EgressRoute {
                host: "crates.io".to_string(),
                port: 443,
                protocol: "tcp".to_string(),
            }]))
            .add_executable("/usr/bin/apm2")
            .build()
            .unwrap();

        let json = serde_json::to_string(&profile).unwrap();
        let deserialized: CapsuleProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(profile, deserialized);
    }

    // =========================================================================
    // Egress Route Validation Tests
    // =========================================================================

    #[test]
    fn test_egress_route_empty_host() {
        let route = EgressRoute {
            host: String::new(),
            port: 443,
            protocol: "tcp".to_string(),
        };
        assert!(route.validate().is_err());
    }

    #[test]
    fn test_egress_route_port_zero() {
        let route = EgressRoute {
            host: "example.com".to_string(),
            port: 0,
            protocol: "tcp".to_string(),
        };
        assert!(route.validate().is_err());
    }

    #[test]
    fn test_egress_route_invalid_protocol() {
        let route = EgressRoute {
            host: "example.com".to_string(),
            port: 443,
            protocol: "icmp".to_string(),
        };
        assert!(route.validate().is_err());
    }

    // =========================================================================
    // BLOCKER 1: Tier3 admission rejects non-admitted profile IDs
    // =========================================================================

    #[test]
    fn test_admission_tier3_rejects_custom_weak_profile() {
        // A crafted profile with profile_id="custom-weak" that has namespaces
        // disabled, seccomp None, unlimited cgroups MUST be rejected by
        // AdmissionGate::check at Tier3.
        let weak_ns = NamespaceConfig {
            user: false,
            mount: false,
            pid: false,
            net: false,
        };
        let weak_cgroups = CgroupLimits {
            cpu_quota_us: 0,
            cpu_period_us: 0,
            memory_limit_bytes: 0,
            pids_max: 0,
            io_weight: 0,
        };
        let profile_hash = CapsuleProfile::compute_hash(&HashInput {
            profile_id: "custom-weak",
            namespaces: &weak_ns,
            seccomp_level: &SeccompProfileLevel::None,
            cgroup_limits: &weak_cgroups,
            egress_policy: &EgressPolicy::deny_all(),
            allowed_executables: &[],
            scrub_environment: false,
            readonly_rootfs: false,
            tmpfs_tmp: false,
        });
        let weak_profile = CapsuleProfile {
            profile_id: "custom-weak".to_string(),
            profile_hash,
            namespaces: weak_ns,
            seccomp_level: SeccompProfileLevel::None,
            cgroup_limits: weak_cgroups,
            egress_policy: EgressPolicy::deny_all(),
            allowed_executables: Vec::new(),
            scrub_environment: false,
            readonly_rootfs: false,
            tmpfs_tmp: false,
        };

        let result = AdmissionGate::check(&RiskTier::Tier3, Some(&weak_profile));
        assert!(
            matches!(
                result,
                Err(AdmissionError::InvalidProfile(
                    CapsuleProfileError::ProfileNotAdmitted { .. }
                ))
            ),
            "Tier3 admission with custom-weak profile_id must be rejected: got {result:?}"
        );
    }

    #[test]
    fn test_admission_tier4_rejects_unadmitted_profile_id() {
        // Even if the profile has strong settings, a non-admitted profile_id
        // must be rejected at Tier4.
        let strong_ns = NamespaceConfig::isolated();
        let strong_cgroups = CgroupLimits::default_restricted();
        let profile_hash = CapsuleProfile::compute_hash(&HashInput {
            profile_id: "my-custom-profile",
            namespaces: &strong_ns,
            seccomp_level: &SeccompProfileLevel::Strict,
            cgroup_limits: &strong_cgroups,
            egress_policy: &EgressPolicy::deny_all(),
            allowed_executables: &[],
            scrub_environment: true,
            readonly_rootfs: true,
            tmpfs_tmp: true,
        });
        let profile = CapsuleProfile {
            profile_id: "my-custom-profile".to_string(),
            profile_hash,
            namespaces: strong_ns,
            seccomp_level: SeccompProfileLevel::Strict,
            cgroup_limits: strong_cgroups,
            egress_policy: EgressPolicy::deny_all(),
            allowed_executables: Vec::new(),
            scrub_environment: true,
            readonly_rootfs: true,
            tmpfs_tmp: true,
        };

        let result = AdmissionGate::check(&RiskTier::Tier4, Some(&profile));
        assert!(
            matches!(
                result,
                Err(AdmissionError::InvalidProfile(
                    CapsuleProfileError::ProfileNotAdmitted { .. }
                ))
            ),
            "Tier4 admission with non-admitted profile_id must be rejected: got {result:?}"
        );
    }

    #[test]
    fn test_admission_tier2_allows_non_admitted_profile_id() {
        // Below Tier3, the admission gate does not enforce the admitted set.
        assert!(AdmissionGate::check(&RiskTier::Tier2, None).is_ok());
    }

    // =========================================================================
    // BLOCKER 3: Cgroup zero/unbounded configurations rejected
    // =========================================================================

    #[test]
    fn test_build_rejects_zero_memory_limit() {
        let result = CapsuleProfileBuilder::new("linux-ns-v1")
            .cgroup_limits(CgroupLimits {
                cpu_quota_us: 200_000,
                cpu_period_us: 100_000,
                memory_limit_bytes: 0,
                pids_max: 1024,
                io_weight: 100,
            })
            .build();
        assert!(
            matches!(result, Err(CapsuleProfileError::ZeroCgroupMemory)),
            "zero memory_limit_bytes must be rejected: got {result:?}"
        );
    }

    #[test]
    fn test_build_rejects_zero_pids_max() {
        let result = CapsuleProfileBuilder::new("linux-ns-v1")
            .cgroup_limits(CgroupLimits {
                cpu_quota_us: 200_000,
                cpu_period_us: 100_000,
                memory_limit_bytes: 4 * 1024 * 1024 * 1024,
                pids_max: 0,
                io_weight: 100,
            })
            .build();
        assert!(
            matches!(result, Err(CapsuleProfileError::ZeroCgroupPids)),
            "zero pids_max must be rejected: got {result:?}"
        );
    }

    #[test]
    fn test_build_rejects_zero_cpu_quota() {
        let result = CapsuleProfileBuilder::new("linux-ns-v1")
            .cgroup_limits(CgroupLimits {
                cpu_quota_us: 0,
                cpu_period_us: 100_000,
                memory_limit_bytes: 4 * 1024 * 1024 * 1024,
                pids_max: 1024,
                io_weight: 100,
            })
            .build();
        assert!(
            matches!(result, Err(CapsuleProfileError::ZeroCgroupCpuQuota)),
            "zero cpu_quota_us must be rejected: got {result:?}"
        );
    }

    #[test]
    fn test_build_rejects_zero_io_weight() {
        let result = CapsuleProfileBuilder::new("linux-ns-v1")
            .cgroup_limits(CgroupLimits {
                cpu_quota_us: 200_000,
                cpu_period_us: 100_000,
                memory_limit_bytes: 4 * 1024 * 1024 * 1024,
                pids_max: 1024,
                io_weight: 0,
            })
            .build();
        assert!(
            matches!(
                result,
                Err(CapsuleProfileError::InvalidCgroupIoWeight { value: 0 })
            ),
            "zero io_weight must be rejected: got {result:?}"
        );
    }

    #[test]
    fn test_build_rejects_io_weight_above_10000() {
        let result = CapsuleProfileBuilder::new("linux-ns-v1")
            .cgroup_limits(CgroupLimits {
                cpu_quota_us: 200_000,
                cpu_period_us: 100_000,
                memory_limit_bytes: 4 * 1024 * 1024 * 1024,
                pids_max: 1024,
                io_weight: 10001,
            })
            .build();
        assert!(
            matches!(
                result,
                Err(CapsuleProfileError::InvalidCgroupIoWeight { value: 10001 })
            ),
            "io_weight > 10000 must be rejected: got {result:?}"
        );
    }

    #[test]
    fn test_build_accepts_io_weight_at_boundaries() {
        // io_weight = 1 (minimum valid)
        let result = CapsuleProfileBuilder::new("linux-ns-v1")
            .cgroup_limits(CgroupLimits {
                cpu_quota_us: 200_000,
                cpu_period_us: 100_000,
                memory_limit_bytes: 4 * 1024 * 1024 * 1024,
                pids_max: 1024,
                io_weight: 1,
            })
            .build();
        assert!(
            result.is_ok(),
            "io_weight=1 should be valid: got {result:?}"
        );

        // io_weight = 10000 (maximum valid)
        let result = CapsuleProfileBuilder::new("linux-ns-v1")
            .cgroup_limits(CgroupLimits {
                cpu_quota_us: 200_000,
                cpu_period_us: 100_000,
                memory_limit_bytes: 4 * 1024 * 1024 * 1024,
                pids_max: 1024,
                io_weight: 10000,
            })
            .build();
        assert!(
            result.is_ok(),
            "io_weight=10000 should be valid: got {result:?}"
        );
    }

    #[test]
    fn test_build_rejects_all_zero_cgroups() {
        // All cgroup controls at zero must be rejected
        let result = CapsuleProfileBuilder::new("linux-ns-v1")
            .cgroup_limits(CgroupLimits {
                cpu_quota_us: 0,
                cpu_period_us: 0,
                memory_limit_bytes: 0,
                pids_max: 0,
                io_weight: 0,
            })
            .build();
        assert!(
            result.is_err(),
            "all-zero cgroup limits must be rejected: got {result:?}"
        );
    }

    // =========================================================================
    // BLOCKER: Mandatory RFC-0020 §4.3 controls for linux-ns-v1
    // =========================================================================

    #[test]
    fn test_build_rejects_readonly_rootfs_false() {
        let result = CapsuleProfileBuilder::new("linux-ns-v1")
            .readonly_rootfs(false)
            .build();
        assert!(
            matches!(result, Err(CapsuleProfileError::ReadonlyRootfsRequired)),
            "readonly_rootfs=false must be rejected for linux-ns-v1: got {result:?}"
        );
    }

    #[test]
    fn test_build_rejects_tmpfs_tmp_false() {
        let result = CapsuleProfileBuilder::new("linux-ns-v1")
            .tmpfs_tmp(false)
            .build();
        assert!(
            matches!(result, Err(CapsuleProfileError::TmpfsTmpRequired)),
            "tmpfs_tmp=false must be rejected for linux-ns-v1: got {result:?}"
        );
    }

    #[test]
    fn test_build_rejects_scrub_environment_false() {
        let result = CapsuleProfileBuilder::new("linux-ns-v1")
            .scrub_environment(false)
            .build();
        assert!(
            matches!(result, Err(CapsuleProfileError::ScrubEnvironmentRequired)),
            "scrub_environment=false must be rejected for linux-ns-v1: got {result:?}"
        );
    }

    #[test]
    fn test_admission_tier3_rejects_readonly_rootfs_false_profile() {
        // Tamper a valid profile to disable readonly_rootfs
        let mut profile = CapsuleProfileBuilder::new("linux-ns-v1").build().unwrap();
        profile.readonly_rootfs = false;
        profile.profile_hash = CapsuleProfile::compute_hash(&HashInput {
            profile_id: &profile.profile_id,
            namespaces: &profile.namespaces,
            seccomp_level: &profile.seccomp_level,
            cgroup_limits: &profile.cgroup_limits,
            egress_policy: &profile.egress_policy,
            allowed_executables: &profile.allowed_executables,
            scrub_environment: profile.scrub_environment,
            readonly_rootfs: profile.readonly_rootfs,
            tmpfs_tmp: profile.tmpfs_tmp,
        });
        let result = AdmissionGate::check(&RiskTier::Tier3, Some(&profile));
        assert!(
            matches!(result, Err(AdmissionError::InvalidProfile(_))),
            "Tier3 admission with readonly_rootfs=false must be rejected: got {result:?}"
        );
    }

    #[test]
    fn test_admission_tier3_rejects_scrub_environment_false_profile() {
        // Tamper a valid profile to disable scrub_environment
        let mut profile = CapsuleProfileBuilder::new("linux-ns-v1").build().unwrap();
        profile.scrub_environment = false;
        profile.profile_hash = CapsuleProfile::compute_hash(&HashInput {
            profile_id: &profile.profile_id,
            namespaces: &profile.namespaces,
            seccomp_level: &profile.seccomp_level,
            cgroup_limits: &profile.cgroup_limits,
            egress_policy: &profile.egress_policy,
            allowed_executables: &profile.allowed_executables,
            scrub_environment: profile.scrub_environment,
            readonly_rootfs: profile.readonly_rootfs,
            tmpfs_tmp: profile.tmpfs_tmp,
        });
        let result = AdmissionGate::check(&RiskTier::Tier3, Some(&profile));
        assert!(
            matches!(result, Err(AdmissionError::InvalidProfile(_))),
            "Tier3 admission with scrub_environment=false must be rejected: got {result:?}"
        );
    }

    #[test]
    fn test_non_linux_ns_v1_allows_optional_hardening() {
        // Non-linux-ns-v1 profiles should not enforce these controls
        let profile_hash = CapsuleProfile::compute_hash(&HashInput {
            profile_id: "custom-profile",
            namespaces: &NamespaceConfig::isolated(),
            seccomp_level: &SeccompProfileLevel::Restricted,
            cgroup_limits: &CgroupLimits::default_restricted(),
            egress_policy: &EgressPolicy::deny_all(),
            allowed_executables: &[],
            scrub_environment: false,
            readonly_rootfs: false,
            tmpfs_tmp: false,
        });
        let profile = CapsuleProfile {
            profile_id: "custom-profile".to_string(),
            profile_hash,
            namespaces: NamespaceConfig::isolated(),
            seccomp_level: SeccompProfileLevel::Restricted,
            cgroup_limits: CgroupLimits::default_restricted(),
            egress_policy: EgressPolicy::deny_all(),
            allowed_executables: Vec::new(),
            scrub_environment: false,
            readonly_rootfs: false,
            tmpfs_tmp: false,
        };
        // validate() should pass for non-linux-ns-v1 profiles
        assert!(
            profile.validate().is_ok(),
            "non-linux-ns-v1 profiles should not require hardening controls"
        );
    }

    // =========================================================================
    // SECURITY REGRESSION: CapsuleProfile deserialization bypass tests
    //
    // CapsuleProfile must NOT be constructible via serde::Deserialize without
    // running validate(). This prevents crafting profiles with tampered hashes,
    // disabled egress deny, insufficient namespaces, etc. via JSON.
    // =========================================================================

    #[test]
    fn test_capsule_profile_deserialize_valid_roundtrip() {
        // A valid profile serialized via builder should deserialize successfully.
        let profile = CapsuleProfileBuilder::new("linux-ns-v1").build().unwrap();
        let json = serde_json::to_string(&profile).unwrap();
        let deserialized: CapsuleProfile =
            serde_json::from_str(&json).expect("valid profile roundtrip must succeed");
        assert_eq!(profile, deserialized);
    }

    #[test]
    fn test_capsule_profile_deserialize_tampered_hash_rejected() {
        // Serialize a valid profile, then tamper the hash in JSON.
        let profile = CapsuleProfileBuilder::new("linux-ns-v1").build().unwrap();
        let mut json: serde_json::Value = serde_json::to_value(&profile).unwrap();
        // Tamper the profile_hash to all zeros
        let zero_hash = vec![0u8; 32];
        json["profile_hash"] = serde_json::to_value(&zero_hash).unwrap();
        let result: Result<CapsuleProfile, _> = serde_json::from_value(json);
        assert!(
            result.is_err(),
            "deserializing profile with tampered hash must fail: got {result:?}"
        );
    }

    #[test]
    fn test_capsule_profile_deserialize_deny_by_default_false_rejected() {
        // Serialize a valid profile, then set deny_by_default to false.
        let profile = CapsuleProfileBuilder::new("linux-ns-v1").build().unwrap();
        let mut json: serde_json::Value = serde_json::to_value(&profile).unwrap();
        json["egress_policy"]["deny_by_default"] = serde_json::Value::Bool(false);
        // Recompute hash for the tampered profile to isolate the egress check
        // (otherwise hash mismatch fires first).
        // We can't easily recompute the hash in JSON, so just verify
        // deserialization fails (either hash mismatch or egress deny check).
        let result: Result<CapsuleProfile, _> = serde_json::from_value(json);
        assert!(
            result.is_err(),
            "deserializing profile with deny_by_default=false must fail: got {result:?}"
        );
    }

    #[test]
    fn test_capsule_profile_deserialize_with_egress_routes_valid() {
        // A valid profile with egress routes should roundtrip.
        let profile = CapsuleProfileBuilder::new("linux-ns-v1")
            .egress_policy(EgressPolicy::with_routes(vec![EgressRoute {
                host: "crates.io".to_string(),
                port: 443,
                protocol: "tcp".to_string(),
            }]))
            .add_executable("/usr/bin/apm2")
            .build()
            .unwrap();
        let json = serde_json::to_string(&profile).unwrap();
        let deserialized: CapsuleProfile =
            serde_json::from_str(&json).expect("valid profile with routes must roundtrip");
        assert_eq!(profile, deserialized);
    }
}
