//! Maps FAC lane configuration to systemd unit configuration.
//!
//! This module is the authoritative conversion point for lane + constraint
//! inputs into systemd-style execution guardrails (resource limits + timeouts +
//! kill mode + sandbox hardening).
//!
//! ## Sandbox Hardening (TCK-00573)
//!
//! `SandboxHardeningProfile` defines systemd security directives that reduce
//! the attack surface of transient units used for FAC job execution. The
//! profile is policy-driven via `FacPolicyV1::sandbox_hardening` and emitted
//! into job receipts for audit.
//!
//! Default-safe directives:
//! - `NoNewPrivileges=yes` — prevent privilege escalation via setuid/setgid
//! - `PrivateTmp=yes` — isolated `/tmp` namespace
//! - `ProtectControlGroups=yes` — read-only cgroup filesystem
//! - `ProtectKernelTunables=yes` — read-only `/proc/sys`, `/sys`
//! - `ProtectKernelLogs=yes` — deny access to kernel log ring buffer
//! - `RestrictSUIDSGID=yes` — deny creating setuid/setgid files
//! - `LockPersonality=yes` — lock execution personality
//! - `RestrictRealtime=yes` — deny realtime scheduling
//! - `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6` — restrict socket types
//! - `SystemCallArchitectures=native` — deny non-native syscall ABIs

use serde::{Deserialize, Serialize};

use super::job_spec::JobConstraints;
use crate::fac::lane::LaneProfileV1;

/// Maximum number of address families allowed in the policy (denial-of-service
/// bound).
const MAX_ADDRESS_FAMILIES: usize = 16;

/// Sandbox hardening profile for systemd transient units (TCK-00573).
///
/// Each field corresponds to a systemd security directive. The default
/// profile enables all hardening directives with safe defaults that
/// preserve build execution (compilers, linkers, test runners).
///
/// This profile is serializable for policy persistence and receipt audit.
/// The BLAKE3 hash of the normalized form is included in job receipts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)] // Each bool maps 1:1 to an independent systemd security directive toggle; a bitflag would obscure the policy-driven toggle semantics.
pub struct SandboxHardeningProfile {
    /// `NoNewPrivileges=yes` — prevent privilege escalation via
    /// setuid/setgid binaries. Default: `true`.
    #[serde(default = "default_true")]
    pub no_new_privileges: bool,

    /// `PrivateTmp=yes` — mount a private `/tmp` for the unit.
    /// Default: `true`.
    #[serde(default = "default_true")]
    pub private_tmp: bool,

    /// `ProtectControlGroups=yes` — make the cgroup filesystem hierarchy
    /// read-only. Default: `true`.
    #[serde(default = "default_true")]
    pub protect_control_groups: bool,

    /// `ProtectKernelTunables=yes` — make `/proc/sys`, `/sys`, and similar
    /// kernel variable interfaces read-only. Default: `true`.
    #[serde(default = "default_true")]
    pub protect_kernel_tunables: bool,

    /// `ProtectKernelLogs=yes` — deny access to the kernel log ring buffer
    /// (`/dev/kmsg`, `/proc/kmsg`). Default: `true`.
    #[serde(default = "default_true")]
    pub protect_kernel_logs: bool,

    /// `RestrictSUIDSGID=yes` — deny creating setuid/setgid files or file
    /// system capabilities. Default: `true`.
    #[serde(default = "default_true")]
    pub restrict_suid_sgid: bool,

    /// `LockPersonality=yes` — lock the execution domain (personality) so
    /// the process cannot change it. Default: `true`.
    #[serde(default = "default_true")]
    pub lock_personality: bool,

    /// `RestrictRealtime=yes` — deny setting realtime scheduling policies.
    /// Default: `true`.
    #[serde(default = "default_true")]
    pub restrict_realtime: bool,

    /// `RestrictAddressFamilies` — allowed socket address families.
    /// Default: `["AF_UNIX", "AF_INET", "AF_INET6"]`.
    ///
    /// An empty list disables the directive (all families allowed).
    /// Bounded by `MAX_ADDRESS_FAMILIES` to prevent denial-of-service.
    #[serde(default = "default_address_families")]
    pub restrict_address_families: Vec<String>,

    /// `SystemCallArchitectures=native` — restrict to native syscall ABI.
    /// Default: `true`.
    #[serde(default = "default_true")]
    pub system_call_architectures_native: bool,
}

const fn default_true() -> bool {
    true
}

fn default_address_families() -> Vec<String> {
    vec![
        "AF_UNIX".to_string(),
        "AF_INET".to_string(),
        "AF_INET6".to_string(),
    ]
}

impl Default for SandboxHardeningProfile {
    fn default() -> Self {
        Self {
            no_new_privileges: true,
            private_tmp: true,
            protect_control_groups: true,
            protect_kernel_tunables: true,
            protect_kernel_logs: true,
            restrict_suid_sgid: true,
            lock_personality: true,
            restrict_realtime: true,
            restrict_address_families: default_address_families(),
            system_call_architectures_native: true,
        }
    }
}

impl SandboxHardeningProfile {
    /// Validate the profile for bounds violations.
    ///
    /// # Errors
    ///
    /// Returns a human-readable error if address families exceed
    /// `MAX_ADDRESS_FAMILIES` or contain empty/overlong entries.
    pub fn validate(&self) -> Result<(), String> {
        if self.restrict_address_families.len() > MAX_ADDRESS_FAMILIES {
            return Err(format!(
                "restrict_address_families has {} entries, max is {MAX_ADDRESS_FAMILIES}",
                self.restrict_address_families.len()
            ));
        }
        for (i, af) in self.restrict_address_families.iter().enumerate() {
            if af.is_empty() {
                return Err(format!("restrict_address_families[{i}] is empty"));
            }
            if af.len() > 32 {
                return Err(format!(
                    "restrict_address_families[{i}] exceeds 32 bytes: len={}",
                    af.len()
                ));
            }
            // Only allow known AF_ prefixed identifiers (alphanumeric + underscore).
            if !af.starts_with("AF_")
                || !af[3..]
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                return Err(format!(
                    "restrict_address_families[{i}] has invalid format: '{af}'; \
                     expected AF_<NAME> with alphanumeric characters"
                ));
            }
        }
        // NIT-3: Enforce uniqueness of address families to prevent
        // accidental duplicate entries from producing surprising hashes.
        {
            let mut seen = std::collections::HashSet::new();
            for (i, af) in self.restrict_address_families.iter().enumerate() {
                if !seen.insert(af.as_str()) {
                    return Err(format!(
                        "restrict_address_families[{i}] is a duplicate: '{af}'"
                    ));
                }
            }
        }
        Ok(())
    }

    /// Render the hardening directives as systemd `[Service]` property
    /// strings suitable for `--property` arguments to `systemd-run`.
    #[must_use]
    pub fn to_property_strings(&self) -> Vec<String> {
        let mut props = Vec::with_capacity(10);

        if self.no_new_privileges {
            props.push("NoNewPrivileges=yes".to_string());
        }
        if self.private_tmp {
            props.push("PrivateTmp=yes".to_string());
        }
        if self.protect_control_groups {
            props.push("ProtectControlGroups=yes".to_string());
        }
        if self.protect_kernel_tunables {
            props.push("ProtectKernelTunables=yes".to_string());
        }
        if self.protect_kernel_logs {
            props.push("ProtectKernelLogs=yes".to_string());
        }
        if self.restrict_suid_sgid {
            props.push("RestrictSUIDSGID=yes".to_string());
        }
        if self.lock_personality {
            props.push("LockPersonality=yes".to_string());
        }
        if self.restrict_realtime {
            props.push("RestrictRealtime=yes".to_string());
        }
        if !self.restrict_address_families.is_empty() {
            props.push(format!(
                "RestrictAddressFamilies={}",
                self.restrict_address_families.join(" ")
            ));
        }
        if self.system_call_architectures_native {
            props.push("SystemCallArchitectures=native".to_string());
        }

        props
    }

    /// Compute a deterministic BLAKE3 hash of the normalized profile for
    /// receipt audit. Uses domain separation and length-prefixed fields.
    #[must_use]
    pub fn content_hash(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"apm2.fac.sandbox_hardening.v1\0");

        // Encode each boolean as a single byte (0/1), deterministic order.
        hasher.update(&[u8::from(self.no_new_privileges)]);
        hasher.update(&[u8::from(self.private_tmp)]);
        hasher.update(&[u8::from(self.protect_control_groups)]);
        hasher.update(&[u8::from(self.protect_kernel_tunables)]);
        hasher.update(&[u8::from(self.protect_kernel_logs)]);
        hasher.update(&[u8::from(self.restrict_suid_sgid)]);
        hasher.update(&[u8::from(self.lock_personality)]);
        hasher.update(&[u8::from(self.restrict_realtime)]);
        hasher.update(&[u8::from(self.system_call_architectures_native)]);

        // Length-prefixed address families list. Sorted for canonical
        // ordering so functionally identical policies (same families,
        // different insertion order) produce the same digest.
        let mut sorted_families = self.restrict_address_families.clone();
        sorted_families.sort();
        let count = sorted_families.len() as u64;
        hasher.update(&count.to_le_bytes());
        for af in &sorted_families {
            let len = af.len() as u64;
            hasher.update(&len.to_le_bytes());
            hasher.update(af.as_bytes());
        }

        *hasher.finalize().as_bytes()
    }

    /// Format the content hash as a `b3-256:` prefixed hex string for
    /// inclusion in receipts.
    #[must_use]
    pub fn content_hash_hex(&self) -> String {
        let hash = self.content_hash();
        format!("b3-256:{}", hex::encode(hash))
    }

    /// Render only the user-mode-safe subset of hardening directives.
    ///
    /// User-mode systemd cannot apply directives that require mount namespaces
    /// (`PrivateTmp`, `ProtectControlGroups`, `ProtectKernelTunables`,
    /// `ProtectKernelLogs`) or capability manipulation (`RestrictSUIDSGID`,
    /// `LockPersonality`, `RestrictRealtime`, `RestrictAddressFamilies`,
    /// `SystemCallArchitectures`). Only `NoNewPrivileges` is safe in user mode
    /// because it uses `prctl(PR_SET_NO_NEW_PRIVS)` which is unprivileged.
    #[must_use]
    pub fn to_user_mode_property_strings(&self) -> Vec<String> {
        let mut props = Vec::with_capacity(1);
        if self.no_new_privileges {
            props.push("NoNewPrivileges=yes".to_string());
        }
        props
    }

    /// Returns the number of enabled directives (for audit logging).
    #[must_use]
    pub fn enabled_directive_count(&self) -> usize {
        let mut count = 0;
        if self.no_new_privileges {
            count += 1;
        }
        if self.private_tmp {
            count += 1;
        }
        if self.protect_control_groups {
            count += 1;
        }
        if self.protect_kernel_tunables {
            count += 1;
        }
        if self.protect_kernel_logs {
            count += 1;
        }
        if self.restrict_suid_sgid {
            count += 1;
        }
        if self.lock_personality {
            count += 1;
        }
        if self.restrict_realtime {
            count += 1;
        }
        if !self.restrict_address_families.is_empty() {
            count += 1;
        }
        if self.system_call_architectures_native {
            count += 1;
        }
        count
    }
}

/// Systemd unit properties derived from FAC lane profile + job constraints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemdUnitProperties {
    /// CPU quota as a percent (`200` == 2 cores).
    pub cpu_quota_percent: u32,
    /// Memory ceiling in bytes (`MemoryMax`).
    pub memory_max_bytes: u64,
    /// Maximum number of tasks/processes (`TasksMax`).
    pub tasks_max: u32,
    /// I/O weight (`IOWeight`).
    pub io_weight: u32,
    /// Job start timeout in seconds (`TimeoutStartSec`).
    pub timeout_start_sec: u64,
    /// Job runtime timeout in seconds (`RuntimeMaxSec`).
    pub runtime_max_sec: u64,
    /// How systemd stops children (`KillMode`).
    pub kill_mode: String,
    /// Sandbox hardening profile (TCK-00573).
    pub sandbox_hardening: SandboxHardeningProfile,
}

impl SystemdUnitProperties {
    /// Build properties from lane profile, job constraints, and an explicit
    /// sandbox hardening profile (from policy).
    ///
    /// This is the ONLY public constructor for `SystemdUnitProperties`.
    /// Production code MUST supply the policy-driven hardening profile
    /// (INV-SBX-001). Using `SandboxHardeningProfile::default()` directly
    /// is prohibited in production paths — the profile must come from
    /// `FacPolicyV1.sandbox_hardening`.
    ///
    /// Job constraints override lane defaults using MIN semantics:
    /// - `memory_max_bytes` = min(`profile.memory_max_bytes`,
    ///   `constraints.memory_max_bytes`)
    /// - `timeout_start_sec` = min(`profile.test_timeout_seconds`,
    ///   `constraints.test_timeout_seconds`)
    #[must_use]
    pub fn from_lane_profile_with_hardening(
        profile: &LaneProfileV1,
        job_constraints: Option<&JobConstraints>,
        hardening: SandboxHardeningProfile,
    ) -> Self {
        let resource_profile = &profile.resource_profile;
        let timeouts = &profile.timeouts;

        let memory_max_bytes = job_constraints
            .and_then(|constraints| constraints.memory_max_bytes)
            .map_or(resource_profile.memory_max_bytes, |value| {
                value.min(resource_profile.memory_max_bytes)
            });

        let timeout_start_sec = job_constraints
            .and_then(|constraints| constraints.test_timeout_seconds)
            .map_or(timeouts.test_timeout_seconds, |value| {
                value.min(timeouts.test_timeout_seconds)
            });

        Self {
            cpu_quota_percent: resource_profile.cpu_quota_percent,
            memory_max_bytes,
            tasks_max: resource_profile.pids_max,
            io_weight: resource_profile.io_weight,
            timeout_start_sec,
            runtime_max_sec: timeouts.job_runtime_max_seconds,
            kill_mode: Self::DEFAULT_KILL_MODE.to_string(),
            sandbox_hardening: hardening,
        }
    }

    /// Build properties from CLI-provided limits and a policy-driven sandbox
    /// hardening profile.
    ///
    /// This constructor is used by the bounded test runner (CLI) where no
    /// `LaneProfileV1` is available. It uses the same centralized defaults
    /// for `io_weight` and `kill_mode` as
    /// [`Self::from_lane_profile_with_hardening`] to avoid hard-coded
    /// values at caller sites (INV-SBX-001).
    ///
    /// The `timeout_seconds` value is used for both `timeout_start_sec` and
    /// `runtime_max_sec` since CLI limits express a single timeout.
    #[must_use]
    pub fn from_cli_limits_with_hardening(
        cpu_quota_percent: u32,
        memory_max_bytes: u64,
        tasks_max: u32,
        timeout_seconds: u64,
        hardening: SandboxHardeningProfile,
    ) -> Self {
        Self {
            cpu_quota_percent,
            memory_max_bytes,
            tasks_max,
            io_weight: Self::DEFAULT_IO_WEIGHT,
            timeout_start_sec: timeout_seconds,
            runtime_max_sec: timeout_seconds,
            kill_mode: Self::DEFAULT_KILL_MODE.to_string(),
            sandbox_hardening: hardening,
        }
    }

    /// Default I/O weight for systemd transient units. Matches the lane
    /// profile default in `LaneResourceProfileV1::default()`.
    const DEFAULT_IO_WEIGHT: u32 = 100;

    /// Default kill mode for systemd transient units.
    const DEFAULT_KILL_MODE: &'static str = "control-group";

    /// Render properties as `[Service]` directives.
    #[must_use]
    pub fn to_unit_directives(&self) -> String {
        let mut directives = vec![
            format!("CPUQuota={}%", self.cpu_quota_percent),
            format!("MemoryMax={}", self.memory_max_bytes),
            format!("TasksMax={}", self.tasks_max),
            format!("IOWeight={}", self.io_weight),
            format!("TimeoutStartSec={}", self.timeout_start_sec),
            format!("RuntimeMaxSec={}", self.runtime_max_sec),
            format!("KillMode={}", self.kill_mode),
        ];
        directives.extend(self.sandbox_hardening.to_property_strings());
        directives.join("\n")
    }

    /// Render properties as D-Bus transient unit properties.
    #[must_use]
    pub fn to_dbus_properties(&self) -> Vec<(String, String)> {
        let mut props = vec![
            (
                "CPUQuota".to_string(),
                format!("{}%", self.cpu_quota_percent),
            ),
            ("MemoryMax".to_string(), self.memory_max_bytes.to_string()),
            ("TasksMax".to_string(), self.tasks_max.to_string()),
            ("IOWeight".to_string(), self.io_weight.to_string()),
            (
                "TimeoutStartSec".to_string(),
                self.timeout_start_sec.to_string(),
            ),
            (
                "RuntimeMaxSec".to_string(),
                self.runtime_max_sec.to_string(),
            ),
            ("KillMode".to_string(), self.kill_mode.clone()),
        ];
        // Append sandbox hardening directives as key=value pairs.
        for prop_str in self.sandbox_hardening.to_property_strings() {
            if let Some((key, value)) = prop_str.split_once('=') {
                props.push((key.to_string(), value.to_string()));
            }
        }
        props
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fac::lane::{LanePolicy, LaneTimeouts, ResourceProfile};

    #[test]
    fn from_lane_profile_with_hardening_uses_lane_defaults_without_overrides() {
        let profile =
            LaneProfileV1::new("lane-00", "b3-256:node", "boundary-00").expect("create profile");
        let properties = SystemdUnitProperties::from_lane_profile_with_hardening(
            &profile,
            None,
            SandboxHardeningProfile::default(),
        );

        assert_eq!(properties.cpu_quota_percent, 200);
        assert_eq!(properties.memory_max_bytes, 51_539_607_552);
        assert_eq!(properties.tasks_max, 1536);
        assert_eq!(properties.io_weight, 100);
        assert_eq!(properties.timeout_start_sec, 600);
        assert_eq!(properties.runtime_max_sec, 1800);
        assert_eq!(properties.kill_mode, "control-group");
        // Hardening profile is applied from explicit parameter (INV-SBX-001).
        assert_eq!(
            properties.sandbox_hardening,
            SandboxHardeningProfile::default()
        );
    }

    #[test]
    fn from_lane_profile_enforces_min_constraints_semantics() {
        let mut profile =
            LaneProfileV1::new("lane-00", "b3-256:node", "boundary-00").expect("create profile");
        profile.resource_profile.memory_max_bytes = 10_000;
        profile.timeouts.test_timeout_seconds = 600;

        let constraints = JobConstraints {
            require_nextest: false,
            memory_max_bytes: Some(1_000),
            test_timeout_seconds: Some(120),
        };
        let properties = SystemdUnitProperties::from_lane_profile_with_hardening(
            &profile,
            Some(&constraints),
            SandboxHardeningProfile::default(),
        );

        assert_eq!(properties.memory_max_bytes, 1_000);
        assert_eq!(properties.timeout_start_sec, 120);

        let loose_constraints = JobConstraints {
            require_nextest: false,
            memory_max_bytes: Some(20_000),
            test_timeout_seconds: Some(600),
        };
        let constrained_properties = SystemdUnitProperties::from_lane_profile_with_hardening(
            &profile,
            Some(&loose_constraints),
            SandboxHardeningProfile::default(),
        );

        assert_eq!(constrained_properties.memory_max_bytes, 10_000);
        assert_eq!(constrained_properties.timeout_start_sec, 600);
    }

    #[test]
    fn to_unit_directives_includes_hardening() {
        let profile =
            LaneProfileV1::new("lane-00", "b3-256:node", "boundary-00").expect("create profile");
        let properties = SystemdUnitProperties::from_lane_profile_with_hardening(
            &profile,
            None,
            SandboxHardeningProfile::default(),
        );

        let directives = properties.to_unit_directives();
        // Resource directives.
        assert!(directives.contains("CPUQuota=200%"));
        assert!(directives.contains("MemoryMax=51539607552"));
        assert!(directives.contains("TasksMax=1536"));
        assert!(directives.contains("KillMode=control-group"));
        // Sandbox hardening directives (TCK-00573).
        assert!(directives.contains("NoNewPrivileges=yes"));
        assert!(directives.contains("PrivateTmp=yes"));
        assert!(directives.contains("ProtectControlGroups=yes"));
        assert!(directives.contains("ProtectKernelTunables=yes"));
        assert!(directives.contains("ProtectKernelLogs=yes"));
        assert!(directives.contains("RestrictSUIDSGID=yes"));
        assert!(directives.contains("LockPersonality=yes"));
        assert!(directives.contains("RestrictRealtime=yes"));
        assert!(directives.contains("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6"));
        assert!(directives.contains("SystemCallArchitectures=native"));
    }

    #[test]
    fn to_dbus_properties_includes_hardening() {
        let profile =
            LaneProfileV1::new("lane-00", "b3-256:node", "boundary-00").expect("create profile");
        let properties = SystemdUnitProperties::from_lane_profile_with_hardening(
            &profile,
            None,
            SandboxHardeningProfile::default(),
        );

        let dbus_props = properties.to_dbus_properties();
        // Core resource properties.
        assert!(dbus_props.contains(&("CPUQuota".to_string(), "200%".to_string())));
        assert!(dbus_props.contains(&("KillMode".to_string(), "control-group".to_string())));
        // Sandbox hardening (TCK-00573).
        assert!(
            dbus_props.contains(&("NoNewPrivileges".to_string(), "yes".to_string())),
            "NoNewPrivileges missing from D-Bus properties"
        );
        assert!(
            dbus_props.contains(&("PrivateTmp".to_string(), "yes".to_string())),
            "PrivateTmp missing from D-Bus properties"
        );
        assert!(
            dbus_props.contains(&("ProtectControlGroups".to_string(), "yes".to_string())),
            "ProtectControlGroups missing from D-Bus properties"
        );
        assert!(
            dbus_props.contains(&("SystemCallArchitectures".to_string(), "native".to_string())),
            "SystemCallArchitectures missing from D-Bus properties"
        );
    }

    #[test]
    fn handles_zero_and_max_edge_values() {
        let zero_profile = LaneProfileV1 {
            schema: "apm2.fac.lane_profile.v1".to_string(),
            lane_id: "lane-00".to_string(),
            node_fingerprint: "b3-256:node".to_string(),
            boundary_id: "boundary-00".to_string(),
            resource_profile: ResourceProfile {
                cpu_quota_percent: 0,
                memory_max_bytes: 0,
                pids_max: 0,
                io_weight: 0,
            },
            timeouts: LaneTimeouts {
                test_timeout_seconds: 0,
                job_runtime_max_seconds: 0,
            },
            policy: LanePolicy::default(),
        };

        let zero_properties = SystemdUnitProperties::from_lane_profile_with_hardening(
            &zero_profile,
            Some(&JobConstraints {
                require_nextest: false,
                test_timeout_seconds: Some(0),
                memory_max_bytes: Some(0),
            }),
            SandboxHardeningProfile::default(),
        );

        assert_eq!(zero_properties.cpu_quota_percent, 0);
        assert_eq!(zero_properties.memory_max_bytes, 0);
        assert_eq!(zero_properties.tasks_max, 0);
        assert_eq!(zero_properties.io_weight, 0);
        assert_eq!(zero_properties.timeout_start_sec, 0);
        assert_eq!(zero_properties.runtime_max_sec, 0);

        let max_profile = LaneProfileV1 {
            schema: "apm2.fac.lane_profile.v1".to_string(),
            lane_id: "lane-00".to_string(),
            node_fingerprint: "b3-256:node".to_string(),
            boundary_id: "boundary-00".to_string(),
            resource_profile: ResourceProfile {
                cpu_quota_percent: u32::MAX,
                memory_max_bytes: u64::MAX,
                pids_max: u32::MAX,
                io_weight: u32::MAX,
            },
            timeouts: LaneTimeouts {
                test_timeout_seconds: u64::MAX,
                job_runtime_max_seconds: u64::MAX,
            },
            policy: LanePolicy::default(),
        };

        let max_properties = SystemdUnitProperties::from_lane_profile_with_hardening(
            &max_profile,
            Some(&JobConstraints {
                require_nextest: false,
                test_timeout_seconds: Some(u64::MAX),
                memory_max_bytes: Some(u64::MAX),
            }),
            SandboxHardeningProfile::default(),
        );

        assert_eq!(max_properties.cpu_quota_percent, u32::MAX);
        assert_eq!(max_properties.memory_max_bytes, u64::MAX);
        assert_eq!(max_properties.tasks_max, u32::MAX);
        assert_eq!(max_properties.io_weight, u32::MAX);
        assert_eq!(max_properties.timeout_start_sec, u64::MAX);
        assert_eq!(max_properties.runtime_max_sec, u64::MAX);
    }

    // ── Sandbox hardening profile tests (TCK-00573) ──

    #[test]
    fn default_hardening_profile_enables_all_directives() {
        let profile = SandboxHardeningProfile::default();
        assert!(profile.no_new_privileges);
        assert!(profile.private_tmp);
        assert!(profile.protect_control_groups);
        assert!(profile.protect_kernel_tunables);
        assert!(profile.protect_kernel_logs);
        assert!(profile.restrict_suid_sgid);
        assert!(profile.lock_personality);
        assert!(profile.restrict_realtime);
        assert!(profile.system_call_architectures_native);
        assert_eq!(
            profile.restrict_address_families,
            vec!["AF_UNIX", "AF_INET", "AF_INET6"]
        );
        assert_eq!(profile.enabled_directive_count(), 10);
    }

    #[test]
    fn hardening_profile_validates_default() {
        let profile = SandboxHardeningProfile::default();
        assert!(profile.validate().is_ok());
    }

    #[test]
    fn hardening_profile_rejects_too_many_address_families() {
        let profile = SandboxHardeningProfile {
            restrict_address_families: (0..17).map(|i| format!("AF_TEST{i}")).collect(),
            ..Default::default()
        };
        let err = profile.validate().unwrap_err();
        assert!(err.contains("max is 16"), "error: {err}");
    }

    #[test]
    fn hardening_profile_rejects_empty_address_family() {
        let profile = SandboxHardeningProfile {
            restrict_address_families: vec![
                "AF_UNIX".to_string(),
                "AF_INET".to_string(),
                "AF_INET6".to_string(),
                String::new(),
            ],
            ..Default::default()
        };
        let err = profile.validate().unwrap_err();
        assert!(err.contains("is empty"), "error: {err}");
    }

    #[test]
    fn hardening_profile_rejects_invalid_address_family_format() {
        let profile = SandboxHardeningProfile {
            restrict_address_families: vec!["AF_UNIX".to_string(), "INVALID".to_string()],
            ..Default::default()
        };
        let err = profile.validate().unwrap_err();
        assert!(err.contains("invalid format"), "error: {err}");
    }

    #[test]
    fn hardening_profile_rejects_duplicate_address_families() {
        let profile = SandboxHardeningProfile {
            restrict_address_families: vec![
                "AF_UNIX".to_string(),
                "AF_INET".to_string(),
                "AF_UNIX".to_string(),
            ],
            ..Default::default()
        };
        let err = profile.validate().unwrap_err();
        assert!(err.contains("duplicate"), "error: {err}");
    }

    #[test]
    fn hardening_profile_property_strings_default() {
        let profile = SandboxHardeningProfile::default();
        let props = profile.to_property_strings();
        assert_eq!(props.len(), 10);
        assert!(props.contains(&"NoNewPrivileges=yes".to_string()));
        assert!(props.contains(&"PrivateTmp=yes".to_string()));
        assert!(props.contains(&"ProtectControlGroups=yes".to_string()));
        assert!(props.contains(&"ProtectKernelTunables=yes".to_string()));
        assert!(props.contains(&"ProtectKernelLogs=yes".to_string()));
        assert!(props.contains(&"RestrictSUIDSGID=yes".to_string()));
        assert!(props.contains(&"LockPersonality=yes".to_string()));
        assert!(props.contains(&"RestrictRealtime=yes".to_string()));
        assert!(props.contains(&"RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6".to_string()));
        assert!(props.contains(&"SystemCallArchitectures=native".to_string()));
    }

    #[test]
    fn hardening_profile_property_strings_partial_disable() {
        let profile = SandboxHardeningProfile {
            no_new_privileges: false,
            private_tmp: false,
            restrict_address_families: vec![],
            ..Default::default()
        };
        let props = profile.to_property_strings();
        assert!(!props.iter().any(|p| p.starts_with("NoNewPrivileges")));
        assert!(!props.iter().any(|p| p.starts_with("PrivateTmp")));
        assert!(
            !props
                .iter()
                .any(|p| p.starts_with("RestrictAddressFamilies"))
        );
        // Other directives still present.
        assert!(props.contains(&"ProtectControlGroups=yes".to_string()));
        assert_eq!(profile.enabled_directive_count(), 7);
    }

    #[test]
    fn hardening_profile_hash_is_deterministic() {
        let a = SandboxHardeningProfile::default();
        let b = SandboxHardeningProfile::default();
        assert_eq!(a.content_hash(), b.content_hash());
        assert_eq!(a.content_hash_hex(), b.content_hash_hex());
        assert!(a.content_hash_hex().starts_with("b3-256:"));
    }

    #[test]
    fn hardening_profile_hash_changes_on_mutation() {
        let a = SandboxHardeningProfile::default();
        let b = SandboxHardeningProfile {
            no_new_privileges: false,
            ..Default::default()
        };
        assert_ne!(a.content_hash(), b.content_hash());
    }

    #[test]
    fn hardening_profile_hash_changes_on_address_family_mutation() {
        let a = SandboxHardeningProfile::default();
        let b = SandboxHardeningProfile {
            restrict_address_families: vec![
                "AF_UNIX".to_string(),
                "AF_INET".to_string(),
                "AF_INET6".to_string(),
                "AF_NETLINK".to_string(),
            ],
            ..Default::default()
        };
        assert_ne!(a.content_hash(), b.content_hash());
    }

    #[test]
    fn hardening_profile_serde_roundtrip() {
        let profile = SandboxHardeningProfile::default();
        let json = serde_json::to_string(&profile).expect("serialize");
        let restored: SandboxHardeningProfile = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(profile, restored);
    }

    #[test]
    fn hardening_profile_serde_partial_with_defaults() {
        // Only specify one field; the rest should default to true/default.
        let json = r#"{"no_new_privileges": false}"#;
        let profile: SandboxHardeningProfile = serde_json::from_str(json).expect("deserialize");
        assert!(!profile.no_new_privileges);
        assert!(profile.private_tmp);
        assert!(profile.protect_control_groups);
        assert_eq!(
            profile.restrict_address_families,
            vec!["AF_UNIX", "AF_INET", "AF_INET6"]
        );
    }

    #[test]
    fn hardening_profile_user_mode_only_emits_no_new_privileges() {
        let profile = SandboxHardeningProfile::default();
        let props = profile.to_user_mode_property_strings();
        assert_eq!(props, vec!["NoNewPrivileges=yes"]);
    }

    #[test]
    fn hardening_profile_user_mode_empty_when_nnp_disabled() {
        let profile = SandboxHardeningProfile {
            no_new_privileges: false,
            ..Default::default()
        };
        let props = profile.to_user_mode_property_strings();
        assert!(props.is_empty());
    }

    #[test]
    fn from_lane_profile_with_hardening_uses_custom_profile() {
        let profile =
            LaneProfileV1::new("lane-00", "b3-256:node", "boundary-00").expect("create profile");
        let hardening = SandboxHardeningProfile {
            private_tmp: false,
            ..Default::default()
        };
        let properties = SystemdUnitProperties::from_lane_profile_with_hardening(
            &profile,
            None,
            hardening.clone(),
        );
        assert_eq!(properties.sandbox_hardening, hardening);
        assert!(!properties.sandbox_hardening.private_tmp);
        // Resource properties are still from lane profile.
        assert_eq!(properties.cpu_quota_percent, 200);
    }
}
