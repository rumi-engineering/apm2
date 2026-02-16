// AGENT-AUTHORED (TCK-00549)
//! Rust-native bounded test executor with policy-driven environment.
//!
//! Replaces shell-wrapper command assembly with deterministic Rust logic.
//! Supports both user-mode (`systemd-run --user`) and system-mode
//! (`systemd-run --system`) execution backends. Backend selection and
//! command construction are delegated to the core
//! [`apm2_core::fac::execution_backend`] module.
//!
//! # Environment Policy (TCK-00549)
//!
//! Environment variables passed to the transient systemd unit are derived
//! entirely from `FacPolicyV1` via `build_job_environment()`. No ad-hoc
//! allowlists are used. The caller supplies a pre-computed policy
//! environment map; this module forwards it as `--setenv` arguments to
//! `systemd-run`. The hardcoded `RUSTC_WRAPPER`/`SCCACHE_*` strip is
//! retained as defense-in-depth (INV-ENV-008) on top of the policy filter.
//!
//! # Resource Caps
//!
//! Timeouts, memory, PIDs, and CPU caps are enforced by systemd unit
//! properties (`RuntimeMaxSec`, `MemoryMax`, `TasksMax`, `CPUQuota`),
//! not by shell timers or process-level limits.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use apm2_core::fac::execution_backend::{
    ExecutionBackend, SystemModeConfig, build_systemd_run_command, probe_user_bus, select_backend,
};
use apm2_core::fac::{SandboxHardeningProfile, SystemdUnitProperties};
use apm2_daemon::telemetry::is_cgroup_v2_available;

use super::timeout_policy::parse_memory_limit;

/// Maximum number of `--setenv` pairs forwarded to the transient unit.
/// Prevents unbounded command-line growth from a misconfigured policy.
const MAX_SETENV_PAIRS: usize = 256;

/// Env var keys that are unconditionally stripped from the spawned bounded
/// test process environment, regardless of policy configuration. This is
/// a defense-in-depth measure (INV-ENV-008, TCK-00548) that ensures
/// sccache cannot bypass cgroup containment even if the policy is
/// misconfigured.
const SCCACHE_ENV_STRIP_KEYS: &[&str] = &["RUSTC_WRAPPER"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedTestCommandSpec {
    pub command: Vec<String>,
    pub environment: Vec<(String, String)>,
    pub setenv_pairs: Vec<(String, String)>,
    /// Env var keys to remove from the spawned process environment.
    /// Prevents parent env inheritance of `sccache`/`RUSTC_WRAPPER` keys
    /// that could bypass the bounded test's cgroup containment.
    pub env_remove_keys: Vec<String>,
    /// The execution backend used for this command.
    pub backend: ExecutionBackend,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundedTestLimits<'a> {
    pub timeout_seconds: u64,
    pub kill_after_seconds: u64,
    pub memory_max: &'a str,
    pub pids_max: u64,
    pub cpu_quota: &'a str,
}

/// Parse a CPU quota string (e.g., "200%", "100%") into a u32 percent value.
fn parse_cpu_quota_percent(cpu_quota: &str) -> Result<u32, String> {
    let trimmed = cpu_quota.trim().trim_end_matches('%');
    if trimmed.is_empty() {
        return Err("cpu_quota cannot be empty".to_string());
    }
    trimmed
        .parse::<u32>()
        .map_err(|_| format!("invalid cpu_quota value: `{cpu_quota}`"))
}

/// Convert CLI `BoundedTestLimits` to core `SystemdUnitProperties`.
///
/// Parses string-format limits (e.g., "48G", "200%") into numeric types
/// used by the core command builder. Uses the provided sandbox hardening
/// profile (from policy) instead of hard-coding the default (TCK-00573).
fn limits_to_properties(
    limits: BoundedTestLimits<'_>,
    sandbox_hardening: SandboxHardeningProfile,
) -> Result<SystemdUnitProperties, String> {
    let memory_max_bytes = parse_memory_limit(limits.memory_max)?;
    let cpu_quota_percent = parse_cpu_quota_percent(limits.cpu_quota)?;

    let tasks_max = u32::try_from(limits.pids_max)
        .map_err(|_| format!("pids_max {} exceeds u32 range", limits.pids_max))?;

    Ok(SystemdUnitProperties::from_cli_limits_with_hardening(
        cpu_quota_percent,
        memory_max_bytes,
        tasks_max,
        limits.timeout_seconds,
        sandbox_hardening,
    ))
}

/// Build a bounded test command using policy-driven environment.
///
/// # Arguments
///
/// * `workspace_root` - Working directory for the transient unit.
/// * `limits` - Resource caps enforced by systemd unit properties.
/// * `nextest_command` - The test command to execute inside the unit.
/// * `policy_env` - Pre-computed environment from `FacPolicyV1` via
///   `build_job_environment()`. This is the *sole* source of environment
///   variables forwarded to the transient unit via `--setenv`. No ad-hoc
///   allowlists are applied on top.
///
/// # Errors
///
/// Returns `Err` if:
/// - `nextest_command` is empty
/// - cgroup v2 controllers are unavailable
/// - `systemd-run` is not on PATH
/// - Backend selection or command construction fails
/// - The policy environment exceeds `MAX_SETENV_PAIRS`
pub fn build_bounded_test_command(
    workspace_root: &Path,
    limits: BoundedTestLimits<'_>,
    nextest_command: &[String],
    policy_env: &[(String, String)],
    sandbox_hardening: SandboxHardeningProfile,
) -> Result<BoundedTestCommandSpec, String> {
    if nextest_command.is_empty() {
        return Err("nextest command cannot be empty".to_string());
    }
    if !is_cgroup_v2_available() {
        return Err("cgroup v2 controllers not found (bounded runner unavailable)".to_string());
    }
    if !command_available("systemd-run") {
        return Err("systemd-run not found on PATH".to_string());
    }

    // Convert CLI limits to core properties for unified command
    // construction. Uses the policy-driven sandbox hardening profile
    // (TCK-00573) instead of hard-coding defaults.
    let properties = limits_to_properties(limits, sandbox_hardening)?;

    // Select execution backend: user-mode (requires D-Bus session) or
    // system-mode (headless VPS). Controlled by APM2_FAC_EXECUTION_BACKEND.
    let backend =
        select_backend().map_err(|e| format!("execution backend selection failed: {e}"))?;

    // Build setenv pairs from the policy-computed environment.
    // TCK-00549: The environment is now entirely derived from FacPolicyV1
    // via build_job_environment(). No ad-hoc allowlists are applied here.
    // Defense-in-depth: strip RUSTC_WRAPPER and SCCACHE_* (INV-ENV-008).
    let setenv_pairs = build_policy_setenv_pairs(policy_env)?;

    // Build the user-mode D-Bus environment for process spawning.
    let environment = match backend {
        ExecutionBackend::UserMode => {
            // Verify user bus is available via the core prober (single
            // source of truth for bus detection).
            if !probe_user_bus() {
                return Err("user D-Bus session bus not found for bounded runner. \
                     Set APM2_FAC_EXECUTION_BACKEND=system for headless environments"
                    .to_string());
            }
            normalized_runtime_environment()
        },
        ExecutionBackend::SystemMode => Vec::new(),
    };

    // Resolve system-mode config if needed.
    let system_config = if backend == ExecutionBackend::SystemMode {
        Some(SystemModeConfig::from_env().map_err(|e| format!("system-mode config error: {e}"))?)
    } else {
        None
    };

    // Delegate to core command builder for deterministic, consistent
    // systemd-run argument construction. This ensures the CLI and
    // daemon use identical property sets (INV-EXEC-005).
    let core_cmd = build_systemd_run_command(
        backend,
        &properties,
        workspace_root,
        None,
        system_config.as_ref(),
        nextest_command,
    )
    .map_err(|e| format!("systemd-run command construction failed: {e}"))?;

    // Insert --setenv arguments into the command. The core command
    // builder does not handle setenv (it is a CLI-specific concern for
    // forwarding build environment into the transient unit). We insert
    // them before the property arguments.
    let mut command = Vec::with_capacity(core_cmd.args.len() + setenv_pairs.len() * 2);
    let property_start = core_cmd
        .args
        .iter()
        .position(|a| a == "--property")
        .unwrap_or(core_cmd.args.len());

    // Copy args before properties, then setenv, then the rest.
    command.extend(core_cmd.args[..property_start].iter().cloned());
    append_systemd_setenv_args(&mut command, &setenv_pairs);
    command.extend(core_cmd.args[property_start..].iter().cloned());

    // Collect sccache-related env var keys to strip from the spawned
    // process environment. This prevents the bounded test unit from
    // inheriting sccache configuration from the parent process, which
    // could bypass cgroup containment (TCK-00548 MAJOR-3).
    let mut env_remove_keys: Vec<String> = SCCACHE_ENV_STRIP_KEYS
        .iter()
        .map(|k| (*k).to_string())
        .collect();
    // Also strip any SCCACHE_* vars from parent env.
    for (key, _) in std::env::vars() {
        if key.starts_with("SCCACHE_") && !env_remove_keys.contains(&key) {
            env_remove_keys.push(key);
        }
    }

    Ok(BoundedTestCommandSpec {
        command,
        environment,
        setenv_pairs,
        env_remove_keys,
        backend,
    })
}

fn append_systemd_setenv_args(command: &mut Vec<String>, setenv_pairs: &[(String, String)]) {
    for (key, value) in setenv_pairs {
        command.push("--setenv".to_string());
        command.push(format!("{key}={value}"));
    }
}

/// Build `--setenv` pairs from a policy-computed environment.
///
/// TCK-00549: This replaces the previous ad-hoc allowlist approach. The
/// caller provides a pre-computed environment from `FacPolicyV1` (via
/// `build_job_environment`), and this function forwards all entries as
/// `--setenv` arguments after applying defense-in-depth stripping of
/// `RUSTC_WRAPPER` and `SCCACHE_*` (INV-ENV-008).
///
/// The entries are sorted by key for deterministic command construction
/// (INV-EXEC-005).
fn build_policy_setenv_pairs(
    policy_env: &[(String, String)],
) -> Result<Vec<(String, String)>, String> {
    if policy_env.len() > MAX_SETENV_PAIRS {
        return Err(format!(
            "policy environment exceeds bounded setenv limit: {} > {MAX_SETENV_PAIRS}",
            policy_env.len()
        ));
    }

    let mut setenv = BTreeMap::new();
    for (key, value) in policy_env {
        // Defense-in-depth: strip RUSTC_WRAPPER and SCCACHE_* regardless
        // of policy. The policy's build_job_environment() already strips
        // these (INV-ENV-008), but we enforce it here too in case the
        // caller bypasses policy filtering.
        if key == "RUSTC_WRAPPER" || key.starts_with("SCCACHE_") {
            continue;
        }
        if !value.is_empty() {
            setenv.insert(key.clone(), value.clone());
        }
    }

    Ok(setenv.into_iter().collect())
}

/// Build the D-Bus runtime environment for user-mode execution.
///
/// Retained for process-spawn environment setup (the subprocess that
/// runs `systemd-run --user` needs these variables set in its
/// environment). Bus socket detection is delegated to core's
/// [`probe_user_bus`].
fn normalized_runtime_environment() -> Vec<(String, String)> {
    let xdg_runtime_dir = std::env::var("XDG_RUNTIME_DIR")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(default_runtime_dir);

    let dbus_session_bus = std::env::var("DBUS_SESSION_BUS_ADDRESS")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| format!("unix:path={xdg_runtime_dir}/bus"));

    vec![
        ("XDG_RUNTIME_DIR".to_string(), xdg_runtime_dir),
        ("DBUS_SESSION_BUS_ADDRESS".to_string(), dbus_session_bus),
    ]
}

fn default_runtime_dir() -> String {
    let uid = nix::unistd::Uid::effective().as_raw();
    format!("/run/user/{uid}")
}

fn command_available(command: &str) -> bool {
    Command::new(command)
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
}

// NOTE: `check_sccache_containment_for_build()` was removed as part of
// TCK-00548 review findings (MAJOR-1, MAJOR-3). It checked containment
// against the CLI process PID (wrong PID -- the bounded test unit does
// not exist yet). The fix unconditionally strips sccache env vars from
// bounded test commands via the allowlist and env_remove_keys instead.

#[cfg(test)]
mod tests {
    use apm2_core::fac::SandboxHardeningProfile;

    use super::{
        BoundedTestLimits, MAX_SETENV_PAIRS, append_systemd_setenv_args,
        build_bounded_test_command, build_policy_setenv_pairs, default_runtime_dir,
        limits_to_properties, parse_cpu_quota_percent,
    };

    #[test]
    fn default_runtime_dir_uses_numeric_uid() {
        let runtime_dir = default_runtime_dir();
        assert!(runtime_dir.starts_with("/run/user/"));
        assert!(
            runtime_dir["/run/user/".len()..]
                .chars()
                .all(|ch| ch.is_ascii_digit())
        );
    }

    #[test]
    fn bounded_command_rejects_empty_nextest_command() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let err = build_bounded_test_command(
            temp_dir.path(),
            BoundedTestLimits {
                timeout_seconds: 10,
                kill_after_seconds: 2,
                memory_max: "1G",
                pids_max: 128,
                cpu_quota: "100%",
            },
            &[],
            &[],
            SandboxHardeningProfile::default(),
        )
        .expect_err("empty command must fail");
        assert!(err.contains("nextest command cannot be empty"));
    }

    #[test]
    fn policy_setenv_pairs_forward_policy_env() {
        let policy_env = vec![
            ("CARGO_TARGET_DIR".to_string(), "target".to_string()),
            ("RUSTFLAGS".to_string(), "-Copt-level=1".to_string()),
            ("PATH".to_string(), "/usr/bin".to_string()),
        ];
        let pairs = build_policy_setenv_pairs(&policy_env).expect("policy env accepted");
        // BTreeMap ordering: sorted by key.
        assert_eq!(pairs.len(), 3);
        assert_eq!(pairs[0].0, "CARGO_TARGET_DIR");
        assert_eq!(pairs[1].0, "PATH");
        assert_eq!(pairs[2].0, "RUSTFLAGS");
    }

    #[test]
    fn policy_setenv_pairs_strip_sccache_defense_in_depth() {
        // TCK-00549: Even if policy env contains RUSTC_WRAPPER or
        // SCCACHE_*, they must be stripped (defense-in-depth).
        let policy_env = vec![
            ("RUSTC_WRAPPER".to_string(), "sccache".to_string()),
            ("SCCACHE_DIR".to_string(), "/tmp/sccache".to_string()),
            ("CARGO_HOME".to_string(), "/home/user/.cargo".to_string()),
        ];
        let pairs = build_policy_setenv_pairs(&policy_env).expect("policy env accepted");
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, "CARGO_HOME");
    }

    #[test]
    fn policy_setenv_pairs_skip_empty_values() {
        let policy_env = vec![
            ("CARGO_HOME".to_string(), "/home/.cargo".to_string()),
            ("EMPTY_VAR".to_string(), String::new()),
        ];
        let pairs = build_policy_setenv_pairs(&policy_env).expect("policy env accepted");
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, "CARGO_HOME");
    }

    #[test]
    fn policy_setenv_pairs_reject_exceeding_limit() {
        let policy_env: Vec<(String, String)> = (0..=MAX_SETENV_PAIRS)
            .map(|i| (format!("VAR_{i}"), format!("val_{i}")))
            .collect();
        let err =
            build_policy_setenv_pairs(&policy_env).expect_err("should reject exceeding limit");
        assert!(err.contains("exceeds bounded setenv limit"));
    }

    #[test]
    fn policy_setenv_pairs_are_deterministic() {
        let policy_env = vec![
            ("Z_VAR".to_string(), "z".to_string()),
            ("A_VAR".to_string(), "a".to_string()),
            ("M_VAR".to_string(), "m".to_string()),
        ];
        let pairs1 = build_policy_setenv_pairs(&policy_env).expect("first call");
        let pairs2 = build_policy_setenv_pairs(&policy_env).expect("second call");
        assert_eq!(pairs1, pairs2);
        // Verify sorted order.
        assert_eq!(pairs1[0].0, "A_VAR");
        assert_eq!(pairs1[1].0, "M_VAR");
        assert_eq!(pairs1[2].0, "Z_VAR");
    }

    #[test]
    fn sccache_env_strip_keys_are_populated() {
        // Verify SCCACHE_ENV_STRIP_KEYS contains RUSTC_WRAPPER.
        assert!(
            super::SCCACHE_ENV_STRIP_KEYS.contains(&"RUSTC_WRAPPER"),
            "RUSTC_WRAPPER must be in SCCACHE_ENV_STRIP_KEYS"
        );
    }

    #[test]
    fn parse_cpu_quota_percent_handles_valid_inputs() {
        assert_eq!(parse_cpu_quota_percent("200%").unwrap(), 200);
        assert_eq!(parse_cpu_quota_percent("100%").unwrap(), 100);
        assert_eq!(parse_cpu_quota_percent("50%").unwrap(), 50);
        assert_eq!(parse_cpu_quota_percent("0%").unwrap(), 0);
    }

    #[test]
    fn parse_cpu_quota_percent_rejects_invalid_inputs() {
        assert!(parse_cpu_quota_percent("").is_err());
        assert!(parse_cpu_quota_percent("abc%").is_err());
        assert!(parse_cpu_quota_percent("%").is_err());
    }

    #[test]
    fn limits_to_properties_converts_correctly() {
        let limits = BoundedTestLimits {
            timeout_seconds: 600,
            kill_after_seconds: 20,
            memory_max: "1G",
            pids_max: 512,
            cpu_quota: "200%",
        };
        let props =
            limits_to_properties(limits, SandboxHardeningProfile::default()).expect("valid limits");
        assert_eq!(props.cpu_quota_percent, 200);
        assert_eq!(props.memory_max_bytes, 1024 * 1024 * 1024);
        assert_eq!(props.tasks_max, 512);
        assert_eq!(props.io_weight, 100);
        assert_eq!(props.runtime_max_sec, 600);
        assert_eq!(props.kill_mode, "control-group");
        assert_eq!(props.sandbox_hardening, SandboxHardeningProfile::default());
    }

    #[test]
    fn limits_to_properties_uses_custom_hardening_profile() {
        let limits = BoundedTestLimits {
            timeout_seconds: 600,
            kill_after_seconds: 20,
            memory_max: "1G",
            pids_max: 512,
            cpu_quota: "200%",
        };
        let hardening = SandboxHardeningProfile {
            private_tmp: false,
            ..Default::default()
        };
        let props = limits_to_properties(limits, hardening.clone()).expect("valid limits");
        assert_eq!(props.sandbox_hardening, hardening);
        assert!(!props.sandbox_hardening.private_tmp);
    }

    #[test]
    fn append_systemd_setenv_args_passes_key_value_pairs() {
        let mut command = Vec::new();
        append_systemd_setenv_args(&mut command, &[("TOKEN".to_string(), "abcd".to_string())]);
        assert_eq!(
            command,
            vec!["--setenv".to_string(), "TOKEN=abcd".to_string()]
        );
    }
}
