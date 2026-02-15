//! Rust-native bounded test runner command construction.
//!
//! Replaces shell-wrapper command assembly with deterministic Rust logic.
//! Supports both user-mode (`systemd-run --user`) and system-mode
//! (`systemd-run --system`) execution backends. Backend selection and
//! command construction are delegated to the core
//! [`apm2_core::fac::execution_backend`] module; this module handles
//! CLI-specific concerns (setenv allowlisting, memory/cpu string
//! parsing, environment normalization).

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use apm2_core::fac::SystemdUnitProperties;
use apm2_core::fac::execution_backend::{
    ExecutionBackend, SystemModeConfig, build_systemd_run_command, probe_user_bus, select_backend,
};
use apm2_daemon::telemetry::is_cgroup_v2_available;

use super::timeout_policy::parse_memory_limit;

const SYSTEMD_SETENV_ALLOWLIST_EXACT: &[&str] = &[
    "GITHUB_RUN_ID",
    "GITHUB_RUN_ATTEMPT",
    "APM2_CI_DRY_RUN",
    "APM2_CI_TARGET_DIR",
    "CARGO_TERM_COLOR",
    "CARGO_INCREMENTAL",
    "RUSTFLAGS",
    "RUST_BACKTRACE",
    "CARGO_TARGET_DIR",
    "CARGO_BUILD_JOBS",
    "NEXTEST_TEST_THREADS",
    "CARGO_HOME",
    "RUSTUP_HOME",
    "RUSTUP_TOOLCHAIN",
    "RUSTDOCFLAGS",
    // TCK-00526: PATH, HOME, USER, and LANG are required for correct
    // toolchain resolution inside the bounded test unit. These are
    // included in the FAC policy's default env_allowlist_prefixes and
    // must be forwarded through systemd --setenv to maintain execution
    // correctness.
    "PATH",
    "HOME",
    "USER",
    "LANG",
];

/// `RUSTC_WRAPPER` and `SCCACHE_*` are intentionally EXCLUDED from the
/// allowlist. In bounded test mode we cannot verify cgroup containment
/// for the systemd transient unit before it starts, so sccache env vars
/// are never forwarded. This prevents cache poisoning from sccache
/// daemons running outside the job's cgroup (MAJOR-1, MAJOR-3 fix per
/// TCK-00548 review findings).
const SYSTEMD_SETENV_ALLOWLIST_PREFIXES: &[&str] = &[];

/// Env var keys that are explicitly stripped from the spawned bounded
/// test process environment to prevent inheritance from the parent.
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
/// used by the core command builder.
fn limits_to_properties(limits: BoundedTestLimits<'_>) -> Result<SystemdUnitProperties, String> {
    let memory_max_bytes = parse_memory_limit(limits.memory_max)?;
    let cpu_quota_percent = parse_cpu_quota_percent(limits.cpu_quota)?;

    Ok(SystemdUnitProperties {
        cpu_quota_percent,
        memory_max_bytes,
        tasks_max: u32::try_from(limits.pids_max)
            .map_err(|_| format!("pids_max {} exceeds u32 range", limits.pids_max))?,
        io_weight: 100,
        timeout_start_sec: limits.timeout_seconds,
        runtime_max_sec: limits.timeout_seconds,
        kill_mode: "control-group".to_string(),
    })
}

pub fn build_bounded_test_command(
    workspace_root: &Path,
    limits: BoundedTestLimits<'_>,
    nextest_command: &[String],
    extra_setenv: &[(String, String)],
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
    // construction.
    let properties = limits_to_properties(limits)?;

    // Select execution backend: user-mode (requires D-Bus session) or
    // system-mode (headless VPS). Controlled by APM2_FAC_EXECUTION_BACKEND.
    let backend =
        select_backend().map_err(|e| format!("execution backend selection failed: {e}"))?;

    // Build setenv pairs (common to both backends).
    let setenv_pairs = build_systemd_setenv_pairs(collect_inherited_setenv_pairs(), extra_setenv)?;

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

fn build_systemd_setenv_pairs(
    inherited_setenv: Vec<(String, String)>,
    extra_setenv: &[(String, String)],
) -> Result<Vec<(String, String)>, String> {
    let mut setenv = BTreeMap::new();
    for (key, value) in inherited_setenv {
        setenv.insert(key, value);
    }

    // Forward caller-supplied env vars (e.g. lane profile NEXTEST_TEST_THREADS,
    // CARGO_BUILD_JOBS) that aren't in the process environment at build time.
    // Extra values override inherited ones for the same key.
    for (key, value) in extra_setenv {
        if !is_allowlisted_setenv_key(key) {
            return Err(format!("unsupported bounded test env override key: {key}"));
        }
        if value.is_empty() {
            continue;
        }
        setenv.insert(key.clone(), value.clone());
    }

    Ok(setenv.into_iter().collect())
}

fn collect_inherited_setenv_pairs() -> Vec<(String, String)> {
    let mut setenv = BTreeMap::new();

    for key in SYSTEMD_SETENV_ALLOWLIST_EXACT {
        if let Ok(value) = std::env::var(key) {
            if !value.is_empty() {
                setenv.insert((*key).to_string(), value);
            }
        }
    }

    for (key, value) in std::env::vars() {
        if SYSTEMD_SETENV_ALLOWLIST_PREFIXES
            .iter()
            .any(|prefix| key.starts_with(prefix))
            && !value.is_empty()
        {
            setenv.insert(key, value);
        }
    }

    setenv.into_iter().collect()
}

fn is_allowlisted_setenv_key(key: &str) -> bool {
    SYSTEMD_SETENV_ALLOWLIST_EXACT.contains(&key)
        || SYSTEMD_SETENV_ALLOWLIST_PREFIXES
            .iter()
            .any(|prefix| key.starts_with(prefix))
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
// against the CLI process PID (wrong PID — the bounded test unit does
// not exist yet). The fix unconditionally strips sccache env vars from
// bounded test commands via the allowlist and env_remove_keys instead.

#[cfg(test)]
mod tests {
    use super::{
        BoundedTestLimits, append_systemd_setenv_args, build_bounded_test_command,
        build_systemd_setenv_pairs, default_runtime_dir, limits_to_properties,
        parse_cpu_quota_percent,
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
        )
        .expect_err("empty command must fail");
        assert!(err.contains("nextest command cannot be empty"));
    }

    #[test]
    fn setenv_pairs_are_deduplicated_and_extra_overrides_inherited() {
        let inherited = vec![
            ("NEXTEST_TEST_THREADS".to_string(), "8".to_string()),
            ("CARGO_BUILD_JOBS".to_string(), "8".to_string()),
            (
                "RUSTFLAGS".to_string(),
                "-Cforce-frame-pointers".to_string(),
            ),
        ];
        let extra = vec![
            ("NEXTEST_TEST_THREADS".to_string(), "4".to_string()),
            ("RUSTFLAGS".to_string(), "-Copt-level=1".to_string()),
            ("CARGO_BUILD_JOBS".to_string(), String::new()),
        ];

        let pairs =
            build_systemd_setenv_pairs(inherited, &extra).expect("allowlisted overrides accepted");
        assert_eq!(
            pairs,
            vec![
                ("CARGO_BUILD_JOBS".to_string(), "8".to_string()),
                ("NEXTEST_TEST_THREADS".to_string(), "4".to_string()),
                ("RUSTFLAGS".to_string(), "-Copt-level=1".to_string()),
            ]
        );
    }

    #[test]
    fn sccache_env_vars_rejected_from_setenv_allowlist() {
        // TCK-00548: RUSTC_WRAPPER and SCCACHE_* must NOT be in the
        // allowlist. They are unconditionally stripped from bounded
        // test commands because cgroup containment cannot be verified
        // for systemd transient units before they start.
        let err = build_systemd_setenv_pairs(
            Vec::new(),
            &[("RUSTC_WRAPPER".to_string(), "sccache".to_string())],
        )
        .expect_err("RUSTC_WRAPPER should be rejected");
        assert!(
            err.contains("RUSTC_WRAPPER"),
            "error should mention key: {err}"
        );

        let err2 = build_systemd_setenv_pairs(
            Vec::new(),
            &[("SCCACHE_CACHE_SIZE".to_string(), "100G".to_string())],
        )
        .expect_err("SCCACHE_* should be rejected");
        assert!(
            err2.contains("SCCACHE_"),
            "error should mention key: {err2}"
        );
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
    fn setenv_pairs_reject_unknown_extra_keys() {
        let err =
            build_systemd_setenv_pairs(Vec::new(), &[("UNSAFE_ENV".to_string(), "1".to_string())])
                .expect_err("unknown override key should fail");
        assert!(err.contains("UNSAFE_ENV"));
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
        let props = limits_to_properties(limits).expect("valid limits");
        assert_eq!(props.cpu_quota_percent, 200);
        assert_eq!(props.memory_max_bytes, 1024 * 1024 * 1024);
        assert_eq!(props.tasks_max, 512);
        assert_eq!(props.io_weight, 100);
        assert_eq!(props.runtime_max_sec, 600);
        assert_eq!(props.kill_mode, "control-group");
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
