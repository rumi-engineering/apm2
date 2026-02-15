//! Rust-native bounded test runner command construction.
//!
//! Replaces shell-wrapper command assembly with deterministic Rust logic.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use apm2_daemon::telemetry::is_cgroup_v2_available;

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
    "RUSTUP_TOOLCHAIN",
    "RUSTC_WRAPPER",
    "RUSTDOCFLAGS",
];

const SYSTEMD_SETENV_ALLOWLIST_PREFIXES: &[&str] = &["SCCACHE_"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedTestCommandSpec {
    pub command: Vec<String>,
    pub environment: Vec<(String, String)>,
    pub setenv_pairs: Vec<(String, String)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundedTestLimits<'a> {
    pub timeout_seconds: u64,
    pub kill_after_seconds: u64,
    pub memory_max: &'a str,
    pub pids_max: u64,
    pub cpu_quota: &'a str,
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

    let environment = normalized_runtime_environment();
    let user_bus_path = resolve_user_bus_socket_path(&environment)
        .ok_or_else(|| "failed to derive D-Bus socket path for bounded runner".to_string())?;
    if !Path::new(&user_bus_path).exists() {
        return Err(format!(
            "user D-Bus socket not found at {user_bus_path}; bounded runner unavailable"
        ));
    }

    let mut command = vec![
        "systemd-run".to_string(),
        "--user".to_string(),
        "--pipe".to_string(),
        "--quiet".to_string(),
        "--wait".to_string(),
        "--working-directory".to_string(),
        workspace_root.display().to_string(),
    ];

    let setenv_pairs = build_systemd_setenv_pairs(collect_inherited_setenv_pairs(), extra_setenv)?;
    append_systemd_setenv_args(&mut command, &setenv_pairs);

    for property in bounded_unit_properties(limits) {
        command.push("--property".to_string());
        command.push(property);
    }

    command.push("--".to_string());
    command.extend(nextest_command.iter().cloned());

    Ok(BoundedTestCommandSpec {
        command,
        environment,
        setenv_pairs,
    })
}

fn bounded_unit_properties(limits: BoundedTestLimits<'_>) -> Vec<String> {
    vec![
        "MemoryAccounting=yes".to_string(),
        "CPUAccounting=yes".to_string(),
        "TasksAccounting=yes".to_string(),
        format!("MemoryMax={}", limits.memory_max),
        format!("TasksMax={}", limits.pids_max),
        format!("CPUQuota={}", limits.cpu_quota),
        format!("RuntimeMaxSec={}s", limits.timeout_seconds),
        // Fail-closed cleanup: tests may intentionally leave TERM-ignoring descendants.
        // Use SIGKILL for unit stop to prevent false FAIL due stop timeout after
        // an otherwise successful test command exit.
        "KillSignal=SIGKILL".to_string(),
        format!("TimeoutStopSec={}s", limits.kill_after_seconds),
        "FinalKillSignal=SIGKILL".to_string(),
        "SendSIGKILL=yes".to_string(),
        "KillMode=control-group".to_string(),
    ]
}

fn append_systemd_setenv_args(command: &mut Vec<String>, setenv_pairs: &[(String, String)]) {
    for (key, _value) in setenv_pairs {
        command.push("--setenv".to_string());
        command.push(key.clone());
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

fn resolve_user_bus_socket_path(environment: &[(String, String)]) -> Option<String> {
    environment
        .iter()
        .find_map(|(key, value)| (key == "DBUS_SESSION_BUS_ADDRESS").then_some(value.as_str()))
        .and_then(parse_dbus_unix_path)
        .map(str::to_string)
        .or_else(|| {
            environment.iter().find_map(|(key, value)| {
                (key == "XDG_RUNTIME_DIR").then_some(format!("{value}/bus"))
            })
        })
}

fn parse_dbus_unix_path(address: &str) -> Option<&str> {
    for endpoint in address.split(';') {
        for token in endpoint.split(',') {
            if let Some(path) = token.strip_prefix("unix:path=") {
                if !path.is_empty() {
                    return Some(path);
                }
            }
        }
    }
    None
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

#[cfg(test)]
mod tests {
    use super::{
        BoundedTestLimits, append_systemd_setenv_args, bounded_unit_properties,
        build_bounded_test_command, build_systemd_setenv_pairs, default_runtime_dir,
        parse_dbus_unix_path, resolve_user_bus_socket_path,
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
            ("SCCACHE_CACHE_SIZE".to_string(), "100G".to_string()),
        ];
        let extra = vec![
            ("NEXTEST_TEST_THREADS".to_string(), "4".to_string()),
            ("SCCACHE_CACHE_SIZE".to_string(), "200G".to_string()),
            ("CARGO_BUILD_JOBS".to_string(), String::new()),
        ];

        let pairs =
            build_systemd_setenv_pairs(inherited, &extra).expect("allowlisted overrides accepted");
        assert_eq!(
            pairs,
            vec![
                ("CARGO_BUILD_JOBS".to_string(), "8".to_string()),
                ("NEXTEST_TEST_THREADS".to_string(), "4".to_string()),
                ("SCCACHE_CACHE_SIZE".to_string(), "200G".to_string()),
            ]
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
    fn parse_dbus_unix_path_extracts_unix_path_entry() {
        assert_eq!(
            parse_dbus_unix_path("unix:path=/run/user/1000/bus,guid=abc"),
            Some("/run/user/1000/bus")
        );
        assert_eq!(
            parse_dbus_unix_path("tcp:host=127.0.0.1;unix:path=/tmp/custom-bus,guid=abc"),
            Some("/tmp/custom-bus")
        );
        assert_eq!(parse_dbus_unix_path("unix:abstract=/tmp/dbus"), None);
    }

    #[test]
    fn resolve_user_bus_socket_prefers_dbus_session_bus_path() {
        let env = vec![
            ("XDG_RUNTIME_DIR".to_string(), "/run/user/1000".to_string()),
            (
                "DBUS_SESSION_BUS_ADDRESS".to_string(),
                "unix:path=/tmp/custom-bus,guid=abc".to_string(),
            ),
        ];
        assert_eq!(
            resolve_user_bus_socket_path(&env),
            Some("/tmp/custom-bus".to_string())
        );
    }

    #[test]
    fn bounded_unit_properties_use_sigkill_teardown() {
        let properties = bounded_unit_properties(BoundedTestLimits {
            timeout_seconds: 600,
            kill_after_seconds: 20,
            memory_max: "48G",
            pids_max: 1536,
            cpu_quota: "200%",
        });

        assert!(properties.iter().any(|p| p == "KillSignal=SIGKILL"));
        assert!(properties.iter().any(|p| p == "FinalKillSignal=SIGKILL"));
        assert!(properties.iter().any(|p| p == "KillMode=control-group"));
    }

    #[test]
    fn append_systemd_setenv_args_only_passes_names() {
        let mut command = Vec::new();
        append_systemd_setenv_args(&mut command, &[("TOKEN".to_string(), "abcd".to_string())]);
        assert_eq!(command, vec!["--setenv".to_string(), "TOKEN".to_string()]);
        assert!(command.iter().all(|arg: &String| !arg.contains('=')));
    }
}
