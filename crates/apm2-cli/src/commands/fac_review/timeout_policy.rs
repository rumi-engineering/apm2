//! Adaptive timeout policy for bounded FAC test execution.
//!
//! FAC keeps a strict steady-state SLA for warm caches (240s) but can
//! temporarily widen the bounded test window for clearly cold workspaces.

use std::path::{Path, PathBuf};

pub const DEFAULT_BOUNDED_TEST_TIMEOUT_SECONDS: u64 = 240;
pub const MAX_MANUAL_TIMEOUT_SECONDS: u64 = 240;
pub const DEFAULT_COLD_CACHE_TIMEOUT_SECONDS: u64 = 420;
pub const MAX_EFFECTIVE_TIMEOUT_SECONDS: u64 = 900;
pub const TEST_TIMEOUT_SLA_MESSAGE: &str = "Steady-state test SLA is p100=240s, p99=180s, p50=80s. FAC may temporarily widen this timeout for cold-cache warm-up runs. Persistent overruns after warm-up are bugs and must be investigated.";

const ENV_COLD_TIMEOUT_SECONDS: &str = "APM2_FAC_COLD_CACHE_TIMEOUT_SECONDS";
const ENV_DISABLE_COLD_BOOST: &str = "APM2_FAC_DISABLE_COLD_CACHE_TIMEOUT_BOOST";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeoutDecision {
    pub requested_seconds: u64,
    pub effective_seconds: u64,
    pub boosted_for_cold_cache: bool,
    pub target_dir: PathBuf,
}

fn env_flag_enabled(name: &str) -> bool {
    std::env::var(name).ok().is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

fn env_u64(name: &str) -> Option<u64> {
    std::env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
}

fn resolve_target_dir(workspace_root: &Path) -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .map_or_else(
            || workspace_root.join("target"),
            |target| {
                if target.is_absolute() {
                    target
                } else {
                    workspace_root.join(target)
                }
            },
        )
}

fn dir_has_entries(dir: &Path) -> bool {
    std::fs::read_dir(dir)
        .ok()
        .and_then(|mut iter| iter.next())
        .is_some()
}

fn cold_cache_detected(target_dir: &Path) -> bool {
    if !target_dir.exists() {
        return true;
    }
    let deps_dir = target_dir.join("debug").join("deps");
    let nextest_dir = target_dir.join("nextest");
    !(dir_has_entries(&deps_dir) || dir_has_entries(&nextest_dir))
}

#[must_use]
pub fn resolve_bounded_test_timeout(
    workspace_root: &Path,
    requested_seconds: u64,
) -> TimeoutDecision {
    let target_dir = resolve_target_dir(workspace_root);
    let disable_boost = env_flag_enabled(ENV_DISABLE_COLD_BOOST);
    let cold_cache = cold_cache_detected(&target_dir);
    let should_boost =
        requested_seconds == DEFAULT_BOUNDED_TEST_TIMEOUT_SECONDS && cold_cache && !disable_boost;

    let effective_seconds = if should_boost {
        env_u64(ENV_COLD_TIMEOUT_SECONDS)
            .unwrap_or(DEFAULT_COLD_CACHE_TIMEOUT_SECONDS)
            .max(requested_seconds)
            .min(MAX_EFFECTIVE_TIMEOUT_SECONDS)
    } else {
        requested_seconds
    };

    TimeoutDecision {
        requested_seconds,
        effective_seconds,
        boosted_for_cold_cache: should_boost && effective_seconds > requested_seconds,
        target_dir,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{
        DEFAULT_BOUNDED_TEST_TIMEOUT_SECONDS, DEFAULT_COLD_CACHE_TIMEOUT_SECONDS,
        resolve_bounded_test_timeout,
    };

    #[test]
    fn cold_workspace_boosts_default_timeout() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let decision =
            resolve_bounded_test_timeout(temp_dir.path(), DEFAULT_BOUNDED_TEST_TIMEOUT_SECONDS);
        assert!(decision.boosted_for_cold_cache);
        assert_eq!(
            decision.effective_seconds,
            DEFAULT_COLD_CACHE_TIMEOUT_SECONDS
        );
    }

    #[test]
    fn warm_workspace_keeps_default_timeout() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let deps_dir = temp_dir.path().join("target").join("debug").join("deps");
        fs::create_dir_all(&deps_dir).expect("create deps dir");
        fs::write(deps_dir.join("libwarm.rmeta"), b"warm").expect("write marker file");

        let decision =
            resolve_bounded_test_timeout(temp_dir.path(), DEFAULT_BOUNDED_TEST_TIMEOUT_SECONDS);
        assert!(!decision.boosted_for_cold_cache);
        assert_eq!(
            decision.effective_seconds,
            DEFAULT_BOUNDED_TEST_TIMEOUT_SECONDS
        );
    }

    #[test]
    fn non_default_timeout_is_not_auto_boosted() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let decision = resolve_bounded_test_timeout(temp_dir.path(), 180);
        assert!(!decision.boosted_for_cold_cache);
        assert_eq!(decision.effective_seconds, 180);
    }
}
