//! Stub implementation for non-Linux platforms.
//!
//! Seccomp is a Linux-specific feature. On other platforms, this module
//! provides a no-op implementation that always reports the filter as
//! not enforced.

use super::{SeccompError, SeccompProfile, SeccompProfileLevel, SeccompResult};

/// Stub implementation that always returns "not applied."
///
/// On non-Linux platforms, seccomp filtering is not available.
/// This function logs a warning and returns successfully with
/// `applied: false`.
///
/// # Errors
///
/// This function never returns an error on non-Linux platforms.
#[allow(clippy::unnecessary_wraps)]
pub fn apply_seccomp_filter(profile: &SeccompProfile) -> Result<SeccompResult, SeccompError> {
    let level_name = profile.level.name();

    if profile.is_enforced() {
        // Log a warning that seccomp is not available
        tracing::warn!(
            level = level_name,
            "Seccomp filtering requested but not available on this platform"
        );
    }

    Ok(SeccompResult {
        applied: false,
        level: profile.level,
        blocked_syscall_count: 0,
        summary: format!("Seccomp not available on this platform (requested level={level_name})"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stub_returns_not_applied() {
        let profile = SeccompProfile::restricted();
        let result = apply_seccomp_filter(&profile).unwrap();

        assert!(!result.applied);
        assert_eq!(result.level, SeccompProfileLevel::Restricted);
        assert_eq!(result.blocked_syscall_count, 0);
        assert!(result.summary.contains("not available"));
    }

    #[test]
    fn test_stub_none_level() {
        let profile = SeccompProfile::none();
        let result = apply_seccomp_filter(&profile).unwrap();

        assert!(!result.applied);
        assert_eq!(result.level, SeccompProfileLevel::None);
    }
}
