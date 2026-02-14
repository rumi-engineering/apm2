//! Local reviewer identity helpers for projection flows.

pub(super) fn resolve_local_reviewer_identity() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "unknown_local_user".to_string())
}
