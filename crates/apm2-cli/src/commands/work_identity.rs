//! Shared work-identity helpers for FAC and work command surfaces.
//!
//! These helpers keep identifier parsing/validation and branch alias extraction
//! behavior consistent across CLI command paths.

/// Maximum supported identifier length for work/lease/session IDs.
pub const MAX_IDENTIFIER_LENGTH: usize = 256;

/// Normalize an optional CLI argument by trimming and dropping empty values.
#[must_use]
pub fn normalize_non_empty_arg(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

/// Validate a canonical identifier under shared shape constraints.
///
/// IDs must:
/// - be non-empty,
/// - not exceed [`MAX_IDENTIFIER_LENGTH`],
/// - start with the required prefix,
/// - contain only ASCII alnum / `_` / `-`.
pub fn validate_identifier(value: &str, field: &str, required_prefix: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{field} cannot be empty"));
    }
    if value.len() > MAX_IDENTIFIER_LENGTH {
        return Err(format!(
            "{field} exceeds max length ({} > {MAX_IDENTIFIER_LENGTH})",
            value.len(),
        ));
    }
    if !value.starts_with(required_prefix) {
        return Err(format!(
            "{field} must start with `{required_prefix}`, got `{value}`"
        ));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(format!(
            "{field} contains invalid characters; only [A-Za-z0-9_-] are allowed"
        ));
    }
    Ok(())
}

/// Validate canonical `W-*` work IDs.
pub fn validate_work_id(value: &str) -> Result<(), String> {
    validate_identifier(value, "work_id", "W-")
}

/// Validate canonical `L-*` lease IDs.
pub fn validate_lease_id(value: &str) -> Result<(), String> {
    validate_identifier(value, "lease_id", "L-")
}

/// Validate canonical `S-*` session IDs.
pub fn validate_session_id(value: &str) -> Result<(), String> {
    validate_identifier(value, "session_id", "S-")
}

/// Extract `TCK-xxxxx` token from arbitrary text.
#[must_use]
pub fn extract_tck_from_text(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    if bytes.len() < 9 {
        return None;
    }

    for idx in 0..=bytes.len() - 9 {
        if &bytes[idx..idx + 4] != b"TCK-" {
            continue;
        }
        let digits = &bytes[idx + 4..idx + 9];
        if !digits.iter().all(u8::is_ascii_digit) {
            continue;
        }
        if idx + 9 < bytes.len() && bytes[idx + 9].is_ascii_digit() {
            continue;
        }
        let matched = std::str::from_utf8(&bytes[idx..idx + 9]).ok()?;
        return Some(matched.to_string());
    }

    None
}

/// Derive deterministic ad-hoc session identity from `(work_id, lease_id)`.
#[must_use]
pub fn derive_adhoc_session_id(work_id: &str, lease_id: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"apm2.work_status.adhoc_session.v1");
    hasher.update(b"\0");
    hasher.update(work_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(lease_id.as_bytes());
    let digest = hasher.finalize();
    format!("S-adhoc-{}", hex::encode(digest.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_identifier_rejects_invalid_prefix() {
        let err =
            validate_identifier("bad", "work_id", "W-").expect_err("invalid prefix must fail");
        assert!(err.contains("must start with `W-`"));
    }

    #[test]
    fn extract_tck_from_text_matches_exact_five_digits() {
        assert_eq!(
            extract_tck_from_text("ticket/RFC-0032/TCK-00640-work"),
            Some("TCK-00640".to_string())
        );
        assert_eq!(
            extract_tck_from_text("ticket/TCK-006401"),
            None,
            "six-digit token must not partially match"
        );
    }

    #[test]
    fn derive_adhoc_session_id_is_deterministic() {
        let first = derive_adhoc_session_id("W-TCK-00640", "L-issued-001");
        let second = derive_adhoc_session_id("W-TCK-00640", "L-issued-001");
        let third = derive_adhoc_session_id("W-TCK-00640", "L-issued-002");
        assert_eq!(first, second);
        assert_ne!(first, third);
        assert!(first.starts_with("S-adhoc-"));
    }
}
