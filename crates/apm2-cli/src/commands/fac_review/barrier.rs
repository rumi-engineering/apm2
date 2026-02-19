//! Admission-control helpers used by FAC review tests.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use super::types::{FacEventContext, now_iso8601_millis};

pub fn read_event_payload_bounded(path: &Path, max_bytes: u64) -> Result<String, String> {
    let mut file = File::open(path)
        .map_err(|err| format!("failed to open event payload {}: {err}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|err| format!("failed to stat event payload {}: {err}", path.display()))?;
    if metadata.len() > max_bytes {
        return Err(format!(
            "event payload {} is too large ({} bytes > {} byte limit)",
            path.display(),
            metadata.len(),
            max_bytes
        ));
    }

    let mut reader = (&mut file).take(max_bytes.saturating_add(1));
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .map_err(|err| format!("failed to read event payload {}: {err}", path.display()))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
        return Err(format!(
            "event payload {} exceeds {} byte limit",
            path.display(),
            max_bytes
        ));
    }

    String::from_utf8(bytes)
        .map_err(|err| format!("event payload {} is not valid UTF-8: {err}", path.display()))
}

pub fn is_allowed_author_association(value: &str) -> bool {
    matches!(value, "OWNER" | "MEMBER" | "COLLABORATOR")
}

pub fn build_barrier_decision_event(
    source: &str,
    repo: &str,
    event_name: &str,
    ctx: Option<&FacEventContext>,
    passed: bool,
    reason: Option<&str>,
) -> serde_json::Value {
    let mut envelope = serde_json::Map::new();
    envelope.insert("ts".to_string(), serde_json::json!(now_iso8601_millis()));
    envelope.insert("event".to_string(), serde_json::json!("barrier_decision"));
    envelope.insert("phase".to_string(), serde_json::json!(source));
    envelope.insert(
        "result".to_string(),
        serde_json::json!(if passed { "pass" } else { "fail" }),
    );
    envelope.insert("repo".to_string(), serde_json::json!(repo));
    envelope.insert("event_name".to_string(), serde_json::json!(event_name));
    envelope.insert(
        "pr_number".to_string(),
        serde_json::json!(ctx.map_or(0, |value| value.pr_number)),
    );
    envelope.insert(
        "head_sha".to_string(),
        serde_json::json!(ctx.map_or("-", |value| value.head_sha.as_str())),
    );
    envelope.insert(
        "author_association".to_string(),
        serde_json::json!(ctx.map_or("-", |value| value.author_association.as_str())),
    );
    envelope.insert(
        "actor_login".to_string(),
        serde_json::json!(ctx.map_or("-", |value| value.actor_login.as_str())),
    );
    if let Some(value) = ctx.and_then(|value| value.actor_permission.as_deref()) {
        envelope.insert("actor_permission".to_string(), serde_json::json!(value));
    }
    if let Some(value) = ctx {
        envelope.insert(
            "pr_url".to_string(),
            serde_json::json!(value.pr_url.as_str()),
        );
        envelope.insert(
            "base_ref".to_string(),
            serde_json::json!(value.base_ref.as_str()),
        );
        envelope.insert(
            "default_branch".to_string(),
            serde_json::json!(value.default_branch.as_str()),
        );
        envelope.insert(
            "author_login".to_string(),
            serde_json::json!(value.author_login.as_str()),
        );
    }
    if let Some(value) = reason {
        envelope.insert("reason".to_string(), serde_json::json!(value));
    }
    serde_json::Value::Object(envelope)
}
