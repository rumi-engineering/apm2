//! Policy event generation.
//!
//! This module provides functions for creating policy-related kernel events,
//! specifically the `PolicyLoaded` event that is emitted when a policy is
//! loaded at startup.

use super::parser::LoadedPolicy;
use crate::events::{PolicyEvent, PolicyLoaded, PolicyViolation, policy_event};

/// Creates a `PolicyLoaded` event from a loaded policy.
///
/// The event includes:
/// - The BLAKE3 hash of the policy content
/// - The policy version string
/// - The number of rules in the policy
#[must_use]
pub fn create_policy_loaded_event(loaded: &LoadedPolicy) -> PolicyEvent {
    PolicyEvent {
        event: Some(policy_event::Event::Loaded(PolicyLoaded {
            policy_hash: loaded.content_hash.to_vec(),
            policy_version: loaded.policy.version.clone(),
            rule_count: loaded.rule_count() as u64,
        })),
    }
}

/// Creates a `PolicyLoaded` event directly from components.
///
/// This is useful when you have the individual components rather than
/// a `LoadedPolicy` struct.
#[must_use]
#[allow(clippy::missing_const_for_fn)] // Cannot be const due to heap allocations in Option
pub fn create_policy_loaded_event_from_parts(
    policy_hash: Vec<u8>,
    policy_version: String,
    rule_count: u64,
) -> PolicyEvent {
    PolicyEvent {
        event: Some(policy_event::Event::Loaded(PolicyLoaded {
            policy_hash,
            policy_version,
            rule_count,
        })),
    }
}

/// Creates a `PolicyViolation` event.
///
/// This should be called when a request is denied by policy or budget.
#[must_use]
#[allow(clippy::missing_const_for_fn)]
pub fn create_policy_violation_event(
    session_id: String,
    violation_type: String,
    rule_id: String,
    details: String,
) -> PolicyEvent {
    PolicyEvent {
        event: Some(policy_event::Event::Violation(PolicyViolation {
            session_id,
            violation_type,
            rule_id,
            details,
        })),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_POLICY_YAML: &str = r#"
policy:
  version: "1.0.0"
  name: "test-policy"
  rules:
    - id: "RULE-001"
      type: tool_allow
      tool: "fs.read"
      decision: allow
  default_decision: deny
"#;

    #[test]
    fn test_create_policy_loaded_event() {
        let loaded = LoadedPolicy::from_yaml(VALID_POLICY_YAML).unwrap();
        let event = create_policy_loaded_event(&loaded);

        match event.event {
            Some(policy_event::Event::Loaded(loaded_event)) => {
                assert_eq!(loaded_event.policy_hash.len(), 32);
                assert_eq!(loaded_event.policy_version, "1.0.0");
                assert_eq!(loaded_event.rule_count, 1);
            },
            _ => panic!("Expected PolicyLoaded event"),
        }
    }

    #[test]
    fn test_create_policy_loaded_event_hash_matches() {
        let loaded = LoadedPolicy::from_yaml(VALID_POLICY_YAML).unwrap();
        let event = create_policy_loaded_event(&loaded);

        match event.event {
            Some(policy_event::Event::Loaded(loaded_event)) => {
                assert_eq!(loaded_event.policy_hash, loaded.content_hash.to_vec());
            },
            _ => panic!("Expected PolicyLoaded event"),
        }
    }

    #[test]
    fn test_create_policy_loaded_event_from_parts() {
        let hash = vec![0u8; 32];
        let version = "2.0.0".to_string();
        let rule_count = 5;

        let event =
            create_policy_loaded_event_from_parts(hash.clone(), version.clone(), rule_count);

        match event.event {
            Some(policy_event::Event::Loaded(loaded_event)) => {
                assert_eq!(loaded_event.policy_hash, hash);
                assert_eq!(loaded_event.policy_version, version);
                assert_eq!(loaded_event.rule_count, rule_count);
            },
            _ => panic!("Expected PolicyLoaded event"),
        }
    }

    #[test]
    fn test_policy_loaded_event_deterministic() {
        // Same policy content should produce same hash in event
        let loaded1 = LoadedPolicy::from_yaml(VALID_POLICY_YAML).unwrap();
        let loaded2 = LoadedPolicy::from_yaml(VALID_POLICY_YAML).unwrap();

        let event1 = create_policy_loaded_event(&loaded1);
        let event2 = create_policy_loaded_event(&loaded2);

        match (&event1.event, &event2.event) {
            (Some(policy_event::Event::Loaded(e1)), Some(policy_event::Event::Loaded(e2))) => {
                assert_eq!(e1.policy_hash, e2.policy_hash);
            },
            _ => panic!("Expected PolicyLoaded events"),
        }
    }

    #[test]
    fn test_create_policy_violation_event() {
        let event = create_policy_violation_event(
            "session-123".to_string(),
            "DENY".to_string(),
            "DEFAULT_DENY".to_string(),
            "No matching rule".to_string(),
        );

        match event.event {
            Some(policy_event::Event::Violation(violation)) => {
                assert_eq!(violation.session_id, "session-123");
                assert_eq!(violation.violation_type, "DENY");
                assert_eq!(violation.rule_id, "DEFAULT_DENY");
                assert_eq!(violation.details, "No matching rule");
            },
            _ => panic!("Expected PolicyViolation event"),
        }
    }
}
