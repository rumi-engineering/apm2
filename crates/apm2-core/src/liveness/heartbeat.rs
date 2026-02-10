//! Liveness heartbeat receipts for launch execution monitoring (RFC-0020).
//!
//! Emits deterministic heartbeat receipts consumable by gate/orchestrator
//! logic. Ambiguous liveness state denies authoritative progression
//! (fail-closed).

use std::fmt;

use serde::de::Visitor;
use serde::{Deserialize, Deserializer, Serialize, de};

/// Maximum length for liveness heartbeat detail strings.
pub const MAX_HEARTBEAT_DETAIL_LENGTH: usize = 512;

/// Maximum length for a liveness heartbeat run identifier.
pub const MAX_RUN_ID_LENGTH: usize = 256;

/// Health verdict for a liveness heartbeat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthVerdict {
    /// Process is running and responsive.
    Healthy,
    /// Process has not responded within expected interval.
    Stalled,
    /// Process has terminated unexpectedly.
    Crashed,
    /// Liveness state is ambiguous (fail-closed: deny progression).
    Ambiguous,
}

/// A deterministic liveness heartbeat receipt for an active launch execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LivenessHeartbeatReceiptV1 {
    /// Stable run identity (from dispatch idempotency).
    #[serde(deserialize_with = "deserialize_run_id")]
    pub run_id: String,
    /// Episode identity hash.
    pub episode_id: [u8; 32],
    /// HTF tick at which this heartbeat was emitted.
    pub emitted_at_tick: u64,
    /// Time envelope reference (HTF authority binding).
    pub time_envelope_ref: [u8; 32],
    /// Current health verdict.
    pub health_verdict: HealthVerdict,
    /// Restart count within current restart window.
    pub restart_count: u32,
    /// Maximum allowed restarts within window.
    pub max_restarts: u32,
    /// Process uptime in milliseconds (since last restart).
    pub uptime_ms: u64,
    /// Optional detail message (bounded).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_detail"
    )]
    pub detail: Option<String>,
}

impl LivenessHeartbeatReceiptV1 {
    /// Returns whether all bounded string constraints are satisfied.
    #[must_use]
    pub fn has_valid_bounds(&self) -> bool {
        self.run_id.len() <= MAX_RUN_ID_LENGTH
            && self
                .detail
                .as_ref()
                .is_none_or(|detail| detail.len() <= MAX_HEARTBEAT_DETAIL_LENGTH)
    }
}

struct BoundedStringVisitor(usize);

impl Visitor<'_> for BoundedStringVisitor {
    type Value = String;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "a string of at most {} bytes", self.0)
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        if value.len() > self.0 {
            Err(E::custom(format!(
                "string exceeds max length: {} > {}",
                value.len(),
                self.0
            )))
        } else {
            Ok(value.to_owned())
        }
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
        if value.len() > self.0 {
            Err(E::custom(format!(
                "string exceeds max length: {} > {}",
                value.len(),
                self.0
            )))
        } else {
            Ok(value)
        }
    }
}

struct OptionalBoundedStringVisitor(usize);

impl<'de> Visitor<'de> for OptionalBoundedStringVisitor {
    type Value = Option<String>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "an optional string of at most {} bytes", self.0)
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer
            .deserialize_string(BoundedStringVisitor(self.0))
            .map(Some)
    }
}

fn deserialize_run_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_string(BoundedStringVisitor(MAX_RUN_ID_LENGTH))
}

fn deserialize_detail<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_option(OptionalBoundedStringVisitor(MAX_HEARTBEAT_DETAIL_LENGTH))
}
