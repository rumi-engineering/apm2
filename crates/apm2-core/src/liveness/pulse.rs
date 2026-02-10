//! Liveness pulse receipts for launch execution monitoring (RFC-0020).
//!
//! Emits deterministic pulse receipts consumable by gate/orchestrator logic.
//! Ambiguous liveness state denies authoritative progression (fail-closed).

use serde::{Deserialize, Deserializer, Serialize, de};

/// Maximum length for liveness pulse detail strings.
pub const MAX_PULSE_DETAIL_LENGTH: usize = 512;

/// Maximum length for a liveness pulse run identifier.
pub const MAX_RUN_ID_LENGTH: usize = 256;

/// Health verdict for a liveness pulse.
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

/// A deterministic liveness pulse receipt for an active launch execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LivenessPulseReceiptV1 {
    /// Stable run identity (from dispatch idempotency).
    #[serde(deserialize_with = "deserialize_run_id")]
    pub run_id: String,
    /// Episode identity hash.
    pub episode_id: [u8; 32],
    /// HTF tick at which this pulse was emitted.
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

impl LivenessPulseReceiptV1 {
    /// Returns whether all bounded string constraints are satisfied.
    #[must_use]
    pub fn has_valid_bounds(&self) -> bool {
        self.run_id.len() <= MAX_RUN_ID_LENGTH
            && self
                .detail
                .as_ref()
                .is_none_or(|detail| detail.len() <= MAX_PULSE_DETAIL_LENGTH)
    }
}

fn deserialize_run_id<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let run_id = String::deserialize(deserializer)?;
    if run_id.len() > MAX_RUN_ID_LENGTH {
        return Err(de::Error::custom(format!(
            "run_id exceeds maximum length ({} > {MAX_RUN_ID_LENGTH})",
            run_id.len()
        )));
    }
    Ok(run_id)
}

fn deserialize_detail<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let detail = Option::<String>::deserialize(deserializer)?;
    if let Some(ref value) = detail
        && value.len() > MAX_PULSE_DETAIL_LENGTH
    {
        return Err(de::Error::custom(format!(
            "detail exceeds maximum length ({} > {MAX_PULSE_DETAIL_LENGTH})",
            value.len()
        )));
    }
    Ok(detail)
}
