//! Reviewer lifecycle telemetry contract, strict NDJSON parsing, and bounded
//! projection summaries.
//!
//! This module defines the versioned lifecycle event schema consumed by FAC
//! review projections:
//! - `stall_detected`
//! - `run_crash`
//! - `model_fallback`
//! - `sha_drift` (with legacy alias `sha_update`)
//!
//! It also provides:
//! - append-only NDJSON writer with lock + rotation support
//! - strict parser for authoritative projection paths
//! - bounded projection summary emitter (target: 1Hz)

use std::collections::{BTreeMap, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use chrono::{DateTime, SecondsFormat, Utc};
use fs2::FileExt;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use thiserror::Error;

/// Canonical schema identifier for reviewer lifecycle telemetry.
pub const REVIEWER_TELEMETRY_SCHEMA: &str = "apm2.reviewer.lifecycle_event.v1";
/// Current lifecycle event schema version.
pub const REVIEWER_TELEMETRY_SCHEMA_VERSION: u32 = 1;
/// Default NDJSON rotation threshold (10 MiB).
pub const DEFAULT_REVIEWER_ROTATE_BYTES: u64 = 10 * 1024 * 1024;
/// Default bounded summary interval for CI logs (1Hz).
pub const DEFAULT_PROJECTION_SUMMARY_INTERVAL: Duration = Duration::from_secs(1);

static REVIEWER_APPEND_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

/// Lifecycle event kinds used for reviewer state-transition monitoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewerLifecycleEventKind {
    /// Reviewer process started.
    RunStart,
    /// Reviewer process completed with a verdict.
    RunComplete,
    /// Reviewer process crashed or exited unexpectedly.
    RunCrash,
    /// Reviewer process stalled past liveness threshold.
    StallDetected,
    /// Model fallback transition occurred.
    ModelFallback,
    /// Head SHA drift transition occurred.
    ShaDrift,
}

impl ReviewerLifecycleEventKind {
    /// Returns the canonical wire name for this event kind.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RunStart => "run_start",
            Self::RunComplete => "run_complete",
            Self::RunCrash => "run_crash",
            Self::StallDetected => "stall_detected",
            Self::ModelFallback => "model_fallback",
            Self::ShaDrift => "sha_drift",
        }
    }

    /// Parses lifecycle event names, including legacy aliases.
    pub fn from_event_name(name: &str) -> Option<Self> {
        match name {
            "run_start" => Some(Self::RunStart),
            "run_complete" => Some(Self::RunComplete),
            "run_crash" => Some(Self::RunCrash),
            "stall_detected" => Some(Self::StallDetected),
            "model_fallback" => Some(Self::ModelFallback),
            "sha_drift" | "sha_update" => Some(Self::ShaDrift),
            _ => None,
        }
    }
}

impl<'de> Deserialize<'de> for ReviewerLifecycleEventKind {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::from_event_name(&raw).ok_or_else(|| {
            serde::de::Error::custom(format!("unsupported reviewer lifecycle event: {raw}"))
        })
    }
}

/// Versioned lifecycle event envelope for reviewer transitions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewerLifecycleEvent {
    /// Stable schema ID for parser negotiation.
    pub schema: String,
    /// Schema version.
    pub schema_version: u32,
    /// RFC3339 timestamp.
    pub ts: String,
    /// Event kind.
    pub event: ReviewerLifecycleEventKind,
    /// Review stream type (`security` or `quality`).
    pub review_type: String,
    /// Pull request number.
    pub pr_number: u32,
    /// Head SHA bound to this event.
    pub head_sha: String,
    /// Monotonic sequence number for per-stream ordering.
    pub seq: u64,
    /// Stable run identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    /// Restart count when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restart_count: Option<u32>,
    /// Explicit reason code for terminal/fallback/drift/stall transitions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    /// Optional human-readable detail string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Additional bounded metadata retained for compatibility.
    #[serde(flatten, default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

impl ReviewerLifecycleEvent {
    /// Parses a JSON value into a lifecycle event.
    ///
    /// Returns `Ok(None)` when the value is not a lifecycle event.
    pub fn from_json_value(value: &Value) -> Result<Option<Self>, ReviewerTelemetryError> {
        let object = value
            .as_object()
            .ok_or_else(|| ReviewerTelemetryError::invalid_event("event is not a JSON object"))?;

        let Some(event_name) = object.get("event").and_then(Value::as_str) else {
            return Ok(None);
        };
        let Some(event_kind) = ReviewerLifecycleEventKind::from_event_name(event_name) else {
            return Ok(None);
        };

        let schema = match object.get("schema").and_then(Value::as_str) {
            Some(found) if found != REVIEWER_TELEMETRY_SCHEMA => {
                return Err(ReviewerTelemetryError::invalid_event(format!(
                    "unsupported schema: {found}"
                )));
            },
            Some(_) | None => REVIEWER_TELEMETRY_SCHEMA.to_string(),
        };

        let schema_version = match object.get("schema_version").and_then(Value::as_u64) {
            Some(found) if found != u64::from(REVIEWER_TELEMETRY_SCHEMA_VERSION) => {
                return Err(ReviewerTelemetryError::invalid_event(format!(
                    "unsupported schema_version: {found}"
                )));
            },
            Some(_) | None => REVIEWER_TELEMETRY_SCHEMA_VERSION,
        };

        let ts = object
            .get("ts")
            .and_then(Value::as_str)
            .ok_or_else(|| ReviewerTelemetryError::invalid_event("missing ts"))?
            .to_string();
        parse_event_epoch(&ts).ok_or_else(|| {
            ReviewerTelemetryError::invalid_event("invalid ts (RFC3339 required)")
        })?;

        let review_type = object
            .get("review_type")
            .and_then(Value::as_str)
            .ok_or_else(|| ReviewerTelemetryError::invalid_event("missing review_type"))?
            .trim()
            .to_string();
        if review_type.is_empty() {
            return Err(ReviewerTelemetryError::invalid_event(
                "review_type must be non-empty",
            ));
        }

        let pr_number_u64 = object
            .get("pr_number")
            .and_then(Value::as_u64)
            .ok_or_else(|| ReviewerTelemetryError::invalid_event("missing pr_number"))?;
        let pr_number = u32::try_from(pr_number_u64).map_err(|_| {
            ReviewerTelemetryError::invalid_event(format!(
                "pr_number out of range for u32: {pr_number_u64}"
            ))
        })?;

        let head_sha = object
            .get("head_sha")
            .and_then(Value::as_str)
            .ok_or_else(|| ReviewerTelemetryError::invalid_event("missing head_sha"))?
            .trim()
            .to_string();
        if head_sha.is_empty() {
            return Err(ReviewerTelemetryError::invalid_event(
                "head_sha must be non-empty",
            ));
        }

        let seq = object
            .get("seq")
            .and_then(Value::as_u64)
            .ok_or_else(|| ReviewerTelemetryError::invalid_event("missing seq"))?;
        if seq == 0 {
            return Err(ReviewerTelemetryError::invalid_event(
                "seq must be non-zero",
            ));
        }

        let reason_code = object
            .get("reason_code")
            .and_then(Value::as_str)
            .map(ToString::to_string)
            .or_else(|| {
                object
                    .get("reason")
                    .and_then(Value::as_str)
                    .map(ToString::to_string)
            })
            .or_else(|| default_reason_code(event_kind, object));

        let detail = object
            .get("detail")
            .and_then(Value::as_str)
            .map(ToString::to_string);

        let mut extra = BTreeMap::new();
        for (key, val) in object {
            if known_lifecycle_key(key) {
                continue;
            }
            extra.insert(key.clone(), val.clone());
        }

        Ok(Some(Self {
            schema,
            schema_version,
            ts,
            event: event_kind,
            review_type,
            pr_number,
            head_sha,
            seq,
            run_id: object
                .get("run_id")
                .and_then(Value::as_str)
                .map(ToString::to_string),
            restart_count: object
                .get("restart_count")
                .and_then(Value::as_u64)
                .and_then(|value| u32::try_from(value).ok()),
            reason_code,
            detail,
            extra,
        }))
    }

    /// Converts this lifecycle event back to JSON value.
    pub fn to_json_value(&self) -> Result<Value, ReviewerTelemetryError> {
        serde_json::to_value(self).map_err(|err| ReviewerTelemetryError::serialize(err.to_string()))
    }
}

/// Projection telemetry stream health for fail-closed decisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReviewerTelemetryHealth {
    /// Telemetry was parsed and yielded lifecycle events (possibly zero).
    Present {
        /// Count of lifecycle events in the filtered projection window.
        lifecycle_events: usize,
    },
    /// Telemetry stream does not exist.
    Missing,
    /// Telemetry stream exists but is malformed.
    Malformed,
}

impl ReviewerTelemetryHealth {
    /// Returns `true` when authoritative projection progression must be
    /// blocked.
    pub const fn blocks_authoritative_progression(
        &self,
        attempting_authoritative_progression: bool,
    ) -> bool {
        match self {
            Self::Present { lifecycle_events } => {
                attempting_authoritative_progression && *lifecycle_events == 0
            },
            Self::Missing | Self::Malformed => attempting_authoritative_progression,
        }
    }
}

/// Filter arguments for reading reviewer lifecycle events for projection.
#[derive(Debug, Clone)]
pub struct ReviewerProjectionFilter {
    /// Pull request number.
    pub pr_number: u32,
    /// Optional head SHA filter.
    pub head_sha: Option<String>,
    /// Optional minimum epoch-seconds bound.
    pub since_epoch: Option<u64>,
    /// Maximum events retained after filtering.
    pub max_events: usize,
}

impl ReviewerProjectionFilter {
    /// Creates a filter for a pull request.
    pub const fn new(pr_number: u32) -> Self {
        Self {
            pr_number,
            head_sha: None,
            since_epoch: None,
            max_events: 400,
        }
    }

    /// Sets the optional head SHA filter.
    #[must_use]
    pub fn with_head_sha(mut self, head_sha: Option<&str>) -> Self {
        self.head_sha = head_sha.map(ToString::to_string);
        self
    }

    /// Sets the optional minimum epoch bound.
    #[must_use]
    pub const fn with_since_epoch(mut self, since_epoch: Option<u64>) -> Self {
        self.since_epoch = since_epoch;
        self
    }

    /// Sets the max retained event count.
    #[must_use]
    pub const fn with_max_events(mut self, max_events: usize) -> Self {
        self.max_events = max_events;
        self
    }
}

/// Parsed lifecycle event paired with its canonicalized JSON object.
#[derive(Debug, Clone)]
pub struct ReviewerProjectionEvent {
    /// Parsed lifecycle envelope.
    pub lifecycle: ReviewerLifecycleEvent,
    /// Canonicalized JSON event.
    pub raw: Value,
}

/// Strict projection read result.
#[derive(Debug, Clone)]
pub struct ReviewerProjectionRead {
    /// Filtered lifecycle events.
    pub events: Vec<ReviewerProjectionEvent>,
    /// Latest sequence number in filtered events.
    pub latest_seq: u64,
    /// Stream health classification.
    pub health: ReviewerTelemetryHealth,
}

/// Reviewer telemetry contract errors.
#[derive(Debug, Error)]
pub enum ReviewerTelemetryError {
    /// Telemetry stream is missing.
    #[error("reviewer telemetry missing: {path}")]
    Missing {
        /// Missing stream path.
        path: PathBuf,
    },
    /// Telemetry line is malformed.
    #[error("reviewer telemetry malformed at {path}:{line}: {detail}")]
    Malformed {
        /// Stream path.
        path: PathBuf,
        /// 1-based line number.
        line: usize,
        /// Parse detail.
        detail: String,
    },
    /// Filesystem I/O failure.
    #[error("reviewer telemetry I/O failure at {path}: {detail}")]
    Io {
        /// Path involved in the operation.
        path: PathBuf,
        /// Error detail.
        detail: String,
    },
    /// Locking failure.
    #[error("reviewer telemetry lock failure at {path}: {detail}")]
    Lock {
        /// Lock file path.
        path: PathBuf,
        /// Error detail.
        detail: String,
    },
    /// Serialization failure.
    #[error("reviewer telemetry serialization failure: {detail}")]
    Serialize {
        /// Error detail.
        detail: String,
    },
    /// Invalid lifecycle event shape.
    #[error("reviewer telemetry invalid lifecycle event: {detail}")]
    InvalidEvent {
        /// Validation detail.
        detail: String,
    },
}

impl ReviewerTelemetryError {
    fn io(path: PathBuf, detail: impl Into<String>) -> Self {
        Self::Io {
            path,
            detail: detail.into(),
        }
    }

    fn lock(path: PathBuf, detail: impl Into<String>) -> Self {
        Self::Lock {
            path,
            detail: detail.into(),
        }
    }

    fn serialize(detail: impl Into<String>) -> Self {
        Self::Serialize {
            detail: detail.into(),
        }
    }

    fn invalid_event(detail: impl Into<String>) -> Self {
        Self::InvalidEvent {
            detail: detail.into(),
        }
    }
}

/// Returns the `.1` rotated path for a telemetry stream.
pub fn reviewer_events_rotated_path(events_path: &Path) -> PathBuf {
    sibling_with_suffix(events_path, ".1")
}

/// Returns the `.lock` companion path for a telemetry stream.
pub fn reviewer_events_lock_path(events_path: &Path) -> PathBuf {
    sibling_with_suffix(events_path, ".lock")
}

/// Canonicalizes a JSON event for writer-safe NDJSON append.
///
/// Lifecycle events are normalized into the versioned schema envelope.
pub fn canonicalize_reviewer_event_value(event: &Value) -> Result<Value, ReviewerTelemetryError> {
    ReviewerLifecycleEvent::from_json_value(event)?
        .map_or_else(|| Ok(event.clone()), |parsed| parsed.to_json_value())
}

/// Append-only NDJSON writer for reviewer telemetry streams.
#[derive(Debug, Clone)]
pub struct ReviewerTelemetryWriter {
    events_path: PathBuf,
    lock_path: PathBuf,
    rotate_bytes: u64,
}

impl ReviewerTelemetryWriter {
    /// Creates a writer with default lock path and rotation threshold.
    pub fn new(events_path: PathBuf) -> Self {
        let lock_path = reviewer_events_lock_path(&events_path);
        Self {
            events_path,
            lock_path,
            rotate_bytes: DEFAULT_REVIEWER_ROTATE_BYTES,
        }
    }

    /// Overrides the lock file path.
    #[must_use]
    pub fn with_lock_path(mut self, lock_path: PathBuf) -> Self {
        self.lock_path = lock_path;
        self
    }

    /// Overrides the rotation threshold.
    #[must_use]
    pub const fn with_rotate_bytes(mut self, rotate_bytes: u64) -> Self {
        self.rotate_bytes = rotate_bytes;
        self
    }

    /// Appends a JSON event to the NDJSON stream.
    pub fn append_value(&self, event: &Value) -> Result<(), ReviewerTelemetryError> {
        let canonical = canonicalize_reviewer_event_value(event)?;
        append_value_to_stream(
            &self.events_path,
            &self.lock_path,
            self.rotate_bytes,
            &canonical,
        )
    }

    /// Appends a typed lifecycle event to the NDJSON stream.
    pub fn append_lifecycle_event(
        &self,
        event: &ReviewerLifecycleEvent,
    ) -> Result<(), ReviewerTelemetryError> {
        let value = event.to_json_value()?;
        append_value_to_stream(
            &self.events_path,
            &self.lock_path,
            self.rotate_bytes,
            &value,
        )
    }
}

/// Convenience helper to append reviewer telemetry without creating a writer.
pub fn append_reviewer_event_ndjson(
    events_path: &Path,
    event: &Value,
    rotate_bytes: u64,
) -> Result<(), ReviewerTelemetryError> {
    ReviewerTelemetryWriter::new(events_path.to_path_buf())
        .with_rotate_bytes(rotate_bytes)
        .append_value(event)
}

/// Reads filtered reviewer lifecycle events strictly from rotated + current
/// NDJSON files.
pub fn read_reviewer_projection_events(
    events_path: &Path,
    filter: &ReviewerProjectionFilter,
) -> Result<ReviewerProjectionRead, ReviewerTelemetryError> {
    let rotated = reviewer_events_rotated_path(events_path);
    let mut sources = Vec::new();
    if rotated.exists() {
        sources.push(rotated);
    }
    if events_path.exists() {
        sources.push(events_path.to_path_buf());
    }
    if sources.is_empty() {
        return Err(ReviewerTelemetryError::Missing {
            path: events_path.to_path_buf(),
        });
    }

    let max_events = filter.max_events.max(1);
    let mut queue = VecDeque::with_capacity(max_events);
    let mut latest_seq = 0_u64;

    for source in sources {
        let file = File::open(&source)
            .map_err(|err| ReviewerTelemetryError::io(source.clone(), err.to_string()))?;
        for (index, line) in BufReader::new(file).lines().enumerate() {
            let line_no = index + 1;
            let line = line.map_err(|err| ReviewerTelemetryError::Malformed {
                path: source.clone(),
                line: line_no,
                detail: err.to_string(),
            })?;
            if line.trim().is_empty() {
                continue;
            }
            let value = serde_json::from_str::<Value>(&line).map_err(|err| {
                ReviewerTelemetryError::Malformed {
                    path: source.clone(),
                    line: line_no,
                    detail: err.to_string(),
                }
            })?;

            let maybe_lifecycle =
                ReviewerLifecycleEvent::from_json_value(&value).map_err(|err| {
                    ReviewerTelemetryError::Malformed {
                        path: source.clone(),
                        line: line_no,
                        detail: err.to_string(),
                    }
                })?;
            let Some(lifecycle) = maybe_lifecycle else {
                continue;
            };

            if lifecycle.pr_number != filter.pr_number {
                continue;
            }
            if let Some(expected_head) = filter.head_sha.as_deref()
                && !lifecycle.head_sha.eq_ignore_ascii_case(expected_head)
            {
                continue;
            }
            if let Some(min_epoch) = filter.since_epoch {
                let Some(epoch) = parse_event_epoch(&lifecycle.ts) else {
                    return Err(ReviewerTelemetryError::Malformed {
                        path: source,
                        line: line_no,
                        detail: "invalid ts (RFC3339 required)".to_string(),
                    });
                };
                if epoch < min_epoch {
                    continue;
                }
            }

            latest_seq = latest_seq.max(lifecycle.seq);
            let raw =
                lifecycle
                    .to_json_value()
                    .map_err(|err| ReviewerTelemetryError::Malformed {
                        path: source.clone(),
                        line: line_no,
                        detail: err.to_string(),
                    })?;

            queue.push_back(ReviewerProjectionEvent { lifecycle, raw });
            while queue.len() > max_events {
                let _ = queue.pop_front();
            }
        }
    }

    let lifecycle_events = queue.len();
    Ok(ReviewerProjectionRead {
        events: queue.into_iter().collect(),
        latest_seq,
        health: ReviewerTelemetryHealth::Present { lifecycle_events },
    })
}

/// Projection summary payload for bounded CI log rendering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionSummary {
    /// Timestamp (RFC3339 seconds precision).
    pub ts: String,
    /// Requested projection SHA.
    pub sha: String,
    /// Current observed head SHA.
    pub current_head_sha: String,
    /// Security projection state.
    pub security: String,
    /// Quality projection state.
    pub quality: String,
    /// Condensed recent events view.
    pub recent_events: String,
}

impl ProjectionSummary {
    /// Builds a projection summary with current UTC time.
    pub fn from_projection(
        sha: impl Into<String>,
        current_head_sha: impl Into<String>,
        security: impl Into<String>,
        quality: impl Into<String>,
        recent_events: impl Into<String>,
    ) -> Self {
        Self {
            ts: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            sha: sha.into(),
            current_head_sha: current_head_sha.into(),
            security: security.into(),
            quality: quality.into(),
            recent_events: recent_events.into(),
        }
    }

    /// Renders one condensed CI-safe status line.
    pub fn render_line(&self) -> String {
        format!(
            "ts={} sha={} current_head_sha={} security={} quality={} events={}",
            self.ts,
            self.sha,
            self.current_head_sha,
            self.security,
            self.quality,
            self.recent_events
        )
    }
}

/// Bounded-rate projection summary emitter.
#[derive(Debug, Clone)]
pub struct ProjectionSummaryEmitter {
    min_interval: Duration,
    last_emit_at: Option<Instant>,
}

impl Default for ProjectionSummaryEmitter {
    fn default() -> Self {
        Self::new(DEFAULT_PROJECTION_SUMMARY_INTERVAL)
    }
}

impl ProjectionSummaryEmitter {
    /// Creates an emitter with a minimum inter-summary interval.
    pub const fn new(min_interval: Duration) -> Self {
        Self {
            min_interval,
            last_emit_at: None,
        }
    }

    /// Emits a summary line only if the interval budget allows it.
    pub fn emit_if_due(&mut self, now: Instant, summary: &ProjectionSummary) -> Option<String> {
        if self
            .last_emit_at
            .is_none_or(|last| now.duration_since(last) >= self.min_interval)
        {
            self.last_emit_at = Some(now);
            Some(summary.render_line())
        } else {
            None
        }
    }
}

fn known_lifecycle_key(key: &str) -> bool {
    matches!(
        key,
        "schema"
            | "schema_version"
            | "ts"
            | "event"
            | "review_type"
            | "pr_number"
            | "head_sha"
            | "seq"
            | "run_id"
            | "restart_count"
            | "reason_code"
            | "reason"
            | "detail"
            | "signal"
    )
}

fn default_reason_code(
    event_kind: ReviewerLifecycleEventKind,
    object: &serde_json::Map<String, Value>,
) -> Option<String> {
    match event_kind {
        ReviewerLifecycleEventKind::RunCrash => object
            .get("signal")
            .and_then(Value::as_str)
            .map(ToString::to_string)
            .or_else(|| Some("run_crash".to_string())),
        ReviewerLifecycleEventKind::StallDetected => Some("stall_detected".to_string()),
        ReviewerLifecycleEventKind::ModelFallback => Some("model_fallback".to_string()),
        ReviewerLifecycleEventKind::ShaDrift => Some("sha_drift".to_string()),
        ReviewerLifecycleEventKind::RunStart | ReviewerLifecycleEventKind::RunComplete => None,
    }
}

fn parse_event_epoch(raw: &str) -> Option<u64> {
    DateTime::parse_from_rfc3339(raw)
        .ok()
        .and_then(|value| value.timestamp().try_into().ok())
}

fn sibling_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let rendered = path.file_name().map_or_else(
        || "review_events.ndjson".to_string(),
        |value| value.to_string_lossy().to_string(),
    );
    let candidate = format!("{rendered}{suffix}");
    match path.parent() {
        Some(parent) => parent.join(&candidate),
        None => PathBuf::from(candidate),
    }
}

fn ensure_parent(path: &Path) -> Result<(), ReviewerTelemetryError> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    fs::create_dir_all(parent)
        .map_err(|err| ReviewerTelemetryError::io(parent.to_path_buf(), err.to_string()))
}

fn append_value_to_stream(
    events_path: &Path,
    lock_path: &Path,
    rotate_bytes: u64,
    value: &Value,
) -> Result<(), ReviewerTelemetryError> {
    let process_lock = REVIEWER_APPEND_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = process_lock
        .lock()
        .map_err(|_| ReviewerTelemetryError::lock(lock_path.to_path_buf(), "mutex poisoned"))?;

    ensure_parent(events_path)?;
    ensure_parent(lock_path)?;

    let lock_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(lock_path)
        .map_err(|err| ReviewerTelemetryError::io(lock_path.to_path_buf(), err.to_string()))?;
    FileExt::lock_exclusive(&lock_file)
        .map_err(|err| ReviewerTelemetryError::lock(lock_path.to_path_buf(), err.to_string()))?;

    if let Ok(meta) = fs::metadata(events_path)
        && meta.len() > rotate_bytes
    {
        let rotated = reviewer_events_rotated_path(events_path);
        let _ = fs::remove_file(&rotated);
        fs::rename(events_path, &rotated)
            .map_err(|err| ReviewerTelemetryError::io(rotated, err.to_string()))?;
    }

    let serialized = serde_json::to_string(value)
        .map_err(|err| ReviewerTelemetryError::serialize(err.to_string()))?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(events_path)
        .map_err(|err| ReviewerTelemetryError::io(events_path.to_path_buf(), err.to_string()))?;
    file.write_all(serialized.as_bytes())
        .map_err(|err| ReviewerTelemetryError::io(events_path.to_path_buf(), err.to_string()))?;
    file.write_all(b"\n")
        .map_err(|err| ReviewerTelemetryError::io(events_path.to_path_buf(), err.to_string()))?;
    file.sync_all()
        .map_err(|err| ReviewerTelemetryError::io(events_path.to_path_buf(), err.to_string()))?;

    Ok(())
}
