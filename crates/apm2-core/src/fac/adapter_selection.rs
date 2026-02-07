//! Deterministic adapter profile selection for multi-model rotation.
//!
//! This module implements weighted adapter selection with deterministic
//! randomness derived from:
//! - work ID
//! - selection attempt
//! - policy hash
//! - backoff epoch
//!
//! TCK-00400 requires deterministic weighted routing so audit and replay can
//! reproduce profile selection decisions exactly.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Process-wide monotonic reference instant for backoff timing.
///
/// All backoff comparisons use seconds elapsed from this reference point,
/// ensuring monotonic behaviour immune to wall-clock adjustments or drift.
/// `Instant` is guaranteed monotonic on all supported platforms.
static MONOTONIC_EPOCH: LazyLock<Instant> = LazyLock::new(Instant::now);

/// Returns monotonic seconds elapsed since the process-wide reference instant.
///
/// This replaces `SystemTime::now()` for all backoff timing paths. The value
/// increases monotonically and is never affected by NTP adjustments, leap
/// seconds, or manual clock changes.
#[must_use]
pub fn monotonic_secs() -> u64 {
    MONOTONIC_EPOCH.elapsed().as_secs()
}

/// Minimum number of failures before non-rate-limit failures trigger backoff.
pub const FAILURE_BACKOFF_THRESHOLD: u32 = 2;

/// Upper bound for configured profile entries.
pub const MAX_PROFILE_WEIGHTS: usize = 64;

/// Selection strategy used by [`AdapterSelectionPolicy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AdapterSelectionStrategy {
    /// Deterministic weighted random selection.
    #[default]
    WeightedRandom,

    /// Deterministic round-robin over eligible entries.
    RoundRobin,
}

/// Per-profile weight and backoff state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileWeight {
    /// CAS hash of the profile.
    pub profile_hash: [u8; 32],

    /// Stable profile ID (e.g. `claude-code-v1`).
    pub profile_id: String,

    /// Static configured weight.
    pub weight: u32,

    /// Whether this profile is enabled.
    pub enabled: bool,

    /// Lower number indicates higher fallback priority.
    pub fallback_priority: u32,

    /// Unix timestamp (seconds) for last failure that triggered backoff.
    pub last_failure_at: Option<u64>,

    /// Rolling failure counter.
    pub failure_count: u32,
}

impl ProfileWeight {
    fn is_in_backoff(&self, now_secs: u64, backoff_secs: u64) -> bool {
        if backoff_secs == 0 {
            return false;
        }
        self.last_failure_at
            .is_some_and(|failed_at| now_secs.saturating_sub(failed_at) < backoff_secs)
    }

    fn clear_expired_backoff(&mut self, now_secs: u64, backoff_secs: u64) {
        if self.is_in_backoff(now_secs, backoff_secs) {
            // Still in active backoff window — keep failure state.
            return;
        }
        // Only reset failure_count when a previous backoff has actually expired
        // (i.e., last_failure_at was set but the window has elapsed). When
        // last_failure_at is None, the counter must continue to accumulate so
        // FAILURE_BACKOFF_THRESHOLD can be reached across selection cycles.
        if self.last_failure_at.is_some() {
            // Backoff window has expired — clear state so the profile is
            // eligible again.
            self.last_failure_at = None;
            self.failure_count = 0;
        }
    }
}

/// Snapshot of a profile's effective eligibility for one selection decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectionWeightSnapshot {
    /// CAS hash of the profile.
    pub profile_hash: [u8; 32],
    /// Profile ID.
    pub profile_id: String,
    /// Configured static weight.
    pub configured_weight: u32,
    /// Effective weight after availability/backoff gating.
    pub effective_weight: u32,
    /// Whether this profile is enabled.
    pub enabled: bool,
    /// Whether runtime supports this profile's adapter path.
    pub adapter_available: bool,
    /// Whether profile is currently inside backoff window.
    pub rate_limited: bool,
    /// Fallback priority.
    pub fallback_priority: u32,
}

/// Full selection output, including deterministic metadata for ledger audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectionDecision {
    /// Selected profile CAS hash.
    pub selected_profile_hash: [u8; 32],
    /// Selected profile ID.
    pub selected_profile_id: String,
    /// Strategy used for this decision.
    pub strategy: AdapterSelectionStrategy,
    /// Whether fallback (not weighted path) was used.
    pub used_fallback: bool,
    /// Work-specific attempt counter input.
    pub selection_attempt: u32,
    /// Backoff epoch input.
    pub backoff_epoch: u64,
    /// Policy hash used in seed derivation.
    pub policy_hash: [u8; 32],
    /// BLAKE3 digest of selection inputs.
    pub selection_input_digest: [u8; 32],
    /// BLAKE3 keyed seed digest.
    pub seed: [u8; 32],
    /// Effective profile weights for this decision.
    pub selection_weights: Vec<SelectionWeightSnapshot>,
}

/// Adapter selection configuration and runtime state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdapterSelectionPolicy {
    /// Weighted profile entries.
    pub entries: Vec<ProfileWeight>,
    /// Selection strategy.
    #[serde(default)]
    pub strategy: AdapterSelectionStrategy,
    /// Backoff window in seconds.
    #[serde(default = "default_rate_limit_backoff_secs")]
    pub rate_limit_backoff_secs: u64,
}

const fn default_rate_limit_backoff_secs() -> u64 {
    300
}

impl Default for AdapterSelectionPolicy {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            strategy: AdapterSelectionStrategy::WeightedRandom,
            rate_limit_backoff_secs: default_rate_limit_backoff_secs(),
        }
    }
}

/// Errors returned by adapter selection operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AdapterSelectionError {
    /// Configuration is invalid.
    #[error("invalid adapter selection policy: {0}")]
    InvalidPolicy(String),

    /// No eligible profile exists for this selection input.
    #[error("no eligible adapter profile found")]
    NoEligibleProfile,

    /// Profile hash is unknown to the policy.
    #[error("profile hash not found in policy: {0}")]
    UnknownProfileHash(String),
}

impl AdapterSelectionPolicy {
    /// Validate policy structure and invariants.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterSelectionError::InvalidPolicy`] when:
    /// - entries is empty or exceeds [`MAX_PROFILE_WEIGHTS`]
    /// - duplicate profile hashes or IDs are present
    /// - no enabled profile exists or no enabled profile has weight > 0
    pub fn validate(&self) -> Result<(), AdapterSelectionError> {
        if self.entries.is_empty() {
            return Err(AdapterSelectionError::InvalidPolicy(
                "entries cannot be empty".to_string(),
            ));
        }
        if self.entries.len() > MAX_PROFILE_WEIGHTS {
            return Err(AdapterSelectionError::InvalidPolicy(format!(
                "entries exceeds max {MAX_PROFILE_WEIGHTS}"
            )));
        }

        let mut enabled_count: usize = 0;
        let mut enabled_positive_weight: usize = 0;
        let mut seen_hashes = BTreeSet::new();
        let mut seen_ids = BTreeSet::new();

        for entry in &self.entries {
            if entry.profile_id.trim().is_empty() {
                return Err(AdapterSelectionError::InvalidPolicy(
                    "profile_id cannot be empty".to_string(),
                ));
            }
            if !seen_hashes.insert(entry.profile_hash) {
                return Err(AdapterSelectionError::InvalidPolicy(format!(
                    "duplicate profile_hash for profile_id '{}'",
                    entry.profile_id
                )));
            }
            if !seen_ids.insert(entry.profile_id.clone()) {
                return Err(AdapterSelectionError::InvalidPolicy(format!(
                    "duplicate profile_id '{}'",
                    entry.profile_id
                )));
            }
            if entry.enabled {
                enabled_count += 1;
                if entry.weight > 0 {
                    enabled_positive_weight += 1;
                }
            }
        }

        if enabled_count == 0 {
            return Err(AdapterSelectionError::InvalidPolicy(
                "at least one profile must be enabled".to_string(),
            ));
        }
        if enabled_positive_weight == 0 {
            return Err(AdapterSelectionError::InvalidPolicy(
                "at least one enabled profile must have weight > 0".to_string(),
            ));
        }

        Ok(())
    }

    /// Compute deterministic policy hash from static policy configuration.
    ///
    /// Runtime failure state is intentionally excluded from this hash.
    #[must_use]
    pub fn policy_hash(&self) -> [u8; 32] {
        #[derive(Serialize)]
        struct PolicyHashView<'a> {
            entries: Vec<PolicyHashEntry<'a>>,
            strategy: AdapterSelectionStrategy,
            rate_limit_backoff_secs: u64,
        }

        #[derive(Serialize)]
        struct PolicyHashEntry<'a> {
            profile_hash: [u8; 32],
            profile_id: &'a str,
            weight: u32,
            enabled: bool,
            fallback_priority: u32,
        }

        let mut entries: Vec<_> = self
            .entries
            .iter()
            .map(|entry| PolicyHashEntry {
                profile_hash: entry.profile_hash,
                profile_id: entry.profile_id.as_str(),
                weight: entry.weight,
                enabled: entry.enabled,
                fallback_priority: entry.fallback_priority,
            })
            .collect();

        entries.sort_by(|a, b| {
            a.fallback_priority
                .cmp(&b.fallback_priority)
                .then_with(|| a.profile_id.cmp(b.profile_id))
                .then_with(|| a.profile_hash.cmp(&b.profile_hash))
        });

        let view = PolicyHashView {
            entries,
            strategy: self.strategy,
            rate_limit_backoff_secs: self.rate_limit_backoff_secs,
        };

        let bytes = serde_json::to_vec(&view).unwrap_or_default();
        *blake3::hash(&bytes).as_bytes()
    }

    /// Select a profile using monotonic (non-wall-clock) time for backoff.
    ///
    /// `adapter_available` is the set of profile hashes whose adapters are
    /// currently implemented and registered in runtime.
    ///
    /// # Monotonic Time
    ///
    /// Uses [`monotonic_secs`] (backed by `Instant`) instead of `SystemTime`.
    /// This ensures backoff windows are immune to NTP adjustments, leap
    /// seconds, and manual clock changes.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterSelectionError`] when policy validation fails or
    /// no eligible profile is available.
    pub fn select_profile(
        &mut self,
        work_id: &str,
        selection_attempt: u32,
        adapter_available: &BTreeSet<[u8; 32]>,
    ) -> Result<SelectionDecision, AdapterSelectionError> {
        let now_secs = monotonic_secs();
        self.select_profile_at(work_id, selection_attempt, now_secs, adapter_available)
    }

    /// Select a profile at a deterministic timestamp (seconds since epoch).
    ///
    /// # Errors
    ///
    /// Returns [`AdapterSelectionError::InvalidPolicy`] when policy validation
    /// fails, or [`AdapterSelectionError::NoEligibleProfile`] when no profile
    /// is available after filtering by adapter availability and backoff state.
    ///
    /// # Panics
    ///
    /// Cannot panic in practice: the `expect` on seed slice conversion is
    /// guaranteed because `seed` is `[u8; 32]` and we take `[0..8]`.
    #[allow(clippy::too_many_lines)]
    pub fn select_profile_at(
        &mut self,
        work_id: &str,
        selection_attempt: u32,
        now_secs: u64,
        adapter_available: &BTreeSet<[u8; 32]>,
    ) -> Result<SelectionDecision, AdapterSelectionError> {
        self.validate()?;

        for entry in &mut self.entries {
            entry.clear_expired_backoff(now_secs, self.rate_limit_backoff_secs);
        }

        let policy_hash = self.policy_hash();
        let backoff_epoch = self.backoff_epoch(now_secs);
        let (selection_input_digest, seed) =
            compute_input_digest_and_seed(work_id, selection_attempt, policy_hash, backoff_epoch);

        let ctx = SelectionContext {
            selection_attempt,
            backoff_epoch,
            policy_hash,
            selection_input_digest,
            seed,
        };

        let (snapshots, eligible, fallback_candidates) =
            self.compute_eligibility(now_secs, adapter_available);

        let total_weight: u64 = eligible.iter().map(|(_, weight)| u64::from(*weight)).sum();

        if total_weight > 0 {
            return self.select_by_strategy(&eligible, total_weight, snapshots, &ctx);
        }

        self.select_fallback(fallback_candidates, snapshots, &ctx)
    }

    /// Compute eligibility snapshots, eligible entries, and fallback
    /// candidates.
    ///
    /// Fallback candidates are profiles that are enabled, adapter-available,
    /// and NOT in backoff. When all profiles are rate-limited, fallback
    /// candidates will be empty and selection returns `NoEligibleProfile`,
    /// maintaining anti-abuse throttling invariants.
    fn compute_eligibility(
        &self,
        now_secs: u64,
        adapter_available: &BTreeSet<[u8; 32]>,
    ) -> (Vec<SelectionWeightSnapshot>, Vec<(usize, u32)>, Vec<usize>) {
        let mut snapshots: Vec<SelectionWeightSnapshot> = Vec::with_capacity(self.entries.len());
        let mut eligible: Vec<(usize, u32)> = Vec::new();
        let mut fallback_candidates: Vec<usize> = Vec::new();

        for (index, entry) in self.entries.iter().enumerate() {
            let is_available = adapter_available.contains(&entry.profile_hash);
            let is_rate_limited = entry.is_in_backoff(now_secs, self.rate_limit_backoff_secs);
            let effective_weight = if entry.enabled && is_available && !is_rate_limited {
                entry.weight
            } else {
                0
            };

            if entry.enabled && is_available && !is_rate_limited && effective_weight > 0 {
                eligible.push((index, effective_weight));
            }

            // Fallback candidates include enabled+available profiles that are NOT
            // in backoff. This ensures rate-limited profiles are not selected via
            // fallback, maintaining anti-abuse throttling invariants.
            if entry.enabled && is_available && !is_rate_limited {
                fallback_candidates.push(index);
            }

            snapshots.push(SelectionWeightSnapshot {
                profile_hash: entry.profile_hash,
                profile_id: entry.profile_id.clone(),
                configured_weight: entry.weight,
                effective_weight,
                enabled: entry.enabled,
                adapter_available: is_available,
                rate_limited: is_rate_limited,
                fallback_priority: entry.fallback_priority,
            });
        }

        eligible.sort_by(|(left_idx, _), (right_idx, _)| {
            self.entry_sort_key(*left_idx)
                .cmp(&self.entry_sort_key(*right_idx))
        });

        (snapshots, eligible, fallback_candidates)
    }

    /// Returns a comparable sort key for entry ordering.
    fn entry_sort_key(&self, idx: usize) -> (u32, &str, [u8; 32]) {
        let e = &self.entries[idx];
        (e.fallback_priority, e.profile_id.as_str(), e.profile_hash)
    }

    /// Select a profile using the configured strategy (weighted random or
    /// round-robin).
    fn select_by_strategy(
        &self,
        eligible: &[(usize, u32)],
        total_weight: u64,
        snapshots: Vec<SelectionWeightSnapshot>,
        ctx: &SelectionContext,
    ) -> Result<SelectionDecision, AdapterSelectionError> {
        let selected_index = match self.strategy {
            AdapterSelectionStrategy::WeightedRandom => {
                let mut prefix: u64 = 0;
                let target = u64::from_le_bytes(ctx.seed[0..8].try_into().expect("slice length"))
                    % total_weight;
                eligible
                    .iter()
                    .find_map(|(entry_index, weight)| {
                        prefix = prefix.saturating_add(u64::from(*weight));
                        (target < prefix).then_some(*entry_index)
                    })
                    .ok_or(AdapterSelectionError::NoEligibleProfile)?
            },
            AdapterSelectionStrategy::RoundRobin => {
                let slot = (ctx.selection_attempt as usize) % eligible.len();
                eligible[slot].0
            },
        };

        let selected_entry = &self.entries[selected_index];
        Ok(ctx.to_decision(selected_entry, self.strategy, false, snapshots))
    }

    /// Select a profile via fallback priority when no weighted selection is
    /// possible.
    fn select_fallback(
        &self,
        mut fallback_candidates: Vec<usize>,
        snapshots: Vec<SelectionWeightSnapshot>,
        ctx: &SelectionContext,
    ) -> Result<SelectionDecision, AdapterSelectionError> {
        fallback_candidates.sort_by(|left_idx, right_idx| {
            self.entry_sort_key(*left_idx)
                .cmp(&self.entry_sort_key(*right_idx))
        });

        let selected_index = fallback_candidates
            .into_iter()
            .next()
            .ok_or(AdapterSelectionError::NoEligibleProfile)?;
        let selected_entry = &self.entries[selected_index];

        Ok(ctx.to_decision(selected_entry, self.strategy, true, snapshots))
    }

    /// Record spawn failure and update backoff state for a profile.
    ///
    /// `rate_limited` should be true for explicit rate-limit failures
    /// (e.g. HTTP 429). Non-rate-limit failures still increment the failure
    /// counter and enter backoff once the threshold is reached.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterSelectionError::UnknownProfileHash`] when the
    /// given profile hash is not found in the policy entries.
    pub fn record_failure(
        &mut self,
        profile_hash: &[u8; 32],
        now_secs: u64,
        rate_limited: bool,
    ) -> Result<(), AdapterSelectionError> {
        let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| &entry.profile_hash == profile_hash)
        else {
            return Err(AdapterSelectionError::UnknownProfileHash(hex::encode(
                profile_hash,
            )));
        };

        entry.failure_count = entry.failure_count.saturating_add(1);
        if rate_limited || entry.failure_count >= FAILURE_BACKOFF_THRESHOLD {
            entry.last_failure_at = Some(now_secs);
        }
        Ok(())
    }

    /// Record successful spawn and clear failure state for this profile.
    ///
    /// # Errors
    ///
    /// Returns [`AdapterSelectionError::UnknownProfileHash`] when the
    /// given profile hash is not found in the policy entries.
    pub fn record_success(&mut self, profile_hash: &[u8; 32]) -> Result<(), AdapterSelectionError> {
        let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| &entry.profile_hash == profile_hash)
        else {
            return Err(AdapterSelectionError::UnknownProfileHash(hex::encode(
                profile_hash,
            )));
        };

        entry.failure_count = 0;
        entry.last_failure_at = None;
        Ok(())
    }

    /// Return profile hash -> profile ID map for lookup at decision logging
    /// sites.
    #[must_use]
    pub fn profile_id_map(&self) -> BTreeMap<[u8; 32], String> {
        self.entries
            .iter()
            .map(|entry| (entry.profile_hash, entry.profile_id.clone()))
            .collect()
    }

    fn backoff_epoch(&self, now_secs: u64) -> u64 {
        if self.rate_limit_backoff_secs == 0 {
            return 0;
        }

        self.entries
            .iter()
            .filter_map(|entry| {
                entry.last_failure_at.and_then(|failed_at| {
                    if now_secs.saturating_sub(failed_at) < self.rate_limit_backoff_secs {
                        Some(failed_at / self.rate_limit_backoff_secs)
                    } else {
                        None
                    }
                })
            })
            .max()
            .unwrap_or(0)
    }
}

/// Intermediate state bundled for passing between selection helper methods
/// without exceeding the argument count lint.
struct SelectionContext {
    selection_attempt: u32,
    backoff_epoch: u64,
    policy_hash: [u8; 32],
    selection_input_digest: [u8; 32],
    seed: [u8; 32],
}

impl SelectionContext {
    /// Build a [`SelectionDecision`] from the context and a selected entry.
    fn to_decision(
        &self,
        entry: &ProfileWeight,
        strategy: AdapterSelectionStrategy,
        used_fallback: bool,
        selection_weights: Vec<SelectionWeightSnapshot>,
    ) -> SelectionDecision {
        SelectionDecision {
            selected_profile_hash: entry.profile_hash,
            selected_profile_id: entry.profile_id.clone(),
            strategy,
            used_fallback,
            selection_attempt: self.selection_attempt,
            backoff_epoch: self.backoff_epoch,
            policy_hash: self.policy_hash,
            selection_input_digest: self.selection_input_digest,
            seed: self.seed,
            selection_weights,
        }
    }
}

/// Compute deterministic input digest and BLAKE3-keyed seed from selection
/// inputs.
fn compute_input_digest_and_seed(
    work_id: &str,
    selection_attempt: u32,
    policy_hash: [u8; 32],
    backoff_epoch: u64,
) -> ([u8; 32], [u8; 32]) {
    let mut input = Vec::with_capacity(work_id.len() + 4 + 32 + 8);
    input.extend_from_slice(work_id.as_bytes());
    input.extend_from_slice(&selection_attempt.to_le_bytes());
    input.extend_from_slice(&policy_hash);
    input.extend_from_slice(&backoff_epoch.to_le_bytes());

    let input_digest = *blake3::hash(&input).as_bytes();
    // Keyed hash is required for deterministic CSPRNG-quality seed derivation.
    let seed = *blake3::keyed_hash(&policy_hash, &input).as_bytes();
    (input_digest, seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn sample_policy() -> AdapterSelectionPolicy {
        AdapterSelectionPolicy {
            entries: vec![
                ProfileWeight {
                    profile_hash: hash(0x11),
                    profile_id: "primary".to_string(),
                    weight: 80,
                    enabled: true,
                    fallback_priority: 0,
                    last_failure_at: None,
                    failure_count: 0,
                },
                ProfileWeight {
                    profile_hash: hash(0x22),
                    profile_id: "secondary".to_string(),
                    weight: 20,
                    enabled: true,
                    fallback_priority: 1,
                    last_failure_at: None,
                    failure_count: 0,
                },
            ],
            strategy: AdapterSelectionStrategy::WeightedRandom,
            rate_limit_backoff_secs: 300,
        }
    }

    #[test]
    fn selection_is_deterministic_for_same_inputs() {
        let mut policy = sample_policy();
        let available = BTreeSet::from([hash(0x11), hash(0x22)]);

        let first = policy
            .select_profile_at("W-DET-001", 7, 10_000, &available)
            .expect("selection should succeed");
        let second = policy
            .select_profile_at("W-DET-001", 7, 10_000, &available)
            .expect("selection should succeed");

        assert_eq!(first.selected_profile_hash, second.selected_profile_hash);
        assert_eq!(first.seed, second.seed);
        assert_eq!(first.selection_input_digest, second.selection_input_digest);
    }

    #[test]
    fn weighted_distribution_matches_expected_ratio() {
        let mut policy = sample_policy();
        let available = BTreeSet::from([hash(0x11), hash(0x22)]);

        let mut primary: u32 = 0;
        let mut secondary: u32 = 0;

        for attempt in 0..1000u32 {
            let decision = policy
                .select_profile_at("W-DIST-001", attempt, 20_000, &available)
                .expect("selection should succeed");
            if decision.selected_profile_hash == hash(0x11) {
                primary = primary.saturating_add(1);
            } else if decision.selected_profile_hash == hash(0x22) {
                secondary = secondary.saturating_add(1);
            }
        }

        assert!(primary > 700, "primary count too low: {primary}");
        assert!(primary < 900, "primary count too high: {primary}");
        assert!(secondary > 100, "secondary count too low: {secondary}");
        assert!(secondary < 300, "secondary count too high: {secondary}");
    }

    #[test]
    fn rate_limit_backoff_triggers_fallback() {
        let mut policy = sample_policy();
        let available = BTreeSet::from([hash(0x11), hash(0x22)]);

        policy
            .record_failure(&hash(0x11), 30_000, true)
            .expect("profile should exist");

        let decision = policy
            .select_profile_at("W-BACKOFF-001", 1, 30_001, &available)
            .expect("selection should succeed");

        assert_eq!(decision.selected_profile_hash, hash(0x22));
        assert_eq!(decision.selected_profile_id, "secondary");
        assert!(!decision.used_fallback, "secondary has positive weight");
    }

    #[test]
    fn unavailable_profiles_are_filtered_out() {
        let mut policy = sample_policy();
        let available = BTreeSet::from([hash(0x11)]);

        let decision = policy
            .select_profile_at("W-AVAIL-001", 3, 40_000, &available)
            .expect("selection should succeed");

        assert_eq!(decision.selected_profile_hash, hash(0x11));
    }

    #[test]
    fn backoff_expires_and_recovers_weight() {
        let mut policy = sample_policy();
        let available = BTreeSet::from([hash(0x11), hash(0x22)]);

        policy
            .record_failure(&hash(0x11), 50_000, true)
            .expect("profile should exist");

        // During backoff, secondary should be selected.
        let during_backoff = policy
            .select_profile_at("W-RECOVER-001", 5, 50_100, &available)
            .expect("selection should succeed");
        assert_eq!(during_backoff.selected_profile_hash, hash(0x22));

        // After backoff window, primary eligibility returns.
        let recovered = policy
            .select_profile_at("W-RECOVER-001", 5, 50_500, &available)
            .expect("selection should succeed");
        assert_eq!(recovered.selected_profile_hash, hash(0x11));
    }

    #[test]
    fn invalid_policy_requires_enabled_profile() {
        let policy = AdapterSelectionPolicy {
            entries: vec![ProfileWeight {
                profile_hash: hash(0x11),
                profile_id: "disabled".to_string(),
                weight: 100,
                enabled: false,
                fallback_priority: 0,
                last_failure_at: None,
                failure_count: 0,
            }],
            strategy: AdapterSelectionStrategy::WeightedRandom,
            rate_limit_backoff_secs: 300,
        };

        let err = policy.validate().expect_err("validation should fail");
        assert!(
            err.to_string()
                .contains("at least one profile must be enabled")
        );
    }

    #[test]
    fn all_in_backoff_returns_no_eligible_profile() {
        let mut policy = sample_policy();
        let available = BTreeSet::from([hash(0x11), hash(0x22)]);

        // Put ALL profiles into backoff.
        policy
            .record_failure(&hash(0x11), 60_000, true)
            .expect("profile should exist");
        policy
            .record_failure(&hash(0x22), 60_000, true)
            .expect("profile should exist");

        // Selection must fail with NoEligibleProfile when all are in backoff.
        let err = policy
            .select_profile_at("W-ALL-BACKOFF-001", 0, 60_001, &available)
            .expect_err("should fail when all profiles are in backoff");

        assert!(
            matches!(err, AdapterSelectionError::NoEligibleProfile),
            "expected NoEligibleProfile, got: {err:?}"
        );
    }

    #[test]
    fn failure_count_accumulates_across_selections_for_non_rate_limit_failures() {
        let mut policy = sample_policy();
        let available = BTreeSet::from([hash(0x11), hash(0x22)]);

        // Record a non-rate-limit failure (failure_count = 1, below threshold).
        policy
            .record_failure(&hash(0x11), 70_000, false)
            .expect("profile should exist");

        // Selection should succeed and primary should still be eligible
        // (failure_count=1 < FAILURE_BACKOFF_THRESHOLD=2, no backoff set).
        let decision = policy
            .select_profile_at("W-ACCUM-001", 0, 70_001, &available)
            .expect("selection should succeed");

        // Verify primary is still eligible (failure_count was NOT reset).
        let primary_snap = decision
            .selection_weights
            .iter()
            .find(|s| s.profile_id == "primary")
            .expect("primary snapshot must exist");
        assert!(
            !primary_snap.rate_limited,
            "primary should not be rate-limited after 1 failure"
        );

        // Record a second non-rate-limit failure (failure_count = 2, meets threshold).
        policy
            .record_failure(&hash(0x11), 70_002, false)
            .expect("profile should exist");

        // Now primary should be in backoff because threshold was reached.
        let decision2 = policy
            .select_profile_at("W-ACCUM-002", 0, 70_003, &available)
            .expect("selection should succeed");
        let primary_snap2 = decision2
            .selection_weights
            .iter()
            .find(|s| s.profile_id == "primary")
            .expect("primary snapshot must exist");
        assert!(
            primary_snap2.rate_limited,
            "primary must be in backoff after reaching failure threshold"
        );
        assert_eq!(
            primary_snap2.effective_weight, 0,
            "primary must have zero effective weight during backoff"
        );
    }

    #[test]
    fn failure_count_resets_only_after_backoff_expires() {
        let mut policy = sample_policy();
        let available = BTreeSet::from([hash(0x11), hash(0x22)]);

        // Trigger backoff for primary via threshold.
        policy
            .record_failure(&hash(0x11), 80_000, false)
            .expect("profile should exist");
        policy
            .record_failure(&hash(0x11), 80_001, false)
            .expect("profile should exist");

        // During backoff window, primary is rate-limited.
        let decision = policy
            .select_profile_at("W-EXPIRE-001", 0, 80_100, &available)
            .expect("selection should succeed");
        let snap = decision
            .selection_weights
            .iter()
            .find(|s| s.profile_id == "primary")
            .expect("primary snapshot must exist");
        assert!(snap.rate_limited, "primary must be in backoff");

        // After backoff expires (300s window), failure state resets and
        // primary regains eligibility.
        let recovered = policy
            .select_profile_at("W-EXPIRE-001", 0, 80_500, &available)
            .expect("selection should succeed");
        let snap_recovered = recovered
            .selection_weights
            .iter()
            .find(|s| s.profile_id == "primary")
            .expect("primary snapshot must exist");
        assert!(
            !snap_recovered.rate_limited,
            "primary must recover after backoff expires"
        );
        assert!(
            snap_recovered.effective_weight > 0,
            "primary must regain positive weight after backoff expires"
        );
    }
}
