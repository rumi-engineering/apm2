//! Lease state types.

use serde::{Deserialize, Serialize};

use super::error::LeaseError;
use crate::htf::HtfTick;

/// The lifecycle state of a lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum LeaseState {
    /// Lease is active and valid.
    Active,
    /// Lease has been released by the holder.
    Released,
    /// Lease has expired due to timeout.
    Expired,
}

impl std::fmt::Display for LeaseState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl LeaseState {
    /// Parses a lease state from a string.
    ///
    /// # Errors
    ///
    /// Returns `LeaseError::InvalidLeaseState` if the string is not a
    /// recognized state.
    pub fn parse(s: &str) -> Result<Self, LeaseError> {
        match s.to_uppercase().as_str() {
            "ACTIVE" => Ok(Self::Active),
            "RELEASED" => Ok(Self::Released),
            "EXPIRED" => Ok(Self::Expired),
            _ => Err(LeaseError::InvalidLeaseState {
                value: s.to_string(),
            }),
        }
    }

    /// Returns the string representation of this state.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "ACTIVE",
            Self::Released => "RELEASED",
            Self::Expired => "EXPIRED",
        }
    }

    /// Returns true if this is a terminal state.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Released | Self::Expired)
    }

    /// Returns true if this is an active (non-terminal) state.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }
}

/// The reason a lease was released.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ReleaseReason {
    /// Work was completed successfully.
    Completed,
    /// Work was aborted.
    Aborted,
    /// Lease holder voluntarily released the lease.
    Voluntary,
}

impl std::fmt::Display for ReleaseReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl ReleaseReason {
    /// Parses a release reason from a string.
    ///
    /// # Errors
    ///
    /// Returns `LeaseError::InvalidReleaseReason` if the string is not
    /// recognized.
    pub fn parse(s: &str) -> Result<Self, LeaseError> {
        match s.to_uppercase().as_str() {
            "COMPLETED" => Ok(Self::Completed),
            "ABORTED" => Ok(Self::Aborted),
            "VOLUNTARY" => Ok(Self::Voluntary),
            _ => Err(LeaseError::InvalidReleaseReason {
                value: s.to_string(),
            }),
        }
    }

    /// Returns the string representation of this reason.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Completed => "COMPLETED",
            Self::Aborted => "ABORTED",
            Self::Voluntary => "VOLUNTARY",
        }
    }
}

/// A lease granting exclusive access to a work item.
///
/// # Time Model (RFC-0016 HTF)
///
/// Leases use tick-based expiry for immunity to wall-clock manipulation:
///
/// - `issued_at_tick` / `expires_at_tick`: Authoritative for expiry checks
/// - `issued_at` / `expires_at`: Retained for backwards compatibility and audit
///
/// The tick-based fields use [`HtfTick`] which is node-local and monotonic.
/// Expiry decisions MUST use tick comparison, not wall time comparison.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub struct Lease {
    /// Unique identifier for this lease.
    pub lease_id: String,

    /// The work item this lease grants access to.
    pub work_id: String,

    /// The actor holding this lease.
    pub actor_id: String,

    /// Current lifecycle state.
    pub state: LeaseState,

    /// Timestamp when the lease was issued (Unix nanos).
    /// Retained for backwards compatibility; not authoritative for expiry.
    pub issued_at: u64,

    /// Timestamp when the lease expires (Unix nanos).
    /// Retained for backwards compatibility; not authoritative for expiry.
    pub expires_at: u64,

    /// Monotonic tick when the lease was issued (RFC-0016 HTF).
    /// Authoritative for timing decisions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at_tick: Option<HtfTick>,

    /// Monotonic tick when the lease expires (RFC-0016 HTF).
    /// Authoritative for expiry checks when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_tick: Option<HtfTick>,

    /// Registrar signature over the lease issuance.
    pub registrar_signature: Vec<u8>,

    /// Number of times this lease has been renewed.
    pub renewal_count: u32,

    /// Timestamp of the last renewal (Unix nanos), if any.
    pub last_renewed_at: Option<u64>,

    /// Release reason, if the lease was released.
    pub release_reason: Option<ReleaseReason>,

    /// Timestamp when the lease was terminated (released or expired).
    pub terminated_at: Option<u64>,
}

impl Lease {
    /// Creates a new lease in the Active state.
    ///
    /// This constructor creates a lease without tick-based timing. Use
    /// [`Lease::new_with_ticks`] for full RFC-0016 HTF compliance.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Can't be const: String/Vec aren't const-constructible
    pub fn new(
        lease_id: String,
        work_id: String,
        actor_id: String,
        issued_at: u64,
        expires_at: u64,
        registrar_signature: Vec<u8>,
    ) -> Self {
        Self {
            lease_id,
            work_id,
            actor_id,
            state: LeaseState::Active,
            issued_at,
            expires_at,
            issued_at_tick: None,
            expires_at_tick: None,
            registrar_signature,
            renewal_count: 0,
            last_renewed_at: None,
            release_reason: None,
            terminated_at: None,
        }
    }

    /// Creates a new lease with tick-based timing (RFC-0016 HTF compliant).
    ///
    /// This is the preferred constructor for new code. The tick-based fields
    /// are authoritative for expiry decisions, immune to wall-clock changes.
    ///
    /// # Arguments
    ///
    /// * `lease_id` - Unique identifier for this lease
    /// * `work_id` - The work item this lease grants access to
    /// * `actor_id` - The actor holding this lease
    /// * `issued_at` - Wall time when issued (for audit/display only)
    /// * `expires_at` - Wall time when expires (for audit/display only)
    /// * `issued_at_tick` - Monotonic tick when issued (authoritative)
    /// * `expires_at_tick` - Monotonic tick when expires (authoritative)
    /// * `registrar_signature` - Registrar signature over the issuance
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::missing_const_for_fn)] // Can't be const: String/Vec aren't const-constructible
    pub fn new_with_ticks(
        lease_id: String,
        work_id: String,
        actor_id: String,
        issued_at: u64,
        expires_at: u64,
        issued_at_tick: HtfTick,
        expires_at_tick: HtfTick,
        registrar_signature: Vec<u8>,
    ) -> Self {
        Self {
            lease_id,
            work_id,
            actor_id,
            state: LeaseState::Active,
            issued_at,
            expires_at,
            issued_at_tick: Some(issued_at_tick),
            expires_at_tick: Some(expires_at_tick),
            registrar_signature,
            renewal_count: 0,
            last_renewed_at: None,
            release_reason: None,
            terminated_at: None,
        }
    }

    /// Returns true if this lease is active.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        self.state.is_active()
    }

    /// Returns true if this lease is in a terminal state.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }

    /// Checks if the lease has expired based on the given current tick.
    ///
    /// This is the RFC-0016 HTF compliant expiry check using monotonic ticks.
    /// Returns true if the current tick is past the lease's expiration tick
    /// AND the lease is still in the Active state.
    ///
    /// # SEC-HTF-003: Tick Rate Validation
    ///
    /// Ticks are node-local and their rates can vary. Comparing raw values
    /// without rate-equality enforcement is dangerous. This method enforces
    /// that `current_tick.tick_rate_hz() == expires_at_tick.tick_rate_hz()`.
    /// If rates differ, returns `true` (fail-closed) to prevent incorrect
    /// expiry decisions.
    ///
    /// # SEC-CTRL-FAC-0015: Legacy Fallback
    ///
    /// For leases WITHOUT tick data (legacy leases), this method returns
    /// `false` to indicate "not expired via tick logic" - the caller should
    /// use the wall-clock fallback via [`Lease::is_expired_at`] for such
    /// leases. Use [`Lease::is_expired_at_tick_or_wall`] for automatic
    /// fallback handling.
    ///
    /// Only when tick data IS present but invalid (mismatched rates), we
    /// fail-closed and return `true`.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // let-else not stable in const fn
    pub fn is_expired_at_tick(&self, current_tick: &HtfTick) -> bool {
        if !self.state.is_active() {
            return false;
        }

        // SEC-CTRL-FAC-0015: For legacy leases without tick data, return false.
        // Caller should use is_expired_at_tick_or_wall() for automatic fallback.
        let Some(expires_at_tick) = &self.expires_at_tick else {
            return false;
        };

        // SEC-HTF-003: Enforce tick rate equality. If rates differ, fail-closed.
        // Ticks are node-local and comparing values across different rates is invalid.
        if current_tick.tick_rate_hz() != expires_at_tick.tick_rate_hz() {
            return true; // Fail-closed: treat as expired
        }

        // Compare tick values (same rate, safe to compare)
        current_tick.value() >= expires_at_tick.value()
    }

    /// Checks if the lease has expired, using tick-based comparison with
    /// wall-clock fallback for legacy leases.
    ///
    /// # SEC-CTRL-FAC-0015: Migration Path for Legacy Leases
    ///
    /// This method provides a migration path for pre-existing leases that
    /// lack tick data:
    ///
    /// - For leases WITH tick data: Uses tick-based comparison (RFC-0016 HTF)
    /// - For leases WITHOUT tick data: Falls back to wall-clock comparison
    ///
    /// This prevents all legacy leases from expiring simultaneously upon
    /// deployment while maintaining security for new tick-based leases.
    ///
    /// # SEC-HTF-003: Tick Rate Validation
    ///
    /// When tick data is present, tick rates must match. Mismatched rates
    /// result in fail-closed behavior (returns `true`).
    #[must_use]
    #[allow(deprecated)] // We intentionally use is_expired_at for legacy fallback
    #[allow(clippy::missing_const_for_fn)] // Uses Option::is_some pattern
    pub fn is_expired_at_tick_or_wall(&self, current_tick: &HtfTick, current_wall_ns: u64) -> bool {
        if !self.state.is_active() {
            return false;
        }

        // Check if tick data is available
        if let Some(expires_at_tick) = &self.expires_at_tick {
            // SEC-HTF-003: Enforce tick rate equality
            if current_tick.tick_rate_hz() != expires_at_tick.tick_rate_hz() {
                return true; // Fail-closed: treat as expired
            }
            // Tick data present and valid: use tick comparison
            current_tick.value() >= expires_at_tick.value()
        } else {
            // SEC-CTRL-FAC-0015: Legacy lease without tick data.
            // Fall back to wall-clock comparison for migration compatibility.
            current_wall_ns >= self.expires_at
        }
    }

    /// Returns true if this is a legacy lease without tick-based timing.
    ///
    /// Legacy leases should use wall-clock fallback for expiry checks.
    #[must_use]
    pub const fn is_legacy_lease(&self) -> bool {
        self.expires_at_tick.is_none()
    }

    /// Returns the remaining ticks until expiration, or 0 if expired.
    ///
    /// This is the RFC-0016 HTF compliant method using monotonic ticks.
    /// Only meaningful for active leases with tick-based timing.
    ///
    /// # SEC-HTF-003: Tick Rate Validation
    ///
    /// Returns 0 if tick rates differ, as comparing ticks across different
    /// rates is invalid.
    ///
    /// # SEC-CTRL-FAC-0015: Legacy Fallback
    ///
    /// Returns 0 if tick-based timing is not available. For legacy leases,
    /// use wall-clock remaining time calculation instead.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // let-else not stable in const fn
    pub fn ticks_remaining(&self, current_tick: &HtfTick) -> u64 {
        // SEC-CTRL-FAC-0015: Return 0 if tick data is missing (legacy lease)
        let Some(expires_at_tick) = &self.expires_at_tick else {
            return 0;
        };

        // SEC-HTF-003: Return 0 if tick rates differ (fail-closed)
        if current_tick.tick_rate_hz() != expires_at_tick.tick_rate_hz() {
            return 0;
        }

        expires_at_tick.value().saturating_sub(current_tick.value())
    }

    /// Checks if the lease has expired based on the given current time (wall
    /// clock).
    ///
    /// **DEPRECATED**: This method uses wall time which can be manipulated.
    /// Use [`Lease::is_expired_at_tick`] for RFC-0016 HTF compliant expiry
    /// checks.
    ///
    /// Returns true if the current time is past the lease's expiration time
    /// AND the lease is still in the Active state.
    #[must_use]
    #[deprecated(
        since = "0.4.0",
        note = "use is_expired_at_tick for tick-based expiry (RFC-0016 HTF)"
    )]
    pub const fn is_expired_at(&self, current_time: u64) -> bool {
        self.state.is_active() && current_time >= self.expires_at
    }

    /// Returns the remaining time until expiration, or 0 if expired (wall
    /// clock).
    ///
    /// **DEPRECATED**: This method uses wall time which can be manipulated.
    /// Use [`Lease::ticks_remaining`] for RFC-0016 HTF compliant timing.
    ///
    /// Only meaningful for active leases.
    #[must_use]
    #[deprecated(
        since = "0.4.0",
        note = "use ticks_remaining for tick-based timing (RFC-0016 HTF)"
    )]
    pub const fn time_remaining(&self, current_time: u64) -> u64 {
        self.expires_at.saturating_sub(current_time)
    }

    /// Returns a summary of this lease.
    #[must_use]
    pub fn summary(&self) -> LeaseSummary {
        LeaseSummary {
            lease_id: self.lease_id.clone(),
            work_id: self.work_id.clone(),
            actor_id: self.actor_id.clone(),
            state: self.state,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            renewal_count: self.renewal_count,
        }
    }
}

/// A summary view of a lease.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseSummary {
    /// Lease ID.
    pub lease_id: String,

    /// Work ID the lease grants access to.
    pub work_id: String,

    /// Actor holding the lease.
    pub actor_id: String,

    /// Current state.
    pub state: LeaseState,

    /// When the lease was issued.
    pub issued_at: u64,

    /// When the lease expires.
    pub expires_at: u64,

    /// Number of renewals.
    pub renewal_count: u32,
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn test_lease_state_parse() {
        assert_eq!(LeaseState::parse("ACTIVE").unwrap(), LeaseState::Active);
        assert_eq!(LeaseState::parse("active").unwrap(), LeaseState::Active);
        assert_eq!(LeaseState::parse("RELEASED").unwrap(), LeaseState::Released);
        assert_eq!(LeaseState::parse("EXPIRED").unwrap(), LeaseState::Expired);
    }

    #[test]
    fn test_lease_state_parse_unknown_fails() {
        let result = LeaseState::parse("UNKNOWN");
        assert!(matches!(result, Err(LeaseError::InvalidLeaseState { .. })));

        let result = LeaseState::parse("");
        assert!(matches!(result, Err(LeaseError::InvalidLeaseState { .. })));
    }

    #[test]
    fn test_lease_state_as_str() {
        assert_eq!(LeaseState::Active.as_str(), "ACTIVE");
        assert_eq!(LeaseState::Released.as_str(), "RELEASED");
        assert_eq!(LeaseState::Expired.as_str(), "EXPIRED");
    }

    #[test]
    fn test_lease_state_terminal() {
        assert!(!LeaseState::Active.is_terminal());
        assert!(LeaseState::Released.is_terminal());
        assert!(LeaseState::Expired.is_terminal());
    }

    #[test]
    fn test_lease_state_active() {
        assert!(LeaseState::Active.is_active());
        assert!(!LeaseState::Released.is_active());
        assert!(!LeaseState::Expired.is_active());
    }

    #[test]
    fn test_release_reason_parse() {
        assert_eq!(
            ReleaseReason::parse("COMPLETED").unwrap(),
            ReleaseReason::Completed
        );
        assert_eq!(
            ReleaseReason::parse("completed").unwrap(),
            ReleaseReason::Completed
        );
        assert_eq!(
            ReleaseReason::parse("ABORTED").unwrap(),
            ReleaseReason::Aborted
        );
        assert_eq!(
            ReleaseReason::parse("VOLUNTARY").unwrap(),
            ReleaseReason::Voluntary
        );
    }

    #[test]
    fn test_release_reason_parse_unknown_fails() {
        let result = ReleaseReason::parse("UNKNOWN");
        assert!(matches!(
            result,
            Err(LeaseError::InvalidReleaseReason { .. })
        ));
    }

    #[test]
    fn test_release_reason_as_str() {
        assert_eq!(ReleaseReason::Completed.as_str(), "COMPLETED");
        assert_eq!(ReleaseReason::Aborted.as_str(), "ABORTED");
        assert_eq!(ReleaseReason::Voluntary.as_str(), "VOLUNTARY");
    }

    #[test]
    fn test_lease_new() {
        let lease = Lease::new(
            "lease-1".to_string(),
            "work-1".to_string(),
            "actor-1".to_string(),
            1_000_000_000,
            2_000_000_000,
            vec![1, 2, 3, 4],
        );

        assert_eq!(lease.lease_id, "lease-1");
        assert_eq!(lease.work_id, "work-1");
        assert_eq!(lease.actor_id, "actor-1");
        assert_eq!(lease.state, LeaseState::Active);
        assert_eq!(lease.issued_at, 1_000_000_000);
        assert_eq!(lease.expires_at, 2_000_000_000);
        assert_eq!(lease.registrar_signature, vec![1, 2, 3, 4]);
        assert_eq!(lease.renewal_count, 0);
        assert!(lease.last_renewed_at.is_none());
        assert!(lease.release_reason.is_none());
        assert!(lease.terminated_at.is_none());
        assert!(lease.is_active());
        assert!(!lease.is_terminal());
    }

    #[test]
    #[allow(deprecated)]
    fn test_lease_is_expired_at() {
        let lease = Lease::new(
            "lease-1".to_string(),
            "work-1".to_string(),
            "actor-1".to_string(),
            1_000_000_000,
            2_000_000_000,
            vec![],
        );

        // Before expiration
        assert!(!lease.is_expired_at(1_500_000_000));

        // At expiration boundary
        assert!(lease.is_expired_at(2_000_000_000));

        // After expiration
        assert!(lease.is_expired_at(3_000_000_000));
    }

    #[test]
    #[allow(deprecated)]
    fn test_lease_time_remaining() {
        let lease = Lease::new(
            "lease-1".to_string(),
            "work-1".to_string(),
            "actor-1".to_string(),
            1_000_000_000,
            2_000_000_000,
            vec![],
        );

        assert_eq!(lease.time_remaining(1_500_000_000), 500_000_000);
        assert_eq!(lease.time_remaining(2_000_000_000), 0);
        assert_eq!(lease.time_remaining(3_000_000_000), 0);
    }

    #[test]
    fn test_lease_summary() {
        let lease = Lease::new(
            "lease-1".to_string(),
            "work-1".to_string(),
            "actor-1".to_string(),
            1_000_000_000,
            2_000_000_000,
            vec![1, 2, 3],
        );

        let summary = lease.summary();
        assert_eq!(summary.lease_id, "lease-1");
        assert_eq!(summary.work_id, "work-1");
        assert_eq!(summary.actor_id, "actor-1");
        assert_eq!(summary.state, LeaseState::Active);
        assert_eq!(summary.issued_at, 1_000_000_000);
        assert_eq!(summary.expires_at, 2_000_000_000);
        assert_eq!(summary.renewal_count, 0);
    }
}

/// TCK-00241: Tick-based lease expiry tests (RFC-0016 HTF).
///
/// These tests verify that lease validity is determined by monotonic ticks,
/// not wall time, and that wall time changes do not affect lease validity.
#[cfg(test)]
mod tck_00241 {
    use super::*;

    const TICK_RATE_HZ: u64 = 1_000_000; // 1MHz = 1 tick per microsecond

    /// Helper to create a tick at a given value with standard tick rate.
    fn tick(value: u64) -> HtfTick {
        HtfTick::new(value, TICK_RATE_HZ)
    }

    /// TCK-00241: Tick-based expiry is independent of wall time.
    ///
    /// Verifies that changing wall time values does not affect lease validity
    /// when tick-based timing is used.
    #[test]
    fn wall_time_changes_do_not_affect_tick_expiry() {
        // Create a lease with tick-based timing
        // Wall time: issued at 1s, expires at 2s
        // Tick time: issued at 1000, expires at 2000
        let lease = Lease::new_with_ticks(
            "lease-1".to_string(),
            "work-1".to_string(),
            "actor-1".to_string(),
            1_000_000_000, // wall issued_at (1s in nanos)
            2_000_000_000, // wall expires_at (2s in nanos)
            tick(1000),    // issued_at_tick
            tick(2000),    // expires_at_tick
            vec![1, 2, 3],
        );

        // Test: At tick 1500, lease should NOT be expired regardless of wall time
        assert!(!lease.is_expired_at_tick(&tick(1500)));
        assert_eq!(lease.ticks_remaining(&tick(1500)), 500);

        // Test: At tick 2500, lease SHOULD be expired regardless of wall time
        assert!(lease.is_expired_at_tick(&tick(2500)));
        assert_eq!(lease.ticks_remaining(&tick(2500)), 0);

        // Key verification: Wall time in the struct can be anything - it
        // doesn't matter The tick-based expiry only looks at the tick
        // values
    }

    /// TCK-00241: Tick-based expiry at exact boundary.
    #[test]
    fn tick_expiry_at_exact_boundary() {
        let lease = Lease::new_with_ticks(
            "lease-1".to_string(),
            "work-1".to_string(),
            "actor-1".to_string(),
            1_000_000_000,
            2_000_000_000,
            tick(1000),
            tick(2000),
            vec![1],
        );

        // One tick before expiration
        assert!(!lease.is_expired_at_tick(&tick(1999)));
        assert_eq!(lease.ticks_remaining(&tick(1999)), 1);

        // Exactly at expiration (tick >= expires_at_tick)
        assert!(lease.is_expired_at_tick(&tick(2000)));
        assert_eq!(lease.ticks_remaining(&tick(2000)), 0);

        // One tick after expiration
        assert!(lease.is_expired_at_tick(&tick(2001)));
        assert_eq!(lease.ticks_remaining(&tick(2001)), 0);
    }

    /// TCK-00241: SEC-CTRL-FAC-0015 legacy lease handling.
    ///
    /// Legacy leases without tick data should NOT be treated as expired by
    /// tick-only methods. Instead, callers should use the wall-clock fallback
    /// method `is_expired_at_tick_or_wall`.
    #[test]
    fn legacy_lease_tick_methods_return_false_or_zero() {
        // Create lease WITHOUT tick data (using legacy constructor)
        let lease = Lease::new(
            "lease-1".to_string(),
            "work-1".to_string(),
            "actor-1".to_string(),
            1_000_000_000,
            2_000_000_000,
            vec![1],
        );

        // Verify tick fields are None
        assert!(lease.issued_at_tick.is_none());
        assert!(lease.expires_at_tick.is_none());
        assert!(lease.is_legacy_lease());

        // is_expired_at_tick returns false for legacy leases
        // (caller should use is_expired_at_tick_or_wall for full check)
        assert!(!lease.is_expired_at_tick(&tick(1500)));
        assert_eq!(lease.ticks_remaining(&tick(1500)), 0);
    }

    /// TCK-00241: SEC-CTRL-FAC-0015 wall-clock fallback for legacy leases.
    ///
    /// Legacy leases should use wall-clock comparison when tick data is
    /// not available. This provides a migration path for existing leases.
    #[test]
    fn legacy_lease_uses_wall_clock_fallback() {
        // Create lease WITHOUT tick data (using legacy constructor)
        let lease = Lease::new(
            "lease-1".to_string(),
            "work-1".to_string(),
            "actor-1".to_string(),
            1_000_000_000, // issued at 1s
            2_000_000_000, // expires at 2s
            vec![1],
        );

        // Before wall time expiration
        assert!(!lease.is_expired_at_tick_or_wall(&tick(1000), 1_500_000_000));

        // At wall time expiration boundary
        assert!(lease.is_expired_at_tick_or_wall(&tick(1000), 2_000_000_000));

        // After wall time expiration
        assert!(lease.is_expired_at_tick_or_wall(&tick(1000), 3_000_000_000));
    }

    /// TCK-00241: Terminal leases are not considered expired.
    ///
    /// A lease in terminal state (Released/Expired) should return false
    /// from `is_expired_at_tick`, as it's already been processed.
    #[test]
    fn terminal_lease_not_considered_expired() {
        let mut lease = Lease::new_with_ticks(
            "lease-1".to_string(),
            "work-1".to_string(),
            "actor-1".to_string(),
            1_000_000_000,
            2_000_000_000,
            tick(1000),
            tick(2000),
            vec![1],
        );

        // Simulate lease being released
        lease.state = LeaseState::Released;

        // Even though current tick is past expiry, terminal lease returns false
        assert!(!lease.is_expired_at_tick(&tick(3000)));
    }

    /// TCK-00241: Injected ticks work correctly for testing.
    ///
    /// Demonstrates that tests can use arbitrary tick values without
    /// needing real time sources.
    #[test]
    fn injected_ticks_for_testing() {
        let lease = Lease::new_with_ticks(
            "lease-1".to_string(),
            "work-1".to_string(),
            "actor-1".to_string(),
            0, // Wall time irrelevant
            0, // Wall time irrelevant
            tick(0),
            tick(5000), // Expires at tick 5000
            vec![1],
        );

        // Test with various injected tick values
        let test_cases = [
            (0, false, 5000),    // Start: not expired, 5000 remaining
            (2500, false, 2500), // Midpoint: not expired, 2500 remaining
            (4999, false, 1),    // Just before: not expired, 1 remaining
            (5000, true, 0),     // At expiry: expired, 0 remaining
            (10000, true, 0),    // Well after: expired, 0 remaining
        ];

        for (tick_value, expected_expired, expected_remaining) in test_cases {
            let current = tick(tick_value);
            assert_eq!(
                lease.is_expired_at_tick(&current),
                expected_expired,
                "tick {tick_value} should be expired={expected_expired}"
            );
            assert_eq!(
                lease.ticks_remaining(&current),
                expected_remaining,
                "tick {tick_value} should have {expected_remaining} remaining"
            );
        }
    }

    /// TCK-00241: SEC-HTF-003 Tick rate mismatch fails closed.
    ///
    /// When tick rates differ between current tick and lease expiry tick,
    /// the comparison is invalid. The method fails closed (returns true
    /// for expired) to prevent incorrect expiry decisions.
    #[test]
    fn tick_rate_mismatch_fails_closed() {
        // Lease with 1MHz tick rate
        let lease = Lease::new_with_ticks(
            "lease-1".to_string(),
            "work-1".to_string(),
            "actor-1".to_string(),
            0,
            0,
            HtfTick::new(1000, 1_000_000), // 1MHz
            HtfTick::new(2000, 1_000_000), // expires at tick 2000
            vec![1],
        );

        // Same rate: normal comparison works
        let current_same_rate = HtfTick::new(1500, 1_000_000);
        assert!(!lease.is_expired_at_tick(&current_same_rate));
        assert_eq!(lease.ticks_remaining(&current_same_rate), 500);

        // Different rate: SEC-HTF-003 fail-closed (treated as expired)
        let current_diff_rate = HtfTick::new(1500, 10_000_000);
        assert!(lease.is_expired_at_tick(&current_diff_rate)); // Fail-closed!
        assert_eq!(lease.ticks_remaining(&current_diff_rate), 0); // Also fails closed

        // Test normal expiry with same rate
        let expired_tick = HtfTick::new(2500, 1_000_000);
        assert!(lease.is_expired_at_tick(&expired_tick));
    }

    /// TCK-00241: Same tick rates allow proper comparison.
    ///
    /// When tick rates match, raw tick values are compared directly.
    #[test]
    fn same_tick_rate_comparison_works() {
        let lease = Lease::new_with_ticks(
            "lease-1".to_string(),
            "work-1".to_string(),
            "actor-1".to_string(),
            0,
            0,
            HtfTick::new(1000, 1_000_000),
            HtfTick::new(2000, 1_000_000),
            vec![1],
        );

        // Before expiry
        assert!(!lease.is_expired_at_tick(&HtfTick::new(1999, 1_000_000)));
        assert_eq!(lease.ticks_remaining(&HtfTick::new(1999, 1_000_000)), 1);

        // At expiry
        assert!(lease.is_expired_at_tick(&HtfTick::new(2000, 1_000_000)));
        assert_eq!(lease.ticks_remaining(&HtfTick::new(2000, 1_000_000)), 0);

        // After expiry
        assert!(lease.is_expired_at_tick(&HtfTick::new(2001, 1_000_000)));
        assert_eq!(lease.ticks_remaining(&HtfTick::new(2001, 1_000_000)), 0);
    }

    /// TCK-00241: `Lease::new_with_ticks` sets all fields correctly.
    #[test]
    fn new_with_ticks_sets_all_fields() {
        let issued = tick(1000);
        let expires = tick(5000);

        let lease = Lease::new_with_ticks(
            "lease-id".to_string(),
            "work-id".to_string(),
            "actor-id".to_string(),
            100_000_000,
            500_000_000,
            issued,
            expires,
            vec![0xDE, 0xAD, 0xBE, 0xEF],
        );

        // Verify all fields
        assert_eq!(lease.lease_id, "lease-id");
        assert_eq!(lease.work_id, "work-id");
        assert_eq!(lease.actor_id, "actor-id");
        assert_eq!(lease.state, LeaseState::Active);
        assert_eq!(lease.issued_at, 100_000_000);
        assert_eq!(lease.expires_at, 500_000_000);
        assert_eq!(lease.issued_at_tick, Some(issued));
        assert_eq!(lease.expires_at_tick, Some(expires));
        assert_eq!(lease.registrar_signature, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(lease.renewal_count, 0);
        assert!(lease.last_renewed_at.is_none());
        assert!(lease.release_reason.is_none());
        assert!(lease.terminated_at.is_none());
        assert!(lease.is_active());
        assert!(!lease.is_terminal());
        assert!(!lease.is_legacy_lease());
    }

    /// TCK-00241: Tick-based lease uses tick comparison, ignores wall time.
    ///
    /// When tick data is present, `is_expired_at_tick_or_wall` uses tick
    /// comparison and ignores the wall time parameter.
    #[test]
    fn tick_based_lease_ignores_wall_time_in_combined_method() {
        let lease = Lease::new_with_ticks(
            "lease-1".to_string(),
            "work-1".to_string(),
            "actor-1".to_string(),
            1_000_000_000, // wall issued at 1s
            2_000_000_000, // wall expires at 2s
            tick(1000),
            tick(2000), // tick expires at 2000
            vec![1],
        );

        // Not expired by tick (1500 < 2000), even if wall time says expired
        assert!(!lease.is_expired_at_tick_or_wall(&tick(1500), 3_000_000_000));

        // Expired by tick (2500 >= 2000), even if wall time says not expired
        assert!(lease.is_expired_at_tick_or_wall(&tick(2500), 1_500_000_000));
    }

    /// TCK-00241: SEC-HTF-003 tick rate mismatch in combined method.
    ///
    /// When tick rates mismatch, the combined method also fails closed.
    #[test]
    fn tick_rate_mismatch_in_combined_method_fails_closed() {
        let lease = Lease::new_with_ticks(
            "lease-1".to_string(),
            "work-1".to_string(),
            "actor-1".to_string(),
            1_000_000_000,
            2_000_000_000,
            HtfTick::new(1000, 1_000_000), // 1MHz
            HtfTick::new(2000, 1_000_000), // expires at tick 2000
            vec![1],
        );

        // Different rate: fails closed even though tick value 1500 < 2000
        let mismatched_tick = HtfTick::new(1500, 10_000_000); // 10MHz
        assert!(lease.is_expired_at_tick_or_wall(&mismatched_tick, 1_500_000_000));
    }

    /// TCK-00241: Terminal lease returns false from all expiry methods.
    #[test]
    fn terminal_lease_not_expired_in_combined_method() {
        let mut lease = Lease::new_with_ticks(
            "lease-1".to_string(),
            "work-1".to_string(),
            "actor-1".to_string(),
            1_000_000_000,
            2_000_000_000,
            tick(1000),
            tick(2000),
            vec![1],
        );

        lease.state = LeaseState::Released;

        // Terminal lease returns false even when tick and wall both say expired
        assert!(!lease.is_expired_at_tick_or_wall(&tick(3000), 3_000_000_000));
    }
}
