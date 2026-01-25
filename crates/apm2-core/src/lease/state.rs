//! Lease state types.

use serde::{Deserialize, Serialize};

use super::error::LeaseError;

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
    pub issued_at: u64,

    /// Timestamp when the lease expires (Unix nanos).
    pub expires_at: u64,

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

    /// Checks if the lease has expired based on the given current time.
    ///
    /// Returns true if the current time is past the lease's expiration time
    /// AND the lease is still in the Active state.
    #[must_use]
    pub const fn is_expired_at(&self, current_time: u64) -> bool {
        self.state.is_active() && current_time >= self.expires_at
    }

    /// Returns the remaining time until expiration, or 0 if expired.
    ///
    /// Only meaningful for active leases.
    #[must_use]
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
