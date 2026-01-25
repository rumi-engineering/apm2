//! Lease types for holonic resource management.
//!
//! This module defines the [`Lease`] type that represents a time-bounded,
//! scoped authorization for a holon to perform work. Leases encapsulate:
//!
//! - **Identity**: Issuer, holder, and unique lease ID
//! - **Scope**: What operations the lease authorizes (via [`LeaseScope`])
//! - **Budget**: Resource limits for execution (via [`Budget`])
//! - **Expiration**: When the lease becomes invalid
//! - **Lineage**: Parent lease for derived leases
//!
//! # Example
//!
//! ```rust
//! use apm2_holon::resource::{Budget, Lease, LeaseScope};
//!
//! // Create a lease with scope and budget
//! let scope = LeaseScope::builder()
//!     .work_ids(["work-001"])
//!     .tools(["read_file"])
//!     .build();
//!
//! let budget = Budget::new(10, 100, 10_000, 60_000);
//!
//! let lease = Lease::builder()
//!     .lease_id("lease-001")
//!     .issuer_id("registrar-001")
//!     .holder_id("agent-001")
//!     .scope(scope)
//!     .budget(budget)
//!     .expires_at_ns(2_000_000_000)
//!     .build()
//!     .unwrap();
//!
//! assert!(!lease.is_expired_at(1_000_000_000));
//! assert!(lease.scope().allows_work_id("work-001"));
//! ```

use serde::{Deserialize, Serialize};

use super::budget::Budget;
use super::error::ResourceError;
use super::scope::LeaseScope;

/// A lease granting scoped, time-bounded authorization to a holon.
///
/// Leases are the fundamental authorization mechanism in holonic coordination.
/// They implement bounded authority (Axiom III) by constraining:
///
/// - What operations can be performed (scope)
/// - How many resources can be consumed (budget)
/// - How long the authorization is valid (expiration)
///
/// # Derivation
///
/// Leases can be derived from parent leases for sub-holons. Derived leases
/// must have:
/// - A scope that is a subset of the parent's scope
/// - A budget that is bounded by the parent's remaining budget
/// - An expiration at or before the parent's expiration
///
/// # Signature
///
/// Leases carry a signature from the registrar that issued them. This prevents
/// forgery and enables verification of lease authenticity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_field_names)]
pub struct Lease {
    /// Unique identifier for this lease.
    id: String,

    /// The entity that issued this lease (typically a registrar).
    issuer_id: String,

    /// The holon holding this lease.
    holder_id: String,

    /// The scope of authority this lease grants.
    scope: LeaseScope,

    /// The resource budget for this lease.
    budget: Budget,

    /// Timestamp when the lease was issued (nanoseconds since epoch).
    issued_at_ns: u64,

    /// Timestamp when the lease expires (nanoseconds since epoch).
    expires_at_ns: u64,

    /// Parent lease ID if this is a derived lease.
    parent_lease_id: Option<String>,

    /// Registrar signature over the lease data.
    /// Empty for unsigned leases (testing only).
    #[serde(with = "serde_bytes")]
    signature: Vec<u8>,
}

impl Lease {
    /// Returns a builder for constructing a `Lease`.
    #[must_use]
    pub fn builder() -> LeaseBuilder {
        LeaseBuilder::default()
    }

    /// Returns the lease ID.
    #[must_use]
    pub fn lease_id(&self) -> &str {
        &self.id
    }

    /// Returns the issuer ID.
    #[must_use]
    pub fn issuer_id(&self) -> &str {
        &self.issuer_id
    }

    /// Returns the holder ID.
    #[must_use]
    pub fn holder_id(&self) -> &str {
        &self.holder_id
    }

    /// Returns the lease scope.
    #[must_use]
    pub const fn scope(&self) -> &LeaseScope {
        &self.scope
    }

    /// Returns the lease budget.
    #[must_use]
    pub const fn budget(&self) -> &Budget {
        &self.budget
    }

    /// Returns a mutable reference to the budget.
    ///
    /// This allows deducting resources during execution.
    pub const fn budget_mut(&mut self) -> &mut Budget {
        &mut self.budget
    }

    /// Returns the issuance timestamp in nanoseconds.
    #[must_use]
    pub const fn issued_at_ns(&self) -> u64 {
        self.issued_at_ns
    }

    /// Returns the expiration timestamp in nanoseconds.
    #[must_use]
    pub const fn expires_at_ns(&self) -> u64 {
        self.expires_at_ns
    }

    /// Returns the parent lease ID, if this is a derived lease.
    #[must_use]
    pub fn parent_lease_id(&self) -> Option<&str> {
        self.parent_lease_id.as_deref()
    }

    /// Returns `true` if this is a derived lease.
    #[must_use]
    pub const fn is_derived(&self) -> bool {
        self.parent_lease_id.is_some()
    }

    /// Returns the signature bytes.
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Returns `true` if this lease has a signature.
    #[must_use]
    pub fn is_signed(&self) -> bool {
        !self.signature.is_empty()
    }

    /// Returns the canonical byte representation used for signing.
    ///
    /// This method produces a deterministic serialization of the lease data
    /// that is suitable for signing and verification. The signature field
    /// itself is excluded from the canonical representation.
    ///
    /// # Canonicalization Rules
    ///
    /// The canonical form is JSON with fields in a deterministic order:
    /// 1. `id`
    /// 2. `issuer_id`
    /// 3. `holder_id`
    /// 4. `scope` (serialized recursively)
    /// 5. `budget` (with all 8 fields in order)
    /// 6. `issued_at_ns`
    /// 7. `expires_at_ns`
    /// 8. `parent_lease_id` (if present)
    ///
    /// # Security
    ///
    /// Consumers MUST use this method to obtain the bytes for signing or
    /// verification. Using arbitrary serialization methods may lead to
    /// verification failures or security vulnerabilities.
    ///
    /// # Panics
    ///
    /// This method will not panic under normal circumstances. The internal
    /// JSON serialization uses only types that are guaranteed to serialize
    /// successfully (strings, integers, Option, and serde-compatible structs).
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        // Create a canonical representation without the signature field
        // Using serde_json ensures deterministic field ordering (BTreeMap in scope)
        let canonical = serde_json::json!({
            "id": self.id,
            "issuer_id": self.issuer_id,
            "holder_id": self.holder_id,
            "scope": self.scope,
            "budget": {
                "initial_episodes": self.budget.initial_episodes(),
                "remaining_episodes": self.budget.remaining_episodes(),
                "initial_tool_calls": self.budget.initial_tool_calls(),
                "remaining_tool_calls": self.budget.remaining_tool_calls(),
                "initial_tokens": self.budget.initial_tokens(),
                "remaining_tokens": self.budget.remaining_tokens(),
                "initial_duration_ms": self.budget.initial_duration_ms(),
                "remaining_duration_ms": self.budget.remaining_duration_ms(),
            },
            "issued_at_ns": self.issued_at_ns,
            "expires_at_ns": self.expires_at_ns,
            "parent_lease_id": self.parent_lease_id,
        });

        // serde_json::to_vec produces deterministic output for objects
        // because we're using serde_json::Value which preserves key order
        serde_json::to_vec(&canonical).expect("serialization cannot fail")
    }

    /// Returns `true` if this lease is expired at the given time.
    ///
    /// # Arguments
    ///
    /// * `current_time_ns` - Current time in nanoseconds since epoch
    #[must_use]
    pub const fn is_expired_at(&self, current_time_ns: u64) -> bool {
        current_time_ns >= self.expires_at_ns
    }

    /// Returns the remaining time until expiration in nanoseconds.
    ///
    /// Returns 0 if the lease is already expired.
    #[must_use]
    pub const fn time_remaining_ns(&self, current_time_ns: u64) -> u64 {
        self.expires_at_ns.saturating_sub(current_time_ns)
    }

    /// Validates that this lease is currently valid.
    ///
    /// # Arguments
    ///
    /// * `current_time_ns` - Current time in nanoseconds since epoch
    ///
    /// # Errors
    ///
    /// Returns `ResourceError::LeaseExpired` if the lease has expired.
    /// Returns `ResourceError::BudgetExhausted` if the budget is exhausted.
    pub fn validate(&self, current_time_ns: u64) -> Result<(), ResourceError> {
        if self.is_expired_at(current_time_ns) {
            return Err(ResourceError::lease_expired(&self.id, self.expires_at_ns));
        }

        if self.budget.is_exhausted() {
            let resource = self.budget.exhausted_resource().unwrap_or("unknown");
            return Err(ResourceError::budget_exhausted(resource, 1, 0));
        }

        Ok(())
    }

    /// Validates that an operation is permitted by this lease's scope.
    ///
    /// # Errors
    ///
    /// Returns `ResourceError::LeaseScopeViolation` if the operation is not
    /// permitted.
    pub fn validate_work_access(&self, work_id: &str) -> Result<(), ResourceError> {
        if !self.scope.allows_work_id(work_id) {
            return Err(ResourceError::scope_violation(format!(
                "work_id '{work_id}' not in lease scope"
            )));
        }
        Ok(())
    }

    /// Validates that a tool invocation is permitted by this lease's scope.
    ///
    /// # Errors
    ///
    /// Returns `ResourceError::LeaseScopeViolation` if the tool is not
    /// permitted.
    pub fn validate_tool_access(&self, tool: &str) -> Result<(), ResourceError> {
        if !self.scope.allows_tool(tool) {
            return Err(ResourceError::scope_violation(format!(
                "tool '{tool}' not in lease scope"
            )));
        }
        Ok(())
    }

    /// Validates that a namespace path is permitted by this lease's scope.
    ///
    /// # Errors
    ///
    /// Returns `ResourceError::LeaseScopeViolation` if the path is not
    /// permitted.
    pub fn validate_namespace_access(&self, path: &str) -> Result<(), ResourceError> {
        if !self.scope.allows_namespace(path) {
            return Err(ResourceError::scope_violation(format!(
                "namespace '{path}' not in lease scope"
            )));
        }
        Ok(())
    }

    /// Derives a child lease for a sub-holon.
    ///
    /// The derived lease will have:
    /// - A new unique ID
    /// - Scope bounded by this lease's scope
    /// - Budget bounded by this lease's remaining budget
    /// - Expiration at or before this lease's expiration
    ///
    /// # Budget Conservation
    ///
    /// This method **deducts** the requested budget from the parent lease's
    /// remaining budget. This prevents "resource inflation" attacks where
    /// multiple children are derived that collectively exceed the parent's
    /// total budget.
    ///
    /// # Arguments
    ///
    /// * `child_lease_id` - Unique ID for the child lease
    /// * `child_holder_id` - The sub-holon that will hold the child lease
    /// * `requested_scope` - The scope requested for the child
    /// * `requested_budget` - The budget requested for the child
    /// * `requested_expires_at_ns` - The expiration requested for the child
    /// * `issued_at_ns` - When the child lease is issued
    ///
    /// # Errors
    ///
    /// Returns `ResourceError::InvalidDerivation` if the requested parameters
    /// exceed this lease's constraints.
    #[allow(clippy::too_many_arguments)]
    pub fn derive(
        &mut self,
        child_lease_id: impl Into<String>,
        child_holder_id: impl Into<String>,
        requested_scope: &LeaseScope,
        requested_budget: &Budget,
        requested_expires_at_ns: u64,
        issued_at_ns: u64,
    ) -> Result<Self, ResourceError> {
        // Validate expiration
        if requested_expires_at_ns > self.expires_at_ns {
            return Err(ResourceError::invalid_derivation(
                "derived lease expiration exceeds parent expiration",
            ));
        }

        // Validate scope
        self.scope.validate_derivation(requested_scope)?;

        // Validate budget - this also checks if the parent has enough remaining
        if !self.budget.can_accommodate(requested_budget) {
            return Err(ResourceError::invalid_derivation(
                "derived lease budget exceeds parent remaining budget",
            ));
        }

        // Deduct the budget from the parent to prevent resource inflation.
        // This is atomic - if deduction fails, no changes are made.
        self.budget.deduct(
            requested_budget.initial_episodes(),
            requested_budget.initial_tool_calls(),
            requested_budget.initial_tokens(),
            requested_budget.initial_duration_ms(),
        )?;

        // Create the child's budget as a fresh budget with the requested values.
        // Note: We already validated that the parent can accommodate and deducted
        // from the parent, so the child gets exactly what was requested.
        let child_budget = Budget::new(
            requested_budget.initial_episodes(),
            requested_budget.initial_tool_calls(),
            requested_budget.initial_tokens(),
            requested_budget.initial_duration_ms(),
        );

        // Create the derived lease
        Ok(Self {
            id: child_lease_id.into(),
            issuer_id: self.issuer_id.clone(),
            holder_id: child_holder_id.into(),
            scope: self.scope.derive_sub_scope(requested_scope),
            budget: child_budget,
            issued_at_ns,
            expires_at_ns: requested_expires_at_ns.min(self.expires_at_ns),
            parent_lease_id: Some(self.id.clone()),
            signature: Vec::new(), // Derived leases need to be signed by registrar
        })
    }
}

/// Builder for constructing [`Lease`] instances.
#[derive(Debug, Default)]
pub struct LeaseBuilder {
    lease_id: Option<String>,
    issuer_id: Option<String>,
    holder_id: Option<String>,
    scope: Option<LeaseScope>,
    budget: Option<Budget>,
    issued_at_ns: Option<u64>,
    expires_at_ns: Option<u64>,
    parent_lease_id: Option<String>,
    signature: Vec<u8>,
}

impl LeaseBuilder {
    /// Sets the lease ID.
    #[must_use]
    pub fn lease_id(mut self, id: impl Into<String>) -> Self {
        self.lease_id = Some(id.into());
        self
    }

    /// Sets the issuer ID.
    #[must_use]
    pub fn issuer_id(mut self, id: impl Into<String>) -> Self {
        self.issuer_id = Some(id.into());
        self
    }

    /// Sets the holder ID.
    #[must_use]
    pub fn holder_id(mut self, id: impl Into<String>) -> Self {
        self.holder_id = Some(id.into());
        self
    }

    /// Sets the scope.
    #[must_use]
    pub fn scope(mut self, scope: LeaseScope) -> Self {
        self.scope = Some(scope);
        self
    }

    /// Sets the budget.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // destructors cannot be const
    pub fn budget(mut self, budget: Budget) -> Self {
        self.budget = Some(budget);
        self
    }

    /// Sets the issuance timestamp.
    #[must_use]
    pub const fn issued_at_ns(mut self, ts: u64) -> Self {
        self.issued_at_ns = Some(ts);
        self
    }

    /// Sets the expiration timestamp.
    #[must_use]
    pub const fn expires_at_ns(mut self, ts: u64) -> Self {
        self.expires_at_ns = Some(ts);
        self
    }

    /// Sets the parent lease ID (for derived leases).
    #[must_use]
    pub fn parent_lease_id(mut self, id: impl Into<String>) -> Self {
        self.parent_lease_id = Some(id.into());
        self
    }

    /// Sets the signature.
    #[must_use]
    pub fn signature(mut self, sig: Vec<u8>) -> Self {
        self.signature = sig;
        self
    }

    /// Builds the `Lease`.
    ///
    /// # Errors
    ///
    /// Returns `ResourceError::MissingField` if any required field is not set.
    pub fn build(self) -> Result<Lease, ResourceError> {
        let lease_id = self
            .lease_id
            .ok_or_else(|| ResourceError::missing_field("lease_id"))?;
        let issuer_id = self
            .issuer_id
            .ok_or_else(|| ResourceError::missing_field("issuer_id"))?;
        let holder_id = self
            .holder_id
            .ok_or_else(|| ResourceError::missing_field("holder_id"))?;
        let scope = self
            .scope
            .ok_or_else(|| ResourceError::missing_field("scope"))?;
        let budget = self
            .budget
            .ok_or_else(|| ResourceError::missing_field("budget"))?;
        let expires_at_ns = self
            .expires_at_ns
            .ok_or_else(|| ResourceError::missing_field("expires_at_ns"))?;

        let issued_at_ns = self.issued_at_ns.unwrap_or_else(current_timestamp_ns);

        Ok(Lease {
            id: lease_id,
            issuer_id,
            holder_id,
            scope,
            budget,
            issued_at_ns,
            expires_at_ns,
            parent_lease_id: self.parent_lease_id,
            signature: self.signature,
        })
    }
}

/// Returns the current timestamp in nanoseconds since epoch.
fn current_timestamp_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    #[allow(clippy::cast_possible_truncation)]
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_lease() -> Lease {
        Lease::builder()
            .lease_id("lease-001")
            .issuer_id("registrar-001")
            .holder_id("agent-001")
            .scope(
                LeaseScope::builder()
                    .work_ids(["work-001", "work-002"])
                    .tools(["read_file", "write_file"])
                    .namespaces(["project/src"])
                    .build(),
            )
            .budget(Budget::new(10, 100, 10_000, 60_000))
            .issued_at_ns(1_000_000_000)
            .expires_at_ns(2_000_000_000)
            .build()
            .unwrap()
    }

    #[test]
    fn test_lease_creation() {
        let lease = test_lease();

        assert_eq!(lease.lease_id(), "lease-001");
        assert_eq!(lease.issuer_id(), "registrar-001");
        assert_eq!(lease.holder_id(), "agent-001");
        assert_eq!(lease.issued_at_ns(), 1_000_000_000);
        assert_eq!(lease.expires_at_ns(), 2_000_000_000);
        assert!(!lease.is_derived());
        assert!(!lease.is_signed());
    }

    #[test]
    fn test_lease_expiration() {
        let lease = test_lease();

        // Before expiration
        assert!(!lease.is_expired_at(1_500_000_000));
        assert_eq!(lease.time_remaining_ns(1_500_000_000), 500_000_000);

        // At expiration
        assert!(lease.is_expired_at(2_000_000_000));
        assert_eq!(lease.time_remaining_ns(2_000_000_000), 0);

        // After expiration
        assert!(lease.is_expired_at(3_000_000_000));
        assert_eq!(lease.time_remaining_ns(3_000_000_000), 0);
    }

    #[test]
    fn test_lease_validate_success() {
        let lease = test_lease();

        assert!(lease.validate(1_500_000_000).is_ok());
    }

    #[test]
    fn test_lease_validate_expired() {
        let lease = test_lease();

        let result = lease.validate(3_000_000_000);
        assert!(result.is_err());
        assert!(matches!(result, Err(ResourceError::LeaseExpired { .. })));
    }

    #[test]
    fn test_lease_validate_budget_exhausted() {
        let mut lease = test_lease();
        lease.budget_mut().deduct_episodes(10).unwrap();

        let result = lease.validate(1_500_000_000);
        assert!(result.is_err());
        assert!(matches!(result, Err(ResourceError::BudgetExhausted { .. })));
    }

    #[test]
    fn test_validate_work_access() {
        let lease = test_lease();

        assert!(lease.validate_work_access("work-001").is_ok());
        assert!(lease.validate_work_access("work-002").is_ok());

        let result = lease.validate_work_access("work-003");
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(ResourceError::LeaseScopeViolation { .. })
        ));
    }

    #[test]
    fn test_validate_tool_access() {
        let lease = test_lease();

        assert!(lease.validate_tool_access("read_file").is_ok());
        assert!(lease.validate_tool_access("write_file").is_ok());

        let result = lease.validate_tool_access("delete_file");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_namespace_access() {
        let lease = test_lease();

        assert!(
            lease
                .validate_namespace_access("project/src/main.rs")
                .is_ok()
        );

        let result = lease.validate_namespace_access("project/tests/test.rs");
        assert!(result.is_err());
    }

    #[test]
    fn test_derive_lease() {
        let mut parent = test_lease();

        let child = parent
            .derive(
                "lease-002",
                "agent-002",
                &LeaseScope::builder()
                    .work_ids(["work-001"])
                    .tools(["read_file"])
                    .build(),
                &Budget::new(5, 50, 5_000, 30_000),
                1_800_000_000,
                1_500_000_000,
            )
            .unwrap();

        assert_eq!(child.lease_id(), "lease-002");
        assert_eq!(child.holder_id(), "agent-002");
        assert_eq!(child.parent_lease_id(), Some("lease-001"));
        assert!(child.is_derived());
        assert_eq!(child.expires_at_ns(), 1_800_000_000);
        assert_eq!(child.budget().remaining_episodes(), 5);

        // Verify parent's budget was deducted (prevents resource inflation)
        assert_eq!(parent.budget().remaining_episodes(), 5); // 10 - 5
        assert_eq!(parent.budget().remaining_tool_calls(), 50); // 100 - 50
    }

    #[test]
    fn test_derive_expiration_bounded() {
        let mut parent = test_lease();

        // Request expiration after parent - should be capped
        let child = parent.derive(
            "lease-002",
            "agent-002",
            &LeaseScope::builder().work_ids(["work-001"]).build(),
            &Budget::new(5, 50, 5_000, 30_000),
            3_000_000_000, // After parent expires
            1_500_000_000,
        );

        // Should fail because requested expiration exceeds parent
        assert!(child.is_err());
    }

    #[test]
    fn test_derive_scope_bounded() {
        let mut parent = test_lease();

        // Request work ID not in parent scope
        let result = parent.derive(
            "lease-002",
            "agent-002",
            &LeaseScope::builder().work_ids(["work-003"]).build(),
            &Budget::new(5, 50, 5_000, 30_000),
            1_800_000_000,
            1_500_000_000,
        );

        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(ResourceError::InvalidDerivation { .. })
        ));
    }

    #[test]
    fn test_derive_budget_bounded() {
        let mut parent = test_lease();

        // Request budget exceeding parent
        let result = parent.derive(
            "lease-002",
            "agent-002",
            &LeaseScope::builder().work_ids(["work-001"]).build(),
            &Budget::new(20, 50, 5_000, 30_000), // 20 > parent's 10
            1_800_000_000,
            1_500_000_000,
        );

        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(ResourceError::InvalidDerivation { .. })
        ));
    }

    #[test]
    fn test_derive_prevents_double_spending() {
        // SECURITY: Verify that deriving multiple children depletes parent budget
        // and prevents creating children that collectively exceed parent's budget.
        let mut parent = test_lease(); // Budget: 10 episodes, 100 tool_calls, etc.

        // First child takes 6 episodes
        let child1 = parent
            .derive(
                "lease-002",
                "agent-002",
                &LeaseScope::builder().work_ids(["work-001"]).build(),
                &Budget::new(6, 50, 5_000, 30_000),
                1_800_000_000,
                1_500_000_000,
            )
            .unwrap();

        assert_eq!(child1.budget().remaining_episodes(), 6);
        assert_eq!(parent.budget().remaining_episodes(), 4); // 10 - 6 = 4

        // Second child tries to take 6 episodes, but parent only has 4 remaining
        let child2_result = parent.derive(
            "lease-003",
            "agent-003",
            &LeaseScope::builder().work_ids(["work-001"]).build(),
            &Budget::new(6, 50, 5_000, 30_000), // 6 > 4 remaining
            1_800_000_000,
            1_500_000_000,
        );

        // Should fail due to insufficient budget
        assert!(child2_result.is_err());

        // Second child with smaller budget should succeed
        let child2 = parent
            .derive(
                "lease-003",
                "agent-003",
                &LeaseScope::builder().work_ids(["work-001"]).build(),
                &Budget::new(4, 50, 5_000, 30_000), // 4 <= 4 remaining
                1_800_000_000,
                1_500_000_000,
            )
            .unwrap();

        assert_eq!(child2.budget().remaining_episodes(), 4);
        assert_eq!(parent.budget().remaining_episodes(), 0); // Fully depleted

        // Cannot derive any more children with budget
        let child3_result = parent.derive(
            "lease-004",
            "agent-004",
            &LeaseScope::builder().work_ids(["work-001"]).build(),
            &Budget::new(1, 1, 1, 1), // Any budget > 0
            1_800_000_000,
            1_500_000_000,
        );

        assert!(child3_result.is_err());
    }

    #[test]
    fn test_builder_missing_lease_id() {
        let result = Lease::builder()
            .issuer_id("registrar-001")
            .holder_id("agent-001")
            .scope(LeaseScope::empty())
            .budget(Budget::new(10, 100, 10_000, 60_000))
            .expires_at_ns(2_000_000_000)
            .build();

        assert!(result.is_err());
        match result {
            Err(ResourceError::MissingField { field }) => {
                assert_eq!(field, "lease_id");
            },
            _ => panic!("Expected MissingField error"),
        }
    }

    #[test]
    fn test_builder_missing_issuer_id() {
        let result = Lease::builder()
            .lease_id("lease-001")
            .holder_id("agent-001")
            .scope(LeaseScope::empty())
            .budget(Budget::new(10, 100, 10_000, 60_000))
            .expires_at_ns(2_000_000_000)
            .build();

        assert!(result.is_err());
        match result {
            Err(ResourceError::MissingField { field }) => {
                assert_eq!(field, "issuer_id");
            },
            _ => panic!("Expected MissingField error"),
        }
    }

    #[test]
    fn test_builder_with_signature() {
        let lease = Lease::builder()
            .lease_id("lease-001")
            .issuer_id("registrar-001")
            .holder_id("agent-001")
            .scope(LeaseScope::empty())
            .budget(Budget::new(10, 100, 10_000, 60_000))
            .expires_at_ns(2_000_000_000)
            .signature(vec![1, 2, 3, 4])
            .build()
            .unwrap();

        assert!(lease.is_signed());
        assert_eq!(lease.signature(), &[1, 2, 3, 4]);
    }

    #[test]
    fn test_builder_with_parent() {
        let lease = Lease::builder()
            .lease_id("lease-002")
            .issuer_id("registrar-001")
            .holder_id("agent-002")
            .scope(LeaseScope::empty())
            .budget(Budget::new(5, 50, 5_000, 30_000))
            .expires_at_ns(1_800_000_000)
            .parent_lease_id("lease-001")
            .build()
            .unwrap();

        assert!(lease.is_derived());
        assert_eq!(lease.parent_lease_id(), Some("lease-001"));
    }

    #[test]
    fn test_serialization() {
        let lease = test_lease();
        let json = serde_json::to_string(&lease).unwrap();
        let deserialized: Lease = serde_json::from_str(&json).unwrap();

        assert_eq!(lease, deserialized);
    }

    #[test]
    fn test_budget_deduction_through_lease() {
        let mut lease = test_lease();

        assert_eq!(lease.budget().remaining_episodes(), 10);

        lease.budget_mut().deduct_episodes(3).unwrap();
        assert_eq!(lease.budget().remaining_episodes(), 7);

        lease.budget_mut().deduct_tokens(1000).unwrap();
        assert_eq!(lease.budget().remaining_tokens(), 9_000);
    }

    #[test]
    fn test_signing_bytes_deterministic() {
        // Create two identical leases
        let lease1 = test_lease();
        let lease2 = test_lease();

        // signing_bytes should produce identical output for identical leases
        assert_eq!(lease1.signing_bytes(), lease2.signing_bytes());
    }

    #[test]
    fn test_signing_bytes_excludes_signature() {
        // Create a lease without signature
        let unsigned = test_lease();

        // Create a lease with signature
        let signed = Lease::builder()
            .lease_id("lease-001")
            .issuer_id("registrar-001")
            .holder_id("agent-001")
            .scope(
                LeaseScope::builder()
                    .work_ids(["work-001", "work-002"])
                    .tools(["read_file", "write_file"])
                    .namespaces(["project/src"])
                    .build(),
            )
            .budget(Budget::new(10, 100, 10_000, 60_000))
            .issued_at_ns(1_000_000_000)
            .expires_at_ns(2_000_000_000)
            .signature(vec![1, 2, 3, 4, 5]) // Different signature
            .build()
            .unwrap();

        // signing_bytes should be the same regardless of signature
        assert_eq!(unsigned.signing_bytes(), signed.signing_bytes());
    }

    #[test]
    fn test_signing_bytes_differs_with_content() {
        let lease1 = test_lease();

        // Create a lease with different content
        let lease2 = Lease::builder()
            .lease_id("lease-002") // Different ID
            .issuer_id("registrar-001")
            .holder_id("agent-001")
            .scope(
                LeaseScope::builder()
                    .work_ids(["work-001", "work-002"])
                    .tools(["read_file", "write_file"])
                    .namespaces(["project/src"])
                    .build(),
            )
            .budget(Budget::new(10, 100, 10_000, 60_000))
            .issued_at_ns(1_000_000_000)
            .expires_at_ns(2_000_000_000)
            .build()
            .unwrap();

        // signing_bytes should differ when content differs
        assert_ne!(lease1.signing_bytes(), lease2.signing_bytes());
    }

    #[test]
    fn test_signing_bytes_is_valid_json() {
        let lease = test_lease();
        let bytes = lease.signing_bytes();

        // Should be valid JSON
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        // Should not contain signature field
        assert!(json.get("signature").is_none());

        // Should contain all other expected fields
        assert!(json.get("id").is_some());
        assert!(json.get("issuer_id").is_some());
        assert!(json.get("holder_id").is_some());
        assert!(json.get("scope").is_some());
        assert!(json.get("budget").is_some());
        assert!(json.get("issued_at_ns").is_some());
        assert!(json.get("expires_at_ns").is_some());
    }
}
