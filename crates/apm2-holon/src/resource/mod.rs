//! Resource management for holonic execution.
//!
//! This module provides the types and operations for managing resources
//! during holon execution:
//!
//! - [`Lease`]: Time-bounded, scoped authorization for work
//! - [`Budget`]: Multi-dimensional resource limits
//! - [`LeaseScope`]: Authority boundaries for operations
//!
//! # Overview
//!
//! Holons operate under resource constraints defined by leases. Each lease
//! specifies:
//!
//! 1. **What** operations are authorized (scope)
//! 2. **How much** can be consumed (budget)
//! 3. **How long** the authorization is valid (expiration)
//!
//! These constraints implement the Bounded Authority axiom (Axiom III) from
//! Principia Holonica, ensuring that holons cannot exceed their delegated
//! permissions.
//!
//! # Lease Derivation
//!
//! When a holon spawns a sub-holon, it derives a child lease from its own
//! lease. The derivation process ensures:
//!
//! - Child scope is a subset of parent scope
//! - Child budget is bounded by parent's remaining budget
//! - Child expiration is at or before parent expiration
//!
//! This creates a hierarchy of decreasing authority, preventing privilege
//! escalation.
//!
//! # Example
//!
//! ```rust
//! use apm2_holon::resource::{Budget, Lease, LeaseScope};
//!
//! // Create a parent lease
//! let scope = LeaseScope::builder()
//!     .work_ids(["work-001", "work-002"])
//!     .tools(["read", "write"])
//!     .build();
//!
//! let budget = Budget::new(10, 100, 10_000, 60_000);
//!
//! let mut parent = Lease::builder()
//!     .lease_id("parent-lease")
//!     .issuer_id("registrar")
//!     .holder_id("parent-agent")
//!     .scope(scope)
//!     .budget(budget)
//!     .expires_at_ns(2_000_000_000)
//!     .build()
//!     .unwrap();
//!
//! // Derive a child lease with reduced permissions.
//! // NOTE: This deducts the budget from the parent, preventing
//! // resource inflation from deriving multiple children.
//! let child = parent
//!     .derive(
//!         "child-lease",
//!         "child-agent",
//!         &LeaseScope::builder()
//!             .work_ids(["work-001"])
//!             .tools(["read"])
//!             .build(),
//!         &Budget::new(5, 50, 5_000, 30_000),
//!         1_800_000_000,
//!         1_500_000_000,
//!     )
//!     .unwrap();
//!
//! assert!(child.is_derived());
//! assert_eq!(child.parent_lease_id(), Some("parent-lease"));
//! // Parent's budget was deducted
//! assert_eq!(parent.budget().remaining_episodes(), 5); // 10 - 5
//! ```

mod budget;
mod error;
mod lease;
mod scope;

#[cfg(test)]
mod proptest_budget;

pub use budget::Budget;
pub use error::ResourceError;
pub use lease::{Lease, LeaseBuilder};
pub use scope::{LeaseScope, LeaseScopeBuilder};

#[cfg(test)]
mod integration_tests {
    use super::*;

    /// Tests the complete derivation flow from parent to child lease.
    #[test]
    fn test_full_derivation_flow() {
        // Create a root lease with full permissions
        let root_scope = LeaseScope::builder()
            .work_ids(["work-001", "work-002", "work-003"])
            .tools(["read", "write", "delete"])
            .namespaces(["project"])
            .build();

        let root_budget = Budget::new(100, 1000, 100_000, 600_000);

        let mut root_lease = Lease::builder()
            .lease_id("root-lease")
            .issuer_id("registrar")
            .holder_id("root-agent")
            .scope(root_scope)
            .budget(root_budget)
            .issued_at_ns(1_000_000_000)
            .expires_at_ns(2_000_000_000)
            .build()
            .unwrap();

        // Derive first-level child
        let mut child1 = root_lease
            .derive(
                "child-1",
                "agent-1",
                &LeaseScope::builder()
                    .work_ids(["work-001", "work-002"])
                    .tools(["read", "write"])
                    .namespaces(["project/src"])
                    .build(),
                &Budget::new(50, 500, 50_000, 300_000),
                1_800_000_000,
                1_100_000_000,
            )
            .unwrap();

        assert!(child1.is_derived());
        assert_eq!(child1.parent_lease_id(), Some("root-lease"));
        assert_eq!(child1.budget().remaining_episodes(), 50);

        // Verify root's budget was deducted
        assert_eq!(root_lease.budget().remaining_episodes(), 50); // 100 - 50

        // Derive second-level child from first child
        let child2 = child1
            .derive(
                "child-2",
                "agent-2",
                &LeaseScope::builder()
                    .work_ids(["work-001"])
                    .tools(["read"])
                    .build(),
                &Budget::new(10, 100, 10_000, 60_000),
                1_700_000_000,
                1_200_000_000,
            )
            .unwrap();

        assert!(child2.is_derived());
        assert_eq!(child2.parent_lease_id(), Some("child-1"));
        assert_eq!(child2.budget().remaining_episodes(), 10);

        // Verify child1's budget was deducted
        assert_eq!(child1.budget().remaining_episodes(), 40); // 50 - 10

        // Child 2 should have reduced permissions
        assert!(child2.scope().allows_work_id("work-001"));
        assert!(!child2.scope().allows_work_id("work-002"));
        assert!(child2.scope().allows_tool("read"));
        assert!(!child2.scope().allows_tool("write"));
    }

    /// Tests that budget exhaustion is detected correctly.
    #[test]
    fn test_budget_exhaustion_detection() {
        let scope = LeaseScope::unlimited();
        let mut budget = Budget::new(5, 10, 100, 1000);

        // Consume all episodes
        for _ in 0..5 {
            budget.deduct_episodes(1).unwrap();
        }

        assert!(budget.is_exhausted());
        assert_eq!(budget.exhausted_resource(), Some("episodes"));

        // Create a lease with exhausted budget
        let lease = Lease::builder()
            .lease_id("exhausted")
            .issuer_id("registrar")
            .holder_id("agent")
            .scope(scope)
            .budget(budget)
            .expires_at_ns(2_000_000_000)
            .build()
            .unwrap();

        // Validation should fail
        let result = lease.validate(1_500_000_000);
        assert!(result.is_err());
        assert!(matches!(result, Err(ResourceError::BudgetExhausted { .. })));
    }

    /// Tests that scope violations are detected.
    #[test]
    fn test_scope_violation_detection() {
        let scope = LeaseScope::builder()
            .work_ids(["allowed-work"])
            .tools(["allowed-tool"])
            .namespaces(["allowed/path"])
            .build();

        let lease = Lease::builder()
            .lease_id("scoped")
            .issuer_id("registrar")
            .holder_id("agent")
            .scope(scope)
            .budget(Budget::new(10, 100, 10_000, 60_000))
            .expires_at_ns(2_000_000_000)
            .build()
            .unwrap();

        // Allowed operations
        assert!(lease.validate_work_access("allowed-work").is_ok());
        assert!(lease.validate_tool_access("allowed-tool").is_ok());
        assert!(
            lease
                .validate_namespace_access("allowed/path/file.rs")
                .is_ok()
        );

        // Denied operations
        assert!(lease.validate_work_access("denied-work").is_err());
        assert!(lease.validate_tool_access("denied-tool").is_err());
        assert!(lease.validate_namespace_access("denied/path").is_err());
    }

    /// Tests that lease expiration is enforced.
    #[test]
    fn test_expiration_enforcement() {
        let lease = Lease::builder()
            .lease_id("expiring")
            .issuer_id("registrar")
            .holder_id("agent")
            .scope(LeaseScope::unlimited())
            .budget(Budget::new(10, 100, 10_000, 60_000))
            .issued_at_ns(1_000_000_000)
            .expires_at_ns(1_500_000_000)
            .build()
            .unwrap();

        // Valid before expiration
        assert!(lease.validate(1_400_000_000).is_ok());

        // Invalid at expiration
        let result = lease.validate(1_500_000_000);
        assert!(result.is_err());
        match result {
            Err(ResourceError::LeaseExpired {
                lease_id,
                expired_at_ns,
            }) => {
                assert_eq!(lease_id, "expiring");
                assert_eq!(expired_at_ns, 1_500_000_000);
            },
            _ => panic!("Expected LeaseExpired error"),
        }

        // Invalid after expiration
        assert!(lease.validate(2_000_000_000).is_err());
    }

    /// Tests that derived leases cannot exceed parent constraints.
    #[test]
    fn test_derivation_constraints() {
        let mut parent = Lease::builder()
            .lease_id("parent")
            .issuer_id("registrar")
            .holder_id("parent-agent")
            .scope(LeaseScope::builder().work_ids(["work-1"]).build())
            .budget(Budget::new(10, 100, 10_000, 60_000))
            .expires_at_ns(2_000_000_000)
            .build()
            .unwrap();

        // Cannot derive with scope exceeding parent
        let result = parent.derive(
            "child",
            "child-agent",
            &LeaseScope::builder().work_ids(["work-1", "work-2"]).build(),
            &Budget::new(5, 50, 5_000, 30_000),
            1_800_000_000,
            1_500_000_000,
        );
        assert!(result.is_err());

        // Cannot derive with budget exceeding parent
        let result = parent.derive(
            "child",
            "child-agent",
            &LeaseScope::builder().work_ids(["work-1"]).build(),
            &Budget::new(20, 50, 5_000, 30_000), // 20 > 10 episodes
            1_800_000_000,
            1_500_000_000,
        );
        assert!(result.is_err());

        // Cannot derive with expiration exceeding parent
        let result = parent.derive(
            "child",
            "child-agent",
            &LeaseScope::builder().work_ids(["work-1"]).build(),
            &Budget::new(5, 50, 5_000, 30_000),
            3_000_000_000, // After parent expires
            1_500_000_000,
        );
        assert!(result.is_err());

        // Valid derivation succeeds
        let result = parent.derive(
            "child",
            "child-agent",
            &LeaseScope::builder().work_ids(["work-1"]).build(),
            &Budget::new(5, 50, 5_000, 30_000),
            1_800_000_000,
            1_500_000_000,
        );
        assert!(result.is_ok());
    }
}
