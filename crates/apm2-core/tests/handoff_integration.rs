//! Integration tests for agent handoff flow (TCK-00089).
//!
//! This test file provides comprehensive integration tests for the agent
//! handoff flow as specified in RFC-0008. It verifies:
//!
//! 1. Full E2E handoff flow (webhook -> event -> transition -> claim)
//! 2. Webhook signature validation (valid and invalid)
//! 3. Idempotency of webhook handling (duplicate delivery IDs)
//! 4. Anti-gaming controls (agent cannot set CI status directly)
//! 5. Error cases (malformed payload, missing headers)
//! 6. Feature flag behavior (each phase can be disabled)
//! 7. Phase transition state machine edge cases
//!
//! # Evidence
//!
//! These tests provide evidence for:
//! - EVID-8005: Anti-gaming controls verified
//!
//! # Running Tests
//!
//! ```bash
//! cargo test -p apm2-core --test handoff_integration
//! ```

#[allow(dead_code)]
mod fixtures;
mod integration;
