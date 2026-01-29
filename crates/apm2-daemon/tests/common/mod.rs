//! Common test utilities for E2E daemon tests.
//!
//! This module provides shared test infrastructure for integration tests
//! including `TestDaemon` for isolated daemon instances.
//!
//! # Test Isolation
//!
//! Each test uses `tempfile` for isolation, ensuring tests don't interfere
//! with each other.
//!
//! # Contract References
//!
//! - TCK-00175: E2E lifecycle and budget tests
//! - TCK-00176: E2E tool and telemetry tests
//! - REQ-EPISODE-001: Episode envelope requirements
//! - REQ-DAEMON-001: Daemon requirements
//! - REQ-TOOL-001: Tool mediation requirements
//! - REQ-TEL-001: Telemetry requirements

pub mod daemon;
pub mod mock_harness;

// Re-export commonly used types for convenience.
// Not all test files use all re-exports, which is expected.
#[allow(unused_imports)]
pub use daemon::TestDaemon;
#[allow(unused_imports)]
pub use mock_harness::MockHarness;
#[allow(unused_imports)]
pub use mock_harness::MockHarnessConfig;
#[allow(unused_imports)]
pub use mock_harness::MockResourceStats;
#[allow(unused_imports)]
pub use mock_harness::MockToolCall;
#[allow(unused_imports)]
pub use mock_harness::ScheduledEvent;
