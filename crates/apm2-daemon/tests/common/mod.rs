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
//! - REQ-EPISODE-001: Episode envelope requirements
//! - REQ-DAEMON-001: Daemon requirements

pub mod daemon;

pub use daemon::TestDaemon;
