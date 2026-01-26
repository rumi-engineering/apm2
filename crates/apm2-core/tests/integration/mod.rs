//! Integration tests for the agent handoff flow.
//!
//! This module contains end-to-end tests verifying the complete handoff flow
//! from webhook reception to agent claiming, including:
//!
//! - Full handoff flow (webhook -> event -> transition -> claim)
//! - Webhook signature validation
//! - Idempotency of webhook handling
//! - Anti-gaming controls (agent cannot set CI status)
//! - Error cases (malformed payload, missing headers)
//! - Feature flag behavior
//! - Phase transition state machine edge cases
//!
//! # Test Evidence
//!
//! These tests provide evidence for:
//! - EVID-8005: Anti-gaming controls verified

pub mod handoff;
