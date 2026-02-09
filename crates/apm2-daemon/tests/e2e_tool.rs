//! E2E tool mediation tests for TCK-00176.
//!
//! This module tests the full tool mediation flow including:
//! - Allow decision flow
//! - Deny decision (unauthorized)
//! - Dedupe cache hit
//! - Budget charging
//!
//! # Test Approach
//!
//! These tests use the `MockHarness` to simulate agent behavior and verify
//! that the tool broker correctly mediates tool requests based on capabilities,
//! policies, and budget constraints.
//!
//! # Contract References
//!
//! - TCK-00176: E2E tool and telemetry tests
//! - CTR-DAEMON-004: `ToolBroker` structure
//! - REQ-TOOL-001: Tool mediation requirements

mod common;

use std::time::Duration;

use apm2_core::tool::ShellBridgePolicy;
use apm2_daemon::episode::{
    BrokerToolRequest, BudgetDelta, BudgetTracker, Capability, CapabilityManifest, CapabilityScope,
    DedupeKey, EpisodeBudget, EpisodeId, RiskTier, ToolBroker, ToolBrokerConfig, ToolClass,
    ToolDecision, ToolResult,
};

// Type alias for the broker with default StubManifestLoader
type TestToolBroker = ToolBroker<apm2_daemon::episode::capability::StubManifestLoader>;
use common::{MockHarness, MockHarnessConfig, MockToolCall, ScheduledEvent};

// =============================================================================
// Test Helpers
// =============================================================================

/// Creates a test episode ID.
fn test_episode_id(suffix: &str) -> EpisodeId {
    EpisodeId::new(format!("e2e-tool-{suffix}")).expect("valid episode ID")
}

/// Creates a test args hash.
fn test_args_hash() -> [u8; 32] {
    *blake3::hash(b"test-args").as_bytes()
}

/// Creates a capability manifest with the specified capabilities.
///
/// Per TCK-00254, the `tool_allowlist` is automatically populated from the
/// capabilities' tool classes, and `write_allowlist` is populated for
/// Write capabilities.
fn create_manifest_with_capabilities(caps: Vec<Capability>) -> CapabilityManifest {
    use std::path::PathBuf;

    // Collect unique tool classes from capabilities for the allowlist
    let tool_classes: Vec<ToolClass> = caps.iter().map(|c| c.tool_class).collect();

    // Collect write paths from Write capabilities for the write_allowlist
    let write_paths: Vec<PathBuf> = caps
        .iter()
        .filter(|c| c.tool_class == ToolClass::Write)
        .flat_map(|c| c.scope.root_paths.clone())
        .collect();

    // If Execute is present, add a default shell_allowlist pattern
    // (for testing purposes - allows all commands)
    let shell_patterns: Vec<String> = if tool_classes.contains(&ToolClass::Execute) {
        vec!["*".to_string()] // Allow all shell commands for testing
    } else {
        Vec::new()
    };

    CapabilityManifest::builder("test-manifest")
        .delegator("test-actor")
        .capabilities(caps)
        .tool_allowlist(tool_classes)
        .write_allowlist(write_paths)
        .shell_allowlist(shell_patterns)
        .build()
        .expect("valid manifest")
}

/// Creates a Read capability for a path.
fn read_capability(path: &str) -> Capability {
    Capability::builder("cap-read", ToolClass::Read)
        .scope(
            CapabilityScope::builder()
                .root_path(path)
                .build()
                .expect("valid scope"),
        )
        .build()
        .expect("valid capability")
}

/// Creates a Write capability for a path.
fn write_capability(path: &str) -> Capability {
    Capability::builder("cap-write", ToolClass::Write)
        .scope(
            CapabilityScope::builder()
                .root_path(path)
                .build()
                .expect("valid scope"),
        )
        .build()
        .expect("valid capability")
}

/// Creates an Execute capability.
fn execute_capability() -> Capability {
    Capability::builder("cap-execute", ToolClass::Execute)
        .build()
        .expect("valid capability")
}

/// Creates a broker tool request.
fn create_request(
    request_id: &str,
    episode_id: EpisodeId,
    tool_class: ToolClass,
    dedupe_key: &str,
    risk_tier: RiskTier,
) -> BrokerToolRequest {
    BrokerToolRequest::new(
        request_id,
        episode_id,
        tool_class,
        DedupeKey::new(dedupe_key),
        test_args_hash(),
        risk_tier,
    )
}

/// Current timestamp in nanoseconds for testing.
const fn current_timestamp_ns() -> u64 {
    1_704_067_200_000_000_000 // 2024-01-01 00:00:00 UTC
}

// =============================================================================
// IT-00176-01: Allow Decision Flow
// =============================================================================

/// Tests that tool requests with matching capabilities are allowed.
#[tokio::test]
async fn test_allow_decision_with_matching_capability() {
    let episode_id = test_episode_id("allow-001");

    // Create manifest with Read capability for /workspace
    let manifest = create_manifest_with_capabilities(vec![read_capability("/workspace")]);

    // Create broker and initialize with manifest
    // NOTE: Use without_policy_check() because this test focuses on capability
    // validation, not policy engine integration (TCK-00292 default-deny behavior)
    let broker: TestToolBroker =
        ToolBroker::new(ToolBrokerConfig::default().without_policy_check());
    broker
        .initialize_with_manifest(manifest)
        .await
        .expect("initialize should succeed");

    // Create request for a file in /workspace
    let request = create_request(
        "req-001",
        episode_id.clone(),
        ToolClass::Read,
        "key-001",
        RiskTier::Tier0,
    )
    .with_path("/workspace/test.txt");

    // Process through broker
    let decision = broker.request(&request, current_timestamp_ns(), None).await;
    assert!(decision.is_ok(), "request should not error");

    let decision = decision.unwrap();

    // Should be allowed
    assert!(
        decision.is_allowed(),
        "request should be allowed with matching capability"
    );

    if let ToolDecision::Allow {
        request_id,
        capability_id,
        ..
    } = decision
    {
        assert_eq!(request_id, "req-001");
        assert_eq!(capability_id, "cap-read");
    }
}

/// Tests that multiple tool classes can be allowed with appropriate
/// capabilities.
#[tokio::test]
async fn test_allow_multiple_tool_classes() {
    let episode_id = test_episode_id("allow-002");

    // Create manifest with Read, Write, and Execute capabilities
    let manifest = create_manifest_with_capabilities(vec![
        read_capability("/workspace"),
        write_capability("/workspace"),
        execute_capability(),
    ]);
    // NOTE: Use without_policy_check() because this test focuses on capability
    // validation, not policy engine integration (TCK-00292 default-deny behavior).
    // Configure a ShellBridgePolicy that allows "ls" so the Execute request passes
    // the shell bridge allowlist check (the default is deny_all per TCK-00377).
    let shell_policy =
        ShellBridgePolicy::new(vec!["ls".to_string()], false).expect("valid shell policy");
    let broker: TestToolBroker = ToolBroker::new(
        ToolBrokerConfig::default()
            .without_policy_check()
            .with_shell_bridge_policy(shell_policy),
    );
    broker
        .initialize_with_manifest(manifest)
        .await
        .expect("initialize should succeed");

    // Test Read
    let read_request = create_request(
        "req-read",
        episode_id.clone(),
        ToolClass::Read,
        "key-read",
        RiskTier::Tier0,
    )
    .with_path("/workspace/file.txt");
    let decision = broker
        .request(&read_request, current_timestamp_ns(), None)
        .await
        .unwrap();
    assert!(decision.is_allowed(), "Read should be allowed");

    // Test Write
    let write_request = create_request(
        "req-write",
        episode_id.clone(),
        ToolClass::Write,
        "key-write",
        RiskTier::Tier0,
    )
    .with_path("/workspace/output.txt");
    let decision = broker
        .request(&write_request, current_timestamp_ns(), None)
        .await
        .unwrap();
    assert!(decision.is_allowed(), "Write should be allowed");

    // Test Execute
    let exec_request = create_request(
        "req-exec",
        episode_id.clone(),
        ToolClass::Execute,
        "key-exec",
        RiskTier::Tier0,
    )
    .with_shell_command("ls"); // Shell command required for Execute requests
    let decision = broker
        .request(&exec_request, current_timestamp_ns(), None)
        .await
        .unwrap();
    assert!(decision.is_allowed(), "Execute should be allowed");
}

// =============================================================================
// IT-00176-02: Deny Decision (Unauthorized)
// =============================================================================

/// Tests that tool requests without matching capabilities are denied.
#[tokio::test]
async fn test_deny_no_matching_capability() {
    let episode_id = test_episode_id("deny-001");

    // Create manifest with only Read capability
    let manifest = create_manifest_with_capabilities(vec![read_capability("/workspace")]);
    let broker: TestToolBroker = ToolBroker::new(ToolBrokerConfig::default());
    broker
        .initialize_with_manifest(manifest)
        .await
        .expect("initialize should succeed");

    // Request Write (not in capabilities)
    let request = create_request(
        "req-001",
        episode_id.clone(),
        ToolClass::Write,
        "key-001",
        RiskTier::Tier0,
    )
    .with_path("/workspace/file.txt");

    let decision = broker
        .request(&request, current_timestamp_ns(), None)
        .await
        .unwrap();

    assert!(
        decision.is_denied(),
        "request should be denied without matching capability"
    );
}

/// Tests that path restrictions are enforced.
#[tokio::test]
async fn test_deny_path_not_in_scope() {
    let episode_id = test_episode_id("deny-002");

    // Create manifest with Read capability only for /workspace
    let manifest = create_manifest_with_capabilities(vec![read_capability("/workspace")]);
    let broker: TestToolBroker = ToolBroker::new(ToolBrokerConfig::default());
    broker
        .initialize_with_manifest(manifest)
        .await
        .expect("initialize should succeed");

    // Request access to /etc (not in scope)
    let request = create_request(
        "req-001",
        episode_id.clone(),
        ToolClass::Read,
        "key-001",
        RiskTier::Tier0,
    )
    .with_path("/etc/passwd");

    let decision = broker
        .request(&request, current_timestamp_ns(), None)
        .await
        .unwrap();

    assert!(
        decision.is_denied(),
        "request should be denied for path outside scope"
    );
}

/// Tests that requests with no capabilities are denied.
#[tokio::test]
async fn test_deny_empty_manifest() {
    let episode_id = test_episode_id("deny-003");

    // Create empty manifest
    let manifest = create_manifest_with_capabilities(vec![]);
    let broker: TestToolBroker = ToolBroker::new(ToolBrokerConfig::default());
    broker
        .initialize_with_manifest(manifest)
        .await
        .expect("initialize should succeed");

    // Any request should be denied
    let request = create_request(
        "req-001",
        episode_id.clone(),
        ToolClass::Read,
        "key-001",
        RiskTier::Tier0,
    );

    let decision = broker
        .request(&request, current_timestamp_ns(), None)
        .await
        .unwrap();

    assert!(
        decision.is_denied(),
        "request should be denied with empty manifest"
    );
}

// =============================================================================
// IT-00176-03: Dedupe Cache Hit
// =============================================================================

/// Tests that dedupe cache returns cached results for identical requests.
#[tokio::test]
async fn test_dedupe_cache_hit() {
    let episode_id = test_episode_id("dedupe-001");

    // Create manifest with Read capability
    let manifest = create_manifest_with_capabilities(vec![read_capability("/workspace")]);
    // NOTE: Use without_policy_check() because this test focuses on dedupe cache
    // behavior, not policy engine integration (TCK-00292 default-deny behavior)
    let broker: TestToolBroker =
        ToolBroker::new(ToolBrokerConfig::default().without_policy_check());
    broker
        .initialize_with_manifest(manifest)
        .await
        .expect("initialize should succeed");

    let timestamp = current_timestamp_ns();

    // First request
    let request = create_request(
        "req-001",
        episode_id.clone(),
        ToolClass::Read,
        "key-001",
        RiskTier::Tier0,
    )
    .with_path("/workspace/file.txt");

    // Process first request - should be allowed
    let decision1 = broker.request(&request, timestamp, None).await.unwrap();
    assert!(decision1.is_allowed());

    // Simulate tool execution and store result in cache
    let result = ToolResult::success(
        "req-001",
        b"file contents".to_vec(),
        BudgetDelta::single_call(),
        Duration::from_millis(10),
        timestamp,
    );

    // Store in cache (simulate what happens after tool execution)
    broker
        .record_result(
            episode_id.clone(),
            &decision1,
            request.dedupe_key.clone(),
            result.clone(),
            timestamp,
        )
        .await
        .expect("record_result should succeed");

    // Second request with same dedupe key
    let request2 = create_request(
        "req-002",
        episode_id.clone(),
        ToolClass::Read,
        "key-001",
        RiskTier::Tier0,
    )
    .with_path("/workspace/file.txt");

    let decision2 = broker
        .request(&request2, timestamp + 1000, None)
        .await
        .unwrap();

    // Should be a cache hit
    assert!(
        decision2.is_cache_hit(),
        "second request should be a dedupe cache hit"
    );

    if let ToolDecision::DedupeCacheHit { request_id, result } = decision2 {
        assert_eq!(request_id, "req-002");
        assert_eq!(result.output, b"file contents");
    }
}

/// Tests that different dedupe keys don't hit cache.
#[tokio::test]
async fn test_dedupe_cache_miss_different_key() {
    let episode_id = test_episode_id("dedupe-002");

    // Create manifest with Read capability
    let manifest = create_manifest_with_capabilities(vec![read_capability("/workspace")]);
    // NOTE: Use without_policy_check() because this test focuses on dedupe cache
    // behavior, not policy engine integration (TCK-00292 default-deny behavior)
    let broker: TestToolBroker =
        ToolBroker::new(ToolBrokerConfig::default().without_policy_check());
    broker
        .initialize_with_manifest(manifest)
        .await
        .expect("initialize should succeed");

    let timestamp = current_timestamp_ns();

    // First request
    let request1 = create_request(
        "req-001",
        episode_id.clone(),
        ToolClass::Read,
        "key-001",
        RiskTier::Tier0,
    )
    .with_path("/workspace/file1.txt");

    let decision1 = broker.request(&request1, timestamp, None).await.unwrap();
    assert!(decision1.is_allowed());

    // Store result
    let result = ToolResult::success(
        "req-001",
        b"file1 contents".to_vec(),
        BudgetDelta::single_call(),
        Duration::from_millis(10),
        timestamp,
    );
    broker
        .record_result(
            episode_id.clone(),
            &decision1,
            request1.dedupe_key.clone(),
            result,
            timestamp,
        )
        .await
        .expect("record_result should succeed");

    // Second request with different dedupe key
    let request2 = create_request(
        "req-002",
        episode_id.clone(),
        ToolClass::Read,
        "key-002",
        RiskTier::Tier0,
    )
    .with_path("/workspace/file2.txt");

    let decision2 = broker
        .request(&request2, timestamp + 1000, None)
        .await
        .unwrap();

    // Should NOT be a cache hit
    assert!(
        decision2.is_allowed(),
        "different dedupe key should not hit cache"
    );
}

/// Tests that dedupe cache enforces episode isolation.
#[tokio::test]
async fn test_dedupe_cache_episode_isolation() {
    let episode_id1 = test_episode_id("dedupe-iso-001");
    let episode_id2 = test_episode_id("dedupe-iso-002");

    // Create manifest with Read capability
    let manifest = create_manifest_with_capabilities(vec![read_capability("/workspace")]);
    // NOTE: Use without_policy_check() because this test focuses on dedupe cache
    // episode isolation, not policy engine integration (TCK-00292 default-deny
    // behavior)
    let broker: TestToolBroker =
        ToolBroker::new(ToolBrokerConfig::default().without_policy_check());
    broker
        .initialize_with_manifest(manifest)
        .await
        .expect("initialize should succeed");

    let timestamp = current_timestamp_ns();

    // First request in episode 1
    let request1 = create_request(
        "req-001",
        episode_id1.clone(),
        ToolClass::Read,
        "shared-key",
        RiskTier::Tier0,
    )
    .with_path("/workspace/file.txt");

    let decision1 = broker.request(&request1, timestamp, None).await.unwrap();
    assert!(decision1.is_allowed());

    // Store result for episode 1
    let result = ToolResult::success(
        "req-001",
        b"episode1 result".to_vec(),
        BudgetDelta::single_call(),
        Duration::from_millis(10),
        timestamp,
    );
    broker
        .record_result(
            episode_id1.clone(),
            &decision1,
            request1.dedupe_key.clone(),
            result,
            timestamp,
        )
        .await
        .expect("record_result should succeed");

    // Second request in episode 2 with SAME dedupe key
    let request2 = create_request(
        "req-002",
        episode_id2.clone(),
        ToolClass::Read,
        "shared-key",
        RiskTier::Tier0,
    )
    .with_path("/workspace/file.txt");

    let decision2 = broker
        .request(&request2, timestamp + 1000, None)
        .await
        .unwrap();

    // Should NOT be a cache hit (different episode)
    assert!(
        decision2.is_allowed(),
        "dedupe cache should isolate episodes"
    );
}

// =============================================================================
// IT-00176-04: Budget Charging
// =============================================================================

/// Tests that budget is charged for allowed tool requests.
#[test]
fn test_budget_charging_on_allow() {
    // Create budget with limits
    let budget = EpisodeBudget::builder()
        .tool_calls(10)
        .tokens(1000)
        .cpu_ms(10_000)
        .bytes_io(1_000_000)
        .build();

    let tracker = BudgetTracker::from_envelope(budget);

    // Charge for a tool call
    let delta = BudgetDelta::single_call()
        .with_tokens(50)
        .with_bytes_io(1024);

    assert!(tracker.charge(&delta).is_ok());

    let remaining = tracker.remaining();
    assert_eq!(remaining.tool_calls(), 9);
    assert_eq!(remaining.tokens(), 950);
    assert_eq!(remaining.bytes_io(), 998_976);
}

/// Tests that budget exhaustion prevents further tool calls.
#[test]
fn test_budget_exhaustion() {
    // Create minimal budget
    let budget = EpisodeBudget::builder().tool_calls(2).build();

    let tracker = BudgetTracker::from_envelope(budget);

    // First call succeeds
    let delta1 = BudgetDelta::single_call();
    assert!(tracker.charge(&delta1).is_ok());

    // Second call succeeds
    let delta2 = BudgetDelta::single_call();
    assert!(tracker.charge(&delta2).is_ok());

    // Third call should fail - budget exhausted
    let delta3 = BudgetDelta::single_call();
    assert!(tracker.charge(&delta3).is_err());
}

/// Tests that budget tracking correctly accumulates consumption.
#[test]
fn test_budget_accumulation() {
    let budget = EpisodeBudget::builder()
        .tokens(1000)
        .cpu_ms(10_000)
        .bytes_io(100_000)
        .build();

    let tracker = BudgetTracker::from_envelope(budget);

    // Multiple charges
    tracker
        .charge(&BudgetDelta::single_call().with_tokens(100))
        .unwrap();
    tracker
        .charge(&BudgetDelta::single_call().with_tokens(200))
        .unwrap();
    tracker
        .charge(
            &BudgetDelta::single_call().with_wall_ms(5000), /* Use wall_ms since cpu_ms isn't
                                                             * available */
        )
        .unwrap();
    tracker
        .charge(&BudgetDelta::single_call().with_bytes_io(50_000))
        .unwrap();

    let consumed = tracker.consumed();
    assert_eq!(consumed.tokens, 300);
    assert_eq!(consumed.bytes_io, 50_000);
    assert_eq!(consumed.tool_calls, 4);
}

// =============================================================================
// IT-00176-05: Mock Harness Integration
// =============================================================================

/// Tests full tool mediation flow with mock harness.
#[test]
fn test_mock_harness_tool_flow() {
    let episode_id = test_episode_id("mock-flow-001");

    // Configure mock harness with tool calls
    let config = MockHarnessConfig::new(episode_id)
        .with_event(ScheduledEvent::tool_call(
            MockToolCall::success("req-001", ToolClass::Read, "key-001", b"file contents"),
            Duration::from_millis(10),
        ))
        .with_event(ScheduledEvent::tool_call(
            MockToolCall::success("req-002", ToolClass::Write, "key-002", b"written"),
            Duration::from_millis(20),
        ))
        .with_event(ScheduledEvent::complete(0, Duration::from_millis(100)));

    let harness = MockHarness::new(config);

    // Start harness
    harness.start().expect("harness should start");
    assert!(harness.is_running());

    // Process events
    let mut tool_calls = Vec::new();
    while let Some(event) = harness.take_next_event() {
        match event {
            ScheduledEvent::ToolCall { call, delay } => {
                harness.advance_time(delay);
                tool_calls.push(call.clone());
                harness.record_tool_call(call);
            },
            ScheduledEvent::Complete { exit_code, delay } => {
                harness.advance_time(delay);
                harness.complete(exit_code);
            },
            ScheduledEvent::Output { delay, .. } => {
                harness.advance_time(delay);
            },
        }
    }

    // Verify
    assert!(harness.is_completed());
    assert_eq!(harness.exit_code(), Some(0));
    assert_eq!(tool_calls.len(), 2);
    assert_eq!(tool_calls[0].request_id, "req-001");
    assert_eq!(tool_calls[1].request_id, "req-002");
}

/// Tests tool mediation with broker and mock harness.
#[tokio::test]
async fn test_broker_with_mock_harness() {
    let episode_id = test_episode_id("broker-mock-001");

    // Create broker with capabilities
    let manifest = create_manifest_with_capabilities(vec![
        read_capability("/workspace"),
        write_capability("/workspace"),
    ]);
    // NOTE: Use without_policy_check() because this test focuses on broker/harness
    // integration, not policy engine integration (TCK-00292 default-deny behavior)
    let broker: TestToolBroker =
        ToolBroker::new(ToolBrokerConfig::default().without_policy_check());
    broker
        .initialize_with_manifest(manifest)
        .await
        .expect("initialize should succeed");

    // Configure mock harness
    let config = MockHarnessConfig::new(episode_id.clone()).with_event(ScheduledEvent::tool_call(
        MockToolCall::success("req-001", ToolClass::Read, "key-001", b"file data")
            .with_path("/workspace/test.txt"),
        Duration::from_millis(10),
    ));

    let harness = MockHarness::new(config);
    harness.start().unwrap();

    // Process tool call through broker
    if let Some(ScheduledEvent::ToolCall { call, .. }) = harness.take_next_event() {
        // Create broker request
        let request = BrokerToolRequest::new(
            &call.request_id,
            episode_id.clone(),
            call.tool_class,
            call.dedupe_key.clone(),
            test_args_hash(),
            RiskTier::Tier0,
        )
        .with_path(call.path.clone().unwrap_or_default());

        // Process through broker
        let decision = broker
            .request(&request, current_timestamp_ns(), None)
            .await
            .unwrap();

        // Should be allowed
        assert!(decision.is_allowed(), "tool call should be allowed");

        // Record in harness
        harness.record_tool_call(call);
    }

    assert_eq!(harness.processed_tool_calls().len(), 1);
}

/// Tests denied tool call with mock harness.
#[tokio::test]
async fn test_denied_tool_with_mock_harness() {
    let episode_id = test_episode_id("denied-mock-001");

    // Create broker with only Read capability
    let manifest = create_manifest_with_capabilities(vec![read_capability("/workspace")]);
    let broker: TestToolBroker = ToolBroker::new(ToolBrokerConfig::default());
    broker
        .initialize_with_manifest(manifest)
        .await
        .expect("initialize should succeed");

    // Configure mock harness with Write tool call (should be denied)
    let config = MockHarnessConfig::new(episode_id.clone()).with_event(ScheduledEvent::tool_call(
        MockToolCall::success("req-001", ToolClass::Write, "key-001", b"data")
            .with_path("/workspace/test.txt"),
        Duration::from_millis(10),
    ));

    let harness = MockHarness::new(config);
    harness.start().unwrap();

    // Process tool call through broker
    let mut denied_count = 0;
    if let Some(ScheduledEvent::ToolCall { call, .. }) = harness.take_next_event() {
        let request = BrokerToolRequest::new(
            &call.request_id,
            episode_id.clone(),
            call.tool_class,
            call.dedupe_key.clone(),
            test_args_hash(),
            RiskTier::Tier0,
        )
        .with_path(call.path.clone().unwrap_or_default());

        let decision = broker
            .request(&request, current_timestamp_ns(), None)
            .await
            .unwrap();

        // Should be denied
        if decision.is_denied() {
            denied_count += 1;
        }
    }

    assert_eq!(denied_count, 1, "Write tool call should be denied");
}

// =============================================================================
// IT-00176-06: Request Validation
// =============================================================================

/// Tests that request validation catches empty request IDs.
#[test]
fn test_request_validation_empty_id() {
    let request = BrokerToolRequest::new(
        "",
        test_episode_id("validate-001"),
        ToolClass::Read,
        DedupeKey::new("key"),
        test_args_hash(),
        RiskTier::Tier0,
    );

    let result = request.validate();
    assert!(result.is_err(), "empty request ID should fail validation");
}

/// Tests that request validation enforces path length limits.
#[test]
fn test_request_validation_path_too_long() {
    let long_path = "/".to_owned() + &"x".repeat(5000);
    let request = BrokerToolRequest::new(
        "req-001",
        test_episode_id("validate-002"),
        ToolClass::Read,
        DedupeKey::new("key"),
        test_args_hash(),
        RiskTier::Tier0,
    )
    .with_path(long_path);

    let result = request.validate();
    assert!(
        result.is_err(),
        "excessively long path should fail validation"
    );
}

/// Tests that valid requests pass validation.
#[test]
fn test_request_validation_valid() {
    let request = BrokerToolRequest::new(
        "req-001",
        test_episode_id("validate-003"),
        ToolClass::Read,
        DedupeKey::new("key"),
        test_args_hash(),
        RiskTier::Tier0,
    )
    .with_path("/workspace/file.txt")
    .with_inline_args(b"small args".to_vec());

    let result = request.validate();
    assert!(result.is_ok(), "valid request should pass validation");
}
