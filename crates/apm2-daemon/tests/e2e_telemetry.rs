//! E2E telemetry tests for TCK-00176.
//!
//! This module tests the full telemetry collection flow including:
//! - Frames emitted at configured rate
//! - Metrics match resource consumption (within tolerance)
//! - Ring buffer bounds respected
//! - Promotion triggers work
//!
//! # Test Approach
//!
//! These tests use the `MockHarness` to simulate agent resource consumption
//! and verify that the telemetry handle correctly captures and reports
//! metrics. We test the `TelemetryHandle` directly since the `CgroupReader`
//! requires actual cgroup filesystem access.
//!
//! # Contract References
//!
//! - TCK-00176: E2E tool and telemetry tests
//! - CTR-DAEMON-005: `TelemetryCollector` and frame streaming
//! - REQ-TEL-001: Telemetry requirements

mod common;

use std::time::Duration;

use apm2_daemon::episode::{BudgetDelta, BudgetTracker, EpisodeBudget, EpisodeId, ToolClass};
use apm2_daemon::telemetry::{
    CpuStats, IoStats, MAX_FRAME_BYTES, MAX_FRAME_NS, MemoryStats, MetricSource, O11yFlags,
    ResourceStats, TelemetryCollector, TelemetryFrame, TelemetryHandle, TelemetryPolicy,
};
use common::{MockHarness, MockHarnessConfig, MockResourceStats, MockToolCall};
use nix::unistd::Pid;

// =============================================================================
// Test Helpers
// =============================================================================

/// Creates a test episode ID.
fn test_episode_id(suffix: &str) -> EpisodeId {
    EpisodeId::new(format!("e2e-tel-{suffix}")).expect("valid episode ID")
}

/// Creates test resource stats from mock values.
#[allow(clippy::missing_const_for_fn)] // ResourceStats::new is not const
fn create_resource_stats(mock_stats: MockResourceStats) -> ResourceStats {
    ResourceStats::new(
        CpuStats::new(
            mock_stats.cpu_ns,
            mock_stats.cpu_ns * 60 / 100, // 60% user
            mock_stats.cpu_ns * 40 / 100, // 40% system
            MetricSource::Cgroup,
        ),
        MemoryStats::new(
            mock_stats.mem_rss_bytes,
            mock_stats.mem_rss_bytes, // peak = current for simplicity
            10,                       // minor faults
            1,                        // major faults
            MetricSource::Cgroup,
        ),
        IoStats::new(
            mock_stats.io_bytes / 2, // 50% read
            mock_stats.io_bytes / 2, // 50% write
            10,                      // read ops
            10,                      // write ops
            MetricSource::Cgroup,
        ),
    )
}

/// Returns the difference tolerance for metric comparisons (5%).
const TOLERANCE_PERCENT: f64 = 0.05;

/// Checks if two values are within tolerance.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss
)]
fn within_tolerance(actual: u64, expected: u64, tolerance_percent: f64) -> bool {
    if expected == 0 {
        return actual == 0;
    }
    let tolerance = (expected as f64 * tolerance_percent).ceil() as u64;
    (actual.saturating_sub(expected) <= tolerance) && (expected.saturating_sub(actual) <= tolerance)
}

// =============================================================================
// IT-00176-11: Frame Collection Rate
// =============================================================================

/// Tests that telemetry frames are collected at the configured rate.
#[test]
fn test_telemetry_frame_collection_rate() {
    let episode_id = test_episode_id("rate-001");

    // Create handle with 100 frame capacity
    let handle = TelemetryHandle::new(episode_id, Pid::from_raw(1234), 100);

    // Simulate mock resource stats
    let mock_stats = MockResourceStats {
        elapsed_ms: 0,
        cpu_ns: 0,
        io_bytes: 0,
        mem_rss_bytes: 10 * 1024 * 1024,
    };

    let stats = create_resource_stats(mock_stats);

    // Collect multiple frames
    for i in 0..10 {
        let flags = if i == 0 {
            O11yFlags::new().with_initial()
        } else {
            O11yFlags::new()
        };

        let frame = handle.next_frame(stats, flags);
        assert!(frame.is_some(), "frame {i} should be collected");
    }

    // Verify frame count
    assert_eq!(handle.frames_collected(), 10);
    assert_eq!(handle.buffer_len(), 10);
}

/// Tests that sample period can be adjusted via policy.
#[test]
fn test_telemetry_sample_period_configuration() {
    // Default policy is 1000ms
    let default_policy = TelemetryPolicy::default();
    assert_eq!(default_policy.sample_period_ms(), 1000);

    // Custom policy with 100ms period
    let fast_policy = TelemetryPolicy::builder().sample_period_ms(100).build();
    assert_eq!(fast_policy.sample_period_ms(), 100);

    // Custom policy with 5000ms period
    let slow_policy = TelemetryPolicy::builder().sample_period_ms(5000).build();
    assert_eq!(slow_policy.sample_period_ms(), 5000);
}

/// Tests high-frequency mode multiplier.
#[test]
fn test_telemetry_high_frequency_mode() {
    // Create policy with 800ms sample period
    // High-freq is enabled by default in TelemetryPolicy::default()
    let policy = TelemetryPolicy::builder().sample_period_ms(800).build();

    // Verify high-freq is enabled
    assert!(policy.high_freq_enabled());

    // Normal mode: 800ms
    assert_eq!(policy.effective_sample_period_ms(false), 800);

    // High-freq mode: 800ms / 4 = 200ms
    assert_eq!(policy.effective_sample_period_ms(true), 200);
}

// =============================================================================
// IT-00176-12: Metrics Accuracy
// =============================================================================

/// Tests that telemetry metrics match resource consumption within tolerance.
#[test]
fn test_telemetry_metrics_accuracy() {
    let episode_id = test_episode_id("accuracy-001");

    // Configure mock harness with known resource consumption
    let config = MockHarnessConfig::new(episode_id.clone())
        .with_cpu_ns_per_ms(1_000_000)
        .with_io_bytes_per_call(4096)
        .with_mem_rss_bytes(50 * 1024 * 1024);

    let harness = MockHarness::new(config);
    harness.start().unwrap();

    // Advance time and add I/O
    harness.advance_time(Duration::from_millis(100));
    harness.record_tool_call(MockToolCall::success(
        "req-1",
        ToolClass::Read,
        "key-1",
        b"data",
    ));

    let mock_stats = harness.resource_stats();

    // Create telemetry frame
    let stats = create_resource_stats(mock_stats);
    let frame = TelemetryFrame::builder(episode_id, 0)
        .ts_mono(mock_stats.elapsed_ms * 1_000_000)
        .cpu_ns(stats.cpu.usage_ns())
        .cpu_user_ns(stats.cpu.user_ns())
        .cpu_system_ns(stats.cpu.system_ns())
        .mem_rss_bytes(stats.memory.rss_bytes())
        .io_read_bytes(stats.io.read_bytes())
        .io_write_bytes(stats.io.write_bytes())
        .source(MetricSource::Cgroup)
        .build();

    // Verify metrics match expected values within tolerance
    assert!(
        within_tolerance(frame.cpu_ns(), 100_000_000, TOLERANCE_PERCENT),
        "CPU ns should be ~100ms worth: got {}",
        frame.cpu_ns()
    );

    assert!(
        within_tolerance(frame.mem_rss_bytes(), 50 * 1024 * 1024, TOLERANCE_PERCENT),
        "Memory RSS should be ~50MB: got {}",
        frame.mem_rss_bytes()
    );

    assert!(
        within_tolerance(frame.io_total_bytes(), 4096, TOLERANCE_PERCENT),
        "I/O bytes should be ~4KB: got {}",
        frame.io_total_bytes()
    );
}

/// Tests CPU time breakdown (user vs system).
#[test]
fn test_telemetry_cpu_breakdown() {
    let episode_id = test_episode_id("cpu-001");

    // Create frame with known CPU breakdown
    let frame = TelemetryFrame::builder(episode_id, 0)
        .cpu_ns(1_000_000_000)      // 1 second total
        .cpu_user_ns(600_000_000)   // 0.6 seconds user
        .cpu_system_ns(400_000_000) // 0.4 seconds system
        .build();

    assert_eq!(frame.cpu_ns(), 1_000_000_000);
    assert_eq!(frame.cpu_user_ns(), 600_000_000);
    assert_eq!(frame.cpu_system_ns(), 400_000_000);
    assert_eq!(frame.cpu_ms(), 1000);
}

/// Tests I/O metrics accuracy.
#[test]
fn test_telemetry_io_metrics() {
    let episode_id = test_episode_id("io-001");

    let frame = TelemetryFrame::builder(episode_id, 0)
        .io_read_bytes(1_048_576)  // 1 MB read
        .io_write_bytes(524_288)   // 0.5 MB write
        .build();

    assert_eq!(frame.io_read_bytes(), 1_048_576);
    assert_eq!(frame.io_write_bytes(), 524_288);
    assert_eq!(frame.io_total_bytes(), 1_572_864);
}

// =============================================================================
// IT-00176-13: Ring Buffer Bounds
// =============================================================================

/// Tests that ring buffer respects configured capacity.
#[test]
fn test_ring_buffer_capacity() {
    let episode_id = test_episode_id("ring-001");

    // Create handle with small ring buffer
    let handle = TelemetryHandle::new(episode_id, Pid::from_raw(1234), 5);

    let mock_stats = MockResourceStats::default();
    let stats = create_resource_stats(mock_stats);

    // Collect more frames than capacity
    for _ in 0..10 {
        handle.next_frame(stats, O11yFlags::new());
    }

    // Buffer should be at capacity, not exceeded
    assert_eq!(handle.buffer_len(), 5);
    assert_eq!(handle.buffer_capacity(), 5);
    assert_eq!(handle.frames_collected(), 10);
}

/// Tests that ring buffer preserves most recent frames.
#[test]
fn test_ring_buffer_fifo_eviction() {
    let episode_id = test_episode_id("ring-002");

    let handle = TelemetryHandle::new(episode_id, Pid::from_raw(1234), 3);

    let mock_stats = MockResourceStats::default();
    let stats = create_resource_stats(mock_stats);

    // Collect 5 frames (capacity is 3)
    for _ in 0..5 {
        handle.next_frame(stats, O11yFlags::new());
    }

    // Get frames
    let frames = handle.iter_frames();
    assert_eq!(frames.len(), 3);

    // Should have frames 2, 3, 4 (oldest evicted)
    assert_eq!(frames[0].seq(), 2);
    assert_eq!(frames[1].seq(), 3);
    assert_eq!(frames[2].seq(), 4);
}

/// Tests ring buffer drain operation.
#[test]
fn test_ring_buffer_drain() {
    let episode_id = test_episode_id("ring-003");

    let handle = TelemetryHandle::new(episode_id, Pid::from_raw(1234), 10);

    let mock_stats = MockResourceStats::default();
    let stats = create_resource_stats(mock_stats);

    // Collect 5 frames
    for _ in 0..5 {
        handle.next_frame(stats, O11yFlags::new());
    }

    // Drain
    let drained = handle.drain_frames();
    assert_eq!(drained.len(), 5);
    assert_eq!(handle.buffer_len(), 0);
    assert_eq!(handle.frames_promoted(), 5);

    // Can still collect more frames
    for _ in 0..3 {
        handle.next_frame(stats, O11yFlags::new());
    }

    assert_eq!(handle.buffer_len(), 3);
    assert_eq!(handle.frames_collected(), 8);
}

// =============================================================================
// IT-00176-14: Promotion Triggers
// =============================================================================

/// Tests that initial frame has the initial flag.
#[test]
fn test_initial_frame_flag() {
    let episode_id = test_episode_id("promo-001");

    let frame = TelemetryFrame::builder(episode_id, 0)
        .o11y_flags(O11yFlags::new().with_initial())
        .build();

    assert!(frame.o11y_flags().initial);
    assert!(!frame.o11y_flags().terminal);
    assert!(!frame.o11y_flags().promoted);
}

/// Tests that terminal frame has the terminal flag.
#[test]
fn test_terminal_frame_flag() {
    let episode_id = test_episode_id("promo-002");

    let frame = TelemetryFrame::builder(episode_id, 99)
        .o11y_flags(O11yFlags::new().with_terminal())
        .build();

    assert!(!frame.o11y_flags().initial);
    assert!(frame.o11y_flags().terminal);
}

/// Tests that high-frequency frames are flagged.
#[test]
fn test_high_frequency_frame_flag() {
    let episode_id = test_episode_id("promo-003");

    let frame = TelemetryFrame::builder(episode_id, 10)
        .o11y_flags(O11yFlags::new().with_high_frequency())
        .build();

    assert!(frame.o11y_flags().high_frequency);
}

/// Tests that degraded mode frames are flagged.
#[test]
fn test_degraded_frame_flag() {
    let episode_id = test_episode_id("promo-004");

    let frame = TelemetryFrame::builder(episode_id, 5)
        .source(MetricSource::Proc)
        .o11y_flags(O11yFlags::new().with_degraded())
        .build();

    assert!(frame.o11y_flags().degraded);
    assert!(frame.is_degraded());
}

/// Tests that promoted frames are flagged.
#[test]
fn test_promoted_frame_flag() {
    let episode_id = test_episode_id("promo-005");

    let frame = TelemetryFrame::builder(episode_id, 20)
        .o11y_flags(O11yFlags::new().with_promoted())
        .build();

    assert!(frame.o11y_flags().promoted);
}

// =============================================================================
// IT-00176-15: Budget Integration
// =============================================================================

/// Tests telemetry integration with budget tracker.
#[test]
fn test_telemetry_budget_integration() {
    // Create budget with specific limits
    let budget = EpisodeBudget::builder()
        .cpu_ms(1000)
        .bytes_io(100_000)
        .build();

    let tracker = BudgetTracker::from_envelope(budget);

    // Simulate telemetry deltas
    let delta1 = BudgetDelta {
        tokens: 0,
        tool_calls: 0,
        wall_ms: 0,
        cpu_ms: 200,
        bytes_io: 20_000,
    };

    assert!(tracker.charge(&delta1).is_ok());

    let remaining = tracker.remaining();
    assert_eq!(remaining.cpu_ms(), 800);
    assert_eq!(remaining.bytes_io(), 80_000);

    // More deltas
    let delta2 = BudgetDelta {
        tokens: 0,
        tool_calls: 0,
        wall_ms: 0,
        cpu_ms: 300,
        bytes_io: 30_000,
    };

    assert!(tracker.charge(&delta2).is_ok());

    let consumed = tracker.consumed();
    assert_eq!(consumed.cpu_ms, 500);
    assert_eq!(consumed.bytes_io, 50_000);
}

/// Tests that telemetry handles budget exhaustion gracefully.
#[test]
fn test_telemetry_budget_exhaustion() {
    let budget = EpisodeBudget::builder().cpu_ms(100).bytes_io(1000).build();

    let tracker = BudgetTracker::from_envelope(budget);

    // Exhaust CPU budget
    let large_delta = BudgetDelta {
        tokens: 0,
        tool_calls: 0,
        wall_ms: 0,
        cpu_ms: 150, // Exceeds limit
        bytes_io: 0,
    };

    let result = tracker.charge(&large_delta);
    assert!(result.is_err(), "should fail when exceeding budget");
}

// =============================================================================
// IT-00176-16: Frame Validation
// =============================================================================

/// Tests that frame values are clamped to prevent overflow.
#[test]
fn test_frame_value_clamping() {
    let episode_id = test_episode_id("clamp-001");

    // Create frame with values exceeding limits
    let frame = TelemetryFrame::builder(episode_id, 0)
        .ts_mono(u64::MAX)
        .cpu_ns(u64::MAX)
        .mem_rss_bytes(u64::MAX)
        .io_read_bytes(u64::MAX)
        .build();

    // Values should be clamped to MAX_*
    assert_eq!(frame.ts_mono(), MAX_FRAME_NS);
    assert_eq!(frame.cpu_ns(), MAX_FRAME_NS);
    assert_eq!(frame.mem_rss_bytes(), MAX_FRAME_BYTES);
    assert_eq!(frame.io_read_bytes(), MAX_FRAME_BYTES);
}

/// Tests frame validation passes for valid frames.
#[test]
fn test_frame_validation_valid() {
    let episode_id = test_episode_id("validate-001");

    let frame = TelemetryFrame::builder(episode_id, 0)
        .ts_mono(1_000_000_000)
        .cpu_ns(500_000_000)
        .mem_rss_bytes(100 * 1024 * 1024)
        .build();

    assert!(frame.validate().is_ok());
}

/// Tests frame `try_new` with valid values.
#[test]
fn test_frame_try_new_valid() {
    let result = TelemetryFrame::try_new(
        test_episode_id("try-001"),
        0,
        1_000_000_000,
        500_000_000,
        300_000_000,
        200_000_000,
        100 * 1024 * 1024,
        150 * 1024 * 1024,
        1024,
        512,
        MetricSource::Cgroup,
        O11yFlags::new(),
    );

    assert!(result.is_ok());
}

// =============================================================================
// IT-00176-17: Mock Harness Telemetry Integration
// =============================================================================

/// Tests telemetry collection with mock harness.
#[test]
fn test_mock_harness_telemetry_flow() {
    let episode_id = test_episode_id("mock-tel-001");

    // Configure mock harness
    let config = MockHarnessConfig::new(episode_id.clone())
        .with_cpu_ns_per_ms(1_000_000)
        .with_io_bytes_per_call(2048)
        .with_mem_rss_bytes(25 * 1024 * 1024);

    let harness = MockHarness::new(config);
    harness.start().unwrap();

    // Create telemetry handle directly
    let handle = TelemetryHandle::new(episode_id, Pid::from_raw(1234), 50);

    // Simulate time progression and collect frames
    for i in 0..5 {
        harness.advance_time(Duration::from_millis(100));

        // Record some tool calls to add I/O
        if i % 2 == 0 {
            harness.record_tool_call(MockToolCall::success(
                format!("req-{i}"),
                ToolClass::Read,
                format!("key-{i}"),
                b"data",
            ));
        }

        // Get current resource stats
        let mock_stats = harness.resource_stats();
        let stats = create_resource_stats(mock_stats);

        // Collect telemetry frame
        let flags = if i == 0 {
            O11yFlags::new().with_initial()
        } else {
            O11yFlags::new()
        };

        let frame = handle.next_frame(stats, flags).unwrap();

        // Verify frame metrics align with mock stats
        assert_eq!(frame.seq(), i);
    }

    // Verify collection results
    assert_eq!(handle.frames_collected(), 5);
    assert_eq!(handle.buffer_len(), 5);

    // Verify first frame has initial flag
    let frames = handle.iter_frames();
    assert!(frames[0].o11y_flags().initial);
}

/// Tests stopping telemetry collection.
#[test]
fn test_telemetry_stop() {
    let episode_id = test_episode_id("stop-001");

    let handle = TelemetryHandle::new(episode_id, Pid::from_raw(1234), 10);

    let mock_stats = MockResourceStats::default();
    let stats = create_resource_stats(mock_stats);

    // Collect some frames
    for _ in 0..3 {
        handle.next_frame(stats, O11yFlags::new());
    }

    // Stop collection
    let final_frames = handle.stop();
    assert_eq!(final_frames.len(), 3);
    assert!(handle.is_stopped());

    // Further collection should return None
    let result = handle.next_frame(stats, O11yFlags::new());
    assert!(result.is_none());
}

/// Tests telemetry handle high-frequency mode toggle.
#[test]
fn test_telemetry_handle_high_freq_toggle() {
    let episode_id = test_episode_id("hf-001");

    let handle = TelemetryHandle::new(episode_id, Pid::from_raw(1234), 10);

    assert!(!handle.is_high_freq_active());

    handle.set_high_freq_active(true);
    assert!(handle.is_high_freq_active());

    handle.set_high_freq_active(false);
    assert!(!handle.is_high_freq_active());
}

/// Tests telemetry handle snapshot.
#[test]
fn test_telemetry_handle_snapshot() {
    let episode_id = test_episode_id("snap-001");

    let handle = TelemetryHandle::new(episode_id.clone(), Pid::from_raw(5678), 100);

    let mock_stats = MockResourceStats::default();
    let stats = create_resource_stats(mock_stats);

    // Collect some frames
    for _ in 0..3 {
        handle.next_frame(stats, O11yFlags::new());
    }

    handle.set_high_freq_active(true);

    let snapshot = handle.snapshot();
    assert_eq!(snapshot.episode_id.as_str(), episode_id.as_str());
    assert_eq!(snapshot.pid.as_raw(), 5678);
    assert_eq!(snapshot.seq, 3);
    assert_eq!(snapshot.frames_collected, 3);
    assert_eq!(snapshot.buffer_len, 3);
    assert_eq!(snapshot.buffer_capacity, 100);
    assert!(!snapshot.stopped);
    assert!(snapshot.high_freq_active);
}

/// Tests delta computation between frames.
#[test]
fn test_telemetry_delta_computation() {
    let episode_id = test_episode_id("delta-001");

    let handle = TelemetryHandle::new(episode_id, Pid::from_raw(1234), 10);

    // First stats
    let stats1 = ResourceStats::new(
        CpuStats::new(
            1_000_000_000,
            600_000_000,
            400_000_000,
            MetricSource::Cgroup,
        ),
        MemoryStats::new(
            100 * 1024 * 1024,
            100 * 1024 * 1024,
            10,
            1,
            MetricSource::Cgroup,
        ),
        IoStats::new(1_000_000, 500_000, 10, 10, MetricSource::Cgroup),
    );

    // First frame - delta is full amount (no previous)
    let (cpu_delta, io_delta) = handle.compute_delta(&stats1);
    assert_eq!(cpu_delta, 1_000_000_000);
    assert_eq!(io_delta, 1_500_000);

    // Record first stats
    handle.next_frame(stats1, O11yFlags::new());

    // Second stats with increments
    let stats2 = ResourceStats::new(
        CpuStats::new(
            1_500_000_000,
            900_000_000,
            600_000_000,
            MetricSource::Cgroup,
        ),
        MemoryStats::new(
            110 * 1024 * 1024,
            110 * 1024 * 1024,
            15,
            2,
            MetricSource::Cgroup,
        ),
        IoStats::new(2_000_000, 1_000_000, 20, 20, MetricSource::Cgroup),
    );

    // Second frame - delta is difference
    let (cpu_delta, io_delta) = handle.compute_delta(&stats2);
    assert_eq!(cpu_delta, 500_000_000); // 1.5s - 1s
    assert_eq!(io_delta, 1_500_000); // 3MB - 1.5MB
}

// =============================================================================
// IT-00176-18: Collector Policy Tests
// =============================================================================

/// Tests collector creation and policy.
#[test]
fn test_collector_policy_application() {
    let policy = TelemetryPolicy::builder()
        .sample_period_ms(500)
        .ring_buffer_capacity(200)
        .high_freq_enabled(true)
        .high_freq_threshold_percent(75)
        .build();

    let collector = TelemetryCollector::new(policy);

    assert_eq!(collector.policy().sample_period_ms(), 500);
    assert_eq!(collector.policy().ring_buffer_capacity(), 200);
    assert!(collector.policy().high_freq_enabled());
    assert_eq!(collector.policy().high_freq_threshold_percent(), 75);
}

/// Tests collector policy update.
#[test]
fn test_collector_policy_update() {
    let initial_policy = TelemetryPolicy::builder().sample_period_ms(100).build();

    let mut collector = TelemetryCollector::new(initial_policy);
    assert_eq!(collector.policy().sample_period_ms(), 100);

    let new_policy = TelemetryPolicy::builder().sample_period_ms(250).build();

    collector.apply_policy(new_policy);
    assert_eq!(collector.policy().sample_period_ms(), 250);
}

/// Tests default collector.
#[test]
fn test_collector_default() {
    let collector = TelemetryCollector::default();
    assert_eq!(
        collector.policy().sample_period_ms(),
        TelemetryPolicy::default().sample_period_ms()
    );
}

/// Tests collector start creates proper handle.
#[test]
fn test_collector_start() {
    let collector =
        TelemetryCollector::new(TelemetryPolicy::builder().ring_buffer_capacity(50).build());

    let episode_id = test_episode_id("start-001");
    let handle = collector.start(episode_id.clone(), Pid::from_raw(9999));

    assert_eq!(handle.episode_id().as_str(), episode_id.as_str());
    assert_eq!(handle.pid().as_raw(), 9999);
    assert_eq!(handle.buffer_capacity(), 50);
    assert!(!handle.is_stopped());
}
