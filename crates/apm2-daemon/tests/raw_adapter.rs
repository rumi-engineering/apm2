//! Integration tests for `RawAdapter` (IT-00162-01).
//!
//! These tests verify that `RawAdapter` can spawn a process and stream output
//! events using the `PtyRunner` integration.
//!
//! Test command: `cargo test -p apm2-daemon --test raw_adapter`

use apm2_daemon::episode::{
    AdapterType, HarnessAdapter, HarnessConfig, HarnessEvent, RawAdapter, TerminationClassification,
};

/// IT-00162-01: Verify `RawAdapter` can spawn a process and stream output
/// events.
///
/// This test validates the core functionality of `RawAdapter`:
/// 1. Spawns a process via `PtyRunner`
/// 2. Receives output events from the process
/// 3. Receives termination event with correct exit code
#[tokio::test]
async fn it_00162_01_raw_adapter_spawn_and_stream_output() {
    // Create the adapter
    let adapter = RawAdapter::new();
    assert_eq!(adapter.adapter_type(), AdapterType::Raw);

    // Configure a simple echo command
    let config = HarnessConfig::new("echo", "it-00162-01-episode")
        .with_args(vec!["hello world".to_string()]);

    // Spawn the process
    let (handle, mut events) = adapter.spawn(config).await.expect("spawn should succeed");

    assert_eq!(handle.episode_id(), "it-00162-01-episode");

    // Collect all events
    let mut output_chunks = Vec::new();
    let mut termination_event = None;

    while let Some(event) = events.recv().await {
        match &event {
            HarnessEvent::Output { chunk, seq, .. } => {
                println!(
                    "Output event seq={}: {:?}",
                    seq,
                    String::from_utf8_lossy(chunk)
                );
                output_chunks.push(chunk.clone());
            },
            HarnessEvent::Terminated { .. } => {
                termination_event = Some(event);
                break;
            },
            _ => {},
        }
    }

    // Verify we received output
    assert!(
        !output_chunks.is_empty(),
        "should receive at least one output chunk"
    );

    // Verify output contains expected content
    let combined_output: Vec<u8> = output_chunks.into_iter().flatten().collect();
    let output_str = String::from_utf8_lossy(&combined_output);
    assert!(
        output_str.contains("hello world"),
        "output should contain 'hello world', got: {output_str}"
    );

    // Verify termination event
    let term_event = termination_event.expect("should receive termination event");
    match term_event {
        HarnessEvent::Terminated {
            exit_code,
            classification,
        } => {
            assert_eq!(exit_code, Some(0), "echo should exit with code 0");
            assert_eq!(
                classification,
                TerminationClassification::Success,
                "successful exit should be classified as Success"
            );
        },
        _ => panic!("expected Terminated event"),
    }
}

/// IT-00162-01b: Verify `RawAdapter` handles non-zero exit codes correctly.
#[tokio::test]
async fn it_00162_01b_raw_adapter_non_zero_exit() {
    let adapter = RawAdapter::new();

    // Command that exits with non-zero code
    let config = HarnessConfig::new("sh", "it-00162-01b-episode")
        .with_args(vec!["-c".to_string(), "exit 42".to_string()]);

    let (_, mut events) = adapter.spawn(config).await.expect("spawn should succeed");

    // Drain until terminated
    let mut termination_event = None;
    while let Some(event) = events.recv().await {
        if event.is_terminal() {
            termination_event = Some(event);
            break;
        }
    }

    // Verify termination with non-zero exit code
    match termination_event.expect("should receive termination event") {
        HarnessEvent::Terminated {
            exit_code,
            classification,
        } => {
            assert_eq!(exit_code, Some(42), "should capture exit code 42");
            assert_eq!(
                classification,
                TerminationClassification::Failure,
                "non-zero exit should be classified as Failure"
            );
        },
        _ => panic!("expected Terminated event"),
    }
}

/// IT-00162-01c: Verify `RawAdapter` produces sequenced output events.
#[tokio::test]
async fn it_00162_01c_raw_adapter_output_sequencing() {
    let adapter = RawAdapter::new();

    // Command that produces multiple lines of output
    let config = HarnessConfig::new("sh", "it-00162-01c-episode").with_args(vec![
        "-c".to_string(),
        "echo line1; echo line2; echo line3".to_string(),
    ]);

    let (_, mut events) = adapter.spawn(config).await.expect("spawn should succeed");

    // Collect sequence numbers
    let mut sequences = Vec::new();

    while let Some(event) = events.recv().await {
        match event {
            HarnessEvent::Output { seq, .. } => {
                sequences.push(seq);
            },
            HarnessEvent::Terminated { .. } => break,
            _ => {},
        }
    }

    // Verify sequences are monotonically increasing
    assert!(!sequences.is_empty(), "should have received output events");
    for i in 1..sequences.len() {
        assert!(
            sequences[i] > sequences[i - 1],
            "sequence numbers should be monotonically increasing"
        );
    }
}

/// IT-00162-01d: Verify `RawAdapter` respects concurrent process limit.
#[tokio::test]
async fn it_00162_01d_raw_adapter_resource_tracking() {
    let adapter = RawAdapter::new();

    // Initial state
    assert_eq!(adapter.active_count(), 0, "should start with 0 active");
    assert!(adapter.available_slots() > 0, "should have available slots");

    // Spawn a process
    let config =
        HarnessConfig::new("sleep", "it-00162-01d-episode").with_args(vec!["0.1".to_string()]);

    let (_, mut events) = adapter.spawn(config).await.expect("spawn should succeed");

    // Drain events
    while events.recv().await.is_some() {}

    // Small delay for task cleanup
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // After completion, slot should be released
    assert_eq!(
        adapter.active_count(),
        0,
        "slot should be released after completion"
    );
}

/// IT-00162-01e: Verify `RawAdapter` validates configuration.
#[tokio::test]
async fn it_00162_01e_raw_adapter_config_validation() {
    let adapter = RawAdapter::new();

    // Empty command should fail
    let config = HarnessConfig::new("", "it-00162-01e-episode");
    let result = adapter.spawn(config).await;
    assert!(result.is_err(), "empty command should be rejected");

    // Command with null byte should fail
    let config = HarnessConfig::new("echo\0", "it-00162-01e-episode");
    let result = adapter.spawn(config).await;
    assert!(result.is_err(), "command with null byte should be rejected");

    // Arg with null byte should fail
    let config =
        HarnessConfig::new("echo", "it-00162-01e-episode").with_args(vec!["bad\0arg".to_string()]);
    let result = adapter.spawn(config).await;
    assert!(result.is_err(), "arg with null byte should be rejected");
}
