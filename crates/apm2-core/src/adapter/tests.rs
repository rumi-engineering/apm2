//! Integration tests for the adapter module.

use std::time::Duration;

use super::*;

/// Test that the black-box adapter correctly handles process lifecycle.
#[cfg_attr(miri, ignore)] // Miri can't spawn processes
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_black_box_adapter_lifecycle() {
    let config = BlackBoxConfig::new("session-lifecycle", "echo").with_args(["test", "output"]);

    let mut adapter = BlackBoxAdapter::new(config);

    // Before start
    assert!(!adapter.is_running());
    assert!(adapter.pid().is_none());
    assert_eq!(adapter.session_id(), "session-lifecycle");

    // Start the adapter
    adapter.start().await.unwrap();
    assert!(adapter.is_running());
    assert!(adapter.pid().is_some());

    // Collect events until process exits
    let mut events = Vec::new();
    loop {
        match adapter.poll().await {
            Ok(Some(event)) => {
                let is_exit = matches!(event.payload, AdapterEventPayload::ProcessExited(_));
                events.push(event);
                if is_exit {
                    break;
                }
            },
            Ok(None) => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            },
            Err(e) => panic!("poll error: {e}"),
        }
    }

    // Verify we got the expected events
    assert!(!events.is_empty(), "Expected at least one event");

    // First event should be ProcessStarted (if we didn't miss it)
    // Last event should be ProcessExited
    let last_event = events.last().unwrap();
    assert!(
        matches!(last_event.payload, AdapterEventPayload::ProcessExited(_)),
        "Last event should be ProcessExited"
    );

    // After exit
    assert!(!adapter.is_running());
}

/// Test that the adapter correctly detects filesystem changes.
#[cfg_attr(miri, ignore)] // Miri can't spawn processes
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_black_box_adapter_filesystem_detection() {
    let dir = tempfile::tempdir().unwrap();

    // Use a process that sleeps long enough for us to create a file
    let mut config = BlackBoxConfig::new("session-fs", "sleep")
        .with_args(["5"])
        .with_working_dir(dir.path())
        .with_watch_path(dir.path());

    // Use shorter debounce for faster test
    config.filesystem.debounce = Duration::from_millis(10);

    let mut adapter = BlackBoxAdapter::new(config);

    // Take the event receiver to get all events including FilesystemChange
    let mut rx = adapter.take_event_receiver().unwrap();

    adapter.start().await.unwrap();

    // Give the adapter time to initialize
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Create a file in the watched directory
    let file_path = dir.path().join("detected.txt");
    std::fs::write(&file_path, "content").unwrap();

    // Poll until we detect the filesystem change
    let mut found_fs_change = false;
    let mut found_tool_detection = false;

    for _ in 0..100 {
        // Trigger event processing
        let _ = adapter.poll().await;

        // Check the event receiver
        while let Ok(event) = tokio::time::timeout(Duration::from_millis(5), rx.recv()).await {
            if let Some(event) = event {
                match &event.payload {
                    AdapterEventPayload::FilesystemChange(change) => {
                        if change.path == file_path {
                            found_fs_change = true;
                        }
                    },
                    AdapterEventPayload::ToolRequestDetected(req) => {
                        if req.tool_name == "file_write" {
                            found_tool_detection = true;
                        }
                    },
                    AdapterEventPayload::ProcessExited(_) => break,
                    _ => {},
                }
            }
        }

        if found_fs_change && found_tool_detection {
            break;
        }

        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    adapter.stop().await.unwrap();

    assert!(found_fs_change, "Expected to detect filesystem change");
    assert!(
        found_tool_detection,
        "Expected to detect tool request from file write"
    );
}

/// Test that stall detection works correctly.
#[cfg_attr(miri, ignore)] // Miri can't spawn processes
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_black_box_adapter_stall_detection() {
    let config = BlackBoxConfig::new("session-stall", "sleep")
        .with_args(["5"])
        .with_stall_timeout(Duration::from_millis(200));

    let mut adapter = BlackBoxAdapter::new(config);
    adapter.start().await.unwrap();

    // Wait for stall detection to trigger
    let mut found_stall = false;
    for _ in 0..20 {
        if let Ok(Some(event)) = adapter.poll().await {
            if matches!(event.payload, AdapterEventPayload::StallDetected(_)) {
                found_stall = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    adapter.stop().await.unwrap();

    assert!(found_stall, "Expected stall detection to trigger");
}

/// Test event receiver functionality.
#[cfg_attr(miri, ignore)] // Miri can't spawn processes
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_black_box_adapter_event_receiver() {
    let config = BlackBoxConfig::new("session-receiver", "echo").with_args(["hello"]);

    let mut adapter = BlackBoxAdapter::new(config);

    // Take the event receiver
    let mut rx = adapter.take_event_receiver().unwrap();

    // Second take should return None
    assert!(adapter.take_event_receiver().is_none());

    // Start the adapter
    adapter.start().await.unwrap();

    // Run in background
    tokio::spawn(async move {
        loop {
            match adapter.poll().await {
                Ok(Some(_) | None) => {},
                Err(_) => break,
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
            if !adapter.is_running() {
                break;
            }
        }
    });

    // Receive events from the channel
    let mut received_events = Vec::new();
    while let Ok(event) = tokio::time::timeout(Duration::from_secs(1), rx.recv()).await {
        if let Some(event) = event {
            let is_exit = matches!(event.payload, AdapterEventPayload::ProcessExited(_));
            received_events.push(event);
            if is_exit {
                break;
            }
        } else {
            break;
        }
    }

    assert!(!received_events.is_empty(), "Expected to receive events");
}

/// Test that environment filtering configuration works correctly.
#[test]
fn test_environment_filtering_config() {
    let mut config = BlackBoxConfig::new("session-env", "echo");
    config.environment.variables = vec![
        ("SAFE_VAR".to_string(), "value".to_string()),
        ("ANTHROPIC_API_KEY".to_string(), "secret".to_string()),
    ];

    // Verify the default config has the exclude list for sensitive keys
    assert!(
        config
            .environment
            .exclude
            .contains(&"ANTHROPIC_API_KEY".to_string())
    );
    assert!(
        config
            .environment
            .exclude
            .contains(&"AWS_SECRET_ACCESS_KEY".to_string())
    );
    assert!(
        config
            .environment
            .exclude
            .contains(&"GITHUB_TOKEN".to_string())
    );

    // The adapter should be created successfully
    let adapter = BlackBoxAdapter::new(config);
    assert_eq!(adapter.session_id(), "session-env");
}

/// Test adapter error handling for invalid command.
#[cfg_attr(miri, ignore)] // Miri can't spawn processes
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_black_box_adapter_spawn_error() {
    let config = BlackBoxConfig::new("session-error", "nonexistent_command_12345");

    let mut adapter = BlackBoxAdapter::new(config);
    let result = adapter.start().await;

    assert!(result.is_err());
    assert!(matches!(result, Err(AdapterError::SpawnFailed(_))));
    assert!(!adapter.is_running());
}

/// Test that adapter correctly reports exit codes.
#[cfg_attr(miri, ignore)] // Miri can't spawn processes
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_black_box_adapter_exit_codes() {
    // Test successful exit
    {
        let config = BlackBoxConfig::new("session-exit-0", "true");
        let mut adapter = BlackBoxAdapter::new(config);
        adapter.start().await.unwrap();

        loop {
            if let Ok(Some(event)) = adapter.poll().await {
                if let AdapterEventPayload::ProcessExited(exit) = event.payload {
                    assert_eq!(exit.exit_code, Some(0));
                    assert_eq!(exit.classification, ExitClassification::CleanSuccess);
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    // Test error exit
    {
        let config = BlackBoxConfig::new("session-exit-1", "false");
        let mut adapter = BlackBoxAdapter::new(config);
        adapter.start().await.unwrap();

        loop {
            if let Ok(Some(event)) = adapter.poll().await {
                if let AdapterEventPayload::ProcessExited(exit) = event.payload {
                    assert_eq!(exit.exit_code, Some(1));
                    assert_eq!(exit.classification, ExitClassification::CleanError);
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

/// Test that progress signals are emitted on activity.
#[cfg_attr(miri, ignore)] // Miri can't spawn processes
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_black_box_adapter_progress_signals() {
    let dir = tempfile::tempdir().unwrap();

    let config = BlackBoxConfig::new("session-progress", "sleep")
        .with_args(["2"])
        .with_watch_path(dir.path());

    let mut adapter = BlackBoxAdapter::new(config);
    adapter.start().await.unwrap();

    // Give time to initialize
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Create a file to trigger activity
    std::fs::write(dir.path().join("activity.txt"), "data").unwrap();

    // Look for progress signal
    let mut found_progress = false;
    for _ in 0..30 {
        if let Ok(Some(event)) = adapter.poll().await {
            if let AdapterEventPayload::Progress(progress) = &event.payload {
                if progress.signal_type == ProgressType::Activity {
                    found_progress = true;
                    break;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    adapter.stop().await.unwrap();

    assert!(found_progress, "Expected progress signal from activity");
}

/// Test adapter event sequence numbers.
#[cfg_attr(miri, ignore)] // Miri can't spawn processes
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_adapter_event_sequence() {
    let config = BlackBoxConfig::new("session-seq", "echo").with_args(["test"]);

    let mut adapter = BlackBoxAdapter::new(config);
    adapter.start().await.unwrap();

    let mut events = Vec::new();
    loop {
        match adapter.poll().await {
            Ok(Some(event)) => {
                let is_exit = matches!(event.payload, AdapterEventPayload::ProcessExited(_));
                events.push(event);
                if is_exit {
                    break;
                }
            },
            Ok(None) => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            },
            Err(_) => break,
        }
    }

    // Verify sequence numbers are monotonically increasing
    let mut last_seq = 0;
    for (i, event) in events.iter().enumerate() {
        if i > 0 {
            assert!(
                event.sequence > last_seq,
                "Sequence number should increase: {} <= {}",
                event.sequence,
                last_seq
            );
        }
        last_seq = event.sequence;
    }
}

/// Test that all events have the correct session ID.
#[cfg_attr(miri, ignore)] // Miri can't spawn processes
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_adapter_event_session_id() {
    let config = BlackBoxConfig::new("session-id-test", "echo").with_args(["hello"]);

    let mut adapter = BlackBoxAdapter::new(config);
    adapter.start().await.unwrap();

    let mut events = Vec::new();
    loop {
        match adapter.poll().await {
            Ok(Some(event)) => {
                let is_exit = matches!(event.payload, AdapterEventPayload::ProcessExited(_));
                events.push(event);
                if is_exit {
                    break;
                }
            },
            Ok(None) => {
                tokio::time::sleep(Duration::from_millis(10)).await;
            },
            Err(_) => break,
        }
    }

    // All events should have the correct session ID
    for event in &events {
        assert_eq!(
            event.session_id, "session-id-test",
            "Event should have correct session ID"
        );
    }
}
