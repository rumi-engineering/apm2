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

// =============================================================================
// Claude Code Instrumented Adapter Tests
// =============================================================================

/// Test Claude Code adapter configuration creation and builder pattern.
#[test]
fn test_claude_code_config_creation() {
    let config = ClaudeCodeConfig::new("claude-session-123");

    assert_eq!(config.session_id, "claude-session-123");
    assert_eq!(config.claude_binary, "claude");
    assert!(config.args.is_empty());
    assert!(config.working_dir.is_none());
    assert!(config.stall_detection_enabled);
    assert!(config.hooks.pre_tool_use);
    assert!(config.hooks.post_tool_use);
    assert!(config.hooks.session_lifecycle);
}

/// Test Claude Code adapter configuration builder.
#[test]
fn test_claude_code_config_builder() {
    let config = ClaudeCodeConfig::new("claude-builder-test")
        .with_binary("/usr/local/bin/claude")
        .with_working_dir("/home/user/project")
        .with_args(["--model", "opus", "--verbose"])
        .with_stall_timeout(Duration::from_secs(180))
        .without_stall_detection();

    assert_eq!(config.session_id, "claude-builder-test");
    assert_eq!(config.claude_binary, "/usr/local/bin/claude");
    assert_eq!(
        config.working_dir,
        Some(std::path::PathBuf::from("/home/user/project"))
    );
    assert_eq!(config.args, vec!["--model", "opus", "--verbose"]);
    assert_eq!(config.stall_timeout, Duration::from_secs(180));
    assert!(!config.stall_detection_enabled);
}

/// Test Claude Code adapter creation and initial state.
#[test]
fn test_claude_code_adapter_creation() {
    let config = ClaudeCodeConfig::new("claude-adapter-test");
    let adapter = ClaudeCodeAdapter::new(config);

    assert_eq!(adapter.session_id(), "claude-adapter-test");
    assert!(!adapter.is_running());
    assert!(adapter.pid().is_none());
    assert!(adapter.claude_session_id().is_none());
    assert!(adapter.exit_code().is_none());
    assert!(adapter.exit_signal().is_none());
}

/// Test that Claude Code adapter implements the Adapter trait correctly.
#[test]
fn test_claude_code_adapter_trait_type() {
    let config = ClaudeCodeConfig::new("trait-test");
    let adapter = ClaudeCodeAdapter::new(config);

    // Verify adapter_type returns the correct string
    assert_eq!(Adapter::adapter_type(&adapter), "claude-code");
}

/// Test hook event serialization and deserialization.
#[test]
fn test_hook_event_serialization() {
    // Test PreToolUse event
    let pre_tool = HookEvent::PreToolUse(ToolUseEvent {
        tool_use_id: "tool-001".to_string(),
        tool_name: "Read".to_string(),
        input: serde_json::json!({"file_path": "/tmp/test.rs"}),
        session_id: Some("session-xyz".to_string()),
        timestamp: Some(1_706_000_000_000),
    });

    let json = serde_json::to_string(&pre_tool).unwrap();
    assert!(json.contains("\"type\":\"pre_tool_use\""));
    assert!(json.contains("Read"));

    // Test PostToolUse event
    let post_tool = HookEvent::PostToolUse(ToolResultEvent {
        tool_use_id: "tool-001".to_string(),
        output: serde_json::json!({"content": "file contents here"}),
        success: true,
        error: None,
        duration_ms: Some(50),
    });

    let json = serde_json::to_string(&post_tool).unwrap();
    assert!(json.contains("\"type\":\"post_tool_use\""));
    assert!(json.contains("tool-001"));

    // Test SessionStart event
    let session_start = HookEvent::SessionStart(SessionStartEvent {
        session_id: "claude-session-abc".to_string(),
        working_dir: Some("/home/user/project".to_string()),
        model: Some("claude-opus-4".to_string()),
        timestamp: Some(1_706_000_000_000),
    });

    let json = serde_json::to_string(&session_start).unwrap();
    assert!(json.contains("\"type\":\"session_start\""));
    assert!(json.contains("claude-opus-4"));

    // Test SessionEnd event
    let session_end = HookEvent::SessionEnd(SessionEndEvent {
        session_id: "claude-session-abc".to_string(),
        reason: Some("completed".to_string()),
        duration_ms: Some(120_000),
    });

    let json = serde_json::to_string(&session_end).unwrap();
    assert!(json.contains("\"type\":\"session_end\""));

    // Test Progress event
    let progress = HookEvent::Progress(ProgressEvent {
        progress_type: "thinking".to_string(),
        description: Some("Processing user request".to_string()),
        token_count: Some(500),
    });

    let json = serde_json::to_string(&progress).unwrap();
    assert!(json.contains("\"type\":\"progress\""));
    assert!(json.contains("thinking"));
}

/// Test hook response creation.
#[test]
fn test_hook_response_creation() {
    // Default response allows continuation
    let default_response = HookResponse::default();
    assert!(default_response.continue_execution);
    assert!(default_response.message.is_none());
    assert!(default_response.modified_input.is_none());

    // Custom deny response
    let deny_response = HookResponse {
        continue_execution: false,
        message: Some("Tool execution denied by policy".to_string()),
        modified_input: None,
    };
    assert!(!deny_response.continue_execution);
    assert!(deny_response.message.is_some());

    // Response with modified input
    let modified_response = HookResponse {
        continue_execution: true,
        message: Some("Input sanitized".to_string()),
        modified_input: Some(serde_json::json!({"sanitized": true})),
    };
    assert!(modified_response.continue_execution);
    assert!(modified_response.modified_input.is_some());
}

/// Test that environment configuration follows security defaults.
#[test]
fn test_claude_code_environment_security() {
    let config = ClaudeCodeConfig::new("security-test");

    // Verify default-deny: inherit is false
    assert!(
        !config.environment.inherit,
        "Default config should not inherit parent environment"
    );

    // Verify sensitive keys are in the exclude list
    let exclude = &config.environment.exclude;
    assert!(exclude.contains(&"ANTHROPIC_API_KEY".to_string()));
    assert!(exclude.contains(&"AWS_SECRET_ACCESS_KEY".to_string()));
    assert!(exclude.contains(&"AWS_ACCESS_KEY_ID".to_string()));
    assert!(exclude.contains(&"GITHUB_TOKEN".to_string()));
    assert!(exclude.contains(&"OPENAI_API_KEY".to_string()));
    assert!(exclude.contains(&"NPM_TOKEN".to_string()));
}

/// Test hook configuration defaults.
#[test]
fn test_hook_config_defaults() {
    let config = HookConfig::default();

    assert!(
        config.pre_tool_use,
        "PreToolUse hook should be enabled by default"
    );
    assert!(
        config.post_tool_use,
        "PostToolUse hook should be enabled by default"
    );
    assert!(
        config.session_lifecycle,
        "Session lifecycle hooks should be enabled by default"
    );
    assert_eq!(
        config.hook_timeout,
        Duration::from_secs(30),
        "Default hook timeout should be 30 seconds"
    );
}

/// Test that the adapter correctly reports adapter type through trait.
#[test]
fn test_adapter_trait_implementation() {
    let config = ClaudeCodeConfig::new("trait-impl-test");
    let mut adapter = ClaudeCodeAdapter::new(config);

    // Test session_id through trait
    assert_eq!(Adapter::session_id(&adapter), "trait-impl-test");

    // Test is_running through trait
    assert!(!Adapter::is_running(&adapter));

    // Test pid through trait
    assert!(Adapter::pid(&adapter).is_none());

    // Test adapter_type through trait
    assert_eq!(Adapter::adapter_type(&adapter), "claude-code");

    // Test take_event_receiver through trait
    let rx = Adapter::take_event_receiver(&mut adapter);
    assert!(rx.is_some());

    // Second take should return None
    let rx2 = Adapter::take_event_receiver(&mut adapter);
    assert!(rx2.is_none());
}

/// Test tool use event structure.
#[test]
fn test_tool_use_event_structure() {
    let event = ToolUseEvent {
        tool_use_id: "toolu_01ABC123".to_string(),
        tool_name: "Bash".to_string(),
        input: serde_json::json!({
            "command": "cargo test",
            "timeout": 60000
        }),
        session_id: Some("sess_xyz".to_string()),
        timestamp: Some(1_706_123_456_789),
    };

    assert_eq!(event.tool_use_id, "toolu_01ABC123");
    assert_eq!(event.tool_name, "Bash");
    assert!(event.input.is_object());
    assert_eq!(event.session_id, Some("sess_xyz".to_string()));
    assert_eq!(event.timestamp, Some(1_706_123_456_789));

    // Verify serialization round-trip
    let json = serde_json::to_string(&event).unwrap();
    let parsed: ToolUseEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.tool_use_id, event.tool_use_id);
    assert_eq!(parsed.tool_name, event.tool_name);
}

/// Test tool result event structure.
#[test]
fn test_tool_result_event_structure() {
    // Success case
    let success_event = ToolResultEvent {
        tool_use_id: "toolu_01ABC123".to_string(),
        output: serde_json::json!({"result": "test passed"}),
        success: true,
        error: None,
        duration_ms: Some(1500),
    };

    assert!(success_event.success);
    assert!(success_event.error.is_none());
    assert_eq!(success_event.duration_ms, Some(1500));

    // Failure case
    let failure_event = ToolResultEvent {
        tool_use_id: "toolu_01ABC123".to_string(),
        output: serde_json::json!(null),
        success: false,
        error: Some("Command failed with exit code 1".to_string()),
        duration_ms: Some(500),
    };

    assert!(!failure_event.success);
    assert!(failure_event.error.is_some());
}

/// Test session lifecycle events.
#[test]
fn test_session_lifecycle_events() {
    let start_event = SessionStartEvent {
        session_id: "sess_lifecycle_test".to_string(),
        working_dir: Some("/home/user/project".to_string()),
        model: Some("claude-opus-4-20250514".to_string()),
        timestamp: Some(1_706_000_000_000),
    };

    assert_eq!(start_event.session_id, "sess_lifecycle_test");
    assert_eq!(
        start_event.working_dir,
        Some("/home/user/project".to_string())
    );
    assert!(start_event.model.as_ref().unwrap().contains("opus"));

    let end_event = SessionEndEvent {
        session_id: "sess_lifecycle_test".to_string(),
        reason: Some("user_terminated".to_string()),
        duration_ms: Some(300_000), // 5 minutes
    };

    assert_eq!(end_event.session_id, "sess_lifecycle_test");
    assert_eq!(end_event.reason, Some("user_terminated".to_string()));
    assert_eq!(end_event.duration_ms, Some(300_000));
}

/// Test progress event types.
#[test]
fn test_progress_event_types() {
    let thinking_event = ProgressEvent {
        progress_type: "thinking".to_string(),
        description: Some("Analyzing code structure".to_string()),
        token_count: Some(1500),
    };

    assert_eq!(thinking_event.progress_type, "thinking");
    assert!(thinking_event.description.is_some());
    assert_eq!(thinking_event.token_count, Some(1500));

    let streaming_event = ProgressEvent {
        progress_type: "streaming".to_string(),
        description: Some("Generating response".to_string()),
        token_count: Some(500),
    };

    assert_eq!(streaming_event.progress_type, "streaming");

    let idle_event = ProgressEvent {
        progress_type: "idle".to_string(),
        description: None,
        token_count: None,
    };

    assert_eq!(idle_event.progress_type, "idle");
    assert!(idle_event.description.is_none());
}

/// Test that Claude Code adapter implements the Adapter trait uniformly.
#[test]
fn test_claude_code_adapter_trait_uniformity() {
    let claude_config = ClaudeCodeConfig::new("uniform-claude");
    let claude = ClaudeCodeAdapter::new(claude_config);

    // Check that the adapter implements the trait correctly through method calls
    let _ = Adapter::session_id(&claude);
    let _ = Adapter::is_running(&claude);
    let _ = Adapter::pid(&claude);
    let _ = Adapter::adapter_type(&claude);

    // Verify adapter type is correct
    assert_eq!(Adapter::adapter_type(&claude), "claude-code");
}

/// Test that spawn failure is handled correctly.
#[cfg_attr(miri, ignore)] // Miri can't spawn processes
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_claude_code_adapter_spawn_failure() {
    let config =
        ClaudeCodeConfig::new("spawn-fail-test").with_binary("nonexistent_claude_binary_12345");

    let mut adapter = ClaudeCodeAdapter::new(config);

    let result = adapter.start().await;
    assert!(result.is_err());

    match result {
        Err(AdapterError::SpawnFailed(msg)) => {
            assert!(!msg.is_empty(), "Error message should not be empty");
        },
        _ => panic!("Expected SpawnFailed error"),
    }

    // Adapter should not be running after failed start
    assert!(!adapter.is_running());
    assert!(adapter.pid().is_none());
}

/// Test that adapter is not running before start is called.
#[test]
fn test_claude_code_adapter_initial_state() {
    let config = ClaudeCodeConfig::new("initial-state-test");
    let adapter = ClaudeCodeAdapter::new(config);

    // Adapter should not be running before start is called
    assert!(!adapter.is_running());
    assert!(adapter.pid().is_none());
    assert!(adapter.claude_session_id().is_none());
}

/// Test exit classification string representation.
///
/// Note: The actual classification logic is tested in the `claude_code`
/// module's unit tests. Here we test the public interface of
/// `ExitClassification`.
#[test]
fn test_exit_classification_as_str() {
    // Verify all classification variants have string representations
    assert_eq!(ExitClassification::CleanSuccess.as_str(), "CLEAN_SUCCESS");
    assert_eq!(ExitClassification::CleanError.as_str(), "CLEAN_ERROR");
    assert_eq!(ExitClassification::Signal.as_str(), "SIGNAL");
    assert_eq!(ExitClassification::Timeout.as_str(), "TIMEOUT");
    assert_eq!(
        ExitClassification::EntropyExceeded.as_str(),
        "ENTROPY_EXCEEDED"
    );
    assert_eq!(ExitClassification::Unknown.as_str(), "UNKNOWN");
}
