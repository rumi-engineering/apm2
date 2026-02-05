//! Process management commands (TCK-00342).
//!
//! # Migration from Legacy JSON IPC
//!
//! Per DD-009 (RFC-0017), all process management commands now use tag-based
//! protobuf framing via the `OperatorClient` (privileged operations) and
//! `SessionClient` (log streaming).
//!
//! # Privileged Operations (operator.sock)
//!
//! - `list` - Lists all managed processes
//! - `status` - Gets detailed status for a process
//! - `start` - Starts a managed process
//! - `stop` - Stops a managed process
//! - `restart` - Restarts a managed process
//! - `reload` - Rolling restart of a managed process
//!
//! # Session Operations (session.sock)
//!
//! - `logs` - Streams logs from a managed process (requires session token)

use std::path::Path;

use anyhow::{Context, Result, bail};
use apm2_daemon::protocol::ProcessStateEnum;

use crate::client::protocol::OperatorClient;

/// Start a managed process.
///
/// Sends a `StartProcess` request to the daemon via operator.sock.
///
/// # Arguments
///
/// * `socket_path` - Path to the operator socket
/// * `name` - Process name to start
pub fn start(socket_path: &Path, name: &str) -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build tokio runtime")?;

    rt.block_on(async {
        let mut client = OperatorClient::connect(socket_path)
            .await
            .context("failed to connect to daemon")?;

        let response = client
            .start_process(name)
            .await
            .context("failed to start process")?;

        println!(
            "Started process '{}': {} instance(s) started",
            response.name, response.instances_started
        );
        Ok(())
    })
}

/// Stop a managed process.
///
/// Sends a `StopProcess` request to the daemon via operator.sock.
///
/// # Arguments
///
/// * `socket_path` - Path to the operator socket
/// * `name` - Process name to stop
pub fn stop(socket_path: &Path, name: &str) -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build tokio runtime")?;

    rt.block_on(async {
        let mut client = OperatorClient::connect(socket_path)
            .await
            .context("failed to connect to daemon")?;

        let response = client
            .stop_process(name)
            .await
            .context("failed to stop process")?;

        println!(
            "Stopped process '{}': {} instance(s) stopped",
            response.name, response.instances_stopped
        );
        Ok(())
    })
}

/// Restart a managed process.
///
/// Sends a `RestartProcess` request to the daemon via operator.sock.
///
/// # Arguments
///
/// * `socket_path` - Path to the operator socket
/// * `name` - Process name to restart
pub fn restart(socket_path: &Path, name: &str) -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build tokio runtime")?;

    rt.block_on(async {
        let mut client = OperatorClient::connect(socket_path)
            .await
            .context("failed to connect to daemon")?;

        let response = client
            .restart_process(name)
            .await
            .context("failed to restart process")?;

        println!(
            "Restarted process '{}': {} instance(s) restarted",
            response.name, response.instances_restarted
        );
        Ok(())
    })
}

/// Graceful reload (rolling restart).
///
/// Sends a `ReloadProcess` request to the daemon via operator.sock.
///
/// # Arguments
///
/// * `socket_path` - Path to the operator socket
/// * `name` - Process name to reload
pub fn reload(socket_path: &Path, name: &str) -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build tokio runtime")?;

    rt.block_on(async {
        let mut client = OperatorClient::connect(socket_path)
            .await
            .context("failed to connect to daemon")?;

        let response = client
            .reload_process(name)
            .await
            .context("failed to reload process")?;

        if response.success {
            println!("Reloaded process '{}': {}", response.name, response.message);
        } else {
            bail!("Failed to reload '{}': {}", response.name, response.message);
        }
        Ok(())
    })
}

/// List all managed processes.
///
/// Sends a `ListProcesses` request to the daemon via operator.sock.
///
/// # Arguments
///
/// * `socket_path` - Path to the operator socket
pub fn list(socket_path: &Path) -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build tokio runtime")?;

    rt.block_on(async {
        let mut client = OperatorClient::connect(socket_path)
            .await
            .context("failed to connect to daemon")?;

        let response = client
            .list_processes()
            .await
            .context("failed to list processes")?;

        if response.processes.is_empty() {
            println!("No managed processes");
            return Ok(());
        }

        // Print header
        println!(
            "{:<20} {:<12} {:>8} {:>8} {:>10}",
            "NAME", "STATE", "RUNNING", "TOTAL", "PID"
        );
        println!("{}", "-".repeat(62));

        for proc in &response.processes {
            let state_str = format_process_state(proc.state);
            let pid_str = proc.pid.map_or_else(|| "-".to_string(), |p| p.to_string());
            println!(
                "{:<20} {:<12} {:>8} {:>8} {:>10}",
                proc.name, state_str, proc.running_instances, proc.instances, pid_str
            );
        }

        Ok(())
    })
}

/// Show detailed status for a process.
///
/// Sends a `ProcessStatus` request to the daemon via operator.sock.
///
/// # Arguments
///
/// * `socket_path` - Path to the operator socket
/// * `name` - Process name to query
pub fn status(socket_path: &Path, name: &str) -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to build tokio runtime")?;

    rt.block_on(async {
        let mut client = OperatorClient::connect(socket_path)
            .await
            .context("failed to connect to daemon")?;

        let response = client
            .process_status(name)
            .await
            .context("failed to get process status")?;

        let info = response
            .info
            .as_ref()
            .context("daemon returned no process info")?;

        println!("Process: {}", info.name);
        println!("State:   {}", format_process_state(info.state));
        println!(
            "Instances: {}/{} running",
            info.running_instances, info.instances
        );

        if let Some(pid) = info.pid {
            println!("PID:     {pid}");
        }

        if let Some(uptime) = info.uptime_secs {
            println!("Uptime:  {}", format_duration(uptime));
        }

        println!("Restarts: {}", response.restart_count);

        if let Some(cpu) = response.cpu_percent {
            println!("CPU:     {cpu:.1}%");
        }

        if let Some(mem) = response.memory_bytes {
            println!("Memory:  {}", format_bytes(mem));
        }

        Ok(())
    })
}

/// Show process info (alias for status).
///
/// # Arguments
///
/// * `socket_path` - Path to the operator socket
/// * `name` - Process name to query
#[allow(dead_code)]
pub fn info(socket_path: &Path, name: &str) -> Result<()> {
    status(socket_path, name)
}

/// Tail process logs.
///
/// Sends a `StreamLogs` request to the daemon via session.sock.
///
/// # Arguments
///
/// * `socket_path` - Path to the session socket
/// * `name` - Process name to stream logs from
/// * `lines` - Number of historical lines to retrieve
/// * `follow` - Whether to stream new lines (not implemented in Phase 1)
///
/// # Note
///
/// This function requires a session token for authentication. The session
/// token is not yet available in the CLI context, so this function returns
/// an error indicating the feature is not yet fully implemented.
pub fn logs(_socket_path: &Path, _name: &str, _lines: u32, _follow: bool) -> Result<()> {
    // TODO(TCK-00342): Implement log streaming once session token management
    // is available in the CLI. The SessionClient.stream_logs method is ready,
    // but we need a way to obtain a valid session token.
    bail!("Log streaming requires session token (not yet available in CLI context)")
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Formats a process state enum value to a human-readable string.
fn format_process_state(state: i32) -> &'static str {
    match ProcessStateEnum::try_from(state) {
        Ok(ProcessStateEnum::ProcessStateStarting) => "starting",
        Ok(ProcessStateEnum::ProcessStateRunning) => "running",
        Ok(ProcessStateEnum::ProcessStateUnhealthy) => "unhealthy",
        Ok(ProcessStateEnum::ProcessStateStopping) => "stopping",
        Ok(ProcessStateEnum::ProcessStateStopped) => "stopped",
        Ok(ProcessStateEnum::ProcessStateCrashed) => "crashed",
        Ok(ProcessStateEnum::ProcessStateTerminated) => "terminated",
        Ok(ProcessStateEnum::ProcessStateUnspecified) | Err(_) => "unknown",
    }
}

/// Formats a duration in seconds to a human-readable string.
fn format_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        let mins = secs / 60;
        let secs = secs % 60;
        format!("{mins}m {secs}s")
    } else if secs < 86400 {
        let hours = secs / 3600;
        let mins = (secs % 3600) / 60;
        format!("{hours}h {mins}m")
    } else {
        let days = secs / 86400;
        let hours = (secs % 86400) / 3600;
        format!("{days}d {hours}h")
    }
}

/// Formats bytes to a human-readable string.
#[allow(clippy::cast_precision_loss)] // Precision loss acceptable for human-readable display
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes < KB {
        format!("{bytes} B")
    } else if bytes < MB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else if bytes < GB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_process_state() {
        // ProcessStateEnum values from proto:
        // 0 = UNSPECIFIED, 1 = STARTING, 2 = RUNNING, 3 = UNHEALTHY,
        // 4 = STOPPING, 5 = STOPPED, 6 = CRASHED, 7 = TERMINATED
        assert_eq!(format_process_state(0), "unknown");
        assert_eq!(format_process_state(1), "starting");
        assert_eq!(format_process_state(2), "running");
        assert_eq!(format_process_state(3), "unhealthy");
        assert_eq!(format_process_state(4), "stopping");
        assert_eq!(format_process_state(5), "stopped");
        assert_eq!(format_process_state(6), "crashed");
        assert_eq!(format_process_state(7), "terminated");
        assert_eq!(format_process_state(999), "unknown");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(30), "30s");
        assert_eq!(format_duration(90), "1m 30s");
        assert_eq!(format_duration(3661), "1h 1m");
        assert_eq!(format_duration(90061), "1d 1h");
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(1_572_864), "1.5 MB");
        assert_eq!(format_bytes(1_610_612_736), "1.5 GB");
    }

    // =========================================================================
    // TCK-00342: Protocol Integration Tests
    //
    // These tests verify that the CLI process management commands use
    // OperatorClient with tag-based protobuf framing (not JSON IPC).
    // =========================================================================

    use apm2_daemon::protocol::{
        BoundedDecode, DecodeConfig, ListProcessesRequest, ListProcessesResponse,
        PrivilegedMessageType, ProcessStatusRequest, ProcessStatusResponse, ReloadProcessRequest,
        RestartProcessRequest, StartProcessRequest, StopProcessRequest,
        encode_list_processes_request, encode_process_status_request,
        encode_reload_process_request, encode_restart_process_request,
        encode_start_process_request, encode_stop_process_request,
    };

    /// IT-00342-01: Verifies that list command uses `OperatorClient` protocol
    /// encoding with correct tag for `ListProcesses`.
    #[test]
    fn process_list_protocol() {
        let request = ListProcessesRequest {};
        let encoded = encode_list_processes_request(&request);

        // Must use tag-based protobuf framing
        assert!(!encoded.is_empty());
        assert_eq!(
            encoded[0],
            PrivilegedMessageType::ListProcesses.tag(),
            "ListProcesses must use tag 5"
        );

        // Payload must be protobuf, not JSON (INV-0001)
        if encoded.len() > 1 {
            assert_ne!(encoded[1], b'{', "must be protobuf, not JSON");
        }

        // Verify roundtrip: encode then decode
        let decoded = ListProcessesRequest::decode_bounded(&encoded[1..], &DecodeConfig::default())
            .expect("should decode successfully");
        // ListProcessesRequest has no fields, just validate it decodes
        let _ = decoded;
    }

    /// IT-00342-02: Verifies that status command uses `OperatorClient` protocol
    /// encoding with correct tag for `ProcessStatus`.
    #[test]
    fn process_status_protocol() {
        let request = ProcessStatusRequest {
            name: "test-process".to_string(),
        };
        let encoded = encode_process_status_request(&request);

        assert!(!encoded.is_empty());
        assert_eq!(
            encoded[0],
            PrivilegedMessageType::ProcessStatus.tag(),
            "ProcessStatus must use tag 6"
        );

        // Verify roundtrip
        let decoded = ProcessStatusRequest::decode_bounded(&encoded[1..], &DecodeConfig::default())
            .expect("should decode successfully");
        assert_eq!(decoded.name, "test-process");
    }

    /// IT-00342-03: Verifies that start command uses `OperatorClient` protocol
    /// encoding with correct tag for `StartProcess`.
    #[test]
    fn process_start_protocol() {
        let request = StartProcessRequest {
            name: "my-app".to_string(),
        };
        let encoded = encode_start_process_request(&request);

        assert!(!encoded.is_empty());
        assert_eq!(
            encoded[0],
            PrivilegedMessageType::StartProcess.tag(),
            "StartProcess must use tag 7"
        );

        let decoded = StartProcessRequest::decode_bounded(&encoded[1..], &DecodeConfig::default())
            .expect("should decode successfully");
        assert_eq!(decoded.name, "my-app");
    }

    /// IT-00342-04: Verifies that stop command uses `OperatorClient` protocol
    /// encoding with correct tag for `StopProcess`.
    #[test]
    fn process_stop_protocol() {
        let request = StopProcessRequest {
            name: "my-app".to_string(),
        };
        let encoded = encode_stop_process_request(&request);

        assert!(!encoded.is_empty());
        assert_eq!(
            encoded[0],
            PrivilegedMessageType::StopProcess.tag(),
            "StopProcess must use tag 8"
        );

        let decoded = StopProcessRequest::decode_bounded(&encoded[1..], &DecodeConfig::default())
            .expect("should decode successfully");
        assert_eq!(decoded.name, "my-app");
    }

    /// Verifies that restart command uses correct protocol tag.
    #[test]
    fn process_restart_protocol() {
        let request = RestartProcessRequest {
            name: "my-app".to_string(),
        };
        let encoded = encode_restart_process_request(&request);

        assert!(!encoded.is_empty());
        assert_eq!(
            encoded[0],
            PrivilegedMessageType::RestartProcess.tag(),
            "RestartProcess must use tag 9"
        );

        let decoded =
            RestartProcessRequest::decode_bounded(&encoded[1..], &DecodeConfig::default())
                .expect("should decode successfully");
        assert_eq!(decoded.name, "my-app");
    }

    /// Verifies that reload command uses correct protocol tag.
    #[test]
    fn process_reload_protocol() {
        let request = ReloadProcessRequest {
            name: "my-app".to_string(),
        };
        let encoded = encode_reload_process_request(&request);

        assert!(!encoded.is_empty());
        assert_eq!(
            encoded[0],
            PrivilegedMessageType::ReloadProcess.tag(),
            "ReloadProcess must use tag 10"
        );

        let decoded = ReloadProcessRequest::decode_bounded(&encoded[1..], &DecodeConfig::default())
            .expect("should decode successfully");
        assert_eq!(decoded.name, "my-app");
    }

    /// Verifies all process management responses can be decoded from
    /// tag-prefixed frames.
    #[test]
    fn process_response_decode_roundtrip() {
        use prost::Message;

        // ListProcessesResponse with ProcessInfo
        let resp = ListProcessesResponse {
            processes: vec![apm2_daemon::protocol::ProcessInfo {
                name: "test".to_string(),
                state: ProcessStateEnum::ProcessStateRunning as i32,
                instances: 2,
                running_instances: 1,
                pid: Some(1234),
                uptime_secs: Some(3600),
                exit_code: None,
            }],
        };
        let mut buf = vec![PrivilegedMessageType::ListProcesses.tag()];
        resp.encode(&mut buf).expect("encode");
        let decoded = ListProcessesResponse::decode_bounded(&buf[1..], &DecodeConfig::default())
            .expect("decode");
        assert_eq!(decoded.processes.len(), 1);
        assert_eq!(decoded.processes[0].name, "test");
        assert_eq!(decoded.processes[0].running_instances, 1);

        // ProcessStatusResponse
        let resp = ProcessStatusResponse {
            info: Some(apm2_daemon::protocol::ProcessInfo {
                name: "worker".to_string(),
                state: ProcessStateEnum::ProcessStateStopped as i32,
                instances: 1,
                running_instances: 0,
                pid: None,
                uptime_secs: None,
                exit_code: Some(0),
            }),
            restart_count: 3,
            cpu_percent: Some(12.5),
            memory_bytes: Some(1024 * 1024),
            command: "python".to_string(),
            cwd: Some("/app".to_string()),
        };
        let mut buf = vec![PrivilegedMessageType::ProcessStatus.tag()];
        resp.encode(&mut buf).expect("encode");
        let decoded = ProcessStatusResponse::decode_bounded(&buf[1..], &DecodeConfig::default())
            .expect("decode");
        assert_eq!(decoded.restart_count, 3);
        assert_eq!(decoded.info.unwrap().name, "worker");
    }

    /// Verifies that log streaming returns appropriate error when session
    /// token is not available.
    #[test]
    fn process_logs_requires_session_token() {
        let result = logs(Path::new("/tmp/test.sock"), "test", 100, false);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("session token"),
            "error should mention session token requirement"
        );
    }
}
