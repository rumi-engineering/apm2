//! Common benchmark fixtures and utilities.
//!
//! Provides shared test data creation functions used across benchmarks.

#![allow(dead_code)]
#![allow(clippy::cast_possible_truncation)]

use std::collections::HashMap;

use apm2_core::ipc::{
    ErrorCode, InstanceInfo, IpcRequest, IpcResponse, LogEntry, ProcessInfo, ProcessSummary,
};
use apm2_core::process::{ProcessId, ProcessSpec, ProcessState};
use chrono::{TimeZone, Utc};

/// Create a process spec with a configurable number of environment variables.
pub fn create_process_spec(name: &str, env_count: usize) -> ProcessSpec {
    let mut builder = ProcessSpec::builder()
        .name(name)
        .command("/usr/bin/echo")
        .args(["hello", "world"])
        .cwd("/tmp")
        .instances(1);

    for i in 0..env_count {
        builder = builder.env(format!("VAR_{i}"), format!("value_{i}"));
    }

    builder.build()
}

/// Create a batch of process specs for supervisor benchmarks.
pub fn create_process_specs(count: usize) -> Vec<ProcessSpec> {
    (0..count)
        .map(|i| create_process_spec(&format!("process-{i}"), 5))
        .collect()
}

/// Create sample IPC requests of various types.
pub fn create_ipc_requests() -> Vec<(&'static str, IpcRequest)> {
    vec![
        ("ping", IpcRequest::Ping),
        ("status", IpcRequest::Status),
        ("list_processes", IpcRequest::ListProcesses),
        (
            "get_process",
            IpcRequest::GetProcess {
                name: "my-process".to_string(),
            },
        ),
        (
            "start_process",
            IpcRequest::StartProcess {
                name: "my-process".to_string(),
            },
        ),
        (
            "stop_process",
            IpcRequest::StopProcess {
                name: "my-process".to_string(),
            },
        ),
        (
            "tail_logs",
            IpcRequest::TailLogs {
                name: Some("my-process".to_string()),
                lines: 100,
                follow: false,
            },
        ),
        ("list_credentials", IpcRequest::ListCredentials),
        (
            "add_credential",
            IpcRequest::AddCredential {
                profile_id: "claude-work".to_string(),
                provider: "anthropic".to_string(),
                auth_method: "api_key".to_string(),
            },
        ),
        ("shutdown", IpcRequest::Shutdown),
    ]
}

/// Create sample IPC responses of various types.
pub fn create_ipc_responses() -> Vec<(&'static str, IpcResponse)> {
    vec![
        (
            "pong",
            IpcResponse::Pong {
                version: "0.1.0".to_string(),
                uptime_secs: 3600,
            },
        ),
        (
            "status",
            IpcResponse::Status {
                version: "0.1.0".to_string(),
                pid: 12345,
                uptime_secs: 86400,
                process_count: 10,
                running_instances: 25,
            },
        ),
        (
            "process_list",
            IpcResponse::ProcessList {
                processes: create_process_summaries(10),
            },
        ),
        (
            "process_details",
            IpcResponse::ProcessDetails {
                process: create_process_info(),
            },
        ),
        (
            "ok",
            IpcResponse::Ok {
                message: Some("Operation completed successfully".to_string()),
            },
        ),
        (
            "error",
            IpcResponse::Error {
                code: ErrorCode::ProcessNotFound,
                message: "Process 'missing' not found".to_string(),
            },
        ),
        (
            "log_lines",
            IpcResponse::LogLines {
                lines: create_log_entries(50),
            },
        ),
    ]
}

/// Create sample process summaries.
pub fn create_process_summaries(count: usize) -> Vec<ProcessSummary> {
    (0..count)
        .map(|i| ProcessSummary {
            name: format!("process-{i}"),
            instances: 3,
            running: 3,
            status: ProcessState::Running,
            cpu_percent: Some(15.5),
            memory_bytes: Some(52_428_800), // 50 MB
            uptime_secs: Some(3600),
            restart_count: 2,
        })
        .collect()
}

/// Create a sample process info.
pub fn create_process_info() -> ProcessInfo {
    ProcessInfo {
        name: "my-process".to_string(),
        id: ProcessId::new(),
        command: "/usr/bin/node".to_string(),
        args: vec![
            "server.js".to_string(),
            "--port".to_string(),
            "3000".to_string(),
        ],
        cwd: Some("/app".to_string()),
        instances: 3,
        instance_details: (0..3)
            .map(|i| InstanceInfo {
                index: i,
                pid: Some(10000 + i),
                state: ProcessState::Running,
                cpu_percent: Some(12.5),
                memory_bytes: Some(26_214_400), // 25 MB
                uptime_secs: Some(7200),
                restart_count: 1,
            })
            .collect(),
        credential_profile: Some("claude-prod".to_string()),
    }
}

/// Create sample log entries.
pub fn create_log_entries(count: usize) -> Vec<LogEntry> {
    (0..count)
        .map(|i| LogEntry {
            timestamp: Utc.with_ymd_and_hms(2026, 1, 15, 12, 0, 0).unwrap(),
            process_name: "my-process".to_string(),
            instance: (i % 3) as u32,
            stream: if i % 2 == 0 { "stdout" } else { "stderr" }.to_string(),
            content: format!(
                "[INFO] Processing request {i} - status: ok, latency: {}ms",
                i * 10
            ),
        })
        .collect()
}

/// Create sample environment variables map.
#[allow(dead_code)]
pub fn create_env_map(count: usize) -> HashMap<String, String> {
    (0..count)
        .map(|i| {
            (
                format!("ENV_VAR_{i}"),
                format!("value_{i}_with_some_content"),
            )
        })
        .collect()
}
