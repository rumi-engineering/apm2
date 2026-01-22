//! IPC request handlers.
//!
//! Implements handlers for each IPC request type.

use std::time::Duration;

use apm2_core::ipc::{
    ErrorCode, InstanceInfo, IpcRequest, IpcResponse, ProcessInfo, ProcessSummary,
};
use apm2_core::process::ProcessState;
use apm2_core::process::runner::ProcessRunner;
use tracing::{info, warn};

use crate::state::SharedState;

/// Daemon version (from Cargo.toml).
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default graceful shutdown timeout.
const DEFAULT_STOP_TIMEOUT: Duration = Duration::from_secs(10);

/// Dispatch an IPC request to the appropriate handler.
pub async fn dispatch(request: IpcRequest, state: &SharedState) -> IpcResponse {
    match request {
        IpcRequest::Ping => handle_ping(state),
        IpcRequest::Status => handle_status(state).await,
        IpcRequest::ListProcesses => handle_list(state).await,
        IpcRequest::GetProcess { name } => handle_get_process(state, &name).await,
        IpcRequest::StartProcess { name } => handle_start(state, &name).await,
        IpcRequest::StopProcess { name } => handle_stop(state, &name).await,
        IpcRequest::RestartProcess { name } => handle_restart(state, &name).await,
        IpcRequest::Shutdown => handle_shutdown(state),
        _ => IpcResponse::Error {
            code: ErrorCode::NotSupported,
            message: "Not implemented yet".into(),
        },
    }
}

/// Handle ping request.
fn handle_ping(state: &SharedState) -> IpcResponse {
    IpcResponse::Pong {
        version: VERSION.to_string(),
        uptime_secs: state.uptime_secs(),
    }
}

/// Handle status request.
#[allow(clippy::cast_possible_truncation)] // Process counts won't exceed u32
async fn handle_status(state: &SharedState) -> IpcResponse {
    let inner = state.read().await;

    let process_count = inner.supervisor.process_count() as u32;
    let running_instances = inner.supervisor.running_count() as u32;

    IpcResponse::Status {
        version: VERSION.to_string(),
        pid: std::process::id(),
        uptime_secs: state.uptime_secs(),
        process_count,
        running_instances,
    }
}

/// Handle list processes request.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // Counts/uptime won't overflow
async fn handle_list(state: &SharedState) -> IpcResponse {
    let inner = state.read().await;

    let mut processes = Vec::new();

    for spec in inner.supervisor.specs() {
        let handles = inner.supervisor.get_handles(&spec.name);

        let running = handles.iter().filter(|h| h.state.is_running()).count() as u32;

        // Determine overall status
        let status = if running > 0 {
            ProcessState::Running
        } else {
            // Get the first handle's state if available
            handles
                .first()
                .map_or(ProcessState::Stopped { exit_code: None }, |h| {
                    h.state.clone()
                })
        };

        // Sum up CPU and memory usage
        let cpu_percent: Option<f32> = handles
            .iter()
            .filter_map(|h| h.cpu_percent)
            .reduce(|a, b| a + b);

        let memory_bytes: Option<u64> = handles
            .iter()
            .filter_map(|h| h.memory_bytes)
            .reduce(|a, b| a + b);

        // Get uptime of oldest running instance
        let uptime_secs: Option<u64> = handles
            .iter()
            .filter(|h| h.state.is_running())
            .filter_map(|h| h.uptime_secs())
            .max()
            .map(|s| s as u64);

        // Sum restart counts
        let restart_count: u32 = handles.iter().map(|h| h.restart_count).sum();

        processes.push(ProcessSummary {
            name: spec.name.clone(),
            instances: spec.instances,
            running,
            status,
            cpu_percent,
            memory_bytes,
            uptime_secs,
            restart_count,
        });
    }

    IpcResponse::ProcessList { processes }
}

/// Handle get process details request.
#[allow(clippy::cast_sign_loss)] // Uptime won't be negative after max(0)
async fn handle_get_process(state: &SharedState, name: &str) -> IpcResponse {
    let inner = state.read().await;

    let Some(spec) = inner.supervisor.get_spec(name) else {
        return IpcResponse::Error {
            code: ErrorCode::ProcessNotFound,
            message: format!("Process '{name}' not found"),
        };
    };

    let handles = inner.supervisor.get_handles(name);

    let instance_details: Vec<InstanceInfo> = handles
        .iter()
        .map(|h| InstanceInfo {
            index: h.instance,
            pid: h.pid,
            state: h.state.clone(),
            cpu_percent: h.cpu_percent,
            memory_bytes: h.memory_bytes,
            uptime_secs: h.uptime_secs().map(|s| s as u64),
            restart_count: h.restart_count,
        })
        .collect();

    let credential_profile = spec.credentials.as_ref().map(|c| c.profile.clone());

    IpcResponse::ProcessDetails {
        process: ProcessInfo {
            name: spec.name.clone(),
            id: spec.id,
            command: spec.command.clone(),
            args: spec.args.clone(),
            cwd: spec.cwd.as_ref().map(|p| p.display().to_string()),
            instances: spec.instances,
            instance_details,
            credential_profile,
        },
    }
}

/// Handle start process request.
async fn handle_start(state: &SharedState, name: &str) -> IpcResponse {
    let mut inner = state.write().await;

    let Some(spec) = inner.supervisor.get_spec(name).cloned() else {
        return IpcResponse::Error {
            code: ErrorCode::ProcessNotFound,
            message: format!("Process '{name}' not found"),
        };
    };

    // Check if already running
    let handles = inner.supervisor.get_handles(name);
    let running = handles.iter().filter(|h| h.state.is_running()).count();
    if running > 0 {
        return IpcResponse::Error {
            code: ErrorCode::ProcessAlreadyRunning,
            message: format!("Process '{name}' is already running"),
        };
    }

    info!("Starting process '{}'", name);

    // Start all instances
    let mut started = 0;
    let mut last_error = None;

    for i in 0..spec.instances {
        let mut runner = ProcessRunner::new(spec.clone(), i);

        match runner.start() {
            Ok(()) => {
                // Update supervisor state
                if let Some(pid) = runner.pid() {
                    inner.supervisor.update_pid(name, i, Some(pid));
                }
                inner
                    .supervisor
                    .update_state(name, i, ProcessState::Running);

                // Store the runner
                inner.insert_runner(spec.id, i, runner);
                started += 1;
            },
            Err(e) => {
                warn!("Failed to start instance {} of '{}': {}", i, name, e);
                last_error = Some(e.to_string());
            },
        }
    }

    if started == 0 {
        IpcResponse::Error {
            code: ErrorCode::InternalError,
            message: last_error.unwrap_or_else(|| "Failed to start any instances".into()),
        }
    } else if started < spec.instances {
        IpcResponse::Ok {
            message: Some(format!(
                "Started {} of {} instances (some failed)",
                started, spec.instances
            )),
        }
    } else {
        IpcResponse::Ok {
            message: Some(format!("Process '{name}' started")),
        }
    }
}

/// Handle stop process request.
async fn handle_stop(state: &SharedState, name: &str) -> IpcResponse {
    // First, get the spec and check if running
    let (spec_id, instances) = {
        let inner = state.read().await;

        let Some(spec) = inner.supervisor.get_spec(name) else {
            return IpcResponse::Error {
                code: ErrorCode::ProcessNotFound,
                message: format!("Process '{name}' not found"),
            };
        };

        let handles = inner.supervisor.get_handles(name);
        let running = handles.iter().filter(|h| h.state.is_running()).count();
        if running == 0 {
            return IpcResponse::Error {
                code: ErrorCode::ProcessNotRunning,
                message: format!("Process '{name}' is not running"),
            };
        }

        (spec.id, spec.instances)
    };

    info!("Stopping process '{}'", name);

    // Stop all instances
    // We need to take the runners out to call async stop on them
    let mut runners_to_stop = Vec::new();
    {
        let mut inner = state.write().await;
        for i in 0..instances {
            if let Some(runner) = inner.remove_runner(spec_id, i) {
                runners_to_stop.push((i, runner));
            }
        }
        // Mark as stopping in supervisor
        for i in 0..instances {
            inner
                .supervisor
                .update_state(name, i, ProcessState::Stopping);
        }
    }

    // Stop each runner
    let mut stopped = 0;
    for (i, mut runner) in runners_to_stop {
        if runner.state().is_running() {
            if let Err(e) = runner.stop(DEFAULT_STOP_TIMEOUT).await {
                warn!("Error stopping instance {} of '{}': {}", i, name, e);
            }
        }
        stopped += 1;

        // Update supervisor state
        let mut inner = state.write().await;
        inner
            .supervisor
            .update_state(name, i, ProcessState::Stopped { exit_code: None });
        inner.supervisor.update_pid(name, i, None);
    }

    IpcResponse::Ok {
        message: Some(format!("Stopped {stopped} instance(s) of '{name}'")),
    }
}

/// Handle restart process request.
async fn handle_restart(state: &SharedState, name: &str) -> IpcResponse {
    // Check if process exists
    {
        let inner = state.read().await;
        if inner.supervisor.get_spec(name).is_none() {
            return IpcResponse::Error {
                code: ErrorCode::ProcessNotFound,
                message: format!("Process '{name}' not found"),
            };
        }
    }

    info!("Restarting process '{}'", name);

    // Stop first (if running)
    let stop_result = handle_stop(state, name).await;
    match &stop_result {
        IpcResponse::Ok { .. }
        | IpcResponse::Error {
            code: ErrorCode::ProcessNotRunning,
            ..
        } => {
            // Ok or not running is fine for restart
        },
        _ => return stop_result,
    }

    // Then start
    handle_start(state, name).await
}

/// Handle shutdown request.
fn handle_shutdown(state: &SharedState) -> IpcResponse {
    info!("Shutdown requested via IPC");
    state.request_shutdown();
    IpcResponse::Ok {
        message: Some("Daemon shutting down".into()),
    }
}
