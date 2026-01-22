//! Process management commands.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

use anyhow::{Context, Result, bail};
use apm2_core::ipc::{IpcRequest, IpcResponse, ProcessSummary};

/// Start a process.
pub fn start(socket_path: &Path, name: &str) -> Result<()> {
    let request = IpcRequest::StartProcess {
        name: name.to_string(),
    };

    match send_request(socket_path, &request)? {
        IpcResponse::Ok { message } => {
            println!(
                "Started '{name}'{}",
                message.map(|m| format!(": {m}")).unwrap_or_default()
            );
        },
        IpcResponse::Error { code, message } => {
            bail!("Failed to start '{name}': {message} ({code:?})");
        },
        _ => bail!("Unexpected response"),
    }

    Ok(())
}

/// Stop a process.
pub fn stop(socket_path: &Path, name: &str) -> Result<()> {
    let request = IpcRequest::StopProcess {
        name: name.to_string(),
    };

    match send_request(socket_path, &request)? {
        IpcResponse::Ok { message } => {
            println!(
                "Stopped '{name}'{}",
                message.map(|m| format!(": {m}")).unwrap_or_default()
            );
        },
        IpcResponse::Error { code, message } => {
            bail!("Failed to stop '{name}': {message} ({code:?})");
        },
        _ => bail!("Unexpected response"),
    }

    Ok(())
}

/// Restart a process.
pub fn restart(socket_path: &Path, name: &str) -> Result<()> {
    let request = IpcRequest::RestartProcess {
        name: name.to_string(),
    };

    match send_request(socket_path, &request)? {
        IpcResponse::Ok { message } => {
            println!(
                "Restarted '{name}'{}",
                message.map(|m| format!(": {m}")).unwrap_or_default()
            );
        },
        IpcResponse::Error { code, message } => {
            bail!("Failed to restart '{name}': {message} ({code:?})");
        },
        _ => bail!("Unexpected response"),
    }

    Ok(())
}

/// Graceful reload (rolling restart).
pub fn reload(socket_path: &Path, name: &str) -> Result<()> {
    let request = IpcRequest::ReloadProcess {
        name: name.to_string(),
    };

    match send_request(socket_path, &request)? {
        IpcResponse::Ok { message } => {
            println!(
                "Reloading '{name}'{}",
                message.map(|m| format!(": {m}")).unwrap_or_default()
            );
        },
        IpcResponse::Error { code, message } => {
            bail!("Failed to reload '{name}': {message} ({code:?})");
        },
        _ => bail!("Unexpected response"),
    }

    Ok(())
}

/// List all processes.
pub fn list(socket_path: &Path) -> Result<()> {
    let request = IpcRequest::ListProcesses;

    match send_request(socket_path, &request)? {
        IpcResponse::ProcessList { processes } => {
            print_process_table(&processes);
        },
        IpcResponse::Error { code, message } => {
            bail!("Failed to list processes: {message} ({code:?})");
        },
        _ => bail!("Unexpected response"),
    }

    Ok(())
}

/// Show process details.
pub fn status(socket_path: &Path, name: &str) -> Result<()> {
    let request = IpcRequest::GetProcess {
        name: name.to_string(),
    };

    match send_request(socket_path, &request)? {
        IpcResponse::ProcessDetails { process } => {
            println!("Name:        {}", process.name);
            println!("ID:          {}", process.id);
            println!(
                "Command:     {} {}",
                process.command,
                process.args.join(" ")
            );
            if let Some(cwd) = &process.cwd {
                println!("Working Dir: {cwd}");
            }
            println!("Instances:   {}", process.instances);
            if let Some(cred) = &process.credential_profile {
                println!("Credentials: {cred}");
            }
            println!();
            println!("Instance Details:");
            for inst in &process.instance_details {
                println!(
                    "  [{index}] PID: {pid:>6}  State: {state:<12}  CPU: {cpu:>5.1}%  Mem: {mem:>8}  Uptime: {uptime:>8}  Restarts: {restarts}",
                    index = inst.index,
                    pid = inst.pid.map_or_else(|| "-".to_string(), |p| p.to_string()),
                    state = inst.state.to_string(),
                    cpu = inst.cpu_percent.unwrap_or(0.0),
                    mem = format_bytes(inst.memory_bytes.unwrap_or(0)),
                    uptime = format_duration(inst.uptime_secs.unwrap_or(0)),
                    restarts = inst.restart_count,
                );
            }
        },
        IpcResponse::Error { code, message } => {
            bail!("Failed to get status for '{name}': {message} ({code:?})");
        },
        _ => bail!("Unexpected response"),
    }

    Ok(())
}

/// Tail process logs.
pub fn logs(socket_path: &Path, name: &str, lines: u32, follow: bool) -> Result<()> {
    let request = IpcRequest::TailLogs {
        name: Some(name.to_string()),
        lines,
        follow,
    };

    match send_request(socket_path, &request)? {
        IpcResponse::LogLines { lines } => {
            for line in lines {
                println!(
                    "[{}] [{}:{}] [{}] {}",
                    line.timestamp.format("%Y-%m-%d %H:%M:%S"),
                    line.process_name,
                    line.instance,
                    line.stream,
                    line.content
                );
            }
        },
        IpcResponse::Error { code, message } => {
            bail!("Failed to get logs for '{name}': {message} ({code:?})");
        },
        _ => bail!("Unexpected response"),
    }

    Ok(())
}

/// Print process list as a table.
fn print_process_table(processes: &[ProcessSummary]) {
    if processes.is_empty() {
        println!("No processes configured");
        return;
    }

    // Header
    println!(
        "{:<20} {:>8} {:>8} {:<12} {:>8} {:>10} {:>10}",
        "NAME", "RUNNING", "TOTAL", "STATUS", "CPU", "MEM", "UPTIME"
    );
    println!("{}", "-".repeat(78));

    // Rows
    for proc in processes {
        println!(
            "{:<20} {:>8} {:>8} {:<12} {:>7.1}% {:>10} {:>10}",
            truncate(&proc.name, 20),
            proc.running,
            proc.instances,
            proc.status.to_string(),
            proc.cpu_percent.unwrap_or(0.0),
            format_bytes(proc.memory_bytes.unwrap_or(0)),
            format_duration(proc.uptime_secs.unwrap_or(0)),
        );
    }
}

/// Format bytes as human-readable string.
#[allow(clippy::cast_precision_loss)] // Acceptable for human-readable display
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.1}G", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1}M", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1}K", bytes as f64 / KB as f64)
    } else {
        format!("{bytes}B")
    }
}

/// Format duration in seconds as human-readable string.
fn format_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else if secs < 86400 {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    } else {
        format!("{}d {}h", secs / 86400, (secs % 86400) / 3600)
    }
}

/// Truncate string to max length.
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

/// Send an IPC request to the daemon.
fn send_request(socket_path: &Path, request: &IpcRequest) -> Result<IpcResponse> {
    // Connect to daemon
    let mut stream = UnixStream::connect(socket_path)
        .context("failed to connect to daemon socket (is the daemon running?)")?;

    // Send request
    let request_json = serde_json::to_vec(&request)?;
    let framed = apm2_core::ipc::frame_message(&request_json);
    stream.write_all(&framed)?;

    // Read response
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;

    let mut response_buf = vec![0u8; len];
    stream.read_exact(&mut response_buf)?;

    let response: IpcResponse = serde_json::from_slice(&response_buf)?;
    Ok(response)
}
