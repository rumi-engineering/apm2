//! `run_push` pipeline: evidence gates, git push, dispatch reviews, project.

use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use super::evidence::run_evidence_gates;
use super::projection::{projection_state_done, projection_state_failed, run_project_inner};
use super::types::{ReviewRunType, apm2_home_dir, now_iso8601};
use crate::exit_codes::codes as exit_codes;

// ── Projection log helpers ──────────────────────────────────────────────────

fn projection_log_path(pr_number: u32) -> Result<PathBuf, String> {
    let dir = apm2_home_dir()?.join("projection");
    fs::create_dir_all(&dir).map_err(|e| format!("failed to create projection dir: {e}"))?;
    Ok(dir.join(format!("pr{pr_number}.log")))
}

fn write_projection_line(file: &mut File, line: &str) {
    let _ = writeln!(file, "{line}");
}

fn emit_terminal_line(file: &mut File, sha: &str, success: bool, reason: Option<&str>) {
    let ts = now_iso8601();
    let terminal = if success { "success" } else { "failure" };
    let mut line = format!("ts={ts} sha={sha} terminal={terminal}");
    if let Some(r) = reason {
        use std::fmt::Write as _;
        let _ = write!(line, " reason={r}");
    }
    write_projection_line(file, &line);
}

// ── run_push entry point ────────────────────────────────────────────────────

pub fn run_push(repo: &str, remote: &str, branch: Option<&str>, max_wait: u64) -> u8 {
    if max_wait == 0 {
        eprintln!("ERROR: max_wait_seconds must be > 0");
        return exit_codes::GENERIC_ERROR;
    }

    let branch = if let Some(b) = branch {
        b.to_string()
    } else {
        let output = Command::new("git")
            .args(["rev-parse", "--abbrev-ref", "HEAD"])
            .output();
        match output {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
            _ => {
                eprintln!("ERROR: failed to resolve current branch");
                return exit_codes::GENERIC_ERROR;
            },
        }
    };

    let sha = match Command::new("git").args(["rev-parse", "HEAD"]).output() {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        _ => {
            eprintln!("ERROR: failed to resolve HEAD SHA");
            return exit_codes::GENERIC_ERROR;
        },
    };

    let pr_number = match Command::new("gh")
        .args([
            "pr",
            "list",
            "--repo",
            repo,
            "--head",
            &branch,
            "--json",
            "number",
            "--jq",
            ".[0].number",
        ])
        .output()
    {
        Ok(o) if o.status.success() => {
            let num_str = String::from_utf8_lossy(&o.stdout).trim().to_string();
            num_str.parse::<u32>().unwrap_or(0)
        },
        _ => 0,
    };

    if pr_number == 0 {
        eprintln!("ERROR: no open PR found for branch `{branch}` in repo `{repo}`");
        return exit_codes::GENERIC_ERROR;
    }

    let pr_url = format!("https://github.com/{repo}/pull/{pr_number}");
    eprintln!("fac push: PR #{pr_number} sha={sha} branch={branch}");

    let log_path = match projection_log_path(pr_number) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("ERROR: {e}");
            return exit_codes::GENERIC_ERROR;
        },
    };

    if log_path.exists() {
        if let Ok(meta) = fs::metadata(&log_path) {
            if meta.len() > 1_048_576 {
                let backup = log_path.with_extension("log.1");
                let _ = fs::rename(&log_path, &backup);
            }
        }
    }

    let mut projection_file = match File::create(&log_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("ERROR: failed to create projection log: {e}");
            return exit_codes::GENERIC_ERROR;
        },
    };

    let workspace_root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    match run_evidence_gates(&workspace_root, &sha, Some(&mut projection_file)) {
        Ok(true) => {
            eprintln!("fac push: all evidence gates passed");
        },
        Ok(false) => {
            eprintln!("ERROR: evidence gates failed — fix before pushing");
            emit_terminal_line(
                &mut projection_file,
                &sha,
                false,
                Some("evidence_gate_failure"),
            );
            return exit_codes::GENERIC_ERROR;
        },
        Err(e) => {
            eprintln!("ERROR: evidence gate error: {e}");
            emit_terminal_line(
                &mut projection_file,
                &sha,
                false,
                Some("evidence_gate_error"),
            );
            return exit_codes::GENERIC_ERROR;
        },
    }

    let push_output = Command::new("git").args(["push", remote, &branch]).output();
    match push_output {
        Ok(o) if o.status.success() => {
            eprintln!("fac push: git push succeeded");
        },
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            eprintln!("ERROR: git push failed: {stderr}");
            emit_terminal_line(&mut projection_file, &sha, false, Some("git_push_failed"));
            return exit_codes::GENERIC_ERROR;
        },
        Err(e) => {
            eprintln!("ERROR: failed to execute git push: {e}");
            emit_terminal_line(&mut projection_file, &sha, false, Some("git_push_error"));
            return exit_codes::GENERIC_ERROR;
        },
    }

    match super::run_dispatch_inner(&pr_url, ReviewRunType::All, Some(&sha)) {
        Ok(dispatch) => {
            eprintln!(
                "fac push: reviews dispatched (epoch={})",
                dispatch.dispatch_epoch
            );

            let deadline = Instant::now() + Duration::from_secs(max_wait);
            let mut after_seq = 0_u64;

            loop {
                match run_project_inner(
                    pr_number,
                    Some(&sha),
                    Some(dispatch.dispatch_epoch),
                    after_seq,
                ) {
                    Ok(projection) => {
                        write_projection_line(&mut projection_file, &projection.line);
                        println!("{}", projection.line);

                        for error in &projection.errors {
                            eprintln!(
                                "ERROR ts={} event={} review={} seq={} detail={}",
                                error.ts, error.event, error.review_type, error.seq, error.detail
                            );
                        }
                        after_seq = projection.last_seq;

                        if projection.terminal_failure {
                            emit_terminal_line(
                                &mut projection_file,
                                &sha,
                                false,
                                Some("terminal_failure"),
                            );
                            return exit_codes::GENERIC_ERROR;
                        }
                        if projection_state_failed(&projection.security) {
                            emit_terminal_line(
                                &mut projection_file,
                                &sha,
                                false,
                                Some("security_failure"),
                            );
                            return exit_codes::GENERIC_ERROR;
                        }
                        if projection_state_failed(&projection.quality) {
                            emit_terminal_line(
                                &mut projection_file,
                                &sha,
                                false,
                                Some("quality_failure"),
                            );
                            return exit_codes::GENERIC_ERROR;
                        }
                        if projection_state_done(&projection.security)
                            && projection_state_done(&projection.quality)
                        {
                            emit_terminal_line(&mut projection_file, &sha, true, None);
                            return exit_codes::SUCCESS;
                        }
                    },
                    Err(e) => {
                        eprintln!("ERROR: projection failed: {e}");
                    },
                }

                if Instant::now() >= deadline {
                    emit_terminal_line(&mut projection_file, &sha, false, Some("timeout"));
                    return exit_codes::GENERIC_ERROR;
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        },
        Err(e) => {
            eprintln!("ERROR: review dispatch failed: {e}");
            emit_terminal_line(&mut projection_file, &sha, false, Some("dispatch_failed"));
            exit_codes::GENERIC_ERROR
        },
    }
}
