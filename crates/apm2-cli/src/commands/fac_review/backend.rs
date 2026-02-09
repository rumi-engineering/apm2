//! Backend command builders for Codex and Gemini review processes.

use std::fs;
use std::path::Path;

use super::types::{ReviewBackend, sh_quote};

fn build_script_wrapper_command(log_path: &Path, inner_command: &str, append: bool) -> String {
    let append_flag = if append { " -a" } else { "" };
    let log_q = sh_quote(&log_path.display().to_string());
    let inner_q = sh_quote(inner_command);
    format!("script -q{append_flag} {log_q} -c {inner_q}")
}

pub fn build_gemini_script_command(prompt_path: &Path, log_path: &Path, model: &str) -> String {
    let prompt_q = sh_quote(&prompt_path.display().to_string());
    let model_q = sh_quote(model);
    let inner = format!("gemini -m {model_q} -y -o stream-json -p \"$(cat {prompt_q})\"");
    build_script_wrapper_command(log_path, &inner, false)
}

pub fn build_script_command_for_backend(
    backend: ReviewBackend,
    prompt_path: &Path,
    log_path: &Path,
    model: &str,
    output_last_message_path: Option<&Path>,
) -> String {
    match backend {
        ReviewBackend::Codex => {
            let prompt_q = sh_quote(&prompt_path.display().to_string());
            let model_q = sh_quote(model);
            let output_flag = output_last_message_path.map_or_else(String::new, |path| {
                let capture_q = sh_quote(&path.display().to_string());
                format!("--output-last-message {capture_q} ")
            });
            let inner = format!(
                "codex exec --model {model_q} --dangerously-bypass-approvals-and-sandbox --json {output_flag}< {prompt_q}"
            );
            build_script_wrapper_command(log_path, &inner, false)
        },
        ReviewBackend::Gemini => build_gemini_script_command(prompt_path, log_path, model),
    }
}

pub fn build_resume_command_for_backend(
    backend: ReviewBackend,
    model: &str,
    sha_update_msg: &str,
) -> String {
    let msg_q = sh_quote(sha_update_msg);
    match backend {
        ReviewBackend::Codex => format!(
            "codex exec resume --last --dangerously-bypass-approvals-and-sandbox --json {msg_q}"
        ),
        ReviewBackend::Gemini => {
            let model_q = sh_quote(model);
            format!("gemini -m {model_q} -y --resume latest -p {msg_q}")
        },
    }
}

pub fn build_resume_script_command_for_backend(
    backend: ReviewBackend,
    log_path: &Path,
    model: &str,
    sha_update_msg: &str,
) -> String {
    let inner = build_resume_command_for_backend(backend, model, sha_update_msg);
    build_script_wrapper_command(log_path, &inner, true)
}

pub fn build_sha_update_message(pr_number: u32, old_sha: &str, new_sha: &str) -> String {
    format!(
        "CRITICAL: The PR HEAD has moved from {old_sha} to {new_sha}. Re-read the diff via 'gh pr diff {pr_number}'. Update your review and post a new comment targeting SHA {new_sha}. Your full prior analysis is preserved in this session."
    )
}

pub fn build_prompt_content(
    prompt_template_path: &Path,
    pr_url: &str,
    head_sha: &str,
    owner: &str,
    repo: &str,
) -> Result<String, String> {
    let template = fs::read_to_string(prompt_template_path).map_err(|err| {
        format!(
            "failed to read prompt template {}: {err}",
            prompt_template_path.display()
        )
    })?;

    Ok(template
        .replace("$PR_URL", pr_url)
        .replace("$HEAD_SHA", head_sha)
        .replace(concat!("{", "owner", "}"), owner)
        .replace(concat!("{", "repo", "}"), repo))
}
