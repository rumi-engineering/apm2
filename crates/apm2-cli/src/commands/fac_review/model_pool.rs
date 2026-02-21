//! Model selection, fallback logic, and provider slot management.

use std::fs::OpenOptions;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use fs2::FileExt;
use rand::Rng;
use rand::seq::SliceRandom;

use super::types::{
    DEFAULT_PROVIDER_SLOT_COUNT, ModelPoolEntry, PROVIDER_BACKOFF_BASE_SECS,
    PROVIDER_BACKOFF_JITTER_MS, PROVIDER_BACKOFF_MAX_SECS, PROVIDER_SLOT_MAX_WAIT_SECS_DEFAULT,
    PROVIDER_SLOT_POLL_INTERVAL, PROVIDER_SLOT_WAIT_JITTER_MS, ProviderSlotLease, ReviewBackend,
    ReviewModelSelection, apm2_home_dir, ensure_parent_dir,
};

// ── Model pool ──────────────────────────────────────────────────────────────

pub const MODEL_POOL: [ModelPoolEntry; 4] = [
    ModelPoolEntry {
        model: "gemini-3-flash-preview",
        backend: ReviewBackend::Gemini,
    },
    ModelPoolEntry {
        model: "gemini-3.1-pro-preview",
        backend: ReviewBackend::Gemini,
    },
    ModelPoolEntry {
        model: "gpt-5.3-codex",
        backend: ReviewBackend::Codex,
    },
    ModelPoolEntry {
        model: "gpt-5.3-codex-spark",
        backend: ReviewBackend::Codex,
    },
];

pub const GEMINI_ALLOWED_MODELS: [&str; 2] = ["gemini-3-flash-preview", "gemini-3.1-pro-preview"];

// ── Selection ───────────────────────────────────────────────────────────────

#[cfg(test)]
#[must_use]
pub fn is_allowed_gemini_model(model: &str) -> bool {
    GEMINI_ALLOWED_MODELS
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(model.trim()))
}

#[must_use]
pub fn normalize_gemini_model(model: &str) -> &'static str {
    GEMINI_ALLOWED_MODELS
        .iter()
        .copied()
        .find(|candidate| candidate.eq_ignore_ascii_case(model.trim()))
        .unwrap_or("gemini-3-flash-preview")
}

fn normalize_review_model_selection(selection: ReviewModelSelection) -> ReviewModelSelection {
    match selection.backend {
        ReviewBackend::Gemini => ReviewModelSelection {
            model: normalize_gemini_model(&selection.model).to_string(),
            backend: ReviewBackend::Gemini,
        },
        ReviewBackend::Codex | ReviewBackend::ClaudeCode => selection,
    }
}

pub fn select_review_model_random() -> ReviewModelSelection {
    let mut rng = rand::thread_rng();
    let idx = rng.gen_range(0..MODEL_POOL.len());
    let selected = MODEL_POOL[idx];
    ReviewModelSelection {
        model: selected.model.to_string(),
        backend: selected.backend,
    }
}

pub fn select_fallback_model(failed: &str) -> Option<ReviewModelSelection> {
    let candidates: Vec<_> = MODEL_POOL
        .iter()
        .filter(|entry| !entry.model.eq_ignore_ascii_case(failed))
        .collect();
    if candidates.is_empty() {
        return None;
    }
    let idx = rand::thread_rng().gen_range(0..candidates.len());
    let next = candidates[idx];
    Some(ReviewModelSelection {
        model: next.model.to_string(),
        backend: next.backend,
    })
}

pub fn select_cross_family_fallback(failed: &str) -> Option<ReviewModelSelection> {
    let current_backend = MODEL_POOL
        .iter()
        .find(|entry| entry.model.eq_ignore_ascii_case(failed))
        .map(|entry| entry.backend);
    let candidates: Vec<_> = MODEL_POOL
        .iter()
        .filter(|entry| !entry.model.eq_ignore_ascii_case(failed))
        .filter(|entry| current_backend.is_none_or(|backend| entry.backend != backend))
        .collect();
    if !candidates.is_empty() {
        let idx = rand::thread_rng().gen_range(0..candidates.len());
        let selected = candidates[idx];
        return Some(ReviewModelSelection {
            model: selected.model.to_string(),
            backend: selected.backend,
        });
    }
    select_fallback_model(failed)
}

// ── Availability ────────────────────────────────────────────────────────────

pub fn ensure_model_backend_available(
    selection: ReviewModelSelection,
) -> Result<ReviewModelSelection, String> {
    let selection = normalize_review_model_selection(selection);
    if backend_tool_available(selection.backend) {
        return Ok(selection);
    }

    let mut candidates: Vec<_> = MODEL_POOL
        .iter()
        .filter(|entry| !entry.model.eq_ignore_ascii_case(&selection.model))
        .collect();
    candidates.shuffle(&mut rand::thread_rng());
    for entry in candidates {
        let normalized = normalize_review_model_selection(ReviewModelSelection {
            model: entry.model.to_string(),
            backend: entry.backend,
        });
        if backend_tool_available(normalized.backend) {
            return Ok(normalized);
        }
    }

    Err(
        "no configured review backend tool is available (need codex, gemini, and/or claude in PATH)"
            .to_string(),
    )
}

pub fn backend_tool_available(backend: ReviewBackend) -> bool {
    let tool = match backend {
        ReviewBackend::Codex => "codex",
        ReviewBackend::Gemini => "gemini",
        ReviewBackend::ClaudeCode => "claude",
    };
    // Check if the binary is locatable via `which`. This avoids passing
    // untrusted strings through `sh -lc` while remaining portable across
    // tools that may not implement `--version`.
    Command::new("which")
        .arg(tool)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

// ── Provider slots ──────────────────────────────────────────────────────────

pub fn provider_slot_count(backend: ReviewBackend) -> usize {
    let key = match backend {
        ReviewBackend::Codex => "APM2_FAC_CODEX_SLOTS",
        ReviewBackend::Gemini => "APM2_FAC_GEMINI_SLOTS",
        ReviewBackend::ClaudeCode => "APM2_FAC_CLAUDE_CODE_SLOTS",
    };
    std::env::var(key)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|count| *count > 0)
        .unwrap_or(DEFAULT_PROVIDER_SLOT_COUNT)
}

pub fn backoff_before_cross_family_fallback(restart_count: u32) {
    let exponent = restart_count.min(6);
    let scale = 1_u64 << exponent;
    let backoff_secs = PROVIDER_BACKOFF_BASE_SECS
        .saturating_mul(scale)
        .min(PROVIDER_BACKOFF_MAX_SECS);
    let jitter_millis = rand::thread_rng().gen_range(0..=PROVIDER_BACKOFF_JITTER_MS);
    thread::sleep(Duration::from_secs(backoff_secs) + Duration::from_millis(jitter_millis));
}

fn review_provider_slots_dir_path() -> Result<std::path::PathBuf, String> {
    Ok(apm2_home_dir()?.join("review_provider_slots"))
}

fn provider_slot_lock_path(
    backend: ReviewBackend,
    slot_index: usize,
) -> Result<std::path::PathBuf, String> {
    let backend_name = backend.as_str();
    Ok(review_provider_slots_dir_path()?.join(format!("{backend_name}-{slot_index}.lock")))
}

pub fn acquire_provider_slot(backend: ReviewBackend) -> Result<ProviderSlotLease, String> {
    let slots = provider_slot_count(backend);
    let max_wait = std::env::var("APM2_FAC_PROVIDER_SLOT_MAX_WAIT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(PROVIDER_SLOT_MAX_WAIT_SECS_DEFAULT);
    let deadline = Instant::now() + Duration::from_secs(max_wait);
    loop {
        for slot_index in 0..slots {
            let path = provider_slot_lock_path(backend, slot_index)?;
            ensure_parent_dir(&path)?;
            let lock_file = OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .truncate(false)
                .open(&path)
                .map_err(|err| {
                    format!(
                        "failed to open provider slot lock {}: {err}",
                        path.display()
                    )
                })?;
            match FileExt::try_lock_exclusive(&lock_file) {
                Ok(()) => {
                    return Ok(ProviderSlotLease {
                        _lock_file: lock_file,
                    });
                },
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {},
                Err(err) => {
                    return Err(format!(
                        "failed to acquire provider slot lock {}: {err}",
                        path.display()
                    ));
                },
            }
        }

        if Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for {} provider slot after {}s (set APM2_FAC_PROVIDER_SLOT_MAX_WAIT_SECS to adjust)",
                backend.as_str(),
                max_wait
            ));
        }

        let jitter_millis = rand::thread_rng().gen_range(0..=PROVIDER_SLOT_WAIT_JITTER_MS);
        thread::sleep(PROVIDER_SLOT_POLL_INTERVAL + Duration::from_millis(jitter_millis));
    }
}

#[cfg(test)]
mod tests {
    use super::{is_allowed_gemini_model, normalize_gemini_model};

    #[test]
    fn normalize_gemini_model_accepts_allowed_values() {
        assert_eq!(
            normalize_gemini_model("gemini-3-flash-preview"),
            "gemini-3-flash-preview"
        );
        assert_eq!(
            normalize_gemini_model("GEMINI-3.1-PRO-PREVIEW"),
            "gemini-3.1-pro-preview"
        );
    }

    #[test]
    fn normalize_gemini_model_rejects_unknown_values() {
        assert_eq!(
            normalize_gemini_model("gemini-2.5-pro"),
            "gemini-3-flash-preview"
        );
        assert!(!is_allowed_gemini_model("gemini-2.5-pro"));
        assert!(is_allowed_gemini_model("gemini-3-flash-preview"));
        assert!(is_allowed_gemini_model("gemini-3.1-pro-preview"));
    }
}
