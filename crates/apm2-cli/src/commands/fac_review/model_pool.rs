//! Model selection, fallback logic, and provider slot management.

use std::fs::OpenOptions;
use std::process::Command;
use std::thread;
use std::time::Duration;

use fs2::FileExt;
use rand::Rng;

use super::types::{
    DEFAULT_PROVIDER_SLOT_COUNT, ModelPoolEntry, PROVIDER_BACKOFF_BASE_SECS,
    PROVIDER_BACKOFF_JITTER_MS, PROVIDER_BACKOFF_MAX_SECS, PROVIDER_SLOT_POLL_INTERVAL,
    PROVIDER_SLOT_WAIT_JITTER_MS, ProviderSlotLease, ReviewBackend, ReviewModelSelection,
    apm2_home_dir, ensure_parent_dir,
};

// ── Model pool ──────────────────────────────────────────────────────────────

pub const MODEL_POOL: [ModelPoolEntry; 3] = [
    ModelPoolEntry {
        model: "gemini-3-flash-preview",
        backend: ReviewBackend::Gemini,
    },
    ModelPoolEntry {
        model: "gemini-3-pro-preview",
        backend: ReviewBackend::Gemini,
    },
    ModelPoolEntry {
        model: "gpt-5.3-codex",
        backend: ReviewBackend::Codex,
    },
];

// ── Selection ───────────────────────────────────────────────────────────────

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
    let current_idx = MODEL_POOL
        .iter()
        .position(|entry| entry.model.eq_ignore_ascii_case(failed))?;
    let next_idx = (current_idx + 1) % MODEL_POOL.len();
    let next = MODEL_POOL[next_idx];
    Some(ReviewModelSelection {
        model: next.model.to_string(),
        backend: next.backend,
    })
}

pub fn select_cross_family_fallback(failed: &str) -> Option<ReviewModelSelection> {
    let current_idx = MODEL_POOL
        .iter()
        .position(|entry| entry.model.eq_ignore_ascii_case(failed))?;
    let current = MODEL_POOL[current_idx];
    for offset in 1..MODEL_POOL.len() {
        let idx = (current_idx + offset) % MODEL_POOL.len();
        let candidate = MODEL_POOL[idx];
        if candidate.backend != current.backend {
            return Some(ReviewModelSelection {
                model: candidate.model.to_string(),
                backend: candidate.backend,
            });
        }
    }
    select_fallback_model(failed)
}

// ── Availability ────────────────────────────────────────────────────────────

pub fn ensure_model_backend_available(
    selection: ReviewModelSelection,
) -> Result<ReviewModelSelection, String> {
    if backend_tool_available(selection.backend) {
        return Ok(selection);
    }

    let mut candidate = selection;
    for _ in 0..MODEL_POOL.len() {
        let fallback = select_fallback_model(&candidate.model)
            .ok_or_else(|| "could not select fallback model".to_string())?;
        if backend_tool_available(fallback.backend) {
            return Ok(fallback);
        }
        candidate = fallback;
    }

    Err(
        "no configured review backend tool is available (need codex and/or gemini in PATH)"
            .to_string(),
    )
}

pub fn backend_tool_available(backend: ReviewBackend) -> bool {
    let tool = match backend {
        ReviewBackend::Codex => "codex",
        ReviewBackend::Gemini => "gemini",
    };
    Command::new("sh")
        .args(["-lc", &format!("command -v {tool} >/dev/null 2>&1")])
        .status()
        .is_ok_and(|status| status.success())
}

// ── Provider slots ──────────────────────────────────────────────────────────

pub fn provider_slot_count(backend: ReviewBackend) -> usize {
    let key = match backend {
        ReviewBackend::Codex => "APM2_FAC_CODEX_SLOTS",
        ReviewBackend::Gemini => "APM2_FAC_GEMINI_SLOTS",
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

        let jitter_millis = rand::thread_rng().gen_range(0..=PROVIDER_SLOT_WAIT_JITTER_MS);
        thread::sleep(PROVIDER_SLOT_POLL_INTERVAL + Duration::from_millis(jitter_millis));
    }
}
