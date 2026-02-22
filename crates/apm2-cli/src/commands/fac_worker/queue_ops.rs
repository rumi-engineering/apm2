#[allow(clippy::wildcard_imports)]
use super::*;

pub(super) fn persist_queue_scheduler_state(
    fac_root: &Path,
    queue_state: &QueueSchedulerState,
    current_tick: u64,
    cost_model: Option<&apm2_core::economics::CostModelV1>,
) -> Result<(), String> {
    let mut state = queue_state.to_scheduler_state_v1(current_tick);
    state.persisted_at_secs = current_timestamp_epoch_secs();
    state.cost_model = cost_model.cloned();
    persist_scheduler_state(fac_root, &state)
        .map(|_| ())
        .map_err(|e| format!("failed to persist scheduler state: {e}"))
}

pub(super) fn check_or_admit_canonicalizer_tuple(
    fac_root: &Path,
) -> Result<CanonicalizerTupleCheck, String> {
    let tuple = CanonicalizerTupleV1::from_current();
    let tuple_path = fac_root
        .join("broker")
        .join("admitted_canonicalizer_tuple.v1.json");

    if !tuple_path.exists() {
        return Ok(CanonicalizerTupleCheck::Missing);
    }

    match FacBroker::load_admitted_tuple(fac_root) {
        Ok(admitted_tuple) => {
            if admitted_tuple == tuple {
                Ok(CanonicalizerTupleCheck::Matched)
            } else {
                Ok(CanonicalizerTupleCheck::Mismatch(admitted_tuple))
            }
        },
        Err(BrokerError::Deserialization { detail }) => {
            Err(format!("canonicalizer tuple is corrupted: {detail}"))
        },
        Err(err) => Err(format!("failed to load canonicalizer tuple: {err}")),
    }
}

// Used by tests to avoid computing digest twice.
// Used by startup checks to avoid duplicated digest logic.
pub(super) fn compute_canonicalizer_tuple_digest() -> String {
    CanonicalizerTupleV1::from_current().compute_digest()
}

// =============================================================================
// Queue scanning
// =============================================================================

/// Acquire the process-level enqueue lockfile under `queue_root`.
///
/// Returns the open `File` handle whose lifetime controls the lock.
/// The lock is released when the file handle is dropped (implicit
/// `flock(LOCK_UN)` on `File::drop`).
///
/// This is the same lock used by `enqueue_direct` in `fac_queue_submit`.
/// Both code paths must use the same lockfile name (`ENQUEUE_LOCKFILE`)
/// to serialize check-then-act sequences against the pending directory.
///
/// # Errors
///
/// Returns `Err` if the lockfile cannot be created or locked.
pub(super) fn acquire_enqueue_lock(queue_root: &Path) -> Result<fs::File, String> {
    let lock_path = queue_root.join(ENQUEUE_LOCKFILE);
    let lock_file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .map_err(|err| {
            format!(
                "cannot open enqueue lockfile {}: {err}",
                lock_path.display()
            )
        })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = lock_file.set_permissions(fs::Permissions::from_mode(0o600));
    }

    lock_file
        .lock_exclusive()
        .map_err(|err| format!("cannot acquire enqueue lock {}: {err}", lock_path.display()))?;

    Ok(lock_file)
}

/// Atomically claim a pending queue entry and hold an exclusive flock on the
/// claimed inode for the caller's full processing lifetime.
///
/// Synchronization model:
/// - Open+lock the pending inode first.
/// - Atomically rename `pending/<file>` -> `claimed/<file>`.
/// - Keep the returned file descriptor alive until processing/commit finishes.
///
/// This ensures runtime reconcile's non-blocking flock probe never treats an
/// actively executing claimed job as orphaned.
pub(super) fn claim_pending_job_with_exclusive_lock(
    pending_path: &Path,
    claimed_dir: &Path,
    file_name: &str,
) -> Result<(PathBuf, fs::File), String> {
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }

    let claimed_lock_file = options.open(pending_path).map_err(|err| {
        format!(
            "cannot open pending job for claimed lock {}: {err}",
            pending_path.display()
        )
    })?;
    let metadata = claimed_lock_file.metadata().map_err(|err| {
        format!(
            "cannot stat pending job for claimed lock {}: {err}",
            pending_path.display()
        )
    })?;
    if !metadata.is_file() {
        return Err(format!(
            "pending job is not a regular file (fail-closed): {}",
            pending_path.display()
        ));
    }

    claimed_lock_file.lock_exclusive().map_err(|err| {
        format!(
            "cannot acquire claimed flock for pending job {}: {err}",
            pending_path.display()
        )
    })?;

    let claimed_path = move_to_dir_safe(pending_path, claimed_dir, file_name)
        .map_err(|err| format!("atomic claim failed: {err}"))?;

    Ok((claimed_path, claimed_lock_file))
}

/// Promote valid job specs from `queue/broker_requests/` into `queue/pending/`
/// (TCK-00577).
///
/// Called by the worker (running as service user) before scanning pending.
/// Each `.json` file in `broker_requests/` is validated (bounded read +
/// deserialize), checked against queue bounds under the enqueue lock, and
/// moved to `pending/` via atomic no-replace rename (`move_to_dir_safe`).
/// Malformed files are quarantined. Files that would exceed queue bounds
/// are quarantined with denial evidence. Files that collide with existing
/// pending entries are quarantined (collision-safe, never overwrites).
///
/// # Arguments
///
/// * `bounds_policy` - The queue bounds policy loaded from the FAC
///   configuration (`FacPolicyV1::queue_bounds_policy`). Must be the same
///   policy used by `enqueue_direct` to ensure broker-mediated promotion
///   enforces identical queue capacity limits.
///
/// # Lock discipline
///
/// Each promotion acquires the same process-level lockfile
/// (`queue/.enqueue.lock`) used by `enqueue_direct` in `fac_queue_submit`,
/// ensuring the check-then-rename sequence is atomic with respect to
/// concurrent enqueue processes. The lock is held for the shortest
/// possible duration: acquire → `check_queue_bounds` → `move_to_dir_safe`
/// → release.
///
/// # Synchronization protocol
///
/// - Protected data: set of files in `queue/pending/` and the snapshot-derived
///   bounds decision.
/// - Who can mutate: only the holder of the exclusive flock on
///   `ENQUEUE_LOCKFILE`.
/// - Lock ordering: single lock, no nesting required.
/// - Happens-before: `lock_exclusive()` → scan pending + move → drop lockfile
///   (implicit `flock(LOCK_UN)`).
/// - Async suspension: not applicable (synchronous path).
pub(super) fn promote_broker_requests(queue_root: &Path, bounds_policy: &QueueBoundsPolicy) {
    let broker_dir = queue_root.join(BROKER_REQUESTS_DIR);
    if !broker_dir.is_dir() {
        return;
    }

    let Ok(entries) = fs::read_dir(&broker_dir) else {
        return;
    };

    let pending_dir = queue_root.join(PENDING_DIR);
    let _ = fs::create_dir_all(&pending_dir);

    let quarantine_dir = queue_root.join(QUARANTINE_DIR);
    let _ = fs::create_dir_all(&quarantine_dir);

    // Queue bounds policy is threaded from the loaded FAC policy by
    // the caller (run_fac_worker). This ensures broker-mediated
    // promotion enforces the same configured limits as enqueue_direct.

    // MAJOR fix (TCK-00577 round 16): Separate candidate counting from junk
    // draining. Only CANDIDATE entries (regular files with .json extension that
    // pass filename validation) count toward MAX_BROKER_REQUESTS_PROMOTE.
    // Non-candidate entries (wrong extension, non-regular files, unreadable
    // metadata) are quarantined without consuming the promotion budget, up to
    // MAX_JUNK_DRAIN_PER_CYCLE. This prevents an attacker from filling
    // broker_requests/ with junk filenames to exhaust the scan budget and
    // starve valid .json requests.
    let mut candidates_processed: usize = 0;
    let mut junk_drained: usize = 0;
    let mut entries_scanned: usize = 0;
    // Track skipped entries for aggregate warning (replaces per-entry spam).
    let mut candidates_skipped: usize = 0;
    let mut junk_skipped: usize = 0;

    for entry in entries {
        // CODE-QUALITY fix (TCK-00577 round 17): Hard total per-cycle
        // entry budget. Stop iterating directory entries once the budget
        // is exhausted, regardless of individual cap states. This bounds
        // work under adversarial directory flood.
        if entries_scanned >= MAX_BROKER_SCAN_BUDGET {
            break;
        }
        entries_scanned += 1;

        // Both individual caps reached: stop scanning.
        if candidates_processed >= MAX_BROKER_REQUESTS_PROMOTE
            && junk_drained >= MAX_JUNK_DRAIN_PER_CYCLE
        {
            break;
        }

        let Ok(entry) = entry else { continue };
        let path = entry.path();

        // ── Classify: is this a candidate (.json extension + valid UTF-8 name)? ──
        let is_json = path.extension().and_then(|e| e.to_str()) == Some("json");
        let file_name = path.file_name().and_then(|n| n.to_str()).map(String::from);

        if !is_json || file_name.is_none() {
            // Non-candidate: quarantine without counting toward promotion cap.
            if junk_drained < MAX_JUNK_DRAIN_PER_CYCLE {
                if let Some(ref name) = file_name {
                    tracing::debug!(
                        path = %path.display(),
                        "TCK-00577: draining non-.json entry from broker_requests/"
                    );
                    let _ = move_to_dir_safe(&path, &quarantine_dir, name);
                } else {
                    // Non-UTF-8 filename: try to remove directly (can't safely
                    // construct a quarantine name).
                    tracing::debug!(
                        path = %path.display(),
                        "TCK-00577: removing non-UTF-8 entry from broker_requests/"
                    );
                    let _ = fs::remove_file(&path);
                }
                junk_drained += 1;
            } else {
                junk_skipped += 1;
            }
            continue;
        }

        let file_name = file_name.unwrap();

        // ── Pre-open file type check (lstat) ──
        // BLOCKER fix (TCK-00577 round 9): Prevent FIFO poisoning.
        // An attacker with write access to broker_requests/ (mode 01733)
        // can create a FIFO named *.json. Opening a FIFO without O_NONBLOCK
        // blocks indefinitely. Use symlink_metadata (lstat) to check file
        // type BEFORE opening. Only regular files proceed; FIFOs, sockets,
        // devices, and symlinks are quarantined as junk.
        match std::fs::symlink_metadata(&path) {
            Ok(meta) => {
                if !meta.file_type().is_file() {
                    // .json extension but not a regular file — this is junk.
                    if junk_drained < MAX_JUNK_DRAIN_PER_CYCLE {
                        let kind = if meta.file_type().is_symlink() {
                            "symlink"
                        } else if meta.file_type().is_dir() {
                            "directory"
                        } else {
                            "non-regular-file (FIFO/socket/device)"
                        };
                        tracing::warn!(
                            path = %path.display(),
                            file_type = kind,
                            "TCK-00577: quarantining non-regular-file broker request \
                             (FIFO poisoning defense)"
                        );
                        let _ = move_to_dir_safe(&path, &quarantine_dir, &file_name);
                        junk_drained += 1;
                    } else {
                        junk_skipped += 1;
                    }
                    continue;
                }
            },
            Err(e) => {
                // Unreadable metadata: treat as junk.
                if junk_drained < MAX_JUNK_DRAIN_PER_CYCLE {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "TCK-00577: quarantining broker request with unreadable metadata"
                    );
                    let _ = move_to_dir_safe(&path, &quarantine_dir, &file_name);
                    junk_drained += 1;
                } else {
                    junk_skipped += 1;
                }
                continue;
            },
        }

        // ── This is a valid candidate: count toward promotion cap ──
        if candidates_processed >= MAX_BROKER_REQUESTS_PROMOTE {
            // CODE-QUALITY fix (TCK-00577 round 17): Track skipped
            // candidates for ONE aggregate warning after the loop,
            // instead of emitting a warning per skipped entry.
            candidates_skipped += 1;
            // Continue draining junk if junk cap not yet reached.
            if junk_drained >= MAX_JUNK_DRAIN_PER_CYCLE {
                break;
            }
            continue;
        }
        candidates_processed += 1;

        // Bounded read (reuse MAX_JOB_SPEC_SIZE from job_spec module).
        // Defense-in-depth: read_bounded also uses O_NONBLOCK and checks
        // file type via fstat after open, but the pre-open lstat above
        // prevents the open(2) call from blocking on a FIFO in the first
        // place.
        let bytes = match read_bounded(&path, apm2_core::fac::job_spec::MAX_JOB_SPEC_SIZE) {
            Ok(b) => b,
            Err(e) => {
                // TCK-00577 round 17: Broker request files are now
                // written with mode 0640 + fchown(gid=service_user).
                // The submitter MUST resolve the service user and
                // fchown must succeed (fail-closed, no 0644 fallback).
                // In cross-user deployments, the worker can read via
                // group membership. EACCES here indicates a
                // misconfiguration (shared group not configured).
                // This is fail-closed: unreadable files are
                // quarantined, not promoted.
                if e.contains("Permission denied") {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "TCK-00577: broker request file is not readable by the worker \
                         (EACCES). In cross-user deployments, configure a shared group \
                         between the submitter and service user, or use POSIX ACLs. \
                         Quarantining file (fail-closed)."
                    );
                } else {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "TCK-00577: quarantining unreadable broker request"
                    );
                }
                let _ = move_to_dir_safe(&path, &quarantine_dir, &file_name);
                continue;
            },
        };

        // Validate deserialization.
        if deserialize_job_spec(&bytes).is_err() {
            tracing::warn!(
                path = %path.display(),
                "TCK-00577: quarantining malformed broker request"
            );
            let _ = move_to_dir_safe(&path, &quarantine_dir, &file_name);
            continue;
        }

        // ---- Begin enqueue lock critical section ----
        // Acquire the same process-level lockfile used by enqueue_direct
        // to prevent TOCTOU races between bounds check and rename.
        let lock_file = match acquire_enqueue_lock(queue_root) {
            Ok(lf) => lf,
            Err(e) => {
                // Fail-closed: cannot acquire lock → do not promote.
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "TCK-00577: cannot acquire enqueue lock, deferring broker request promotion"
                );
                continue;
            },
        };

        // Check queue bounds with proposed file size before promoting.
        let proposed_bytes = bytes.len() as u64;
        if let Err(bounds_err) = check_queue_bounds(&pending_dir, proposed_bytes, bounds_policy) {
            // Queue is at capacity: quarantine the broker request with
            // denial evidence instead of promoting.
            tracing::warn!(
                path = %path.display(),
                error = %bounds_err,
                "TCK-00577: queue bounds exceeded, quarantining broker request"
            );
            drop(lock_file);
            let _ = move_to_dir_safe(&path, &quarantine_dir, &file_name);
            continue;
        }

        // BLOCKER fix (TCK-00577 round 12): Do NOT rename the attacker-owned
        // inode into pending/. The original file is owned by the non-service-user
        // submitter with mode 0600, and rename() preserves ownership+mode across
        // filesystems. This means the submitter retains write authority over the
        // file in pending/ and can mutate it after validation (TOCTOU).
        //
        // Instead: create a NEW temp file in pending/ owned by the current
        // process (service user) with mode 0600, write the validated content,
        // fsync, then rename_noreplace into its final pending/ name. Only then
        // remove the original broker_requests file.
        match promote_via_rewrite(&bytes, &pending_dir, &file_name) {
            Ok(_promoted_path) => {
                // Lock released after successful promotion.
                drop(lock_file);
                // Remove the original attacker-owned broker request file.
                // Best-effort: if removal fails, the file stays in
                // broker_requests/ and will be re-read next cycle, but
                // deserialization will match a pending/ file so it's harmless
                // (duplicate detection handles this).
                if let Err(e) = fs::remove_file(&path) {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "TCK-00577: could not remove original broker request after promotion"
                    );
                }
                tracing::info!(
                    file = %file_name,
                    "TCK-00577: promoted broker request to pending/ (service-user-owned rewrite)"
                );
            },
            Err(e) => {
                drop(lock_file);
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "TCK-00577: failed to promote broker request to pending via rewrite, quarantining"
                );
                let _ = move_to_dir_safe(&path, &quarantine_dir, &file_name);
            },
        }
        // ---- End enqueue lock critical section ----
    }

    // CODE-QUALITY fix (TCK-00577 round 17): Emit ONE aggregate warning
    // per cycle instead of per-entry warnings. This bounds log output
    // under adversarial flood.
    let total_skipped = candidates_skipped + junk_skipped;
    if total_skipped > 0 || entries_scanned >= MAX_BROKER_SCAN_BUDGET {
        tracing::warn!(
            entries_scanned = entries_scanned,
            scan_budget = MAX_BROKER_SCAN_BUDGET,
            candidates_promoted = candidates_processed,
            candidates_skipped = candidates_skipped,
            junk_drained = junk_drained,
            junk_skipped = junk_skipped,
            budget_exhausted = entries_scanned >= MAX_BROKER_SCAN_BUDGET,
            "TCK-00577: broker promotion cycle summary — \
             {total_skipped} entries deferred to next cycle"
        );
    }
}

/// Promote validated broker request content into `pending/` by creating a NEW
/// service-user-owned file (BLOCKER fix, TCK-00577 round 12).
///
/// Instead of renaming the attacker-owned inode (which preserves submitter
/// ownership and mode across `rename()`), this function:
/// 1. Creates a new temp file in `pending/` owned by the current process (the
///    service user) with mode 0600.
/// 2. Writes the already-validated content.
/// 3. Calls `fsync()` for crash safety.
/// 4. Uses `rename_noreplace()` to atomically place the file at its final name
///    in `pending/`.
///
/// On filename collision (EEXIST from `rename_noreplace`), a timestamped
/// suffix is appended to prevent clobbering existing pending jobs.
///
/// # Security invariants
///
/// - The inode in `pending/` is always owned by the service user with mode
///   0600. The original submitter has zero write authority over it.
/// - The validated `bytes` are the single source of truth; the attacker cannot
///   modify the content between validation and promotion.
pub(super) fn promote_via_rewrite(
    bytes: &[u8],
    pending_dir: &Path,
    file_name: &str,
) -> Result<PathBuf, String> {
    // Create a temp file in pending/ — this will be owned by the current
    // process uid (the service user) with permissions set below.
    let temp = tempfile::NamedTempFile::new_in(pending_dir)
        .map_err(|e| format!("cannot create temp file in {}: {e}", pending_dir.display()))?;

    {
        let file = temp.as_file();
        // Set mode 0600 so only the service user can read/write.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("cannot set mode 0600 on temp file: {e}"))?;
        }
        // Write the validated content (already deserialized + bounds-checked).
        std::io::Write::write_all(&mut &*file, bytes)
            .map_err(|e| format!("cannot write validated content to temp file: {e}"))?;
        // fsync for crash safety.
        file.sync_all()
            .map_err(|e| format!("cannot fsync promoted file: {e}"))?;
    }

    // Atomically place the file at its final name in pending/.
    let dest = pending_dir.join(file_name);
    match rename_noreplace(temp.path(), &dest) {
        Ok(()) => {
            // Disown the NamedTempFile so it doesn't delete the now-renamed file.
            let _ = temp.into_temp_path();
            Ok(dest)
        },
        Err(e)
            if e.raw_os_error() == Some(libc::EEXIST)
                || e.raw_os_error() == Some(libc::ENOTEMPTY)
                || e.kind() == std::io::ErrorKind::AlreadyExists =>
        {
            // Collision: generate a timestamped fallback name.
            let ts_nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let stem = file_name.trim_end_matches(".json");
            let safe_name = format!("{stem}-{ts_nanos}.json");
            let safe_dest = pending_dir.join(&safe_name);
            rename_noreplace(temp.path(), &safe_dest).map_err(|e2| {
                format!(
                    "rename {} -> {}: {e2}",
                    temp.path().display(),
                    safe_dest.display()
                )
            })?;
            let _ = temp.into_temp_path();
            Ok(safe_dest)
        },
        Err(e) => Err(format!(
            "rename {} -> {}: {e}",
            temp.path().display(),
            dest.display()
        )),
    }
}

/// Scans `queue/pending/` and returns sorted candidates.
///
/// Files are read with bounded I/O (INV-WRK-001), deserialized, and sorted
/// by (priority ASC, `enqueue_time` ASC, `job_id` ASC) for deterministic
/// ordering (INV-WRK-005).
///
/// Malformed, unreadable, or oversize files are quarantined with receipts
/// (INV-WRK-007) rather than silently dropped.
pub(super) fn scan_pending(
    queue_root: &Path,
    fac_root: &Path,
    canonicalizer_tuple_digest: &str,
    // TCK-00538: Optional toolchain fingerprint for scan receipt provenance.
    toolchain_fingerprint: Option<&str>,
) -> Result<Vec<PendingCandidate>, String> {
    let pending_dir = queue_root.join(PENDING_DIR);
    if !pending_dir.is_dir() {
        return Ok(Vec::new());
    }

    let entries =
        fs::read_dir(&pending_dir).map_err(|e| format!("cannot read pending directory: {e}"))?;

    let mut candidates = Vec::new();

    for (idx, entry) in entries.enumerate() {
        // Bound the number of entries scanned (INV-WRK-006).
        if idx >= MAX_PENDING_SCAN_ENTRIES {
            break;
        }

        let Ok(entry) = entry else { continue };

        let path = entry.path();

        // Only process .json files.
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }

        let file_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };

        // Read with bounded I/O (INV-WRK-001).
        // On read failure -> quarantine + receipt (INV-WRK-007).
        let bytes = match read_bounded(&path, MAX_JOB_SPEC_SIZE) {
            Ok(b) => b,
            Err(e) => {
                let reason = format!("read failure: {e}");
                let moved_path =
                    move_to_dir_safe(&path, &queue_root.join(QUARANTINE_DIR), &file_name)
                        .map(|p| {
                            p.strip_prefix(queue_root)
                                .unwrap_or(&p)
                                .to_string_lossy()
                                .to_string()
                        })
                        .ok();
                let job_id = file_name.trim_end_matches(".json").to_string();
                let _ = emit_scan_receipt(
                    fac_root,
                    &file_name,
                    &job_id,
                    &compute_job_spec_digest_preview(&[]),
                    FacJobOutcome::Quarantined,
                    DenialReasonCode::MalformedSpec,
                    moved_path.as_deref(),
                    &reason,
                    canonicalizer_tuple_digest,
                    toolchain_fingerprint,
                );
                continue;
            },
        };

        // Bounded deserialize.
        // On deserialize failure -> quarantine + receipt (INV-WRK-007).
        let spec = match deserialize_job_spec(&bytes) {
            Ok(s) => s,
            Err(e) => {
                let reason = format!("deserialization failed: {e}");
                let moved_path =
                    move_to_dir_safe(&path, &queue_root.join(QUARANTINE_DIR), &file_name)
                        .map(|p| {
                            p.strip_prefix(queue_root)
                                .unwrap_or(&p)
                                .to_string_lossy()
                                .to_string()
                        })
                        .ok();
                let job_id = file_name.trim_end_matches(".json").to_string();
                let _ = emit_scan_receipt(
                    fac_root,
                    &file_name,
                    &job_id,
                    &compute_job_spec_digest_preview(&bytes),
                    FacJobOutcome::Quarantined,
                    DenialReasonCode::MalformedSpec,
                    moved_path.as_deref(),
                    &reason,
                    canonicalizer_tuple_digest,
                    toolchain_fingerprint,
                );
                continue;
            },
        };

        candidates.push(PendingCandidate {
            path,
            spec,
            raw_bytes: bytes,
        });
    }

    // Sort deterministically (INV-WRK-005): priority ASC, enqueue_time ASC,
    // job_id ASC.
    candidates.sort_by(|a, b| {
        a.spec
            .priority
            .cmp(&b.spec.priority)
            .then_with(|| a.spec.enqueue_time.cmp(&b.spec.enqueue_time))
            .then_with(|| a.spec.job_id.cmp(&b.spec.job_id))
    });

    Ok(candidates)
}

// =============================================================================
// Queue lane parsing
// =============================================================================

/// Parses a queue lane string into a `QueueLane` enum variant.
///
/// Supports the serde `snake_case` names used in `QueueLane` serialization.
/// Unknown lane strings default to `QueueLane::Bulk` (fail-safe: unknown
/// lane gets lowest priority).
pub(super) fn append_completed_gates_fingerprint_if_loaded(
    completed_gates_cache: &mut Option<CompletedGatesCache>,
    spec: &FacJobSpecV1,
    toolchain_digest: &str,
) {
    let Some(cache) = completed_gates_cache.as_mut() else {
        return;
    };
    let Some(fingerprint) = CompletedGatesFingerprint::from_spec(spec, toolchain_digest) else {
        return;
    };
    cache.insert(fingerprint);
}

pub(super) fn normalize_dedupe_key_component(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

pub(super) fn load_completed_gates_fingerprints(
    queue_root: &Path,
    fac_root: &Path,
) -> Vec<CompletedGatesFingerprint> {
    let mut fingerprints = Vec::new();
    let completed_dir = queue_root.join(COMPLETED_DIR);
    if !completed_dir.is_dir() {
        return fingerprints;
    }

    let receipts_dir = fac_root.join(FAC_RECEIPTS_DIR);
    let Ok(entries) = fs::read_dir(&completed_dir) else {
        return fingerprints;
    };

    for (idx, entry) in entries.enumerate() {
        if idx >= MAX_COMPLETED_SCAN_ENTRIES {
            break;
        }

        let Ok(entry) = entry else { continue };
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }

        let Ok(bytes) = read_bounded(&path, MAX_JOB_SPEC_SIZE) else {
            continue;
        };
        let parsed: CompletedGatesFingerprintSpec = match serde_json::from_slice(&bytes) {
            Ok(p) => p,
            Err(_) => continue,
        };
        if !parsed.kind.eq_ignore_ascii_case("gates") {
            continue;
        }

        let Some(existing_receipt) =
            apm2_core::fac::find_receipt_for_job(&receipts_dir, &parsed.job_id)
        else {
            continue;
        };
        if existing_receipt.outcome != FacJobOutcome::Completed {
            continue;
        }

        fingerprints.push(CompletedGatesFingerprint {
            job_id: parsed.job_id,
            enqueue_time: parsed.enqueue_time,
            repo_id: parsed.source.repo_id,
            head_sha: parsed.source.head_sha,
            toolchain_digest: existing_receipt
                .canonicalizer_tuple_digest
                .unwrap_or_default(),
        });
    }

    fingerprints
}

pub(super) fn load_completed_gates_cache(
    queue_root: &Path,
    fac_root: &Path,
) -> CompletedGatesCache {
    CompletedGatesCache::from_fingerprints(load_completed_gates_fingerprints(queue_root, fac_root))
}

pub(super) fn find_completed_gates_duplicate_in_cache(
    incoming: &FacJobSpecV1,
    completed_gates_cache: &CompletedGatesCache,
    current_toolchain_digest: &str,
) -> Option<ShaDuplicateMatch> {
    let key = (
        normalize_dedupe_key_component(incoming.source.repo_id.as_str()),
        normalize_dedupe_key_component(incoming.source.head_sha.as_str()),
    );
    let existing_fingerprints = completed_gates_cache.by_repo_sha.get(&key)?;
    // Only match when the toolchain digest is identical — a rebuilt binary must
    // re-gate the same SHA so that gate results reflect the current toolchain.
    let existing = existing_fingerprints
        .iter()
        .find(|fp| fp.toolchain_digest == current_toolchain_digest)?;
    Some(ShaDuplicateMatch {
        existing_job_id: existing.job_id.clone(),
        existing_enqueue_time: existing.enqueue_time.clone(),
        matched_by: "repo_sha_toolchain",
    })
}

pub(super) fn find_completed_gates_duplicate(
    queue_root: &Path,
    fac_root: &Path,
    incoming: &FacJobSpecV1,
    completed_gates_cache: &mut Option<CompletedGatesCache>,
    current_toolchain_digest: &str,
) -> Option<ShaDuplicateMatch> {
    if !incoming.kind.eq_ignore_ascii_case("gates") {
        return None;
    }

    let cache = completed_gates_cache
        .get_or_insert_with(|| load_completed_gates_cache(queue_root, fac_root));
    find_completed_gates_duplicate_in_cache(incoming, cache, current_toolchain_digest)
}

pub(super) fn derive_queue_root_from_fac_root(fac_root: &Path) -> Option<PathBuf> {
    let apm2_home = fac_root.parent()?.parent()?;
    Some(apm2_home.join(QUEUE_DIR))
}

pub(super) fn annotate_denied_job_file(
    denied_path: &Path,
    denial_reason: Option<DenialReasonCode>,
    reason: &str,
) -> Result<(), String> {
    let bytes = read_bounded(denied_path, MAX_TERMINAL_JOB_METADATA_FILE_SIZE)?;
    let mut payload: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| {
        format!(
            "cannot parse denied job file {}: {e}",
            denied_path.display()
        )
    })?;
    let Some(map) = payload.as_object_mut() else {
        return Err(format!(
            "denied job payload is not a JSON object: {}",
            denied_path.display()
        ));
    };

    let denial_reason_code = denial_reason.map_or_else(
        || "missing_denial_reason_code".to_string(),
        serialize_denial_reason_code,
    );
    let denial_reason_text = {
        let trimmed = reason.trim();
        if trimmed.is_empty() {
            format!("denied ({denial_reason_code})")
        } else {
            trimmed.to_string()
        }
    };

    map.insert(
        "denial_reason_code".to_string(),
        serde_json::Value::String(denial_reason_code),
    );
    map.insert(
        "denial_reason".to_string(),
        serde_json::Value::String(denial_reason_text),
    );
    map.insert(
        "denied_at".to_string(),
        serde_json::Value::String(Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)),
    );

    let output = serde_json::to_vec_pretty(&payload).map_err(|e| {
        format!(
            "cannot serialize denied job metadata update {}: {e}",
            denied_path.display()
        )
    })?;
    if output.len() > MAX_TERMINAL_JOB_METADATA_FILE_SIZE {
        return Err(format!(
            "denied job metadata payload exceeds max size ({} > {}) for {}",
            output.len(),
            MAX_TERMINAL_JOB_METADATA_FILE_SIZE,
            denied_path.display()
        ));
    }

    fac_permissions::write_fac_file_with_mode(denied_path, &output).map_err(|e| {
        format!(
            "cannot persist denied job metadata for {}: {e}",
            denied_path.display()
        )
    })
}

pub(super) fn annotate_denied_job_metadata_from_receipt(
    terminal_path: &Path,
    receipt: &FacJobReceiptV1,
) {
    if receipt.outcome != FacJobOutcome::Denied {
        return;
    }
    if let Err(err) = annotate_denied_job_file(
        terminal_path,
        receipt.denial_reason,
        receipt.reason.as_str(),
    ) {
        eprintln!(
            "worker: WARNING: duplicate denied job metadata update failed for {}: {err}",
            terminal_path.display()
        );
    }
}

pub(super) fn annotate_denied_job_from_moved_path(
    fac_root: &Path,
    moved_job_path: &str,
    denial_reason: Option<DenialReasonCode>,
    reason: &str,
) {
    let normalized = moved_job_path.trim().trim_start_matches('/');
    if normalized.is_empty() || !normalized.starts_with("denied/") {
        return;
    }

    let rel_path = Path::new(normalized);
    if rel_path.is_absolute()
        || rel_path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::RootDir))
    {
        eprintln!(
            "worker: WARNING: refusing denied metadata update for unsafe moved path: {moved_job_path}"
        );
        return;
    }

    let Some(queue_root) = derive_queue_root_from_fac_root(fac_root) else {
        return;
    };
    let denied_path = queue_root.join(rel_path);
    if let Err(err) = annotate_denied_job_file(&denied_path, denial_reason, reason) {
        eprintln!(
            "worker: WARNING: failed to populate denied job metadata for {}: {err}",
            denied_path.display()
        );
    }
}

// =============================================================================
// Job processing
// =============================================================================

/// Processes a single pending job through the validation pipeline.
///
/// Returns the outcome (quarantine, deny, complete, or skip).
#[allow(clippy::too_many_arguments)]
pub(super) fn find_target_job_in_dir(dir: &Path, target_job_id: &str) -> Option<PathBuf> {
    let entries = fs::read_dir(dir).ok()?;

    for (idx, entry) in entries.enumerate() {
        if idx >= MAX_PENDING_SCAN_ENTRIES {
            break;
        }
        let Ok(entry) = entry else { continue };
        let path = entry.path();

        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }

        // Try reading the spec to match by job_id.
        let Ok(bytes) = read_bounded(&path, MAX_JOB_SPEC_SIZE) else {
            continue;
        };
        let Ok(spec) = serde_json::from_slice::<FacJobSpecV1>(&bytes) else {
            continue;
        };
        if spec.job_id == target_job_id {
            return Some(path);
        }
    }

    None
}

pub(super) fn resolve_queue_root() -> Result<PathBuf, String> {
    let home = resolve_apm2_home().ok_or_else(|| "could not resolve APM2 home".to_string())?;
    Ok(home.join(QUEUE_DIR))
}

/// Resolves the FAC root directory at `$APM2_HOME/private/fac`.
pub(super) fn resolve_fac_root() -> Result<PathBuf, String> {
    let home = resolve_apm2_home().ok_or_else(|| "could not resolve APM2 home".to_string())?;
    Ok(home.join("private").join("fac"))
}

/// Ensures all required queue subdirectories exist with deterministic
/// secure permissions, regardless of the process umask.
///
/// TCK-00577 round 6: Creates `queue/` itself with mode 0711 (owner rwx,
/// group/other execute-only) so non-service-user callers can traverse to
/// reach `broker_requests/`. The `private/fac/` parent remains 0700.
///
/// TCK-00577 round 11 BLOCKER fix: After `create_dir_all` for each queue
/// subdir, explicitly calls `set_permissions` to set mode 0711
/// (traverse-only). This prevents umask-derived default modes (e.g.,
/// 0775 from umask 0o002) from causing `validate_directory_mode_only`
/// failures during the relaxed preflight path.
///
/// TCK-00577 round 11 MAJOR fix: `broker_requests/` permissions are now
/// enforced unconditionally at every startup, not just when newly
/// created. Pre-existing `broker_requests/` with unsafe modes (e.g.,
/// 0333 — world-writable without sticky) are hardened to 01733.
#[cfg(unix)]
fn ensure_directory_mode_nofollow(path: &Path, mode: u32) -> Result<(), String> {
    use nix::errno::Errno;
    use nix::fcntl::{OFlag, open};
    use nix::sys::stat::Mode;

    // Open without following symlinks. Linux uses `O_PATH` so we can recover
    // mode-000 directories; other Unix targets use `O_RDONLY` and then `fchmod`
    // directly on the opened descriptor.
    #[cfg(target_os = "linux")]
    let open_flags = OFlag::O_PATH | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let open_flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;

    let classify_path = || -> Result<(), String> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            return Err(format!(
                "refusing to set permissions on symlink path {} (fail-closed)",
                path.display()
            ));
        }
        if !file_type.is_dir() {
            return Err(format!(
                "expected directory at {}, found non-directory (fail-closed)",
                path.display()
            ));
        }
        Ok(())
    };

    let dir_fd = match open(path, open_flags, Mode::empty()) {
        Ok(fd) => fd,
        Err(Errno::ENOENT) => {
            fs::create_dir_all(path)
                .map_err(|e| format!("cannot create {}: {e}", path.display()))?;
            open(path, open_flags, Mode::empty()).map_err(|e| match e {
                Errno::ELOOP | Errno::ENOTDIR => {
                    if let Err(reason) = classify_path() {
                        reason
                    } else {
                        format!(
                            "expected directory at {}, found non-directory (fail-closed)",
                            path.display()
                        )
                    }
                },
                _ => format!(
                    "cannot open directory {} after creation: {e}",
                    path.display()
                ),
            })?
        },
        Err(Errno::ELOOP | Errno::ENOTDIR) => {
            classify_path()?;
            return Err(format!(
                "expected directory at {}, found non-directory (fail-closed)",
                path.display()
            ));
        },
        Err(e) => return Err(format!("cannot open directory {}: {e}", path.display())),
    };

    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;

        let mode = mode as libc::mode_t;
        #[allow(unsafe_code)]
        let rc = unsafe {
            // SAFETY:
            // - `dir_fd` is a live fd returned by `open`.
            // - `c""` is a valid NUL-terminated empty C string.
            // - `AT_EMPTY_PATH` targets the opened path object directly.
            libc::fchmodat(dir_fd.as_raw_fd(), c"".as_ptr(), mode, libc::AT_EMPTY_PATH)
        };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            return Err(format!(
                "cannot set mode {mode:#o} on {}: {err}",
                path.display()
            ));
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        use nix::sys::stat::fchmod;
        fchmod(&dir_fd, Mode::from_bits_truncate(mode))
            .map_err(|e| format!("cannot set mode {mode:#o} on {}: {e}", path.display()))?;
    }

    Ok(())
}

pub(super) fn ensure_queue_dirs(queue_root: &Path) -> Result<(), String> {
    // Ensure the queue root itself exists with mode 0711 for traversal.
    #[cfg(unix)]
    ensure_directory_mode_nofollow(queue_root, 0o711)?;
    #[cfg(not(unix))]
    fs::create_dir_all(queue_root)
        .map_err(|e| format!("cannot create {}: {e}", queue_root.display()))?;

    for dir in [
        PENDING_DIR,
        CLAIMED_DIR,
        COMPLETED_DIR,
        DENIED_DIR,
        QUARANTINE_DIR,
        CANCELLED_DIR,
        CONSUME_RECEIPTS_DIR,
    ] {
        let path = queue_root.join(dir);
        // TCK-00577 round 11 BLOCKER fix: Set deterministic mode 0711 on
        // every queue subdir, regardless of the process umask. Without
        // this, create_dir_all inherits the umask which may produce
        // 0775 or 0777, causing validate_directory_mode_only to reject
        // these directories during relaxed preflight.
        #[cfg(unix)]
        ensure_directory_mode_nofollow(&path, 0o711)?;
        #[cfg(not(unix))]
        fs::create_dir_all(&path).map_err(|e| format!("cannot create {}: {e}", path.display()))?;
    }

    // TCK-00577 round 5 BLOCKER fix: Create broker_requests/ with mode 01733
    // (sticky bit + world-writable). Non-service-user callers use the broker
    // fallback to drop job specs into this directory. The sticky bit prevents
    // callers from deleting each other's files while still allowing writes.
    // Mode 01733 = owner rwx, group wx, others wx, sticky bit set.
    //
    // DirBuilder::mode() is subject to the process umask, so we must
    // explicitly chmod after creation to ensure the exact mode is applied.
    //
    // TCK-00577 round 11 MAJOR fix: Permissions are now enforced
    // unconditionally — both for newly created AND pre-existing
    // broker_requests/ directories. A pre-existing directory with an
    // unsafe mode (e.g., 0333 — world-writable without sticky) is
    // hardened to 01733 at every worker startup. This prevents an
    // attacker from tampering with the directory mode between restarts
    // and ensures the sticky bit invariant is always enforced.
    let broker_dir = queue_root.join(BROKER_REQUESTS_DIR);
    #[cfg(unix)]
    ensure_directory_mode_nofollow(&broker_dir, 0o1733)?;
    #[cfg(not(unix))]
    fs::create_dir_all(&broker_dir)
        .map_err(|e| format!("cannot create {}: {e}", broker_dir.display()))?;

    Ok(())
}

/// Checks if a PCAC authority token has already been consumed for this job.
///
/// Returns true if a consume receipt exists for the given `job_id`, indicating
/// the authority was already consumed and the job should be skipped.
pub(super) fn is_authority_consumed(queue_root: &Path, job_id: &str) -> bool {
    let consume_dir = queue_root.join(CONSUME_RECEIPTS_DIR);
    let receipt_path = consume_dir.join(format!("{job_id}.consumed"));
    receipt_path.exists()
}

/// Durably records PCAC authority consumption BEFORE any side effect.
///
/// This implements the essential property of the PCAC lifecycle:
/// a single-use, durable authorization record must exist before the
/// authority-bearing effect (job claim + receipt emission).
///
/// The consume receipt commits to: `job_id`, `claim timestamp`, and
/// `spec_digest` for binding integrity.
pub(super) fn consume_authority(
    queue_root: &Path,
    job_id: &str,
    spec_digest: &str,
) -> Result<(), String> {
    let consume_dir = queue_root.join(CONSUME_RECEIPTS_DIR);
    fs::create_dir_all(&consume_dir)
        .map_err(|e| format!("cannot create consume receipt dir: {e}"))?;

    let receipt_path = consume_dir.join(format!("{job_id}.consumed"));

    let receipt = serde_json::json!({
        "schema": "apm2.fac.pcac_consume.v1",
        "job_id": job_id,
        "spec_digest": spec_digest,
        "consumed_at_epoch_secs": current_timestamp_epoch_secs(),
    });

    let bytes = serde_json::to_vec_pretty(&receipt)
        .map_err(|e| format!("cannot serialize consume receipt: {e}"))?;

    // Enforce single-use authority consumption with atomic create-only write.
    // This closes the TOCTOU gap in `exists()` + `write()` under concurrent
    // workers claiming the same job.
    let mut receipt_file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&receipt_path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                format!("authority already consumed for job {job_id}")
            } else {
                format!(
                    "cannot create consume receipt {}: {e}",
                    receipt_path.display()
                )
            }
        })?;

    if let Err(err) = receipt_file.write_all(&bytes) {
        drop(receipt_file);
        let cleanup_suffix = match fs::remove_file(&receipt_path) {
            Ok(()) => String::new(),
            Err(cleanup_err) => format!("; cleanup failed: {cleanup_err}"),
        };
        return Err(format!(
            "cannot write consume receipt {}: {err}{cleanup_suffix}",
            receipt_path.display()
        ));
    }

    if let Err(err) = receipt_file.sync_all() {
        drop(receipt_file);
        let cleanup_suffix = match fs::remove_file(&receipt_path) {
            Ok(()) => String::new(),
            Err(cleanup_err) => format!("; cleanup failed: {cleanup_err}"),
        };
        return Err(format!(
            "cannot sync consume receipt {}: {err}{cleanup_suffix}",
            receipt_path.display()
        ));
    }

    if let Ok(dir) = fs::File::open(&consume_dir) {
        let _ = dir.sync_all();
    }

    Ok(())
}

pub(super) fn validate_worker_service_user_ownership(
    fac_root: &Path,
    queue_root: &Path,
    backend: ExecutionBackend,
) -> Result<(), String> {
    use apm2_core::fac::service_user_gate::{
        ServiceUserGateError, validate_directory_service_user_ownership,
    };

    if backend == ExecutionBackend::UserMode {
        tracing::info!(
            backend = %backend,
            "TCK-00657: user-mode backend selected — skipping service-user ownership checks"
        );
        return Ok(());
    }

    // Directories that MUST be owned by the service user in production.
    // Note: BROKER_REQUESTS_DIR is intentionally excluded — it uses
    // mode 01733 (world-writable with sticky) so that non-service-user
    // callers can submit broker requests.
    let service_user_dirs = [
        queue_root.join(PENDING_DIR),
        queue_root.join(CLAIMED_DIR),
        queue_root.join(COMPLETED_DIR),
        queue_root.join(DENIED_DIR),
        queue_root.join(CANCELLED_DIR),
        queue_root.join(QUARANTINE_DIR),
        queue_root.join(CONSUME_RECEIPTS_DIR),
    ];
    // Also validate the receipt store if it exists.
    let receipt_dir = fac_root.join(FAC_RECEIPTS_DIR);

    for dir in service_user_dirs
        .iter()
        .chain(std::iter::once(&receipt_dir))
    {
        if !dir.exists() {
            continue;
        }
        match validate_directory_service_user_ownership(dir) {
            Ok(()) => {},
            Err(ServiceUserGateError::ServiceUserNotResolved {
                ref service_user,
                ref reason,
                ..
            }) => {
                return Err(format!(
                    "service user '{service_user}' not resolvable: {reason} \
                     (fail-closed: worker will not start when service user \
                      identity cannot be confirmed)",
                ));
            },
            Err(e) => {
                return Err(format!(
                    "service user ownership check failed for {}: {e} \
                     (fail-closed: worker will not start with incorrect \
                      directory ownership)",
                    dir.display()
                ));
            },
        }
    }
    Ok(())
}

/// Reads a file with bounded I/O (INV-WRK-001).
///
/// Returns an error if the file is larger than `max_size` or cannot be read.
pub(super) fn read_bounded(path: &Path, max_size: usize) -> Result<Vec<u8>, String> {
    fac_secure_io::read_bounded(path, max_size)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))
}

/// Loads or generates a persistent signing key from
/// `$APM2_HOME/private/fac/signing_key`.
///
/// On first run, generates a new key and saves it with 0600 permissions.
/// On subsequent runs, loads the existing key. This keeps broker state and
/// receipts consistent across worker restarts.
pub(super) fn move_to_dir_safe(
    src: &Path,
    dest_dir: &Path,
    file_name: &str,
) -> Result<PathBuf, String> {
    let do_move = || -> Result<PathBuf, String> {
        if !dest_dir.exists() {
            fac_permissions::ensure_dir_with_mode(dest_dir)
                .map_err(|e| format!("cannot create {}: {e}", dest_dir.display()))?;
        }
        let dest = dest_dir.join(file_name);

        // Attempt atomic no-replace rename (RENAME_NOREPLACE).
        // On collision (EEXIST / ENOTEMPTY), generate a unique timestamped name.
        match rename_noreplace(src, &dest) {
            Ok(()) => return Ok(dest),
            Err(e)
                if e.raw_os_error() == Some(libc::EEXIST)
                    || e.raw_os_error() == Some(libc::ENOTEMPTY)
                    || e.kind() == std::io::ErrorKind::AlreadyExists => {},
            Err(e) => {
                return Err(format!(
                    "rename {} -> {}: {e}",
                    src.display(),
                    dest.display()
                ));
            },
        }

        // Generate a unique timestamped filename for the collision case.
        let ts_nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let stem = file_name.trim_end_matches(".json");
        let safe_name = format!("{stem}-{ts_nanos}.json");
        let safe_dest = dest_dir.join(&safe_name);
        rename_noreplace(src, &safe_dest)
            .map_err(|e| format!("rename {} -> {}: {e}", src.display(), safe_dest.display()))?;
        Ok(safe_dest)
    };

    let result = do_move();
    if let Err(ref e) = result {
        eprintln!("worker: WARNING: move_to_dir_safe failed: {e}");
    }
    result
}

// NOTE: `rename_noreplace` is imported from `apm2_core::fac::rename_noreplace`
// (MAJOR-3 fix round 7: unified into single canonical implementation in
// receipt_pipeline.rs to avoid behavioral drift and security maintenance
// burden).
