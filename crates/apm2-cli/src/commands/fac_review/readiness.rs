//! FAC gates readiness controller.
//!
//! Runs a deterministic check -> autofix -> recheck loop over the minimal
//! substrate required for queued `apm2 fac gates` execution.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use apm2_core::fac::broker::FacBroker;
use apm2_core::fac::economics_adoption::{
    EconomicsAdoptionError, adopt_economics_profile_by_hash, load_admitted_economics_profile_root,
};
use apm2_core::fac::policy_adoption::{
    PolicyAdoptionError, adopt_policy, load_admitted_policy_root,
};
use apm2_core::fac::{
    CanonicalizerTupleV1, FacPolicyV1, LaneManager, LaneProfileV1, MAX_POLICY_SIZE,
    compute_policy_hash, create_dir_restricted, deserialize_policy, persist_policy,
};
use apm2_core::github::resolve_apm2_home;
use serde::Serialize;

use super::policy_loader::ensure_managed_cargo_home;
use crate::commands::fac_permissions::validate_fac_root_permissions_for;
use crate::commands::fac_queue_submit::{init_broker, resolve_fac_root, resolve_queue_root};
use crate::commands::fac_secure_io;

const READINESS_ACTOR_ID: &str = "operator:readiness-controller";
const READINESS_POLICY_REASON: &str = "readiness controller auto-adopt policy";
const READINESS_ECONOMICS_REASON: &str = "readiness controller auto-adopt economics profile";
const EXTERNAL_WORKER_BOOTSTRAP_POLL_INTERVAL_MS: u64 = 250;
const EXTERNAL_WORKER_BOOTSTRAP_MAX_POLLS: u32 = 40;
const DEFAULT_AUTHORITY_CLOCK: &str = "local";

const FAC_REQUIRED_SUBDIRS: &[&str] = &[
    "lanes",
    "locks",
    "locks/lanes",
    "policy",
    "broker",
    "receipts",
    "evidence",
    "cargo_home",
];

const QUEUE_REQUIRED_SUBDIRS: &[&str] = &[
    "pending",
    "claimed",
    "completed",
    "cancelled",
    "denied",
    "quarantine",
    "quarantined",
    "authority_consumed",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ReadinessOptions {
    pub(super) require_external_worker: bool,
    pub(super) wait_for_worker: bool,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct ComponentReport {
    pub(super) component: &'static str,
    pub(super) status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) detail: Option<String>,
}

#[derive(Debug, Clone)]
pub(super) struct ReadinessOutcome {
    pub(super) worker_bootstrapped: bool,
    pub(super) component_reports: Vec<ComponentReport>,
    pub(super) elapsed_ms: u128,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct ReadinessFailure {
    pub(super) component: &'static str,
    pub(super) root_cause: String,
    pub(super) remediation: &'static str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(super) diagnostics: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(super) component_reports: Vec<ComponentReport>,
}

#[derive(Clone, Copy)]
pub(super) struct WorkerReadinessHooks<'a> {
    pub(super) has_live_worker_heartbeat: &'a dyn Fn(&Path) -> bool,
    pub(super) spawn_detached_worker: &'a dyn Fn() -> Result<(), String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubstrateComponent {
    FacRoot,
    LanePool,
    Canonicalizer,
    EconomicsProfile,
    WorkerBroker,
    CargoDeps,
}

impl SubstrateComponent {
    const fn as_str(self) -> &'static str {
        match self {
            Self::FacRoot => "fac_root",
            Self::LanePool => "lane_pool",
            Self::Canonicalizer => "canonicalizer_tuple",
            Self::EconomicsProfile => "economics_profile",
            Self::WorkerBroker => "worker_broker",
            Self::CargoDeps => "cargo_dependencies",
        }
    }

    const fn remediation(self) -> &'static str {
        match self {
            Self::FacRoot => {
                "ensure $APM2_HOME is writable and rerun `apm2 fac gates`; if needed run `apm2 fac bootstrap`"
            },
            Self::LanePool => {
                "repair lane substrate with `apm2 fac doctor --fix` or reinitialize with `apm2 fac lane init`"
            },
            Self::Canonicalizer => {
                "reset broker admission artifacts under $APM2_HOME/private/fac/broker and rerun readiness"
            },
            Self::EconomicsProfile => {
                "adopt a valid economics profile hash with `apm2 fac economics adopt <b3-256:...>`"
            },
            Self::WorkerBroker => {
                "start a FAC worker (`apm2 fac worker --poll-interval-secs 1`) and ensure broker state is healthy"
            },
            Self::CargoDeps => {
                "fix managed cargo home permissions under $APM2_HOME/private/fac/cargo_home"
            },
        }
    }
}

#[derive(Debug, Clone)]
struct ReadinessPaths {
    apm2_home: PathBuf,
    fac_root: PathBuf,
    queue_root: PathBuf,
}

pub(super) fn run_readiness_controller(
    options: ReadinessOptions,
    hooks: WorkerReadinessHooks<'_>,
) -> Result<ReadinessOutcome, ReadinessFailure> {
    let paths = resolve_paths()?;
    run_readiness_controller_for_paths(&paths, options, hooks)
}

fn run_readiness_controller_for_paths(
    paths: &ReadinessPaths,
    options: ReadinessOptions,
    hooks: WorkerReadinessHooks<'_>,
) -> Result<ReadinessOutcome, ReadinessFailure> {
    let start = Instant::now();
    let mut reports = Vec::with_capacity(6);
    let mut worker_bootstrapped = false;

    run_component_with_autofix(
        &mut reports,
        SubstrateComponent::FacRoot,
        || check_fac_root(paths),
        || autofix_fac_root(paths),
    )?;

    run_component_with_autofix(
        &mut reports,
        SubstrateComponent::LanePool,
        || check_lane_pool(&paths.fac_root),
        || autofix_lane_pool(&paths.fac_root),
    )?;

    run_component_with_autofix(
        &mut reports,
        SubstrateComponent::Canonicalizer,
        || check_policy_and_canonicalizer(&paths.fac_root),
        || autofix_policy_and_canonicalizer(&paths.fac_root),
    )?;

    run_component_with_autofix(
        &mut reports,
        SubstrateComponent::EconomicsProfile,
        || check_economics_profile(&paths.fac_root),
        || autofix_economics_profile(&paths.fac_root),
    )?;

    run_component_with_autofix(
        &mut reports,
        SubstrateComponent::WorkerBroker,
        || check_worker_and_broker(paths, options, hooks),
        || {
            autofix_worker_and_broker(paths, options, hooks).map(|spawned| {
                worker_bootstrapped |= spawned;
            })
        },
    )?;

    run_component_with_autofix(
        &mut reports,
        SubstrateComponent::CargoDeps,
        || check_cargo_deps(paths),
        || autofix_cargo_deps(paths),
    )?;

    Ok(ReadinessOutcome {
        worker_bootstrapped,
        component_reports: reports,
        elapsed_ms: start.elapsed().as_millis(),
    })
}

fn resolve_paths() -> Result<ReadinessPaths, ReadinessFailure> {
    let Some(apm2_home) = resolve_apm2_home() else {
        return Err(ReadinessFailure {
            component: SubstrateComponent::FacRoot.as_str(),
            root_cause: "cannot resolve APM2_HOME".to_string(),
            remediation: SubstrateComponent::FacRoot.remediation(),
            diagnostics: vec!["set APM2_HOME or HOME before running `apm2 fac gates`".to_string()],
            component_reports: Vec::new(),
        });
    };
    let fac_root = resolve_fac_root().map_err(|err| ReadinessFailure {
        component: SubstrateComponent::FacRoot.as_str(),
        root_cause: "cannot resolve FAC root".to_string(),
        remediation: SubstrateComponent::FacRoot.remediation(),
        diagnostics: vec![err],
        component_reports: Vec::new(),
    })?;
    let queue_root = resolve_queue_root().map_err(|err| ReadinessFailure {
        component: SubstrateComponent::FacRoot.as_str(),
        root_cause: "cannot resolve FAC queue root".to_string(),
        remediation: SubstrateComponent::FacRoot.remediation(),
        diagnostics: vec![err],
        component_reports: Vec::new(),
    })?;
    Ok(ReadinessPaths {
        apm2_home,
        fac_root,
        queue_root,
    })
}

fn run_component_with_autofix<FCheck, FFix>(
    reports: &mut Vec<ComponentReport>,
    component: SubstrateComponent,
    mut check: FCheck,
    mut fix: FFix,
) -> Result<(), ReadinessFailure>
where
    FCheck: FnMut() -> Result<(), String>,
    FFix: FnMut() -> Result<(), String>,
{
    match check() {
        Ok(()) => {
            reports.push(ComponentReport {
                component: component.as_str(),
                status: "ready",
                detail: None,
            });
            Ok(())
        },
        Err(check_err) => {
            let mut diagnostics = vec![format!("check failed: {check_err}")];
            if let Err(fix_err) = fix() {
                diagnostics.push(format!("autofix failed: {fix_err}"));
                reports.push(ComponentReport {
                    component: component.as_str(),
                    status: "failed",
                    detail: Some(check_err),
                });
                return Err(ReadinessFailure {
                    component: component.as_str(),
                    root_cause: format!("{} is not ready", component.as_str()),
                    remediation: component.remediation(),
                    diagnostics,
                    component_reports: reports.clone(),
                });
            }
            match check() {
                Ok(()) => {
                    reports.push(ComponentReport {
                        component: component.as_str(),
                        status: "autofixed",
                        detail: Some(check_err),
                    });
                    Ok(())
                },
                Err(recheck_err) => {
                    diagnostics.push(format!("recheck failed: {recheck_err}"));
                    reports.push(ComponentReport {
                        component: component.as_str(),
                        status: "failed",
                        detail: Some(recheck_err),
                    });
                    Err(ReadinessFailure {
                        component: component.as_str(),
                        root_cause: format!(
                            "{} remained not ready after autofix",
                            component.as_str()
                        ),
                        remediation: component.remediation(),
                        diagnostics,
                        component_reports: reports.clone(),
                    })
                },
            }
        },
    }
}

fn check_fac_root(paths: &ReadinessPaths) -> Result<(), String> {
    validate_fac_root_permissions_for(&paths.apm2_home)
        .map_err(|err| format!("FAC permission validation failed: {err}"))?;
    ensure_dir_exists(&paths.fac_root, "fac_root")?;
    ensure_dir_exists(&paths.queue_root, "queue_root")?;
    for rel in FAC_REQUIRED_SUBDIRS {
        ensure_dir_exists(&paths.fac_root.join(rel), rel)?;
    }
    for rel in QUEUE_REQUIRED_SUBDIRS {
        ensure_dir_exists(&paths.queue_root.join(rel), rel)?;
    }
    Ok(())
}

fn autofix_fac_root(paths: &ReadinessPaths) -> Result<(), String> {
    create_dir_restricted(&paths.apm2_home).map_err(|err| {
        format!(
            "cannot create APM2_HOME {}: {err}",
            paths.apm2_home.display()
        )
    })?;
    create_dir_restricted(&paths.fac_root)
        .map_err(|err| format!("cannot create fac_root {}: {err}", paths.fac_root.display()))?;
    create_dir_restricted(&paths.queue_root).map_err(|err| {
        format!(
            "cannot create queue_root {}: {err}",
            paths.queue_root.display()
        )
    })?;

    for rel in FAC_REQUIRED_SUBDIRS {
        let path = paths.fac_root.join(rel);
        create_dir_restricted(&path)
            .map_err(|err| format!("cannot create {}: {err}", path.display()))?;
    }
    for rel in QUEUE_REQUIRED_SUBDIRS {
        let path = paths.queue_root.join(rel);
        create_dir_restricted(&path)
            .map_err(|err| format!("cannot create {}: {err}", path.display()))?;
    }
    Ok(())
}

fn check_lane_pool(fac_root: &Path) -> Result<(), String> {
    let manager = LaneManager::new(fac_root.to_path_buf())
        .map_err(|err| format!("cannot initialize lane manager: {err}"))?;
    for lane_id in LaneManager::default_lane_ids() {
        let lane_dir = manager.lane_dir(&lane_id);
        ensure_dir_exists(&lane_dir, &format!("lane {lane_id}"))?;
        LaneProfileV1::load(&lane_dir)
            .map_err(|err| format!("invalid lane profile for {lane_id}: {err}"))?;
    }
    Ok(())
}

fn autofix_lane_pool(fac_root: &Path) -> Result<(), String> {
    let manager = LaneManager::new(fac_root.to_path_buf())
        .map_err(|err| format!("cannot initialize lane manager: {err}"))?;
    manager
        .init_lanes()
        .map_err(|err| format!("lane initialization failed: {err}"))?;
    Ok(())
}

fn check_policy_and_canonicalizer(fac_root: &Path) -> Result<(), String> {
    let policy = load_policy_from_disk(fac_root)?;
    let policy_hash =
        compute_policy_hash(&policy).map_err(|err| format!("cannot compute policy hash: {err}"))?;
    let admitted_policy = load_admitted_policy_root(fac_root)
        .map_err(|err| format!("admitted policy root unavailable: {err}"))?;
    if admitted_policy.admitted_policy_hash != policy_hash {
        return Err(format!(
            "admitted policy hash mismatch (expected {policy_hash}, got {})",
            admitted_policy.admitted_policy_hash
        ));
    }

    let admitted_tuple = FacBroker::load_admitted_tuple(fac_root)
        .map_err(|err| format!("admitted canonicalizer tuple unavailable: {err}"))?;
    let current_tuple = CanonicalizerTupleV1::from_current();
    if admitted_tuple != current_tuple {
        return Err(format!(
            "canonicalizer tuple mismatch (current={}/{}, admitted={}/{})",
            current_tuple.canonicalizer_id,
            current_tuple.canonicalizer_version,
            admitted_tuple.canonicalizer_id,
            admitted_tuple.canonicalizer_version
        ));
    }
    Ok(())
}

fn autofix_policy_and_canonicalizer(fac_root: &Path) -> Result<(), String> {
    let policy = ensure_policy_file(fac_root)?;
    let policy_bytes = serde_json::to_vec_pretty(&policy)
        .map_err(|err| format!("cannot serialize policy for adoption: {err}"))?;
    match adopt_policy(
        fac_root,
        &policy_bytes,
        READINESS_ACTOR_ID,
        READINESS_POLICY_REASON,
    ) {
        Ok((_root, _receipt)) => {},
        Err(PolicyAdoptionError::AlreadyAdmitted { .. }) => {},
        Err(err) => {
            return Err(format!("cannot auto-adopt policy: {err}"));
        },
    }

    let mut broker = FacBroker::new();
    broker
        .admit_canonicalizer_tuple(fac_root)
        .map_err(|err| format!("cannot admit canonicalizer tuple: {err}"))?;
    Ok(())
}

fn check_economics_profile(fac_root: &Path) -> Result<(), String> {
    let policy = load_policy_from_disk(fac_root)?;
    let Some(expected_hash) = expected_economics_hash(&policy) else {
        return Ok(());
    };

    let admitted = load_admitted_economics_profile_root(fac_root)
        .map_err(|err| format!("admitted economics profile root unavailable: {err}"))?;
    if admitted.admitted_profile_hash != expected_hash {
        return Err(format!(
            "admitted economics profile mismatch (expected {expected_hash}, got {})",
            admitted.admitted_profile_hash
        ));
    }
    Ok(())
}

fn autofix_economics_profile(fac_root: &Path) -> Result<(), String> {
    let policy = ensure_policy_file(fac_root)?;
    let Some(expected_hash) = expected_economics_hash(&policy) else {
        return Ok(());
    };

    match adopt_economics_profile_by_hash(
        fac_root,
        &expected_hash,
        READINESS_ACTOR_ID,
        READINESS_ECONOMICS_REASON,
    ) {
        Ok((_root, _receipt)) => Ok(()),
        Err(EconomicsAdoptionError::AlreadyAdmitted { .. }) => Ok(()),
        Err(err) => Err(format!("cannot auto-adopt economics profile: {err}")),
    }
}

fn check_worker_and_broker(
    paths: &ReadinessPaths,
    options: ReadinessOptions,
    hooks: WorkerReadinessHooks<'_>,
) -> Result<(), String> {
    let boundary_id = apm2_core::fac::load_or_default_boundary_id(&paths.apm2_home)
        .unwrap_or_else(|_| DEFAULT_AUTHORITY_CLOCK.to_string());
    init_broker(&paths.fac_root, &boundary_id)
        .map_err(|err| format!("broker readiness check failed: {err}"))?;

    if (options.require_external_worker || options.wait_for_worker)
        && !(hooks.has_live_worker_heartbeat)(&paths.fac_root)
    {
        return Err("no live FAC worker heartbeat detected".to_string());
    }
    Ok(())
}

fn autofix_worker_and_broker(
    paths: &ReadinessPaths,
    options: ReadinessOptions,
    hooks: WorkerReadinessHooks<'_>,
) -> Result<bool, String> {
    let boundary_id = apm2_core::fac::load_or_default_boundary_id(&paths.apm2_home)
        .unwrap_or_else(|_| DEFAULT_AUTHORITY_CLOCK.to_string());
    init_broker(&paths.fac_root, &boundary_id)
        .map_err(|err| format!("cannot initialize broker readiness state: {err}"))?;

    if (hooks.has_live_worker_heartbeat)(&paths.fac_root) {
        return Ok(false);
    }

    (hooks.spawn_detached_worker)()?;

    if options.require_external_worker || options.wait_for_worker {
        for _ in 0..EXTERNAL_WORKER_BOOTSTRAP_MAX_POLLS {
            if (hooks.has_live_worker_heartbeat)(&paths.fac_root) {
                return Ok(true);
            }
            std::thread::sleep(Duration::from_millis(
                EXTERNAL_WORKER_BOOTSTRAP_POLL_INTERVAL_MS,
            ));
        }
        if !(hooks.has_live_worker_heartbeat)(&paths.fac_root) {
            return Err(
                "worker heartbeat did not become live after auto-start attempts".to_string(),
            );
        }
    }

    Ok(true)
}

fn check_cargo_deps(paths: &ReadinessPaths) -> Result<(), String> {
    let policy = load_policy_from_disk(&paths.fac_root)?;
    if let Some(cargo_home) = policy.resolve_cargo_home(&paths.apm2_home) {
        apm2_core::fac::verify_dir_permissions(&cargo_home, "managed CARGO_HOME")
            .map_err(|err| format!("managed cargo_home not ready: {err}"))?;
    }
    Ok(())
}

fn autofix_cargo_deps(paths: &ReadinessPaths) -> Result<(), String> {
    let policy = ensure_policy_file(&paths.fac_root)?;
    if let Some(cargo_home) = policy.resolve_cargo_home(&paths.apm2_home) {
        ensure_managed_cargo_home(&cargo_home)?;
    }
    Ok(())
}

fn ensure_policy_file(fac_root: &Path) -> Result<FacPolicyV1, String> {
    let policy_path = policy_file_path(fac_root);
    if !policy_path.exists() {
        let policy = FacPolicyV1::default_policy();
        persist_policy(fac_root, &policy)
            .map_err(|err| format!("cannot persist default fac policy: {err}"))?;
        return Ok(policy);
    }
    load_policy_from_disk(fac_root)
}

fn load_policy_from_disk(fac_root: &Path) -> Result<FacPolicyV1, String> {
    let policy_path = policy_file_path(fac_root);
    let bytes = fac_secure_io::read_bounded(&policy_path, MAX_POLICY_SIZE)
        .map_err(|err| format!("cannot read fac policy {}: {err}", policy_path.display()))?;
    deserialize_policy(&bytes).map_err(|err| format!("cannot parse fac policy: {err}"))
}

fn policy_file_path(fac_root: &Path) -> PathBuf {
    fac_root.join("policy").join("fac_policy.v1.json")
}

fn expected_economics_hash(policy: &FacPolicyV1) -> Option<String> {
    if policy.economics_profile_hash == [0u8; 32] {
        None
    } else {
        Some(format!(
            "b3-256:{}",
            hex::encode(policy.economics_profile_hash)
        ))
    }
}

fn ensure_dir_exists(path: &Path, label: &str) -> Result<(), String> {
    if path.is_dir() {
        Ok(())
    } else {
        Err(format!("{label} missing at {}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    fn readiness_paths_for(apm2_home: &Path) -> ReadinessPaths {
        std::fs::create_dir_all(apm2_home).expect("create APM2_HOME");
        #[cfg(unix)]
        std::fs::set_permissions(apm2_home, std::fs::Permissions::from_mode(0o700))
            .expect("chmod APM2_HOME");
        ReadinessPaths {
            apm2_home: apm2_home.to_path_buf(),
            fac_root: apm2_home.join("private/fac"),
            queue_root: apm2_home.join("private/fac/queue"),
        }
    }

    #[test]
    fn readiness_autoheals_empty_apm2_home() {
        let temp = tempfile::tempdir().expect("tempdir");
        let apm2_home = temp.path().join("apm2_home");
        let paths = readiness_paths_for(&apm2_home);

        let worker_live = Arc::new(AtomicBool::new(false));
        let worker_live_clone = Arc::clone(&worker_live);
        let hooks = WorkerReadinessHooks {
            has_live_worker_heartbeat: &move |_| worker_live.load(Ordering::SeqCst),
            spawn_detached_worker: &move || {
                worker_live_clone.store(true, Ordering::SeqCst);
                Ok(())
            },
        };

        let outcome = run_readiness_controller_for_paths(
            &paths,
            ReadinessOptions {
                require_external_worker: true,
                wait_for_worker: true,
            },
            hooks,
        )
        .expect("readiness should auto-heal");

        assert!(outcome.worker_bootstrapped);
        assert!(
            outcome
                .component_reports
                .iter()
                .any(|entry| entry.status == "autofixed"),
            "fresh substrate should require autofix"
        );

        let fac_root = apm2_home.join("private/fac");
        assert!(fac_root.join("lanes/lane-00/profile.v1.json").exists());
        assert!(
            fac_root
                .join("broker/admitted_canonicalizer_tuple.v1.json")
                .exists()
        );
        assert!(
            fac_root
                .join("broker/admitted_policy_root.v1.json")
                .exists()
        );
    }

    #[test]
    fn readiness_repairs_missing_lane_pool() {
        let temp = tempfile::tempdir().expect("tempdir");
        let apm2_home = temp.path().join("apm2_home");
        let paths = readiness_paths_for(&apm2_home);

        let worker_live = Arc::new(AtomicBool::new(true));
        let hooks = WorkerReadinessHooks {
            has_live_worker_heartbeat: &move |_| worker_live.load(Ordering::SeqCst),
            spawn_detached_worker: &move || Ok(()),
        };

        run_readiness_controller_for_paths(
            &paths,
            ReadinessOptions {
                require_external_worker: false,
                wait_for_worker: false,
            },
            hooks,
        )
        .expect("initial readiness");

        let fac_root = apm2_home.join("private/fac");
        std::fs::remove_dir_all(fac_root.join("lanes")).expect("remove lanes");

        let outcome = run_readiness_controller_for_paths(
            &paths,
            ReadinessOptions {
                require_external_worker: false,
                wait_for_worker: false,
            },
            hooks,
        )
        .expect("lane pool should be reconciled");

        assert!(fac_root.join("lanes/lane-00/profile.v1.json").exists());
        assert!(
            outcome
                .component_reports
                .iter()
                .any(|entry| entry.component == "lane_pool" && entry.status == "autofixed")
        );
    }

    #[test]
    fn readiness_fails_closed_when_worker_autofix_fails() {
        let temp = tempfile::tempdir().expect("tempdir");
        let apm2_home = temp.path().join("apm2_home");
        let paths = readiness_paths_for(&apm2_home);

        let hooks = WorkerReadinessHooks {
            has_live_worker_heartbeat: &move |_| false,
            spawn_detached_worker: &move || Err("spawn denied".to_string()),
        };

        let err = run_readiness_controller_for_paths(
            &paths,
            ReadinessOptions {
                require_external_worker: true,
                wait_for_worker: true,
            },
            hooks,
        )
        .expect_err("worker failure should propagate as PREP_NOT_READY");

        assert_eq!(err.component, "worker_broker");
        assert!(
            err.diagnostics
                .iter()
                .any(|entry| entry.contains("spawn denied")),
            "diagnostics should include autofix failure"
        );
    }

    #[test]
    fn readiness_is_noop_on_ready_substrate_under_100ms() {
        let temp = tempfile::tempdir().expect("tempdir");
        let apm2_home = temp.path().join("apm2_home");
        let paths = readiness_paths_for(&apm2_home);

        let worker_live = Arc::new(AtomicBool::new(true));
        let hooks = WorkerReadinessHooks {
            has_live_worker_heartbeat: &move |_| worker_live.load(Ordering::SeqCst),
            spawn_detached_worker: &move || Ok(()),
        };

        run_readiness_controller_for_paths(
            &paths,
            ReadinessOptions {
                require_external_worker: false,
                wait_for_worker: false,
            },
            hooks,
        )
        .expect("first run establishes substrate");

        let outcome = run_readiness_controller_for_paths(
            &paths,
            ReadinessOptions {
                require_external_worker: false,
                wait_for_worker: false,
            },
            hooks,
        )
        .expect("ready run should pass");

        assert!(
            outcome.elapsed_ms < 100,
            "ready substrate run should stay below 100ms, observed {}ms",
            outcome.elapsed_ms
        );
        assert!(
            outcome
                .component_reports
                .iter()
                .all(|entry| entry.status == "ready"),
            "ready run should not mutate substrate"
        );
    }
}
