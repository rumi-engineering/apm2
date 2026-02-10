//! Shared daemon state.
//!
//! Provides thread-safe shared state for the daemon.
//!
//! # TCK-00287: Security Fixes
//!
//! Per the security review, dispatchers and registries must be shared across
//! connections to prevent state loss and authentication secret rotation issues.
//! This module provides the `DispatcherState` struct that holds:
//! - `PrivilegedDispatcher` with shared registries
//! - `SessionDispatcher` with stable `TokenMinter` secret
//! - `FailClosedManifestStore` that denies all tools by default

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use apm2_core::config::{AdapterRotationConfig, AdapterRotationStrategyConfig, EcosystemConfig};
use apm2_core::credentials::{AuthMethod, CredentialProfile, CredentialStore, ProfileId, Provider};
use apm2_core::fac::{
    AdapterSelectionPolicy, AdapterSelectionStrategy, CLAUDE_CODE_PROFILE_ID, CODEX_CLI_PROFILE_ID,
    GEMINI_CLI_PROFILE_ID, LOCAL_INFERENCE_PROFILE_ID, ProfileWeight, all_builtin_profiles,
};
use apm2_core::process::ProcessId;
use apm2_core::process::runner::ProcessRunner;
use apm2_core::schema_registry::InMemorySchemaRegistry;
use apm2_core::supervisor::Supervisor;
use chrono::{DateTime, Utc};
use rusqlite::Connection;
use secrecy::{ExposeSecret, SecretString};
use tokio::sync::RwLock;

use crate::cas::{DurableCas, DurableCasConfig, DurableCasError};
use crate::episode::capability::{InMemoryCasManifestLoader, StubManifestLoader};
use crate::episode::executor::ContentAddressedStore;
use crate::episode::handlers::{
    ArtifactFetchHandler, ExecuteHandler, GitOperationHandler, ListFilesHandler, ReadFileHandler,
    SandboxConfig, SearchHandler, WriteFileHandler,
};
use crate::episode::{
    CapabilityManifest, EpisodeRuntime, EpisodeRuntimeConfig, InMemorySessionRegistry,
    PersistentRegistryError, PersistentSessionRegistry, SessionBrokerRegistry,
    SharedSessionBrokerRegistry, ToolBrokerConfig,
};
use crate::evidence::keychain::{
    GitHubCredentialStore, KeychainError, MAX_SSH_AUTH_SOCK_LEN, MAX_TOKEN_SIZE, SshCredentialStore,
};
use crate::gate::{GateOrchestrator, GateOrchestratorEvent, MergeExecutor, SessionTerminatedInfo};
use crate::governance::{
    GovernanceFreshnessConfig, GovernanceFreshnessMonitor, GovernancePolicyResolver,
};
use crate::htf::{ClockConfig, HolonicClock};
use crate::ledger::{SqliteLeaseValidator, SqliteLedgerEventEmitter, SqliteWorkRegistry};
use crate::metrics::SharedMetricsRegistry;
use crate::protocol::dispatch::{
    PolicyResolutionError, PolicyResolver, PrivilegedDispatcher, PrivilegedPcacPolicy,
};
use crate::protocol::messages::{DecodeConfig, WorkRole};
use crate::protocol::resource_governance::{SharedSubscriptionRegistry, SubscriptionRegistry};
use crate::protocol::session_dispatch::{
    InMemoryManifestStore, ManifestStore, SessionDispatcher, V1ManifestStore,
};
use crate::protocol::session_token::TokenMinter;
use crate::session::{SessionRegistry, SessionStopConditionsStore, SessionTelemetryStore};

// ============================================================================
// TCK-00343: Credential Store Service Name
// ============================================================================

/// Service name for the credential store keyring entries (TCK-00343).
///
/// This service name is used when creating the `CredentialStore` that backs
/// the credential management IPC commands (`ListCredentials`, `AddCredential`,
/// `RemoveCredential`, etc.). It is distinct from the signing key service name
/// (`apm2-receipt-signing`) and GitHub token service name
/// (`apm2-github-tokens`) to avoid keyring entry collisions.
const CREDENTIAL_STORE_SERVICE_NAME: &str = "apm2-credentials";

/// Stores all builtin adapter profiles in CAS and returns `profile_id` -> hash.
///
/// TCK-00400 requires all builtin profiles to be addressable in CAS at daemon
/// startup so hash-based selection and explicit overrides can resolve them.
fn seed_builtin_profiles_in_cas(
    cas: &dyn apm2_core::evidence::ContentAddressedStore,
) -> Result<HashMap<String, [u8; 32]>, String> {
    let mut profile_hashes: HashMap<String, [u8; 32]> = HashMap::new();
    for profile in all_builtin_profiles() {
        let profile_id = profile.profile_id.clone();
        let hash = profile
            .store_in_cas(cas)
            .map_err(|e| format!("failed to store builtin profile '{profile_id}' in CAS: {e}"))?;
        profile_hashes.insert(profile_id, hash);
    }
    Ok(profile_hashes)
}

/// Returns true if this builtin profile is supported by the registered
/// adapters.
fn is_profile_adapter_available(
    profile_id: &str,
    adapter_registry: &crate::episode::AdapterRegistry,
) -> bool {
    use crate::episode::AdapterType;

    match profile_id {
        // Current spawn path uses Raw adapter for most black-box profiles.
        CLAUDE_CODE_PROFILE_ID | GEMINI_CLI_PROFILE_ID | LOCAL_INFERENCE_PROFILE_ID => {
            adapter_registry.contains(AdapterType::Raw)
        },
        // TCK-00402: codex-cli-v1 uses dedicated Codex adapter.
        CODEX_CLI_PROFILE_ID => adapter_registry.contains(AdapterType::Codex),
        _ => false,
    }
}

/// Builds adapter selection policy + availability set from config and CAS
/// hashes.
fn build_adapter_selection_policy(
    rotation: &AdapterRotationConfig,
    profile_hashes: &HashMap<String, [u8; 32]>,
    adapter_registry: &crate::episode::AdapterRegistry,
) -> Result<(AdapterSelectionPolicy, std::collections::BTreeSet<[u8; 32]>), String> {
    let strategy = match rotation.strategy {
        AdapterRotationStrategyConfig::WeightedRandom => AdapterSelectionStrategy::WeightedRandom,
        AdapterRotationStrategyConfig::RoundRobin => AdapterSelectionStrategy::RoundRobin,
    };

    let mut available_profile_hashes = std::collections::BTreeSet::new();
    let mut entries: Vec<ProfileWeight> = Vec::with_capacity(rotation.profiles.len());
    for configured in &rotation.profiles {
        let Some(profile_hash) = profile_hashes.get(&configured.profile_id).copied() else {
            return Err(format!(
                "daemon.adapter_rotation references unknown profile_id '{}'",
                configured.profile_id
            ));
        };

        if is_profile_adapter_available(&configured.profile_id, adapter_registry) {
            available_profile_hashes.insert(profile_hash);
        }

        entries.push(ProfileWeight {
            profile_hash,
            profile_id: configured.profile_id.clone(),
            weight: configured.weight,
            enabled: configured.enabled,
            fallback_priority: configured.fallback_priority,
            last_failure_at: None,
            failure_count: 0,
        });
    }

    let policy = AdapterSelectionPolicy {
        entries,
        strategy,
        rate_limit_backoff_secs: rotation.rate_limit_backoff_secs,
    };
    policy.validate().map_err(|e| e.to_string())?;

    // Fail closed at startup if no configured+enabled profile is currently
    // adapter-eligible.
    let has_runtime_eligible = policy.entries.iter().any(|entry| {
        entry.enabled && entry.weight > 0 && available_profile_hashes.contains(&entry.profile_hash)
    });
    if !has_runtime_eligible {
        return Err(
            "daemon.adapter_rotation has no adapter-eligible enabled profile (all gated unavailable)"
                .to_string(),
        );
    }

    Ok((policy, available_profile_hashes))
}

/// Derives the durable PCAC consume-log path from the `SQLite` main database.
///
/// Authoritative persistence mode must bind durable consume state to the
/// daemon's durable runtime storage, not a temporary directory.
fn derive_pcac_consume_log_path(sqlite_conn: &Arc<Mutex<Connection>>) -> Result<PathBuf, String> {
    let conn = sqlite_conn
        .lock()
        .map_err(|e| format!("sqlite connection lock poisoned while deriving PCAC path: {e}"))?;

    let mut stmt = conn
        .prepare("PRAGMA database_list")
        .map_err(|e| format!("failed to query sqlite database list for PCAC path: {e}"))?;
    let mut rows = stmt
        .query([])
        .map_err(|e| format!("failed to iterate sqlite database list for PCAC path: {e}"))?;

    while let Some(row) = rows
        .next()
        .map_err(|e| format!("failed to read sqlite database row for PCAC path: {e}"))?
    {
        let name: String = row
            .get(1)
            .map_err(|e| format!("failed to read sqlite database name for PCAC path: {e}"))?;
        if name != "main" {
            continue;
        }

        let file: String = row
            .get(2)
            .map_err(|e| format!("failed to read sqlite database file for PCAC path: {e}"))?;
        if file.is_empty() || file == ":memory:" {
            return Err(
                "authoritative PCAC requires file-backed sqlite; in-memory main database has no durable path"
                    .to_string(),
            );
        }

        let db_path = PathBuf::from(file);
        let Some(parent) = db_path.parent() else {
            return Err(format!(
                "sqlite main database has no parent directory for PCAC path: {}",
                db_path.display()
            ));
        };
        return Ok(parent.join("pcac_consume.log"));
    }

    Err("sqlite main database entry not found while deriving PCAC path".to_string())
}

/// Returns the bootstrap sovereignty enforcement mode used during daemon
/// construction.
///
/// TODO(TCK-00427): Load this mode from runtime governance/policy projection
/// instead of a transitional static default.
const fn bootstrap_sovereignty_enforcement_mode() -> apm2_core::pcac::SovereigntyEnforcementMode {
    apm2_core::pcac::SovereigntyEnforcementMode::Strict
}

/// Builds the bootstrap sovereignty state snapshot for session dispatcher
/// wiring.
///
/// TODO(TCK-00427): Hydrate and wire authoritative sovereignty state via
/// runtime IPC/projection updates.
///
/// NOTE: Tier2+ requests are denied fail-closed by default because no runtime
/// sovereignty state is hydrated. This is intentional — the operator must
/// provide authoritative sovereignty state via IPC before Tier2+ operations are
/// permitted. See RFC-0027 §6.6 for runtime hydration requirements.
fn bootstrap_sovereignty_state(
    mode: apm2_core::pcac::SovereigntyEnforcementMode,
) -> Option<Arc<crate::pcac::SovereigntyState>> {
    if mode == apm2_core::pcac::SovereigntyEnforcementMode::Disabled {
        return None;
    }

    None
}

const GITHUB_PROFILE_PREFIX: &str = "github-installation:";
const SSH_PROFILE_PREFIX: &str = "ssh-session:";

#[derive(Clone)]
struct CredentialStoreGitHubAdapter {
    store: Arc<CredentialStore>,
}

impl CredentialStoreGitHubAdapter {
    const fn new(store: Arc<CredentialStore>) -> Self {
        Self { store }
    }

    fn profile_id(installation_id: &str) -> ProfileId {
        ProfileId::new(format!("{GITHUB_PROFILE_PREFIX}{installation_id}"))
    }
}

impl GitHubCredentialStore for CredentialStoreGitHubAdapter {
    fn store_token(&self, installation_id: &str, token: &str) -> Result<(), KeychainError> {
        if token.len() > MAX_TOKEN_SIZE {
            return Err(KeychainError::TokenTooLarge {
                size: token.len(),
                max: MAX_TOKEN_SIZE,
            });
        }

        let profile = CredentialProfile::new(
            Self::profile_id(installation_id),
            Provider::Custom,
            AuthMethod::ApiKey {
                key: SecretString::from(token.to_string()),
            },
        );

        self.store.store(profile).map_err(|e| match e {
            apm2_core::credentials::CredentialStoreError::NotFound(_) => KeychainError::NotFound {
                key_id: installation_id.to_string(),
            },
            apm2_core::credentials::CredentialStoreError::LockPoisoned => {
                KeychainError::LockPoisoned
            },
            apm2_core::credentials::CredentialStoreError::Keyring(msg)
            | apm2_core::credentials::CredentialStoreError::Serialization(msg) => {
                KeychainError::Keychain(msg)
            },
        })
    }

    fn get_token(&self, installation_id: &str) -> Result<String, KeychainError> {
        let profile = self
            .store
            .get(&Self::profile_id(installation_id))
            .map_err(|e| match e {
                apm2_core::credentials::CredentialStoreError::NotFound(_) => {
                    KeychainError::NotFound {
                        key_id: installation_id.to_string(),
                    }
                },
                apm2_core::credentials::CredentialStoreError::LockPoisoned => {
                    KeychainError::LockPoisoned
                },
                apm2_core::credentials::CredentialStoreError::Keyring(msg)
                | apm2_core::credentials::CredentialStoreError::Serialization(msg) => {
                    KeychainError::Keychain(msg)
                },
            })?;

        let token = match profile.auth {
            AuthMethod::ApiKey { key } => key.expose_secret().to_string(),
            AuthMethod::OAuth { access_token, .. } => access_token.expose_secret().to_string(),
            AuthMethod::SessionToken { token, .. } => token.expose_secret().to_string(),
        };
        Ok(token)
    }

    fn delete_token(&self, installation_id: &str) -> Result<(), KeychainError> {
        match self.store.remove(&Self::profile_id(installation_id)) {
            Ok(()) | Err(apm2_core::credentials::CredentialStoreError::NotFound(_)) => Ok(()),
            Err(apm2_core::credentials::CredentialStoreError::LockPoisoned) => {
                Err(KeychainError::LockPoisoned)
            },
            Err(
                apm2_core::credentials::CredentialStoreError::Keyring(msg)
                | apm2_core::credentials::CredentialStoreError::Serialization(msg),
            ) => Err(KeychainError::Keychain(msg)),
        }
    }
}

#[derive(Clone)]
struct CredentialStoreSshAdapter {
    store: Arc<CredentialStore>,
}

impl CredentialStoreSshAdapter {
    const fn new(store: Arc<CredentialStore>) -> Self {
        Self { store }
    }

    fn profile_id(session_id: &str) -> ProfileId {
        ProfileId::new(format!("{SSH_PROFILE_PREFIX}{session_id}"))
    }
}

impl SshCredentialStore for CredentialStoreSshAdapter {
    fn store_ssh_auth_sock(
        &self,
        session_id: &str,
        auth_sock_path: &str,
    ) -> Result<(), KeychainError> {
        if auth_sock_path.len() > MAX_SSH_AUTH_SOCK_LEN {
            return Err(KeychainError::SshAuthSockTooLong {
                len: auth_sock_path.len(),
                max: MAX_SSH_AUTH_SOCK_LEN,
            });
        }

        let profile = CredentialProfile::new(
            Self::profile_id(session_id),
            Provider::Custom,
            AuthMethod::SessionToken {
                token: SecretString::from(auth_sock_path.to_string()),
                cookie_jar: None,
                expires_at: None,
            },
        );

        self.store.store(profile).map_err(|e| match e {
            apm2_core::credentials::CredentialStoreError::NotFound(_) => KeychainError::NotFound {
                key_id: session_id.to_string(),
            },
            apm2_core::credentials::CredentialStoreError::LockPoisoned => {
                KeychainError::LockPoisoned
            },
            apm2_core::credentials::CredentialStoreError::Keyring(msg)
            | apm2_core::credentials::CredentialStoreError::Serialization(msg) => {
                KeychainError::Keychain(msg)
            },
        })
    }

    fn get_ssh_auth_sock(&self, session_id: &str) -> Result<String, KeychainError> {
        let profile = self
            .store
            .get(&Self::profile_id(session_id))
            .map_err(|e| match e {
                apm2_core::credentials::CredentialStoreError::NotFound(_) => {
                    KeychainError::NotFound {
                        key_id: session_id.to_string(),
                    }
                },
                apm2_core::credentials::CredentialStoreError::LockPoisoned => {
                    KeychainError::LockPoisoned
                },
                apm2_core::credentials::CredentialStoreError::Keyring(msg)
                | apm2_core::credentials::CredentialStoreError::Serialization(msg) => {
                    KeychainError::Keychain(msg)
                },
            })?;

        let path = match profile.auth {
            AuthMethod::SessionToken { token, .. } => token.expose_secret().to_string(),
            AuthMethod::ApiKey { key } => key.expose_secret().to_string(),
            AuthMethod::OAuth { access_token, .. } => access_token.expose_secret().to_string(),
        };
        Ok(path)
    }

    fn clear_ssh_auth_sock(&self, session_id: &str) -> Result<(), KeychainError> {
        match self.store.remove(&Self::profile_id(session_id)) {
            Ok(()) | Err(apm2_core::credentials::CredentialStoreError::NotFound(_)) => Ok(()),
            Err(apm2_core::credentials::CredentialStoreError::LockPoisoned) => {
                Err(KeychainError::LockPoisoned)
            },
            Err(
                apm2_core::credentials::CredentialStoreError::Keyring(msg)
                | apm2_core::credentials::CredentialStoreError::Serialization(msg),
            ) => Err(KeychainError::Keychain(msg)),
        }
    }

    fn is_ssh_agent_available(&self) -> bool {
        self.get_daemon_ssh_auth_sock().is_some()
    }

    fn get_daemon_ssh_auth_sock(&self) -> Option<String> {
        std::env::var("SSH_AUTH_SOCK")
            .ok()
            .filter(|path| std::path::Path::new(path).exists())
    }
}

#[cfg(not(test))]
const GOVERNANCE_FRESHNESS_POLL_INTERVAL_MS: u64 = 30_000;
#[cfg(test)]
const GOVERNANCE_FRESHNESS_POLL_INTERVAL_MS: u64 = 25;

#[cfg(not(test))]
const GOVERNANCE_FRESHNESS_THRESHOLD_MS: u64 = 30_000;
#[cfg(test)]
const GOVERNANCE_FRESHNESS_THRESHOLD_MS: u64 = 120;

// ============================================================================
// TCK-00287: Fail-Closed Manifest Store (kept for potential future use)
// ============================================================================

/// A manifest store that always returns `None`, enforcing fail-closed behavior.
///
/// Per TCK-00287 security review item 3 (Permissive Default), the
/// `SessionDispatcher` must deny all tools if no manifest is available. When
/// this store is used with `SessionDispatcher::with_manifest_store()`, any tool
/// request will be denied because `get_manifest()` returns `None`, triggering
/// the fail-closed path in `handle_request_tool()`.
///
/// # Security Invariant (INV-TCK-00260-002)
///
/// Empty or missing `tool_allowlist` denies all tools (fail-closed).
///
/// # Current Status
///
/// This struct is currently unused as the implementation now uses
/// `InMemoryManifestStore` shared between dispatchers. It is kept for potential
/// future use as a default-deny store for testing or specific security
/// scenarios.
#[derive(Debug, Default)]
#[allow(dead_code)]
pub struct FailClosedManifestStore;

impl ManifestStore for FailClosedManifestStore {
    fn get_manifest(&self, _session_id: &str) -> Option<Arc<CapabilityManifest>> {
        // Always return None to trigger fail-closed behavior in SessionDispatcher.
        // The dispatcher will return SESSION_ERROR_TOOL_NOT_ALLOWED when no manifest
        // is found for a session.
        None
    }
}

// ============================================================================
// TCK-00287: Shared Dispatcher State
// ============================================================================

/// Shared dispatcher state across all connections.
///
/// Per TCK-00287 security review:
/// - Item 1 (Cross-Connection State Loss): Dispatchers must persist across
///   connections
/// - Item 2 (Authentication Secret Rotation): `TokenMinter` secret must be
///   stable
/// - Item 3 (Permissive Default): Must use fail-closed manifest store
///   initially, but allow manifests to be registered during `SpawnEpisode`
///
/// # TCK-00287 BLOCKER 1, 2, 3 Fixes
///
/// This struct now shares:
/// - `TokenMinter`: Same secret for both minting and validation
/// - `InMemoryManifestStore`: Manifests registered during spawn are visible
/// - `SessionRegistry`: Global session registry from `DaemonStateHandle`
///
/// This ensures that:
/// 1. Sessions spawned via IPC are visible to daemon's persistent state
/// 2. Clients receive HMAC-signed tokens they can use for session endpoints
/// 3. Tool requests can be validated against manifests registered during spawn
pub struct DispatcherState {
    /// Privileged endpoint dispatcher with shared registries.
    ///
    /// Contains `WorkRegistry`, `SessionRegistry`, and `LedgerEventEmitter`
    /// that persist across connections. Now also contains shared
    /// `TokenMinter` and `ManifestStore` for TCK-00287 fixes.
    privileged_dispatcher: PrivilegedDispatcher,

    /// Session endpoint dispatcher with stable token minter.
    ///
    /// The `TokenMinter` uses the same secret as `PrivilegedDispatcher`,
    /// ensuring tokens minted during spawn can be validated here.
    /// The `ManifestStore` is shared with `PrivilegedDispatcher` so manifests
    /// registered during spawn are accessible for tool validation.
    session_dispatcher: SessionDispatcher<InMemoryManifestStore>,

    /// Gate execution orchestrator for autonomous gate lifecycle (TCK-00388).
    ///
    /// When set, the dispatcher invokes
    /// [`GateOrchestrator::on_session_terminated`] from the production
    /// session termination path, returning ledger events for persistence.
    gate_orchestrator: Option<Arc<GateOrchestrator>>,

    /// Merge executor for autonomous merge after gate approval (TCK-00390).
    ///
    /// When set, the merge executor is available for triggering the
    /// autonomous merge lifecycle when all gate receipts reach PASS verdict.
    /// It verifies policy hash, executes squash merge via GitHub API,
    /// creates a signed `MergeReceipt`, and transitions work to Completed.
    merge_executor: Option<Arc<MergeExecutor>>,

    /// Shared stop authority for runtime mutation (TCK-00351 MAJOR 2 FIX).
    ///
    /// Stored as `Arc` so operator/governance control-plane paths can
    /// mutate stop flags at runtime (e.g., set emergency stop) and the
    /// pre-actuation gate immediately sees the change.
    stop_authority: Option<Arc<crate::episode::preactuation::StopAuthority>>,

    /// Governance freshness monitor wired to the shared stop authority.
    ///
    /// When present, explicit governance probe paths can toggle
    /// `governance_uncertain` fail-closed behavior in pre-actuation.
    governance_freshness_monitor: Option<Arc<GovernanceFreshnessMonitor>>,

    /// Shared evidence CAS backend (TCK-00418).
    ///
    /// When present, this is the same `DurableCas` (or `MemoryCas` in tests)
    /// that backs the `PrivilegedDispatcher`'s `validate_lease_time_authority`.
    /// The gate orchestrator MUST share this instance so that
    /// `time_envelope_ref` hashes stored during `issue_gate_lease` are
    /// resolvable by the dispatcher during receipt ingestion.
    evidence_cas: Option<Arc<dyn apm2_core::evidence::ContentAddressedStore>>,
}

impl DispatcherState {
    /// Creates new dispatcher state with shared registries and stable secrets.
    ///
    /// # Arguments
    ///
    /// * `metrics_registry` - Optional metrics registry for observability
    ///
    /// # Security
    ///
    /// - Generates a single HMAC secret for `TokenMinter` at startup
    /// - Shares `TokenMinter` between both dispatchers for token
    ///   minting/validation
    /// - Shares `InMemoryManifestStore` so spawn manifests are visible to
    ///   session handlers
    /// - Registries persist for daemon lifetime
    ///
    /// # TCK-00287 Fixes
    ///
    /// - BLOCKER 1: Uses shared session registry (passed via
    ///   `with_session_registry`)
    /// - BLOCKER 2: Shares `TokenMinter` so spawn can mint tokens
    /// - MAJOR 3: Shares `ManifestStore` so spawn manifests are visible
    ///
    /// # Note
    ///
    /// This constructor creates an internal stub session registry. For
    /// production use with the global daemon session registry, use
    /// `with_session_registry`.
    #[must_use]
    #[allow(dead_code)] // Kept for testing and potential future use
    pub fn new(metrics_registry: Option<SharedMetricsRegistry>) -> Self {
        // TCK-00287 Item 2: Generate a single stable secret at daemon startup.
        // This secret is used for the entire daemon lifetime, ensuring tokens
        // minted on one connection are valid on other connections.
        let token_secret = TokenMinter::generate_secret();
        let token_minter = Arc::new(TokenMinter::new(token_secret));

        // TCK-00287 MAJOR 3: Use shared manifest store.
        // Manifests registered during SpawnEpisode will be visible to SessionDispatcher
        // for tool request validation. If no manifest is registered for a session,
        // tool requests will be denied (fail-closed behavior in handle_request_tool).
        let manifest_store = Arc::new(InMemoryManifestStore::new());

        // TCK-00287: Create session registry (stub for now, use with_session_registry
        // for real)
        let session_registry: Arc<dyn SessionRegistry> = Arc::new(InMemorySessionRegistry::new());

        // TCK-00289: Create shared HolonicClock to prevent mixed clock domain hazard
        // (RSK-2503)
        let clock = Arc::new(
            HolonicClock::new(ClockConfig::default(), None)
                .expect("failed to create default clock"),
        );

        // TCK-00303: Create shared subscription registry for HEF resource governance
        let subscription_registry: SharedSubscriptionRegistry =
            Arc::new(SubscriptionRegistry::with_defaults());

        // TCK-00343: Create credential store for credential management
        let credential_store = Arc::new(CredentialStore::new(CREDENTIAL_STORE_SERVICE_NAME));

        // TCK-00287 BLOCKER 1 & 2: Create privileged dispatcher with shared state
        let privileged_dispatcher = PrivilegedDispatcher::with_shared_state(
            Arc::clone(&token_minter),
            Arc::clone(&manifest_store),
            Arc::clone(&session_registry),
            clock,
            Arc::clone(&subscription_registry),
        )
        .with_credential_store(credential_store)
        .with_privileged_pcac_policy(PrivilegedPcacPolicy::default());

        // Add metrics if provided
        let privileged_dispatcher = if let Some(metrics) = metrics_registry {
            privileged_dispatcher.with_metrics(metrics)
        } else {
            privileged_dispatcher
        };

        // TCK-00384: Create shared telemetry store for session counters
        let telemetry_store = Arc::new(SessionTelemetryStore::new());

        // TCK-00384: Wire telemetry store into privileged dispatcher for SpawnEpisode
        // registration
        let privileged_dispatcher =
            privileged_dispatcher.with_telemetry_store(Arc::clone(&telemetry_store));

        // TCK-00287: Create session dispatcher with same token minter and manifest
        // store This ensures:
        // - Tokens minted during SpawnEpisode can be validated
        // - Manifests registered during SpawnEpisode are visible for tool validation
        // TCK-00303: Share subscription registry for HEF resource governance
        // TCK-00344: Wire session registry for SessionStatus queries
        // TCK-00384: Wire telemetry store for counter updates and SessionStatus queries
        let session_dispatcher =
            SessionDispatcher::with_manifest_store((*token_minter).clone(), manifest_store)
                .with_channel_context_signer(Arc::new(apm2_core::crypto::Signer::generate()))
                .with_subscription_registry(subscription_registry)
                .with_session_registry(session_registry)
                .with_telemetry_store(telemetry_store);

        Self {
            privileged_dispatcher,
            session_dispatcher,
            gate_orchestrator: None,
            merge_executor: None,
            stop_authority: None,
            governance_freshness_monitor: None,
            evidence_cas: None,
        }
    }

    /// Creates new dispatcher state with a specific session registry.
    ///
    /// # TCK-00287 BLOCKER 1
    ///
    /// This constructor allows using the global `DaemonStateHandle` session
    /// registry instead of an internal stub, ensuring sessions spawned via
    /// IPC are visible to the daemon's persistent state.
    ///
    /// # Arguments
    ///
    /// * `session_registry` - The global session registry from
    ///   `DaemonStateHandle`
    /// * `metrics_registry` - Optional metrics registry for observability
    #[must_use]
    pub fn with_session_registry(
        session_registry: Arc<dyn SessionRegistry>,
        metrics_registry: Option<SharedMetricsRegistry>,
    ) -> Self {
        // TCK-00287 Item 2: Generate a single stable secret at daemon startup.
        let token_secret = TokenMinter::generate_secret();
        let token_minter = Arc::new(TokenMinter::new(token_secret));

        // TCK-00287 MAJOR 3: Use shared manifest store.
        let manifest_store = Arc::new(InMemoryManifestStore::new());

        // TCK-00289: Create shared HolonicClock to prevent mixed clock domain hazard
        // (RSK-2503)
        let clock = Arc::new(
            HolonicClock::new(ClockConfig::default(), None)
                .expect("failed to create default clock"),
        );

        // TCK-00303: Create shared subscription registry for HEF resource governance
        let subscription_registry: SharedSubscriptionRegistry =
            Arc::new(SubscriptionRegistry::with_defaults());

        // TCK-00343: Create credential store for credential management
        let credential_store = Arc::new(CredentialStore::new(CREDENTIAL_STORE_SERVICE_NAME));

        // TCK-00287 BLOCKER 1: Create privileged dispatcher with global session
        // registry
        let privileged_dispatcher = PrivilegedDispatcher::with_shared_state(
            Arc::clone(&token_minter),
            Arc::clone(&manifest_store),
            Arc::clone(&session_registry),
            clock,
            Arc::clone(&subscription_registry),
        )
        .with_credential_store(credential_store)
        .with_privileged_pcac_policy(PrivilegedPcacPolicy::default());

        // Add metrics if provided
        let privileged_dispatcher = if let Some(metrics) = metrics_registry {
            privileged_dispatcher.with_metrics(metrics)
        } else {
            privileged_dispatcher
        };

        // TCK-00384: Create shared telemetry store for session counters
        let telemetry_store = Arc::new(SessionTelemetryStore::new());

        // TCK-00384: Wire telemetry store into privileged dispatcher for SpawnEpisode
        // registration
        let privileged_dispatcher =
            privileged_dispatcher.with_telemetry_store(Arc::clone(&telemetry_store));

        // TCK-00287: Create session dispatcher with same token minter and manifest
        // store
        // TCK-00303: Share subscription registry for HEF resource governance
        // TCK-00344: Wire session registry for SessionStatus queries
        // TCK-00384: Wire telemetry store for counter updates and SessionStatus queries
        let session_dispatcher =
            SessionDispatcher::with_manifest_store((*token_minter).clone(), manifest_store)
                .with_channel_context_signer(Arc::new(apm2_core::crypto::Signer::generate()))
                .with_subscription_registry(subscription_registry)
                .with_session_registry(session_registry)
                .with_telemetry_store(telemetry_store);

        Self {
            privileged_dispatcher,
            session_dispatcher,
            gate_orchestrator: None,
            merge_executor: None,
            stop_authority: None,
            governance_freshness_monitor: None,
            evidence_cas: None,
        }
    }

    /// Creates new dispatcher state with persistent ledger components
    /// (TCK-00289).
    ///
    /// # Arguments
    ///
    /// * `session_registry` - Global session registry
    /// * `metrics_registry` - Optional metrics registry
    /// * `sqlite_conn` - Optional `SQLite` connection for persistent ledger. If
    ///   provided, uses durable `Sqlite*` implementations. Otherwise uses
    ///   stubs.
    /// * `ledger_signing_key` - Optional ledger signing key. When provided, the
    ///   dispatcher reuses this key instead of generating a new ephemeral one.
    ///   Per Security Review v5 MAJOR 2, there must be ONE signing key per
    ///   daemon lifecycle, shared between crash recovery and the dispatcher.
    /// # Errors
    ///
    /// Returns `Err` if adapter rotation initialization fails (e.g. CAS
    /// seeding or policy validation).
    pub fn with_persistence(
        session_registry: Arc<dyn SessionRegistry>,
        metrics_registry: Option<SharedMetricsRegistry>,
        sqlite_conn: Option<Arc<Mutex<Connection>>>,
        ledger_signing_key: Option<ed25519_dalek::SigningKey>,
    ) -> Result<Self, String> {
        Self::with_persistence_and_adapter_rotation(
            session_registry,
            metrics_registry,
            sqlite_conn,
            ledger_signing_key,
            &AdapterRotationConfig::default(),
        )
    }

    /// Creates new dispatcher state with persistent ledger components and
    /// adapter rotation config (TCK-00400).
    ///
    /// # Errors
    ///
    /// Returns `Err` if adapter rotation initialization fails. Specifically:
    /// - CAS seeding of builtin adapter profiles fails
    /// - Adapter selection policy validation fails
    /// - No adapter-eligible enabled profile is available at startup
    ///
    /// Fail-closed: startup errors must be surfaced to the caller rather
    /// than silently falling back to defaults that may violate policy.
    pub fn with_persistence_and_adapter_rotation(
        session_registry: Arc<dyn SessionRegistry>,
        metrics_registry: Option<SharedMetricsRegistry>,
        sqlite_conn: Option<Arc<Mutex<Connection>>>,
        ledger_signing_key: Option<ed25519_dalek::SigningKey>,
        adapter_rotation: &AdapterRotationConfig,
    ) -> Result<Self, String> {
        let token_secret = TokenMinter::generate_secret();
        let token_minter = Arc::new(TokenMinter::new(token_secret));
        let manifest_store = Arc::new(InMemoryManifestStore::new());
        let sqlite_conn_for_pcac = sqlite_conn.clone();
        let mut channel_context_signer = Arc::new(apm2_core::crypto::Signer::generate());
        let mut sovereignty_trusted_signer_key = ledger_signing_key
            .as_ref()
            .map(|key| key.verifying_key().to_bytes());

        // TCK-00303: Create shared subscription registry for HEF resource governance
        let subscription_registry: SharedSubscriptionRegistry =
            Arc::new(SubscriptionRegistry::with_defaults());

        // TCK-00344: Clone session_registry before it is moved into the
        // privileged dispatcher so we can also wire it into the session dispatcher.
        let session_registry_for_session = Arc::clone(&session_registry);
        // TCK-00385 BLOCKER 1: Clone session_registry for EpisodeRuntime so that
        // stop()/quarantine() can call mark_terminated() in production.
        let session_registry_for_runtime = Arc::clone(&session_registry);

        // TCK-00343: Create credential store for credential management
        let credential_store = Arc::new(CredentialStore::new(CREDENTIAL_STORE_SERVICE_NAME));

        // TCK-00352: Create shared V1 manifest store for scope enforcement
        let v1_manifest_store = Arc::new(V1ManifestStore::new());

        let privileged_dispatcher = if let Some(conn) = sqlite_conn {
            // Use real implementations
            // Security Review v5 MAJOR 2: Reuse the daemon-lifecycle signing key
            // if provided, otherwise generate a new one. This ensures recovery
            // and dispatcher events are signed with the same key.
            let signing_key = ledger_signing_key.unwrap_or_else(|| {
                use rand::rngs::OsRng;
                ed25519_dalek::SigningKey::generate(&mut OsRng)
            });
            channel_context_signer = Arc::new(apm2_core::crypto::Signer::new(signing_key.clone()));
            sovereignty_trusted_signer_key = Some(signing_key.verifying_key().to_bytes());

            let policy_resolver = Arc::new(GovernancePolicyResolver::new());
            let work_registry = Arc::new(SqliteWorkRegistry::new(Arc::clone(&conn)));
            let event_emitter = Arc::new(SqliteLedgerEventEmitter::new(
                Arc::clone(&conn),
                signing_key,
            ));
            let lease_validator = Arc::new(SqliteLeaseValidator::new(Arc::clone(&conn)));

            // TCK-00319 SECURITY: Configure EpisodeRuntime with workspace-rooted handlers
            // All file/execute handlers MUST use rooted factories that receive the
            // workspace root at episode start time. This ensures handlers are isolated
            // to the episode's workspace, not the daemon's CWD.
            let mut episode_runtime = EpisodeRuntime::new(EpisodeRuntimeConfig::default());
            episode_runtime = episode_runtime
                // ReadFileHandler - reads files within workspace
                .with_rooted_handler_factory(|root| {
                    Box::new(ReadFileHandler::with_root(root))
                })
                // WriteFileHandler - writes files within workspace
                .with_rooted_handler_factory(|root| {
                    Box::new(WriteFileHandler::with_root(root))
                })
                // ExecuteHandler - executes commands within workspace
                // TCK-00338: Env scrubbing + stall detection are always active.
                // Shell allowlist uses permissive() because the ToolBroker already
                // enforces shell allowlists via CapabilityManifest before the
                // handler is invoked. The handler-level allowlist is defense-in-depth
                // for non-brokered contexts only.
                .with_rooted_handler_factory(|root| {
                    Box::new(ExecuteHandler::with_root_and_sandbox(
                        root,
                        SandboxConfig::permissive(),
                    ))
                })
                // GitOperationHandler - git operations within workspace
                .with_rooted_handler_factory(|root| {
                    Box::new(GitOperationHandler::with_root(root))
                })
                // ListFilesHandler - lists files within workspace
                .with_rooted_handler_factory(|root| {
                    Box::new(ListFilesHandler::with_root(root))
                })
                // SearchHandler - searches files within workspace
                .with_rooted_handler_factory(|root| {
                    Box::new(SearchHandler::with_root(root))
                })
                // TCK-00385 BLOCKER 1: Wire session registry so stop()/quarantine()
                // call mark_terminated() in production.
                .with_session_registry(session_registry_for_runtime);

            let episode_runtime = Arc::new(episode_runtime);
            let clock =
                Arc::new(HolonicClock::new(ClockConfig::default(), None).expect("clock failed"));

            // TCK-00399: Create adapter registry so SpawnEpisode can spawn
            // adapter processes (fail-closed: registry is required).
            let mut adapter_registry = crate::episode::AdapterRegistry::new();
            adapter_registry.register(Box::new(crate::episode::raw_adapter::RawAdapter::new()));
            adapter_registry.register(Box::new(
                crate::episode::claude_code::ClaudeCodeAdapter::new(),
            ));
            adapter_registry.register(Box::new(crate::episode::codex_cli::CodexCliAdapter::new()));

            // TCK-00399: CAS for adapter profile resolution during spawn.
            let cas: Arc<dyn apm2_core::evidence::ContentAddressedStore> =
                Arc::new(apm2_core::evidence::MemoryCas::new());

            // TCK-00400: Store all builtin adapter profiles in CAS at startup.
            let profile_hashes = seed_builtin_profiles_in_cas(cas.as_ref())
                .map_err(|e| format!("builtin adapter profile CAS seeding failed: {e}"))?;
            // Fail-closed: invalid adapter rotation config must prevent
            // startup rather than silently falling back to defaults.
            let (adapter_selection_policy, available_profile_hashes) =
                build_adapter_selection_policy(
                    adapter_rotation,
                    &profile_hashes,
                    &adapter_registry,
                )?;
            let adapter_registry = Arc::new(adapter_registry);

            PrivilegedDispatcher::with_dependencies(
                DecodeConfig::default(),
                policy_resolver,
                work_registry,
                event_emitter,
                episode_runtime,
                session_registry,
                lease_validator,
                clock,
                token_minter.clone(),
                manifest_store.clone(),
                // TCK-00317: Pre-seed CAS with reviewer v0 manifest
                Arc::new(InMemoryCasManifestLoader::with_reviewer_v0_manifest()),
                Arc::clone(&subscription_registry),
            )
            // TCK-00352: Wire V1 manifest store into production path
            .with_v1_manifest_store(Arc::clone(&v1_manifest_store))
            // TCK-00399: Wire adapter registry for agent CLI process spawning.
            // CAS is intentionally NOT wired here via .with_cas(): fail-closed
            // publish/ingest handlers require explicit CAS configuration via
            // with_persistence_and_cas(). The MemoryCas above is used only to
            // seed builtin adapter profiles at startup; it must NOT be wired
            // as the dispatcher CAS or PublishChangeSet will incorrectly
            // succeed without durable storage (TCK-00412). Authority binding
            // validation (TCK-00416) creates a per-request fallback MemoryCas
            // when self.cas is None, so it works without wiring here.
            .with_adapter_registry(adapter_registry)
            .with_adapter_selection_policy(
                adapter_selection_policy,
                available_profile_hashes,
                profile_hashes,
                cas,
            )
        } else {
            // Use stubs
            let clock = Arc::new(
                HolonicClock::new(ClockConfig::default(), None)
                    .expect("failed to create default clock"),
            );
            PrivilegedDispatcher::with_shared_state(
                token_minter.clone(),
                manifest_store.clone(),
                session_registry,
                clock,
                Arc::clone(&subscription_registry),
            )
        }
        .with_credential_store(credential_store);

        let mut privileged_dispatcher =
            privileged_dispatcher.with_privileged_pcac_policy(PrivilegedPcacPolicy::default());

        privileged_dispatcher = if let Some(metrics) = metrics_registry {
            privileged_dispatcher.with_metrics(metrics)
        } else {
            privileged_dispatcher
        };

        // TCK-00384: Create shared telemetry store for session counters
        let telemetry_store = Arc::new(SessionTelemetryStore::new());

        // TCK-00351 v4: Create shared stop conditions store for per-session
        // stop limits (max_episodes, escalation_predicate).
        let stop_conditions_store = Arc::new(SessionStopConditionsStore::new());

        // TCK-00351 BLOCKER 1 & 2 FIX: Create production pre-actuation gate
        // with real StopAuthority and fail-closed budget enforcement.
        //
        // TCK-00351 MAJOR 2 FIX: Wire a deferred budget tracker sentinel.
        // The gate evaluates budget availability but records
        // `budget_checked=false` because enforcement is deferred to
        // EpisodeRuntime.
        let stop_authority = Arc::new(crate::episode::preactuation::StopAuthority::new());
        let deferred_budget = Arc::new(crate::episode::budget_tracker::BudgetTracker::deferred());
        let preactuation_gate = Arc::new(
            crate::episode::preactuation::PreActuationGate::production_gate(
                Arc::clone(&stop_authority),
                Some(deferred_budget),
            ),
        );
        let governance_freshness_monitor =
            Self::wire_governance_freshness_monitor(Arc::clone(&stop_authority));

        // TCK-00384: Wire telemetry store into privileged dispatcher for SpawnEpisode
        // registration
        // TCK-00351 v4: Wire stop conditions store into privileged dispatcher
        privileged_dispatcher = privileged_dispatcher
            .with_telemetry_store(Arc::clone(&telemetry_store))
            .with_stop_conditions_store(Arc::clone(&stop_conditions_store))
            .with_stop_authority(Arc::clone(&stop_authority))
            .with_governance_freshness_monitor(Arc::clone(&governance_freshness_monitor));

        // TCK-00303: Share subscription registry for HEF resource governance
        // TCK-00344: Wire session registry for SessionStatus queries
        // TCK-00384: Wire telemetry store for counter updates and SessionStatus queries
        // TCK-00351: Wire pre-actuation gate, stop authority, and stop conditions store
        // TCK-00352: Wire V1 manifest store for scope enforcement
        // TCK-00426: Authoritative persistence mode requires durable consume
        // enforcement and lifecycle gate wiring.
        let mut session_dispatcher =
            SessionDispatcher::with_manifest_store((*token_minter).clone(), manifest_store)
                .with_channel_context_signer(channel_context_signer)
                .with_subscription_registry(subscription_registry)
                .with_session_registry(session_registry_for_session)
                .with_telemetry_store(telemetry_store)
                .with_preactuation_gate(preactuation_gate)
                .with_stop_authority(Arc::clone(&stop_authority))
                .with_stop_conditions_store(stop_conditions_store)
                .with_v1_manifest_store(v1_manifest_store);

        let sovereignty_trusted_signer_key = sovereignty_trusted_signer_key.unwrap_or([0u8; 32]);
        if let Some(conn) = sqlite_conn_for_pcac {
            match derive_pcac_consume_log_path(&conn) {
                Ok(consume_log_path) => {
                    let durable_index = crate::pcac::FileBackedConsumeIndex::open(
                        &consume_log_path,
                        Some(crate::pcac::DurableConsumeMetrics::global()),
                    )
                    .map_err(|e| {
                        format!(
                            "failed to open durable consume index at {}: {e}",
                            consume_log_path.display()
                        )
                    })?;
                    let tick_kernel = Arc::new(crate::pcac::InProcessKernel::new(1));
                    let durable_kernel = crate::pcac::DurableKernel::new_with_shared_kernel(
                        Arc::clone(&tick_kernel),
                        Box::new(durable_index),
                    );
                    let pcac_kernel: Arc<dyn apm2_core::pcac::AuthorityJoinKernel> =
                        Arc::new(durable_kernel);
                    let sovereignty_checker =
                        crate::pcac::SovereigntyChecker::new(sovereignty_trusted_signer_key);
                    let sovereignty_mode = bootstrap_sovereignty_enforcement_mode();
                    let sovereignty_state = bootstrap_sovereignty_state(sovereignty_mode);
                    let pcac_gate = Arc::new(
                        crate::pcac::LifecycleGate::with_tick_kernel_and_sovereignty(
                            pcac_kernel,
                            tick_kernel,
                            sovereignty_checker,
                            Arc::clone(&stop_authority),
                        ),
                    );
                    privileged_dispatcher =
                        privileged_dispatcher.with_pcac_lifecycle_gate(Arc::clone(&pcac_gate));
                    session_dispatcher = session_dispatcher.with_pcac_lifecycle_gate(pcac_gate);
                    if let Some(sovereignty_state) = sovereignty_state {
                        session_dispatcher =
                            session_dispatcher.with_sovereignty_state(sovereignty_state);
                    }
                },
                Err(error) if error.contains("in-memory main database has no durable path") => {
                    tracing::warn!(
                        reason = %error,
                        "Skipping PCAC durable consume wiring for in-memory sqlite (non-authoritative mode)"
                    );
                },
                Err(error) => return Err(error),
            }
        }

        Ok(Self {
            privileged_dispatcher,
            session_dispatcher,
            gate_orchestrator: None,
            merge_executor: None,
            // TCK-00351 MAJOR 2 FIX: Store shared stop authority for
            // runtime mutation by operator/governance control plane.
            stop_authority: Some(stop_authority),
            governance_freshness_monitor: Some(governance_freshness_monitor),
            // TCK-00418: No evidence CAS in non-durable path; gate
            // orchestrator will need a fallback MemoryCas if wired here.
            evidence_cas: None,
        })
    }

    /// Creates new dispatcher state with persistent ledger, CAS, and
    /// `ToolBroker` (TCK-00316).
    ///
    /// # TCK-00316: Session Dispatcher Viability
    ///
    /// This constructor properly wires ALL production dependencies:
    /// - `ledger`: For `EmitEvent` persistence
    /// - `cas`: For `PublishEvidence` artifact storage
    /// - `clock`: For HTF-compliant monotonic timestamps
    /// - `broker`: For `RequestTool` capability/policy validation and execution
    ///
    /// # Arguments
    ///
    /// * `session_registry` - Global session registry
    /// * `metrics_registry` - Optional metrics registry
    /// * `sqlite_conn` - `SQLite` connection for persistent ledger
    /// * `cas_path` - Path for durable CAS storage
    ///
    /// # Errors
    ///
    /// Returns an error if CAS initialization fails (e.g., relative path,
    /// symlink components, bad permissions). The caller should handle this
    /// gracefully (e.g., log the error and exit) rather than panicking.
    #[allow(clippy::needless_pass_by_value)] // Arc is intentionally moved for shared ownership
    pub fn with_persistence_and_cas(
        session_registry: Arc<dyn SessionRegistry>,
        metrics_registry: Option<SharedMetricsRegistry>,
        sqlite_conn: Arc<Mutex<Connection>>,
        cas_path: impl AsRef<Path>,
    ) -> Result<Self, crate::cas::DurableCasError> {
        Self::with_persistence_and_cas_and_rotation(
            session_registry,
            metrics_registry,
            sqlite_conn,
            cas_path,
            AdapterRotationConfig::default(),
        )
    }

    /// Creates new dispatcher state with persistent ledger, CAS, and
    /// adapter rotation config (TCK-00400).
    #[allow(clippy::needless_pass_by_value)] // Arc is intentionally moved for shared ownership
    pub fn with_persistence_and_cas_and_rotation(
        session_registry: Arc<dyn SessionRegistry>,
        metrics_registry: Option<SharedMetricsRegistry>,
        sqlite_conn: Arc<Mutex<Connection>>,
        cas_path: impl AsRef<Path>,
        adapter_rotation: AdapterRotationConfig,
    ) -> Result<Self, crate::cas::DurableCasError> {
        Self::with_persistence_and_cas_and_key(
            session_registry,
            metrics_registry,
            sqlite_conn,
            cas_path,
            None,
            adapter_rotation,
        )
    }

    /// Creates new dispatcher state with persistent ledger, CAS,
    /// `ToolBroker`, and an optional pre-existing ledger signing key
    /// (TCK-00387 Security Review v5 MAJOR 2).
    ///
    /// When `ledger_signing_key` is `Some`, that key is reused for the ledger
    /// event emitter instead of generating a new ephemeral one. This ensures
    /// ONE signing key per daemon lifecycle, shared between crash recovery and
    /// the dispatcher.
    ///
    /// # Errors
    ///
    /// Returns an error if CAS initialization fails.
    #[allow(clippy::needless_pass_by_value)] // Arc is intentionally moved for shared ownership
    pub fn with_persistence_and_cas_and_key(
        session_registry: Arc<dyn SessionRegistry>,
        metrics_registry: Option<SharedMetricsRegistry>,
        sqlite_conn: Arc<Mutex<Connection>>,
        cas_path: impl AsRef<Path>,
        ledger_signing_key: Option<ed25519_dalek::SigningKey>,
        adapter_rotation: AdapterRotationConfig,
    ) -> Result<Self, crate::cas::DurableCasError> {
        let token_secret = TokenMinter::generate_secret();
        let token_minter = Arc::new(TokenMinter::new(token_secret));
        let manifest_store = Arc::new(InMemoryManifestStore::new());

        // TCK-00303: Create shared subscription registry for HEF resource governance
        let subscription_registry: SharedSubscriptionRegistry =
            Arc::new(SubscriptionRegistry::with_defaults());

        // TCK-00344: Clone session_registry before it is moved into the
        // privileged dispatcher so we can also wire it into the session dispatcher.
        let session_registry_for_session = Arc::clone(&session_registry);
        // TCK-00385 BLOCKER 1: Clone session_registry for EpisodeRuntime so that
        // stop()/quarantine() can call mark_terminated() in production.
        let session_registry_for_runtime = Arc::clone(&session_registry);

        // TCK-00316: Create durable CAS
        // Keep the concrete type so we can upcast to both executor and evidence
        // CAS traits (TCK-00408: dispatcher needs evidence::ContentAddressedStore).
        let cas_config = DurableCasConfig::new(cas_path.as_ref().to_path_buf());
        let durable_cas = Arc::new(DurableCas::new(cas_config)?);
        // Coerce to executor::ContentAddressedStore (infallible, daemon-local)
        let cas: Arc<dyn ContentAddressedStore> =
            Arc::clone(&durable_cas) as Arc<dyn ContentAddressedStore>;
        // Coerce to apm2_core::evidence::ContentAddressedStore (fallible, core)
        // Used by PrivilegedDispatcher for AgentAdapterProfileV1::load_from_cas
        // and TCK-00408 fail-closed ingest/publish validation.
        let evidence_cas: Arc<dyn apm2_core::evidence::ContentAddressedStore> =
            Arc::clone(&durable_cas) as Arc<dyn apm2_core::evidence::ContentAddressedStore>;

        // TCK-00289: Create shared HolonicClock
        let clock =
            Arc::new(HolonicClock::new(ClockConfig::default(), None).expect("clock failed"));

        // Security Review v5 MAJOR 2: Reuse the daemon-lifecycle signing key
        // if provided, otherwise generate a new one. This ensures recovery
        // and dispatcher events are signed with the same key.
        let signing_key = ledger_signing_key.unwrap_or_else(|| {
            use rand::rngs::OsRng;
            ed25519_dalek::SigningKey::generate(&mut OsRng)
        });
        let channel_context_signer = Arc::new(apm2_core::crypto::Signer::new(signing_key.clone()));
        let sovereignty_trusted_signer_key = signing_key.verifying_key().to_bytes();

        let policy_resolver = Arc::new(GovernancePolicyResolver::new());
        let work_registry = Arc::new(SqliteWorkRegistry::new(Arc::clone(&sqlite_conn)));
        let event_emitter = Arc::new(SqliteLedgerEventEmitter::new(
            Arc::clone(&sqlite_conn),
            signing_key,
        ));
        let lease_validator = Arc::new(SqliteLeaseValidator::new(Arc::clone(&sqlite_conn)));

        // TCK-00316: Initialize EpisodeRuntime with CAS and handlers
        // Use safe production defaults:
        // - max_concurrent_episodes = 100 (thread exhaustion protection for sync
        //   dispatch)
        // - default_budget = EpisodeBudget::default() (resource exhaustion protection)
        let runtime_config = EpisodeRuntimeConfig::default().with_max_concurrent_episodes(100);
        let mut episode_runtime = EpisodeRuntime::new(runtime_config);
        episode_runtime = episode_runtime
            .with_cas(Arc::clone(&cas))
            .with_default_budget(crate::episode::EpisodeBudget::default());

        // Register workspace-rooted tool handler factories (TCK-00319)
        // Use rooted factories that accept workspace_root at episode start time.
        // This ensures handlers are isolated to the episode's workspace, not the
        // daemon's CWD.
        let cas_for_handlers = Arc::clone(&cas);
        episode_runtime = episode_runtime
            // ReadFileHandler - reads files within workspace
            .with_rooted_handler_factory(|root| {
                Box::new(ReadFileHandler::with_root(root))
            })
            // WriteFileHandler - writes files within workspace
            .with_rooted_handler_factory(|root| {
                Box::new(WriteFileHandler::with_root(root))
            })
            // ExecuteHandler - executes commands within workspace
            // TCK-00338: Env scrubbing + stall detection always active.
            // Shell allowlist permissive (ToolBroker enforces manifest allowlists).
            .with_rooted_handler_factory(|root| {
                Box::new(ExecuteHandler::with_root_and_sandbox(
                    root,
                    SandboxConfig::permissive(),
                ))
            })
            // GitOperationHandler - git operations within workspace
            .with_rooted_handler_factory(|root| {
                Box::new(GitOperationHandler::with_root(root))
            })
            // ArtifactFetchHandler - CAS operations (not workspace-rooted)
            // TCK-00336: Intentionally uses deprecated with_handler_factory because
            // ArtifactFetchHandler accesses CAS (content-addressed store), not the
            // filesystem workspace. CAS access is safe without workspace rooting.
            ;
        #[allow(deprecated)]
        let episode_runtime = episode_runtime.with_handler_factory(move || {
            Box::new(ArtifactFetchHandler::new(cas_for_handlers.clone()))
        })
            // ListFilesHandler - lists files within workspace
            .with_rooted_handler_factory(|root| {
                Box::new(ListFilesHandler::with_root(root))
            })
            // SearchHandler - searches files within workspace
            .with_rooted_handler_factory(|root| {
                Box::new(SearchHandler::with_root(root))
            })
            // TCK-00385 BLOCKER 1: Wire session registry so stop()/quarantine()
            // call mark_terminated() in production.
            .with_session_registry(session_registry_for_runtime);

        // TCK-00399: Create adapter registry with explicit adapter registrations.
        // MAJOR fix: Use explicit new() + register() instead of deprecated
        // with_defaults() to avoid ambient defaults (DoD requires
        // profile-explicit production path).
        let mut adapter_registry = crate::episode::AdapterRegistry::new();
        adapter_registry.register(Box::new(crate::episode::raw_adapter::RawAdapter::new()));
        adapter_registry.register(Box::new(
            crate::episode::claude_code::ClaudeCodeAdapter::new(),
        ));
        adapter_registry.register(Box::new(crate::episode::codex_cli::CodexCliAdapter::new()));
        // TCK-00400: Store all builtin adapter profiles in CAS at startup.
        let profile_hashes = seed_builtin_profiles_in_cas(evidence_cas.as_ref()).map_err(|e| {
            DurableCasError::InitializationFailed {
                message: format!("builtin adapter profile CAS seeding failed: {e}"),
            }
        })?;
        // Fail-closed: invalid adapter rotation config must prevent startup
        // rather than silently falling back to defaults (propagate error).
        let (adapter_selection_policy, available_profile_hashes) =
            build_adapter_selection_policy(&adapter_rotation, &profile_hashes, &adapter_registry)
                .map_err(|error| DurableCasError::InitializationFailed { message: error })?;
        let adapter_registry = Arc::new(adapter_registry);
        let episode_runtime = episode_runtime.with_adapter_registry(Arc::clone(&adapter_registry));

        let episode_runtime = Arc::new(episode_runtime);

        // TCK-00343: Create credential store for credential management
        let credential_store = Arc::new(CredentialStore::new(CREDENTIAL_STORE_SERVICE_NAME));
        let broker_github_store: Arc<dyn GitHubCredentialStore> = Arc::new(
            CredentialStoreGitHubAdapter::new(Arc::clone(&credential_store)),
        );
        let broker_ssh_store: Arc<dyn SshCredentialStore> = Arc::new(
            CredentialStoreSshAdapter::new(Arc::clone(&credential_store)),
        );
        let session_broker_registry: SharedSessionBrokerRegistry<StubManifestLoader> =
            Arc::new(SessionBrokerRegistry::new());

        // TCK-00352: Create shared V1 manifest store for scope enforcement
        let v1_manifest_store = Arc::new(V1ManifestStore::new());

        let mut privileged_dispatcher = PrivilegedDispatcher::with_dependencies(
            DecodeConfig::default(),
            policy_resolver,
            work_registry,
            Arc::clone(&event_emitter) as Arc<dyn crate::protocol::dispatch::LedgerEventEmitter>,
            Arc::clone(&episode_runtime),
            session_registry,
            lease_validator,
            Arc::clone(&clock),
            token_minter.clone(),
            manifest_store.clone(),
            // TCK-00317: Pre-seed CAS with reviewer v0 manifest
            Arc::new(InMemoryCasManifestLoader::with_reviewer_v0_manifest()),
            Arc::clone(&subscription_registry),
        )
        .with_credential_store(credential_store)
        .with_session_broker_registry(Arc::clone(&session_broker_registry))
        .with_broker_config(ToolBrokerConfig::default())
        .with_broker_cas(Arc::clone(&cas))
        .with_broker_github_store(Arc::clone(&broker_github_store))
        .with_broker_ssh_store(Arc::clone(&broker_ssh_store))
        // TCK-00408: Wire CAS into privileged dispatcher for fail-closed
        // ingest/publish validation. Uses the core evidence trait impl.
        .with_cas(Arc::clone(&evidence_cas))
        // TCK-00352: Wire V1 manifest store into production path
        .with_v1_manifest_store(Arc::clone(&v1_manifest_store))
        // TCK-00399: Wire adapter registry and CAS for agent CLI process spawning
        .with_adapter_registry(adapter_registry)
        .with_adapter_selection_policy(
            adapter_selection_policy,
            available_profile_hashes,
            profile_hashes,
            Arc::clone(&evidence_cas),
        )
        .with_privileged_pcac_policy(PrivilegedPcacPolicy::default());

        privileged_dispatcher = if let Some(ref metrics) = metrics_registry {
            privileged_dispatcher.with_metrics(Arc::clone(metrics))
        } else {
            privileged_dispatcher
        };

        // TCK-00384: Create shared telemetry store for session counters
        let telemetry_store = Arc::new(SessionTelemetryStore::new());

        // TCK-00351 v4: Create shared stop conditions store for per-session
        // stop limits (max_episodes, escalation_predicate).
        let stop_conditions_store = Arc::new(SessionStopConditionsStore::new());

        // TCK-00351 BLOCKER 1 & 2 FIX: Create production pre-actuation gate
        // with real StopAuthority and fail-closed budget enforcement.
        //
        // TCK-00351 MAJOR 2 FIX: Wire a deferred budget tracker sentinel.
        // The gate evaluates budget availability but records
        // `budget_checked=false` because enforcement is deferred to
        // EpisodeRuntime.
        let stop_authority = Arc::new(crate::episode::preactuation::StopAuthority::new());
        let deferred_budget = Arc::new(crate::episode::budget_tracker::BudgetTracker::deferred());
        let preactuation_gate = Arc::new(
            crate::episode::preactuation::PreActuationGate::production_gate(
                Arc::clone(&stop_authority),
                Some(deferred_budget),
            ),
        );
        let governance_freshness_monitor =
            Self::wire_governance_freshness_monitor(Arc::clone(&stop_authority));

        // TCK-00384: Wire telemetry store into privileged dispatcher for SpawnEpisode
        // registration
        // TCK-00351 v4: Wire stop conditions store into privileged dispatcher
        privileged_dispatcher = privileged_dispatcher
            .with_telemetry_store(Arc::clone(&telemetry_store))
            .with_stop_conditions_store(Arc::clone(&stop_conditions_store))
            .with_stop_authority(Arc::clone(&stop_authority))
            .with_governance_freshness_monitor(Arc::clone(&governance_freshness_monitor));

        // TCK-00316: Wire SessionDispatcher with all production dependencies
        // TCK-00344: Wire session registry for SessionStatus queries
        // TCK-00384: Wire telemetry store for counter updates and SessionStatus queries
        // TCK-00351: Wire pre-actuation gate, stop authority, stop conditions store
        // TCK-00352: Wire V1 manifest store for scope enforcement
        // TCK-00426 BLOCKER 1 FIX: Wire DurableKernel + FileBackedConsumeIndex
        // in production constructor. The consume log path is co-located inside
        // the CAS directory to ensure per-instance isolation.
        let consume_log_path = cas_path.as_ref().join("pcac_consume.log");
        let durable_index = crate::pcac::FileBackedConsumeIndex::open(
            &consume_log_path,
            Some(crate::pcac::DurableConsumeMetrics::global()),
        )
        .map_err(|e| crate::cas::DurableCasError::InitializationFailed {
            message: format!(
                "failed to open durable consume index at {}: {e}",
                consume_log_path.display()
            ),
        })?;
        let tick_kernel = Arc::new(crate::pcac::InProcessKernel::new(1));
        let durable_kernel = crate::pcac::DurableKernel::new_with_shared_kernel(
            Arc::clone(&tick_kernel),
            Box::new(durable_index),
        );
        let pcac_kernel: Arc<dyn apm2_core::pcac::AuthorityJoinKernel> = Arc::new(durable_kernel);
        let sovereignty_checker =
            crate::pcac::SovereigntyChecker::new(sovereignty_trusted_signer_key);
        let sovereignty_mode = bootstrap_sovereignty_enforcement_mode();
        let sovereignty_state = bootstrap_sovereignty_state(sovereignty_mode);
        let pcac_gate = Arc::new(
            crate::pcac::LifecycleGate::with_tick_kernel_and_sovereignty(
                pcac_kernel,
                tick_kernel,
                sovereignty_checker,
                Arc::clone(&stop_authority),
            ),
        );
        privileged_dispatcher =
            privileged_dispatcher.with_pcac_lifecycle_gate(Arc::clone(&pcac_gate));
        let mut session_dispatcher =
            SessionDispatcher::with_manifest_store((*token_minter).clone(), manifest_store)
                .with_channel_context_signer(channel_context_signer)
                .with_subscription_registry(subscription_registry)
                .with_session_registry(session_registry_for_session)
                .with_ledger(event_emitter)
                .with_cas(cas)
                .with_clock(clock)
                .with_session_brokers(session_broker_registry)
                .with_episode_runtime(episode_runtime)
                .with_telemetry_store(telemetry_store)
                .with_preactuation_gate(preactuation_gate)
                .with_stop_authority(Arc::clone(&stop_authority))
                .with_stop_conditions_store(stop_conditions_store)
                .with_v1_manifest_store(v1_manifest_store)
                .with_pcac_lifecycle_gate(pcac_gate);
        if let Some(sovereignty_state) = sovereignty_state {
            session_dispatcher = session_dispatcher.with_sovereignty_state(sovereignty_state);
        }

        Ok(Self {
            privileged_dispatcher,
            session_dispatcher,
            gate_orchestrator: None,
            merge_executor: None,
            // TCK-00351 MAJOR 2 FIX: Store shared stop authority for
            // runtime mutation by operator/governance control plane.
            stop_authority: Some(stop_authority),
            governance_freshness_monitor: Some(governance_freshness_monitor),
            // TCK-00418: Share the durable evidence CAS so the gate
            // orchestrator writes time-envelope artifacts into the same
            // store the dispatcher reads during `validate_lease_time_authority`.
            evidence_cas: Some(evidence_cas),
        })
    }

    /// Wires governance freshness monitoring to a shared stop authority.
    fn wire_governance_freshness_monitor(
        stop_authority: Arc<crate::episode::preactuation::StopAuthority>,
    ) -> Arc<GovernanceFreshnessMonitor> {
        // Phase-1 resolver is transitional-local until authenticated governance
        // transport is implemented (TCK-00364).
        let transitional_resolver = true;
        let config = GovernanceFreshnessConfig {
            poll_interval_ms: GOVERNANCE_FRESHNESS_POLL_INTERVAL_MS,
            freshness_threshold_ms: GOVERNANCE_FRESHNESS_THRESHOLD_MS,
        };
        let monitor = Arc::new(GovernanceFreshnessMonitor::new(
            stop_authority,
            config.clone(),
            transitional_resolver,
        ));

        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let monitor_for_task = Arc::clone(&monitor);
            let poll_interval_ms = config.poll_interval_ms.max(1);
            let transitional_resolver_for_task = transitional_resolver;
            std::mem::drop(handle.spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_millis(poll_interval_ms)).await;
                    // Active governance health probe:
                    // resolve policy through the governance resolver on each
                    // poll cycle, then evaluate freshness using the updated
                    // watermark.
                    Self::run_governance_health_probe(
                        &monitor_for_task,
                        transitional_resolver_for_task,
                    );
                    monitor_for_task.check_freshness();
                }
            }));
        }

        monitor
    }

    /// Executes a lightweight active governance health probe.
    ///
    /// This probe records monitor state using strict classification:
    /// - `record_success()` on successful governance transport responses
    /// - `record_failure()` only for governance transport/service failures
    /// - local resolver contract errors are ignored here (freshness falls back
    ///   to elapsed-time checks and existing watermark state)
    fn run_governance_health_probe(
        monitor: &GovernanceFreshnessMonitor,
        transitional_resolver: bool,
    ) {
        if transitional_resolver {
            static TRANSITIONAL_WARN_ONCE: std::sync::Once = std::sync::Once::new();
            TRANSITIONAL_WARN_ONCE.call_once(|| {
                tracing::warn!(
                    "Governance freshness probe running in transitional local resolver mode; \
                     resolver success is not authoritative freshness evidence (WVR-0101 path)."
                );
            });
            monitor.record_failure();
            return;
        }

        let resolver = GovernancePolicyResolver::new();
        let probe_result = resolver.resolve_for_claim(
            "governance-health-probe",
            WorkRole::Coordinator,
            "governance-freshness-monitor",
        );

        match probe_result {
            Ok(_) => monitor.record_success(),
            Err(PolicyResolutionError::GovernanceFailed { .. }) => {
                // This qualifies as a governance probe failure because the
                // resolver reported a governance-side service failure.
                monitor.record_failure();
            },
            Err(
                PolicyResolutionError::NotFound { .. }
                | PolicyResolutionError::InvalidCredential { .. },
            ) => {
                // Local resolver contract/input errors are not governance
                // transport failures and must not force a failure sample.
            },
        }
    }

    /// Sets the daemon state for process management (TCK-00342).
    ///
    /// When set, process management handlers (`ListProcesses`,
    /// `ProcessStatus`, `StartProcess`, `StopProcess`, `RestartProcess`,
    /// `ReloadProcess`) query the `Supervisor` within `DaemonState` for
    /// live process information instead of returning stub responses.
    #[must_use]
    pub fn with_daemon_state(mut self, state: SharedState) -> Self {
        self.privileged_dispatcher = self.privileged_dispatcher.with_daemon_state(state);
        self
    }

    /// Sets privileged PCAC rollout policy for authority-bearing handlers.
    #[must_use]
    pub fn with_privileged_pcac_policy(mut self, policy: PrivilegedPcacPolicy) -> Self {
        self.privileged_dispatcher = self
            .privileged_dispatcher
            .with_privileged_pcac_policy(policy);
        self
    }

    /// Clears privileged PCAC lifecycle gate wiring (TEST ONLY).
    #[cfg(test)]
    #[must_use]
    pub fn without_privileged_pcac_lifecycle_gate(mut self) -> Self {
        self.privileged_dispatcher = self.privileged_dispatcher.without_pcac_lifecycle_gate();
        self
    }

    /// Sets the gate orchestrator for autonomous gate lifecycle (TCK-00388).
    ///
    /// When set, [`notify_session_terminated`](Self::notify_session_terminated)
    /// delegates to [`GateOrchestrator::on_session_terminated`], returning
    /// ledger events for the caller to persist.
    #[must_use]
    pub fn with_gate_orchestrator(mut self, orchestrator: Arc<GateOrchestrator>) -> Self {
        // Wire orchestrator into session dispatcher so termination triggers
        // gate lifecycle directly from the session dispatch path (Security
        // BLOCKER 1 fix).
        self.session_dispatcher
            .set_gate_orchestrator(Arc::clone(&orchestrator));
        // Wire orchestrator into privileged dispatcher so DelegateSublease
        // can access the orchestrator for sublease issuance (Quality BLOCKER 4 fix).
        self.privileged_dispatcher = self
            .privileged_dispatcher
            .with_gate_orchestrator(Arc::clone(&orchestrator));
        self.gate_orchestrator = Some(orchestrator);
        self
    }

    /// Returns a reference to the gate orchestrator, if configured.
    #[must_use]
    pub const fn gate_orchestrator(&self) -> Option<&Arc<GateOrchestrator>> {
        self.gate_orchestrator.as_ref()
    }

    /// Returns the shared evidence CAS, if configured (TCK-00418).
    ///
    /// The gate orchestrator MUST use this CAS so that
    /// `time_envelope_ref` hashes it stores are resolvable by the
    /// dispatcher during `validate_lease_time_authority`.
    #[must_use]
    pub fn evidence_cas(&self) -> Option<Arc<dyn apm2_core::evidence::ContentAddressedStore>> {
        self.evidence_cas.clone()
    }

    /// Sets the merge executor for autonomous merge after gate approval
    /// (TCK-00390).
    ///
    /// When set, [`merge_executor`](Self::merge_executor) returns the executor
    /// that the caller can invoke to trigger the autonomous merge lifecycle
    /// when all gates pass.
    #[must_use]
    pub fn with_merge_executor(mut self, executor: Arc<MergeExecutor>) -> Self {
        self.merge_executor = Some(executor);
        self
    }

    /// Returns a reference to the merge executor, if configured.
    #[must_use]
    pub const fn merge_executor(&self) -> Option<&Arc<MergeExecutor>> {
        self.merge_executor.as_ref()
    }

    /// Notifies the gate orchestrator that a session has terminated.
    ///
    /// This is the production entry point that wires the
    /// `GateOrchestrator` into the daemon runtime (Quality BLOCKER 4 fix).
    /// The caller is responsible for persisting the returned events to the
    /// ledger.
    ///
    /// Returns `None` if no gate orchestrator is configured.
    ///
    /// # Errors
    ///
    /// Returns the orchestrator error if gate setup fails.
    pub async fn notify_session_terminated(
        &self,
        info: SessionTerminatedInfo,
    ) -> Option<Result<Vec<GateOrchestratorEvent>, crate::gate::GateOrchestratorError>> {
        let orch = self.gate_orchestrator.as_ref()?;
        let result = orch.on_session_terminated(info).await;
        Some(result.map(|(_gate_types, _signers, events)| events))
    }

    /// Returns a reference to the privileged dispatcher.
    #[must_use]
    pub const fn privileged_dispatcher(&self) -> &PrivilegedDispatcher {
        &self.privileged_dispatcher
    }

    /// Returns a reference to the session dispatcher.
    #[must_use]
    pub const fn session_dispatcher(&self) -> &SessionDispatcher<InMemoryManifestStore> {
        &self.session_dispatcher
    }

    /// Returns the shared subscription registry for connection lifecycle
    /// management.
    ///
    /// # TCK-00303: Connection Cleanup
    ///
    /// When a connection closes, the connection handler MUST call
    /// `unregister_connection(connection_id)` on this registry to free
    /// resources and prevent `DoS` via connection slot exhaustion.
    #[must_use]
    pub const fn subscription_registry(&self) -> &SharedSubscriptionRegistry {
        self.privileged_dispatcher.subscription_registry()
    }

    /// Returns the ledger event emitter from the privileged dispatcher
    /// (TCK-00348).
    ///
    /// Used by the connection handler to persist contract binding events
    /// after successful handshake.
    #[must_use]
    pub fn event_emitter(&self) -> &Arc<dyn crate::protocol::dispatch::LedgerEventEmitter> {
        self.privileged_dispatcher.event_emitter()
    }

    /// Returns the shared stop authority for runtime mutation (TCK-00351
    /// MAJOR 2 FIX).
    ///
    /// Operator/governance control-plane paths use this to flip stop flags
    /// at runtime.  Changes are immediately visible to the pre-actuation
    /// gate because the `Arc` is shared.
    ///
    /// Returns `None` for non-production dispatchers that were created
    /// without a pre-actuation gate.
    #[must_use]
    pub const fn stop_authority(
        &self,
    ) -> Option<&Arc<crate::episode::preactuation::StopAuthority>> {
        self.stop_authority.as_ref()
    }

    /// Mutates runtime stop flags on the shared
    /// [`StopAuthority`](crate::episode::preactuation::StopAuthority).
    ///
    /// Returns `true` when stop authority is wired and the update was applied,
    /// `false` when no shared stop authority exists on this dispatcher state.
    pub fn set_stop_flags(
        &self,
        emergency_stop_active: Option<bool>,
        governance_stop_active: Option<bool>,
    ) -> bool {
        let Some(authority) = self.stop_authority.as_ref() else {
            return false;
        };

        if let Some(active) = emergency_stop_active {
            authority.set_emergency_stop(active);
        }
        if let Some(active) = governance_stop_active {
            authority.set_governance_stop(active);
        }
        true
    }

    /// Returns the governance freshness monitor when wired in production
    /// constructors.
    #[must_use]
    pub const fn governance_freshness_monitor(&self) -> Option<&Arc<GovernanceFreshnessMonitor>> {
        self.governance_freshness_monitor.as_ref()
    }
}

/// Shared dispatcher state type alias.
pub type SharedDispatcherState = Arc<DispatcherState>;

/// Key for looking up process runners: (`ProcessId`, `instance_index`).
pub type RunnerKey = (ProcessId, u32);

/// Shared daemon state protected by `Arc<RwLock<...>>`.
pub type SharedState = Arc<DaemonStateHandle>;

/// Handle to daemon state with interior mutability.
pub struct DaemonStateHandle {
    /// The inner mutable state.
    inner: RwLock<DaemonState>,
    /// Shutdown flag (atomic for lock-free checking).
    shutdown: AtomicBool,
    /// Time when the daemon started.
    started_at: DateTime<Utc>,
    /// Schema registry (shared across the daemon lifetime).
    /// Used by future handlers for schema validation (TCK-00181).
    #[allow(dead_code)]
    schema_registry: InMemorySchemaRegistry,
    /// Session registry for RFC-0017 control-plane IPC (TCK-00266).
    /// This is either a persistent or in-memory registry based on
    /// configuration. Will be used when RFC-0017 protobuf IPC is fully
    /// wired up.
    #[allow(dead_code)]
    session_registry: Arc<dyn SessionRegistry>,
    /// Metrics registry for daemon health observability (TCK-00268).
    /// Used by handlers to record IPC request metrics per REQ-DCP-0012.
    #[allow(dead_code)] // Will be used when RFC-0017 protobuf IPC is fully wired up
    metrics_registry: Option<SharedMetricsRegistry>,
}

impl DaemonStateHandle {
    /// Create a new daemon state handle with an in-memory session registry.
    ///
    /// For production use with persistent sessions, use
    /// [`new_with_persistent_sessions`](Self::new_with_persistent_sessions)
    /// instead.
    #[must_use]
    #[allow(dead_code)] // Used in tests and for in-memory mode
    pub fn new(
        config: EcosystemConfig,
        supervisor: Supervisor,
        schema_registry: InMemorySchemaRegistry,
        metrics_registry: Option<SharedMetricsRegistry>,
    ) -> Self {
        Self {
            inner: RwLock::new(DaemonState {
                supervisor,
                runners: HashMap::new(),
                config,
            }),
            shutdown: AtomicBool::new(false),
            started_at: Utc::now(),
            schema_registry,
            session_registry: Arc::new(InMemorySessionRegistry::new()),
            metrics_registry,
        }
    }

    /// Create a new daemon state handle with a persistent session registry.
    ///
    /// # TCK-00266
    ///
    /// This constructor loads existing session state from the state file
    /// (if it exists) and persists new sessions to disk. Use this for
    /// production deployments where session state should survive daemon
    /// restarts.
    ///
    /// # Errors
    ///
    /// Returns an error if the state file exists but cannot be parsed.
    pub fn new_with_persistent_sessions(
        config: EcosystemConfig,
        supervisor: Supervisor,
        schema_registry: InMemorySchemaRegistry,
        state_file_path: impl AsRef<Path>,
        metrics_registry: Option<SharedMetricsRegistry>,
    ) -> Result<Self, PersistentRegistryError> {
        let session_registry =
            Arc::new(PersistentSessionRegistry::load_from_file(state_file_path)?);

        Ok(Self {
            inner: RwLock::new(DaemonState {
                supervisor,
                runners: HashMap::new(),
                config,
            }),
            shutdown: AtomicBool::new(false),
            started_at: Utc::now(),
            schema_registry,
            session_registry,
            metrics_registry,
        })
    }

    /// Get a reference to the schema registry.
    /// Will be used by future handlers for schema validation (TCK-00181).
    #[must_use]
    #[allow(dead_code)]
    pub const fn schema_registry(&self) -> &InMemorySchemaRegistry {
        &self.schema_registry
    }

    /// Get a reference to the session registry.
    ///
    /// # TCK-00266
    ///
    /// Returns the session registry for RFC-0017 control-plane IPC.
    /// This may be either a persistent or in-memory registry depending
    /// on how the daemon was configured.
    #[must_use]
    #[allow(dead_code)] // Will be used when RFC-0017 protobuf IPC is fully wired up
    pub fn session_registry(&self) -> &Arc<dyn SessionRegistry> {
        &self.session_registry
    }

    /// Get a reference to the metrics registry.
    ///
    /// # TCK-00268
    ///
    /// Returns the metrics registry for daemon health observability.
    /// Used by handlers to record IPC request metrics per REQ-DCP-0012.
    #[must_use]
    #[allow(dead_code)] // Will be used when RFC-0017 protobuf IPC is fully wired up
    pub const fn metrics_registry(&self) -> Option<&SharedMetricsRegistry> {
        self.metrics_registry.as_ref()
    }

    /// Get read access to the inner state.
    pub async fn read(&self) -> tokio::sync::RwLockReadGuard<'_, DaemonState> {
        self.inner.read().await
    }

    /// Try to get read access to the inner state without blocking (TCK-00342).
    ///
    /// Returns `None` if the write lock is currently held. This is used by
    /// synchronous dispatch handlers that cannot `.await`.
    #[must_use]
    pub fn try_read(&self) -> Option<tokio::sync::RwLockReadGuard<'_, DaemonState>> {
        self.inner.try_read().ok()
    }

    /// Try to get write access to the inner state without blocking (TCK-00342).
    ///
    /// Returns `None` if any lock (read or write) is currently held. This is
    /// used by synchronous dispatch handlers for process state mutations
    /// that cannot `.await`.
    #[must_use]
    pub fn try_write(&self) -> Option<tokio::sync::RwLockWriteGuard<'_, DaemonState>> {
        self.inner.try_write().ok()
    }

    /// Get write access to the inner state.
    pub async fn write(&self) -> tokio::sync::RwLockWriteGuard<'_, DaemonState> {
        self.inner.write().await
    }

    /// Check if shutdown has been requested.
    #[must_use]
    pub fn is_shutdown_requested(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    /// Request shutdown.
    pub fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    /// Get the daemon start time.
    #[must_use]
    #[allow(dead_code)] // Part of public API for future use
    pub const fn started_at(&self) -> DateTime<Utc> {
        self.started_at
    }

    /// Get daemon uptime in seconds.
    #[must_use]
    #[allow(dead_code)] // Will be used when RFC-0017 protobuf IPC is fully wired up
    #[allow(clippy::cast_sign_loss)] // max(0) ensures non-negative
    pub fn uptime_secs(&self) -> u64 {
        let now = Utc::now();
        (now - self.started_at).num_seconds().max(0) as u64
    }
}

/// Inner daemon state (mutable part).
pub struct DaemonState {
    /// The supervisor managing process specs and handles.
    pub supervisor: Supervisor,
    /// Active process runners keyed by (`spec_id`, instance).
    pub runners: HashMap<RunnerKey, ProcessRunner>,
    /// Current configuration.
    #[allow(dead_code)] // Part of public API for future use
    pub config: EcosystemConfig,
}

#[allow(dead_code)] // Methods are part of public API for future use
impl DaemonState {
    /// Get a reference to the supervisor.
    #[must_use]
    pub const fn supervisor(&self) -> &Supervisor {
        &self.supervisor
    }

    /// Get a mutable reference to the supervisor.
    pub const fn supervisor_mut(&mut self) -> &mut Supervisor {
        &mut self.supervisor
    }

    /// Get a runner by process name and instance.
    #[must_use]
    pub fn get_runner(&self, name: &str, instance: u32) -> Option<&ProcessRunner> {
        let spec = self.supervisor.get_spec(name)?;
        self.runners.get(&(spec.id, instance))
    }

    /// Get a mutable runner by process name and instance.
    pub fn get_runner_mut(&mut self, name: &str, instance: u32) -> Option<&mut ProcessRunner> {
        let spec = self.supervisor.get_spec(name)?;
        let key = (spec.id, instance);
        self.runners.get_mut(&key)
    }

    /// Insert a runner.
    pub fn insert_runner(&mut self, spec_id: ProcessId, instance: u32, runner: ProcessRunner) {
        self.runners.insert((spec_id, instance), runner);
    }

    /// Remove a runner.
    pub fn remove_runner(&mut self, spec_id: ProcessId, instance: u32) -> Option<ProcessRunner> {
        self.runners.remove(&(spec_id, instance))
    }

    /// Get all runners for a process name.
    pub fn get_runners(&self, name: &str) -> Vec<&ProcessRunner> {
        let Some(spec) = self.supervisor.get_spec(name) else {
            return Vec::new();
        };

        let spec_id = spec.id;
        let instances = spec.instances;

        (0..instances)
            .filter_map(|i| self.runners.get(&(spec_id, i)))
            .collect()
    }

    /// Iterate over all runners.
    pub fn runners(&self) -> impl Iterator<Item = (&RunnerKey, &ProcessRunner)> {
        self.runners.iter()
    }

    /// Iterate over all runners mutably.
    pub fn runners_mut(&mut self) -> impl Iterator<Item = (&RunnerKey, &mut ProcessRunner)> {
        self.runners.iter_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::episode::envelope::StopConditions;
    use crate::episode::preactuation::{
        DEFAULT_STOP_UNCERTAINTY_DEADLINE_MS, PreActuationDenial, PreActuationGate,
    };
    use crate::protocol::ConnectionContext;
    use crate::protocol::credentials::PeerCredentials;
    use crate::protocol::dispatch::{
        PrivilegedResponse, encode_claim_work_request, encode_spawn_episode_request,
        encode_update_stop_flags_request,
    };
    use crate::protocol::messages::{
        ClaimWorkRequest, RequestToolRequest, SpawnEpisodeRequest, UpdateStopFlagsRequest, WorkRole,
    };
    use crate::protocol::session_dispatch::{SessionResponse, encode_request_tool_request};

    #[test]
    fn production_wiring_transitional_governance_uncertain_allows_gate() {
        let session_registry: Arc<dyn SessionRegistry> = Arc::new(InMemorySessionRegistry::new());
        let state = DispatcherState::with_persistence(session_registry, None, None, None)
            .expect("test dispatcher state initialization must succeed");

        let monitor = state
            .governance_freshness_monitor()
            .expect("production constructor must wire governance freshness monitor");
        let authority = Arc::clone(
            state
                .stop_authority()
                .expect("production constructor must wire stop authority"),
        );

        assert!(
            monitor.transitional_resolver(),
            "production monitor should run in transitional resolver mode"
        );
        assert!(
            !monitor.has_last_success_for_test(),
            "transitional production monitor should start with no success watermark"
        );
        assert!(
            authority.governance_uncertain(),
            "transitional production monitor should remain uncertain"
        );

        // Transitional uncertainty uses the WVR-0101 carve-out and remains
        // gate-allowing while the waiver is active.
        let gate = PreActuationGate::production_gate(Arc::clone(&authority), None);
        let receipt = gate
            .check(
                &StopConditions::default(),
                0,
                false,
                false,
                DEFAULT_STOP_UNCERTAINTY_DEADLINE_MS,
                1_000,
            )
            .expect("transitional uncertainty should allow under active waiver");
        assert!(receipt.stop_checked);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn production_wiring_periodic_probe_keeps_governance_uncertainty_in_transitional_mode() {
        let session_registry: Arc<dyn SessionRegistry> = Arc::new(InMemorySessionRegistry::new());
        let state = DispatcherState::with_persistence(session_registry, None, None, None)
            .expect("test dispatcher state initialization must succeed");

        let monitor = Arc::clone(
            state
                .governance_freshness_monitor()
                .expect("production constructor must wire governance freshness monitor"),
        );
        let authority = Arc::clone(
            state
                .stop_authority()
                .expect("production constructor must wire stop authority"),
        );

        monitor.record_failure();
        assert!(
            authority.governance_uncertain(),
            "explicit governance failure should set uncertainty"
        );

        // Periodic transitional probes must not establish freshness evidence.
        let wait_for = std::time::Duration::from_millis(
            GOVERNANCE_FRESHNESS_POLL_INTERVAL_MS.saturating_mul(3),
        );
        tokio::time::sleep(wait_for).await;

        assert!(
            authority.governance_uncertain(),
            "periodic transitional probe must keep governance uncertainty"
        );
        assert!(
            !monitor.has_last_success_for_test(),
            "periodic transitional probe must not produce a success watermark"
        );
    }

    #[test]
    fn production_wiring_claim_work_success_does_not_clear_transitional_uncertainty() {
        let session_registry: Arc<dyn SessionRegistry> = Arc::new(InMemorySessionRegistry::new());
        let state = DispatcherState::with_persistence(session_registry, None, None, None)
            .expect("test dispatcher state initialization must succeed");

        let monitor = Arc::clone(
            state
                .governance_freshness_monitor()
                .expect("production constructor must wire governance freshness monitor"),
        );
        let authority = Arc::clone(
            state
                .stop_authority()
                .expect("production constructor must wire stop authority"),
        );

        // Force uncertain state, then prove ClaimWork success refreshes health.
        monitor.record_failure();
        assert!(
            authority.governance_uncertain(),
            "failure sample should set governance uncertainty"
        );

        let ctx = ConnectionContext::privileged_session_open(Some(PeerCredentials {
            uid: 1000,
            gid: 1000,
            pid: Some(12345),
        }));
        let claim_request = ClaimWorkRequest {
            actor_id: "monitor-refresh-actor".to_string(),
            role: WorkRole::Implementer.into(),
            credential_signature: vec![1, 2, 3],
            nonce: vec![4, 5, 6],
        };
        let claim_frame = encode_claim_work_request(&claim_request);
        let claim_response = state
            .privileged_dispatcher()
            .dispatch(&claim_frame, &ctx)
            .expect("ClaimWork dispatch should succeed");
        assert!(
            matches!(claim_response, PrivilegedResponse::ClaimWork(_)),
            "ClaimWork should complete successfully to refresh governance health"
        );

        assert!(
            authority.governance_uncertain(),
            "transitional ClaimWork success must not clear governance uncertainty"
        );
        assert!(
            !monitor.has_last_success_for_test(),
            "transitional ClaimWork success must not produce freshness evidence"
        );
    }

    #[test]
    fn non_transitional_governance_failure_denies_after_deadline() {
        let authority = Arc::new(crate::episode::preactuation::StopAuthority::new());
        let monitor = GovernanceFreshnessMonitor::new(
            Arc::clone(&authority),
            GovernanceFreshnessConfig {
                poll_interval_ms: 1,
                freshness_threshold_ms: 1,
            },
            false,
        );
        monitor.record_failure();

        let gate = PreActuationGate::production_gate(Arc::clone(&authority), None);
        let denial = gate
            .check(
                &StopConditions::default(),
                0,
                false,
                false,
                DEFAULT_STOP_UNCERTAINTY_DEADLINE_MS,
                1_000,
            )
            .expect_err("non-transitional governance failure should deny");
        assert!(matches!(denial, PreActuationDenial::StopUncertain));
    }

    #[test]
    fn spawn_default_max_episodes_allows_first_request_tool_gate() {
        let session_registry: Arc<dyn SessionRegistry> = Arc::new(InMemorySessionRegistry::new());
        let conn = Connection::open_in_memory().expect("sqlite in-memory should open");
        SqliteLedgerEventEmitter::init_schema(&conn).expect("ledger schema init should succeed");
        SqliteWorkRegistry::init_schema(&conn).expect("work schema init should succeed");
        let conn = Arc::new(Mutex::new(conn));
        let cas_root = tempfile::tempdir().expect("temp CAS root should be created");
        let cas_dir = cas_root.path().join("cas");
        std::fs::create_dir(&cas_dir).expect("CAS dir should be created");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mut perms = std::fs::metadata(&cas_dir)
                .expect("CAS dir metadata should exist")
                .permissions();
            perms.set_mode(0o700);
            std::fs::set_permissions(&cas_dir, perms).expect("CAS dir permissions should be set");
        }
        let state = DispatcherState::with_persistence_and_cas(
            session_registry,
            None,
            Arc::clone(&conn),
            &cas_dir,
        )
        .expect("state with persistence+cas should be created");

        let creds = PeerCredentials {
            uid: 1000,
            gid: 1000,
            pid: Some(12345),
        };
        let privileged_ctx = ConnectionContext::privileged_session_open(Some(creds.clone()));

        let claim_request = ClaimWorkRequest {
            actor_id: "state-test-actor".to_string(),
            role: WorkRole::Implementer.into(),
            credential_signature: vec![1, 2, 3],
            nonce: vec![4, 5, 6],
        };
        let claim_frame = encode_claim_work_request(&claim_request);
        let claim_response = state
            .privileged_dispatcher()
            .dispatch(&claim_frame, &privileged_ctx)
            .expect("ClaimWork dispatch should succeed");
        let (work_id, lease_id) = match claim_response {
            PrivilegedResponse::ClaimWork(resp) => (resp.work_id, resp.lease_id),
            other => panic!("expected ClaimWork response, got {other:?}"),
        };

        let workspace_root = std::env::current_dir()
            .expect("cwd should exist")
            .to_string_lossy()
            .into_owned();
        let spawn_request = SpawnEpisodeRequest {
            work_id,
            role: WorkRole::Implementer.into(),
            lease_id: Some(lease_id),
            workspace_root,
            adapter_profile_hash: None,
            max_episodes: None,
            escalation_predicate: None,
            permeability_receipt_hash: None,
        };
        let spawn_frame = encode_spawn_episode_request(&spawn_request);
        let spawn_response = state
            .privileged_dispatcher()
            .dispatch(&spawn_frame, &privileged_ctx)
            .expect("SpawnEpisode dispatch should succeed");
        let (session_id, session_token) = match spawn_response {
            PrivilegedResponse::SpawnEpisode(resp) => (resp.session_id, resp.session_token),
            other => panic!("expected SpawnEpisode response, got {other:?}"),
        };

        let session_ctx = ConnectionContext::session_open(Some(creds), Some(session_id));
        let request_tool = RequestToolRequest {
            session_token,
            tool_id: "network".to_string(),
            // Denied before broker dispatch by URL-userinfo guard in V1 scope
            // enforcement. This keeps the test sync-only while still proving
            // the pre-actuation gate admitted the first request.
            arguments: br#"{"url":"https://user:pass@example.com/resource"}"#.to_vec(),
            dedupe_key: "tck-00351-first-request".to_string(),
            epoch_seal: None,
        };
        let request_frame = encode_request_tool_request(&request_tool);
        let request_response = state
            .session_dispatcher()
            .dispatch(&request_frame, &session_ctx)
            .expect("RequestTool dispatch should succeed");

        match request_response {
            SessionResponse::Error(err) => {
                assert!(
                    err.message.contains("userinfo"),
                    "first RequestTool should pass pre-actuation gate; got: {}",
                    err.message
                );
                assert!(
                    !err.message.contains("max_episodes_reached"),
                    "default max_episodes must not deny first RequestTool: {}",
                    err.message
                );
            },
            other => panic!("expected SessionResponse::Error, got {other:?}"),
        }
    }

    #[test]
    fn production_constructor_binds_deferred_budget_receipt_fields() {
        let session_registry: Arc<dyn SessionRegistry> = Arc::new(InMemorySessionRegistry::new());
        let state = DispatcherState::with_persistence(session_registry, None, None, None)
            .expect("test dispatcher state initialization must succeed");
        let gate = state
            .session_dispatcher()
            .preactuation_gate_for_test()
            .expect("production constructor must wire pre-actuation gate");

        let receipt = gate
            .check(&StopConditions::default(), 0, false, false, 0, 1_000)
            .expect("production pre-actuation gate should produce receipt");

        assert!(receipt.stop_checked, "stop proof must be bound in receipt");
        assert!(
            !receipt.budget_checked,
            "production constructor wires deferred pre-actuation budget enforcement"
        );
        assert!(
            receipt.budget_enforcement_deferred,
            "deferred budget enforcement marker must be bound in receipt"
        );
    }

    #[test]
    fn update_stop_flags_emergency_stop_denies_subsequent_request_tool() {
        let session_registry: Arc<dyn SessionRegistry> = Arc::new(InMemorySessionRegistry::new());
        let conn = Connection::open_in_memory().expect("sqlite in-memory should open");
        SqliteLedgerEventEmitter::init_schema(&conn).expect("ledger schema init should succeed");
        SqliteWorkRegistry::init_schema(&conn).expect("work schema init should succeed");
        let conn = Arc::new(Mutex::new(conn));
        let cas_root = tempfile::tempdir().expect("temp CAS root should be created");
        let cas_dir = cas_root.path().join("cas");
        std::fs::create_dir(&cas_dir).expect("CAS dir should be created");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mut perms = std::fs::metadata(&cas_dir)
                .expect("CAS dir metadata should exist")
                .permissions();
            perms.set_mode(0o700);
            std::fs::set_permissions(&cas_dir, perms).expect("CAS dir permissions should be set");
        }

        let state = DispatcherState::with_persistence_and_cas(
            session_registry,
            None,
            Arc::clone(&conn),
            &cas_dir,
        )
        .expect("state with persistence+cas should be created");

        let creds = PeerCredentials {
            uid: 1000,
            gid: 1000,
            pid: Some(12345),
        };
        let privileged_ctx = ConnectionContext::privileged_session_open(Some(creds.clone()));

        let claim_request = ClaimWorkRequest {
            actor_id: "state-stop-flags-actor".to_string(),
            role: WorkRole::Implementer.into(),
            credential_signature: vec![1, 2, 3],
            nonce: vec![4, 5, 6],
        };
        let claim_frame = encode_claim_work_request(&claim_request);
        let claim_response = state
            .privileged_dispatcher()
            .dispatch(&claim_frame, &privileged_ctx)
            .expect("ClaimWork dispatch should succeed");
        let (work_id, lease_id) = match claim_response {
            PrivilegedResponse::ClaimWork(resp) => (resp.work_id, resp.lease_id),
            other => panic!("expected ClaimWork response, got {other:?}"),
        };

        let workspace_root = std::env::current_dir()
            .expect("cwd should exist")
            .to_string_lossy()
            .into_owned();
        let spawn_request = SpawnEpisodeRequest {
            work_id,
            role: WorkRole::Implementer.into(),
            lease_id: Some(lease_id),
            workspace_root,
            adapter_profile_hash: None,
            max_episodes: None,
            escalation_predicate: None,
            permeability_receipt_hash: None,
        };
        let spawn_frame = encode_spawn_episode_request(&spawn_request);
        let spawn_response = state
            .privileged_dispatcher()
            .dispatch(&spawn_frame, &privileged_ctx)
            .expect("SpawnEpisode dispatch should succeed");
        let (session_id, session_token) = match spawn_response {
            PrivilegedResponse::SpawnEpisode(resp) => (resp.session_id, resp.session_token),
            other => panic!("expected SpawnEpisode response, got {other:?}"),
        };

        let update_flags_request = UpdateStopFlagsRequest {
            emergency_stop_active: Some(true),
            governance_stop_active: None,
        };
        let update_frame = encode_update_stop_flags_request(&update_flags_request);
        let update_response = state
            .privileged_dispatcher()
            .dispatch(&update_frame, &privileged_ctx)
            .expect("UpdateStopFlags dispatch should succeed");
        match update_response {
            PrivilegedResponse::UpdateStopFlags(resp) => {
                assert!(
                    resp.emergency_stop_active,
                    "emergency stop should be active after update"
                );
            },
            other => panic!("expected UpdateStopFlags response, got {other:?}"),
        }

        let session_ctx = ConnectionContext::session_open(Some(creds), Some(session_id));
        let request_tool = RequestToolRequest {
            session_token,
            tool_id: "network".to_string(),
            arguments: br#"{"url":"https://example.com/resource"}"#.to_vec(),
            dedupe_key: "tck-00351-stop-active".to_string(),
            epoch_seal: None,
        };
        let request_frame = encode_request_tool_request(&request_tool);
        let request_response = state
            .session_dispatcher()
            .dispatch(&request_frame, &session_ctx)
            .expect("RequestTool dispatch should succeed");

        match request_response {
            SessionResponse::Error(err) => {
                assert!(
                    err.message.contains("emergency_stop"),
                    "expected emergency stop denial, got: {}",
                    err.message
                );
            },
            other => panic!("expected SessionResponse::Error, got {other:?}"),
        }
    }
}
