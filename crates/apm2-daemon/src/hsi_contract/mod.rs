//! HSI Contract Manifest V1 for RFC-0020 (TCK-00347).
//!
//! This module implements the `HSIContractManifestV1` artifact as specified in
//! RFC-0020 section 3.1. The manifest is a canonical inventory of daemon and
//! CLI dispatch routes with semantics annotations, deterministic canonical
//! bytes, and a stable content hash.
//!
//! # Architecture
//!
//! ```text
//! HSIContractManifestV1
//!     |
//!     +-- schema: "apm2.hsi_contract.v1"
//!     +-- schema_version: "1.0.0"
//!     +-- cli_version: CliVersion
//!     +-- routes: Vec<HsiRouteEntry> (sorted by route)
//!     |       +-- id, route, stability
//!     |       +-- request_schema, response_schema
//!     |       +-- semantics: HsiRouteSemantics
//!     |               +-- authoritative, idempotency
//!     |               +-- receipt_required
//!     +-- canonical_bytes() -> Result<Vec<u8>, ManifestValidationError>
//!     +-- content_hash()   -> Result<String, ManifestValidationError>
//! ```
//!
//! # Determinism Requirement (REQ-0001)
//!
//! - Identical code + build inputs produce identical `cli_contract_hash`
//! - Any semantic change produces a different hash
//! - Missing route semantics annotations fail the build at runtime via
//!   `build_manifest()` returning `Err(ManifestBuildError::MissingSemantics)`
//!
//! # Contract References
//!
//! - RFC-0020 section 3.1: `HSIContractManifestV1`
//! - RFC-0020 section 3.1.1: Generation and determinism
//! - RFC-0020 section 1.5: `ContentHash`, canonical bytes
//! - RFC-0020 section 1.5.2: Domain separation
//! - `CTR-0001`: `HSIContractManifestV1` contract
//! - `REQ-0001`: `HSIContractManifest` deterministic generation

pub mod handshake_binding;
pub mod manifest;
pub mod registry;
pub mod semantics;

#[cfg(test)]
pub mod golden_vectors;

pub use handshake_binding::{
    CanonicalizerInfo, ContractBinding, ContractBindingError, MismatchOutcome, RiskTier,
    SessionContractBinding, evaluate_mismatch_policy, validate_contract_binding,
};
pub use manifest::{
    CliVersion, HsiContractManifestV1, HsiRouteEntry, HsiRouteSemantics, IdempotencyRequirement,
    ManifestValidationError, StabilityClass,
};
pub use registry::build_manifest;
