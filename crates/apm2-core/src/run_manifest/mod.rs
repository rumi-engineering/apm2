//! Run manifest generation and signing for pipeline execution records.
//!
//! This module provides the infrastructure for creating cryptographically
//! signed records of pipeline execution. Manifests capture input/output hashes,
//! routing decisions, stage timings, and are signed with Ed25519 to enable
//! verification and reproducibility auditing.
//!
//! # Overview
//!
//! A run manifest is a complete record of a single pipeline execution,
//! including:
//!
//! - **Input artifacts**: BLAKE3 hashes of all input files
//! - **Output artifacts**: BLAKE3 hashes of all generated files
//! - **Routing decisions**: Which provider handled each pipeline stage
//! - **Timing information**: Duration of each stage in milliseconds
//! - **CCP grounding**: Hash of the CCP index used for context
//!
//! # Signing
//!
//! Manifests are signed using Ed25519 signatures from the [`crate::crypto`]
//! module. The signing process:
//!
//! 1. Serializes the manifest to canonical JSON (sorted keys)
//! 2. Signs the JSON bytes with Ed25519
//! 3. Bundles the bytes, signature, and public key into a [`SignedManifest`]
//!
//! # Invariants
//!
//! - [INV-0001] Manifests are deterministically serialized (`BTreeMap`
//!   ordering)
//! - [INV-0002] UUID v7 manifest IDs enable temporal ordering
//! - [INV-0003] Signatures cover the canonical representation
//! - [INV-0004] All BLAKE3 hashes are hex-encoded
//!
//! # Contracts
//!
//! - [CTR-0001] `ManifestBuilder` requires `lease_id`, `routing_profile_id`,
//!   and `ccp_index_hash`
//! - [CTR-0002] `verify_manifest` fails if signature doesn't match bytes
//! - [CTR-0003] `verify_manifest_with_key` fails if public key doesn't match
//!
//! # Example
//!
//! ```rust,no_run
//! use apm2_core::crypto::Signer;
//! use apm2_core::run_manifest::{ManifestBuilder, sign_manifest, verify_manifest};
//!
//! // Build a manifest
//! let manifest = ManifestBuilder::new()
//!     .with_lease_id("lease-abc123")
//!     .with_routing_profile_id("production")
//!     .with_ccp_index_hash("deadbeef")
//!     .add_input("requirements.yaml", b"requirement content")
//!     .add_output("impact_map.yaml", b"generated output")
//!     .record_routing_decision("impact_map", "claude-opus-4")
//!     .record_stage_timing("impact_map", 1500)
//!     .build()
//!     .unwrap();
//!
//! // Sign the manifest
//! let signer = Signer::generate();
//! let signed = sign_manifest(&manifest, &signer);
//!
//! // Verify and extract the manifest
//! let verified = verify_manifest(&signed).unwrap();
//! assert_eq!(verified.lease_id, "lease-abc123");
//! ```

mod manifest;
mod signer;

pub use manifest::{ManifestBuilder, ManifestError, RunManifest};
pub use signer::{
    ManifestSignerError, SignedManifest, sign_manifest, verify_manifest, verify_manifest_with_key,
};
