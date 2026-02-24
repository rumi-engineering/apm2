//! Compile command for end-to-end idea-to-RFC pipeline orchestration.
//!
//! This module provides the `apm2 factory compile` command that orchestrates
//! the complete pipeline from PRD to RFC. It chains all stages in order:
//!
//! 1. **CCP Build**: Build the Code Context Protocol index
//! 2. **Impact Map**: Map PRD requirements to CCP components
//! 3. **RFC Frame**: Generate RFC skeleton with CCP grounding
//!
//! # Features
//!
//! - **Dry-run mode**: Preview intended writes without modifying the filesystem
//! - **NDJSON observability**: Emit structured events for pipeline monitoring
//! - **Routing profiles**: Configurable model routing for each stage
//! - **Run manifests**: Cryptographically signed execution records
//!
//! # Invariants
//!
//! - [INV-COMPILE-001] Stages execute in strict order; no stage skipping
//! - [INV-COMPILE-002] Each stage receives output from previous stage
//! - [INV-COMPILE-003] Errors halt pipeline immediately with context
//! - [INV-COMPILE-004] Dry-run produces no filesystem modifications
//!
//! # Contracts
//!
//! - [CTR-COMPILE-001] `compile` requires valid PRD ID format
//! - [CTR-COMPILE-002] RFC ID is auto-generated if not provided
//! - [CTR-COMPILE-003] Routing profile must exist if specified
//! - [CTR-COMPILE-004] Output directory defaults to `evidence/prd/<PRD-ID>`

// Allow truncation when casting duration milliseconds - durations won't exceed u64::MAX in practice
#![allow(clippy::cast_possible_truncation)]

use std::io::Write;
use std::path::PathBuf;
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use apm2_core::ccp::index::{CcpBuildOptions, CcpBuildResult, build_ccp_index};
use apm2_core::crypto::Signer;
use apm2_core::impact_map::{ImpactMapBuildOptions, ImpactMapBuildResult, build_impact_map};
use apm2_core::model_router::{RoutingProfile, load_profile_by_id};
use apm2_core::rfc_framer::{RfcFrameOptions, RfcFrameResult, frame_rfc};
use apm2_core::run_manifest::{ManifestBuilder, RunManifest, SignedManifest, sign_manifest};
use chrono::{DateTime, Utc};
use clap::Args;
use regex::Regex;
use serde::Serialize;
use tempfile::NamedTempFile;
use tracing::warn;
use uuid::Uuid;

/// Regex for validating PRD identifiers (e.g., "PRD-0001").
/// Requires PRD- prefix followed by 4+ digits to prevent path traversal.
static PRD_ID_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^PRD-\d{4,}$").expect("PRD regex is valid"));

/// Regex for validating RFC identifiers (e.g., "RFC-0001").
/// Requires RFC- prefix followed by 4+ digits to prevent path traversal.
static RFC_ID_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^RFC-\d{4,}$").expect("RFC regex is valid"));

/// Arguments for the `factory compile` command.
#[derive(Debug, Args)]
pub struct CompileArgs {
    /// PRD identifier (e.g., "PRD-0005"). Required.
    #[arg(long, required = true)]
    pub prd: String,

    /// RFC identifier (e.g., "RFC-0011"). Auto-generated if omitted.
    #[arg(long)]
    pub rfc: Option<String>,

    /// Routing profile name (default: "local").
    #[arg(long, default_value = "local")]
    pub profile: String,

    /// Dry run mode - report intended writes without modifying files.
    #[arg(long, default_value = "false")]
    pub dry_run: bool,

    /// Override default output directory.
    #[arg(long)]
    pub output_dir: Option<PathBuf>,

    /// Sign the run manifest with configured key.
    #[arg(long, default_value = "false")]
    pub sign: bool,

    /// Path to repository root. Defaults to current directory.
    #[arg(long)]
    pub repo_root: Option<PathBuf>,

    /// Force rebuild even if artifacts are up to date.
    #[arg(long, default_value = "false")]
    pub force: bool,

    /// Output format (text or json for NDJSON events).
    #[arg(long, default_value = "text", value_parser = ["text", "json"])]
    pub format: String,
}

/// Pipeline stages for orchestration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    /// CCP index build stage.
    CcpBuild,
    /// Impact map generation stage.
    ImpactMap,
    /// RFC framing stage.
    RfcFrame,
}

impl Stage {
    /// Returns the stage name as a string.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::CcpBuild => "ccp_build",
            Self::ImpactMap => "impact_map",
            Self::RfcFrame => "rfc_frame",
        }
    }
}

/// NDJSON event types for observability.
#[derive(Debug, Serialize)]
#[serde(tag = "event_type", rename_all = "snake_case")]
pub enum PipelineEvent {
    /// A stage has started.
    StageStart {
        /// ISO 8601 timestamp.
        timestamp: DateTime<Utc>,
        /// Stage name.
        stage: &'static str,
        /// PRD identifier.
        prd_id: String,
    },
    /// A stage has completed successfully.
    StageComplete {
        /// ISO 8601 timestamp.
        timestamp: DateTime<Utc>,
        /// Stage name.
        stage: &'static str,
        /// Duration in milliseconds.
        duration_ms: u64,
        /// Stage-specific output summary.
        summary: serde_json::Value,
    },
    /// A stage has failed.
    StageError {
        /// ISO 8601 timestamp.
        timestamp: DateTime<Utc>,
        /// Stage name.
        stage: &'static str,
        /// Duration in milliseconds until failure.
        duration_ms: u64,
        /// Error message.
        error: String,
    },
    /// The entire pipeline has completed.
    PipelineComplete {
        /// ISO 8601 timestamp.
        timestamp: DateTime<Utc>,
        /// Total duration in milliseconds.
        total_duration_ms: u64,
        /// Number of stages completed.
        stages_completed: usize,
        /// Whether this was a dry run.
        dry_run: bool,
        /// Run manifest ID (if generated).
        manifest_id: Option<String>,
    },
    /// Final pipeline summary with all results.
    PipelineSummary {
        /// Whether the pipeline succeeded.
        success: bool,
        /// PRD identifier.
        prd_id: String,
        /// RFC identifier.
        rfc_id: String,
        /// Run manifest ID.
        manifest_id: String,
        /// Total duration in milliseconds.
        total_duration_ms: u64,
        /// Whether this was a dry run.
        dry_run: bool,
        /// CCP index summary.
        ccp: serde_json::Value,
        /// Impact map summary.
        impact_map: serde_json::Value,
        /// RFC summary.
        rfc: serde_json::Value,
    },
}

impl PipelineEvent {
    /// Emits this event as NDJSON to stdout.
    pub fn emit(&self) {
        if let Ok(json) = serde_json::to_string(self) {
            println!("{json}");
        }
    }
}

/// Tracks intended writes for dry-run mode.
#[derive(Debug, Default)]
pub struct DryRunContext {
    /// List of files that would be written.
    pub intended_writes: Vec<IntendedWrite>,
}

/// An intended file write operation.
#[derive(Debug, Clone)]
pub struct IntendedWrite {
    /// Stage that would produce this write.
    pub stage: Stage,
    /// Path to the file that would be written.
    pub path: PathBuf,
    /// Description of what would be written.
    pub description: String,
}

impl DryRunContext {
    /// Creates a new dry-run context.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records an intended write.
    pub fn record_write(&mut self, stage: Stage, path: PathBuf, description: impl Into<String>) {
        self.intended_writes.push(IntendedWrite {
            stage,
            path,
            description: description.into(),
        });
    }

    /// Prints the summary of intended writes.
    pub fn print_summary(&self) {
        eprintln!("\nDry Run Summary - Intended Writes:");
        eprintln!("===================================");
        if self.intended_writes.is_empty() {
            eprintln!("  (no writes would be performed)");
        } else {
            for write in &self.intended_writes {
                eprintln!(
                    "  [{:?}] {} - {}",
                    write.stage,
                    write.path.display(),
                    write.description
                );
            }
        }
        eprintln!();
    }
}

/// Pipeline orchestration context.
pub struct CompilePipeline {
    /// Repository root path.
    repo_root: PathBuf,
    /// PRD identifier.
    prd_id: String,
    /// RFC identifier.
    rfc_id: String,
    /// Routing profile.
    profile: Option<RoutingProfile>,
    /// Whether dry-run mode is enabled.
    dry_run: bool,
    /// Whether to sign the manifest.
    sign: bool,
    /// Output format.
    format: String,
    /// Force rebuild.
    force: bool,
    /// Dry-run tracking context.
    dry_run_ctx: DryRunContext,
    /// Manifest builder.
    manifest_builder: ManifestBuilder,
    /// Pipeline start time.
    pipeline_start: Instant,
}

impl CompilePipeline {
    /// Creates a new pipeline context.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        repo_root: PathBuf,
        prd_id: String,
        rfc_id: String,
        profile: Option<RoutingProfile>,
        dry_run: bool,
        sign: bool,
        format: String,
        force: bool,
    ) -> Self {
        let profile_id = profile
            .as_ref()
            .map_or_else(|| "local".to_string(), |p| p.profile_id.clone());

        Self {
            repo_root,
            prd_id,
            rfc_id,
            profile,
            dry_run,
            sign,
            format,
            force,
            dry_run_ctx: DryRunContext::new(),
            manifest_builder: ManifestBuilder::new()
                .with_lease_id(Uuid::now_v7().to_string())
                .with_routing_profile_id(profile_id),
            pipeline_start: Instant::now(),
        }
    }

    /// Emits a stage start event.
    fn emit_stage_start(&self, stage: Stage) {
        if self.format == "json" {
            PipelineEvent::StageStart {
                timestamp: Utc::now(),
                stage: stage.name(),
                prd_id: self.prd_id.clone(),
            }
            .emit();
        } else {
            eprintln!("Starting stage: {}", stage.name());
        }
    }

    /// Emits a stage complete event.
    fn emit_stage_complete(&self, stage: Stage, duration: Duration, summary: serde_json::Value) {
        let duration_ms = duration.as_millis() as u64;
        if self.format == "json" {
            PipelineEvent::StageComplete {
                timestamp: Utc::now(),
                stage: stage.name(),
                duration_ms,
                summary,
            }
            .emit();
        } else {
            eprintln!("Completed stage: {} ({}ms)", stage.name(), duration_ms);
        }
    }

    /// Emits a stage error event.
    fn emit_stage_error<E: std::fmt::Display>(&self, stage: Stage, duration: Duration, error: &E) {
        let duration_ms = duration.as_millis() as u64;
        if self.format == "json" {
            PipelineEvent::StageError {
                timestamp: Utc::now(),
                stage: stage.name(),
                duration_ms,
                error: error.to_string(),
            }
            .emit();
        } else {
            eprintln!("Error in stage {}: {error}", stage.name());
        }
    }

    /// Runs the CCP build stage.
    fn run_ccp_build(&mut self) -> Result<CcpBuildResult> {
        let stage = Stage::CcpBuild;
        self.emit_stage_start(stage);
        let start = Instant::now();

        let options = CcpBuildOptions {
            force: self.force,
            dry_run: self.dry_run,
        };

        let result = build_ccp_index(&self.repo_root, &self.prd_id, &options);
        let duration = start.elapsed();

        match &result {
            Ok(r) => {
                // Record routing decision (local for CCP build)
                self.manifest_builder = std::mem::take(&mut self.manifest_builder)
                    .record_routing_decision(stage.name(), "local")
                    .record_stage_timing(stage.name(), duration.as_millis() as u64)
                    .with_ccp_index_hash(&r.index.index_hash);

                // Track dry-run writes
                if self.dry_run {
                    self.dry_run_ctx.record_write(
                        stage,
                        r.output_dir.join("ccp_index.json"),
                        "CCP index metadata",
                    );
                    self.dry_run_ctx.record_write(
                        stage,
                        r.output_dir.join("component_atlas.yaml"),
                        "Component atlas",
                    );
                    self.dry_run_ctx.record_write(
                        stage,
                        r.output_dir.join("crate_graph.yaml"),
                        "Crate dependency graph",
                    );
                }

                let summary = serde_json::json!({
                    "index_hash": r.index.index_hash,
                    "component_count": r.index.component_count,
                    "crate_count": r.index.crate_count,
                    "skipped": r.skipped,
                });
                self.emit_stage_complete(stage, duration, summary);
            },
            Err(e) => {
                self.emit_stage_error(stage, duration, e);
            },
        }

        result.context("CCP build stage failed")
    }

    /// Runs the impact map stage.
    fn run_impact_map(&mut self) -> Result<ImpactMapBuildResult> {
        let stage = Stage::ImpactMap;
        self.emit_stage_start(stage);
        let start = Instant::now();

        let options = ImpactMapBuildOptions {
            force: self.force,
            dry_run: self.dry_run,
        };

        let result = build_impact_map(&self.repo_root, &self.prd_id, &options);
        let duration = start.elapsed();

        match &result {
            Ok(r) => {
                // Determine provider from routing profile
                let provider = self
                    .profile
                    .as_ref()
                    .and_then(|p| p.get_stage_config(stage.name()))
                    .map_or("local", |c| c.provider.as_str());

                self.manifest_builder = std::mem::take(&mut self.manifest_builder)
                    .record_routing_decision(stage.name(), provider)
                    .record_stage_timing(stage.name(), duration.as_millis() as u64);

                // Track dry-run writes
                if self.dry_run {
                    self.dry_run_ctx.record_write(
                        stage,
                        r.output_dir.join("impact_map.yaml"),
                        "Impact map with requirement mappings",
                    );
                }

                let summary = serde_json::json!({
                    "content_hash": r.impact_map.content_hash,
                    "total_requirements": r.impact_map.summary.total_requirements,
                    "high_confidence_matches": r.impact_map.summary.high_confidence_matches,
                    "needs_review": r.impact_map.summary.needs_review,
                    "skipped": r.skipped,
                });
                self.emit_stage_complete(stage, duration, summary);
            },
            Err(e) => {
                self.emit_stage_error(stage, duration, e);
            },
        }

        result.context("Impact map stage failed")
    }

    /// Runs the RFC frame stage.
    fn run_rfc_frame(&mut self) -> Result<RfcFrameResult> {
        let stage = Stage::RfcFrame;
        self.emit_stage_start(stage);
        let start = Instant::now();

        let options = RfcFrameOptions {
            force: self.force,
            dry_run: self.dry_run,
            skip_validation: false,
        };

        let result = frame_rfc(&self.repo_root, &self.prd_id, &self.rfc_id, &options);
        let duration = start.elapsed();

        match &result {
            Ok(r) => {
                // Determine provider from routing profile
                let provider = self
                    .profile
                    .as_ref()
                    .and_then(|p| p.get_stage_config(stage.name()))
                    .map_or("local", |c| c.provider.as_str());

                self.manifest_builder = std::mem::take(&mut self.manifest_builder)
                    .record_routing_decision(stage.name(), provider)
                    .record_stage_timing(stage.name(), duration.as_millis() as u64);

                // Track dry-run writes
                if self.dry_run {
                    for section in &r.frame.sections {
                        self.dry_run_ctx.record_write(
                            stage,
                            r.output_dir.join(section.section_type.filename()),
                            format!("RFC section: {}", section.section_type.filename()),
                        );
                    }
                }

                let summary = serde_json::json!({
                    "rfc_id": r.frame.rfc_id,
                    "title": r.frame.title,
                    "sections_generated": r.frame.sections.len(),
                    "ccp_index_hash": r.ccp_grounding.ccp_index_hash,
                });
                self.emit_stage_complete(stage, duration, summary);
            },
            Err(e) => {
                self.emit_stage_error(stage, duration, e);
            },
        }

        result.context("RFC frame stage failed")
    }

    /// Generates and optionally signs the run manifest.
    fn generate_manifest(&mut self) -> Result<(RunManifest, Option<SignedManifest>)> {
        // Take ownership of the builder and replace with a fresh one
        let builder = std::mem::take(&mut self.manifest_builder);
        let manifest = builder.build().context("Failed to build run manifest")?;

        let signed = if self.sign {
            // TODO(key-management): Replace ephemeral key generation with configured key
            // store once key management infrastructure is implemented.
            // Currently uses an ephemeral key generated per-run which provides
            // integrity verification but NOT identity attestation - anyone can
            // generate a valid signature for any manifest. See: https://github.com/anthropics/apm2/issues/XXX (key management tracking issue)
            warn!(
                "Using ephemeral signing key: provides integrity verification only, not identity. \
                 Key management infrastructure is not yet implemented."
            );
            let signer = Signer::generate();
            Some(sign_manifest(&manifest, &signer))
        } else {
            None
        };

        Ok((manifest, signed))
    }

    /// Writes the run manifest to the evidence directory.
    ///
    /// Uses atomic writes via `NamedTempFile` + `persist()` to prevent partial
    /// writes from corrupting manifests on disk.
    fn write_manifest(
        &self,
        manifest: &RunManifest,
        signed: Option<&SignedManifest>,
    ) -> Result<PathBuf> {
        let manifest_dir = self
            .repo_root
            .join("evidence")
            .join("prd")
            .join(&self.prd_id)
            .join("manifests");

        if !self.dry_run {
            crate::commands::fac_permissions::ensure_dir_with_mode(&manifest_dir)
                .context("Failed to create manifest directory")?;

            // Write manifest atomically using temp file + persist
            let manifest_path = manifest_dir.join(format!("{}.json", manifest.manifest_id));
            let manifest_json =
                serde_json::to_string_pretty(manifest).context("Failed to serialize manifest")?;
            let mut temp_file = NamedTempFile::new_in(&manifest_dir)
                .context("Failed to create temp file for manifest")?;
            temp_file
                .write_all(manifest_json.as_bytes())
                .context("Failed to write manifest to temp file")?;
            temp_file
                .persist(&manifest_path)
                .context("Failed to atomically persist manifest file")?;

            if let Some(signed) = signed {
                // Write signed manifest atomically using temp file + persist
                let signed_path =
                    manifest_dir.join(format!("{}.signed.json", manifest.manifest_id));
                let signed_json = serde_json::to_string_pretty(signed)
                    .context("Failed to serialize signed manifest")?;
                let mut signed_temp_file = NamedTempFile::new_in(&manifest_dir)
                    .context("Failed to create temp file for signed manifest")?;
                signed_temp_file
                    .write_all(signed_json.as_bytes())
                    .context("Failed to write signed manifest to temp file")?;
                signed_temp_file
                    .persist(&signed_path)
                    .context("Failed to atomically persist signed manifest file")?;
            }
        }

        Ok(manifest_dir)
    }

    /// Runs the complete pipeline.
    pub fn run(&mut self) -> Result<CompileResult> {
        let mut stages_completed = 0;

        // Stage 1: CCP Build
        let ccp_result = self.run_ccp_build()?;
        stages_completed += 1;

        // Stage 2: Impact Map
        let impact_result = self.run_impact_map()?;
        stages_completed += 1;

        // Stage 3: RFC Frame
        let rfc_result = self.run_rfc_frame()?;
        stages_completed += 1;

        // Generate manifest
        let (manifest, signed) = self.generate_manifest()?;

        // Write manifest
        let manifest_dir = self.write_manifest(&manifest, signed.as_ref())?;

        // Emit pipeline complete event
        let total_duration = self.pipeline_start.elapsed();
        if self.format == "json" {
            PipelineEvent::PipelineComplete {
                timestamp: Utc::now(),
                total_duration_ms: total_duration.as_millis() as u64,
                stages_completed,
                dry_run: self.dry_run,
                manifest_id: Some(manifest.manifest_id.clone()),
            }
            .emit();
        }

        // Print dry-run summary
        if self.dry_run {
            self.dry_run_ctx.print_summary();
        }

        Ok(CompileResult {
            prd_id: self.prd_id.clone(),
            rfc_id: self.rfc_id.clone(),
            ccp_result,
            impact_result,
            rfc_result,
            manifest,
            signed_manifest: signed,
            manifest_dir,
            total_duration,
            dry_run: self.dry_run,
        })
    }
}

/// Result of a compile pipeline run.
pub struct CompileResult {
    /// PRD identifier.
    pub prd_id: String,
    /// RFC identifier.
    pub rfc_id: String,
    /// CCP build result.
    pub ccp_result: CcpBuildResult,
    /// Impact map result.
    pub impact_result: ImpactMapBuildResult,
    /// RFC frame result.
    pub rfc_result: RfcFrameResult,
    /// Run manifest.
    pub manifest: RunManifest,
    /// Signed manifest (if signing was requested).
    pub signed_manifest: Option<SignedManifest>,
    /// Directory where manifest was written.
    pub manifest_dir: PathBuf,
    /// Total pipeline duration.
    pub total_duration: Duration,
    /// Whether this was a dry run.
    pub dry_run: bool,
}

/// Generates an RFC ID based on the PRD ID.
fn generate_rfc_id(prd_id: &str) -> String {
    // Extract the numeric part from PRD-XXXX and use it for RFC-XXXX
    // If PRD-0005, generate RFC-0005 (or the next available)
    prd_id.strip_prefix("PRD-").map_or_else(
        || {
            // Fallback to UUID-based ID
            format!(
                "RFC-{}",
                Uuid::now_v7()
                    .to_string()
                    .split('-')
                    .next()
                    .unwrap_or("0000")
            )
        },
        |num_str| format!("RFC-{num_str}"),
    )
}

/// Runs the compile command.
pub fn run_compile(args: &CompileArgs) -> Result<()> {
    // Determine repo root
    let repo_root = match &args.repo_root {
        Some(path) => path.clone(),
        None => std::env::current_dir().context("Failed to get current directory")?,
    };

    // Validate repo root
    if !repo_root.exists() {
        bail!("Repository root does not exist: {}", repo_root.display());
    }
    if !repo_root.is_dir() {
        bail!(
            "Repository root is not a directory: {}",
            repo_root.display()
        );
    }

    // Validate PRD ID format with strict regex to prevent path traversal attacks.
    // Pattern: ^PRD-\d{4,}$ ensures only PRD- followed by 4+ digits, no path
    // components.
    if !PRD_ID_REGEX.is_match(&args.prd) {
        bail!(
            "Invalid PRD identifier format: '{}'. Expected format: PRD-XXXX (4+ digits, no special characters)",
            args.prd
        );
    }

    // Determine RFC ID
    let rfc_id = args
        .rfc
        .clone()
        .unwrap_or_else(|| generate_rfc_id(&args.prd));

    // Validate RFC ID format with strict regex to prevent path traversal attacks.
    // Pattern: ^RFC-\d{4,}$ ensures only RFC- followed by 4+ digits, no path
    // components.
    if !RFC_ID_REGEX.is_match(&rfc_id) {
        bail!(
            "Invalid RFC identifier format: '{rfc_id}'. Expected format: RFC-XXXX (4+ digits, no special characters)"
        );
    }

    // Load routing profile (if it exists)
    let profile = load_profile_by_id(&repo_root, &args.profile)
        .ok()
        .or_else(|| {
            // Profile doesn't exist, use default local routing
            if args.format == "text" {
                eprintln!(
                    "Note: Routing profile '{}' not found, using default local routing",
                    args.profile
                );
            }
            None
        });

    // Print header
    if args.format == "text" {
        if args.dry_run {
            eprintln!("Compile Pipeline (dry run)");
        } else {
            eprintln!("Compile Pipeline");
        }
        eprintln!("  PRD: {}", args.prd);
        eprintln!("  RFC: {rfc_id}");
        eprintln!("  Profile: {}", args.profile);
        eprintln!("  Repository: {}", repo_root.display());
        eprintln!("  Force: {}", args.force);
        eprintln!("  Sign: {}", args.sign);
        eprintln!();
    }

    // Create and run pipeline
    let mut pipeline = CompilePipeline::new(
        repo_root,
        args.prd.clone(),
        rfc_id,
        profile,
        args.dry_run,
        args.sign,
        args.format.clone(),
        args.force,
    );

    let result = pipeline.run()?;

    // Print summary
    if args.format == "text" {
        print_summary(&result)?;
    } else {
        // Output final summary as single-line NDJSON event for consistency
        PipelineEvent::PipelineSummary {
            success: true,
            prd_id: result.prd_id.clone(),
            rfc_id: result.rfc_id.clone(),
            manifest_id: result.manifest.manifest_id.clone(),
            total_duration_ms: result.total_duration.as_millis() as u64,
            dry_run: result.dry_run,
            ccp: serde_json::json!({
                "index_hash": result.ccp_result.index.index_hash,
                "component_count": result.ccp_result.index.component_count,
            }),
            impact_map: serde_json::json!({
                "content_hash": result.impact_result.impact_map.content_hash,
                "total_requirements": result.impact_result.impact_map.summary.total_requirements,
            }),
            rfc: serde_json::json!({
                "title": result.rfc_result.frame.title,
                "sections": result.rfc_result.frame.sections.len(),
            }),
        }
        .emit();
    }

    Ok(())
}

/// Prints a human-readable summary of the compile result.
fn print_summary(result: &CompileResult) -> Result<()> {
    let mut stderr = std::io::stderr();

    writeln!(stderr)?;
    if result.dry_run {
        writeln!(stderr, "Pipeline completed (dry run - no files written)")?;
    } else {
        writeln!(stderr, "Pipeline completed successfully")?;
    }
    writeln!(stderr)?;

    writeln!(stderr, "Summary:")?;
    writeln!(stderr, "  PRD: {}", result.prd_id)?;
    writeln!(stderr, "  RFC: {}", result.rfc_id)?;
    writeln!(
        stderr,
        "  Total Duration: {}ms",
        result.total_duration.as_millis()
    )?;
    writeln!(stderr)?;

    writeln!(stderr, "CCP Index:")?;
    writeln!(stderr, "  Hash: {}", result.ccp_result.index.index_hash)?;
    writeln!(
        stderr,
        "  Components: {}",
        result.ccp_result.index.component_count
    )?;
    writeln!(stderr, "  Crates: {}", result.ccp_result.index.crate_count)?;
    writeln!(stderr)?;

    writeln!(stderr, "Impact Map:")?;
    writeln!(
        stderr,
        "  Content Hash: {}",
        result.impact_result.impact_map.content_hash
    )?;
    writeln!(
        stderr,
        "  Requirements: {}",
        result.impact_result.impact_map.summary.total_requirements
    )?;
    writeln!(
        stderr,
        "  High Confidence: {}",
        result
            .impact_result
            .impact_map
            .summary
            .high_confidence_matches
    )?;
    writeln!(stderr)?;

    writeln!(stderr, "RFC:")?;
    writeln!(stderr, "  Title: {}", result.rfc_result.frame.title)?;
    writeln!(
        stderr,
        "  Sections: {}",
        result.rfc_result.frame.sections.len()
    )?;
    writeln!(stderr)?;

    writeln!(stderr, "Run Manifest:")?;
    writeln!(stderr, "  ID: {}", result.manifest.manifest_id)?;
    if result.signed_manifest.is_some() {
        writeln!(stderr, "  Signed: yes")?;
    }
    if !result.dry_run {
        writeln!(stderr, "  Location: {}", result.manifest_dir.display())?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn test_generate_rfc_id_from_prd() {
        assert_eq!(generate_rfc_id("PRD-0005"), "RFC-0005");
        assert_eq!(generate_rfc_id("PRD-0123"), "RFC-0123");
    }

    #[test]
    fn test_generate_rfc_id_fallback() {
        let rfc_id = generate_rfc_id("INVALID");
        assert!(rfc_id.starts_with("RFC-"));
    }

    #[test]
    fn test_prd_format_validation() {
        let temp_dir = TempDir::new().unwrap();

        let args = CompileArgs {
            prd: "INVALID".to_string(),
            rfc: None,
            profile: "local".to_string(),
            dry_run: true,
            output_dir: None,
            sign: false,
            repo_root: Some(temp_dir.path().to_path_buf()),
            force: false,
            format: "text".to_string(),
        };

        let result = run_compile(&args);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid PRD identifier")
        );
    }

    #[test]
    fn test_prd_path_traversal_rejected() {
        let temp_dir = TempDir::new().unwrap();

        // Attempt path traversal attack via PRD ID
        let args = CompileArgs {
            prd: "PRD-../../sensitive".to_string(),
            rfc: None,
            profile: "local".to_string(),
            dry_run: true,
            output_dir: None,
            sign: false,
            repo_root: Some(temp_dir.path().to_path_buf()),
            force: false,
            format: "text".to_string(),
        };

        let result = run_compile(&args);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Invalid PRD identifier"),
            "Expected path traversal to be rejected, got: {err_msg}"
        );
    }

    #[test]
    fn test_rfc_path_traversal_rejected() {
        let temp_dir = TempDir::new().unwrap();

        // Attempt path traversal attack via RFC ID
        let args = CompileArgs {
            prd: "PRD-0001".to_string(),
            rfc: Some("RFC-../../etc/passwd".to_string()),
            profile: "local".to_string(),
            dry_run: true,
            output_dir: None,
            sign: false,
            repo_root: Some(temp_dir.path().to_path_buf()),
            force: false,
            format: "text".to_string(),
        };

        let result = run_compile(&args);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Invalid RFC identifier"),
            "Expected path traversal to be rejected, got: {err_msg}"
        );
    }

    #[test]
    fn test_nonexistent_repo_root() {
        let args = CompileArgs {
            prd: "PRD-0001".to_string(),
            rfc: None,
            profile: "local".to_string(),
            dry_run: true,
            output_dir: None,
            sign: false,
            repo_root: Some(PathBuf::from("/nonexistent/path")),
            force: false,
            format: "text".to_string(),
        };

        let result = run_compile(&args);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("does not exist"));
    }

    #[test]
    fn test_repo_root_is_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("file.txt");
        std::fs::write(&file_path, "content").unwrap();

        let args = CompileArgs {
            prd: "PRD-0001".to_string(),
            rfc: None,
            profile: "local".to_string(),
            dry_run: true,
            output_dir: None,
            sign: false,
            repo_root: Some(file_path),
            force: false,
            format: "text".to_string(),
        };

        let result = run_compile(&args);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not a directory"));
    }

    #[test]
    fn test_dry_run_context() {
        let mut ctx = DryRunContext::new();
        assert!(ctx.intended_writes.is_empty());

        ctx.record_write(
            Stage::CcpBuild,
            PathBuf::from("/test/path.json"),
            "test description",
        );
        assert_eq!(ctx.intended_writes.len(), 1);
        assert_eq!(ctx.intended_writes[0].stage, Stage::CcpBuild);
    }

    #[test]
    fn test_stage_names() {
        assert_eq!(Stage::CcpBuild.name(), "ccp_build");
        assert_eq!(Stage::ImpactMap.name(), "impact_map");
        assert_eq!(Stage::RfcFrame.name(), "rfc_frame");
    }

    #[test]
    fn test_rfc_format_validation() {
        let temp_dir = TempDir::new().unwrap();

        let args = CompileArgs {
            prd: "PRD-0001".to_string(),
            rfc: Some("INVALID".to_string()),
            profile: "local".to_string(),
            dry_run: true,
            output_dir: None,
            sign: false,
            repo_root: Some(temp_dir.path().to_path_buf()),
            force: false,
            format: "text".to_string(),
        };

        let result = run_compile(&args);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Invalid RFC identifier"),
            "Expected RFC validation error, got: {err_msg}"
        );
    }

    #[test]
    fn test_prd_regex_validation() {
        // Valid formats
        assert!(PRD_ID_REGEX.is_match("PRD-0001"));
        assert!(PRD_ID_REGEX.is_match("PRD-12345"));
        assert!(PRD_ID_REGEX.is_match("PRD-00000"));

        // Invalid formats (path traversal attempts)
        assert!(!PRD_ID_REGEX.is_match("PRD-../../test"));
        assert!(!PRD_ID_REGEX.is_match("PRD-001")); // Too few digits
        assert!(!PRD_ID_REGEX.is_match("PRD-abc"));
        assert!(!PRD_ID_REGEX.is_match("PRD-0001/../../"));
        assert!(!PRD_ID_REGEX.is_match("../PRD-0001"));
        assert!(!PRD_ID_REGEX.is_match("PRD-0001\0"));
    }

    #[test]
    fn test_rfc_regex_validation() {
        // Valid formats
        assert!(RFC_ID_REGEX.is_match("RFC-0001"));
        assert!(RFC_ID_REGEX.is_match("RFC-12345"));
        assert!(RFC_ID_REGEX.is_match("RFC-00000"));

        // Invalid formats (path traversal attempts)
        assert!(!RFC_ID_REGEX.is_match("RFC-../../test"));
        assert!(!RFC_ID_REGEX.is_match("RFC-001")); // Too few digits
        assert!(!RFC_ID_REGEX.is_match("RFC-abc"));
        assert!(!RFC_ID_REGEX.is_match("RFC-0001/../../"));
        assert!(!RFC_ID_REGEX.is_match("../RFC-0001"));
        assert!(!RFC_ID_REGEX.is_match("RFC-0001\0"));
    }
}
