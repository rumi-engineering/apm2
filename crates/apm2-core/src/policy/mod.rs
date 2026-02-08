//! Policy DSL parser for APM2.
//!
//! This module provides the policy configuration infrastructure for the APM2
//! kernel. Policies define the rules that govern agent behavior through a
//! default-deny model.
//!
//! # Overview
//!
//! Policies are YAML documents that specify:
//! - **Tool access rules**: Which tools agents can use and on what resources
//! - **Budget limits**: Caps on tokens, time, or operation counts
//! - **Network access**: Allowed hosts and ports
//! - **Filesystem access**: Path patterns that can be accessed
//! - **Secrets access**: Which secrets can be accessed
//! - **Inference access**: Model and provider restrictions
//!
//! # Default-Deny Model
//!
//! All policies operate on a default-deny principle:
//! - Actions not explicitly allowed are denied
//! - Rules are evaluated in order; first matching rule determines outcome
//! - The `default_decision` should always be `deny`
//!
//! # Policy Schema
//!
//! ```yaml
//! policy:
//!   version: "1.0.0"
//!   name: "my-policy"
//!   description: "Optional description"
//!   rules:
//!     - id: "unique-rule-id"
//!       type: tool_allow | tool_deny | budget | network | filesystem | secrets | inference
//!       decision: allow | deny
//!       # Type-specific fields...
//!   default_decision: deny
//! ```
//!
//! # Example
//!
//! ```rust
//! use apm2_core::policy::{LoadedPolicy, create_policy_loaded_event};
//!
//! let yaml = r#"
//! policy:
//!   version: "1.0.0"
//!   name: "example"
//!   rules:
//!     - id: "allow-fs-read"
//!       type: tool_allow
//!       tool: "fs.read"
//!       paths:
//!         - "/workspace/**"
//!       decision: allow
//!   default_decision: deny
//! "#;
//!
//! let loaded = LoadedPolicy::from_yaml(yaml).unwrap();
//! println!(
//!     "Loaded policy '{}' with {} rules",
//!     loaded.name(),
//!     loaded.rule_count()
//! );
//! println!("Policy hash: {}", loaded.content_hash_hex());
//!
//! // Create a PolicyLoaded event for the ledger
//! let event = create_policy_loaded_event(&loaded);
//! ```
//!
//! # Security Properties
//!
//! - **Deterministic evaluation**: Same policy hash guarantees same decisions
//! - **Content-addressed**: Policies are identified by BLAKE3 hash
//! - **Validation**: All policies are validated before use
//! - **Fail-closed**: Invalid policies are rejected; default is deny

mod engine;
mod error;
mod event;
mod parser;
mod schema;
pub mod taint;
mod validator;

#[cfg(test)]
mod tests;

pub use engine::{
    BUDGET_EXCEEDED_RULE_ID, CONTEXT_MISS_RATIONALE, CONTEXT_MISS_RULE_ID, DEFAULT_DENY_RATIONALE,
    DEFAULT_DENY_RULE_ID, EvaluationResult, ManifestEvaluationResult, PolicyEngine,
};
pub use error::PolicyError;
pub use event::{create_policy_loaded_event, create_policy_loaded_event_from_parts};
pub use parser::{
    LoadedPolicy, compute_policy_hash, load_and_validate_policy_from_file, load_policy_from_file,
    parse_and_validate_policy, parse_policy,
};
pub use schema::{BudgetType, Decision, Policy, PolicyDocument, PolicyVersion, Rule, RuleType};
pub use taint::{
    BoundaryPolicy, ConfidentialityLevel, DataLabel, DeclassificationPolicy,
    DeclassificationReceipt, DualLatticePolicy, RfcConfidentialityLevel, SignatureVerifier,
    TaintError, TaintLevel, propagate_classification, propagate_taint,
};
pub use validator::{ValidatedPolicy, validate_policy};
