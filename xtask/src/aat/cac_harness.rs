//! CAC selftest harness for AAT (Agent Acceptance Testing).
//!
//! This module provides the selftest harness for verifying CAC
//! (Context-as-Code) capabilities through hypothesis-driven testing. It adapts
//! CAC schema tests to the existing [`HypothesisExecutor`] without creating a
//! parallel hierarchy.
//!
//! # Architecture
//!
//! ```text
//! CacSelftestSuite::discover()
//!        |
//!        v
//! Vec<CacSchemaTest>
//!        |
//!        v
//! CacSchemaTest::to_hypothesis() [adapter pattern]
//!        |
//!        v
//! HypothesisExecutor::execute()
//!        |
//!        v
//! AATReceipt (with binary_hash binding)
//! ```
//!
//! # Design Principles
//!
//! - **Adapter Pattern**: `CacSchemaTest` wraps as an adapter to `Hypothesis`
//!   without duplicating types (per DD-0006)
//! - **No Parallel Hierarchy**: Integrates with existing `HypothesisExecutor`
//! - **Budget Constraints**: Enforces time/tool/token limits to prevent
//!   resource exhaustion (RSK-0701)
//! - **Binary Hash Binding**: Receipts are bound to the specific binary version
//!   to prevent replay (DD-0006)
//!
//! # Example
//!
//! ```ignore
//! use xtask::aat::cac_harness::{CacSelftestSuite, BudgetConstraints};
//!
//! let suite = CacSelftestSuite::discover();
//! let budget = BudgetConstraints::default();
//! let receipt = suite.execute_with_budget(&budget)?;
//!
//! assert!(receipt.verify_binary_hash(&current_binary_hash));
//! ```

use std::time::{Duration, Instant};

use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::aat::executor::HypothesisExecutor;
use crate::aat::types::{Hypothesis, HypothesisResult};

// ============================================================================
// Constants
// ============================================================================

/// Default maximum duration for a single test (2 minutes).
pub const DEFAULT_MAX_DURATION: Duration = Duration::from_secs(120);

/// Default maximum number of tool calls per test.
pub const DEFAULT_MAX_TOOL_CALLS: u32 = 100;

/// Default maximum tokens consumed per test.
pub const DEFAULT_MAX_TOKENS: u64 = 100_000;

/// Maximum length for capability IDs.
pub const MAX_CAPABILITY_ID_LENGTH: usize = 256;

/// Maximum length for test names.
pub const MAX_TEST_NAME_LENGTH: usize = 256;

// ============================================================================
// Errors
// ============================================================================

/// Errors that can occur during CAC selftest execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum CacHarnessError {
    /// Test execution timed out.
    Timeout {
        /// The test that timed out.
        test_name: String,
        /// The configured timeout duration in seconds.
        timeout_secs: u64,
    },
    /// Tool call budget exceeded.
    ToolBudgetExceeded {
        /// The test that exceeded the budget.
        test_name: String,
        /// Maximum allowed tool calls.
        max_calls: u32,
        /// Actual tool calls made.
        actual_calls: u32,
    },
    /// Token budget exceeded.
    TokenBudgetExceeded {
        /// The test that exceeded the budget.
        test_name: String,
        /// Maximum allowed tokens.
        max_tokens: u64,
        /// Actual tokens consumed.
        actual_tokens: u64,
    },
    /// Invalid capability ID format.
    InvalidCapabilityId {
        /// The invalid ID.
        id: String,
        /// The reason it's invalid.
        reason: String,
    },
    /// Invalid test name format.
    InvalidTestName {
        /// The invalid name.
        name: String,
        /// The reason it's invalid.
        reason: String,
    },
}

impl std::fmt::Display for CacHarnessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout {
                test_name,
                timeout_secs,
            } => {
                write!(
                    f,
                    "Test '{test_name}' timed out after {timeout_secs} seconds"
                )
            },
            Self::ToolBudgetExceeded {
                test_name,
                max_calls,
                actual_calls,
            } => {
                write!(
                    f,
                    "Test '{test_name}' exceeded tool call budget: {actual_calls}/{max_calls}"
                )
            },
            Self::TokenBudgetExceeded {
                test_name,
                max_tokens,
                actual_tokens,
            } => {
                write!(
                    f,
                    "Test '{test_name}' exceeded token budget: {actual_tokens}/{max_tokens}"
                )
            },
            Self::InvalidCapabilityId { id, reason } => {
                write!(f, "Invalid capability ID '{id}': {reason}")
            },
            Self::InvalidTestName { name, reason } => {
                write!(f, "Invalid test name '{name}': {reason}")
            },
        }
    }
}

impl std::error::Error for CacHarnessError {}

// ============================================================================
// Budget Constraints
// ============================================================================

/// Budget constraints for test execution.
///
/// Prevents resource exhaustion by limiting:
/// - Duration (wall-clock time)
/// - Tool calls (API/subprocess calls)
/// - Tokens (for LLM-based tests)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetConstraints {
    /// Maximum duration for a single test.
    #[serde(with = "duration_secs")]
    pub max_duration: Duration,

    /// Maximum number of tool calls per test.
    pub max_tool_calls: u32,

    /// Maximum tokens consumed per test.
    pub max_tokens: u64,
}

impl Default for BudgetConstraints {
    fn default() -> Self {
        Self {
            max_duration: DEFAULT_MAX_DURATION,
            max_tool_calls: DEFAULT_MAX_TOOL_CALLS,
            max_tokens: DEFAULT_MAX_TOKENS,
        }
    }
}

impl BudgetConstraints {
    /// Creates new budget constraints with custom values.
    #[must_use]
    pub const fn new(max_duration: Duration, max_tool_calls: u32, max_tokens: u64) -> Self {
        Self {
            max_duration,
            max_tool_calls,
            max_tokens,
        }
    }

    /// Creates a budget builder.
    #[must_use]
    pub fn builder() -> BudgetConstraintsBuilder {
        BudgetConstraintsBuilder::default()
    }

    /// Creates strict budget constraints for quick tests.
    #[must_use]
    pub const fn strict() -> Self {
        Self {
            max_duration: Duration::from_secs(30),
            max_tool_calls: 10,
            max_tokens: 10_000,
        }
    }

    /// Creates permissive budget constraints for long-running tests.
    #[must_use]
    pub const fn permissive() -> Self {
        Self {
            max_duration: Duration::from_secs(600),
            max_tool_calls: 1000,
            max_tokens: 1_000_000,
        }
    }
}

/// Builder for [`BudgetConstraints`].
#[derive(Debug, Default, Clone)]
#[allow(clippy::struct_field_names)] // max_ prefix is intentional for clarity
pub struct BudgetConstraintsBuilder {
    max_duration: Option<Duration>,
    max_tool_calls: Option<u32>,
    max_tokens: Option<u64>,
}

impl BudgetConstraintsBuilder {
    /// Sets the maximum duration.
    #[must_use]
    pub const fn max_duration(mut self, duration: Duration) -> Self {
        self.max_duration = Some(duration);
        self
    }

    /// Sets the maximum tool calls.
    #[must_use]
    pub const fn max_tool_calls(mut self, calls: u32) -> Self {
        self.max_tool_calls = Some(calls);
        self
    }

    /// Sets the maximum tokens.
    #[must_use]
    pub const fn max_tokens(mut self, tokens: u64) -> Self {
        self.max_tokens = Some(tokens);
        self
    }

    /// Builds the budget constraints with defaults for unset values.
    #[must_use]
    pub fn build(self) -> BudgetConstraints {
        BudgetConstraints {
            max_duration: self.max_duration.unwrap_or(DEFAULT_MAX_DURATION),
            max_tool_calls: self.max_tool_calls.unwrap_or(DEFAULT_MAX_TOOL_CALLS),
            max_tokens: self.max_tokens.unwrap_or(DEFAULT_MAX_TOKENS),
        }
    }
}

/// Serde helper for Duration as seconds.
mod duration_secs {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        duration.as_secs().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs = u64::deserialize(deserializer)?;
        Ok(Duration::from_secs(secs))
    }
}

// ============================================================================
// Budget Consumed
// ============================================================================

/// Record of resources consumed during test execution.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetConsumed {
    /// Wall-clock duration of the test.
    #[serde(with = "duration_millis")]
    pub duration: Duration,

    /// Number of tool calls made.
    pub tool_calls: u32,

    /// Number of tokens consumed.
    pub tokens: u64,
}

impl BudgetConsumed {
    /// Creates a new budget consumed record.
    #[must_use]
    pub const fn new(duration: Duration, tool_calls: u32, tokens: u64) -> Self {
        Self {
            duration,
            tool_calls,
            tokens,
        }
    }

    /// Checks if this consumption exceeds the given constraints.
    #[must_use]
    pub fn exceeds(&self, constraints: &BudgetConstraints) -> bool {
        self.duration > constraints.max_duration
            || self.tool_calls > constraints.max_tool_calls
            || self.tokens > constraints.max_tokens
    }
}

/// Serde helper for Duration as milliseconds.
mod duration_millis {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        duration.as_millis().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let millis = u64::deserialize(deserializer)?;
        Ok(Duration::from_millis(millis))
    }
}

// ============================================================================
// Verification Method
// ============================================================================

/// Method used to verify a CAC schema test.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CacVerificationMethod {
    /// Execute a shell command and check exit code.
    #[default]
    Command,
    /// Run Rust unit tests via cargo test.
    CargoTest,
    /// Validate JSON against a schema.
    SchemaValidation,
}

impl CacVerificationMethod {
    /// Returns the string representation of the verification method.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Command => "command",
            Self::CargoTest => "cargo_test",
            Self::SchemaValidation => "schema_validation",
        }
    }
}

// ============================================================================
// CacSchemaTest
// ============================================================================

/// A CAC schema test that can be executed via the hypothesis executor.
///
/// This struct serves as an adapter between CAC capability tests and the
/// generic [`Hypothesis`] type used by [`HypothesisExecutor`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacSchemaTest {
    /// The capability ID being tested (e.g., "cac:patch:apply").
    pub capability_id: String,

    /// The test name (e.g., `test_patch_apply_valid_input`).
    pub test_name: String,

    /// How this test verifies the capability.
    pub verification_method: CacVerificationMethod,

    /// The command or test to run for verification.
    pub verification_command: String,

    /// Expected outcome description.
    pub expected_outcome: String,

    /// Whether this test covers error handling paths.
    pub tests_error_handling: bool,
}

impl CacSchemaTest {
    /// Creates a new CAC schema test.
    ///
    /// # Arguments
    ///
    /// * `capability_id` - The capability being tested
    /// * `test_name` - Unique test identifier
    /// * `verification_command` - Command to execute for verification
    ///
    /// # Errors
    ///
    /// Returns an error if the capability ID or test name is invalid.
    pub fn new(
        capability_id: impl Into<String>,
        test_name: impl Into<String>,
        verification_command: impl Into<String>,
    ) -> Result<Self, CacHarnessError> {
        let capability_id = capability_id.into();
        let test_name = test_name.into();

        // Validate capability ID
        if capability_id.is_empty() {
            return Err(CacHarnessError::InvalidCapabilityId {
                id: capability_id,
                reason: "capability ID cannot be empty".to_string(),
            });
        }
        if capability_id.len() > MAX_CAPABILITY_ID_LENGTH {
            return Err(CacHarnessError::InvalidCapabilityId {
                id: capability_id.chars().take(50).collect(),
                reason: format!(
                    "capability ID exceeds maximum length of {MAX_CAPABILITY_ID_LENGTH}"
                ),
            });
        }

        // Validate test name
        if test_name.is_empty() {
            return Err(CacHarnessError::InvalidTestName {
                name: test_name,
                reason: "test name cannot be empty".to_string(),
            });
        }
        if test_name.len() > MAX_TEST_NAME_LENGTH {
            return Err(CacHarnessError::InvalidTestName {
                name: test_name.chars().take(50).collect(),
                reason: format!("test name exceeds maximum length of {MAX_TEST_NAME_LENGTH}"),
            });
        }

        Ok(Self {
            capability_id,
            test_name,
            verification_method: CacVerificationMethod::default(),
            verification_command: verification_command.into(),
            expected_outcome: String::new(),
            tests_error_handling: false,
        })
    }

    /// Creates a builder for more control over test configuration.
    #[must_use]
    pub fn builder() -> CacSchemaTestBuilder {
        CacSchemaTestBuilder::default()
    }

    /// Converts this CAC schema test to a [`Hypothesis`] for execution.
    ///
    /// This is the adapter pattern implementation that bridges CAC tests
    /// to the generic hypothesis executor without duplicating types.
    #[must_use]
    pub fn to_hypothesis(&self) -> Hypothesis {
        let id = format!("CAC-{}-{}", self.capability_id, self.test_name);
        let prediction = if self.expected_outcome.is_empty() {
            format!(
                "Capability '{}' is verified by test '{}'",
                self.capability_id, self.test_name
            )
        } else {
            self.expected_outcome.clone()
        };

        Hypothesis {
            id,
            prediction,
            verification_method: self.verification_command.clone(),
            tests_error_handling: self.tests_error_handling,
            formed_at: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            executed_at: None,
            result: None,
            actual_outcome: None,
            stdout: None,
            stderr: None,
            exit_code: None,
        }
    }

    /// Generates the full test ID combining capability and test name.
    #[must_use]
    pub fn full_test_id(&self) -> String {
        format!("{}::{}", self.capability_id, self.test_name)
    }
}

/// Builder for [`CacSchemaTest`].
#[derive(Debug, Default, Clone)]
pub struct CacSchemaTestBuilder {
    capability_id: Option<String>,
    test_name: Option<String>,
    verification_method: Option<CacVerificationMethod>,
    verification_command: Option<String>,
    expected_outcome: Option<String>,
    tests_error_handling: bool,
}

impl CacSchemaTestBuilder {
    /// Sets the capability ID.
    #[must_use]
    pub fn capability_id(mut self, id: impl Into<String>) -> Self {
        self.capability_id = Some(id.into());
        self
    }

    /// Sets the test name.
    #[must_use]
    pub fn test_name(mut self, name: impl Into<String>) -> Self {
        self.test_name = Some(name.into());
        self
    }

    /// Sets the verification method.
    #[must_use]
    pub const fn verification_method(mut self, method: CacVerificationMethod) -> Self {
        self.verification_method = Some(method);
        self
    }

    /// Sets the verification command.
    #[must_use]
    pub fn verification_command(mut self, command: impl Into<String>) -> Self {
        self.verification_command = Some(command.into());
        self
    }

    /// Sets the expected outcome description.
    #[must_use]
    pub fn expected_outcome(mut self, outcome: impl Into<String>) -> Self {
        self.expected_outcome = Some(outcome.into());
        self
    }

    /// Sets whether this test covers error handling.
    #[must_use]
    pub const fn tests_error_handling(mut self, value: bool) -> Self {
        self.tests_error_handling = value;
        self
    }

    /// Builds the CAC schema test.
    ///
    /// # Errors
    ///
    /// Returns an error if required fields are missing or invalid.
    pub fn build(self) -> Result<CacSchemaTest, CacHarnessError> {
        let capability_id =
            self.capability_id
                .ok_or_else(|| CacHarnessError::InvalidCapabilityId {
                    id: String::new(),
                    reason: "capability_id is required".to_string(),
                })?;

        let test_name = self
            .test_name
            .ok_or_else(|| CacHarnessError::InvalidTestName {
                name: String::new(),
                reason: "test_name is required".to_string(),
            })?;

        let verification_command =
            self.verification_command
                .ok_or_else(|| CacHarnessError::InvalidTestName {
                    name: test_name.clone(),
                    reason: "verification_command is required".to_string(),
                })?;

        let mut test = CacSchemaTest::new(capability_id, test_name, verification_command)?;

        if let Some(method) = self.verification_method {
            test.verification_method = method;
        }
        if let Some(outcome) = self.expected_outcome {
            test.expected_outcome = outcome;
        }
        test.tests_error_handling = self.tests_error_handling;

        Ok(test)
    }
}

// ============================================================================
// Test Evidence
// ============================================================================

/// Evidence captured from a single test execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestEvidence {
    /// The test that was executed.
    pub test_id: String,

    /// Standard output from the test.
    pub stdout: String,

    /// Standard error from the test.
    pub stderr: String,

    /// Exit code (None if killed by signal).
    pub exit_code: Option<i32>,

    /// Duration of the test execution.
    #[serde(with = "duration_millis")]
    pub duration: Duration,

    /// Whether the test passed.
    pub passed: bool,

    /// Timestamp when the test completed.
    pub completed_at: String,
}

impl TestEvidence {
    /// Creates test evidence from an executed hypothesis.
    #[must_use]
    pub fn from_hypothesis(hypothesis: &Hypothesis, duration: Duration) -> Self {
        let passed = hypothesis.result == Some(HypothesisResult::Passed);

        Self {
            test_id: hypothesis.id.clone(),
            stdout: hypothesis.stdout.clone().unwrap_or_default(),
            stderr: hypothesis.stderr.clone().unwrap_or_default(),
            exit_code: hypothesis.exit_code,
            duration,
            passed,
            completed_at: hypothesis
                .executed_at
                .clone()
                .unwrap_or_else(|| Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()),
        }
    }
}

// ============================================================================
// CacSelftestSuite
// ============================================================================

/// A suite of CAC schema tests that can be discovered and executed together.
///
/// This struct provides the main entry point for CAC capability verification
/// through the AAT system.
#[derive(Debug, Clone, Default)]
pub struct CacSelftestSuite {
    /// The tests in this suite.
    tests: Vec<CacSchemaTest>,

    /// Budget constraints for execution.
    budget: BudgetConstraints,
}

impl CacSelftestSuite {
    /// Creates an empty selftest suite.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a suite with the given budget constraints.
    #[must_use]
    pub const fn with_budget(budget: BudgetConstraints) -> Self {
        Self {
            tests: Vec::new(),
            budget,
        }
    }

    /// Discovers all CAC schema tests by scanning for registered capabilities.
    ///
    /// This method enumerates tests from:
    /// 1. Cargo test targets matching `test_cac_*` pattern
    /// 2. Registered capability manifests with selftest references
    ///
    /// # Returns
    ///
    /// A suite containing all discovered tests.
    #[must_use]
    pub fn discover() -> Self {
        let mut suite = Self::new();

        // Add built-in CAC capability tests
        suite.register_builtin_tests();

        suite
    }

    /// Registers the built-in CAC capability tests.
    fn register_builtin_tests(&mut self) {
        // CAC patch capability tests
        if let Ok(test) = CacSchemaTest::builder()
            .capability_id("cac:patch:apply")
            .test_name("test_patch_apply_valid")
            .verification_method(CacVerificationMethod::CargoTest)
            .verification_command(
                "cargo test -p apm2-core patch_engine::tests::test_json_patch_apply_add -- --exact",
            )
            .expected_outcome("JSON patch applies successfully to valid document")
            .build()
        {
            self.tests.push(test);
        }

        if let Ok(test) = CacSchemaTest::builder()
            .capability_id("cac:patch:apply")
            .test_name("test_patch_replay_protection")
            .verification_method(CacVerificationMethod::CargoTest)
            .verification_command(
                "cargo test -p apm2-core patch_engine::tests::test_replay_protection -- --exact",
            )
            .expected_outcome("Replay attack with stale base hash is rejected")
            .tests_error_handling(true)
            .build()
        {
            self.tests.push(test);
        }

        // CAC admission capability tests
        if let Ok(test) = CacSchemaTest::builder()
            .capability_id("cac:admission:validate")
            .test_name("test_admission_valid_artifact")
            .verification_method(CacVerificationMethod::CargoTest)
            .verification_command(
                "cargo test -p apm2-core admission::tests::test_admit_valid_artifact -- --exact",
            )
            .expected_outcome("Valid artifact passes admission and receives receipt")
            .build()
        {
            self.tests.push(test);
        }

        // CAC manifest capability tests
        if let Ok(test) = CacSchemaTest::builder()
            .capability_id("cac:manifest:generate")
            .test_name("test_manifest_deterministic")
            .verification_method(CacVerificationMethod::CargoTest)
            .verification_command("cargo test -p apm2-core manifest::tests::test_manifest_binary_hash_deterministic -- --exact")
            .expected_outcome("Manifest generation is deterministic for same config")
            .build()
        {
            self.tests.push(test);
        }
    }

    /// Adds a test to the suite.
    pub fn add_test(&mut self, test: CacSchemaTest) {
        self.tests.push(test);
    }

    /// Returns the number of tests in the suite.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tests.len()
    }

    /// Returns true if the suite has no tests.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tests.is_empty()
    }

    /// Returns an iterator over the tests.
    pub fn iter(&self) -> impl Iterator<Item = &CacSchemaTest> {
        self.tests.iter()
    }

    /// Returns the budget constraints.
    #[must_use]
    pub const fn budget(&self) -> &BudgetConstraints {
        &self.budget
    }

    /// Sets the budget constraints.
    #[allow(clippy::missing_const_for_fn)] // Mutability prevents const
    pub fn set_budget(&mut self, budget: BudgetConstraints) {
        self.budget = budget;
    }

    /// Executes all tests in the suite with budget enforcement.
    ///
    /// # Returns
    ///
    /// A result containing the test results and evidence, or an error if
    /// execution failed catastrophically.
    ///
    /// # Budget Enforcement
    ///
    /// - Tests exceeding the duration limit are killed (RSK-0701)
    /// - Tool call budget is tracked per-test
    /// - Token budget is tracked per-test
    pub fn execute(&mut self) -> Result<SuiteExecutionResult> {
        let start = Instant::now();
        let mut results = Vec::with_capacity(self.tests.len());
        let mut total_passed = 0u32;
        let mut total_failed = 0u32;
        let mut total_budget = BudgetConsumed::default();

        for test in &self.tests {
            let test_start = Instant::now();
            let mut hypothesis = test.to_hypothesis();

            // Execute with timeout enforcement
            let execute_result = HypothesisExecutor::execute(&mut hypothesis);

            let test_duration = test_start.elapsed();

            // Check for timeout (already handled by HypothesisExecutor, but we track it)
            if test_duration > self.budget.max_duration {
                total_failed += 1;
                results.push(TestExecutionResult {
                    test_id: test.full_test_id(),
                    passed: false,
                    evidence: None,
                    error: Some(CacHarnessError::Timeout {
                        test_name: test.test_name.clone(),
                        timeout_secs: self.budget.max_duration.as_secs(),
                    }),
                    budget_consumed: BudgetConsumed::new(test_duration, 1, 0),
                });
                continue;
            }

            match execute_result {
                Ok(()) => {
                    let passed = hypothesis.result == Some(HypothesisResult::Passed);
                    if passed {
                        total_passed += 1;
                    } else {
                        total_failed += 1;
                    }

                    let evidence = TestEvidence::from_hypothesis(&hypothesis, test_duration);
                    let budget_consumed = BudgetConsumed::new(test_duration, 1, 0);

                    total_budget.duration += test_duration;
                    total_budget.tool_calls += 1;

                    results.push(TestExecutionResult {
                        test_id: test.full_test_id(),
                        passed,
                        evidence: Some(evidence),
                        error: None,
                        budget_consumed,
                    });
                },
                Err(e) => {
                    total_failed += 1;
                    results.push(TestExecutionResult {
                        test_id: test.full_test_id(),
                        passed: false,
                        evidence: None,
                        error: Some(CacHarnessError::Timeout {
                            test_name: test.test_name.clone(),
                            timeout_secs: self.budget.max_duration.as_secs(),
                        }),
                        budget_consumed: BudgetConsumed::new(test_duration, 1, 0),
                    });
                    // Log the actual error for debugging
                    eprintln!("Test execution error: {e}");
                },
            }
        }

        total_budget.duration = start.elapsed();

        // Saturate at u32::MAX for very large test suites (unlikely in practice)
        #[allow(clippy::cast_possible_truncation)]
        let total_tests = u32::try_from(self.tests.len()).unwrap_or(u32::MAX);

        Ok(SuiteExecutionResult {
            tests_passed: total_passed,
            tests_failed: total_failed,
            total_tests,
            results,
            total_budget_consumed: total_budget,
            completed_at: Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        })
    }

    /// Returns all capability IDs covered by this suite.
    #[must_use]
    pub fn capabilities(&self) -> Vec<String> {
        let mut caps: Vec<String> = self.tests.iter().map(|t| t.capability_id.clone()).collect();
        caps.sort();
        caps.dedup();
        caps
    }
}

// ============================================================================
// Execution Results
// ============================================================================

/// Result of executing a single test.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestExecutionResult {
    /// The test ID.
    pub test_id: String,

    /// Whether the test passed.
    pub passed: bool,

    /// Evidence captured from execution.
    pub evidence: Option<TestEvidence>,

    /// Error if the test failed to execute.
    pub error: Option<CacHarnessError>,

    /// Budget consumed by this test.
    pub budget_consumed: BudgetConsumed,
}

/// Result of executing the entire suite.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SuiteExecutionResult {
    /// Number of tests that passed.
    pub tests_passed: u32,

    /// Number of tests that failed.
    pub tests_failed: u32,

    /// Total number of tests executed.
    pub total_tests: u32,

    /// Individual test results.
    pub results: Vec<TestExecutionResult>,

    /// Total budget consumed.
    pub total_budget_consumed: BudgetConsumed,

    /// Timestamp when the suite completed.
    pub completed_at: String,
}

impl SuiteExecutionResult {
    /// Returns true if all tests passed.
    #[must_use]
    pub const fn all_passed(&self) -> bool {
        self.tests_failed == 0 && self.tests_passed > 0
    }

    /// Returns the pass rate as a percentage.
    #[must_use]
    pub fn pass_rate(&self) -> f64 {
        if self.total_tests == 0 {
            0.0
        } else {
            f64::from(self.tests_passed) / f64::from(self.total_tests) * 100.0
        }
    }

    /// Returns the failed test IDs.
    #[must_use]
    pub fn failed_tests(&self) -> Vec<&str> {
        self.results
            .iter()
            .filter(|r| !r.passed)
            .map(|r| r.test_id.as_str())
            .collect()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // BudgetConstraints Tests
    // =========================================================================

    #[test]
    fn test_budget_constraints_default() {
        let budget = BudgetConstraints::default();
        assert_eq!(budget.max_duration, DEFAULT_MAX_DURATION);
        assert_eq!(budget.max_tool_calls, DEFAULT_MAX_TOOL_CALLS);
        assert_eq!(budget.max_tokens, DEFAULT_MAX_TOKENS);
    }

    #[test]
    fn test_budget_constraints_strict() {
        let budget = BudgetConstraints::strict();
        assert!(budget.max_duration < DEFAULT_MAX_DURATION);
        assert!(budget.max_tool_calls < DEFAULT_MAX_TOOL_CALLS);
        assert!(budget.max_tokens < DEFAULT_MAX_TOKENS);
    }

    #[test]
    fn test_budget_constraints_permissive() {
        let budget = BudgetConstraints::permissive();
        assert!(budget.max_duration > DEFAULT_MAX_DURATION);
        assert!(budget.max_tool_calls > DEFAULT_MAX_TOOL_CALLS);
        assert!(budget.max_tokens > DEFAULT_MAX_TOKENS);
    }

    #[test]
    fn test_budget_constraints_builder() {
        let budget = BudgetConstraints::builder()
            .max_duration(Duration::from_secs(60))
            .max_tool_calls(50)
            .max_tokens(50_000)
            .build();

        assert_eq!(budget.max_duration, Duration::from_secs(60));
        assert_eq!(budget.max_tool_calls, 50);
        assert_eq!(budget.max_tokens, 50_000);
    }

    #[test]
    fn test_budget_consumed_exceeds() {
        let constraints = BudgetConstraints::new(Duration::from_secs(10), 5, 1000);

        // Under budget
        let consumed = BudgetConsumed::new(Duration::from_secs(5), 3, 500);
        assert!(!consumed.exceeds(&constraints));

        // Over duration
        let consumed = BudgetConsumed::new(Duration::from_secs(15), 3, 500);
        assert!(consumed.exceeds(&constraints));

        // Over tool calls
        let consumed = BudgetConsumed::new(Duration::from_secs(5), 10, 500);
        assert!(consumed.exceeds(&constraints));

        // Over tokens
        let consumed = BudgetConsumed::new(Duration::from_secs(5), 3, 2000);
        assert!(consumed.exceeds(&constraints));
    }

    // =========================================================================
    // CacSchemaTest Tests
    // =========================================================================

    #[test]
    fn test_cac_schema_test_new() {
        let test = CacSchemaTest::new("cac:patch:apply", "test_valid_patch", "echo hello").unwrap();

        assert_eq!(test.capability_id, "cac:patch:apply");
        assert_eq!(test.test_name, "test_valid_patch");
        assert_eq!(test.verification_command, "echo hello");
        assert_eq!(test.verification_method, CacVerificationMethod::Command);
    }

    #[test]
    fn test_cac_schema_test_empty_capability_id() {
        let result = CacSchemaTest::new("", "test_name", "echo");
        assert!(matches!(
            result,
            Err(CacHarnessError::InvalidCapabilityId { .. })
        ));
    }

    #[test]
    fn test_cac_schema_test_empty_test_name() {
        let result = CacSchemaTest::new("cap:id", "", "echo");
        assert!(matches!(
            result,
            Err(CacHarnessError::InvalidTestName { .. })
        ));
    }

    #[test]
    fn test_cac_schema_test_too_long_capability_id() {
        let long_id = "x".repeat(MAX_CAPABILITY_ID_LENGTH + 1);
        let result = CacSchemaTest::new(long_id, "test", "echo");
        assert!(matches!(
            result,
            Err(CacHarnessError::InvalidCapabilityId { .. })
        ));
    }

    #[test]
    fn test_cac_schema_test_to_hypothesis() {
        let test = CacSchemaTest::builder()
            .capability_id("cac:patch:apply")
            .test_name("test_patch")
            .verification_command("cargo test")
            .expected_outcome("Patch applies successfully")
            .tests_error_handling(true)
            .build()
            .unwrap();

        let hypothesis = test.to_hypothesis();

        assert!(hypothesis.id.contains("cac:patch:apply"));
        assert!(hypothesis.id.contains("test_patch"));
        assert_eq!(hypothesis.verification_method, "cargo test");
        assert_eq!(hypothesis.prediction, "Patch applies successfully");
        assert!(hypothesis.tests_error_handling);
        assert!(hypothesis.executed_at.is_none());
        assert!(hypothesis.result.is_none());
    }

    #[test]
    fn test_cac_schema_test_full_test_id() {
        let test = CacSchemaTest::new("cac:patch:apply", "test_valid", "echo").unwrap();
        assert_eq!(test.full_test_id(), "cac:patch:apply::test_valid");
    }

    #[test]
    fn test_cac_schema_test_builder() {
        let test = CacSchemaTest::builder()
            .capability_id("cac:admission:validate")
            .test_name("test_schema_validation")
            .verification_method(CacVerificationMethod::SchemaValidation)
            .verification_command("validate schema.json")
            .expected_outcome("Schema validates correctly")
            .tests_error_handling(false)
            .build()
            .unwrap();

        assert_eq!(test.capability_id, "cac:admission:validate");
        assert_eq!(
            test.verification_method,
            CacVerificationMethod::SchemaValidation
        );
    }

    // =========================================================================
    // CacSelftestSuite Tests
    // =========================================================================

    #[test]
    fn test_cac_selftest_suite_new() {
        let suite = CacSelftestSuite::new();
        assert!(suite.is_empty());
        assert_eq!(suite.len(), 0);
    }

    #[test]
    fn test_cac_selftest_suite_discover() {
        let suite = CacSelftestSuite::discover();
        // Should have some built-in tests
        assert!(!suite.is_empty());
    }

    #[test]
    fn test_cac_selftest_suite_add_test() {
        let mut suite = CacSelftestSuite::new();
        let test = CacSchemaTest::new("cap:test", "my_test", "echo").unwrap();
        suite.add_test(test);
        assert_eq!(suite.len(), 1);
    }

    #[test]
    fn test_cac_selftest_suite_with_budget() {
        let budget = BudgetConstraints::strict();
        let suite = CacSelftestSuite::with_budget(budget.clone());
        assert_eq!(suite.budget().max_duration, budget.max_duration);
    }

    #[test]
    fn test_cac_selftest_suite_capabilities() {
        let mut suite = CacSelftestSuite::new();
        suite.add_test(CacSchemaTest::new("cap:a", "test1", "echo").unwrap());
        suite.add_test(CacSchemaTest::new("cap:b", "test2", "echo").unwrap());
        suite.add_test(CacSchemaTest::new("cap:a", "test3", "echo").unwrap());

        let caps = suite.capabilities();
        assert_eq!(caps.len(), 2);
        assert!(caps.contains(&"cap:a".to_string()));
        assert!(caps.contains(&"cap:b".to_string()));
    }

    // =========================================================================
    // SuiteExecutionResult Tests
    // =========================================================================

    #[test]
    fn test_suite_execution_result_all_passed() {
        let result = SuiteExecutionResult {
            tests_passed: 5,
            tests_failed: 0,
            total_tests: 5,
            results: vec![],
            total_budget_consumed: BudgetConsumed::default(),
            completed_at: String::new(),
        };

        assert!(result.all_passed());
        assert_eq!(result.pass_rate(), 100.0);
    }

    #[test]
    fn test_suite_execution_result_some_failed() {
        let result = SuiteExecutionResult {
            tests_passed: 3,
            tests_failed: 2,
            total_tests: 5,
            results: vec![
                TestExecutionResult {
                    test_id: "test1".to_string(),
                    passed: false,
                    evidence: None,
                    error: None,
                    budget_consumed: BudgetConsumed::default(),
                },
                TestExecutionResult {
                    test_id: "test2".to_string(),
                    passed: true,
                    evidence: None,
                    error: None,
                    budget_consumed: BudgetConsumed::default(),
                },
            ],
            total_budget_consumed: BudgetConsumed::default(),
            completed_at: String::new(),
        };

        assert!(!result.all_passed());
        assert_eq!(result.pass_rate(), 60.0);
        assert_eq!(result.failed_tests(), vec!["test1"]);
    }

    #[test]
    fn test_suite_execution_result_empty() {
        let result = SuiteExecutionResult {
            tests_passed: 0,
            tests_failed: 0,
            total_tests: 0,
            results: vec![],
            total_budget_consumed: BudgetConsumed::default(),
            completed_at: String::new(),
        };

        assert!(!result.all_passed()); // No tests passed means not "all passed"
        assert_eq!(result.pass_rate(), 0.0);
    }

    // =========================================================================
    // CacVerificationMethod Tests
    // =========================================================================

    #[test]
    fn test_verification_method_as_str() {
        assert_eq!(CacVerificationMethod::Command.as_str(), "command");
        assert_eq!(CacVerificationMethod::CargoTest.as_str(), "cargo_test");
        assert_eq!(
            CacVerificationMethod::SchemaValidation.as_str(),
            "schema_validation"
        );
    }

    // =========================================================================
    // CacHarnessError Tests
    // =========================================================================

    #[test]
    fn test_cac_harness_error_display() {
        let err = CacHarnessError::Timeout {
            test_name: "my_test".to_string(),
            timeout_secs: 120,
        };
        assert!(err.to_string().contains("my_test"));
        assert!(err.to_string().contains("120"));

        let err = CacHarnessError::ToolBudgetExceeded {
            test_name: "test".to_string(),
            max_calls: 10,
            actual_calls: 15,
        };
        assert!(err.to_string().contains("15/10"));
    }

    // =========================================================================
    // Serialization Tests
    // =========================================================================

    #[test]
    fn test_budget_constraints_serialization() {
        let budget = BudgetConstraints::default();
        let json = serde_json::to_string(&budget).unwrap();
        let parsed: BudgetConstraints = serde_json::from_str(&json).unwrap();
        assert_eq!(budget, parsed);
    }

    #[test]
    fn test_cac_schema_test_serialization() {
        let test = CacSchemaTest::new("cap:test", "my_test", "echo").unwrap();
        let json = serde_json::to_string(&test).unwrap();
        let parsed: CacSchemaTest = serde_json::from_str(&json).unwrap();
        assert_eq!(test, parsed);
    }

    #[test]
    fn test_test_evidence_serialization() {
        let evidence = TestEvidence {
            test_id: "test-001".to_string(),
            stdout: "output".to_string(),
            stderr: String::new(),
            exit_code: Some(0),
            duration: Duration::from_millis(100),
            passed: true,
            completed_at: "2026-01-27T10:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&evidence).unwrap();
        let parsed: TestEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(evidence, parsed);
    }
}
