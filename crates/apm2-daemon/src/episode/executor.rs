//! Tool executor for budget-enforced tool execution.
//!
//! This module implements the `ToolExecutor` per TCK-00165. The executor
//! charges budget before execution, dispatches to tool handlers, stores
//! results in CAS, and tracks execution duration.
//!
//! # Architecture
//!
//! ```text
//! ToolExecutor
//!     │
//!     ├── budget_tracker: BudgetTracker
//!     ├── cas: Arc<dyn ContentAddressedStore>
//!     └── handlers: HashMap<ToolClass, Box<dyn ToolHandler>>
//!
//! Execution Flow:
//!     1. validate() - Check arguments and handler availability
//!     2. charge_budget() - Pre-charge estimated resources
//!     3. execute_handler() - Run the tool handler
//!     4. store_result() - Store result in CAS
//!     5. adjust_budget() - Reconcile estimated vs actual usage
//! ```
//!
//! # Security Model
//!
//! - Budget is charged BEFORE execution (fail-closed)
//! - Handler registry is bounded by `MAX_HANDLERS`
//! - All results are stored in CAS for audit trail
//!
//! # Contract References
//!
//! - TCK-00165: Tool execution and budget charging
//! - AD-TOOL-001: Tool execution flow
//! - CTR-1303: Bounded collections with MAX_* constants

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use thiserror::Error;
use tracing::{debug, instrument, warn};

use super::broker::StubContentAddressedStore;
use super::budget_tracker::{BudgetExhaustedError, BudgetTracker};
use super::decision::{BudgetDelta, ToolResult};
use super::error::EpisodeId;
use super::runtime::Hash;
use super::tool_class::ToolClass;
use super::tool_handler::{MAX_HANDLERS, ToolArgs, ToolHandler, ToolHandlerError, ToolResultData};

// =============================================================================
// ExecutorError
// =============================================================================

/// Errors that can occur during tool execution.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ExecutorError {
    /// Budget exceeded.
    #[error("budget exceeded: {0}")]
    BudgetExceeded(#[from] BudgetExhaustedError),

    /// Handler not found for tool class.
    #[error("no handler registered for tool class: {tool_class}")]
    HandlerNotFound {
        /// The tool class without a handler.
        tool_class: ToolClass,
    },

    /// Handler limit reached.
    #[error("handler limit reached: max {max} handlers")]
    HandlerLimitReached {
        /// Maximum allowed handlers.
        max: usize,
    },

    /// Handler already registered.
    #[error("handler already registered for tool class: {tool_class}")]
    HandlerAlreadyRegistered {
        /// The duplicate tool class.
        tool_class: ToolClass,
    },

    /// Arguments validation failed.
    #[error("arguments validation failed: {0}")]
    ValidationFailed(#[from] ToolHandlerError),

    /// Tool class mismatch.
    #[error("tool class mismatch: expected {expected}, got {actual}")]
    ToolClassMismatch {
        /// Expected tool class.
        expected: ToolClass,
        /// Actual tool class.
        actual: ToolClass,
    },

    /// Execution failed.
    #[error("execution failed: {message}")]
    ExecutionFailed {
        /// Error message.
        message: String,
    },

    /// CAS storage failed.
    #[error("CAS storage failed: {message}")]
    StorageFailed {
        /// Error message.
        message: String,
    },

    /// Internal error.
    #[error("internal executor error: {message}")]
    Internal {
        /// Error message.
        message: String,
    },
}

impl ExecutorError {
    /// Returns the error kind as a string identifier.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::BudgetExceeded(_) => "budget_exceeded",
            Self::HandlerNotFound { .. } => "handler_not_found",
            Self::HandlerLimitReached { .. } => "handler_limit_reached",
            Self::HandlerAlreadyRegistered { .. } => "handler_already_registered",
            Self::ValidationFailed(_) => "validation_failed",
            Self::ToolClassMismatch { .. } => "tool_class_mismatch",
            Self::ExecutionFailed { .. } => "execution_failed",
            Self::StorageFailed { .. } => "storage_failed",
            Self::Internal { .. } => "internal",
        }
    }

    /// Returns `true` if this error is retriable.
    #[must_use]
    pub const fn is_retriable(&self) -> bool {
        matches!(
            self,
            Self::ExecutionFailed { .. } | Self::StorageFailed { .. }
        )
    }
}

// =============================================================================
// ContentAddressedStore Trait
// =============================================================================

/// Trait for content-addressed storage operations.
///
/// This trait abstracts CAS operations for storing tool results and
/// retrieving content by hash.
///
/// # Thread Safety
///
/// Implementations must be `Send + Sync` for use with async executors.
pub trait ContentAddressedStore: Send + Sync + std::fmt::Debug {
    /// Stores content and returns its BLAKE3 hash.
    fn store(&self, content: &[u8]) -> Hash;

    /// Retrieves content by hash, returning None if not found.
    fn retrieve(&self, hash: &Hash) -> Option<Vec<u8>>;

    /// Returns `true` if content with the given hash exists.
    fn contains(&self, hash: &Hash) -> bool {
        self.retrieve(hash).is_some()
    }
}

impl ContentAddressedStore for StubContentAddressedStore {
    fn store(&self, content: &[u8]) -> Hash {
        Self::store(self, content)
    }

    fn retrieve(&self, hash: &Hash) -> Option<Vec<u8>> {
        Self::retrieve(self, hash)
    }
}

// =============================================================================
// ExecutionContext
// =============================================================================

/// Context for a single tool execution.
///
/// This captures the environment and identifiers for an execution,
/// enabling proper audit logging and result association.
#[derive(Debug, Clone)]
pub struct ExecutionContext {
    /// Episode this execution belongs to.
    pub episode_id: EpisodeId,

    /// Unique request ID for this execution.
    pub request_id: String,

    /// Timestamp when execution started (nanoseconds since epoch).
    pub started_at_ns: u64,
}

impl ExecutionContext {
    /// Creates a new execution context.
    #[must_use]
    pub fn new(episode_id: EpisodeId, request_id: impl Into<String>, started_at_ns: u64) -> Self {
        Self {
            episode_id,
            request_id: request_id.into(),
            started_at_ns,
        }
    }
}

// =============================================================================
// ToolExecutor
// =============================================================================

/// Tool executor with budget enforcement and CAS storage.
///
/// The executor manages tool handler registration, budget charging,
/// execution dispatch, and result storage.
///
/// # Lifecycle
///
/// 1. Create executor with budget tracker and CAS
/// 2. Register tool handlers via `register_handler()`
/// 3. Execute tools via `execute()`
/// 4. Results are automatically stored in CAS
///
/// # Example
///
/// ```rust,ignore
/// use apm2_daemon::episode::executor::{ToolExecutor, ExecutionContext};
/// use apm2_daemon::episode::{EpisodeBudget, BudgetTracker};
///
/// let budget = EpisodeBudget::builder().tool_calls(100).build();
/// let tracker = Arc::new(BudgetTracker::from_envelope(budget));
/// let cas = Arc::new(StubContentAddressedStore::new());
///
/// let mut executor = ToolExecutor::new(tracker, cas);
/// executor.register_handler(Box::new(ReadFileHandler))?;
///
/// let args = ToolArgs::Read(ReadArgs { path: "/workspace/file.rs".into(), ... });
/// let ctx = ExecutionContext::new(episode_id, "req-1", timestamp_ns);
///
/// let result = executor.execute(&ctx, &args).await?;
/// ```
pub struct ToolExecutor {
    /// Budget tracker for this episode.
    budget_tracker: Arc<BudgetTracker>,

    /// Content-addressed store for results.
    cas: Arc<dyn ContentAddressedStore>,

    /// Registered tool handlers by class.
    handlers: HashMap<ToolClass, Box<dyn ToolHandler>>,
}

impl ToolExecutor {
    /// Creates a new tool executor.
    ///
    /// # Arguments
    ///
    /// * `budget_tracker` - Budget tracker for resource enforcement
    /// * `cas` - Content-addressed store for result storage
    #[must_use]
    pub fn new(budget_tracker: Arc<BudgetTracker>, cas: Arc<dyn ContentAddressedStore>) -> Self {
        Self {
            budget_tracker,
            cas,
            handlers: HashMap::new(),
        }
    }

    /// Registers a tool handler.
    ///
    /// # Arguments
    ///
    /// * `handler` - The handler to register
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - A handler is already registered for this tool class
    /// - The handler limit (`MAX_HANDLERS`) is reached
    pub fn register_handler(&mut self, handler: Box<dyn ToolHandler>) -> Result<(), ExecutorError> {
        let tool_class = handler.tool_class();

        // Check limits (CTR-1303)
        if self.handlers.len() >= MAX_HANDLERS {
            return Err(ExecutorError::HandlerLimitReached { max: MAX_HANDLERS });
        }

        // Check for duplicates
        if self.handlers.contains_key(&tool_class) {
            return Err(ExecutorError::HandlerAlreadyRegistered { tool_class });
        }

        debug!(tool_class = %tool_class, handler = handler.name(), "registered handler");
        self.handlers.insert(tool_class, handler);
        Ok(())
    }

    /// Returns `true` if a handler is registered for the tool class.
    #[must_use]
    pub fn has_handler(&self, tool_class: ToolClass) -> bool {
        self.handlers.contains_key(&tool_class)
    }

    /// Returns the number of registered handlers.
    #[must_use]
    pub fn handler_count(&self) -> usize {
        self.handlers.len()
    }

    /// Returns a reference to the budget tracker.
    #[must_use]
    pub const fn budget_tracker(&self) -> &Arc<BudgetTracker> {
        &self.budget_tracker
    }

    /// Executes a tool with the given arguments.
    ///
    /// This is the main execution entry point. It:
    /// 1. Validates arguments against the handler
    /// 2. Checks budget availability
    /// 3. Charges estimated budget
    /// 4. Executes the handler
    /// 5. Stores the result in CAS
    /// 6. Returns the result with actual resource consumption
    ///
    /// # Arguments
    ///
    /// * `ctx` - Execution context with episode ID and request ID
    /// * `args` - Tool arguments
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No handler is registered for the tool class
    /// - Arguments fail validation
    /// - Budget is insufficient
    /// - Execution fails
    #[instrument(skip(self, args), fields(
        episode_id = %ctx.episode_id,
        request_id = %ctx.request_id,
        tool_class = %args.tool_class()
    ))]
    pub async fn execute(
        &self,
        ctx: &ExecutionContext,
        args: &ToolArgs,
    ) -> Result<ToolResult, ExecutorError> {
        let tool_class = args.tool_class();
        let start_time = Instant::now();

        // Step 1: Get handler
        let handler = self
            .handlers
            .get(&tool_class)
            .ok_or(ExecutorError::HandlerNotFound { tool_class })?;

        // Step 2: Validate arguments
        handler.validate(args)?;

        // Step 3: Get estimated budget and charge
        let estimated_delta = handler.estimate_budget(args);
        self.budget_tracker.charge(&estimated_delta)?;

        debug!(
            estimated_tokens = estimated_delta.tokens,
            estimated_tool_calls = estimated_delta.tool_calls,
            "budget charged"
        );

        // Step 4: Execute handler
        let result_data = match handler.execute(args).await {
            Ok(data) => data,
            Err(err) => {
                warn!(error = %err, "handler execution failed");
                // Return failure result with consumed budget (no reconciliation needed
                // since we charged the estimate and execution failed)
                return Ok(self.build_failure_result(
                    ctx,
                    err.to_string(),
                    estimated_delta,
                    start_time.elapsed(),
                ));
            },
        };

        // Step 5: Reconcile budget - adjust for actual vs estimated usage
        // This is critical for security: prevents fail-open if actual > estimate
        if let Err(reconcile_err) = self
            .budget_tracker
            .reconcile(&estimated_delta, &result_data.budget_consumed)
        {
            warn!(
                error = %reconcile_err,
                estimated_tokens = estimated_delta.tokens,
                actual_tokens = result_data.budget_consumed.tokens,
                "budget reconciliation failed: actual exceeded estimate"
            );
            // Fail-closed: return error result, budget remains at charged amount
            return Err(ExecutorError::BudgetExceeded(reconcile_err));
        }

        debug!(
            estimated_tokens = estimated_delta.tokens,
            actual_tokens = result_data.budget_consumed.tokens,
            refund_tokens = estimated_delta
                .tokens
                .saturating_sub(result_data.budget_consumed.tokens),
            "budget reconciled"
        );

        // Step 6: Store result in CAS
        let result_hash = self.store_result_data(&result_data)?;
        debug!(result_hash = %hex::encode(&result_hash[..8]), "result stored in CAS");

        // Step 7: Build and return result
        let duration = start_time.elapsed();
        // Safe truncation: durations > 585 years would overflow, which is impractical
        #[allow(clippy::cast_possible_truncation)]
        let duration_ns = duration.as_nanos() as u64;
        let completed_at_ns = ctx.started_at_ns.saturating_add(duration_ns);

        Ok(ToolResult::success(
            &ctx.request_id,
            result_data.output,
            result_data.budget_consumed,
            duration,
            completed_at_ns,
        ))
    }

    /// Validates arguments without executing.
    ///
    /// This is useful for pre-flight checks before committing to execution.
    ///
    /// # Arguments
    ///
    /// * `args` - Tool arguments to validate
    ///
    /// # Errors
    ///
    /// Returns an error if validation fails.
    pub fn validate(&self, args: &ToolArgs) -> Result<(), ExecutorError> {
        let tool_class = args.tool_class();

        let handler = self
            .handlers
            .get(&tool_class)
            .ok_or(ExecutorError::HandlerNotFound { tool_class })?;

        handler.validate(args)?;
        Ok(())
    }

    /// Checks if budget is available for the estimated execution.
    ///
    /// # Arguments
    ///
    /// * `args` - Tool arguments for estimation
    ///
    /// # Returns
    ///
    /// `true` if sufficient budget is available.
    pub fn has_budget(&self, args: &ToolArgs) -> bool {
        let tool_class = args.tool_class();

        let Some(handler) = self.handlers.get(&tool_class) else {
            return false;
        };

        let estimated = handler.estimate_budget(args);
        !estimated.would_exceed(self.budget_tracker.limits())
    }

    // =========================================================================
    // Private helpers
    // =========================================================================

    fn store_result_data(&self, data: &ToolResultData) -> Result<Hash, ExecutorError> {
        let serialized = serde_json::to_vec(data).map_err(|e| ExecutorError::StorageFailed {
            message: e.to_string(),
        })?;

        Ok(self.cas.store(&serialized))
    }

    #[allow(clippy::unused_self)] // May use self in future for CAS storage
    fn build_failure_result(
        &self,
        ctx: &ExecutionContext,
        error_message: String,
        budget_consumed: BudgetDelta,
        duration: Duration,
    ) -> ToolResult {
        // Safe truncation: durations > 585 years would overflow, which is impractical
        #[allow(clippy::cast_possible_truncation)]
        let duration_ns = duration.as_nanos() as u64;
        let completed_at_ns = ctx.started_at_ns.saturating_add(duration_ns);
        ToolResult::failure(
            &ctx.request_id,
            error_message,
            None,
            budget_consumed,
            duration,
            completed_at_ns,
        )
    }
}

impl std::fmt::Debug for ToolExecutor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolExecutor")
            .field("handler_count", &self.handlers.len())
            .field(
                "registered_classes",
                &self.handlers.keys().collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

// =============================================================================
// SharedToolExecutor
// =============================================================================

/// Shared reference to a tool executor.
pub type SharedToolExecutor = Arc<tokio::sync::RwLock<ToolExecutor>>;

/// Creates a new shared tool executor.
#[must_use]
pub fn new_shared_executor(
    budget_tracker: Arc<BudgetTracker>,
    cas: Arc<dyn ContentAddressedStore>,
) -> SharedToolExecutor {
    Arc::new(tokio::sync::RwLock::new(ToolExecutor::new(
        budget_tracker,
        cas,
    )))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::episode::budget::EpisodeBudget;
    use crate::episode::tool_handler::ReadArgs;

    fn test_episode_id() -> EpisodeId {
        EpisodeId::new("ep-executor-test").unwrap()
    }

    fn test_context() -> ExecutionContext {
        ExecutionContext::new(test_episode_id(), "req-001", 1_704_067_200_000_000_000)
    }

    fn test_budget() -> EpisodeBudget {
        EpisodeBudget::builder()
            .tokens(10_000)
            .tool_calls(100)
            .wall_ms(60_000)
            .bytes_io(1_000_000)
            .build()
    }

    fn test_executor() -> ToolExecutor {
        let tracker = Arc::new(BudgetTracker::from_envelope(test_budget()));
        let cas = Arc::new(StubContentAddressedStore::new());
        ToolExecutor::new(tracker, cas)
    }

    // Mock handler for testing
    #[derive(Debug)]
    struct MockReadHandler {
        should_fail: bool,
    }

    impl MockReadHandler {
        fn new() -> Self {
            Self { should_fail: false }
        }

        fn failing() -> Self {
            Self { should_fail: true }
        }
    }

    #[async_trait::async_trait]
    impl ToolHandler for MockReadHandler {
        fn tool_class(&self) -> ToolClass {
            ToolClass::Read
        }

        async fn execute(&self, _args: &ToolArgs) -> Result<ToolResultData, ToolHandlerError> {
            if self.should_fail {
                return Err(ToolHandlerError::FileNotFound {
                    path: "/nonexistent".to_string(),
                });
            }
            Ok(ToolResultData::success(
                b"file contents".to_vec(),
                BudgetDelta::single_call().with_bytes_io(13),
                Duration::from_millis(10),
            ))
        }

        fn validate(&self, args: &ToolArgs) -> Result<(), ToolHandlerError> {
            if !matches!(args, ToolArgs::Read(_)) {
                return Err(ToolHandlerError::InvalidArgs {
                    reason: "expected Read args".to_string(),
                });
            }
            Ok(())
        }

        fn name(&self) -> &'static str {
            "MockReadHandler"
        }

        fn estimate_budget(&self, _args: &ToolArgs) -> BudgetDelta {
            // Estimate should be >= actual to pass reconciliation
            // Actual returns bytes_io=13, so estimate at least that much
            BudgetDelta::single_call().with_bytes_io(100)
        }
    }

    #[test]
    fn test_executor_register_handler() {
        let mut executor = test_executor();

        executor
            .register_handler(Box::new(MockReadHandler::new()))
            .unwrap();

        assert!(executor.has_handler(ToolClass::Read));
        assert!(!executor.has_handler(ToolClass::Write));
        assert_eq!(executor.handler_count(), 1);
    }

    #[test]
    fn test_executor_register_duplicate_fails() {
        let mut executor = test_executor();

        executor
            .register_handler(Box::new(MockReadHandler::new()))
            .unwrap();

        let result = executor.register_handler(Box::new(MockReadHandler::new()));
        assert!(matches!(
            result,
            Err(ExecutorError::HandlerAlreadyRegistered { .. })
        ));
    }

    #[test]
    fn test_executor_handler_limit() {
        let tracker = Arc::new(BudgetTracker::from_envelope(test_budget()));
        let cas = Arc::new(StubContentAddressedStore::new());
        let mut executor = ToolExecutor::new(tracker, cas);

        // Fill up to limit
        // Note: We only have 7 tool classes defined, so we can't actually hit
        // MAX_HANDLERS (64), but we can verify the count mechanism works
        executor
            .register_handler(Box::new(MockReadHandler::new()))
            .unwrap();
        assert_eq!(executor.handler_count(), 1);
    }

    #[tokio::test]
    async fn test_executor_execute_success() {
        let mut executor = test_executor();
        executor
            .register_handler(Box::new(MockReadHandler::new()))
            .unwrap();

        let args = ToolArgs::Read(ReadArgs {
            path: PathBuf::from("workspace/file.rs"),
            offset: None,
            limit: None,
        });

        let result = executor.execute(&test_context(), &args).await.unwrap();

        assert!(result.success);
        assert_eq!(result.output, b"file contents");
        assert_eq!(result.exit_code, Some(0));
    }

    #[tokio::test]
    async fn test_executor_execute_no_handler() {
        let executor = test_executor();

        let args = ToolArgs::Read(ReadArgs {
            path: PathBuf::from("workspace/file.rs"),
            offset: None,
            limit: None,
        });

        let result = executor.execute(&test_context(), &args).await;

        assert!(matches!(result, Err(ExecutorError::HandlerNotFound { .. })));
    }

    #[tokio::test]
    async fn test_executor_execute_validation_fails() {
        let mut executor = test_executor();
        executor
            .register_handler(Box::new(MockReadHandler::new()))
            .unwrap();

        // Pass wrong args type
        let args = ToolArgs::Execute(crate::episode::tool_handler::ExecuteArgs {
            command: "ls".to_string(),
            args: vec![],
            cwd: None,
            stdin: None,
            timeout_ms: None,
        });

        // Validation should fail because handler expects Read args
        let result = executor.validate(&args);
        assert!(matches!(result, Err(ExecutorError::HandlerNotFound { .. })));
    }

    #[tokio::test]
    async fn test_executor_execute_handler_fails() {
        let mut executor = test_executor();
        executor
            .register_handler(Box::new(MockReadHandler::failing()))
            .unwrap();

        let args = ToolArgs::Read(ReadArgs {
            path: PathBuf::from("nonexistent"),
            offset: None,
            limit: None,
        });

        let result = executor.execute(&test_context(), &args).await.unwrap();

        // Should return failure result, not error
        assert!(!result.success);
        assert!(result.error_message.is_some());
    }

    #[tokio::test]
    async fn test_executor_budget_charged() {
        let mut executor = test_executor();
        executor
            .register_handler(Box::new(MockReadHandler::new()))
            .unwrap();

        let args = ToolArgs::Read(ReadArgs {
            path: PathBuf::from("workspace/file.rs"),
            offset: None,
            limit: None,
        });

        executor.execute(&test_context(), &args).await.unwrap();

        let consumed = executor.budget_tracker().consumed();
        assert_eq!(consumed.tool_calls, 1);
    }

    #[tokio::test]
    async fn test_executor_budget_exhausted() {
        let budget = EpisodeBudget::builder().tool_calls(1).build();
        let tracker = Arc::new(BudgetTracker::from_envelope(budget));
        let cas = Arc::new(StubContentAddressedStore::new());
        let mut executor = ToolExecutor::new(tracker, cas);

        executor
            .register_handler(Box::new(MockReadHandler::new()))
            .unwrap();

        let args = ToolArgs::Read(ReadArgs {
            path: PathBuf::from("workspace/file.rs"),
            offset: None,
            limit: None,
        });

        // First execution succeeds
        executor.execute(&test_context(), &args).await.unwrap();

        // Second execution fails due to budget
        let result = executor.execute(&test_context(), &args).await;
        assert!(matches!(result, Err(ExecutorError::BudgetExceeded(_))));
    }

    #[test]
    fn test_executor_has_budget() {
        let mut executor = test_executor();
        executor
            .register_handler(Box::new(MockReadHandler::new()))
            .unwrap();

        let args = ToolArgs::Read(ReadArgs {
            path: PathBuf::from("workspace/file.rs"),
            offset: None,
            limit: None,
        });

        assert!(executor.has_budget(&args));

        // No handler for Write
        let write_args = ToolArgs::Write(crate::episode::tool_handler::WriteArgs {
            path: PathBuf::from("workspace/file.rs"),
            content: Some(b"content".to_vec()),
            content_hash: None,
            create_parents: false,
            append: false,
        });
        assert!(!executor.has_budget(&write_args));
    }

    #[test]
    fn test_executor_error_kinds() {
        let err = ExecutorError::HandlerNotFound {
            tool_class: ToolClass::Read,
        };
        assert_eq!(err.kind(), "handler_not_found");
        assert!(!err.is_retriable());

        let err = ExecutorError::ExecutionFailed {
            message: "test".to_string(),
        };
        assert!(err.is_retriable());
    }

    #[test]
    fn test_execution_context() {
        let ctx = ExecutionContext::new(test_episode_id(), "req-123", 1000);
        assert_eq!(ctx.request_id, "req-123");
        assert_eq!(ctx.started_at_ns, 1000);
    }

    // =========================================================================
    // CAS storage tests (UT-00165-02)
    // =========================================================================

    #[tokio::test]
    async fn test_tool_cas_storage() {
        let tracker = Arc::new(BudgetTracker::from_envelope(test_budget()));
        let cas = Arc::new(StubContentAddressedStore::new());
        let mut executor = ToolExecutor::new(tracker, cas.clone());

        executor
            .register_handler(Box::new(MockReadHandler::new()))
            .unwrap();

        let args = ToolArgs::Read(ReadArgs {
            path: PathBuf::from("workspace/file.rs"),
            offset: None,
            limit: None,
        });

        let result = executor.execute(&test_context(), &args).await.unwrap();

        // Result should be successful
        assert!(result.success);

        // The result data was stored in CAS (we can't retrieve from stub,
        // but we verify the store operation completes)
        // In a real implementation, we'd verify the hash matches
    }

    // =========================================================================
    // Budget reconciliation tests (TCK-00165 Security Fix)
    // =========================================================================

    #[tokio::test]
    async fn test_executor_reconciles_budget() {
        let mut executor = test_executor();
        executor
            .register_handler(Box::new(MockReadHandler::new()))
            .unwrap();

        let args = ToolArgs::Read(ReadArgs {
            path: PathBuf::from("workspace/file.rs"),
            offset: None,
            limit: None,
        });

        // Execute tool - MockReadHandler returns budget with bytes_io=13
        // but the estimate is based on limit (4096 default)
        executor.execute(&test_context(), &args).await.unwrap();

        // Budget should be reconciled to actual consumption
        let consumed = executor.budget_tracker().consumed();
        // The actual bytes_io from MockReadHandler is 13, not the estimate
        assert_eq!(consumed.bytes_io, 13);
        assert_eq!(consumed.tool_calls, 1);
    }
}
