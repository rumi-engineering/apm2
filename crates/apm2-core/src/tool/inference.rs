//! Inference tool implementation.
//!
//! Provides the execution logic for inference calls (`InferenceCall`).
//! Integrates with a provider abstraction and deducts token usage from the
//! budget.

use std::sync::Arc;

use tracing::info;

use super::{InferenceCall, ToolError};
use crate::adapter::BoxFuture;
use crate::budget::{BudgetTracker, BudgetType};
use crate::evidence::{CasError, ContentAddressedStore};

/// Trait for inference providers.
pub trait InferenceProvider: Send + Sync + std::fmt::Debug {
    /// Perform an inference call.
    ///
    /// Returns the generated text and token usage.
    fn generate<'a>(
        &'a self,
        prompt: &'a str,
        req: &'a InferenceCall,
    ) -> BoxFuture<'a, Result<InferenceResult, ToolError>>;
}

/// Result of an inference call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InferenceResult {
    /// Generated text.
    pub text: String,
    /// Token usage stats.
    pub usage: TokenUsage,
}

/// Token usage statistics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenUsage {
    /// Number of tokens in the input prompt.
    pub input_tokens: u64,
    /// Number of tokens in the generated output.
    pub output_tokens: u64,
}

/// Inference tool handler.
pub struct InferenceTool {
    provider: Box<dyn InferenceProvider>,
    cas: Arc<dyn ContentAddressedStore>,
}

impl std::fmt::Debug for InferenceTool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InferenceTool")
            .field("provider", &self.provider)
            .field("cas", &"<CAS>")
            .finish()
    }
}

impl InferenceTool {
    /// Create a new inference tool handler.
    pub fn new(provider: Box<dyn InferenceProvider>, cas: Arc<dyn ContentAddressedStore>) -> Self {
        Self { provider, cas }
    }

    /// Execute an inference request.
    ///
    /// # Errors
    ///
    /// Returns a `ToolError` if:
    /// - The prompt cannot be retrieved from CAS
    /// - The prompt is not valid UTF-8
    /// - The budget is insufficient
    /// - The provider fails
    pub async fn execute(
        &self,
        req: &InferenceCall,
        budget: &mut BudgetTracker,
    ) -> Result<InferenceResult, ToolError> {
        info!("Executing inference call: {}/{}", req.provider, req.model);

        // 1. Check budget for max_tokens (conservative check)
        // We assume 1 input token minimum, plus max_tokens output.
        // This is a rough check to fail fast if the budget is obviously depleted.
        if !budget.can_charge(BudgetType::Token, req.max_tokens) {
            return Err(ToolError {
                error_code: "BUDGET_EXCEEDED".to_string(),
                message: "Insufficient token budget for max_tokens".to_string(),
                retryable: false,
                retry_after_ms: 0,
            });
        }

        // 2. Retrieve prompt from CAS
        let prompt_bytes = self
            .cas
            .retrieve_hash(&req.prompt_hash)
            .map_err(|e| ToolError {
                error_code: "CAS_ERROR".to_string(),
                message: format!("Failed to retrieve prompt: {e}"),
                retryable: matches!(e, CasError::NotFound { .. }), /* Maybe retryable if upload
                                                                    * lagging? */
                retry_after_ms: 0,
            })?;

        let prompt = String::from_utf8(prompt_bytes).map_err(|e| ToolError {
            error_code: "INVALID_PROMPT".to_string(),
            message: format!("Prompt is not valid UTF-8: {e}"),
            retryable: false,
            retry_after_ms: 0,
        })?;

        // 3. Call provider
        let result = self.provider.generate(&prompt, req).await?;

        // 4. Charge actual usage
        let total_tokens = result.usage.input_tokens + result.usage.output_tokens;
        // This might exceed the remaining budget if our conservative check passed
        // but actual usage was higher (e.g. huge prompt).
        // BudgetTracker saturates, so it's safe.
        budget.record_tokens(total_tokens);

        Ok(result)
    }
}

// Helper trait to allow retrieving by raw byte slice (from proto)
trait CasExt {
    fn retrieve_hash(&self, hash_bytes: &[u8]) -> Result<Vec<u8>, CasError>;
}

impl<T: ContentAddressedStore + ?Sized> CasExt for T {
    fn retrieve_hash(&self, hash_bytes: &[u8]) -> Result<Vec<u8>, CasError> {
        if hash_bytes.len() != 32 {
            return Err(CasError::InvalidHash {
                expected: 32,
                actual: hash_bytes.len(),
            });
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(hash_bytes);
        self.retrieve(&array)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::BudgetConfig;
    use crate::evidence::MemoryCas;

    #[derive(Debug)]
    struct MockProvider {
        response_text: String,
        input_tokens: u64,
        output_tokens: u64,
    }

    impl InferenceProvider for MockProvider {
        fn generate<'a>(
            &'a self,
            _prompt: &'a str,
            _req: &'a InferenceCall,
        ) -> BoxFuture<'a, Result<InferenceResult, ToolError>> {
            Box::pin(async move {
                Ok(InferenceResult {
                    text: self.response_text.clone(),
                    usage: TokenUsage {
                        input_tokens: self.input_tokens,
                        output_tokens: self.output_tokens,
                    },
                })
            })
        }
    }

    #[tokio::test]
    async fn test_inference_success() {
        let cas = Arc::new(MemoryCas::new());
        let prompt = "Hello AI";
        let store_result = cas.store(prompt.as_bytes()).unwrap();
        let prompt_hash = store_result.hash.to_vec();

        let provider = Box::new(MockProvider {
            response_text: "Hello User".to_string(),
            input_tokens: 10,
            output_tokens: 5,
        });

        let tool = InferenceTool::new(provider, cas);
        let mut budget = BudgetTracker::new("session-1", BudgetConfig::default());

        let req = InferenceCall {
            provider: "mock".to_string(),
            model: "test".to_string(),
            prompt_hash,
            max_tokens: 100,
            temperature_scaled: 70,
            system_prompt_hash: vec![],
        };

        let result = tool.execute(&req, &mut budget).await.unwrap();
        assert_eq!(result.text, "Hello User");
        assert_eq!(budget.consumed(BudgetType::Token), 15);
    }

    #[tokio::test]
    async fn test_inference_budget_exceeded_pre_check() {
        let cas = Arc::new(MemoryCas::new());
        let provider = Box::new(MockProvider {
            response_text: String::new(),
            input_tokens: 0,
            output_tokens: 0,
        });

        let tool = InferenceTool::new(provider, cas);
        // Budget limit 50
        let config = BudgetConfig::builder().token_budget(50).build();
        let mut budget = BudgetTracker::new("session-1", config);

        let req = InferenceCall {
            provider: "mock".to_string(),
            model: "test".to_string(),
            prompt_hash: vec![0u8; 32], // Doesn't matter, fails before CAS
            max_tokens: 100,            // Exceeds budget
            temperature_scaled: 0,
            system_prompt_hash: vec![],
        };

        let err = tool.execute(&req, &mut budget).await.unwrap_err();
        assert_eq!(err.error_code, "BUDGET_EXCEEDED");
    }
}
