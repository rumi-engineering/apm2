//! Durable planned-intent buffer contract.

/// Durable intent queue contract used between Plan and Execute phases.
#[allow(async_fn_in_trait)]
pub trait IntentStore<Intent, IntentKey>: Send + Sync {
    /// Store-specific error type.
    type Error;

    /// Enqueues planned intents durably.
    ///
    /// Returns the count of newly enqueued intents.
    async fn enqueue_many(&self, intents: &[Intent]) -> Result<usize, Self::Error>;

    /// Dequeues a bounded batch for execution.
    async fn dequeue_batch(&self, limit: usize) -> Result<Vec<Intent>, Self::Error>;

    /// Marks an intent as done.
    async fn mark_done(&self, key: &IntentKey) -> Result<(), Self::Error>;

    /// Marks an intent as blocked with a fail-closed reason.
    async fn mark_blocked(&self, key: &IntentKey, reason: &str) -> Result<(), Self::Error>;

    /// Marks an intent as retryable and returns it to pending execution.
    async fn mark_retryable(&self, key: &IntentKey, reason: &str) -> Result<(), Self::Error>;
}
