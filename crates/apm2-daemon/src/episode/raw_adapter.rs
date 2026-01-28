//! Raw adapter implementation.
//!
//! The [`RawAdapter`] is a baseline adapter that spawns processes and emits
//! all PTY output as raw [`HarnessEvent::Output`] events without any parsing.
//!
//! # Behavior
//!
//! - Spawns processes using PTY (pseudo-terminal) for proper terminal emulation
//! - Emits all output as `Output` events with `OutputKind::Combined`
//! - Does not parse tool calls or structured events
//! - Forwards termination status directly
//!
//! This adapter is useful for:
//! - Running arbitrary shell commands
//! - Testing and debugging harness infrastructure
//! - Processes that don't have structured output formats

use std::pin::Pin;
use std::process::ExitStatus;
use std::sync::atomic::{AtomicU64, Ordering};

use super::adapter::{
    AdapterError, AdapterResult, AdapterType, HarnessAdapter, HarnessConfig, HarnessEvent,
    HarnessEventStream, HarnessHandle, HarnessHandleInner, TerminationClassification,
};

/// Counter for generating unique handle IDs.
static HANDLE_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Raw adapter that emits unstructured output.
///
/// This adapter spawns processes and emits all PTY output as raw events.
/// It does not parse tool calls or structured events.
///
/// # Example
///
/// ```rust,ignore
/// use apm2_daemon::episode::raw_adapter::RawAdapter;
/// use apm2_daemon::episode::adapter::{HarnessConfig, HarnessAdapter};
///
/// let adapter = RawAdapter::new();
/// let config = HarnessConfig::new("echo", "episode-1")
///     .with_args(vec!["hello".to_string()]);
///
/// let (handle, mut events) = adapter.spawn(config).await?;
///
/// while let Some(event) = events.recv().await {
///     println!("Event: {:?}", event);
/// }
/// ```
#[derive(Debug, Default)]
pub struct RawAdapter {
    /// Placeholder for future configuration.
    _private: (),
}

impl RawAdapter {
    /// Create a new raw adapter.
    #[must_use]
    pub const fn new() -> Self {
        Self { _private: () }
    }

    /// Generate a new unique handle ID.
    fn next_handle_id() -> u64 {
        HANDLE_ID_COUNTER.fetch_add(1, Ordering::Relaxed)
    }
}

impl HarnessAdapter for RawAdapter {
    fn adapter_type(&self) -> AdapterType {
        AdapterType::Raw
    }

    fn spawn(
        &self,
        config: HarnessConfig,
    ) -> Pin<
        Box<
            dyn std::future::Future<Output = AdapterResult<(HarnessHandle, HarnessEventStream)>>
                + Send
                + '_,
        >,
    > {
        Box::pin(async move {
            // For now, create a placeholder implementation.
            // Full PTY integration will come with TCK-00161.
            //
            // This creates a handle and a channel that can be used for testing
            // the adapter interface.

            let handle_id = Self::next_handle_id();
            let episode_id = config.episode_id.clone();

            // Create the event channel
            let (tx, rx) = tokio::sync::mpsc::channel(256);

            // Spawn a task that runs the process
            // For now, just immediately emit a terminated event as a placeholder
            tokio::spawn(async move {
                // Placeholder: In full implementation, this would:
                // 1. Create PTY master/slave pair
                // 2. Fork and exec the command
                // 3. Read from PTY master and emit Output events
                // 4. Emit Terminated event when process exits

                // For now, emit a placeholder terminated event
                let _ = tx
                    .send(HarnessEvent::terminated(
                        None,
                        TerminationClassification::Unknown,
                    ))
                    .await;
            });

            let handle = HarnessHandle::new(handle_id, episode_id, HarnessHandleInner::Placeholder);

            Ok((handle, rx))
        })
    }

    fn send_input(
        &self,
        _handle: &HarnessHandle,
        _input: &[u8],
    ) -> Pin<Box<dyn std::future::Future<Output = AdapterResult<()>> + Send + '_>> {
        Box::pin(async move {
            // Placeholder implementation - full PTY integration will write to PTY master
            Err(AdapterError::input_failed(
                "raw adapter PTY not yet implemented",
            ))
        })
    }

    fn terminate(
        &self,
        _handle: &HarnessHandle,
    ) -> Pin<Box<dyn std::future::Future<Output = AdapterResult<ExitStatus>> + Send + '_>> {
        Box::pin(async move {
            // Placeholder implementation - full PTY integration will:
            // 1. Send SIGTERM
            // 2. Wait with timeout
            // 3. Send SIGKILL if needed
            Err(AdapterError::terminate_failed(
                "raw adapter PTY not yet implemented",
            ))
        })
    }
}

/// Helper functions for testing the raw adapter.
#[cfg(test)]
pub(crate) mod test_helpers {
    use std::time::SystemTime;

    use super::super::adapter::OutputKind;
    use super::*;

    /// Get the current timestamp in nanoseconds.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn now_ns() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    }

    /// Create a mock output event for testing.
    #[must_use]
    pub fn mock_output_event(data: &[u8], seq: u64) -> HarnessEvent {
        HarnessEvent::output(data.to_vec(), OutputKind::Combined, seq, now_ns())
    }
}

#[cfg(test)]
mod tests {
    use super::super::adapter::OutputKind;
    use super::*;

    #[test]
    fn test_raw_adapter_new() {
        let adapter = RawAdapter::new();
        assert_eq!(adapter.adapter_type(), AdapterType::Raw);
    }

    #[test]
    fn test_raw_adapter_default() {
        let adapter = RawAdapter::default();
        assert_eq!(adapter.adapter_type(), AdapterType::Raw);
    }

    #[test]
    fn test_raw_adapter_debug() {
        let adapter = RawAdapter::new();
        let debug_str = format!("{adapter:?}");
        assert!(debug_str.contains("RawAdapter"));
    }

    #[test]
    fn test_handle_id_generation() {
        let id1 = RawAdapter::next_handle_id();
        let id2 = RawAdapter::next_handle_id();
        let id3 = RawAdapter::next_handle_id();

        // IDs should be monotonically increasing
        assert!(id2 > id1);
        assert!(id3 > id2);
    }

    #[tokio::test]
    async fn test_raw_adapter_spawn() {
        let adapter = RawAdapter::new();
        let config =
            HarnessConfig::new("echo", "episode-test").with_args(vec!["hello".to_string()]);

        let result = adapter.spawn(config).await;
        assert!(result.is_ok());

        let (handle, mut events) = result.unwrap();
        assert!(!handle.episode_id().is_empty());
        assert_eq!(handle.episode_id(), "episode-test");

        // Should receive at least one event (the placeholder terminated event)
        let event =
            tokio::time::timeout(std::time::Duration::from_millis(100), events.recv()).await;

        assert!(event.is_ok());
        let event = event.unwrap();
        assert!(event.is_some());
        assert!(event.unwrap().is_terminal());
    }

    #[tokio::test]
    async fn test_raw_adapter_send_input_not_implemented() {
        let adapter = RawAdapter::new();
        let config = HarnessConfig::new("cat", "episode-test");

        let (handle, _events) = adapter.spawn(config).await.unwrap();

        let result = adapter.send_input(&handle, b"test input").await;
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(matches!(err, AdapterError::InputFailed { .. }));
    }

    #[tokio::test]
    async fn test_raw_adapter_terminate_not_implemented() {
        let adapter = RawAdapter::new();
        let config = HarnessConfig::new("sleep", "episode-test").with_args(vec!["1".to_string()]);

        let (handle, _events) = adapter.spawn(config).await.unwrap();

        let result = adapter.terminate(&handle).await;
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(matches!(err, AdapterError::TerminateFailed { .. }));
    }

    #[test]
    fn test_mock_output_event() {
        let event = test_helpers::mock_output_event(b"test data", 1);

        match event {
            HarnessEvent::Output {
                chunk,
                kind,
                seq,
                ts,
            } => {
                assert_eq!(chunk, b"test data");
                assert_eq!(kind, OutputKind::Combined);
                assert_eq!(seq, 1);
                assert!(ts > 0);
            },
            _ => panic!("expected Output event"),
        }
    }
}
