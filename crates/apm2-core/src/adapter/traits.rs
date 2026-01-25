//! Adapter trait definitions.
//!
//! This module defines the common interface that all adapters (black-box and
//! instrumented) must implement. The trait enables the supervisor to interact
//! with different adapter types uniformly.

use std::future::Future;
use std::pin::Pin;

use tokio::sync::mpsc;

use super::error::AdapterError;
use super::event::AdapterEvent;

/// A boxed future for async trait methods.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Trait for agent adapters.
///
/// All adapter implementations (black-box, instrumented, etc.) implement this
/// trait to provide a uniform interface for the supervisor.
///
/// # Lifecycle
///
/// 1. Create adapter with configuration
/// 2. Call `start()` to spawn process and begin monitoring
/// 3. Use `poll()` or `take_event_receiver()` to receive events
/// 4. Call `stop()` to terminate the adapter
///
/// # Event Ordering
///
/// Events are guaranteed to be ordered by their sequence number within a
/// single adapter instance. The first event is always `ProcessStarted` and
/// the last event is always `ProcessExited` (unless the adapter crashes).
pub trait Adapter: Send {
    /// Starts the adapter, spawning the agent process.
    ///
    /// This initializes the adapter, spawns the agent process, and begins
    /// monitoring for events. After this returns successfully, events will
    /// be available via `poll()` or the event receiver.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The adapter is already running
    /// - The process fails to spawn
    /// - Initialization of monitoring systems fails
    fn start(&mut self) -> BoxFuture<'_, Result<(), AdapterError>>;

    /// Polls for the next event.
    ///
    /// This is a non-blocking poll that checks for:
    /// - Process status changes (exit, signals)
    /// - Filesystem changes (for black-box adapters)
    /// - Tool requests (from instrumentation or inference)
    /// - Stall detection
    ///
    /// Returns `Ok(None)` if no event is available.
    /// Returns `Ok(Some(event))` if an event is available.
    ///
    /// # Errors
    ///
    /// Returns an error if the adapter is not running or an internal error
    /// occurs.
    fn poll(&mut self) -> BoxFuture<'_, Result<Option<AdapterEvent>, AdapterError>>;

    /// Stops the adapter, terminating the agent process.
    ///
    /// This sends a termination signal to the agent process and performs
    /// cleanup. After this returns, no more events will be emitted.
    ///
    /// # Errors
    ///
    /// Returns an error if termination fails.
    fn stop(&mut self) -> BoxFuture<'_, Result<(), AdapterError>>;

    /// Takes the event receiver for async event consumption.
    ///
    /// This can only be called once. Subsequent calls return `None`.
    /// Use this to receive events asynchronously rather than polling.
    fn take_event_receiver(&mut self) -> Option<mpsc::Receiver<AdapterEvent>>;

    /// Returns the session ID for this adapter.
    fn session_id(&self) -> &str;

    /// Returns whether the adapter is currently running.
    fn is_running(&self) -> bool;

    /// Returns the process ID if the adapter is running.
    fn pid(&self) -> Option<u32>;

    /// Returns the adapter type identifier.
    fn adapter_type(&self) -> &'static str;
}

/// Extension trait for adapters with additional capabilities.
pub trait AdapterExt: Adapter {
    /// Runs the adapter until the process exits.
    ///
    /// This is a convenience method that calls `poll()` in a loop until
    /// the process exits or an error occurs.
    fn run_until_exit(&mut self) -> BoxFuture<'_, Result<(), AdapterError>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test that the trait can be used as a trait object
    fn _assert_object_safety(_: &dyn Adapter) {}

    // Test that BoxFuture works correctly
    #[tokio::test]
    async fn test_box_future() {
        let future: BoxFuture<'_, i32> = Box::pin(async { 42 });
        assert_eq!(future.await, 42);
    }
}
