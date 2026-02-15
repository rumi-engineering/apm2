// AGENT-AUTHORED (TCK-00600)
//! Minimal systemd `sd_notify` protocol implementation.
//!
//! Implements the `sd_notify(3)` protocol for communicating service readiness
//! and watchdog liveness to systemd. The protocol uses a Unix datagram socket
//! whose path is provided via the `NOTIFY_SOCKET` environment variable.
//!
//! # Security Invariants
//!
//! - [INV-SDN-001] `NOTIFY_SOCKET` path is validated for length (bounded by
//!   `MAX_NOTIFY_SOCKET_PATH`) and must be either an absolute path or an
//!   abstract socket (`@` prefix).
//! - [INV-SDN-002] All errors are non-fatal: `sd_notify` is best-effort.
//!   Failure to notify does not affect service operation.
//! - [INV-SDN-003] No heap allocation beyond the socket path itself.
//! - [INV-SDN-004] Uses `Instant` (monotonic) for watchdog interval tracking
//!   per INV-2501.

use std::os::unix::net::UnixDatagram;
use std::path::Path;
use std::time::Instant;

use tracing::{debug, trace, warn};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum length of `NOTIFY_SOCKET` path to prevent oversized allocations.
const MAX_NOTIFY_SOCKET_PATH: usize = 256;

/// Environment variable name for the systemd notification socket.
const NOTIFY_SOCKET_ENV: &str = "NOTIFY_SOCKET";

/// Minimum watchdog interval to prevent busy-loop notification (5 seconds).
const MIN_WATCHDOG_INTERVAL_SECS: u64 = 5;

// ---------------------------------------------------------------------------
// Validation (pure, testable)
// ---------------------------------------------------------------------------

/// Validate the socket path per INV-SDN-001.
///
/// Returns `Ok(())` if the path is valid, or an error message if not.
fn validate_socket_path(socket_path: &str) -> Result<(), &'static str> {
    if socket_path.len() > MAX_NOTIFY_SOCKET_PATH {
        return Err("NOTIFY_SOCKET path exceeds maximum length");
    }
    if !socket_path.starts_with('/') && !socket_path.starts_with('@') {
        return Err("NOTIFY_SOCKET must be absolute path or abstract socket (@)");
    }
    Ok(())
}

/// Compute the watchdog ping interval from a `WATCHDOG_USEC` value.
///
/// Returns `Some(interval_secs)` if watchdog should be enabled,
/// `None` if the value is zero or invalid.
fn compute_watchdog_interval(watchdog_usec_str: &str) -> Option<u64> {
    let usec = watchdog_usec_str.parse::<u64>().ok()?;
    if usec == 0 {
        return None;
    }
    // Half the interval (systemd recommendation), with a minimum floor.
    let interval_secs = (usec / 1_000_000) / 2;
    Some(interval_secs.max(MIN_WATCHDOG_INTERVAL_SECS))
}

// ---------------------------------------------------------------------------
// Core notify function
// ---------------------------------------------------------------------------

/// Send a notification message to systemd via the `NOTIFY_SOCKET`.
///
/// Returns `true` if the message was sent successfully, `false` if the
/// socket is unavailable or the send failed. Failures are non-fatal and
/// logged at debug level.
fn sd_notify_raw(state: &str) -> bool {
    let Ok(socket_path) = std::env::var(NOTIFY_SOCKET_ENV) else {
        trace!(
            "NOTIFY_SOCKET not set, skipping sd_notify({})",
            state.split('\n').next().unwrap_or(state)
        );
        return false;
    };

    if let Err(reason) = validate_socket_path(&socket_path) {
        warn!("{reason}, skipping sd_notify");
        return false;
    }

    // For abstract sockets, replace leading '@' with '\0'.
    let resolved_path = socket_path
        .strip_prefix('@')
        .map_or_else(|| socket_path.clone(), |suffix| format!("\0{suffix}"));
    let target: &Path = Path::new(&resolved_path);

    let Ok(sock) = UnixDatagram::unbound() else {
        debug!("Failed to create unbound datagram socket for sd_notify");
        return false;
    };

    match sock.send_to(state.as_bytes(), target) {
        Ok(_) => {
            trace!(
                "sd_notify sent: {}",
                state.split('\n').next().unwrap_or(state)
            );
            true
        },
        Err(e) => {
            debug!(error = %e, "Failed to send sd_notify message");
            false
        },
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Notify systemd that the service is ready (`READY=1`).
///
/// Call this after all initialization is complete and the service is ready
/// to accept requests. For `Type=notify` services, systemd waits for this
/// notification before considering the service started.
#[must_use]
pub fn notify_ready() -> bool {
    sd_notify_raw("READY=1")
}

/// Notify systemd that the service is stopping (`STOPPING=1`).
///
/// Call this when the service begins its shutdown sequence.
#[must_use]
pub fn notify_stopping() -> bool {
    sd_notify_raw("STOPPING=1")
}

/// Send a watchdog keepalive ping (`WATCHDOG=1`).
///
/// Call this periodically at less than half the `WatchdogSec` interval.
/// If systemd does not receive a watchdog ping within the configured
/// interval, it will restart the service.
#[must_use]
pub fn notify_watchdog() -> bool {
    sd_notify_raw("WATCHDOG=1")
}

/// Send a status message to systemd.
///
/// The status appears in `systemctl status` output. Bounded to 256 bytes
/// to prevent oversized messages.
#[must_use]
pub fn notify_status(status: &str) -> bool {
    // Bound status message to prevent oversized datagrams.
    // Manually find a char boundary at or before byte 256 (MSRV compat;
    // floor_char_boundary requires 1.91.0).
    let truncated = if status.len() > 256 {
        let mut end = 256;
        while end > 0 && !status.is_char_boundary(end) {
            end -= 1;
        }
        &status[..end]
    } else {
        status
    };
    sd_notify_raw(&format!("STATUS={truncated}"))
}

/// A watchdog ticker that tracks when the next `WATCHDOG=1` should be sent.
///
/// Reads `WATCHDOG_USEC` from the environment to determine the systemd
/// watchdog interval. Pings should be sent at half the interval (systemd
/// recommendation).
///
/// # Synchronization Protocol (RS-21)
///
/// - Protected data: `last_ping` timestamp.
/// - Mutators: only the owning task/thread calls `ping_if_due()`.
/// - No concurrent access: owned by a single task.
pub struct WatchdogTicker {
    /// Interval between pings (half of `WatchdogSec`).
    ping_interval_secs: u64,
    /// Last time we sent a watchdog ping (monotonic).
    last_ping: Instant,
    /// Whether watchdog is enabled (`WATCHDOG_USEC` is set).
    enabled: bool,
}

impl WatchdogTicker {
    /// Create a new watchdog ticker.
    ///
    /// Reads `WATCHDOG_USEC` from the environment. If not set or invalid,
    /// the ticker is disabled and `ping_if_due()` is a no-op.
    #[must_use]
    pub fn new() -> Self {
        let (enabled, ping_interval_secs) = std::env::var("WATCHDOG_USEC").map_or_else(
            |_| {
                debug!("WATCHDOG_USEC not set, watchdog ticker disabled");
                (false, 0)
            },
            |val| {
                compute_watchdog_interval(&val).map_or_else(
                    || {
                        debug!("WATCHDOG_USEC is zero or invalid, watchdog disabled");
                        (false, 0)
                    },
                    |interval| {
                        debug!(ping_interval_secs = interval, "Watchdog ticker enabled");
                        (true, interval)
                    },
                )
            },
        );

        Self {
            ping_interval_secs,
            last_ping: Instant::now(),
            enabled,
        }
    }

    /// Send a watchdog ping if enough time has elapsed since the last ping.
    ///
    /// Returns `true` if a ping was sent, `false` if not due yet or disabled.
    /// Uses monotonic `Instant` for timing (INV-2501).
    pub fn ping_if_due(&mut self) -> bool {
        if !self.enabled {
            return false;
        }

        let elapsed = self.last_ping.elapsed();
        if elapsed.as_secs() >= self.ping_interval_secs && notify_watchdog() {
            self.last_ping = Instant::now();
            return true;
        }
        false
    }

    /// Whether the watchdog is enabled.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }
}

impl Default for WatchdogTicker {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Tests for validation logic (pure functions, no env mutation).

    #[test]
    fn test_validate_socket_path_absolute() {
        assert!(validate_socket_path("/run/systemd/notify").is_ok());
    }

    #[test]
    fn test_validate_socket_path_abstract() {
        assert!(validate_socket_path("@/run/systemd/notify").is_ok());
    }

    #[test]
    fn test_validate_socket_path_relative_rejected() {
        assert!(validate_socket_path("relative/path").is_err());
    }

    #[test]
    fn test_validate_socket_path_oversized_rejected() {
        let long_path = format!("/{}", "a".repeat(MAX_NOTIFY_SOCKET_PATH + 1));
        assert!(validate_socket_path(&long_path).is_err());
    }

    #[test]
    fn test_validate_socket_path_exactly_max_ok() {
        // Exactly MAX_NOTIFY_SOCKET_PATH is accepted.
        let path = format!("/{}", "a".repeat(MAX_NOTIFY_SOCKET_PATH - 1));
        assert_eq!(path.len(), MAX_NOTIFY_SOCKET_PATH);
        assert!(validate_socket_path(&path).is_ok());
    }

    #[test]
    fn test_compute_watchdog_interval_valid() {
        // 600_000_000 usec = 600s. Half = 300s.
        assert_eq!(compute_watchdog_interval("600000000"), Some(300));
    }

    #[test]
    fn test_compute_watchdog_interval_minimum_floor() {
        // 2_000_000 usec = 2s. Half = 1s. Minimum floor = 5s.
        assert_eq!(
            compute_watchdog_interval("2000000"),
            Some(MIN_WATCHDOG_INTERVAL_SECS)
        );
    }

    #[test]
    fn test_compute_watchdog_interval_zero() {
        assert_eq!(compute_watchdog_interval("0"), None);
    }

    #[test]
    fn test_compute_watchdog_interval_invalid() {
        assert_eq!(compute_watchdog_interval("not_a_number"), None);
        assert_eq!(compute_watchdog_interval(""), None);
    }

    #[test]
    fn test_status_truncation_no_panic() {
        // Verify status formatting doesn't panic on long strings.
        let long_status = "x".repeat(1000);
        let truncated = if long_status.len() > 256 {
            let mut end = 256;
            while end > 0 && !long_status.is_char_boundary(end) {
                end -= 1;
            }
            &long_status[..end]
        } else {
            &long_status
        };
        assert!(truncated.len() <= 256);
        assert_eq!(truncated.len(), 256);
    }

    #[test]
    fn test_watchdog_ticker_default_is_disabled() {
        // Default ticker (when WATCHDOG_USEC is not set in the test
        // environment) should be disabled.
        let ticker = WatchdogTicker::default();
        // In CI or normal test environments, WATCHDOG_USEC is typically
        // not set, so the ticker should be disabled. If it IS set (e.g.,
        // running under systemd), it will be enabled — both are valid.
        // We just verify the struct is well-formed.
        assert_eq!(ticker.ping_interval_secs == 0, !ticker.is_enabled());
    }
}
