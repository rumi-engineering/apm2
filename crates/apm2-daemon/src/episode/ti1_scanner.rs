//! TI1 `ToolIntent` scanner for delimiter-framed tool requests.
//!
//! This module scans PTY output lines for the `⟦TI1 <nonce>⟧` delimiter
//! grammar defined in RFC-0019 section 11, Option C. Lines that do not
//! match the delimiter are treated as opaque agent output (Markov blanket
//! preserved).
//!
//! # Wire Format
//!
//! Request: `⟦TI1 <nonce>⟧ <request_id> <tool_name> <args_b64url>`
//! Response: `⟦TR1 <nonce>⟧ <request_id> ok <cas_result_hash>`
//!
//! # Security Invariants
//!
//! - Nonce MUST be per-episode: `BLAKE3(nonce_prefix || episode_id ||
//!   spawn_time_ns)`
//! - `args_b64url` MUST be bounded by `max_args_size` from `ToolBridgeConfig`
//! - Non-matching lines are NEVER interpreted as tool requests

use base64::Engine;

use super::adapter::HarnessEvent;

/// Unicode left double angle bracket (U+27E6).
const TI1_OPEN: char = '\u{27E6}';

/// Unicode right double angle bracket (U+27E7).
const TI1_CLOSE: char = '\u{27E7}';

/// TI1 request delimiter prefix.
const TI1_PREFIX: &str = "TI1 ";

/// Maximum bytes retained for a single in-progress PTY output line.
///
/// This bounds `line_buffer` growth when an agent emits output without
/// newline delimiters.
pub const MAX_LINE_LENGTH: usize = 256 * 1024;

/// Error type for TI1 frame parsing failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ti1ParseError {
    /// Line does not contain the TI1 delimiter.
    NotTi1Frame,

    /// Nonce in the frame does not match the expected per-episode nonce.
    NonceMismatch {
        /// The expected nonce.
        expected: String,
        /// The nonce found in the frame.
        found: String,
    },

    /// The frame is missing required fields.
    MalformedFrame {
        /// Description of what is missing.
        reason: String,
    },

    /// The base64url-encoded args exceed the configured `max_args_size`.
    ArgsTooLarge {
        /// Decoded size in bytes.
        decoded_size: usize,
        /// Maximum allowed size.
        max_size: usize,
    },

    /// The base64url input length exceeds the safe pre-decode bound for
    /// `max_args_size`.
    ArgsBase64TooLarge {
        /// Encoded base64url size in bytes.
        encoded_size: usize,
        /// Maximum allowed encoded size in bytes.
        max_encoded_size: usize,
        /// Maximum decoded size in bytes.
        max_decoded_size: usize,
    },

    /// Failed to decode base64url args.
    InvalidBase64 {
        /// Description of the decode error.
        reason: String,
    },

    /// A PTY output line exceeded `MAX_LINE_LENGTH` during scanning.
    LineTooLong {
        /// Attempted line length in bytes.
        line_length: usize,
        /// Maximum allowed line size.
        max_size: usize,
    },

    /// Failed to parse decoded args as JSON.
    InvalidJson {
        /// Description of the parse error.
        reason: String,
    },
}

impl std::fmt::Display for Ti1ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotTi1Frame => write!(f, "not a TI1 frame"),
            Self::NonceMismatch { expected, found } => {
                write!(f, "nonce mismatch: expected '{expected}', found '{found}'")
            },
            Self::MalformedFrame { reason } => write!(f, "malformed TI1 frame: {reason}"),
            Self::ArgsTooLarge {
                decoded_size,
                max_size,
            } => write!(
                f,
                "TI1 args too large: {decoded_size} bytes exceeds maximum {max_size}"
            ),
            Self::ArgsBase64TooLarge {
                encoded_size,
                max_encoded_size,
                max_decoded_size,
            } => write!(
                f,
                "TI1 args base64 too large: encoded {encoded_size} bytes exceeds maximum \
                 {max_encoded_size} bytes for decoded limit {max_decoded_size}"
            ),
            Self::InvalidBase64 { reason } => write!(f, "invalid base64url in TI1 args: {reason}"),
            Self::LineTooLong {
                line_length,
                max_size,
            } => write!(
                f,
                "TI1 scanner line too long: {line_length} bytes exceeds maximum {max_size}"
            ),
            Self::InvalidJson { reason } => write!(f, "invalid JSON in TI1 args: {reason}"),
        }
    }
}

impl std::error::Error for Ti1ParseError {}

/// A parsed TI1 tool request frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ti1Frame {
    /// Unique request ID for correlation.
    pub request_id: String,
    /// Tool name being requested.
    pub tool_name: String,
    /// Decoded tool arguments as JSON.
    pub args: serde_json::Value,
}

/// Compute the per-episode nonce: `BLAKE3(nonce_prefix || episode_id ||
/// spawn_time_ns)`.
///
/// The nonce is truncated to 16 hex characters (8 bytes) for wire brevity.
#[must_use]
pub fn compute_nonce(nonce_prefix: &str, episode_id: &str, spawn_time_ns: u64) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(nonce_prefix.as_bytes());
    hasher.update(episode_id.as_bytes());
    hasher.update(&spawn_time_ns.to_le_bytes());
    let hash = hasher.finalize();
    hex::encode(&hash.as_bytes()[..8])
}

/// Format a TR1 response line for injecting tool results back via stdin.
///
/// Format: `⟦TR1 <nonce>⟧ <request_id> ok <cas_result_hash>\n`
#[must_use]
pub fn format_tr1_response(nonce: &str, request_id: &str, cas_result_hash: &str) -> String {
    format!("{TI1_OPEN}TR1 {nonce}{TI1_CLOSE} {request_id} ok {cas_result_hash}\n")
}

/// Format a TR1 denial response line.
///
/// Format: `⟦TR1 <nonce>⟧ <request_id> denied <reason_code>\n`
#[must_use]
pub fn format_tr1_denial(nonce: &str, request_id: &str, reason_code: &str) -> String {
    format!("{TI1_OPEN}TR1 {nonce}{TI1_CLOSE} {request_id} denied {reason_code}\n")
}

/// TI1 scanner configuration.
#[derive(Debug, Clone)]
pub struct Ti1ScannerConfig {
    /// Per-episode nonce for delimiter validation.
    pub nonce: String,
    /// Maximum decoded args size in bytes.
    pub max_args_size: usize,
}

/// Compute a safe pre-decode bound for base64url input length.
///
/// Uses the upper-bound formula `decoded ~= encoded * 3 / 4`, rearranged to
/// `encoded <= (max_args_size * 4 / 3) + 4`.
const fn max_base64_input_len(max_args_size: usize) -> usize {
    max_args_size
        .saturating_mul(4)
        .saturating_div(3)
        .saturating_add(4)
}

/// Scans a single line for a TI1 frame.
///
/// Returns `Ok(Ti1Frame)` if the line matches the `⟦TI1 <nonce>⟧` delimiter
/// and passes all validation. Returns `Err(Ti1ParseError::NotTi1Frame)` for
/// lines that are opaque agent output (Markov blanket preserved).
///
/// # Security
///
/// - Nonce is validated against the per-episode expected value
/// - Decoded args are bounded by `max_args_size`
/// - Args must be valid base64url-encoded JSON
pub fn parse_ti1_line(line: &str, config: &Ti1ScannerConfig) -> Result<Ti1Frame, Ti1ParseError> {
    let line = line.trim();

    // Look for ⟦TI1 ... ⟧ delimiter
    if !line.starts_with(TI1_OPEN) {
        return Err(Ti1ParseError::NotTi1Frame);
    }

    let after_open = &line[TI1_OPEN.len_utf8()..];

    // Must start with "TI1 "
    if !after_open.starts_with(TI1_PREFIX) {
        return Err(Ti1ParseError::NotTi1Frame);
    }

    let after_prefix = &after_open[TI1_PREFIX.len()..];

    // Find closing delimiter
    let Some(close_pos) = after_prefix.find(TI1_CLOSE) else {
        return Err(Ti1ParseError::MalformedFrame {
            reason: "missing closing delimiter".to_string(),
        });
    };

    // Extract nonce (between "TI1 " and ⟧)
    let frame_nonce = &after_prefix[..close_pos];

    // Validate nonce
    if frame_nonce != config.nonce {
        return Err(Ti1ParseError::NonceMismatch {
            expected: config.nonce.clone(),
            found: frame_nonce.to_string(),
        });
    }

    // After closing delimiter, expect: " <request_id> <tool_name> <args_b64url>"
    let payload = after_prefix[close_pos + TI1_CLOSE.len_utf8()..].trim();

    let parts: Vec<&str> = payload.splitn(3, ' ').collect();
    if parts.len() < 3 {
        return Err(Ti1ParseError::MalformedFrame {
            reason: format!(
                "expected 3 fields (request_id tool_name args_b64url), got {}",
                parts.len()
            ),
        });
    }

    let request_id = parts[0];
    let tool_name = parts[1];
    let args_b64url = parts[2];

    let max_b64_len = max_base64_input_len(config.max_args_size);
    if args_b64url.len() > max_b64_len {
        return Err(Ti1ParseError::ArgsBase64TooLarge {
            encoded_size: args_b64url.len(),
            max_encoded_size: max_b64_len,
            max_decoded_size: config.max_args_size,
        });
    }

    // Decode base64url args
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let decoded_bytes = engine
        .decode(args_b64url)
        .map_err(|e| Ti1ParseError::InvalidBase64 {
            reason: e.to_string(),
        })?;

    // Enforce max_args_size
    if decoded_bytes.len() > config.max_args_size {
        return Err(Ti1ParseError::ArgsTooLarge {
            decoded_size: decoded_bytes.len(),
            max_size: config.max_args_size,
        });
    }

    // Parse JSON
    let args: serde_json::Value =
        serde_json::from_slice(&decoded_bytes).map_err(|e| Ti1ParseError::InvalidJson {
            reason: e.to_string(),
        })?;

    Ok(Ti1Frame {
        request_id: request_id.to_string(),
        tool_name: tool_name.to_string(),
        args,
    })
}

/// Convert a parsed TI1 frame to a `HarnessEvent::ToolRequest`.
#[must_use]
pub fn frame_to_harness_event(frame: &Ti1Frame) -> HarnessEvent {
    HarnessEvent::tool_request(&frame.request_id, &frame.tool_name, frame.args.clone())
}

/// Scan a chunk of PTY output (possibly multiple lines) for TI1 frames.
///
/// Returns a list of parsed frames and preserves opaque lines for logging.
/// Non-matching lines are not interpreted (Markov blanket preserved).
pub fn scan_output(
    chunk: &[u8],
    config: &Ti1ScannerConfig,
    line_buffer: &mut String,
) -> Vec<Result<Ti1Frame, Ti1ParseError>> {
    let text = String::from_utf8_lossy(chunk);
    let mut results = Vec::new();

    for piece in text.split_inclusive('\n') {
        let has_newline = piece.ends_with('\n');
        let line_fragment = if has_newline {
            &piece[..piece.len() - 1]
        } else {
            piece
        };

        if line_buffer.len() + line_fragment.len() > MAX_LINE_LENGTH {
            let attempted_len = line_buffer.len().saturating_add(line_fragment.len());
            results.push(Err(Ti1ParseError::LineTooLong {
                line_length: attempted_len,
                max_size: MAX_LINE_LENGTH,
            }));

            // Terminate the overlong line and start fresh from the current
            // fragment when it is representable within bounds.
            line_buffer.clear();
            if line_fragment.len() <= MAX_LINE_LENGTH {
                line_buffer.push_str(line_fragment);
            }
        } else {
            line_buffer.push_str(line_fragment);
        }

        if has_newline {
            let line = std::mem::take(line_buffer);
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            match parse_ti1_line(trimmed, config) {
                Ok(frame) => results.push(Ok(frame)),
                Err(Ti1ParseError::NotTi1Frame) => {
                    // Opaque agent output -- Markov blanket preserved.
                    // Not an error; just not a TI1 frame.
                },
                Err(e) => results.push(Err(e)),
            }
        }
    }

    results
}

// =============================================================================
// TI1 Preamble Generation
// =============================================================================

/// Generate the TI1 system prompt preamble to teach the agent the TI1 grammar.
///
/// This preamble is prepended to the agent's prompt at spawn time so the agent
/// emits `⟦TI1 <nonce>⟧` frames instead of using native tool calls.
#[must_use]
pub fn generate_ti1_preamble(
    nonce: &str,
    capability_map: &std::collections::BTreeMap<String, String>,
) -> String {
    let tool_listing = capability_map
        .iter()
        .map(|(tool_name, kernel_class)| format!("{tool_name}:{kernel_class}"))
        .collect::<Vec<_>>()
        .join(", ");

    format!(
        "TOOL PROTOCOL: use only delimiter-framed tool requests. \
         Request format: {TI1_OPEN}TI1 {nonce}{TI1_CLOSE} <request_id> <tool_name> <args_b64url>. \
         Args MUST be base64url(JSON). \
         Allowed tool names: [{tool_listing}]. \
         Response format: {TI1_OPEN}TR1 {nonce}{TI1_CLOSE} <request_id> ok <cas_result_hash> \
         or {TI1_OPEN}TR1 {nonce}{TI1_CLOSE} <request_id> denied <reason_code>. \
         Wait for each TR1 response before continuing. "
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> Ti1ScannerConfig {
        Ti1ScannerConfig {
            nonce: "abc123def456".to_string(),
            max_args_size: 1024 * 1024, // 1 MB
        }
    }

    fn encode_args(json: &serde_json::Value) -> String {
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        engine.encode(serde_json::to_vec(json).unwrap())
    }

    // =========================================================================
    // Nonce computation tests
    // =========================================================================

    #[test]
    fn test_compute_nonce_deterministic() {
        let n1 = compute_nonce("codex", "ep-001", 1_234_567_890);
        let n2 = compute_nonce("codex", "ep-001", 1_234_567_890);
        assert_eq!(n1, n2, "nonce must be deterministic");
    }

    #[test]
    fn test_compute_nonce_varies_with_inputs() {
        let n1 = compute_nonce("codex", "ep-001", 1_234_567_890);
        let n2 = compute_nonce("codex", "ep-002", 1_234_567_890);
        let n3 = compute_nonce("codex", "ep-001", 9_999_999_999);
        let n4 = compute_nonce("other", "ep-001", 1_234_567_890);

        assert_ne!(
            n1, n2,
            "different episode_id should produce different nonce"
        );
        assert_ne!(
            n1, n3,
            "different spawn_time should produce different nonce"
        );
        assert_ne!(n1, n4, "different prefix should produce different nonce");
    }

    #[test]
    fn test_compute_nonce_length() {
        let nonce = compute_nonce("codex", "ep-001", 1_000_000);
        // 8 bytes = 16 hex chars
        assert_eq!(nonce.len(), 16, "nonce should be 16 hex chars");
        assert!(
            nonce.chars().all(|c| c.is_ascii_hexdigit()),
            "nonce should be hex-encoded"
        );
    }

    // =========================================================================
    // TI1 frame parsing tests
    // =========================================================================

    #[test]
    fn test_parse_valid_ti1_frame() {
        let config = test_config();
        let args = serde_json::json!({"path": "/tmp/test.txt"});
        let args_b64 = encode_args(&args);
        let line = format!(
            "\u{27E6}TI1 {}\u{27E7} req-001 read_file {}",
            config.nonce, args_b64
        );

        let result = parse_ti1_line(&line, &config);
        assert!(result.is_ok(), "valid TI1 frame should parse: {result:?}");

        let frame = result.unwrap();
        assert_eq!(frame.request_id, "req-001");
        assert_eq!(frame.tool_name, "read_file");
        assert_eq!(frame.args, args);
    }

    #[test]
    fn test_parse_opaque_output_returns_not_ti1() {
        let config = test_config();
        let line = "Thinking about the problem...";
        let result = parse_ti1_line(line, &config);
        assert!(
            matches!(result, Err(Ti1ParseError::NotTi1Frame)),
            "opaque output should return NotTi1Frame"
        );
    }

    #[test]
    fn test_parse_empty_line() {
        let config = test_config();
        let result = parse_ti1_line("", &config);
        assert!(matches!(result, Err(Ti1ParseError::NotTi1Frame)));
    }

    #[test]
    fn test_parse_embedded_delimiter_is_opaque() {
        let config = test_config();
        let args = serde_json::json!({});
        let args_b64 = encode_args(&args);
        let line = format!(
            "prefix text \u{27E6}TI1 {}\u{27E7} req-001 read_file {}",
            config.nonce, args_b64
        );

        let result = parse_ti1_line(&line, &config);
        assert!(matches!(result, Err(Ti1ParseError::NotTi1Frame)));
    }

    #[test]
    fn test_parse_nonce_mismatch() {
        let config = test_config();
        let args = serde_json::json!({});
        let args_b64 = encode_args(&args);
        let line = format!("\u{27E6}TI1 wrong_nonce\u{27E7} req-001 read_file {args_b64}");

        let result = parse_ti1_line(&line, &config);
        assert!(
            matches!(result, Err(Ti1ParseError::NonceMismatch { .. })),
            "wrong nonce should be rejected: {result:?}"
        );
    }

    #[test]
    fn test_parse_missing_close_delimiter() {
        let config = test_config();
        let line = format!("\u{27E6}TI1 {} req-001 read_file abc", config.nonce);

        let result = parse_ti1_line(&line, &config);
        assert!(
            matches!(result, Err(Ti1ParseError::MalformedFrame { .. })),
            "missing close delimiter should fail: {result:?}"
        );
    }

    #[test]
    fn test_parse_missing_fields() {
        let config = test_config();
        // Only request_id, no tool_name or args
        let line = format!("\u{27E6}TI1 {}\u{27E7} req-001", config.nonce);

        let result = parse_ti1_line(&line, &config);
        assert!(
            matches!(result, Err(Ti1ParseError::MalformedFrame { .. })),
            "missing fields should fail: {result:?}"
        );
    }

    #[test]
    fn test_parse_args_too_large() {
        let config = Ti1ScannerConfig {
            nonce: "abc123def456".to_string(),
            max_args_size: 10, // Very small limit
        };
        // Keep encoded length under the pre-decode cap while decoded JSON still
        // exceeds max_args_size to exercise the post-decode bound.
        let args = serde_json::json!({"a": 12345});
        let args_b64 = encode_args(&args);
        let line = format!(
            "\u{27E6}TI1 {}\u{27E7} req-001 read_file {}",
            config.nonce, args_b64
        );

        let result = parse_ti1_line(&line, &config);
        assert!(
            matches!(result, Err(Ti1ParseError::ArgsTooLarge { .. })),
            "oversized args should fail: {result:?}"
        );
    }

    #[test]
    fn test_parse_invalid_base64() {
        let config = test_config();
        let line = format!(
            "\u{27E6}TI1 {}\u{27E7} req-001 read_file !!!not-base64!!!",
            config.nonce
        );

        let result = parse_ti1_line(&line, &config);
        assert!(
            matches!(result, Err(Ti1ParseError::InvalidBase64 { .. })),
            "invalid base64 should fail: {result:?}"
        );
    }

    #[test]
    fn test_parse_invalid_json() {
        let config = test_config();
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let args_b64 = engine.encode(b"not json");
        let line = format!(
            "\u{27E6}TI1 {}\u{27E7} req-001 read_file {}",
            config.nonce, args_b64
        );

        let result = parse_ti1_line(&line, &config);
        assert!(
            matches!(result, Err(Ti1ParseError::InvalidJson { .. })),
            "invalid JSON should fail: {result:?}"
        );
    }

    #[test]
    fn test_parse_rejects_oversized_base64_before_decode() {
        let config = Ti1ScannerConfig {
            nonce: "abc123def456".to_string(),
            max_args_size: 12,
        };
        let max_encoded_len = max_base64_input_len(config.max_args_size);
        let oversized_b64 = "A".repeat(max_encoded_len + 1);
        let line = format!(
            "\u{27E6}TI1 {}\u{27E7} req-001 read_file {}",
            config.nonce, oversized_b64
        );

        let result = parse_ti1_line(&line, &config);
        assert!(
            matches!(result, Err(Ti1ParseError::ArgsBase64TooLarge { .. })),
            "oversized base64 should fail pre-decode: {result:?}"
        );
    }

    // =========================================================================
    // TR1 response formatting tests
    // =========================================================================

    #[test]
    fn test_format_tr1_response() {
        let response = format_tr1_response("abc123", "req-001", "deadbeef");
        assert_eq!(response, "\u{27E6}TR1 abc123\u{27E7} req-001 ok deadbeef\n");
    }

    #[test]
    fn test_format_tr1_denial() {
        let response = format_tr1_denial("abc123", "req-001", "POLICY_DENIED");
        assert_eq!(
            response,
            "\u{27E6}TR1 abc123\u{27E7} req-001 denied POLICY_DENIED\n"
        );
    }

    // =========================================================================
    // Scan output tests (mixed opaque + TI1 lines)
    // =========================================================================

    #[test]
    fn test_scan_mixed_output() {
        let config = test_config();
        let args = serde_json::json!({"path": "/tmp/file.txt"});
        let args_b64 = encode_args(&args);

        let chunk = format!(
            "Thinking about the problem...\n\
             Some more agent reasoning\n\
             \u{27E6}TI1 {}\u{27E7} req-001 read_file {}\n\
             More opaque output\n",
            config.nonce, args_b64
        );

        let mut line_buf = String::new();
        let results = scan_output(chunk.as_bytes(), &config, &mut line_buf);

        // Should have exactly 1 successful TI1 frame; opaque lines are ignored
        assert_eq!(results.len(), 1, "expected 1 TI1 frame, got: {results:?}");
        let frame = results[0].as_ref().unwrap();
        assert_eq!(frame.request_id, "req-001");
        assert_eq!(frame.tool_name, "read_file");
        assert_eq!(frame.args, args);
    }

    #[test]
    fn test_scan_no_ti1_frames() {
        let config = test_config();
        let chunk = b"Just normal agent output\nMore output\n";
        let mut line_buf = String::new();
        let results = scan_output(chunk, &config, &mut line_buf);
        assert!(results.is_empty(), "no TI1 frames expected");
    }

    #[test]
    fn test_scan_partial_line_buffered() {
        let config = test_config();
        let args = serde_json::json!({});
        let args_b64 = encode_args(&args);
        let full_line = format!(
            "\u{27E6}TI1 {}\u{27E7} req-001 read_file {}",
            config.nonce, args_b64
        );

        // Send first half without newline
        let first_half = &full_line[..full_line.len() / 2];
        let mut line_buf = String::new();
        let results = scan_output(first_half.as_bytes(), &config, &mut line_buf);
        assert!(results.is_empty(), "partial line should not emit frame");

        // Send second half with newline
        let second_half = format!("{}\n", &full_line[full_line.len() / 2..]);
        let results = scan_output(second_half.as_bytes(), &config, &mut line_buf);
        assert_eq!(results.len(), 1, "completed line should emit frame");
        assert!(results[0].is_ok());
    }

    #[test]
    fn test_scan_long_line_without_newline_triggers_limit() {
        let config = test_config();
        let chunk = vec![b'x'; MAX_LINE_LENGTH + 1];
        let mut line_buf = String::new();

        let results = scan_output(&chunk, &config, &mut line_buf);
        assert!(
            matches!(
                results.as_slice(),
                [Err(Ti1ParseError::LineTooLong {
                    line_length: _,
                    max_size: MAX_LINE_LENGTH
                })]
            ),
            "oversized line should trigger scanner bound: {results:?}"
        );
        assert!(
            line_buf.is_empty(),
            "scanner should not retain oversized unterminated line"
        );
    }

    // =========================================================================
    // Frame to HarnessEvent conversion
    // =========================================================================

    #[test]
    fn test_frame_to_harness_event() {
        let frame = Ti1Frame {
            request_id: "req-042".to_string(),
            tool_name: "write_file".to_string(),
            args: serde_json::json!({"path": "/tmp/out.txt", "content": "hello"}),
        };

        let event = frame_to_harness_event(&frame);
        match event {
            HarnessEvent::ToolRequest {
                request_id,
                tool,
                args,
            } => {
                assert_eq!(request_id, "req-042");
                assert_eq!(tool, "write_file");
                assert_eq!(args["path"], "/tmp/out.txt");
            },
            _ => panic!("expected ToolRequest event"),
        }
    }

    // =========================================================================
    // TI1 preamble generation
    // =========================================================================

    #[test]
    fn test_generate_ti1_preamble() {
        let mut cap_map = std::collections::BTreeMap::new();
        cap_map.insert("read_file".to_string(), "kernel.fs.read".to_string());
        cap_map.insert("write_file".to_string(), "kernel.fs.write".to_string());

        let preamble = generate_ti1_preamble("test_nonce", &cap_map);
        assert!(preamble.contains("TI1"));
        assert!(preamble.contains("test_nonce"));
        assert!(preamble.contains("read_file"));
        assert!(preamble.contains("write_file"));
        assert!(preamble.contains("kernel.fs.read"));
        assert!(preamble.contains("base64url"));
    }

    // =========================================================================
    // Ti1ParseError display
    // =========================================================================

    #[test]
    fn test_error_display() {
        let e = Ti1ParseError::NotTi1Frame;
        assert_eq!(e.to_string(), "not a TI1 frame");

        let e = Ti1ParseError::NonceMismatch {
            expected: "aaa".to_string(),
            found: "bbb".to_string(),
        };
        assert!(e.to_string().contains("aaa"));
        assert!(e.to_string().contains("bbb"));

        let e = Ti1ParseError::ArgsTooLarge {
            decoded_size: 2_000_000,
            max_size: 1_000_000,
        };
        assert!(e.to_string().contains("2000000"));
        assert!(e.to_string().contains("1000000"));

        let e = Ti1ParseError::LineTooLong {
            line_length: MAX_LINE_LENGTH + 1,
            max_size: MAX_LINE_LENGTH,
        };
        assert!(e.to_string().contains("line too long"));
    }
}
