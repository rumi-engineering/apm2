//! Parser for Claude Code PTY output.
//!
//! This module implements a deterministic state machine parser for extracting
//! structured events from Claude Code CLI output, per AD-ADAPT-001.
//!
//! # Design
//!
//! The parser operates as a streaming state machine that:
//! - Strips ANSI escape sequences from PTY output
//! - Detects tool call markers in the output stream
//! - Emits [`HarnessEvent::ToolRequest`] when tool calls are detected
//! - Handles partial UTF-8 and malformed input gracefully
//!
//! # Tool Call Detection
//!
//! Claude Code emits tool calls in a JSON format within the PTY output.
//! The parser detects these by looking for the characteristic JSON structure
//! containing tool invocations with name and arguments.
//!
//! # Rate Limiting
//!
//! Per TB-ADAPTER-001, the parser enforces rate limiting on tool request
//! extraction to prevent `DoS` via rapid tool markers. Default: 10
//! requests/sec.
//!
//! # Invariants
//!
//! - [INV-CP001] Parsing failures emit defects, never crash
//! - [INV-CP002] Output is sanitized (ANSI stripped) before parsing
//! - [INV-CP003] Partial UTF-8 sequences are buffered until complete
//! - [INV-CP004] Tool call extraction is rate-limited
//!
//! # Contract References
//!
//! - AD-ADAPT-001: `HarnessAdapter` implements Holon trait
//! - TB-ADAPTER-001: ANSI sanitization and rate limiting

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::adapter::HarnessEvent;

// ============================================================================
// Constants
// ============================================================================

/// Maximum buffer size for accumulating partial tool call data (64 KB).
///
/// Per CTR-1601 (Bounded Reads), we limit the buffer size to prevent
/// memory exhaustion from malformed input that never completes a tool call.
pub const MAX_BUFFER_SIZE: usize = 65536;

/// Maximum length of a tool name (256 chars).
pub const MAX_TOOL_NAME_LEN: usize = 256;

/// Maximum size of inline tool arguments (64 KB).
///
/// Larger arguments should be stored in CAS and referenced by hash.
pub const MAX_TOOL_ARGS_SIZE: usize = 65536;

/// Default rate limit for tool request extraction (requests per second).
pub const DEFAULT_RATE_LIMIT_PER_SEC: u32 = 10;

/// Size of the rate limit sliding window.
const RATE_LIMIT_WINDOW_SIZE: usize = 100;

// XML-style patterns are handled in try_parse_xml_tool_call via string search.
// These constants are kept for documentation but may be used in future
// versions.
#[allow(dead_code)]
const INVOKE_START_PATTERN: &str = "invoke name=\"";
#[allow(dead_code)]
const PARAM_START_PATTERN: &str = "parameter name=\"";

// ============================================================================
// Parser State
// ============================================================================

/// Parser state for the Claude Code output state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ParserState {
    /// Idle state, waiting for tool call markers.
    #[default]
    Idle,

    /// Inside a tool call block, accumulating data.
    InToolCall,

    /// Parsing tool invocation details.
    InInvoke,

    /// Parsing parameter value.
    InParameter,
}

/// A parsed tool invocation from Claude Code output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedToolCall {
    /// Tool name being invoked.
    pub tool_name: String,

    /// Tool arguments as key-value pairs.
    pub arguments: serde_json::Map<String, serde_json::Value>,

    /// Generated request ID for correlation.
    pub request_id: String,
}

/// Defect record for parsing failures.
///
/// Per INV-CP001, parsing failures emit defects rather than crashing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParserDefect {
    /// Description of the defect.
    pub description: String,

    /// Raw data that caused the defect (truncated).
    pub context: String,

    /// Byte offset where the defect occurred.
    pub offset: usize,
}

impl ParserDefect {
    /// Create a new parser defect.
    fn new(description: impl Into<String>, context: &[u8], offset: usize) -> Self {
        // Truncate context to avoid huge defect records
        let context_str = String::from_utf8_lossy(&context[..context.len().min(256)]);
        Self {
            description: description.into(),
            context: context_str.into_owned(),
            offset,
        }
    }
}

/// Result of parsing a chunk of PTY output.
#[derive(Debug, Clone)]
pub struct ParseResult {
    /// Tool calls extracted from the output.
    pub tool_calls: Vec<ParsedToolCall>,

    /// Defects encountered during parsing.
    pub defects: Vec<ParserDefect>,

    /// Sanitized output with ANSI codes stripped.
    pub sanitized_output: Vec<u8>,
}

impl ParseResult {
    /// Create an empty parse result.
    #[allow(dead_code)]
    #[allow(clippy::missing_const_for_fn)]
    #[must_use]
    pub fn empty() -> Self {
        Self {
            tool_calls: Vec::new(),
            defects: Vec::new(),
            sanitized_output: Vec::new(),
        }
    }

    /// Check if the result has any tool calls.
    #[must_use]
    pub fn has_tool_calls(&self) -> bool {
        !self.tool_calls.is_empty()
    }

    /// Check if the result has any defects.
    #[must_use]
    pub fn has_defects(&self) -> bool {
        !self.defects.is_empty()
    }
}

// ============================================================================
// Rate Limiter
// ============================================================================

/// Sliding window rate limiter for tool request extraction.
#[derive(Debug)]
struct RateLimiter {
    /// Timestamps of recent requests within the window.
    window: VecDeque<Instant>,

    /// Maximum requests per second.
    max_per_sec: u32,

    /// Window duration (1 second by default).
    window_duration: Duration,
}

impl RateLimiter {
    /// Create a new rate limiter.
    fn new(max_per_sec: u32) -> Self {
        Self {
            window: VecDeque::with_capacity(RATE_LIMIT_WINDOW_SIZE),
            max_per_sec,
            window_duration: Duration::from_secs(1),
        }
    }

    /// Check if a request is allowed and record it if so.
    fn check_and_record(&mut self) -> bool {
        let now = Instant::now();
        let cutoff = now.checked_sub(self.window_duration).unwrap_or(now);

        // Remove expired entries
        while self
            .window
            .front()
            .is_some_and(|&timestamp| timestamp < cutoff)
        {
            self.window.pop_front();
        }

        // Check if under limit
        if self.window.len() < self.max_per_sec as usize {
            self.window.push_back(now);
            true
        } else {
            false
        }
    }

    /// Reset the rate limiter.
    fn reset(&mut self) {
        self.window.clear();
    }
}

// ============================================================================
// ANSI Escape Sequence Stripper
// ============================================================================

/// Strip ANSI escape sequences from a byte slice.
///
/// Per INV-CP002, output is sanitized before parsing. This function removes:
/// - CSI sequences: ESC `[` ... `final_byte`
/// - OSC sequences: ESC `]` ... ST
/// - Simple escape sequences: ESC char
///
/// # Arguments
///
/// * `input` - Raw PTY output bytes
///
/// # Returns
///
/// Sanitized output with ANSI codes removed.
pub fn strip_ansi(input: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len());
    let mut i = 0;

    while i < input.len() {
        // Check for ESC character (0x1B)
        if input[i] == 0x1B {
            // Look for CSI sequence: ESC [
            if i + 1 < input.len() && input[i + 1] == b'[' {
                // Skip CSI sequence until final byte (0x40-0x7E)
                i += 2;
                while i < input.len() && !(0x40..=0x7E).contains(&input[i]) {
                    i += 1;
                }
                if i < input.len() {
                    i += 1; // Skip final byte
                }
                continue;
            }

            // Look for OSC sequence: ESC ]
            if i + 1 < input.len() && input[i + 1] == b']' {
                i += 2;
                // Skip until ST (ESC \) or BEL (0x07)
                while i < input.len() {
                    if input[i] == 0x07 {
                        i += 1;
                        break;
                    }
                    if input[i] == 0x1B && i + 1 < input.len() && input[i + 1] == b'\\' {
                        i += 2;
                        break;
                    }
                    i += 1;
                }
                continue;
            }

            // Simple escape sequence: ESC char
            if i + 1 < input.len() {
                i += 2;
                continue;
            }
        }

        // Regular character - keep it
        output.push(input[i]);
        i += 1;
    }

    output
}

// ============================================================================
// Claude Code Parser
// ============================================================================

/// Parser for Claude Code PTY output.
///
/// Implements a deterministic state machine for extracting tool calls from
/// the PTY output stream. The parser:
///
/// - Strips ANSI escape sequences
/// - Detects tool invocation patterns
/// - Extracts tool names and arguments
/// - Emits structured `HarnessEvent::ToolRequest` events
/// - Records defects for malformed input (never crashes)
///
/// # Example
///
/// ```rust,ignore
/// use apm2_daemon::episode::claude_parser::ClaudeCodeParser;
///
/// let mut parser = ClaudeCodeParser::new();
///
/// // Parse PTY output chunks as they arrive
/// let result = parser.parse(b"some output...");
///
/// for tool_call in result.tool_calls {
///     println!("Tool: {} with args: {:?}", tool_call.tool_name, tool_call.arguments);
/// }
/// ```
#[derive(Debug)]
pub struct ClaudeCodeParser {
    /// Current parser state.
    state: ParserState,

    /// Buffer for accumulating partial data.
    buffer: Vec<u8>,

    /// Rate limiter for tool request extraction.
    rate_limiter: RateLimiter,

    /// Counter for generating request IDs.
    request_counter: u64,

    /// Total bytes processed.
    bytes_processed: u64,

    /// Current tool name being parsed.
    current_tool_name: Option<String>,

    /// Current parameter name being parsed.
    current_param_name: Option<String>,

    /// Current tool arguments being accumulated.
    current_args: serde_json::Map<String, serde_json::Value>,
}

impl Default for ClaudeCodeParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ClaudeCodeParser {
    /// Create a new parser with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::with_rate_limit(DEFAULT_RATE_LIMIT_PER_SEC)
    }

    /// Create a new parser with a custom rate limit.
    #[must_use]
    pub fn with_rate_limit(max_per_sec: u32) -> Self {
        Self {
            state: ParserState::Idle,
            buffer: Vec::with_capacity(4096),
            rate_limiter: RateLimiter::new(max_per_sec),
            request_counter: 0,
            bytes_processed: 0,
            current_tool_name: None,
            current_param_name: None,
            current_args: serde_json::Map::new(),
        }
    }

    /// Parse a chunk of PTY output.
    ///
    /// This is the main entry point for parsing. Call this method with each
    /// chunk of PTY output as it arrives. The parser maintains internal state
    /// across calls to handle partial tool calls spanning multiple chunks.
    ///
    /// # Arguments
    ///
    /// * `chunk` - Raw PTY output bytes
    ///
    /// # Returns
    ///
    /// A [`ParseResult`] containing extracted tool calls, defects, and
    /// sanitized output.
    pub fn parse(&mut self, chunk: &[u8]) -> ParseResult {
        // Sanitize ANSI escape sequences
        let sanitized = strip_ansi(chunk);

        let mut result = ParseResult {
            tool_calls: Vec::new(),
            defects: Vec::new(),
            sanitized_output: sanitized.clone(),
        };

        // Update bytes processed
        self.bytes_processed = self.bytes_processed.saturating_add(chunk.len() as u64);

        // Append to buffer
        self.buffer.extend_from_slice(&sanitized);

        // Check buffer size limit (CTR-1601)
        if self.buffer.len() > MAX_BUFFER_SIZE {
            #[allow(clippy::cast_possible_truncation)]
            let offset = self.bytes_processed as usize;
            result.defects.push(ParserDefect::new(
                "buffer overflow: tool call data exceeds maximum size",
                &self.buffer,
                offset,
            ));
            self.reset_state();
            return result;
        }

        // Process buffer for tool calls
        self.process_buffer(&mut result);

        result
    }

    /// Process the internal buffer looking for tool call patterns.
    fn process_buffer(&mut self, result: &mut ParseResult) {
        // Convert buffer to owned String to avoid borrow issues
        // Use lossy conversion to handle partial UTF-8
        let buffer_str = String::from_utf8_lossy(&self.buffer).into_owned();

        // Look for invoke patterns
        // Pattern: <invoke name="ToolName">
        // Note: We search for a simplified pattern to avoid XML parsing complexity

        // Find JSON-style tool calls (alternative format)
        // Pattern: {"tool": "name", "args": {...}}
        if let Some(tool_call) = self.try_parse_json_tool_call(&buffer_str) {
            if self.rate_limiter.check_and_record() {
                result.tool_calls.push(tool_call);
            } else {
                #[allow(clippy::cast_possible_truncation)]
                let offset = self.bytes_processed as usize;
                result.defects.push(ParserDefect::new(
                    "rate limit exceeded for tool request extraction",
                    self.buffer.as_slice(),
                    offset,
                ));
            }
            // Clear buffer after successful parse
            self.buffer.clear();
            return;
        }

        // Look for XML-style invoke patterns
        if let Some(tool_call) = self.try_parse_xml_tool_call(&buffer_str) {
            if self.rate_limiter.check_and_record() {
                result.tool_calls.push(tool_call);
            } else {
                #[allow(clippy::cast_possible_truncation)]
                let offset = self.bytes_processed as usize;
                result.defects.push(ParserDefect::new(
                    "rate limit exceeded for tool request extraction",
                    self.buffer.as_slice(),
                    offset,
                ));
            }
            // Clear buffer after successful parse
            self.buffer.clear();
            return;
        }

        // If buffer is getting large and no patterns found, trim old data
        // Keep only recent data that might contain partial patterns
        if self.buffer.len() > MAX_BUFFER_SIZE / 2 {
            let trim_point = self.buffer.len() - (MAX_BUFFER_SIZE / 4);
            self.buffer.drain(..trim_point);
        }
    }

    /// Try to parse a JSON-style tool call from the buffer.
    fn try_parse_json_tool_call(&mut self, buffer: &str) -> Option<ParsedToolCall> {
        // Look for JSON object with "tool" and "args" keys
        // Example: {"tool": "Read", "args": {"path": "/tmp/test.txt"}}

        // Find potential JSON objects
        let mut depth = 0;
        let mut start = None;

        for (i, c) in buffer.char_indices() {
            match c {
                '{' => {
                    if depth == 0 {
                        start = Some(i);
                    }
                    depth += 1;
                },
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        if let Some(s) = start {
                            let json_str = &buffer[s..=i];
                            if let Ok(value) = serde_json::from_str::<serde_json::Value>(json_str) {
                                if let Some(tool_call) = self.extract_tool_from_json(&value) {
                                    return Some(tool_call);
                                }
                            }
                        }
                        start = None;
                    }
                },
                _ => {},
            }
        }

        None
    }

    /// Extract a tool call from a JSON value.
    fn extract_tool_from_json(&mut self, value: &serde_json::Value) -> Option<ParsedToolCall> {
        let obj = value.as_object()?;

        // Look for "tool" or "name" field
        let tool_name = obj
            .get("tool")
            .or_else(|| obj.get("name"))
            .and_then(|v| v.as_str())?;

        // Validate tool name length
        if tool_name.len() > MAX_TOOL_NAME_LEN {
            return None;
        }

        // Look for "args" or "arguments" or "parameters" field
        let args = obj
            .get("args")
            .or_else(|| obj.get("arguments"))
            .or_else(|| obj.get("parameters"))
            .cloned()
            .unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new()));

        // Validate args size
        let args_str = serde_json::to_string(&args).unwrap_or_default();
        if args_str.len() > MAX_TOOL_ARGS_SIZE {
            return None;
        }

        let arguments = match args {
            serde_json::Value::Object(map) => map,
            _ => serde_json::Map::new(),
        };

        self.request_counter += 1;
        let request_id = format!("claude-{}", self.request_counter);

        Some(ParsedToolCall {
            tool_name: tool_name.to_string(),
            arguments,
            request_id,
        })
    }

    /// Try to parse an XML-style tool call from the buffer.
    ///
    /// This parses the XML-like format that Claude Code uses for tool
    /// invocations. The format uses invoke and parameter tags with name
    /// attributes.
    fn try_parse_xml_tool_call(&mut self, buffer: &str) -> Option<ParsedToolCall> {
        // Use regex-like pattern matching for XML invoke blocks
        // We look for: invoke name="..." followed by parameter tags

        // Find invoke tag with name attribute
        let invoke_start = "invoke name=\"";
        let invoke_pos = buffer.find(invoke_start)?;
        let name_start = invoke_pos + invoke_start.len();

        // Find end of tool name (closing quote)
        let remaining = &buffer[name_start..];
        let name_end = remaining.find('"')?;
        let tool_name = &remaining[..name_end];

        // Validate tool name
        if tool_name.is_empty() || tool_name.len() > MAX_TOOL_NAME_LEN {
            return None;
        }

        // Find invoke closing tag
        let invoke_close = "/invoke>";
        if !buffer[name_start..].contains(invoke_close) {
            // Incomplete invoke block, wait for more data
            return None;
        }

        // Extract parameters between invoke open and close
        let mut arguments = serde_json::Map::new();
        let param_start_pattern = "parameter name=\"";

        let mut search_start = name_start;
        while let Some(param_pos) = buffer[search_start..].find(param_start_pattern) {
            let abs_param_pos = search_start + param_pos;
            let param_name_start = abs_param_pos + param_start_pattern.len();

            // Find parameter name end
            if let Some(param_name_end) = buffer[param_name_start..].find('"') {
                let param_name = &buffer[param_name_start..param_name_start + param_name_end];

                // Find parameter value (after the >)
                let value_start_pos = param_name_start + param_name_end + 2; // Skip ">
                if value_start_pos < buffer.len() {
                    // Find parameter closing tag
                    let param_close = "/parameter>";
                    if let Some(value_end) = buffer[value_start_pos..].find(param_close) {
                        // Handle the closing tag format (may include <)
                        let mut value = &buffer[value_start_pos..value_start_pos + value_end];
                        // Trim trailing < if present
                        if value.ends_with('<') {
                            value = &value[..value.len() - 1];
                        }

                        // Validate size
                        if value.len() <= MAX_TOOL_ARGS_SIZE {
                            arguments.insert(
                                param_name.to_string(),
                                serde_json::Value::String(value.to_string()),
                            );
                        }

                        search_start = value_start_pos + value_end;
                        continue;
                    }
                }
            }
            break;
        }

        self.request_counter += 1;
        let request_id = format!("claude-{}", self.request_counter);

        Some(ParsedToolCall {
            tool_name: tool_name.to_string(),
            arguments,
            request_id,
        })
    }

    /// Reset the parser state.
    ///
    /// Called when an error occurs or when explicitly resetting between
    /// episodes.
    pub fn reset_state(&mut self) {
        self.state = ParserState::Idle;
        self.buffer.clear();
        self.current_tool_name = None;
        self.current_param_name = None;
        self.current_args.clear();
    }

    /// Reset the parser completely, including counters.
    pub fn reset(&mut self) {
        self.reset_state();
        self.rate_limiter.reset();
        self.request_counter = 0;
        self.bytes_processed = 0;
    }

    /// Returns the current parser state.
    #[must_use]
    pub const fn state(&self) -> ParserState {
        self.state
    }

    /// Returns the number of bytes processed.
    #[must_use]
    pub const fn bytes_processed(&self) -> u64 {
        self.bytes_processed
    }

    /// Returns the number of tool calls parsed.
    #[must_use]
    pub const fn request_count(&self) -> u64 {
        self.request_counter
    }

    /// Convert a parsed tool call to a [`HarnessEvent`].
    #[must_use]
    pub fn to_harness_event(tool_call: &ParsedToolCall) -> HarnessEvent {
        HarnessEvent::tool_request(
            &tool_call.request_id,
            &tool_call.tool_name,
            serde_json::Value::Object(tool_call.arguments.clone()),
        )
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_ansi_basic() {
        // Test stripping CSI sequences
        let input = b"\x1b[31mred text\x1b[0m";
        let output = strip_ansi(input);
        assert_eq!(output, b"red text");
    }

    #[test]
    fn test_strip_ansi_complex() {
        // Multiple sequences
        let input = b"\x1b[1;32mgreen bold\x1b[0m normal \x1b[4munderline\x1b[0m";
        let output = strip_ansi(input);
        assert_eq!(output, b"green bold normal underline");
    }

    #[test]
    fn test_strip_ansi_osc() {
        // OSC sequence (title setting)
        let input = b"\x1b]0;window title\x07rest of text";
        let output = strip_ansi(input);
        assert_eq!(output, b"rest of text");
    }

    #[test]
    fn test_strip_ansi_preserves_text() {
        let input = b"plain text without escapes";
        let output = strip_ansi(input);
        assert_eq!(output, input.to_vec());
    }

    #[test]
    fn test_parser_new() {
        let parser = ClaudeCodeParser::new();
        assert_eq!(parser.state(), ParserState::Idle);
        assert_eq!(parser.bytes_processed(), 0);
        assert_eq!(parser.request_count(), 0);
    }

    #[test]
    fn test_parser_json_tool_call() {
        let mut parser = ClaudeCodeParser::new();

        let input =
            br#"Some output {"tool": "Read", "args": {"path": "/tmp/test.txt"}} more output"#;
        let result = parser.parse(input);

        assert!(result.has_tool_calls());
        assert_eq!(result.tool_calls.len(), 1);
        assert_eq!(result.tool_calls[0].tool_name, "Read");
        assert!(result.tool_calls[0].arguments.contains_key("path"));
    }

    #[test]
    fn test_parser_no_tool_call() {
        let mut parser = ClaudeCodeParser::new();

        let input = b"Regular output without any tool calls";
        let result = parser.parse(input);

        assert!(!result.has_tool_calls());
        assert!(!result.has_defects());
    }

    #[test]
    fn test_parser_buffer_overflow() {
        let mut parser = ClaudeCodeParser::new();

        // Create input larger than MAX_BUFFER_SIZE
        let large_input = vec![b'x'; MAX_BUFFER_SIZE + 1];
        let result = parser.parse(&large_input);

        assert!(result.has_defects());
        assert!(result.defects[0].description.contains("buffer overflow"));
    }

    #[test]
    fn test_parser_rate_limit() {
        let mut parser = ClaudeCodeParser::with_rate_limit(2);

        // Send 3 tool calls rapidly
        for i in 0..3 {
            let input = format!(r#"{{"tool": "Tool{i}", "args": {{}}}}"#);
            let result = parser.parse(input.as_bytes());

            if i < 2 {
                assert!(result.has_tool_calls(), "Tool call {i} should succeed");
            } else {
                // Third call should be rate limited
                assert!(
                    result.has_defects() || !result.has_tool_calls(),
                    "Tool call {i} should be rate limited",
                );
            }
        }
    }

    #[test]
    fn test_parser_tool_name_too_long() {
        let mut parser = ClaudeCodeParser::new();

        let long_name = "x".repeat(MAX_TOOL_NAME_LEN + 1);
        let input = format!(r#"{{"tool": "{long_name}", "args": {{}}}}"#);
        let result = parser.parse(input.as_bytes());

        // Should not parse as tool call due to name length
        assert!(!result.has_tool_calls());
    }

    #[test]
    fn test_parser_reset() {
        let mut parser = ClaudeCodeParser::new();

        // Parse something
        let input = br#"{"tool": "Read", "args": {}}"#;
        let _ = parser.parse(input);

        assert!(parser.request_count() > 0);

        // Reset
        parser.reset();

        assert_eq!(parser.state(), ParserState::Idle);
        assert_eq!(parser.bytes_processed(), 0);
        assert_eq!(parser.request_count(), 0);
    }

    #[test]
    fn test_to_harness_event() {
        let tool_call = ParsedToolCall {
            tool_name: "Read".to_string(),
            arguments: {
                let mut map = serde_json::Map::new();
                map.insert(
                    "path".to_string(),
                    serde_json::Value::String("/tmp/test.txt".to_string()),
                );
                map
            },
            request_id: "claude-1".to_string(),
        };

        let event = ClaudeCodeParser::to_harness_event(&tool_call);

        match event {
            HarnessEvent::ToolRequest {
                request_id,
                tool,
                args,
            } => {
                assert_eq!(request_id, "claude-1");
                assert_eq!(tool, "Read");
                assert!(args.get("path").is_some());
            },
            _ => panic!("Expected ToolRequest event"),
        }
    }

    #[test]
    fn test_parser_defect_context_truncation() {
        let defect = ParserDefect::new(
            "test defect",
            &vec![b'x'; 1000], // Large context
            100,
        );

        // Context should be truncated to 256 bytes
        assert!(defect.context.len() <= 256);
    }

    #[test]
    fn test_parse_result_methods() {
        let mut result = ParseResult::empty();

        assert!(!result.has_tool_calls());
        assert!(!result.has_defects());

        result.tool_calls.push(ParsedToolCall {
            tool_name: "Test".to_string(),
            arguments: serde_json::Map::new(),
            request_id: "test-1".to_string(),
        });

        assert!(result.has_tool_calls());
    }

    #[test]
    fn test_parser_xml_style_tool_call() {
        let mut parser = ClaudeCodeParser::new();

        // Simulated XML-style tool call (simplified)
        let input = br#"Some text invoke name="Read" then parameter name="path">/tmp/test.txt</parameter> more /invoke> done"#;
        let result = parser.parse(input);

        // This should parse the invoke block
        assert!(result.has_tool_calls());
        if !result.tool_calls.is_empty() {
            assert_eq!(result.tool_calls[0].tool_name, "Read");
        }
    }

    #[test]
    fn test_parser_incremental() {
        let mut parser = ClaudeCodeParser::new();

        // Send partial chunks
        let result1 = parser.parse(br#"{"tool": "Re"#);
        assert!(!result1.has_tool_calls());

        let result2 = parser.parse(br#"ad", "args": {}}"#);
        assert!(result2.has_tool_calls());
        assert_eq!(result2.tool_calls[0].tool_name, "Read");
    }
}
