//! Topic grammar and wildcard matching for HEF Pulse Plane (RFC-0018,
//! RFC-0032::REQ-0097).
//!
//! This module implements topic validation and pattern matching for the Holonic
//! Event Fabric (HEF) pulse subscription system. Topics are ASCII,
//! dot-delimited, length-bounded strings with constrained wildcard support.
//!
//! # Topic Grammar
//!
//! Topics follow a strict grammar designed for bounded complexity:
//!
//! ```text
//! topic       ::= segment ("." segment)*
//! segment     ::= 1*ALPHA_NUM     -- for concrete topics
//! pattern     ::= seg_or_wild ("." seg_or_wild)* ["." ">"]
//! seg_or_wild ::= segment | "*"   -- wildcard matches exactly one segment
//! ">"         ::= terminal wildcard, matches zero or more remaining segments
//! ```
//!
//! # Constraints (DD-HEF-0003)
//!
//! - ASCII-only characters (0x00-0x7F)
//! - Dot-delimited segments (`.` separator)
//! - No empty segments
//! - Maximum topic length: 128 characters
//! - Maximum segment count: 16
//! - Maximum wildcards per pattern: 2
//! - `*` matches exactly one segment
//! - `>` is terminal-only and matches remaining segments
//! - No regex patterns allowed
//!
//! # Security Invariants
//!
//! - [INV-HEF-0003] All string IDs are ASCII-only and length-bounded
//! - [INV-HEF-0007] Invalid patterns rejected with reason code
//!   `INVALID_PATTERN`
//! - Bounded matching prevents CPU exhaustion (no backtracking, no regex)
//!
//! # Example
//!
//! ```rust,ignore
//! use apm2_daemon::protocol::pulse_topic::{TopicPattern, validate_topic};
//!
//! // Validate a concrete topic
//! validate_topic("work.W-123.events").expect("valid topic");
//!
//! // Parse and match patterns
//! let pattern = TopicPattern::parse("work.*.events").expect("valid pattern");
//! assert!(pattern.matches("work.W-123.events"));
//! assert!(pattern.matches("work.W-456.events"));
//! assert!(!pattern.matches("work.W-123.other"));
//!
//! // Terminal wildcard
//! let pattern = TopicPattern::parse("episode.EP-001.>").expect("valid pattern");
//! assert!(pattern.matches("episode.EP-001.lifecycle"));
//! assert!(pattern.matches("episode.EP-001.tool.result"));
//! ```

use std::fmt;

// ============================================================================
// Constants (DD-HEF-0003, REQ-HEF-0007)
// ============================================================================

/// Maximum length for a topic string.
/// Per REQ-HEF-0002: "`topic`: max 128 chars"
pub const MAX_TOPIC_LEN: usize = 128;

/// Maximum number of segments in a topic.
/// Per resource governance: bounded complexity.
pub const MAX_SEGMENT_COUNT: usize = 16;

/// Maximum number of wildcards per pattern.
/// Per DD-HEF-0003: "maximum of 2 wildcards per pattern"
pub const MAX_WILDCARDS: usize = 2;

/// Minimum segment length (no empty segments).
pub const MIN_SEGMENT_LEN: usize = 1;

/// Maximum segment length.
/// Per bounded design: single segment cannot exceed total max.
pub const MAX_SEGMENT_LEN: usize = 64;

/// Single-segment wildcard character.
pub const WILDCARD_SINGLE: &str = "*";

/// Terminal wildcard character (matches remaining segments).
pub const WILDCARD_TERMINAL: &str = ">";

/// Segment separator.
pub const SEGMENT_SEPARATOR: char = '.';

// ============================================================================
// Error Types (CTR-0703: Structured Error Types)
// ============================================================================

/// Error type for topic validation failures.
///
/// Per CTR-0703, error types must be structured when callers branch on cause.
/// Each variant includes actionable context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TopicError {
    /// Topic string is empty.
    Empty,

    /// Topic exceeds maximum length.
    TooLong {
        /// Actual length.
        len: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// Topic contains non-ASCII characters.
    NonAscii {
        /// Byte position of first non-ASCII character.
        position: usize,
    },

    /// Topic contains an empty segment (consecutive dots or leading/trailing
    /// dot).
    EmptySegment {
        /// Segment index (0-based) where empty segment was found.
        segment_index: usize,
    },

    /// Segment exceeds maximum length.
    SegmentTooLong {
        /// Segment index (0-based).
        segment_index: usize,
        /// Actual length.
        len: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// Too many segments in topic.
    TooManySegments {
        /// Actual segment count.
        count: usize,
        /// Maximum allowed count.
        max: usize,
    },

    /// Segment contains invalid characters.
    InvalidCharacter {
        /// Segment index (0-based).
        segment_index: usize,
        /// Character that is invalid.
        character: char,
        /// Position within segment.
        position: usize,
    },
}

impl fmt::Display for TopicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "topic string is empty"),
            Self::TooLong { len, max } => {
                write!(f, "topic too long: {len} characters exceeds maximum {max}")
            },
            Self::NonAscii { position } => {
                write!(
                    f,
                    "topic contains non-ASCII character at position {position}"
                )
            },
            Self::EmptySegment { segment_index } => {
                write!(f, "empty segment at index {segment_index}")
            },
            Self::SegmentTooLong {
                segment_index,
                len,
                max,
            } => {
                write!(
                    f,
                    "segment {segment_index} too long: {len} characters exceeds maximum {max}"
                )
            },
            Self::TooManySegments { count, max } => {
                write!(f, "too many segments: {count} exceeds maximum {max}")
            },
            Self::InvalidCharacter {
                segment_index,
                character,
                position,
            } => {
                write!(
                    f,
                    "invalid character '{character}' in segment {segment_index} at position {position}"
                )
            },
        }
    }
}

impl std::error::Error for TopicError {}

/// Error type for pattern validation failures.
///
/// Extends `TopicError` with pattern-specific validation failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PatternError {
    /// Underlying topic validation failed.
    Topic(TopicError),

    /// Too many wildcards in pattern.
    TooManyWildcards {
        /// Actual wildcard count.
        count: usize,
        /// Maximum allowed count.
        max: usize,
    },

    /// Terminal wildcard `>` not in terminal position.
    TerminalNotTerminal {
        /// Segment index where `>` was found.
        segment_index: usize,
        /// Total segment count.
        total_segments: usize,
    },

    /// Regex-like pattern detected (not supported).
    RegexDetected {
        /// Description of the regex-like construct.
        construct: String,
    },
}

impl fmt::Display for PatternError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Topic(err) => write!(f, "{err}"),
            Self::TooManyWildcards { count, max } => {
                write!(f, "too many wildcards: {count} exceeds maximum {max}")
            },
            Self::TerminalNotTerminal {
                segment_index,
                total_segments,
            } => {
                write!(
                    f,
                    "terminal wildcard '>' at index {segment_index} is not terminal \
                     (total segments: {total_segments})"
                )
            },
            Self::RegexDetected { construct } => {
                write!(f, "regex pattern not supported: {construct}")
            },
        }
    }
}

impl std::error::Error for PatternError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Topic(err) => Some(err),
            _ => None,
        }
    }
}

impl From<TopicError> for PatternError {
    fn from(err: TopicError) -> Self {
        Self::Topic(err)
    }
}

// ============================================================================
// Segment Classification
// ============================================================================

/// Classification of a topic segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SegmentKind {
    /// Concrete segment (alphanumeric identifier).
    Concrete,
    /// Single-segment wildcard `*`.
    WildcardSingle,
    /// Terminal wildcard `>`.
    WildcardTerminal,
}

impl SegmentKind {
    /// Classifies a segment string.
    fn classify(segment: &str) -> Self {
        match segment {
            WILDCARD_SINGLE => Self::WildcardSingle,
            WILDCARD_TERMINAL => Self::WildcardTerminal,
            _ => Self::Concrete,
        }
    }

    /// Returns true if this is any wildcard type.
    #[allow(dead_code)] // May be useful for future pattern analysis
    const fn is_wildcard(self) -> bool {
        matches!(self, Self::WildcardSingle | Self::WildcardTerminal)
    }
}

// ============================================================================
// Topic Validation
// ============================================================================

/// Validates a concrete topic string (no wildcards).
///
/// # Arguments
///
/// * `topic` - The topic string to validate
///
/// # Returns
///
/// `Ok(())` if the topic is valid.
///
/// # Errors
///
/// Returns `TopicError` if validation fails:
/// - `Empty`: Topic is empty
/// - `TooLong`: Topic exceeds 128 characters
/// - `NonAscii`: Contains non-ASCII bytes
/// - `EmptySegment`: Contains empty segment (consecutive dots)
/// - `SegmentTooLong`: A segment exceeds 64 characters
/// - `TooManySegments`: More than 16 segments
/// - `InvalidCharacter`: Contains invalid character in segment
///
/// # Security
///
/// Per INV-HEF-0003 and DD-HEF-0003:
/// - All validation is fail-closed
/// - Rejects any non-ASCII input
/// - Enforces bounded complexity
pub fn validate_topic(topic: &str) -> Result<(), TopicError> {
    // Check empty
    if topic.is_empty() {
        return Err(TopicError::Empty);
    }

    // Check length
    if topic.len() > MAX_TOPIC_LEN {
        return Err(TopicError::TooLong {
            len: topic.len(),
            max: MAX_TOPIC_LEN,
        });
    }

    // Check ASCII (fail-fast on non-ASCII)
    if let Some(pos) = topic.bytes().position(|b| !b.is_ascii()) {
        return Err(TopicError::NonAscii { position: pos });
    }

    // Split and validate segments
    let segments: Vec<&str> = topic.split(SEGMENT_SEPARATOR).collect();

    // Check segment count
    if segments.len() > MAX_SEGMENT_COUNT {
        return Err(TopicError::TooManySegments {
            count: segments.len(),
            max: MAX_SEGMENT_COUNT,
        });
    }

    // Validate each segment
    for (idx, segment) in segments.iter().enumerate() {
        validate_concrete_segment(segment, idx)?;
    }

    Ok(())
}

/// Validates a single concrete segment (no wildcards allowed).
fn validate_concrete_segment(segment: &str, segment_index: usize) -> Result<(), TopicError> {
    // Check empty segment
    if segment.is_empty() {
        return Err(TopicError::EmptySegment { segment_index });
    }

    // Check segment length
    if segment.len() > MAX_SEGMENT_LEN {
        return Err(TopicError::SegmentTooLong {
            segment_index,
            len: segment.len(),
            max: MAX_SEGMENT_LEN,
        });
    }

    // Validate characters: alphanumeric, hyphen, underscore
    // Per topic taxonomy examples: "work.W-123.events", "episode.EP-001.lifecycle"
    for (pos, ch) in segment.chars().enumerate() {
        if !is_valid_segment_char(ch) {
            return Err(TopicError::InvalidCharacter {
                segment_index,
                character: ch,
                position: pos,
            });
        }
    }

    Ok(())
}

/// Returns true if the character is valid for a topic segment.
///
/// Valid characters:
/// - Alphanumeric (a-z, A-Z, 0-9)
/// - Hyphen (`-`)
/// - Underscore (`_`)
#[inline]
const fn is_valid_segment_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '-' || ch == '_'
}

// ============================================================================
// Pattern Parsing and Matching
// ============================================================================

/// A parsed topic pattern for subscription matching.
///
/// `TopicPattern` supports two wildcard types:
/// - `*` matches exactly one segment
/// - `>` matches zero or more remaining segments (terminal only)
///
/// # Invariants
///
/// - Maximum 2 wildcards per pattern
/// - `>` can only appear as the last segment
/// - All segments are ASCII and length-bounded
///
/// # Example
///
/// ```rust,ignore
/// let pattern = TopicPattern::parse("work.*.events")?;
/// assert!(pattern.matches("work.W-123.events"));
///
/// let pattern = TopicPattern::parse("episode.EP-001.>")?;
/// assert!(pattern.matches("episode.EP-001.tool"));
/// assert!(pattern.matches("episode.EP-001.tool.result"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopicPattern {
    /// The parsed segments.
    segments: Vec<PatternSegment>,

    /// Number of wildcards in the pattern.
    wildcard_count: usize,

    /// Whether the pattern has a terminal wildcard.
    has_terminal: bool,
}

/// A single segment in a pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PatternSegment {
    /// Concrete segment that must match exactly.
    Concrete(String),
    /// Single-segment wildcard `*`.
    WildcardSingle,
    /// Terminal wildcard `>`.
    WildcardTerminal,
}

impl TopicPattern {
    /// Parses a topic pattern string.
    ///
    /// # Arguments
    ///
    /// * `pattern` - The pattern string to parse
    ///
    /// # Returns
    ///
    /// A validated `TopicPattern` ready for matching.
    ///
    /// # Errors
    ///
    /// Returns `PatternError` if parsing fails:
    /// - `Topic(...)`: Underlying topic validation failed
    /// - `TooManyWildcards`: More than 2 wildcards
    /// - `TerminalNotTerminal`: `>` not in last position
    /// - `RegexDetected`: Regex-like construct detected
    ///
    /// # Security
    ///
    /// Per DD-HEF-0003:
    /// - No regex support
    /// - Bounded wildcard count
    /// - Deterministic matching complexity
    pub fn parse(pattern: &str) -> Result<Self, PatternError> {
        // Basic validation (reuse topic validation for common checks)
        if pattern.is_empty() {
            return Err(TopicError::Empty.into());
        }

        if pattern.len() > MAX_TOPIC_LEN {
            return Err(TopicError::TooLong {
                len: pattern.len(),
                max: MAX_TOPIC_LEN,
            }
            .into());
        }

        // Check ASCII
        if let Some(pos) = pattern.bytes().position(|b| !b.is_ascii()) {
            return Err(TopicError::NonAscii { position: pos }.into());
        }

        // Detect regex patterns (fail-fast)
        detect_regex_patterns(pattern)?;

        // Split into segments
        let raw_segments: Vec<&str> = pattern.split(SEGMENT_SEPARATOR).collect();

        if raw_segments.len() > MAX_SEGMENT_COUNT {
            return Err(TopicError::TooManySegments {
                count: raw_segments.len(),
                max: MAX_SEGMENT_COUNT,
            }
            .into());
        }

        let mut segments = Vec::with_capacity(raw_segments.len());
        let mut wildcard_count = 0;
        let mut has_terminal = false;

        for (idx, seg_str) in raw_segments.iter().enumerate() {
            // Check empty segment
            if seg_str.is_empty() {
                return Err(TopicError::EmptySegment { segment_index: idx }.into());
            }

            let kind = SegmentKind::classify(seg_str);

            match kind {
                SegmentKind::WildcardSingle => {
                    wildcard_count += 1;
                    if wildcard_count > MAX_WILDCARDS {
                        return Err(PatternError::TooManyWildcards {
                            count: wildcard_count,
                            max: MAX_WILDCARDS,
                        });
                    }
                    segments.push(PatternSegment::WildcardSingle);
                },
                SegmentKind::WildcardTerminal => {
                    wildcard_count += 1;
                    if wildcard_count > MAX_WILDCARDS {
                        return Err(PatternError::TooManyWildcards {
                            count: wildcard_count,
                            max: MAX_WILDCARDS,
                        });
                    }
                    // Terminal wildcard must be last segment
                    if idx != raw_segments.len() - 1 {
                        return Err(PatternError::TerminalNotTerminal {
                            segment_index: idx,
                            total_segments: raw_segments.len(),
                        });
                    }
                    has_terminal = true;
                    segments.push(PatternSegment::WildcardTerminal);
                },
                SegmentKind::Concrete => {
                    // Check for embedded wildcards (e.g., "*events" or "work*")
                    if contains_embedded_wildcard(seg_str) {
                        return Err(PatternError::RegexDetected {
                            construct: "embedded wildcard (wildcards must be standalone segments)"
                                .to_string(),
                        });
                    }
                    // Validate concrete segment
                    validate_pattern_segment(seg_str, idx)?;
                    segments.push(PatternSegment::Concrete((*seg_str).to_string()));
                },
            }
        }

        Ok(Self {
            segments,
            wildcard_count,
            has_terminal,
        })
    }

    /// Matches a topic string against this pattern.
    ///
    /// # Arguments
    ///
    /// * `topic` - The topic string to match
    ///
    /// # Returns
    ///
    /// `true` if the topic matches the pattern.
    ///
    /// # Complexity
    ///
    /// O(n) where n is the number of segments. No backtracking.
    /// The terminal wildcard `>` matches greedily without backtracking.
    ///
    /// # Security
    ///
    /// Per DD-HEF-0003: "Simple bounded grammar keeps matching predictable"
    #[must_use]
    pub fn matches(&self, topic: &str) -> bool {
        // Quick ASCII check (invalid topics never match)
        if !topic.is_ascii() {
            return false;
        }

        let topic_segments: Vec<&str> = topic.split(SEGMENT_SEPARATOR).collect();

        self.match_segments(&topic_segments)
    }

    /// Matches pre-split topic segments against this pattern.
    ///
    /// This is an optimized version for batch matching where the topic has
    /// already been split into segments. Use this when matching the same
    /// topic against multiple patterns to avoid repeated string splitting.
    ///
    /// # Arguments
    ///
    /// * `segments` - Pre-split topic segments
    ///
    /// # Returns
    ///
    /// `true` if the segments match the pattern.
    ///
    /// # Complexity
    ///
    /// O(n) where n is the number of segments. No backtracking.
    #[must_use]
    pub fn matches_segments(&self, segments: &[&str]) -> bool {
        self.match_segments(segments)
    }

    /// Internal segment-by-segment matching.
    fn match_segments(&self, topic_segments: &[&str]) -> bool {
        let pattern_len = self.segments.len();
        let topic_len = topic_segments.len();

        // If pattern has terminal wildcard, topic must have at least (pattern_len - 1)
        // segments plus at least one segment for the `>` to consume (i.e., >=
        // pattern_len segments total) Otherwise, lengths must match exactly
        if self.has_terminal {
            // Terminal wildcard: pattern segments before `>` must match exactly,
            // and `>` must match at least one additional segment.
            // Example: "a.b.>" matches "a.b.c", "a.b.c.d" but NOT "a.b"
            //
            // Per RFC-0018 semantics: `>` matches "zero or more remaining segments"
            // But for practical use, we require at least one segment after prefix
            // to avoid "a.>" matching "a" which would be confusing.
            //
            // Pattern "a.b.>" has 3 segments (a, b, >).
            // It matches topics with >= 3 segments where first 2 match (a, b).
            if topic_len < pattern_len {
                return false;
            }

            // Match all segments before the terminal wildcard
            for (i, seg) in self.segments.iter().enumerate() {
                if matches!(seg, PatternSegment::WildcardTerminal) {
                    // Terminal reached, remaining topic segments match
                    return true;
                }

                // Check if we still have topic segments to match
                if i >= topic_len {
                    return false;
                }

                if !Self::segment_matches(seg, topic_segments[i]) {
                    return false;
                }
            }
        } else {
            // No terminal wildcard: exact segment count required
            if topic_len != pattern_len {
                return false;
            }

            // Match each segment
            for (seg, topic_seg) in self.segments.iter().zip(topic_segments.iter()) {
                if !Self::segment_matches(seg, topic_seg) {
                    return false;
                }
            }
        }

        // All pattern segments matched
        true
    }

    /// Matches a single pattern segment against a topic segment.
    #[inline]
    fn segment_matches(pattern_seg: &PatternSegment, topic_seg: &str) -> bool {
        match pattern_seg {
            PatternSegment::Concrete(expected) => expected == topic_seg,
            PatternSegment::WildcardSingle => !topic_seg.is_empty(),
            PatternSegment::WildcardTerminal => true, // Handled by caller
        }
    }

    /// Returns the number of wildcards in this pattern.
    #[must_use]
    pub const fn wildcard_count(&self) -> usize {
        self.wildcard_count
    }

    /// Returns true if this pattern has a terminal wildcard.
    #[must_use]
    pub const fn has_terminal_wildcard(&self) -> bool {
        self.has_terminal
    }

    /// Returns true if this is an exact pattern (no wildcards).
    #[must_use]
    pub const fn is_exact(&self) -> bool {
        self.wildcard_count == 0
    }

    /// Returns the pattern as a string (for display/logging).
    #[must_use]
    pub fn as_str(&self) -> String {
        self.segments
            .iter()
            .map(|seg| match seg {
                PatternSegment::Concrete(s) => s.as_str(),
                PatternSegment::WildcardSingle => WILDCARD_SINGLE,
                PatternSegment::WildcardTerminal => WILDCARD_TERMINAL,
            })
            .collect::<Vec<_>>()
            .join(".")
    }
}

impl fmt::Display for TopicPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Validates a pattern segment (allows wildcards unlike concrete validation).
fn validate_pattern_segment(segment: &str, segment_index: usize) -> Result<(), TopicError> {
    // Wildcards are handled separately, this is for concrete segments in patterns
    if segment.len() > MAX_SEGMENT_LEN {
        return Err(TopicError::SegmentTooLong {
            segment_index,
            len: segment.len(),
            max: MAX_SEGMENT_LEN,
        });
    }

    // Validate characters
    for (pos, ch) in segment.chars().enumerate() {
        if !is_valid_segment_char(ch) {
            return Err(TopicError::InvalidCharacter {
                segment_index,
                character: ch,
                position: pos,
            });
        }
    }

    Ok(())
}

/// Checks if a segment contains embedded wildcards (invalid).
///
/// Wildcards (`*` and `>`) must be standalone segments, not embedded in text.
/// For example, `*events` or `work*` are invalid.
fn contains_embedded_wildcard(segment: &str) -> bool {
    // If segment is exactly "*" or ">", it's a valid wildcard, not embedded
    if segment == WILDCARD_SINGLE || segment == WILDCARD_TERMINAL {
        return false;
    }

    // Check if segment contains wildcard characters but isn't a pure wildcard
    segment.contains('*') || segment.contains('>')
}

/// Detects regex-like patterns and rejects them.
///
/// Per DD-HEF-0003: "Regex and empty segments are forbidden"
///
/// This function checks for regex constructs while allowing valid wildcard
/// patterns. The `.` character is allowed as a segment separator, and `*`/`>`
/// are allowed as standalone segments (wildcards). What's rejected:
/// - `.*` or `.+` or `.?` (regex quantifiers after dot)
/// - Character classes `[...]`
/// - Capture groups `(...)`
/// - Alternation `|`
/// - Anchors `^` and `$`
/// - Escape sequences `\`
/// - Quantifiers `{...}`
/// - Double wildcards `**` or `>>`
fn detect_regex_patterns(pattern: &str) -> Result<(), PatternError> {
    // Check for regex quantifiers after non-separator characters
    // We need to be careful: "a.*" is regex, but "a.*.b" is valid
    // (dot-wildcard-dot)
    let bytes = pattern.as_bytes();
    let len = bytes.len();

    for i in 0..len {
        let ch = bytes[i] as char;

        match ch {
            // Character class brackets
            '[' | ']' => {
                return Err(PatternError::RegexDetected {
                    construct: "character class".to_string(),
                });
            },
            // Capture groups
            '(' | ')' => {
                return Err(PatternError::RegexDetected {
                    construct: "capture group".to_string(),
                });
            },
            // Alternation
            '|' => {
                return Err(PatternError::RegexDetected {
                    construct: "alternation".to_string(),
                });
            },
            // Anchors
            '^' | '$' => {
                return Err(PatternError::RegexDetected {
                    construct: "anchor".to_string(),
                });
            },
            // Escape sequences
            '\\' => {
                return Err(PatternError::RegexDetected {
                    construct: "escape sequence".to_string(),
                });
            },
            // Quantifier braces
            '{' | '}' => {
                return Err(PatternError::RegexDetected {
                    construct: "quantifier".to_string(),
                });
            },
            // Regex quantifiers: + and ? are always invalid in our grammar
            '+' | '?' => {
                return Err(PatternError::RegexDetected {
                    construct: "regex quantifier".to_string(),
                });
            },
            // Double wildcards
            '*' => {
                if i + 1 < len && bytes[i + 1] as char == '*' {
                    return Err(PatternError::RegexDetected {
                        construct: "double wildcard (use single *)".to_string(),
                    });
                }
                // Check for `*>` which is invalid (terminal must be alone)
                if i + 1 < len && bytes[i + 1] as char == '>' {
                    return Err(PatternError::RegexDetected {
                        construct: "wildcard before terminal".to_string(),
                    });
                }
            },
            '>' => {
                if i + 1 < len && bytes[i + 1] as char == '>' {
                    return Err(PatternError::RegexDetected {
                        construct: "double terminal (use single >)".to_string(),
                    });
                }
            },
            _ => {},
        }
    }

    Ok(())
}

// ============================================================================
// Batch Validation
// ============================================================================

/// Result of validating a batch of patterns.
#[derive(Debug, Clone)]
pub struct PatternValidationResult {
    /// Patterns that were accepted.
    pub accepted: Vec<TopicPattern>,
    /// Patterns that were rejected with reasons.
    pub rejected: Vec<(String, PatternError)>,
}

impl PatternValidationResult {
    /// Returns true if all patterns were accepted.
    #[must_use]
    pub fn all_accepted(&self) -> bool {
        self.rejected.is_empty()
    }

    /// Returns true if any patterns were rejected.
    #[must_use]
    pub fn has_rejections(&self) -> bool {
        !self.rejected.is_empty()
    }
}

/// Validates a batch of pattern strings.
///
/// Continues validation even if some patterns fail, returning both
/// accepted and rejected patterns.
///
/// # Arguments
///
/// * `patterns` - Iterator of pattern strings to validate
///
/// # Returns
///
/// A `PatternValidationResult` containing accepted patterns and rejection
/// reasons.
pub fn validate_patterns<'a, I>(patterns: I) -> PatternValidationResult
where
    I: IntoIterator<Item = &'a str>,
{
    let mut result = PatternValidationResult {
        accepted: Vec::new(),
        rejected: Vec::new(),
    };

    for pattern_str in patterns {
        match TopicPattern::parse(pattern_str) {
            Ok(pattern) => result.accepted.push(pattern),
            Err(err) => result.rejected.push((pattern_str.to_string(), err)),
        }
    }

    result
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Topic Validation Tests
    // ========================================================================

    mod topic_validation {
        use super::*;

        #[test]
        fn valid_simple_topic() {
            assert!(validate_topic("ledger.head").is_ok());
        }

        #[test]
        fn valid_topic_with_hyphen() {
            assert!(validate_topic("work.W-123.events").is_ok());
        }

        #[test]
        fn valid_topic_with_underscore() {
            assert!(validate_topic("episode.EP_001.lifecycle").is_ok());
        }

        #[test]
        fn valid_long_topic() {
            // Generate a topic near max length
            let segments: Vec<String> = (0..10).map(|i| format!("seg{i}")).collect();
            let topic = segments.join(".");
            assert!(topic.len() <= MAX_TOPIC_LEN);
            assert!(validate_topic(&topic).is_ok());
        }

        #[test]
        fn invalid_empty_topic() {
            assert_eq!(validate_topic(""), Err(TopicError::Empty));
        }

        #[test]
        fn invalid_too_long() {
            let topic = "a".repeat(MAX_TOPIC_LEN + 1);
            assert!(matches!(
                validate_topic(&topic),
                Err(TopicError::TooLong { .. })
            ));
        }

        #[test]
        fn invalid_non_ascii() {
            assert!(matches!(
                validate_topic("topic.with.emoji.\u{1F600}"),
                Err(TopicError::NonAscii { .. })
            ));
        }

        #[test]
        fn invalid_empty_segment_leading_dot() {
            assert!(matches!(
                validate_topic(".topic.name"),
                Err(TopicError::EmptySegment { segment_index: 0 })
            ));
        }

        #[test]
        fn invalid_empty_segment_trailing_dot() {
            assert!(matches!(
                validate_topic("topic.name."),
                Err(TopicError::EmptySegment { segment_index: 2 })
            ));
        }

        #[test]
        fn invalid_empty_segment_consecutive_dots() {
            assert!(matches!(
                validate_topic("topic..name"),
                Err(TopicError::EmptySegment { segment_index: 1 })
            ));
        }

        #[test]
        fn invalid_too_many_segments() {
            let segments: Vec<&str> = vec!["seg"; MAX_SEGMENT_COUNT + 1];
            let topic = segments.join(".");
            assert!(matches!(
                validate_topic(&topic),
                Err(TopicError::TooManySegments { .. })
            ));
        }

        #[test]
        fn invalid_character_space() {
            assert!(matches!(
                validate_topic("topic.with space"),
                Err(TopicError::InvalidCharacter { character: ' ', .. })
            ));
        }

        #[test]
        fn invalid_character_slash() {
            assert!(matches!(
                validate_topic("topic/name"),
                Err(TopicError::InvalidCharacter { character: '/', .. })
            ));
        }

        #[test]
        fn invalid_character_at() {
            assert!(matches!(
                validate_topic("topic@name"),
                Err(TopicError::InvalidCharacter { character: '@', .. })
            ));
        }
    }

    // ========================================================================
    // Pattern Parsing Tests
    // ========================================================================

    mod pattern_parsing {
        use super::*;

        #[test]
        fn valid_exact_pattern() {
            let pattern = TopicPattern::parse("work.W-123.events").unwrap();
            assert!(pattern.is_exact());
            assert_eq!(pattern.wildcard_count(), 0);
            assert!(!pattern.has_terminal_wildcard());
        }

        #[test]
        fn valid_single_wildcard() {
            let pattern = TopicPattern::parse("work.*.events").unwrap();
            assert!(!pattern.is_exact());
            assert_eq!(pattern.wildcard_count(), 1);
            assert!(!pattern.has_terminal_wildcard());
        }

        #[test]
        fn valid_terminal_wildcard() {
            let pattern = TopicPattern::parse("episode.EP-001.>").unwrap();
            assert!(!pattern.is_exact());
            assert_eq!(pattern.wildcard_count(), 1);
            assert!(pattern.has_terminal_wildcard());
        }

        #[test]
        fn valid_two_wildcards() {
            let pattern = TopicPattern::parse("*.*.events").unwrap();
            assert_eq!(pattern.wildcard_count(), 2);
        }

        #[test]
        fn valid_single_and_terminal_wildcard() {
            let pattern = TopicPattern::parse("work.*.>").unwrap();
            assert_eq!(pattern.wildcard_count(), 2);
            assert!(pattern.has_terminal_wildcard());
        }

        #[test]
        fn invalid_too_many_wildcards() {
            assert!(matches!(
                TopicPattern::parse("*.*.*"),
                Err(PatternError::TooManyWildcards { count: 3, max: 2 })
            ));
        }

        #[test]
        fn invalid_terminal_not_terminal() {
            let err = TopicPattern::parse("work.>.events").unwrap_err();
            assert!(matches!(err, PatternError::TerminalNotTerminal { .. }));
        }

        #[test]
        fn invalid_regex_dot_star() {
            // Embedded wildcards are rejected (wildcards must be standalone segments)
            assert!(matches!(
                TopicPattern::parse("work.*events"),
                Err(PatternError::RegexDetected { .. })
            ));
            // Character classes are rejected
            assert!(matches!(
                TopicPattern::parse("work.[a-z].events"),
                Err(PatternError::RegexDetected { .. })
            ));
            // Double wildcards are rejected
            assert!(matches!(
                TopicPattern::parse("work.**.events"),
                Err(PatternError::RegexDetected { .. })
            ));
        }

        #[test]
        fn invalid_regex_character_class() {
            assert!(matches!(
                TopicPattern::parse("work.[abc].events"),
                Err(PatternError::RegexDetected { .. })
            ));
        }

        #[test]
        fn invalid_regex_alternation() {
            assert!(matches!(
                TopicPattern::parse("work|events"),
                Err(PatternError::RegexDetected { .. })
            ));
        }

        #[test]
        fn invalid_double_wildcard() {
            assert!(matches!(
                TopicPattern::parse("work.**.events"),
                Err(PatternError::RegexDetected { .. })
            ));
        }

        #[test]
        fn invalid_empty_pattern() {
            assert!(matches!(
                TopicPattern::parse(""),
                Err(PatternError::Topic(TopicError::Empty))
            ));
        }

        #[test]
        fn pattern_display() {
            let pattern = TopicPattern::parse("work.*.events").unwrap();
            assert_eq!(pattern.to_string(), "work.*.events");

            let pattern = TopicPattern::parse("episode.EP-001.>").unwrap();
            assert_eq!(pattern.to_string(), "episode.EP-001.>");
        }
    }

    // ========================================================================
    // Pattern Matching Tests
    // ========================================================================

    mod pattern_matching {
        use super::*;

        #[test]
        fn exact_match() {
            let pattern = TopicPattern::parse("work.W-123.events").unwrap();
            assert!(pattern.matches("work.W-123.events"));
            assert!(!pattern.matches("work.W-456.events"));
            assert!(!pattern.matches("work.W-123"));
            assert!(!pattern.matches("work.W-123.events.extra"));
        }

        #[test]
        fn single_wildcard_match() {
            let pattern = TopicPattern::parse("work.*.events").unwrap();
            assert!(pattern.matches("work.W-123.events"));
            assert!(pattern.matches("work.W-456.events"));
            assert!(pattern.matches("work.anything.events"));
            assert!(!pattern.matches("work.events")); // Missing segment
            assert!(!pattern.matches("work.W-123.other")); // Wrong suffix
            assert!(!pattern.matches("work.W-123.events.extra")); // Too many segments
        }

        #[test]
        fn terminal_wildcard_match() {
            let pattern = TopicPattern::parse("episode.EP-001.>").unwrap();
            assert!(pattern.matches("episode.EP-001.lifecycle"));
            assert!(pattern.matches("episode.EP-001.tool"));
            assert!(pattern.matches("episode.EP-001.tool.result"));
            assert!(pattern.matches("episode.EP-001.io.stdout.chunk"));
            // Terminal wildcard `>` requires at least one segment to match
            // "episode.EP-001" has only 2 segments, pattern needs 3 (2 prefix + 1 for >)
            assert!(!pattern.matches("episode.EP-001"));
            assert!(!pattern.matches("episode.EP-002.lifecycle")); // Wrong episode
        }

        #[test]
        fn terminal_wildcard_requires_one_segment() {
            // "work.W-123.>" requires at least 3 segments total
            // The `>` must consume at least one segment
            let pattern = TopicPattern::parse("work.W-123.>").unwrap();
            // "work.W-123" has only 2 segments, so it should NOT match
            assert!(!pattern.matches("work.W-123"));
            // "work.W-123.events" has 3 segments, so it SHOULD match
            assert!(pattern.matches("work.W-123.events"));
            assert!(pattern.matches("work.W-123.events.sub"));
        }

        #[test]
        fn two_wildcards_match() {
            let pattern = TopicPattern::parse("gate.*.*.G-001").unwrap();
            assert!(pattern.matches("gate.W-123.CS-abc.G-001"));
            assert!(pattern.matches("gate.W-456.CS-def.G-001"));
            assert!(!pattern.matches("gate.W-123.G-001")); // Missing segment
            assert!(!pattern.matches("gate.W-123.CS-abc.G-002")); // Wrong gate
        }

        #[test]
        fn single_and_terminal_match() {
            let pattern = TopicPattern::parse("work.*.>").unwrap();
            assert!(pattern.matches("work.W-123.events"));
            assert!(pattern.matches("work.W-123.events.sub"));
            assert!(pattern.matches("work.W-456.other.stuff.here"));
            assert!(!pattern.matches("work.events")); // Missing middle segment for *
        }

        #[test]
        fn non_ascii_topic_does_not_match() {
            let pattern = TopicPattern::parse("work.*.events").unwrap();
            assert!(!pattern.matches("work.W\u{00E9}123.events")); // Contains é
        }

        #[test]
        fn empty_topic_does_not_match() {
            let pattern = TopicPattern::parse("work.*.events").unwrap();
            assert!(!pattern.matches(""));
        }
    }

    // ========================================================================
    // Batch Validation Tests
    // ========================================================================

    mod batch_validation {
        use super::*;

        #[test]
        fn all_valid() {
            let patterns = ["work.*.events", "episode.EP-001.>", "ledger.head"];
            let result = validate_patterns(patterns.iter().copied());
            assert!(result.all_accepted());
            assert_eq!(result.accepted.len(), 3);
            assert!(result.rejected.is_empty());
        }

        #[test]
        fn some_invalid() {
            let patterns = ["work.*.events", "invalid.[regex]", "valid.topic"];
            let result = validate_patterns(patterns.iter().copied());
            assert!(!result.all_accepted());
            assert_eq!(result.accepted.len(), 2);
            assert_eq!(result.rejected.len(), 1);
            assert_eq!(result.rejected[0].0, "invalid.[regex]");
        }

        #[test]
        fn all_invalid() {
            let patterns = ["", "work.*.*.*", "has space"];
            let result = validate_patterns(patterns.iter().copied());
            assert!(result.accepted.is_empty());
            assert_eq!(result.rejected.len(), 3);
        }
    }

    // ========================================================================
    // Phase 1 Topic Taxonomy Tests
    // ========================================================================

    mod taxonomy {
        use super::*;

        #[test]
        fn system_topic() {
            assert!(validate_topic("ledger.head").is_ok());
        }

        #[test]
        fn work_topic() {
            assert!(validate_topic("work.W-00123.events").is_ok());
        }

        #[test]
        fn gate_topic() {
            assert!(validate_topic("gate.W-00123.CS-abcdef.G-001").is_ok());
        }

        #[test]
        fn episode_lifecycle_topic() {
            assert!(validate_topic("episode.EP-00001.lifecycle").is_ok());
        }

        #[test]
        fn episode_tool_topic() {
            assert!(validate_topic("episode.EP-00001.tool").is_ok());
        }

        #[test]
        fn episode_io_topic() {
            assert!(validate_topic("episode.EP-00001.io").is_ok());
        }

        #[test]
        fn defect_topic() {
            assert!(validate_topic("defect.new").is_ok());
        }

        #[test]
        fn work_wildcard_pattern() {
            let pattern = TopicPattern::parse("work.*.events").unwrap();
            assert!(pattern.matches("work.W-00123.events"));
            assert!(pattern.matches("work.W-00456.events"));
        }

        #[test]
        fn episode_terminal_pattern() {
            let pattern = TopicPattern::parse("episode.*.>").unwrap();
            assert!(pattern.matches("episode.EP-00001.lifecycle"));
            assert!(pattern.matches("episode.EP-00001.tool"));
            assert!(pattern.matches("episode.EP-00001.io"));
        }

        #[test]
        fn gate_pattern() {
            // gate.<work_id>.<changeset_digest>.<gate_id>
            let pattern = TopicPattern::parse("gate.W-00123.*.G-001").unwrap();
            assert!(pattern.matches("gate.W-00123.CS-abcdef.G-001"));
            assert!(pattern.matches("gate.W-00123.CS-ghijkl.G-001"));
            assert!(!pattern.matches("gate.W-00456.CS-abcdef.G-001")); // Wrong work_id
        }
    }

    // ========================================================================
    // Security Tests (INV-HEF-0007)
    // ========================================================================

    mod security {
        use super::*;

        #[test]
        fn reject_regex_quantifiers() {
            // Note: "a.*" is actually valid as "a" followed by wildcard segment "*"
            // but "a+" and "a?" contain invalid characters
            for pattern in ["a+", "a?", "a.{2}", "a.{2,3}", "ab+c", "ab?c"] {
                assert!(
                    TopicPattern::parse(pattern).is_err(),
                    "should reject regex pattern: {pattern}"
                );
            }
        }

        #[test]
        fn reject_regex_anchors() {
            for pattern in ["^work", "work$", "^work$"] {
                assert!(
                    TopicPattern::parse(pattern).is_err(),
                    "should reject regex pattern: {pattern}"
                );
            }
        }

        #[test]
        fn reject_regex_groups() {
            for pattern in ["(work)", "work(events)", "(a|b)"] {
                assert!(
                    TopicPattern::parse(pattern).is_err(),
                    "should reject regex pattern: {pattern}"
                );
            }
        }

        #[test]
        fn reject_regex_escapes() {
            for pattern in ["work\\.events", "\\w+", "\\d+"] {
                assert!(
                    TopicPattern::parse(pattern).is_err(),
                    "should reject regex pattern: {pattern}"
                );
            }
        }

        #[test]
        fn bounded_complexity() {
            // Ensure matching is O(n) by verifying it completes quickly
            // even with many segments
            let mut topic_parts = vec!["seg"; MAX_SEGMENT_COUNT];
            let topic = topic_parts.join(".");

            // Pattern with wildcards
            topic_parts[0] = "*";
            topic_parts[MAX_SEGMENT_COUNT - 1] = ">";
            let pattern_str = topic_parts.join(".");

            let pattern = TopicPattern::parse(&pattern_str).unwrap();
            assert!(pattern.matches(&topic));
        }

        #[test]
        fn non_ascii_rejected_early() {
            // UTF-8 encoded emoji at various positions
            assert!(validate_topic("\u{1F600}").is_err());
            assert!(validate_topic("work.\u{1F600}").is_err());
            assert!(validate_topic("work.valid.\u{1F600}").is_err());

            // High-bit ASCII
            assert!(validate_topic("work.\u{00FF}").is_err());
        }
    }
}
