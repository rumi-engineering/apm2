//! PR description parser for AAT.
//!
//! This module parses PR description markdown to extract the four AAT-required
//! sections: Usage, Expected Outcomes, Evidence Script, and Known Limitations.
//!
//! # Security Note
//!
//! PR descriptions are untrusted input from potentially adversarial agents.
//! All parsed content is sanitized and validated before use.

use regex::Regex;

use crate::aat::types::{KnownLimitation, OutcomeItem, ParseError, ParsedPRDescription};

/// Parses a PR description markdown to extract AAT-required sections.
///
/// # Arguments
///
/// * `markdown` - The raw PR description markdown content.
///
/// # Returns
///
/// * `Ok(ParsedPRDescription)` - Successfully parsed description with all
///   sections.
/// * `Err(ParseError)` - If a required section is missing or malformed.
///
/// # Required Sections
///
/// - `## Usage` - CLI invocation examples (required)
/// - `## Expected Outcomes` - Verifiable predicates with checkboxes (required)
/// - `## Evidence Script` - Script path/content (optional)
/// - `## Known Limitations` - Documented TODOs with optional waiver IDs
///   (optional)
///
/// # Example
///
/// ```ignore
/// let markdown = "## Usage\n\nRun with: `cargo xtask aat <PR_URL>`\n\n\
///     ## Expected Outcomes\n\n- [x] PR is verified\n";
/// let result = parse_pr_description(markdown)?;
/// assert!(result.usage.contains("cargo xtask aat"));
/// ```
pub fn parse_pr_description(markdown: &str) -> Result<ParsedPRDescription, ParseError> {
    // Parse each section
    let usage = parse_usage(markdown)?;
    let expected_outcomes = parse_expected_outcomes(markdown)?;
    let evidence_script = parse_evidence_script(markdown);
    let known_limitations = parse_known_limitations(markdown);

    Ok(ParsedPRDescription {
        usage,
        expected_outcomes,
        evidence_script,
        known_limitations,
    })
}

/// Extracts the content after the `## Usage` header.
///
/// The usage section contains CLI invocation examples and is required.
fn parse_usage(markdown: &str) -> Result<String, ParseError> {
    extract_section(markdown, "Usage").ok_or(ParseError::MissingUsage)
}

/// Extracts and parses the `## Expected Outcomes` section.
///
/// Parses checkbox items in the format:
/// - `- [x] Completed outcome`
/// - `- [ ] Pending outcome`
fn parse_expected_outcomes(markdown: &str) -> Result<Vec<OutcomeItem>, ParseError> {
    let content = extract_section(markdown, "Expected Outcomes")
        .ok_or(ParseError::MissingExpectedOutcomes)?;

    let outcomes = parse_checkbox_items(&content);

    if outcomes.is_empty() {
        return Err(ParseError::MalformedSection {
            section: "Expected Outcomes".to_string(),
            reason: "no checkbox items found (expected '- [ ]' or '- [x]' format)".to_string(),
        });
    }

    Ok(outcomes)
}

/// Extracts the content from the `## Evidence Script` section.
///
/// This section is optional. Returns `None` if not present.
/// If present, extracts the content (preferably from a code block).
fn parse_evidence_script(markdown: &str) -> Option<String> {
    let content = extract_section(markdown, "Evidence Script")?;

    // Try to extract from a code block first
    if let Some(code) = extract_code_block(&content) {
        return Some(code);
    }

    // Fall back to the raw content if no code block
    let trimmed = content.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Extracts and parses the `## Known Limitations` section.
///
/// Parses list items, optionally with waiver IDs in format `(WAIVER-XXXX)`.
fn parse_known_limitations(markdown: &str) -> Vec<KnownLimitation> {
    let Some(content) = extract_section(markdown, "Known Limitations") else {
        return Vec::new();
    };

    parse_limitation_items(&content)
}

/// Extracts the content of a section starting with `## <header>`.
///
/// Returns the content between the header and the next section (or end of
/// document). Handles variations in whitespace and heading levels (##, ###).
fn extract_section(markdown: &str, header: &str) -> Option<String> {
    // Match ## or ### followed by the header (case-insensitive)
    // Use (?i) for case insensitivity on the header name
    let pattern = format!(r"(?mi)^##\s*{}\s*\n", regex::escape(header));
    let header_re = Regex::new(&pattern).ok()?;

    let header_match = header_re.find(markdown)?;
    let start = header_match.end();

    // Find the next section header (## or ###) or end of document
    let next_section_re = Regex::new(r"(?m)^##\s+\S").ok()?;
    let end = next_section_re
        .find_at(markdown, start)
        .map_or(markdown.len(), |m| m.start());

    let content = &markdown[start..end];
    let trimmed = content.trim();

    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Parses checkbox items from markdown content.
///
/// Matches patterns like:
/// - `- [x] Text` (checked)
/// - `- [ ] Text` (unchecked)
/// - `* [x] Text` (checked, asterisk variant)
fn parse_checkbox_items(content: &str) -> Vec<OutcomeItem> {
    let checkbox_re = Regex::new(r"(?m)^[-*]\s*\[([ xX])\]\s*(.+)$").expect("valid regex");

    checkbox_re
        .captures_iter(content)
        .map(|cap| {
            let checked = cap.get(1).is_some_and(|m| m.as_str() != " ");
            let text = cap
                .get(2)
                .map(|m| sanitize_text(m.as_str()))
                .unwrap_or_default();

            OutcomeItem { text, checked }
        })
        .collect()
}

/// Parses limitation items, extracting optional waiver IDs.
///
/// Matches patterns like:
/// - `- Limitation text (WAIVER-0001)`
/// - `* Limitation text`
/// - `- Limitation text (waiver-0002)` (case insensitive)
fn parse_limitation_items(content: &str) -> Vec<KnownLimitation> {
    let list_item_re = Regex::new(r"(?m)^[-*]\s*(.+)$").expect("valid regex");
    let waiver_re = Regex::new(r"(?i)\(WAIVER-(\d+)\)").expect("valid regex");

    list_item_re
        .captures_iter(content)
        .map(|cap| {
            let full_text = cap.get(1).map_or("", |m| m.as_str());

            // Extract waiver ID if present
            let waiver_id = waiver_re
                .captures(full_text)
                .and_then(|wc| wc.get(1))
                .map(|m| format!("WAIVER-{}", m.as_str()));

            // Remove the waiver ID from the text
            let text = waiver_re.replace(full_text, "").trim().to_string();
            let text = sanitize_text(&text);

            KnownLimitation { text, waiver_id }
        })
        .collect()
}

/// Extracts content from a fenced code block.
///
/// Supports both triple backticks and tildes, with optional language specifier.
fn extract_code_block(content: &str) -> Option<String> {
    // Match code blocks with optional language specifier
    // Handles: ```bash, ```shell, ```, ~~~, etc.
    let code_block_re =
        Regex::new(r"(?s)(?:```|~~~)[a-zA-Z]*\s*\n(.*?)(?:```|~~~)").expect("valid regex");

    code_block_re
        .captures(content)
        .and_then(|cap| cap.get(1))
        .map(|m| m.as_str().trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Sanitizes parsed text by removing potentially dangerous characters.
///
/// # Security
///
/// PR descriptions are untrusted input. This function:
/// - Trims leading/trailing whitespace
/// - Removes null bytes
/// - Limits line length to prevent denial of service
fn sanitize_text(text: &str) -> String {
    const MAX_LINE_LENGTH: usize = 10000;

    text.trim()
        .replace('\0', "")
        .chars()
        .take(MAX_LINE_LENGTH)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==========================================================================
    // parse_pr_description tests
    // ==========================================================================

    #[test]
    fn test_parse_valid_pr_description() {
        let markdown = r"
## Summary

This PR adds the AAT feature.

## Usage

Run the AAT command:

```bash
cargo xtask aat https://github.com/owner/repo/pull/123
```

## Expected Outcomes

- [x] PR is parsed successfully
- [ ] Evidence bundle is generated
- [x] Status check is set

## Evidence Script

```bash
./scripts/run_aat.sh
```

## Known Limitations

- Does not support forks (WAIVER-0001)
- Requires gh CLI to be installed
";

        let result = parse_pr_description(markdown).unwrap();

        assert!(result.usage.contains("cargo xtask aat"));
        assert_eq!(result.expected_outcomes.len(), 3);
        assert!(result.expected_outcomes[0].checked);
        assert!(!result.expected_outcomes[1].checked);
        assert!(result.expected_outcomes[2].checked);
        assert_eq!(
            result.evidence_script,
            Some("./scripts/run_aat.sh".to_string())
        );
        assert_eq!(result.known_limitations.len(), 2);
        assert_eq!(
            result.known_limitations[0].waiver_id,
            Some("WAIVER-0001".to_string())
        );
        assert!(result.known_limitations[1].waiver_id.is_none());
    }

    #[test]
    fn test_parse_minimal_valid_description() {
        let markdown = r"
## Usage

Run it.

## Expected Outcomes

- [ ] It works
";

        let result = parse_pr_description(markdown).unwrap();
        assert_eq!(result.usage, "Run it.");
        assert_eq!(result.expected_outcomes.len(), 1);
        assert!(result.evidence_script.is_none());
        assert!(result.known_limitations.is_empty());
    }

    #[test]
    fn test_missing_usage_section() {
        let markdown = r"
## Expected Outcomes

- [ ] Something happens
";

        let result = parse_pr_description(markdown);
        assert!(matches!(result, Err(ParseError::MissingUsage)));
    }

    #[test]
    fn test_missing_expected_outcomes_section() {
        let markdown = r"
## Usage

Run the command.
";

        let result = parse_pr_description(markdown);
        assert!(matches!(result, Err(ParseError::MissingExpectedOutcomes)));
    }

    #[test]
    fn test_empty_expected_outcomes() {
        let markdown = r"
## Usage

Run the command.

## Expected Outcomes

No checkbox items here, just text.
";

        let result = parse_pr_description(markdown);
        assert!(matches!(
            result,
            Err(ParseError::MalformedSection { section, .. }) if section == "Expected Outcomes"
        ));
    }

    // ==========================================================================
    // parse_usage tests
    // ==========================================================================

    #[test]
    fn test_parse_usage_with_code_block() {
        let markdown = r"
## Usage

```bash
cargo xtask aat <PR_URL>
```

## Expected Outcomes
";

        let usage = parse_usage(markdown).unwrap();
        assert!(usage.contains("cargo xtask aat"));
    }

    #[test]
    fn test_parse_usage_multiline() {
        let markdown = r"
## Usage

First, build the project:

```
cargo build
```

Then run:

```
cargo xtask aat <PR_URL>
```

## Expected Outcomes
";

        let usage = parse_usage(markdown).unwrap();
        assert!(usage.contains("cargo build"));
        assert!(usage.contains("cargo xtask aat"));
    }

    // ==========================================================================
    // parse_expected_outcomes tests
    // ==========================================================================

    #[test]
    fn test_parse_outcomes_checked_and_unchecked() {
        let markdown = r"
## Expected Outcomes

- [x] First outcome is done
- [ ] Second outcome is pending
- [X] Third outcome uses capital X
";

        let outcomes = parse_expected_outcomes(markdown).unwrap();
        assert_eq!(outcomes.len(), 3);
        assert!(outcomes[0].checked);
        assert!(!outcomes[1].checked);
        assert!(outcomes[2].checked);
    }

    #[test]
    fn test_parse_outcomes_asterisk_syntax() {
        let markdown = r"
## Expected Outcomes

* [x] Using asterisks
* [ ] Also works
";

        let outcomes = parse_expected_outcomes(markdown).unwrap();
        assert_eq!(outcomes.len(), 2);
        assert!(outcomes[0].checked);
        assert!(!outcomes[1].checked);
    }

    // ==========================================================================
    // parse_evidence_script tests
    // ==========================================================================

    #[test]
    fn test_parse_evidence_script_with_code_block() {
        let markdown = r"
## Evidence Script

```bash
./run_tests.sh
```

## Known Limitations
";

        let script = parse_evidence_script(markdown);
        assert_eq!(script, Some("./run_tests.sh".to_string()));
    }

    #[test]
    fn test_parse_evidence_script_without_code_block() {
        let markdown = r"
## Evidence Script

evidence/aat/verify.sh (NEW)

## Known Limitations
";

        let script = parse_evidence_script(markdown);
        assert_eq!(script, Some("evidence/aat/verify.sh (NEW)".to_string()));
    }

    #[test]
    fn test_parse_evidence_script_missing() {
        let markdown = r"
## Usage

Run it.

## Expected Outcomes

- [ ] Works
";

        let script = parse_evidence_script(markdown);
        assert!(script.is_none());
    }

    #[test]
    fn test_parse_evidence_script_tilde_fence() {
        let markdown = r#"
## Evidence Script

~~~shell
echo "Using tilde fences"
~~~
"#;

        let script = parse_evidence_script(markdown);
        assert_eq!(script, Some(r#"echo "Using tilde fences""#.to_string()));
    }

    // ==========================================================================
    // parse_known_limitations tests
    // ==========================================================================

    #[test]
    fn test_parse_limitations_with_waiver() {
        let markdown = r"
## Known Limitations

- Does not support Windows (WAIVER-0001)
- No caching implemented (WAIVER-0042)
";

        let limitations = parse_known_limitations(markdown);
        assert_eq!(limitations.len(), 2);
        assert_eq!(limitations[0].text, "Does not support Windows");
        assert_eq!(limitations[0].waiver_id, Some("WAIVER-0001".to_string()));
        assert_eq!(limitations[1].waiver_id, Some("WAIVER-0042".to_string()));
    }

    #[test]
    fn test_parse_limitations_without_waiver() {
        let markdown = r"
## Known Limitations

- This is a limitation
- Another one without waiver
";

        let limitations = parse_known_limitations(markdown);
        assert_eq!(limitations.len(), 2);
        assert!(limitations[0].waiver_id.is_none());
        assert!(limitations[1].waiver_id.is_none());
    }

    #[test]
    fn test_parse_limitations_mixed() {
        let markdown = r"
## Known Limitations

- Has waiver (WAIVER-0001)
- No waiver here
- Another waiver (waiver-0002)
";

        let limitations = parse_known_limitations(markdown);
        assert_eq!(limitations.len(), 3);
        assert_eq!(limitations[0].waiver_id, Some("WAIVER-0001".to_string()));
        assert!(limitations[1].waiver_id.is_none());
        assert_eq!(limitations[2].waiver_id, Some("WAIVER-0002".to_string()));
    }

    #[test]
    fn test_parse_limitations_empty_section() {
        let markdown = r"
## Usage

Test

## Expected Outcomes

- [ ] Works

## Known Limitations
";

        let limitations = parse_known_limitations(markdown);
        assert!(limitations.is_empty());
    }

    // ==========================================================================
    // extract_section tests
    // ==========================================================================

    #[test]
    fn test_extract_section_basic() {
        let markdown = r"
## First Section

Content here.

## Second Section

More content.
";

        let first = extract_section(markdown, "First Section");
        assert_eq!(first, Some("Content here.".to_string()));

        let second = extract_section(markdown, "Second Section");
        assert_eq!(second, Some("More content.".to_string()));
    }

    #[test]
    fn test_extract_section_case_insensitive() {
        let markdown = r"
## USAGE

Command here.

## Expected Outcomes
";

        let usage = extract_section(markdown, "Usage");
        assert_eq!(usage, Some("Command here.".to_string()));
    }

    #[test]
    fn test_extract_section_with_extra_whitespace() {
        let markdown = "##   Usage   \n\nContent with spaces.\n\n## Next";

        let usage = extract_section(markdown, "Usage");
        assert_eq!(usage, Some("Content with spaces.".to_string()));
    }

    #[test]
    fn test_extract_section_at_end() {
        let markdown = r"
## Other

Stuff.

## Final Section

This is at the end of the document.
";

        let final_section = extract_section(markdown, "Final Section");
        assert_eq!(
            final_section,
            Some("This is at the end of the document.".to_string())
        );
    }

    // ==========================================================================
    // parse_checkbox_items tests
    // ==========================================================================

    #[test]
    fn test_checkbox_items_basic() {
        let content = r"
- [x] Checked item
- [ ] Unchecked item
";

        let items = parse_checkbox_items(content);
        assert_eq!(items.len(), 2);
        assert!(items[0].checked);
        assert_eq!(items[0].text, "Checked item");
        assert!(!items[1].checked);
    }

    #[test]
    fn test_checkbox_items_with_special_chars() {
        let content = "- [x] Item with `code` and *emphasis*\n";

        let items = parse_checkbox_items(content);
        assert_eq!(items.len(), 1);
        assert!(items[0].text.contains("`code`"));
    }

    // ==========================================================================
    // extract_code_block tests
    // ==========================================================================

    #[test]
    fn test_code_block_with_language() {
        let content = "```bash\necho hello\n```";
        let code = extract_code_block(content);
        assert_eq!(code, Some("echo hello".to_string()));
    }

    #[test]
    fn test_code_block_without_language() {
        let content = "```\nplain code\n```";
        let code = extract_code_block(content);
        assert_eq!(code, Some("plain code".to_string()));
    }

    #[test]
    fn test_code_block_multiline() {
        let content = "```rust\nfn main() {\n    println!(\"hello\");\n}\n```";
        let code = extract_code_block(content);
        assert!(code.is_some());
        let code = code.unwrap();
        assert!(code.contains("fn main()"));
        assert!(code.contains("println!"));
    }

    #[test]
    fn test_code_block_empty() {
        let content = "```\n```";
        let code = extract_code_block(content);
        assert!(code.is_none());
    }

    // ==========================================================================
    // sanitize_text tests
    // ==========================================================================

    #[test]
    fn test_sanitize_removes_null_bytes() {
        let text = "hello\0world";
        let sanitized = sanitize_text(text);
        assert_eq!(sanitized, "helloworld");
    }

    #[test]
    fn test_sanitize_trims_whitespace() {
        let text = "  spaced  ";
        let sanitized = sanitize_text(text);
        assert_eq!(sanitized, "spaced");
    }

    #[test]
    fn test_sanitize_limits_length() {
        let long_text = "a".repeat(20000);
        let sanitized = sanitize_text(&long_text);
        assert_eq!(sanitized.len(), 10000);
    }

    // ==========================================================================
    // Real-world PR description tests
    // ==========================================================================

    #[test]
    fn test_realistic_pr_description() {
        let markdown = r"
## Summary

Implements the AAT PR parser as specified in TCK-00051.

## Usage

The parser is invoked internally by the AAT command:

```bash
cargo xtask aat https://github.com/owner/repo/pull/123
```

It extracts the following sections from the PR body:
- Usage
- Expected Outcomes
- Evidence Script
- Known Limitations

## Expected Outcomes

- [x] `parse_pr_description()` correctly parses well-formed markdown
- [x] `ParseError::MissingUsage` returned for missing Usage section
- [x] `ParseError::MissingExpectedOutcomes` returned for missing outcomes
- [ ] Checkbox state (`[x]` vs `[ ]`) correctly parsed
- [x] WAIVER-ID extracted from Known Limitations entries

## Evidence Script

```bash
# Run parser tests
cargo test -p xtask aat::parser

# Verify with sample PR descriptions
./scripts/test_parser.sh
```

## Known Limitations

- Does not parse nested checkboxes (WAIVER-0001)
- Evidence Script code block language is not validated
- Large PR descriptions may be truncated for security (WAIVER-0002)

## Test Plan

1. Run unit tests: `cargo test -p xtask`
2. Run clippy: `cargo clippy -p xtask`
3. Manual test with real PR descriptions
";

        let result = parse_pr_description(markdown).unwrap();

        // Verify usage
        assert!(result.usage.contains("cargo xtask aat"));

        // Verify expected outcomes
        assert_eq!(result.expected_outcomes.len(), 5);
        let checked_count = result
            .expected_outcomes
            .iter()
            .filter(|o| o.checked)
            .count();
        assert_eq!(checked_count, 4);

        // Verify evidence script
        assert!(result.evidence_script.is_some());
        let script = result.evidence_script.unwrap();
        assert!(script.contains("cargo test"));

        // Verify known limitations
        assert_eq!(result.known_limitations.len(), 3);
        assert_eq!(
            result.known_limitations[0].waiver_id,
            Some("WAIVER-0001".to_string())
        );
        assert!(result.known_limitations[1].waiver_id.is_none());
        assert_eq!(
            result.known_limitations[2].waiver_id,
            Some("WAIVER-0002".to_string())
        );
    }
}
