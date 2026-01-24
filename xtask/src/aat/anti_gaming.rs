//! Anti-gaming analysis for detecting adversarial patterns in PR diffs.
//!
//! This module implements pattern detection to identify code that may
//! attempt to circumvent acceptance testing. It analyzes unified diffs
//! to find:
//!
//! - `if test` / `cfg(test)` conditionals that might bypass verification
//! - Hardcoded UUIDs that might indicate test-specific behavior
//! - Mock/stub/fake patterns in non-test code
//! - TODO/FIXME/HACK comments not documented in Known Limitations

use std::sync::LazyLock;

use regex::Regex;

use crate::aat::types::{AntiGamingResult, GamingViolation, KnownLimitation, TodoItem};

// =============================================================================
// Regex Patterns
// =============================================================================

/// Pattern for detecting `if test`, `if is_test`, `cfg(test)`, `cfg!(test)`,
/// `#[cfg(test)]`
static IF_TEST_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?x)
        # Match 'if test' or 'if is_test' patterns
        if\s+(is_)?test
        |
        # Match cfg(test) or cfg!(test) in any context (macro and attribute forms)
        cfg\s*!?\s*\(\s*test\s*\)
        |
        # Match #[cfg(test)] attribute
        \#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]
    ",
    )
    .expect("IF_TEST_REGEX should compile")
});

/// Pattern for detecting UUID v4 (case-insensitive)
static UUID_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
        .expect("UUID_REGEX should compile")
});

/// Pattern for detecting mock/stub/fake prefixed identifiers
static MOCK_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(mock|stub|fake)_\w+").expect("MOCK_REGEX should compile"));

/// Pattern for detecting TODO/FIXME/HACK comments
static TODO_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(TODO|FIXME|HACK):\s*(.*)").expect("TODO_REGEX should compile")
});

// =============================================================================
// Diff Parsing
// =============================================================================

/// Information about a line in a unified diff.
#[derive(Debug, Clone)]
struct DiffLine<'a> {
    /// The file path this line belongs to.
    file: &'a str,
    /// The line number in the new file (for added lines).
    line: u32,
    /// The content of the line (without the leading +/-/ ).
    content: &'a str,
}

/// Parse a unified diff and extract added lines with file/line info.
///
/// This function processes unified diff format:
/// - `--- a/path` and `+++ b/path` headers indicate file paths
/// - `@@ -old_start,old_count +new_start,new_count @@` indicates hunk headers
/// - Lines starting with `+` (but not `+++`) are added lines
fn parse_added_lines(diff: &str) -> Vec<DiffLine<'_>> {
    let mut result = Vec::new();
    let mut current_file: Option<&str> = None;
    let mut current_line: u32 = 0;

    for line in diff.lines() {
        // Parse file path from +++ header
        if let Some(path) = line.strip_prefix("+++ ") {
            // Handle both "+++ b/path" and "+++ path" formats
            current_file = Some(path.strip_prefix("b/").unwrap_or(path));
            continue;
        }

        // Skip --- header lines
        if line.starts_with("--- ") {
            continue;
        }

        // Parse hunk header for starting line number
        if line.starts_with("@@ ") {
            // Format: @@ -old_start,old_count +new_start,new_count @@
            if let Some(plus_part) = line.split('+').nth(1) {
                if let Some(line_num_str) = plus_part.split(',').next() {
                    if let Some(line_num_str) = line_num_str.split(' ').next() {
                        if let Ok(line_num) = line_num_str.parse::<u32>() {
                            current_line = line_num;
                            continue;
                        }
                    }
                }
            }
            continue;
        }

        // Process content lines
        if let Some(file) = current_file {
            if let Some(content) = line.strip_prefix('+') {
                // This is an added line
                result.push(DiffLine {
                    file,
                    line: current_line,
                    content,
                });
                current_line += 1;
            } else if line.starts_with('-') {
                // Removed line - don't increment line counter
            } else if line.starts_with(' ') || line.is_empty() {
                // Context line or empty - increment line counter
                current_line += 1;
            }
        }
    }

    result
}

// =============================================================================
// Detection Functions
// =============================================================================

/// Detect `if test`, `cfg(test)`, and `#[cfg(test)]` patterns in added lines.
///
/// These patterns may indicate code that behaves differently during testing,
/// which could be used to game acceptance tests.
///
/// # Arguments
/// * `diff` - A unified diff string
///
/// # Returns
/// A vector of `GamingViolation::IfTestConditional` for each match found.
pub fn detect_if_test_patterns(diff: &str) -> Vec<GamingViolation> {
    let mut violations = Vec::new();
    let added_lines = parse_added_lines(diff);

    for diff_line in added_lines {
        // Skip if this is in a test file
        if is_test_file(diff_line.file) {
            continue;
        }

        for mat in IF_TEST_REGEX.find_iter(diff_line.content) {
            violations.push(GamingViolation::IfTestConditional {
                file: diff_line.file.to_string(),
                line: diff_line.line,
                snippet: mat.as_str().to_string(),
            });
        }
    }

    violations
}

/// Detect hardcoded UUID patterns in added lines.
///
/// Hardcoded UUIDs may indicate test-specific behavior or magic values
/// that could be used to game acceptance tests.
///
/// # Arguments
/// * `diff` - A unified diff string
///
/// # Returns
/// A vector of `GamingViolation::HardcodedUuid` for each UUID found.
pub fn detect_hardcoded_uuids(diff: &str) -> Vec<GamingViolation> {
    let mut violations = Vec::new();
    let added_lines = parse_added_lines(diff);

    for diff_line in added_lines {
        // Skip if this is in a test file - UUIDs in tests are expected
        if is_test_file(diff_line.file) {
            continue;
        }

        for mat in UUID_REGEX.find_iter(diff_line.content) {
            violations.push(GamingViolation::HardcodedUuid {
                file: diff_line.file.to_string(),
                line: diff_line.line,
                snippet: mat.as_str().to_string(),
            });
        }
    }

    violations
}

/// Detect mock/stub/fake patterns in added lines.
///
/// These patterns in non-test code may indicate attempts to bypass
/// real functionality during testing.
///
/// # Arguments
/// * `diff` - A unified diff string
///
/// # Returns
/// A vector of `GamingViolation::MockPattern` for each match found.
pub fn detect_mock_patterns(diff: &str) -> Vec<GamingViolation> {
    let mut violations = Vec::new();
    let added_lines = parse_added_lines(diff);

    for diff_line in added_lines {
        // Skip if this is in a test file - mocks in tests are expected
        if is_test_file(diff_line.file) {
            continue;
        }

        for mat in MOCK_REGEX.find_iter(diff_line.content) {
            violations.push(GamingViolation::MockPattern {
                file: diff_line.file.to_string(),
                line: diff_line.line,
                snippet: mat.as_str().to_string(),
            });
        }
    }

    violations
}

/// Extract TODO/FIXME/HACK comments from added lines.
///
/// These comments indicate incomplete work that should be documented
/// in the PR's Known Limitations section.
///
/// # Arguments
/// * `diff` - A unified diff string
///
/// # Returns
/// A vector of `TodoItem` for each TODO/FIXME/HACK comment found.
pub fn extract_todos(diff: &str) -> Vec<TodoItem> {
    let mut todos = Vec::new();
    let added_lines = parse_added_lines(diff);

    for diff_line in added_lines {
        if let Some(caps) = TODO_REGEX.captures(diff_line.content) {
            // Get the full match including the keyword and description
            let keyword = caps.get(1).map_or("", |m| m.as_str());
            let description = caps.get(2).map_or("", |m| m.as_str());
            let text = format!("{keyword}: {description}");

            todos.push(TodoItem {
                text,
                file: diff_line.file.to_string(),
                line: diff_line.line,
            });
        }
    }

    todos
}

/// Check if TODOs are documented in Known Limitations.
///
/// Each TODO/FIXME/HACK comment in the code should have a corresponding
/// entry in the PR's Known Limitations section. This ensures incomplete
/// work is explicitly acknowledged.
///
/// # Arguments
/// * `todos` - List of TODO items extracted from the diff
/// * `known_limitations` - List of known limitations from PR description
///
/// # Returns
/// A vector of `GamingViolation::UndocumentedTodo` for each TODO
/// not found in the known limitations.
pub fn check_todos_documented(
    todos: &[TodoItem],
    known_limitations: &[KnownLimitation],
) -> Vec<GamingViolation> {
    let mut violations = Vec::new();

    for todo in todos {
        // Check if this TODO is documented in any known limitation
        // We do a case-insensitive substring match on the description
        let todo_lower = todo.text.to_lowercase();
        let is_documented = known_limitations.iter().any(|limitation| {
            let limitation_lower = limitation.text.to_lowercase();
            // Check if the TODO description appears in the limitation text
            // or if the limitation text appears in the TODO description
            // Extract just the description part after the keyword
            let todo_desc = todo_lower
                .split(':')
                .nth(1)
                .map_or(todo_lower.as_str(), |s| s.trim());
            limitation_lower.contains(todo_desc)
                || todo_desc.contains(&limitation_lower)
                || has_significant_word_overlap(&limitation_lower, todo_desc)
        });

        if !is_documented {
            violations.push(GamingViolation::UndocumentedTodo {
                file: todo.file.clone(),
                line: todo.line,
                snippet: todo.text.clone(),
            });
        }
    }

    violations
}

/// Check if two strings have significant word overlap.
///
/// This helps match TODOs to limitations when the exact wording differs
/// but the concepts are the same.
fn has_significant_word_overlap(a: &str, b: &str) -> bool {
    let words_a: std::collections::HashSet<&str> = a
        .split_whitespace()
        .filter(|w| w.len() > 3) // Ignore short words
        .collect();
    let words_b: std::collections::HashSet<&str> =
        b.split_whitespace().filter(|w| w.len() > 3).collect();

    if words_a.is_empty() || words_b.is_empty() {
        return false;
    }

    let overlap = words_a.intersection(&words_b).count();
    let min_words = words_a.len().min(words_b.len());

    // Require at least 50% overlap of the smaller set
    overlap * 2 >= min_words
}

/// Check if a file path indicates a test file.
///
/// Test files are expected to contain test-specific code, mocks, and UUIDs,
/// so we skip them during anti-gaming analysis.
fn is_test_file(path: &str) -> bool {
    // Common test file patterns
    path.contains("/tests/")
        || path.contains("/test/")
        || path.ends_with("_test.rs")
        || path.ends_with("_test.go")
        || path.ends_with(".test.ts")
        || path.ends_with(".test.js")
        || path.ends_with("_spec.rb")
        || path.contains("/spec/")
        || path.contains("test_")
        || (path.contains("/src/") && path.contains("/mod.rs") && path.contains("tests"))
}

// =============================================================================
// Main Analysis Function
// =============================================================================

/// Analyze a PR diff for anti-gaming violations.
///
/// This is the main entry point for anti-gaming analysis. It runs all
/// detection functions and aggregates the results.
///
/// # Arguments
/// * `diff` - A unified diff string from the PR
/// * `known_limitations` - List of known limitations from the PR description
///
/// # Returns
/// An `AntiGamingResult` containing all violations found and whether
/// the check passed (no violations).
///
/// # Example
/// ```
/// use xtask::aat::anti_gaming::analyze_diff;
/// use xtask::aat::types::KnownLimitation;
///
/// let diff = r#"
/// diff --git a/src/lib.rs b/src/lib.rs
/// --- a/src/lib.rs
/// +++ b/src/lib.rs
/// @@ -1,3 +1,5 @@
///  fn main() {
/// +    // TODO: implement caching
/// +    let id = "550e8400-e29b-41d4-a716-446655440000";
///  }
/// "#;
///
/// let known_limitations = vec![KnownLimitation {
///     text: "Caching is not yet implemented".to_string(),
///     waiver_id: None,
/// }];
///
/// let result = analyze_diff(diff, &known_limitations);
/// // Result will contain a HardcodedUuid violation
/// // but no UndocumentedTodo (since caching is documented)
/// ```
pub fn analyze_diff(diff: &str, known_limitations: &[KnownLimitation]) -> AntiGamingResult {
    let mut violations = Vec::new();

    // Detect if-test patterns
    violations.extend(detect_if_test_patterns(diff));

    // Detect hardcoded UUIDs
    violations.extend(detect_hardcoded_uuids(diff));

    // Detect mock patterns
    violations.extend(detect_mock_patterns(diff));

    // Extract TODOs and check documentation
    let todos = extract_todos(diff);
    violations.extend(check_todos_documented(&todos, known_limitations));

    let passed = violations.is_empty();

    AntiGamingResult { violations, passed }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // If-Test Pattern Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_detect_if_test_basic() {
        let diff = r"
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,3 +1,5 @@
 fn main() {
+    if test {
+        return;
+    }
 }
";
        let violations = detect_if_test_patterns(diff);
        assert_eq!(violations.len(), 1);
        if let GamingViolation::IfTestConditional { file, snippet, .. } = &violations[0] {
            assert_eq!(file, "src/lib.rs");
            assert_eq!(snippet, "if test");
        } else {
            panic!("Expected IfTestConditional violation");
        }
    }

    #[test]
    fn test_detect_if_is_test() {
        let diff = r"
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,3 +1,5 @@
 fn main() {
+    if is_test {
+        skip_validation();
+    }
 }
";
        let violations = detect_if_test_patterns(diff);
        assert_eq!(violations.len(), 1);
        if let GamingViolation::IfTestConditional { snippet, .. } = &violations[0] {
            assert_eq!(snippet, "if is_test");
        } else {
            panic!("Expected IfTestConditional violation");
        }
    }

    #[test]
    fn test_detect_cfg_test() {
        let diff = r"
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,3 +1,5 @@
+#[cfg(test)]
 mod tests {
     #[test]
     fn it_works() {}
 }
";
        let violations = detect_if_test_patterns(diff);
        assert_eq!(violations.len(), 1);
        if let GamingViolation::IfTestConditional { snippet, .. } = &violations[0] {
            assert_eq!(snippet, "#[cfg(test)]");
        } else {
            panic!("Expected IfTestConditional violation");
        }
    }

    #[test]
    fn test_detect_cfg_test_inline() {
        let diff = r"
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,3 +1,5 @@
 fn main() {
+    if cfg!(test) {
+        return;
+    }
 }
";
        let violations = detect_if_test_patterns(diff);
        assert_eq!(violations.len(), 1);
        if let GamingViolation::IfTestConditional { snippet, .. } = &violations[0] {
            assert!(snippet.contains("cfg") && snippet.contains("test"));
        } else {
            panic!("Expected IfTestConditional violation");
        }
    }

    #[test]
    fn test_skip_test_files() {
        let diff = r"
diff --git a/src/tests/mod.rs b/src/tests/mod.rs
--- a/src/tests/mod.rs
+++ b/src/tests/mod.rs
@@ -1,3 +1,5 @@
+#[cfg(test)]
 fn test_helper() {
+    if test {
+        setup();
+    }
 }
";
        let violations = detect_if_test_patterns(diff);
        assert!(violations.is_empty(), "Should skip test files");
    }

    // -------------------------------------------------------------------------
    // Hardcoded UUID Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_detect_uuid_lowercase() {
        let diff = r#"
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,3 +1,4 @@
 fn main() {
+    let id = "550e8400-e29b-41d4-a716-446655440000";
 }
"#;
        let violations = detect_hardcoded_uuids(diff);
        assert_eq!(violations.len(), 1);
        if let GamingViolation::HardcodedUuid { snippet, .. } = &violations[0] {
            assert_eq!(snippet, "550e8400-e29b-41d4-a716-446655440000");
        } else {
            panic!("Expected HardcodedUuid violation");
        }
    }

    #[test]
    fn test_detect_uuid_uppercase() {
        let diff = r#"
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,3 +1,4 @@
 fn main() {
+    let id = "550E8400-E29B-41D4-A716-446655440000";
 }
"#;
        let violations = detect_hardcoded_uuids(diff);
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn test_uuid_in_test_file_allowed() {
        let diff = r#"
diff --git a/src/lib_test.rs b/src/lib_test.rs
--- a/src/lib_test.rs
+++ b/src/lib_test.rs
@@ -1,3 +1,4 @@
 fn test_main() {
+    let id = "550e8400-e29b-41d4-a716-446655440000";
 }
"#;
        let violations = detect_hardcoded_uuids(diff);
        assert!(
            violations.is_empty(),
            "UUIDs in test files should be allowed"
        );
    }

    // -------------------------------------------------------------------------
    // Mock Pattern Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_detect_mock_pattern() {
        let diff = r"
diff --git a/src/service.rs b/src/service.rs
--- a/src/service.rs
+++ b/src/service.rs
@@ -1,3 +1,4 @@
 fn main() {
+    let db = mock_database();
 }
";
        let violations = detect_mock_patterns(diff);
        assert_eq!(violations.len(), 1);
        if let GamingViolation::MockPattern { snippet, .. } = &violations[0] {
            assert_eq!(snippet, "mock_database");
        } else {
            panic!("Expected MockPattern violation");
        }
    }

    #[test]
    fn test_detect_stub_pattern() {
        let diff = r"
diff --git a/src/service.rs b/src/service.rs
--- a/src/service.rs
+++ b/src/service.rs
@@ -1,3 +1,4 @@
 fn main() {
+    let service = stub_api_client();
 }
";
        let violations = detect_mock_patterns(diff);
        assert_eq!(violations.len(), 1);
        if let GamingViolation::MockPattern { snippet, .. } = &violations[0] {
            assert_eq!(snippet, "stub_api_client");
        } else {
            panic!("Expected MockPattern violation");
        }
    }

    #[test]
    fn test_detect_fake_pattern() {
        let diff = r"
diff --git a/src/service.rs b/src/service.rs
--- a/src/service.rs
+++ b/src/service.rs
@@ -1,3 +1,4 @@
 fn main() {
+    let auth = fake_authenticator();
 }
";
        let violations = detect_mock_patterns(diff);
        assert_eq!(violations.len(), 1);
        if let GamingViolation::MockPattern { snippet, .. } = &violations[0] {
            assert_eq!(snippet, "fake_authenticator");
        } else {
            panic!("Expected MockPattern violation");
        }
    }

    #[test]
    fn test_mock_in_test_file_allowed() {
        let diff = r"
diff --git a/tests/integration_test.rs b/tests/integration_test.rs
--- a/tests/integration_test.rs
+++ b/tests/integration_test.rs
@@ -1,3 +1,4 @@
 fn test_service() {
+    let db = mock_database();
 }
";
        let violations = detect_mock_patterns(diff);
        assert!(
            violations.is_empty(),
            "Mocks in test files should be allowed"
        );
    }

    // -------------------------------------------------------------------------
    // TODO Extraction Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_extract_todo() {
        let diff = r"
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,3 +1,4 @@
 fn main() {
+    // TODO: implement caching
 }
";
        let todos = extract_todos(diff);
        assert_eq!(todos.len(), 1);
        assert!(todos[0].text.contains("TODO"));
        assert!(todos[0].text.contains("implement caching"));
    }

    #[test]
    fn test_extract_fixme() {
        let diff = r"
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,3 +1,4 @@
 fn main() {
+    // FIXME: handle edge case
 }
";
        let todos = extract_todos(diff);
        assert_eq!(todos.len(), 1);
        assert!(todos[0].text.contains("FIXME"));
    }

    #[test]
    fn test_extract_hack() {
        let diff = r"
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,3 +1,4 @@
 fn main() {
+    // HACK: workaround for bug #123
 }
";
        let todos = extract_todos(diff);
        assert_eq!(todos.len(), 1);
        assert!(todos[0].text.contains("HACK"));
    }

    // -------------------------------------------------------------------------
    // TODO Documentation Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_todo_documented() {
        let todos = vec![TodoItem {
            text: "TODO: implement caching".to_string(),
            file: "src/lib.rs".to_string(),
            line: 10,
        }];

        let known_limitations = vec![KnownLimitation {
            text: "Caching is not implemented yet".to_string(),
            waiver_id: None,
        }];

        let violations = check_todos_documented(&todos, &known_limitations);
        assert!(
            violations.is_empty(),
            "TODO should be considered documented due to word overlap"
        );
    }

    #[test]
    fn test_todo_undocumented() {
        let todos = vec![TodoItem {
            text: "TODO: implement caching".to_string(),
            file: "src/lib.rs".to_string(),
            line: 10,
        }];

        let known_limitations = vec![KnownLimitation {
            text: "Does not support Windows".to_string(),
            waiver_id: None,
        }];

        let violations = check_todos_documented(&todos, &known_limitations);
        assert_eq!(violations.len(), 1);
        if let GamingViolation::UndocumentedTodo { snippet, .. } = &violations[0] {
            assert!(snippet.contains("TODO"));
            assert!(snippet.contains("caching"));
        } else {
            panic!("Expected UndocumentedTodo violation");
        }
    }

    #[test]
    fn test_todo_with_waiver() {
        let todos = vec![TodoItem {
            text: "TODO: add rate limiting".to_string(),
            file: "src/api.rs".to_string(),
            line: 25,
        }];

        let known_limitations = vec![KnownLimitation {
            text: "Rate limiting not implemented".to_string(),
            waiver_id: Some("WAIVER-0001".to_string()),
        }];

        let violations = check_todos_documented(&todos, &known_limitations);
        assert!(
            violations.is_empty(),
            "TODO should be documented via known limitation with waiver"
        );
    }

    // -------------------------------------------------------------------------
    // Analyze Diff Integration Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_analyze_diff_clean() {
        let diff = r#"
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,3 +1,5 @@
 fn main() {
+    let x = 42;
+    println!("{}", x);
 }
"#;
        let result = analyze_diff(diff, &[]);
        assert!(result.passed);
        assert!(result.violations.is_empty());
    }

    #[test]
    fn test_analyze_diff_with_violations() {
        let diff = r#"
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,3 +1,7 @@
 fn main() {
+    let id = "550e8400-e29b-41d4-a716-446655440000";
+    if cfg!(test) {
+        return;
+    }
+    // TODO: implement caching
 }
"#;
        let result = analyze_diff(diff, &[]);
        assert!(!result.passed);
        assert_eq!(result.violations.len(), 3); // UUID + cfg(test) + TODO
    }

    #[test]
    fn test_analyze_diff_documented_todo() {
        let diff = r"
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,3 +1,4 @@
 fn main() {
+    // TODO: implement caching
 }
";
        let known_limitations = vec![KnownLimitation {
            text: "Caching not yet implemented".to_string(),
            waiver_id: None,
        }];

        let result = analyze_diff(diff, &known_limitations);
        assert!(result.passed);
        assert!(result.violations.is_empty());
    }

    // -------------------------------------------------------------------------
    // Line Number Tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_line_numbers_correct() {
        let diff = r#"
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -10,3 +10,5 @@
 fn existing() {}
+
+let id = "550e8400-e29b-41d4-a716-446655440000";
"#;
        let violations = detect_hardcoded_uuids(diff);
        assert_eq!(violations.len(), 1);
        if let GamingViolation::HardcodedUuid { line, .. } = &violations[0] {
            assert_eq!(*line, 12, "Line number should be 12 (10 + 2 added lines)");
        } else {
            panic!("Expected HardcodedUuid violation");
        }
    }

    // -------------------------------------------------------------------------
    // Edge Cases
    // -------------------------------------------------------------------------

    #[test]
    fn test_empty_diff() {
        let result = analyze_diff("", &[]);
        assert!(result.passed);
        assert!(result.violations.is_empty());
    }

    #[test]
    fn test_diff_with_only_removed_lines() {
        let diff = r#"
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,5 +1,2 @@
 fn main() {
-    let id = "550e8400-e29b-41d4-a716-446655440000";
-    if cfg!(test) {
-        return;
-    }
 }
"#;
        let result = analyze_diff(diff, &[]);
        assert!(result.passed, "Removed lines should not trigger violations");
    }

    #[test]
    fn test_multiple_files() {
        let diff = r"
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,2 +1,3 @@
 fn main() {
+    let x = mock_service();
 }
diff --git a/src/util.rs b/src/util.rs
--- a/src/util.rs
+++ b/src/util.rs
@@ -1,2 +1,3 @@
 fn helper() {
+    let y = fake_database();
 }
";
        let violations = detect_mock_patterns(diff);
        assert_eq!(violations.len(), 2);

        let files: Vec<&str> = violations
            .iter()
            .map(|v| {
                if let GamingViolation::MockPattern { file, .. } = v {
                    file.as_str()
                } else {
                    ""
                }
            })
            .collect();

        assert!(files.contains(&"src/lib.rs"));
        assert!(files.contains(&"src/util.rs"));
    }
}
