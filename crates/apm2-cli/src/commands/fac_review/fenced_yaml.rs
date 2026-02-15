//! Shared fenced-YAML helpers for GitHub comment projection payloads.

use serde::Serialize;

fn max_backtick_run(input: &str) -> usize {
    let mut max_run = 0usize;
    let mut current = 0usize;
    for ch in input.chars() {
        if ch == '`' {
            current = current.saturating_add(1);
            max_run = max_run.max(current);
        } else {
            current = 0;
        }
    }
    max_run
}

/// Render a marker-prefixed Markdown comment containing YAML inside a fenced
/// code block.
///
/// The fence width is chosen dynamically so any backtick runs inside YAML
/// values cannot prematurely close the outer fence.
pub fn render_marked_yaml_comment<T: Serialize>(
    marker: &str,
    payload: &T,
) -> Result<String, String> {
    let yaml = serde_yaml::to_string(payload)
        .map_err(|err| format!("failed to serialize YAML payload: {err}"))?;
    let yaml = yaml.trim_end_matches('\n');
    let fence_len = max_backtick_run(yaml).saturating_add(1).max(3);
    let fence = "`".repeat(fence_len);
    Ok(format!(
        "<!-- {marker} -->\n{fence}yaml\n# {marker}\n{yaml}\n{fence}\n"
    ))
}

/// Test-only helpers for parsing fenced YAML blocks from GitHub comment bodies.
///
/// `parse_opening_fence`, `is_closing_fence`, and `extract_fenced_yaml` are
/// used exclusively by tests (in this module and `ci_status::tests`) to
/// round-trip verify that `render_marked_yaml_comment` output can be parsed
/// back. They are not wired into production paths.
#[cfg(test)]
pub mod parse {
    pub fn parse_opening_fence(line: &str) -> Option<usize> {
        let trimmed = line.trim();
        let fence_len = trimmed.chars().take_while(|ch| *ch == '`').count();
        if fence_len < 3 {
            return None;
        }
        let rest = trimmed[fence_len..].trim();
        if rest.is_empty() || rest.eq_ignore_ascii_case("yaml") {
            Some(fence_len)
        } else {
            None
        }
    }

    pub fn is_closing_fence(line: &str, fence_len: usize) -> bool {
        let trimmed = line.trim();
        trimmed.chars().count() == fence_len && trimmed.chars().all(|ch| ch == '`')
    }

    /// Extract the YAML payload from the first fenced YAML block in `body`.
    ///
    /// Requires the closing fence to be on its own line and to match the
    /// opening fence width.
    pub fn extract_fenced_yaml(body: &str) -> Option<&str> {
        let mut offset = 0usize;
        for line in body.split_inclusive('\n') {
            let line_without_newline = line.trim_end_matches(['\n', '\r']);
            let Some(fence_len) = parse_opening_fence(line_without_newline) else {
                offset = offset.saturating_add(line.len());
                continue;
            };

            let yaml_start = offset.saturating_add(line.len());
            let mut inner_offset = yaml_start;
            for inner_line in body[yaml_start..].split_inclusive('\n') {
                let inner_without_newline = inner_line.trim_end_matches(['\n', '\r']);
                if is_closing_fence(inner_without_newline, fence_len) {
                    return Some(body[yaml_start..inner_offset].trim());
                }
                inner_offset = inner_offset.saturating_add(inner_line.len());
            }
            return None;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::parse::extract_fenced_yaml;
    use super::render_marked_yaml_comment;

    #[derive(serde::Serialize)]
    struct Payload<'a> {
        schema: &'a str,
        reason: &'a str,
    }

    #[test]
    fn render_uses_wider_fence_when_yaml_contains_backticks() {
        let payload = Payload {
            schema: "apm2.test",
            reason: "contains ``` inner fence",
        };
        let body = render_marked_yaml_comment("marker", &payload).expect("render");
        assert!(body.contains("````yaml"));
    }

    #[test]
    fn extract_ignores_inner_backticks_and_finds_matching_close() {
        let body =
            "<!-- marker -->\n````yaml\nschema: apm2.test\nreason: \"uses ``` inside\"\n````\n";
        let yaml = extract_fenced_yaml(body).expect("yaml");
        assert!(yaml.contains("schema: apm2.test"));
        assert!(yaml.contains("uses ``` inside"));
    }
}
