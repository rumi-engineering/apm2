//! Typed selector tokens for FAC digest-first zoom-in.

use super::types::{split_owner_repo, validate_expected_head_sha};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectorType {
    Finding,
    ToolOutput,
}

impl SelectorType {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Finding => "finding",
            Self::ToolOutput => "tool_output",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindingSelector {
    pub owner_repo: String,
    pub pr: u32,
    pub sha: String,
    pub dimension: String,
    pub comment_id: u64,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolOutputSelector {
    pub sha: String,
    pub gate: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectorToken {
    Finding(FindingSelector),
    ToolOutput(ToolOutputSelector),
}

pub fn parse_selector_type(input: &str) -> Result<SelectorType, String> {
    match input.trim().to_ascii_lowercase().as_str() {
        "finding" => Ok(SelectorType::Finding),
        "tool_output" | "tool-output" => Ok(SelectorType::ToolOutput),
        other => Err(format!(
            "invalid selector type `{other}` (expected finding|tool_output)"
        )),
    }
}

pub fn parse_selector(selector_type: SelectorType, token: &str) -> Result<SelectorToken, String> {
    match selector_type {
        SelectorType::Finding => parse_finding_selector(token).map(SelectorToken::Finding),
        SelectorType::ToolOutput => {
            parse_tool_output_selector(token).map(SelectorToken::ToolOutput)
        },
    }
}

#[must_use]
pub fn render_finding_selector(
    owner_repo: &str,
    pr: u32,
    sha: &str,
    dimension: &str,
    comment_id: u64,
    line: usize,
) -> String {
    format!(
        "finding:v1:{owner_repo}:{pr}:{sha}:{}:{comment_id}:{line}",
        normalize_dimension(dimension)
    )
}

#[must_use]
pub fn render_tool_output_selector(sha: &str, gate: &str) -> String {
    format!("tool_output:v1:{sha}:{gate}")
}

pub fn normalize_dimension(input: &str) -> String {
    match input.trim().to_ascii_lowercase().as_str() {
        "security" => "security".to_string(),
        "quality" | "code-quality" | "code_quality" => "code-quality".to_string(),
        other => other.to_string(),
    }
}

fn parse_finding_selector(token: &str) -> Result<FindingSelector, String> {
    let parts = token.split(':').collect::<Vec<_>>();
    if parts.len() != 8 {
        return Err(format!(
            "invalid finding selector format `{token}` (expected finding:v1:<owner/repo>:<pr>:<sha>:<dimension>:<comment_id>:<line>)"
        ));
    }
    if parts[0] != "finding" || parts[1] != "v1" {
        return Err(format!(
            "invalid finding selector prefix `{token}` (expected finding:v1:...)"
        ));
    }

    let owner_repo = parts[2].trim();
    split_owner_repo(owner_repo)?;

    let pr = parts[3]
        .parse::<u32>()
        .map_err(|err| format!("invalid finding selector pr `{}`: {err}", parts[3]))?;
    if pr == 0 {
        return Err("invalid finding selector pr `0`".to_string());
    }

    let sha = parts[4].to_ascii_lowercase();
    validate_expected_head_sha(&sha)?;

    let dimension = normalize_dimension(parts[5]);
    if !matches!(dimension.as_str(), "security" | "code-quality") {
        return Err(format!(
            "invalid finding selector dimension `{}` (expected security|code-quality)",
            parts[5]
        ));
    }

    let comment_id = parts[6]
        .parse::<u64>()
        .map_err(|err| format!("invalid finding selector comment_id `{}`: {err}", parts[6]))?;
    if comment_id == 0 {
        return Err("invalid finding selector comment_id `0`".to_string());
    }

    let line = parts[7]
        .parse::<usize>()
        .map_err(|err| format!("invalid finding selector line `{}`: {err}", parts[7]))?;
    if line == 0 {
        return Err("invalid finding selector line `0`".to_string());
    }

    Ok(FindingSelector {
        owner_repo: owner_repo.to_string(),
        pr,
        sha,
        dimension,
        comment_id,
        line,
    })
}

fn parse_tool_output_selector(token: &str) -> Result<ToolOutputSelector, String> {
    let parts = token.split(':').collect::<Vec<_>>();
    if parts.len() != 4 {
        return Err(format!(
            "invalid tool output selector format `{token}` (expected tool_output:v1:<sha>:<gate>)"
        ));
    }
    if parts[0] != "tool_output" || parts[1] != "v1" {
        return Err(format!(
            "invalid tool output selector prefix `{token}` (expected tool_output:v1:...)"
        ));
    }

    let sha = parts[2].to_ascii_lowercase();
    validate_expected_head_sha(&sha)?;

    let gate = parts[3].trim().to_string();
    if gate.is_empty() {
        return Err("invalid tool output selector gate: empty".to_string());
    }
    if gate
        .chars()
        .any(|ch| !(ch.is_ascii_alphanumeric() || ch == '-' || ch == '_'))
    {
        return Err(format!(
            "invalid tool output selector gate `{gate}`: only [A-Za-z0-9_-] allowed"
        ));
    }

    Ok(ToolOutputSelector { sha, gate })
}

#[cfg(test)]
mod tests {
    use super::{
        SelectorToken, SelectorType, normalize_dimension, parse_selector, parse_selector_type,
        render_finding_selector, render_tool_output_selector,
    };

    #[test]
    fn parse_selector_type_accepts_aliases() {
        assert_eq!(
            parse_selector_type("tool_output").expect("tool_output"),
            SelectorType::ToolOutput
        );
        assert_eq!(
            parse_selector_type("tool-output").expect("tool-output"),
            SelectorType::ToolOutput
        );
        assert_eq!(
            parse_selector_type("finding").expect("finding"),
            SelectorType::Finding
        );
    }

    #[test]
    fn render_and_parse_finding_selector_roundtrip() {
        let token = render_finding_selector(
            "guardian-intelligence/apm2",
            482,
            "0123456789abcdef0123456789abcdef01234567",
            "quality",
            123_456,
            42,
        );
        let parsed = parse_selector(SelectorType::Finding, &token).expect("parsed");
        match parsed {
            SelectorToken::Finding(finding) => {
                assert_eq!(finding.owner_repo, "guardian-intelligence/apm2");
                assert_eq!(finding.pr, 482);
                assert_eq!(finding.dimension, "code-quality");
                assert_eq!(finding.comment_id, 123_456);
                assert_eq!(finding.line, 42);
            },
            SelectorToken::ToolOutput(_) => panic!("expected finding selector"),
        }
    }

    #[test]
    fn render_and_parse_tool_output_selector_roundtrip() {
        let token =
            render_tool_output_selector("0123456789abcdef0123456789abcdef01234567", "rustfmt");
        let parsed = parse_selector(SelectorType::ToolOutput, &token).expect("parsed");
        match parsed {
            SelectorToken::ToolOutput(tool) => {
                assert_eq!(tool.gate, "rustfmt");
            },
            SelectorToken::Finding(_) => panic!("expected tool output selector"),
        }
    }

    #[test]
    fn parse_selector_rejects_bad_prefix() {
        let err = parse_selector(
            SelectorType::Finding,
            "finding:v2:guardian-intelligence/apm2:482:0123456789abcdef0123456789abcdef01234567:security:1:2",
        )
        .expect_err("bad prefix should fail");
        assert!(err.contains("prefix"));
    }

    #[test]
    fn parse_selector_rejects_bad_gate() {
        let err = parse_selector(
            SelectorType::ToolOutput,
            "tool_output:v1:0123456789abcdef0123456789abcdef01234567:bad/path",
        )
        .expect_err("bad gate");
        assert!(err.contains("only [A-Za-z0-9_-] allowed"));
    }

    #[test]
    fn normalize_dimension_aliases() {
        assert_eq!(normalize_dimension("quality"), "code-quality");
        assert_eq!(normalize_dimension("code_quality"), "code-quality");
        assert_eq!(normalize_dimension("security"), "security");
    }
}
