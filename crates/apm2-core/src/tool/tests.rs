//! Tests for tool protocol messages.

use prost::Message;

use super::*;

/// Test that tool requests can be roundtrip encoded/decoded.
#[test]
fn test_file_read_roundtrip() {
    let request = ToolRequest {
        consumption_mode: false,
        request_id: "req-001".to_string(),
        session_token: "session-abc".to_string(),
        dedupe_key: "key-123".to_string(),
        tool: Some(tool_request::Tool::FileRead(FileRead {
            path: "/path/to/file.txt".to_string(),
            offset: 100,
            limit: 1024,
        })),
    };

    let bytes = request.encode_to_vec();
    let decoded = ToolRequest::decode(bytes.as_slice()).expect("decode failed");

    assert_eq!(decoded.request_id, "req-001");
    assert_eq!(decoded.session_token, "session-abc");
    assert_eq!(decoded.dedupe_key, "key-123");

    match decoded.tool {
        Some(tool_request::Tool::FileRead(file_read)) => {
            assert_eq!(file_read.path, "/path/to/file.txt");
            assert_eq!(file_read.offset, 100);
            assert_eq!(file_read.limit, 1024);
        },
        _ => panic!("expected FileRead tool"),
    }
}

#[test]
fn test_file_write_roundtrip() {
    let content = b"Hello, World!".to_vec();
    let request = ToolRequest {
        consumption_mode: false,
        request_id: "req-002".to_string(),
        session_token: "session-abc".to_string(),
        dedupe_key: String::new(),
        tool: Some(tool_request::Tool::FileWrite(FileWrite {
            path: "/path/to/output.txt".to_string(),
            content: content.clone(),
            create_only: true,
            append: false,
        })),
    };

    let bytes = request.encode_to_vec();
    let decoded = ToolRequest::decode(bytes.as_slice()).expect("decode failed");

    match decoded.tool {
        Some(tool_request::Tool::FileWrite(file_write)) => {
            assert_eq!(file_write.path, "/path/to/output.txt");
            assert_eq!(file_write.content, content);
            assert!(file_write.create_only);
            assert!(!file_write.append);
        },
        _ => panic!("expected FileWrite tool"),
    }
}

#[test]
fn test_file_edit_roundtrip() {
    let request = ToolRequest {
        consumption_mode: false,
        request_id: "req-003".to_string(),
        session_token: "session-abc".to_string(),
        dedupe_key: String::new(),
        tool: Some(tool_request::Tool::FileEdit(FileEdit {
            path: "/path/to/file.rs".to_string(),
            old_content: "fn old() {}".to_string(),
            new_content: "fn new() {}".to_string(),
        })),
    };

    let bytes = request.encode_to_vec();
    let decoded = ToolRequest::decode(bytes.as_slice()).expect("decode failed");

    match decoded.tool {
        Some(tool_request::Tool::FileEdit(file_edit)) => {
            assert_eq!(file_edit.path, "/path/to/file.rs");
            assert_eq!(file_edit.old_content, "fn old() {}");
            assert_eq!(file_edit.new_content, "fn new() {}");
        },
        _ => panic!("expected FileEdit tool"),
    }
}

#[test]
fn test_shell_exec_roundtrip() {
    let request = ToolRequest {
        consumption_mode: false,
        request_id: "req-004".to_string(),
        session_token: "session-abc".to_string(),
        dedupe_key: String::new(),
        tool: Some(tool_request::Tool::ShellExec(ShellExec {
            command: "cargo test".to_string(),
            cwd: "/home/user/project".to_string(),
            timeout_ms: 60_000,
            network_access: false,
            env: vec!["RUST_BACKTRACE=1".to_string(), "PATH=/usr/bin".to_string()],
        })),
    };

    let bytes = request.encode_to_vec();
    let decoded = ToolRequest::decode(bytes.as_slice()).expect("decode failed");

    match decoded.tool {
        Some(tool_request::Tool::ShellExec(shell_exec)) => {
            assert_eq!(shell_exec.command, "cargo test");
            assert_eq!(shell_exec.cwd, "/home/user/project");
            assert_eq!(shell_exec.timeout_ms, 60_000);
            assert!(!shell_exec.network_access);
            assert_eq!(shell_exec.env.len(), 2);
            assert!(shell_exec.env.contains(&"RUST_BACKTRACE=1".to_string()));
        },
        _ => panic!("expected ShellExec tool"),
    }
}

#[test]
fn test_git_operation_roundtrip() {
    let request = ToolRequest {
        consumption_mode: false,
        request_id: "req-005".to_string(),
        session_token: "session-abc".to_string(),
        dedupe_key: String::new(),
        tool: Some(tool_request::Tool::GitOp(GitOperation {
            operation: "DIFF".to_string(),
            args: vec!["--cached".to_string(), "HEAD~1".to_string()],
            cwd: "/home/user/repo".to_string(),
        })),
    };

    let bytes = request.encode_to_vec();
    let decoded = ToolRequest::decode(bytes.as_slice()).expect("decode failed");

    match decoded.tool {
        Some(tool_request::Tool::GitOp(git_op)) => {
            assert_eq!(git_op.operation, "DIFF");
            assert_eq!(git_op.args, vec!["--cached", "HEAD~1"]);
            assert_eq!(git_op.cwd, "/home/user/repo");
        },
        _ => panic!("expected GitOperation tool"),
    }
}

#[test]
fn test_inference_call_roundtrip() {
    let prompt_hash = vec![0xab; 32];
    let system_hash = vec![0xcd; 32];

    let request = ToolRequest {
        consumption_mode: false,
        request_id: "req-006".to_string(),
        session_token: "session-abc".to_string(),
        dedupe_key: String::new(),
        tool: Some(tool_request::Tool::Inference(InferenceCall {
            provider: "anthropic".to_string(),
            model: "claude-3-opus".to_string(),
            prompt_hash: prompt_hash.clone(),
            max_tokens: 4096,
            temperature_scaled: 70, // 0.70
            system_prompt_hash: system_hash.clone(),
        })),
    };

    let bytes = request.encode_to_vec();
    let decoded = ToolRequest::decode(bytes.as_slice()).expect("decode failed");

    match decoded.tool {
        Some(tool_request::Tool::Inference(inference)) => {
            assert_eq!(inference.provider, "anthropic");
            assert_eq!(inference.model, "claude-3-opus");
            assert_eq!(inference.prompt_hash, prompt_hash);
            assert_eq!(inference.max_tokens, 4096);
            assert_eq!(inference.temperature_scaled, 70);
            assert_eq!(inference.system_prompt_hash, system_hash);
        },
        _ => panic!("expected InferenceCall tool"),
    }
}

#[test]
fn test_artifact_publish_roundtrip() {
    let content_hash = vec![0xef; 32];

    let request = ToolRequest {
        consumption_mode: false,
        request_id: "req-007".to_string(),
        session_token: "session-abc".to_string(),
        dedupe_key: String::new(),
        tool: Some(tool_request::Tool::ArtifactPublish(ArtifactPublish {
            artifact_id: "art-001".to_string(),
            content_hash: content_hash.clone(),
            category: "test_results".to_string(),
            metadata: vec!["format=junit".to_string(), "version=1.0".to_string()],
        })),
    };

    let bytes = request.encode_to_vec();
    let decoded = ToolRequest::decode(bytes.as_slice()).expect("decode failed");

    match decoded.tool {
        Some(tool_request::Tool::ArtifactPublish(artifact)) => {
            assert_eq!(artifact.artifact_id, "art-001");
            assert_eq!(artifact.content_hash, content_hash);
            assert_eq!(artifact.category, "test_results");
            assert_eq!(artifact.metadata.len(), 2);
        },
        _ => panic!("expected ArtifactPublish tool"),
    }
}

#[test]
fn test_tool_response_success_roundtrip() {
    let response = ToolResponse {
        request_id: "req-001".to_string(),
        result: Some(tool_response::Result::Success(ToolSuccess {
            result_hash: vec![0x12; 32],
            inline_result: b"file contents here".to_vec(),
            budget_consumed: 100,
            duration_ms: 50,
        })),
    };

    let bytes = response.encode_to_vec();
    let decoded = ToolResponse::decode(bytes.as_slice()).expect("decode failed");

    assert_eq!(decoded.request_id, "req-001");
    match decoded.result {
        Some(tool_response::Result::Success(success)) => {
            assert_eq!(success.result_hash.len(), 32);
            assert_eq!(success.inline_result, b"file contents here");
            assert_eq!(success.budget_consumed, 100);
            assert_eq!(success.duration_ms, 50);
        },
        _ => panic!("expected Success result"),
    }
}

#[test]
fn test_tool_response_denied_roundtrip() {
    let response = ToolResponse {
        request_id: "req-002".to_string(),
        result: Some(tool_response::Result::Denied(ToolDenied {
            rule_id: "rule-no-shell".to_string(),
            rationale_code: "SHELL_EXEC_DENIED".to_string(),
            message: "Shell execution is not permitted for this session".to_string(),
        })),
    };

    let bytes = response.encode_to_vec();
    let decoded = ToolResponse::decode(bytes.as_slice()).expect("decode failed");

    assert_eq!(decoded.request_id, "req-002");
    match decoded.result {
        Some(tool_response::Result::Denied(denied)) => {
            assert_eq!(denied.rule_id, "rule-no-shell");
            assert_eq!(denied.rationale_code, "SHELL_EXEC_DENIED");
            assert!(denied.message.contains("Shell execution"));
        },
        _ => panic!("expected Denied result"),
    }
}

#[test]
fn test_tool_response_error_roundtrip() {
    let response = ToolResponse {
        request_id: "req-003".to_string(),
        result: Some(tool_response::Result::Error(ToolError {
            error_code: "FILE_NOT_FOUND".to_string(),
            message: "The specified file does not exist".to_string(),
            retryable: false,
            retry_after_ms: 0,
        })),
    };

    let bytes = response.encode_to_vec();
    let decoded = ToolResponse::decode(bytes.as_slice()).expect("decode failed");

    assert_eq!(decoded.request_id, "req-003");
    match decoded.result {
        Some(tool_response::Result::Error(error)) => {
            assert_eq!(error.error_code, "FILE_NOT_FOUND");
            assert!(!error.retryable);
        },
        _ => panic!("expected Error result"),
    }
}

#[test]
fn test_tool_response_error_retryable() {
    let response = ToolResponse {
        request_id: "req-004".to_string(),
        result: Some(tool_response::Result::Error(ToolError {
            error_code: "RATE_LIMITED".to_string(),
            message: "Too many requests".to_string(),
            retryable: true,
            retry_after_ms: 5000,
        })),
    };

    let bytes = response.encode_to_vec();
    let decoded = ToolResponse::decode(bytes.as_slice()).expect("decode failed");

    match decoded.result {
        Some(tool_response::Result::Error(error)) => {
            assert!(error.retryable);
            assert_eq!(error.retry_after_ms, 5000);
        },
        _ => panic!("expected Error result"),
    }
}

/// Test that encoding produces deterministic bytes (canonical encoding).
#[test]
fn test_canonical_encoding_deterministic() {
    let request = ToolRequest {
        consumption_mode: false,
        request_id: "req-001".to_string(),
        session_token: "session-abc".to_string(),
        dedupe_key: "key-123".to_string(),
        tool: Some(tool_request::Tool::FileRead(FileRead {
            path: "/path/to/file.txt".to_string(),
            offset: 100,
            limit: 1024,
        })),
    };

    // Encode multiple times
    let bytes1 = request.encode_to_vec();
    let bytes2 = request.encode_to_vec();
    let bytes3 = request.encode_to_vec();

    // All encodings must be identical
    assert_eq!(bytes1, bytes2);
    assert_eq!(bytes2, bytes3);

    // Decode and re-encode must produce identical bytes
    let decoded = ToolRequest::decode(bytes1.as_slice()).expect("decode failed");
    let bytes4 = decoded.encode_to_vec();
    assert_eq!(bytes1, bytes4);
}

/// Test empty/default request encoding.
#[test]
fn test_empty_request_encoding() {
    let request = ToolRequest::default();
    let bytes = request.encode_to_vec();

    let decoded = ToolRequest::decode(bytes.as_slice()).expect("decode failed");
    assert!(decoded.request_id.is_empty());
    assert!(decoded.session_token.is_empty());
    assert!(decoded.tool.is_none());
}

/// Test large payload handling.
#[test]
fn test_large_content() {
    let large_content = vec![0xffu8; 1024 * 1024]; // 1MB

    let request = ToolRequest {
        consumption_mode: false,
        request_id: "req-large".to_string(),
        session_token: "session-abc".to_string(),
        dedupe_key: String::new(),
        tool: Some(tool_request::Tool::FileWrite(FileWrite {
            path: "/path/to/large.bin".to_string(),
            content: large_content.clone(),
            create_only: false,
            append: false,
        })),
    };

    let bytes = request.encode_to_vec();
    let decoded = ToolRequest::decode(bytes.as_slice()).expect("decode failed");

    match decoded.tool {
        Some(tool_request::Tool::FileWrite(file_write)) => {
            assert_eq!(file_write.content.len(), 1024 * 1024);
            assert_eq!(file_write.content, large_content);
        },
        _ => panic!("expected FileWrite tool"),
    }
}

/// Test all tool request variants encode without error.
#[test]
fn test_all_tool_variants_encode() {
    let file_read = ToolRequest {
        tool: Some(tool_request::Tool::FileRead(FileRead::default())),
        ..Default::default()
    };
    let _ = file_read.encode_to_vec();

    let file_write = ToolRequest {
        tool: Some(tool_request::Tool::FileWrite(FileWrite::default())),
        ..Default::default()
    };
    let _ = file_write.encode_to_vec();

    let file_edit = ToolRequest {
        tool: Some(tool_request::Tool::FileEdit(FileEdit::default())),
        ..Default::default()
    };
    let _ = file_edit.encode_to_vec();

    let shell_exec = ToolRequest {
        tool: Some(tool_request::Tool::ShellExec(ShellExec::default())),
        ..Default::default()
    };
    let _ = shell_exec.encode_to_vec();

    let git_op = ToolRequest {
        tool: Some(tool_request::Tool::GitOp(GitOperation::default())),
        ..Default::default()
    };
    let _ = git_op.encode_to_vec();

    let inference = ToolRequest {
        tool: Some(tool_request::Tool::Inference(InferenceCall::default())),
        ..Default::default()
    };
    let _ = inference.encode_to_vec();

    let artifact = ToolRequest {
        tool: Some(tool_request::Tool::ArtifactPublish(
            ArtifactPublish::default(),
        )),
        ..Default::default()
    };
    let _ = artifact.encode_to_vec();
}

/// Test all response variants encode without error.
#[test]
fn test_all_response_variants_encode() {
    let success = ToolResponse {
        result: Some(tool_response::Result::Success(ToolSuccess::default())),
        ..Default::default()
    };
    let _ = success.encode_to_vec();

    let denied = ToolResponse {
        result: Some(tool_response::Result::Denied(ToolDenied::default())),
        ..Default::default()
    };
    let _ = denied.encode_to_vec();

    let error = ToolResponse {
        result: Some(tool_response::Result::Error(ToolError::default())),
        ..Default::default()
    };
    let _ = error.encode_to_vec();
}

/// Test validation error encoding.
#[test]
fn test_validation_error_roundtrip() {
    let error = ValidationError {
        field: "file_read.path".to_string(),
        rule: "required".to_string(),
        message: "path must be non-empty".to_string(),
    };

    let bytes = error.encode_to_vec();
    let decoded = ValidationError::decode(bytes.as_slice()).expect("decode failed");

    assert_eq!(decoded.field, "file_read.path");
    assert_eq!(decoded.rule, "required");
    assert_eq!(decoded.message, "path must be non-empty");
}

/// Test that validation is applied correctly.
#[test]
fn test_validation_integration() {
    use super::Validator;

    // Valid request
    let valid = ToolRequest {
        consumption_mode: false,
        request_id: "req-001".to_string(),
        session_token: "session-abc".to_string(),
        dedupe_key: String::new(),
        tool: Some(tool_request::Tool::FileRead(FileRead {
            path: "/path/to/file.txt".to_string(),
            offset: 0,
            limit: 0,
        })),
    };
    assert!(valid.validate().is_ok());

    // Invalid request (empty request_id)
    let invalid = ToolRequest {
        consumption_mode: false,
        request_id: String::new(),
        session_token: "session-abc".to_string(),
        dedupe_key: String::new(),
        tool: Some(tool_request::Tool::FileRead(FileRead {
            path: "/path/to/file.txt".to_string(),
            offset: 0,
            limit: 0,
        })),
    };
    assert!(invalid.validate().is_err());
}
