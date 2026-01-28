{
  "schema": "apm2.repo_root_markdown_onboarding.v1",
  "schema_version": "1.1.0",
  "repo": {
    "name": "apm2-rfc-consensus",
    "root": ".",
    "git": {
      "head_commit": {
        "algo": "sha1",
        "object_kind": "commit",
        "object_id": "d992b2323f8fe2884226dd8716f286e6ffbf5e4d"
      },
      "head_tree": {
        "algo": "sha1",
        "object_kind": "tree",
        "object_id": "28dac4f95e6527b1987fbde38d6336b4b7f27474"
      },
      "dirty_worktree_expected": true,
      "origin_remote": "https://github.com/Anveio/apm2.git"
    }
  },
  "onboarding": {
    "goals": [
      "token_efficiency",
      "auditability"
    ],
    "read_first": [
      "AGENTS.md",
      "SECURITY.md"
    ],
    "precedence": [
      "AGENTS.md",
      "documents/skills/**/SKILL.md",
      "crates/**/AGENTS.md",
      "other_docs"
    ],
    "worktree_rules": [
      "Assume the repo may be dirty.",
      "Do not revert/clean unrelated changes unless explicitly requested.",
      "If unrelated changes block the task (e.g., merge conflict in the same file), ask for guidance."
    ]
  },
  "root_markdown": [
    {
      "path": "AGENTS.md",
      "bytes": 2882,
      "agent_onboarding": {
        "read": true,
        "priority": 1
      },
      "schema": "apm2.repo_agents.v1",
      "content_hash": "b3-256:03dec1a8695b1b2fa251539b171f609e713a7a6d440f0a6984a8f42ce2dd3d1d"
    },
    {
      "path": "SECURITY.md",
      "bytes": 497,
      "agent_onboarding": {
        "read": true,
        "priority": 2
      },
      "schema": "apm2.security_policy.v1",
      "content_hash": "b3-256:84e457f7c4114240f244e93ae8683c5cb3f2ea6ed7ea2ea7ced54b3b682b24e1"
    }
  ],
  "meta": {
    "generated_at_utc": "2026-01-28T00:00:00Z",
    "generator": {
      "id": "manual-docs-alignment",
      "version": "1.0.0"
    }
  }
}
