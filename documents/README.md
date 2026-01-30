# APM2 Documentation Index

This directory contains all project documentation, standards, and specifications.

## Quick Navigation

| Directory | Purpose | Entry Point |
|-----------|---------|-------------|
| `standards/` | Document standards (schemas/enums/lint) + CAC specs | `standards/00_standards_meta.yaml` |
| `standards/cac/` | Context-as-Code (CAC) spec bundle (schemas/examples/volumes) | `standards/cac/MASTER.json` |
| `prds/` | Product Requirements Documents + AIPs | `prds/template/` |
| `rfcs/` | Request for Comments | `rfcs/template/` |
| `protocol_profiles/` | Protocol configuration profiles | `protocol_profiles/README.yaml` |
| `protocols/` | Normative runtime/agent protocols | `protocols/AGENT_EXIT_PROTOCOL.md` |
| `strategy/` | Strategy & SDLC pipeline | `strategy/SDLC_PIPELINE.md` |
| `skills/` | Agent skills (executable specifications) | `skills/README.md` |
| `work/` | Tickets and work tracking | `work/tickets/` |
| `reviews/` | Review prompts + CI expectations | `reviews/` |
| `security/` | Security documentation | `security/SECURITY_POLICY.md` |
| `releases/` | Release documentation | `releases/README.md` |

## Standards

Standards define the schemas and validation rules for all documents.

```
documents/standards/
├── 00_standards_meta.yaml    # Entry point - start here
├── cac/                      # Context-as-Code spec bundle (JSON)
├── enums/                    # Enumerated types (status codes, roles, etc.)
├── instructions/             # Shared instruction fragments and standards
├── schemas/                  # YAML schemas for PRDs, RFCs, tickets, etc.
└── lint/                     # Lint rules for document validation
```

**For agents:** To understand document structure, read `standards/00_standards_meta.yaml` first, then consult `standards/schemas/` for specific document types.

## Document Structure Convention

PRDs and RFCs use numbered YAML sections:

```
PRD-0001/
├── 00_meta.yaml              # Document metadata and IDs
├── 01_customer.yaml          # Customer definition
├── 02_problem.yaml           # Problem statement
├── 03_goals_scope.yaml       # Goals and scope
├── ...
├── requirements/             # Individual requirement files
└── evidence_artifacts/       # Evidence and proof artifacts
```

This convention enables:
- Predictable file locations across all documents
- Incremental loading (read only sections you need)
- Clear separation of concerns

## Creating New Documents

1. **New PRD:** Copy `prds/template/` to `prds/PRD-XXXX/`
2. **New RFC:** Copy `rfcs/template/` to `rfcs/RFC-XXXX/`
3. **New Ticket:** See `work/tickets/` for format

## For Agents

If you're an agent trying to understand this project:

1. **Root onboarding** - `AGENTS.md` + `ROOT_ONBOARDING.cac.md` (repo-level pointers) + `SECURITY.md` (security policy summary)
2. **Start with standards** - Read `standards/00_standards_meta.yaml`
3. **Understand schemas** - Check `standards/schemas/` for document structures
4. **Check enums** - `standards/enums/` defines valid status codes and types
5. **Use skills (preferred)** - `skills/glossary/SKILL.md` (terms), `skills/laws-of-holonic-agent-systems/SKILL.md` (laws), `skills/ticket-queue/SKILL.md` (orchestration), `skills/ticket/SKILL.md` (implementation)
