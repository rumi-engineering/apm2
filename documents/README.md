# APM2 Documentation Index

This directory contains all project documentation, standards, and specifications.

## Quick Navigation

| Directory | Purpose | Entry Point |
|-----------|---------|-------------|
| `standards/` | Schemas, enums, and lint rules | `standards/00_standards_meta.yaml` |
| `prds/` | Product Requirements Documents | `prds/template/` for new PRDs |
| `rfcs/` | Request for Comments | `rfcs/template/` for new RFCs |
| `protocol_profiles/` | Agent protocol configurations | |
| `skills/` | Agent skill definitions | `skills` |
| `work/` | Tickets and work tracking | `work/tickets/` |
| `coding/` | Coding guidelines | |
| `security/` | Security documentation | |
| `releases/` | Release documentation | |

## Standards

Standards define the schemas and validation rules for all documents.

```
documents/standards/
├── 00_standards_meta.yaml    # Entry point - start here
├── enums/                    # Enumerated types (status codes, roles, etc.)
├── schemas/                  # YAML schemas for PRDs, RFCs, tickets, etc.
└── lint/                     # Lint rules for document validation
```

**For agents:** To understand the document structure, read `standards/00_standards_meta.yaml` first, then explore `schemas/` for specific document types.

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

1. **Start with standards** - Read `standards/00_standards_meta.yaml`
2. **Understand schemas** - Check `standards/schemas/` for document structures
3. **Check enums** - `standards/enums/` defines all valid status codes and types
4. **Read the skill** - `skills/holonic-agent-network/SKILL.md` defines agent behavior
