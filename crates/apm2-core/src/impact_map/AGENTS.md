# Impact Map Module

## Purpose

The impact_map module maps PRD requirements to existing codebase components identified in the CCP (Code Context Protocol) index. It bridges requirements and implementation by:

- Parsing PRD requirement YAML files
- Matching requirements to CCP components via keyword similarity (Jaccard coefficient)
- Detecting duplication risks when multiple extension points are viable
- Classifying unmapped requirements as "net-new substrate"
- Generating deterministic YAML output for downstream RFC framing

## Key Types

### Core Data Structures

| Type | Description |
|------|-------------|
| `ImpactMap` | Complete impact map output containing mappings, adjudication, and summary |
| `MappedRequirement` | A requirement with its ranked candidate components |
| `CandidateComponent` | A component match with fit score and rationale |
| `UnresolvedMapping` | A requirement that could not be matched and needs human/LLM review |
| `FitScore` | Confidence level for matches: High, Medium, Low |

### Adjudication Types

| Type | Description |
|------|-------------|
| `AdjudicationResult` | Analysis result with duplication risks and net-new classifications |
| `DuplicationRisk` | Warning when multiple extension points could satisfy a requirement |
| `NetNewClassification` | Classification for requirements without strong component matches |
| `DuplicationSeverity` | Risk severity: High, Medium, Low |

### Configuration

| Type | Description |
|------|-------------|
| `ImpactMapBuildOptions` | Options for build (force, dry_run) |
| `ImpactMapBuildResult` | Result containing impact map and output path |
| `ImpactMapSummary` | Statistics: total, matched, needs_review, net_new, unresolved |

## Invariants

- **[INV-0001]** Impact map output is deterministic: same inputs produce identical YAML
- **[INV-0002]** All requirements are either mapped to components, classified as net-new, or marked unresolved
- **[INV-0003]** Duplication risks are flagged when multiple extension points match
- **[INV-0004]** Output files use canonical YAML formatting with sorted keys
- **[INV-MAPPER-001]** Requirement IDs are unique within a PRD
- **[INV-MAPPER-002]** Candidates are sorted by fit score (descending)
- **[INV-MAPPER-003]** All parsed requirements are included in output

## Path Safety

All functions that accept `prd_id` validate it to prevent path traversal attacks:

- PRD IDs must not contain `/`, `\`, or `..`
- Paths are canonicalized and verified to stay within repo root
- File reads are bounded to prevent denial-of-service

## Matching Algorithm

The matcher uses a multi-stage approach:

1. **Exact substring match** on component description or module names (highest priority)
2. **Word-level Jaccard similarity** (threshold >= 0.3 for candidate inclusion)
3. **Fit score assignment**:
   - High: exact match or Jaccard >= 0.6
   - Medium: Jaccard >= 0.4
   - Low: Jaccard >= 0.3
4. **Unresolved**: Requirements with no matches above threshold are placed in `unresolved_mappings` for human/LLM review

## Output Location

Impact maps are written to:
```
evidence/prd/<PRD-ID>/impact_map/impact_map.yaml
```

## Contracts

- **[CTR-0001]** `build_impact_map` requires a valid CCP index to exist
- **[CTR-0002]** PRD requirements directory must exist and contain YAML files
- **[CTR-0003]** Output directory is created if it doesn't exist
- **[CTR-0004]** Atomic writes ensure no partial/corrupt files on crash

## Security

- **[SEC-0001]** File reads are bounded to prevent denial-of-service (1MB per file, 1000 files max)
- **[SEC-0002]** Path traversal is prevented by PRD ID validation and canonicalization
- **[SEC-0003]** Only files within repo root are processed
- **[SEC-0004]** All serde structs use `deny_unknown_fields` to reject malformed input
