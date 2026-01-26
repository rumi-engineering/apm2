# Defects in Holonic Agent Systems — Zero-Tool Ideal and Context Compilation

## 1. Zero-Tool Ideal (ZTI)
ZTI: an implementing holon SHOULD be spawned with all necessary context preloaded into its context window. Execution SHOULD be actuation, not exploration. This applies to **scoped implementation tasks**.

**The Research Exemption:**
ZTI does NOT apply to holons whose primary mission is **Research, Discovery, or Mapping**. For research tasks, tool-based exploration is the core work product and is not classified as an inefficiency.

Tool calls for context discovery in implementation tasks are inefficiency defects and must be minimized via compiler improvements.

## 2. ContextPacks
A ContextPack is a bounded allowlist of files, commands, schemas, and evidence needed for a task. ContextPacks MUST:
- fit a declared ContextBudget,
- be content-addressed and referenced from the ticket,
- be enforceable (deny-by-default access outside the pack),
- be sufficient for task completion under ZTI.

Any deviation between pack and actual access emits a context defect and updates the pack compiler.
