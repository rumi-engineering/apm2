# Zero-Tool Ideal (ZTI)

**Definition:** The architectural goal that an implementing holon should be able to complete its assigned work using only the preloaded context provided at initialization, without executing additional tool calls for information discovery.

**Scope and The Research Exemption:**
ZTI applies strictly to the **execution of scoped implementation tasks** (actuation). It does **NOT** apply to **Research Holons** or **Exploration Episodes** where the primary objective is discovery, mapping, or feasibility analysis. In research contexts, tool-based exploration is the *work object*, not a defect.

**The Inefficiency Defect:**
In an agent-native system, "exploring" the codebase or documentation during a scoped implementation task is treated as a failure of the planning/compilation stage. Any non-zero tool calls used primarily to discover missing context in these tasks are recorded as **Inefficiency Defects**.

## Exemptions
- **Research/Exploration Tasks:** Where discovery is the defined mission.
- **Verification Tools:** Compilers, linters, and test runners used for active inference and validation.

## Benefits
- **Determinism:** Precompiled context reduces the state space the agent must navigate.
- **Speed:** Actuation is faster than discovery.
- **Security:** "Deny-by-default" access outside the ContextPack prevents accidental leakage or distraction.

## See Also
- **ContextPack**: The artifact that enables ZTI.
- **Context Compilation**: The process of generating a ContextPack.
