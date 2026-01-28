# OCAP (Object-Capability)

A security model where authority to perform an action is represented by possession of an unforgeable token or handle ("capability").

In holonic networks, **OCAP** is used to grant **Holons** sealed tool interfaces that operate strictly on the hashes/selectors provided in their **ContextPack** (and governed by policy). This eliminates ambient authority (like broad filesystem access) and prevents "confused deputy" attacks.

Where possible, capabilities should be **intent-bound** (parameter- and object-scoped), e.g. "apply this specific diff hash that passed gates," not "write arbitrary files."
