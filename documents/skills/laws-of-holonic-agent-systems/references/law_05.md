---
id: LAW-05
name: Dual-Axis Containment
effective_date: 2026-01-27
citation: apm2://skills/laws-of-holonic-agent-systems
status: active
---

# Law 05: Dual-Axis Containment

## The Law
Containment requires both **Authority (Capabilities)** and **Accountability (Identity/Audit)**.

## Operationalization
1. **ContextRead Firewalls:** Access to context must be as strictly controlled as access to tools.
2. **Confused-Deputy Prevention:** Agents must not be able to "know" things they are not authorized to "act" upon if that knowledge facilitates unauthorized actuation.
3. **Audit Trail:** Every capability use must be linked back to a stable identity and work ID.
4. **Relay-Mediated Connectivity:** Connectivity for contained agents MUST use authenticated management tunnels (Relays) to preserve the outbound-only security boundary while enabling distributed consensus.

## Rationale
Limiting what an agent can *do* is insufficient if the agent can *know* everything. Security in a holonic system requires controlling the information flow into the cognitive process.
