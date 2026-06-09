# lantern-filesystem — Threat Model

Inherits the [system threat model](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Threat-Model.md). Protects user data
at rest and the integrity/provenance of stored objects (system threats T1, T6).

## Assets
- Confidentiality of data at rest.
- Integrity of stored content (tamper-evidence via content addressing).
- Provenance records (who/what wrote each version).
- Access mediation (only cap holders read/write).

## Threats and mitigations
| # | Threat | Mitigation |
| --- | --- | --- |
| F1 | Device theft exposes data | Encrypted by default; keys hardware-bound via [`lantern-crypto`](https://github.com/lantern-os/lantern-crypto). |
| F2 | An app reads files it wasn't granted | Capability-gated objects; no global namespace; no path-based access. |
| F3 | Silent tampering with stored data | Content addressing: any change changes the hash; verified on read. |
| F4 | Forged provenance (agent disowns/blames a write) | Provenance bound to the capability used; recorded in immutable history. |
| F5 | A compromised filesystem service reads everything | Confined service; holds caps only to mounted objects; keys stay in crypto service. |
| F6 | Metadata leakage (sizes, access patterns) | Acknowledged; padding/oblivious-access are research directions, not solved at Phase 0. |

## Non-goals
- Hiding all access-pattern metadata (Phase 0).
- Plaintext recovery without keys (by design there is none).
