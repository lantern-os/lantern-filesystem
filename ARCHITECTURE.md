# lantern-filesystem — Architecture

Companion to [wiki/Filesystem](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Filesystem.md).

## Layering
```
  names & directories (capability objects)        ← what apps see
  versioned object model (history, provenance)
  encryption layer (per-object keys via lantern-crypto)
  content-addressed block store (hash-named blocks, dedup)
  block-device drivers (confined user space)
```
The whole stack is a confined user-space service: a filesystem bug cannot reach the kernel or
other services, only the data it holds capabilities to.

## Key decisions
- **Content addressing**: blocks named by cryptographic hash → integrity by construction,
  free dedup, natural fit for [P2P sync](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Networking.md).
- **Encrypted by default**: per-object keys from [`lantern-crypto`](https://github.com/lantern-os/lantern-crypto), bound
  to a hardware root of trust where possible; no plaintext-at-rest mode is offered.
- **Capability access**: directories are capability objects; you open an object because you
  hold a cap, not because you can name a path → no path-based ambient authority, no
  TOCTOU-by-path.
- **Immutable history + provenance**: updates create new versions; each version records which
  component/agent wrote it under which capability → snapshots, audit, and trustable
  attribution of [AI](https://github.com/lantern-os/lantern-docs/blob/main/wiki/AI.md) outputs.

## Documented trade-offs
CAS → cheap dedup/integrity but mutation = rewrite+relink and GC complexity. Encrypted →
confidentiality on loss but key management is critical-path. Immutable history → audit/snapshots
but storage growth needs compaction. Capability access → no ambient authority but needs
ergonomic granting UX.

## Open questions
- GC/retention for an immutable, deduplicated, encrypted store.
- Efficient large-file / random-write patterns over CAS.
- Searchable encryption vs. local plaintext indices.
- Key rotation over long-lived encrypted history.
- Multi-device local-first sync/conflict model (CRDTs?).
