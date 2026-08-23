# lantern-filesystem

**Content-addressed, encrypted-by-default, capability-gated, history-preserving** storage.
There is no global filesystem namespace — data is reached only through capabilities to
objects.

- **Layer:** system service (confined user space).
- **System context:** [wiki/Filesystem](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Filesystem.md).

> ⚠️ **Phase 2.** Content-addressed store v0 prototype in progress. See [`STATUS.md`](./STATUS.md).

## In this repo
- [`ARCHITECTURE.md`](./ARCHITECTURE.md), [`THREAT_MODEL.md`](./THREAT_MODEL.md), [`STATUS.md`](./STATUS.md).

## Four ideas
Content addressing (integrity + dedup + P2P-friendly) · encrypted by default (no plaintext
mode) · capability-gated access (open by cap, not by path) · immutable history & provenance
(snapshots, audit, attribution of agent writes).
