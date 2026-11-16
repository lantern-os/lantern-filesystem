# lantern-filesystem

**Content-addressed, encrypted-by-default, capability-gated, history-preserving** storage.
There is no global filesystem namespace — data is reached only through capabilities to
objects.

- **Layer:** system service (confined user space).
- **System context:** [wiki/Filesystem](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Filesystem.md).

> **Phase 4** ([RFC-0036](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0036-phase-3-to-phase-4-transition.md)): hardware and assurance. The store runs as a confined service, sealed on the disk, and keeps who wrote each file. Its key
> is a software-held demo key until Phase 4's hardware root of trust. See [`STATUS.md`](./STATUS.md).

## In this repo
- [`ARCHITECTURE.md`](./ARCHITECTURE.md), [`THREAT_MODEL.md`](./THREAT_MODEL.md), [`STATUS.md`](./STATUS.md).

## Four ideas
Content addressing (integrity + dedup + P2P-friendly) · encrypted by default (no plaintext
mode) · capability-gated access (open by cap, not by path) · immutable history & provenance
(snapshots, audit, attribution of agent writes).
