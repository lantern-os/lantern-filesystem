# lantern-filesystem — Status

**Phase:** 2 (Capability runtime & first services) — open per [RFC-0009](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0009-phase-1-to-phase-2-transition.md)/[ADR-0014](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0014-phase-1-complete-phase-2-opened.md). Still fully blocked — see "Blocked on".

## Done
- Layered CAS + encryption + capability + history design drafted and reviewed ([ARCHITECTURE.md](./ARCHITECTURE.md)).
- Trade-offs and threat model documented and reviewed.

## Next
- Decide the block store / object model details and GC strategy.
- Phase 2: a content-addressed store v0 reachable only via granted capabilities.

## Blocked on
- Crypto keystore/AEAD ([`lantern-crypto`](https://github.com/lantern-os/lantern-crypto)).
- Capability brokering ([`lantern-capabilities`](https://github.com/lantern-os/lantern-capabilities)).
