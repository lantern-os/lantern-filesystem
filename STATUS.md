# lantern-filesystem — Status

**Phase:** 0 (Foundations) — design only.

## Done
- Layered CAS + encryption + capability + history design drafted and reviewed ([ARCHITECTURE.md](./ARCHITECTURE.md)).
- Trade-offs and threat model documented and reviewed.

## Next
- Decide the block store / object model details and GC strategy.
- Phase 2: a content-addressed store v0 reachable only via granted capabilities.

## Blocked on
- Crypto keystore/AEAD ([`lantern-crypto`](https://github.com/lantern-os/lantern-crypto)).
- Capability brokering ([`lantern-capabilities`](https://github.com/lantern-os/lantern-capabilities)).
