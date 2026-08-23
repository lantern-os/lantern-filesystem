# lantern-filesystem — Status

**Phase:** 2 (Capability runtime & first services) — open per [RFC-0009](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0009-phase-1-to-phase-2-transition.md)/[ADR-0014](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0014-phase-1-complete-phase-2-opened.md). First prototype code now exists — see "Done".

## Done
- Layered CAS + encryption + capability + history design drafted and reviewed ([ARCHITECTURE.md](./ARCHITECTURE.md)).
- Trade-offs and threat model documented and reviewed.
- **First prototype code merged** (`src/lib.rs`): a fixed-capacity `Store` of content-addressed,
  AEAD-encrypted, refcounted blocks named by `FileId` capability objects, gated through a
  composed [`lantern-capabilities`](https://github.com/lantern-os/lantern-capabilities) `Broker` — the same badge-gated
  shape [`lantern-crypto`](https://github.com/lantern-os/lantern-crypto)'s `Keystore` already established, one layer up.
  Needed no dedicated RFC: [ADR-0014](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0014-phase-1-complete-phase-2-opened.md)
  already pre-authorised "a content-addressed filesystem v0" as Phase 2 prototype work, and
  this crate composes only already-accepted mechanisms (RFC-0003/RFC-0010's capability
  model, RFC-0007's BLAKE3/AEAD primitives) — the same precedent `Keystore`'s own AEAD/
  signing/MAC work set. This resolves the "decide the block store / object model details and
  GC strategy" item that was blocking this crate, as a set of deliberately narrow v0 slices
  (each documented in `src/lib.rs`'s own top-level doc, not silently decided):
  - **One block per file**, capped at `MAX_BLOCK_LEN` (256 B) — real chunking for larger
    content is `ARCHITECTURE.md`'s own open question, deferred (see "Next").
  - **A single store-wide AEAD key for v0**, reached only through `Keystore`'s own
    badge-gated `encrypt`/`decrypt` — `Store` never holds raw key material itself, matching
    "no raw keys to apps" one layer up. Per-object keys (`ARCHITECTURE.md`'s eventual design)
    are deferred.
  - **Content addressing hashes plaintext; the stored body is ciphertext** — what makes
    deduplication (a real refcount, not nominal) meaningful across encrypted objects. The
    acknowledged cost (two objects with identical plaintext become linkable by address)
    matches F6's existing "acknowledged, not solved at Phase 0" framing (`THREAT_MODEL.md`).
  - **The AEAD nonce is derived from the content hash itself**, not sourced from randomness
    — sound because deduplication guarantees a given plaintext is only ever encrypted once
    under the store's key, which is exactly the property nonce uniqueness needs (X4).
  - **GC is immediate, exact reference counting.** v0 blocks never reference other blocks
    (no chunking tree yet), so the reference graph is acyclic by construction and refcounting
    is complete: a block's slot frees the instant its refcount hits zero and is reused
    freely — unlike `FileId`, which (like `lantern-crypto`'s `KeyId`) is never reused after
    `Store::destroy`, since it's externally badge-visible and reuse would be a real
    confused-deputy bug.
  12 unit tests pass, each exercising the mechanism against a real
  `lantern_kernel::state::KernelState` with a real composed `Keystore` and real IPC-driven
  grants (crypto-service thread, filesystem-service thread, and per-grant client threads —
  the same discipline `lantern-capabilities`/`lantern-crypto`'s own test suites follow),
  covering write/read round-trips, deduplication, refcount-driven GC on both destroy and
  rewrite, and the full badge-gating deny-by-default surface (unknown/revoked/wrong-file/
  wrong-op). `cargo clippy -D warnings` clean on host and `riscv64gc-unknown-none-elf`
  (debug and release).

## Next
- Multi-block chunking for content larger than `MAX_BLOCK_LEN` — `ARCHITECTURE.md`'s
  "efficient large-file... patterns over CAS" open question.
- Per-object AEAD keys, replacing v0's single store-wide key.
- Immutable version history / provenance (`ARCHITECTURE.md`'s fourth pillar) — v0 only
  tracks a file's *current* block, not prior versions.
- Wire `Caveat::ExpiresAt`/sealed-capability unsealing
  ([RFC-0011](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0011-sealed-capability-token-format.md)) into file-access
  grants once a real consumer needs cross-machine sharing — `lantern-crypto/STATUS.md`'s own
  "Next" already names this crate as the missing concrete consumer.
- Turning `Store` into deployable confined-service code needs `lantern-runtime`'s
  not-yet-built confined execution environment, same gap `lantern-capabilities`/
  `lantern-crypto` both document for `Broker`/`Keystore` — this crate's methods still take
  `&mut KernelState` directly, valid only for privileged, same-address-space code.

## Blocked on
- ~~Crypto keystore/AEAD ([`lantern-crypto`](https://github.com/lantern-os/lantern-crypto)).~~ Resolved — `Keystore`
  is real (`lantern-crypto/STATUS.md`), and this crate now builds on it.
- ~~Capability brokering ([`lantern-capabilities`](https://github.com/lantern-os/lantern-capabilities)).~~ Resolved —
  `Broker` is real and proven (`lantern-capabilities/STATUS.md`), and this crate now builds
  on it.
