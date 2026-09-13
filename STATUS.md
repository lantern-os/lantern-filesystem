# lantern-filesystem — Status

**Phase:** 2 — opened per [RFC-0009](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0009-phase-1-to-phase-2-transition.md)/[ADR-0014](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0014-phase-1-complete-phase-2-opened.md), **closed** per [RFC-0017](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0017-phase-2-to-phase-3-transition.md)/[ADR-0021](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0021-phase-2-complete-phase-3-opened.md): the Phase 2 exit criterion is met (a confined Wasm app reads a file *only* via a granted capability — `lantern-example-signer`). This crate's "Next" items (chunking, per-object keys, version history) continue; the Roadmap's gate has moved to Phase 3. **`Store`'s admin API is confinable** (2026-09-13, mirroring `lantern_crypto::Keystore`'s identical treatment): `request_file_access`/`deliver_grant`/`deliver_grant_via_reply` take `&mut impl BrokerBackend`, `default-features = false` links only `lantern-abi`/`lantern-crypto`. **`Store::write`/`Store::read` now reach the AEAD key through a `Cipher` trait** (same day), with an in-process implementation (`InProcessCipher`, what every test and `lantern-runtime`'s `InProcessFilesystem` use) and a `Channel`-based one (`ChannelCipher`, for a confined `store-service` — the remaining ADR-0022 Part 1 piece for this crate). A live `store-service` demo proving `ChannelCipher` under QEMU is un-started — see "Next".

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
- **`Store`'s admin methods generalized to `BrokerBackend`** (2026-09-13,
  [RFC-0018](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0018-confined-execution-port.md)/[ADR-0022](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0022-confined-service-model-and-call-transport.md)) —
  mechanical, mirroring `lantern_crypto::Keystore`'s same-day port: `Store` dropped its
  `self_tcb: TcbId` field; `request_file_access`/`deliver_grant`/`deliver_grant_via_reply`
  take `&mut impl BrokerBackend`. `Cargo.toml` gained the matching `kernel-backend` feature
  split (`lantern-hal`/`lantern-kernel` optional; unconditional `lantern-abi`,
  `lantern-capabilities`/`lantern-crypto` both `default-features = false`). Also fixes the
  same real bug `lantern-crypto` found: `request_file_access` now mints `Rights::WRITE |
  Rights::GRANT` (was `READ | GRANT` — a confined client couldn't have `Call`ed through it).
  12 tests still green (`--features kernel-backend`, default); confined
  (`--no-default-features`) build + clippy clean on host and `riscv64`.
- **`Store::write`/`Store::read` generalized onto a `Cipher` trait** (2026-09-13, same
  round as the `lantern-kernel` IPC round-trip-loss fix that unblocked this): new
  `src/cipher.rs` — `Cipher::encrypt`/`decrypt` take only `nonce`/`aad`/`buffer` (no
  badge/key parameters; those are implicit in *how* a given `Cipher` was constructed).
  `Store` itself dropped its `aead_badge`/`aead_key` fields entirely — `Store::new` now
  takes only `self_cnode_cptr`, matching `Broker`'s own "no backend state of its own"
  split one layer down. Two implementations: `InProcessCipher` (wraps a direct
  `&Keystore` reference plus the badge/key this store was granted — what every test in
  this crate, and `lantern-runtime`'s `InProcessFilesystem` stand-in, use) and
  `ChannelCipher` (issues real `Channel::call`s to a confined `keystore-service` over
  `lantern_crypto::wire`'s `OP_ENCRYPT`/`OP_DECRYPT` codecs — builds confined,
  `default-features = false`, unverified under real QEMU yet, see "Next"). 12 tests
  green (updated to construct an `InProcessCipher` per call); clean clippy on host
  (default + `--no-default-features`) and `riscv64` (`--no-default-features`).
  `lantern-runtime`'s `InProcessFilesystem` updated to match (`FilesystemService::read`/
  `write` build an `InProcessCipher` per call instead of relying on `Store`'s own
  now-removed fields) — 23+28 `lantern-runtime` tests green.

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
- **A live, confined `store-service` demo proving `ChannelCipher` under real QEMU** — the
  `Cipher` trait redesign above is done and unit-tested, but `ChannelCipher` itself has
  only ever been exercised by the type checker, not a real `Channel::call` round trip. A
  real demo needs *three* confined programs (`keystore-service`, `store-service`, a
  client) — `store-service` holds a real `Store` but reaches its AEAD key only via a
  `ChannelCipher` wrapping its own granted `Channel` to `keystore-service`, exactly the
  shape `lantern-boot-keystore-demo` already proved for the keystore leg alone. No
  longer blocked on anything (the `lantern-kernel` scheduling bug is fixed) — just
  un-started integration work.
  **Progress from the other side:** `lantern-runtime` now exposes a `lantern:host/filesystem`
  WIT interface and the resource-scoped `file`-handle ⇄ badge mapping that reaches it
  ([RFC-0016](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0016-filesystem-wit-interface.md)/[ADR-0019](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0019-filesystem-wit-interface.md),
  `lantern-runtime/STATUS.md`) — shaped like `Store` (a `FileId` by handle, no paths), it
  drives a *real* `Store` today via an in-process `InProcessFilesystem` stand-in. What's
  still missing is exactly this crate's confined-IPC-service form, not the Wasm-guest-facing
  surface.

## Blocked on
- ~~Crypto keystore/AEAD ([`lantern-crypto`](https://github.com/lantern-os/lantern-crypto)).~~ Resolved — `Keystore`
  is real (`lantern-crypto/STATUS.md`), and this crate now builds on it.
- ~~Capability brokering ([`lantern-capabilities`](https://github.com/lantern-os/lantern-capabilities)).~~ Resolved —
  `Broker` is real and proven (`lantern-capabilities/STATUS.md`), and this crate now builds
  on it.
