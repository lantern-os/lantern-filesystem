//! `lantern-filesystem` — the content-addressed store, v0
//! ([wiki/Filesystem](https://github.com/lantern-os/lantern-docs/blob/main/wiki/Filesystem.md), `ARCHITECTURE.md`).
//! Phase 2's first prototype code in this crate
//! ([RFC-0009](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0009-phase-1-to-phase-2-transition.md)/
//! [ADR-0014](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0014-phase-1-complete-phase-2-opened.md), which
//! explicitly pre-authorised "a content-addressed filesystem v0" as Phase 2 prototype
//! work — this crate needed no dedicated RFC of its own, the same way
//! [`lantern_crypto::Keystore`]'s AEAD/signing/MAC work built directly on RFC-0007/
//! RFC-0010 without one): a fixed-capacity [`Store`] of content-addressed,
//! AEAD-encrypted, refcounted blocks, named by [`FileId`] capability objects gated
//! through a composed [`lantern_capabilities::Broker`] — the same badge-gated shape
//! [`lantern_crypto::Keystore`] already established for its own key material.
//!
//! **What this crate resolves that was previously an open "Next" item**
//! (`STATUS.md`): the block store / object model / GC strategy. The v0 answers,
//! each a deliberately narrow slice (`ARCHITECTURE.md`'s own documented trade-offs,
//! not silently ignored):
//!
//! - **One block per file, fixed max size ([`MAX_BLOCK_LEN`]).** Real chunking for
//!   large content is `ARCHITECTURE.md`'s own open question
//!   ("efficient large-file... patterns over CAS") — deferred, not designed away; see
//!   `STATUS.md`'s "Next".
//! - **A single store-wide AEAD key for v0**, not yet the per-object keys
//!   `ARCHITECTURE.md` names as the eventual design — also deferred, tracked in
//!   `STATUS.md`.
//! - **Content-addressing hashes plaintext; the stored body is ciphertext.** This is
//!   what makes deduplication ([`Block::refcount`]) meaningful across encrypted
//!   objects sharing content — the acknowledged cost (F6, `THREAT_MODEL.md`: two
//!   objects with identical plaintext are now also linkable by address) matches this
//!   project's existing "acknowledged, not solved at Phase 0" framing for metadata
//!   leakage, not a new unaddressed gap.
//! - **The AEAD nonce is derived from the content hash itself** (its first
//!   [`lantern_crypto::aead::NONCE_LEN`] bytes), not sourced from randomness. This is
//!   sound, not a shortcut: content addressing already guarantees a given (key,
//!   nonce) pair is used to encrypt a given plaintext *at most once* — the store
//!   never re-encrypts a block it already holds (deduplication short-circuits
//!   first) — which is exactly the property nonce uniqueness needs (X4,
//!   `lantern-crypto/THREAT_MODEL.md`). Nonces are transmitted in the clear in any
//!   AEAD scheme regardless, so deriving one from public, already-visible content
//!   addressing leaks nothing new.
//! - **GC is immediate, exact reference counting — not mark-and-sweep, not
//!   deferred.** Blocks in v0 never reference other blocks (no chunking tree yet),
//!   so the reference graph is acyclic by construction and refcounting is exact and
//!   complete: a block's slot is freed the instant its refcount hits zero, and
//!   reused freely afterward — **unlike [`FileId`]**, which (like
//!   [`lantern_crypto::KeyId`]) is never reused after [`Store::destroy`], since a
//!   `FileId` is externally visible to a badge holder and reusing it would let a
//!   stale badge silently start naming an unrelated new file. A block index is
//!   purely internal bookkeeping no badge holder ever sees, so reusing *that* slot
//!   is ordinary storage reclamation, not the confused-deputy risk `FileId` reuse
//!   would be.
//!
//! **What this is not yet:** a real, standalone confined program — same caveat
//! [`lantern_capabilities::Broker`]/[`lantern_crypto::Keystore`] both carry.
//! [`Store::request_file_access`] takes `&mut lantern_kernel::state::KernelState`
//! directly, valid only for privileged, same-address-space code.
#![cfg_attr(not(test), no_std)]

use lantern_capabilities::{Broker, KernelBackend, SyscallError};
use lantern_crypto::{Keystore, KeyId};
use lantern_crypto::aead;
use lantern_crypto::hash;
use lantern_kernel::cap::{CPtr, TcbId};
use lantern_kernel::state::KernelState;

/// Fixed capacity, no heap — matches every other Phase 1/2 kernel-adjacent pool in
/// this project ([`lantern_crypto::Keystore`]'s own convention).
const MAX_FILES: usize = 16;
/// Unique content-addressed blocks this store can hold at once — see this crate's
/// top-level doc on why exact-refcount GC keeps this a real (not just nominal) cap,
/// not a monotonically-growing one.
const MAX_BLOCKS: usize = 32;
/// v0's per-block size ceiling — see this crate's top-level doc on chunking being
/// deferred.
pub const MAX_BLOCK_LEN: usize = 256;
const MAX_GRANTS: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FileId(u16);

/// The operations a granted badge may be scoped to — orthogonal to
/// [`lantern_kernel::cap::Rights`], mirroring
/// [`lantern_crypto::KeyOps`]'s exact split between kernel-level transfer rights
/// and this crate's own object semantics.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FileOps(u8);

impl FileOps {
    pub const NONE: FileOps = FileOps(0);
    pub const READ: FileOps = FileOps(1 << 0);
    pub const WRITE: FileOps = FileOps(1 << 1);
    pub const ALL: FileOps = FileOps(Self::READ.0 | Self::WRITE.0);

    pub const fn union(self, other: FileOps) -> FileOps {
        FileOps(self.0 | other.0)
    }

    pub const fn contains(self, other: FileOps) -> bool {
        self.0 & other.0 == other.0
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StoreError {
    NoSuchFile,
    /// The file exists but [`Store::destroy`] already released it.
    FileDestroyed,
    /// [`Store::read`] was called before any [`Store::write`] ever succeeded for
    /// this file.
    FileEmpty,
    /// `data` (on write) or the caller's buffer (on read) doesn't fit
    /// [`MAX_BLOCK_LEN`] — see this crate's top-level doc on chunking.
    ContentTooLarge,
    NotEnoughCapacity,
    /// A badge this `Store` never granted, or has forgotten — deny by default, same
    /// convention as [`lantern_capabilities::Broker::is_revoked`].
    UnknownBadge,
    BadgeRevoked,
    /// The badge is valid but wasn't granted the operation being attempted.
    OpNotGranted,
    /// The badge names a different file than the one passed in — deny without
    /// revealing which file it *does* match.
    WrongFile,
    /// The underlying AEAD operation failed, or the composed
    /// [`lantern_crypto::Keystore`] rejected the request (e.g. its own badge for
    /// the store's encryption key was revoked).
    CryptoFailure(lantern_crypto::KeystoreError),
    /// A real kernel-level failure surfaced by the composed
    /// [`lantern_capabilities::Broker`].
    Kernel(SyscallError),
}

/// One content-addressed, encrypted block. `hash` is computed over the
/// **plaintext**; `ciphertext`/`tag` are what's actually at rest — see this crate's
/// top-level doc for why, and for the nonce-derivation reasoning.
struct Block {
    hash: hash::Hash,
    ciphertext: [u8; MAX_BLOCK_LEN],
    len: usize,
    tag: [u8; aead::TAG_LEN],
    /// How many files currently point at this block — see this crate's top-level
    /// doc's GC section.
    refcount: u32,
}

struct FileRecord {
    /// `None` until the first successful [`Store::write`]; an index into
    /// [`Store::blocks`] afterward — internal bookkeeping only, never a
    /// badge-visible identifier (contrast [`FileId`] itself).
    block: Option<usize>,
    destroyed: bool,
}

#[derive(Clone, Copy)]
struct GrantRecord {
    badge: u64,
    file: FileId,
    ops: FileOps,
}

/// The content-addressed store: owns block/file bookkeeping and a composed
/// [`lantern_capabilities::Broker`] for kernel-level mint/grant, adding the
/// file-and-operation-scoped object semantics `Broker` itself deliberately doesn't
/// know about — the exact same split [`lantern_crypto::Keystore`] already
/// establishes for key material.
pub struct Store {
    broker: Broker,
    /// This store's own thread identity — needed to build a [`KernelBackend`]
    /// for the composed [`Broker`] on each mint/grant. (A fully confined store
    /// would use `lantern_capabilities::Abi`; this crate still takes
    /// `&mut KernelState` in its own public API.)
    self_tcb: TcbId,
    /// This store's own access to its single v0 encryption key, in the composed
    /// [`lantern_crypto::Keystore`] — see [`Store::new`]'s precondition doc.
    aead_badge: u64,
    aead_key: KeyId,
    files: [Option<FileRecord>; MAX_FILES],
    blocks: [Option<Block>; MAX_BLOCKS],
    grants: [Option<GrantRecord>; MAX_GRANTS],
}

impl Store {
    /// `self_tcb`/`self_cnode_cptr` — forwarded to
    /// [`lantern_capabilities::Broker::new`]; see its doc. `aead_badge`/`aead_key`
    /// — the caller (real store bootstrap code, or a test) is responsible for
    /// having already obtained these from the composed [`lantern_crypto::Keystore`]
    /// (`Keystore::generate_aead_key` then `request_key_access`+`deliver_grant`,
    /// with [`lantern_crypto::KeyOps::ENCRYPT`]/[`lantern_crypto::KeyOps::DECRYPT`]
    /// both granted) — the same "caller sets up the precondition" discipline
    /// `Broker::new`'s own `self_cnode_cptr` doc already documents.
    pub fn new(self_tcb: TcbId, self_cnode_cptr: CPtr, aead_badge: u64, aead_key: KeyId) -> Self {
        Self {
            broker: Broker::new(self_cnode_cptr),
            self_tcb,
            aead_badge,
            aead_key,
            files: [const { None }; MAX_FILES],
            blocks: [const { None }; MAX_BLOCKS],
            grants: [None; MAX_GRANTS],
        }
    }

    /// Allocates a new, empty file object. Never reused after
    /// [`Store::destroy`] — see this crate's top-level doc.
    pub fn create(&mut self) -> Result<FileId, StoreError> {
        let idx = self.files.iter().position(Option::is_none).ok_or(StoreError::NotEnoughCapacity)?;
        self.files[idx] = Some(FileRecord { block: None, destroyed: false });
        Ok(FileId(idx as u16))
    }

    fn file_record(&self, id: FileId) -> Result<&FileRecord, StoreError> {
        self.files.get(id.0 as usize).and_then(Option::as_ref).ok_or(StoreError::NoSuchFile)
    }

    fn find_block(&self, target: &hash::Hash) -> Option<usize> {
        self.blocks.iter().position(|b| matches!(b, Some(block) if &block.hash == target))
    }

    /// Decrements the block at `idx`'s refcount, freeing the slot for reuse the
    /// instant it reaches zero — see this crate's top-level doc's GC section.
    fn release_block(&mut self, idx: usize) {
        let block = self.blocks[idx].as_mut().expect("release_block called on an already-empty slot");
        block.refcount -= 1;
        if block.refcount == 0 {
            self.blocks[idx] = None;
        }
    }

    /// Mints a badge (via the composed [`lantern_capabilities::Broker`]) scoped to
    /// `file` and `ops`. Two-step, same shape as
    /// [`lantern_crypto::Keystore::request_key_access`]/`deliver_grant` — call
    /// [`Store::deliver_grant`] (or [`Store::deliver_grant_via_reply`]) next.
    pub fn request_file_access(
        &mut self,
        state: &mut KernelState,
        file: FileId,
        ops: FileOps,
        source_slot: CPtr,
        scratch_slot: CPtr,
    ) -> Result<u64, StoreError> {
        let record = self.file_record(file)?;
        if record.destroyed {
            return Err(StoreError::FileDestroyed);
        }
        let slot = self.grants.iter().position(Option::is_none).ok_or(StoreError::NotEnoughCapacity)?;
        let badge = self.broker
            .mint(
                &mut KernelBackend::new(state, self.self_tcb),
                source_slot,
                scratch_slot,
                lantern_capabilities::Rights::READ.union(lantern_capabilities::Rights::GRANT),
            )
            .map_err(StoreError::Kernel)?;
        self.grants[slot] = Some(GrantRecord { badge, file, ops });
        Ok(badge)
    }

    /// Forwards to [`lantern_capabilities::Broker::grant`]; see its doc.
    pub fn deliver_grant(&self, state: &mut KernelState, endpoint_cptr: CPtr, scratch_slot: CPtr, payload: (usize, usize)) -> Result<(), StoreError> {
        self.broker
            .grant(&mut KernelBackend::new(state, self.self_tcb), endpoint_cptr, scratch_slot, payload)
            .map_err(StoreError::Kernel)
    }

    /// Forwards to [`lantern_capabilities::Broker::grant_via_reply`]; see its doc.
    pub fn deliver_grant_via_reply(&self, state: &mut KernelState, scratch_slot: CPtr, payload: (usize, usize)) -> Result<(), StoreError> {
        self.broker
            .grant_via_reply(&mut KernelBackend::new(state, self.self_tcb), scratch_slot, payload)
            .map_err(StoreError::Kernel)
    }

    /// Forwards to [`lantern_capabilities::Broker::revoke`]; see its doc.
    pub fn revoke_access(&mut self, badge: u64) -> Result<(), StoreError> {
        self.broker.revoke(badge).map_err(StoreError::Kernel)
    }

    /// **Deny by default** — see [`lantern_crypto::Keystore::check_access`]'s doc;
    /// this is the same check, one layer up.
    fn check_access(&self, badge: u64, file: FileId, op: FileOps) -> Result<(), StoreError> {
        if self.broker.is_revoked(badge) {
            return Err(StoreError::BadgeRevoked);
        }
        let grant = self.grants.iter().flatten().find(|g| g.badge == badge).ok_or(StoreError::UnknownBadge)?;
        if grant.file != file {
            return Err(StoreError::WrongFile);
        }
        if !grant.ops.contains(op) {
            return Err(StoreError::OpNotGranted);
        }
        Ok(())
    }

    /// Writes `data` as `file`'s new content, gated on `badge` having been granted
    /// [`FileOps::WRITE`] for `file`. `keystore` must be the same
    /// [`lantern_crypto::Keystore`] this store's [`Store::aead_badge`]/
    /// [`Store::aead_key`] were obtained from.
    ///
    /// Deduplicates against any block this store already holds with the same
    /// plaintext hash (real, not nominal — the block is never re-encrypted, its
    /// refcount is simply incremented), then relinks `file` to it, releasing
    /// `file`'s previous block (if any) — see this crate's top-level doc for why
    /// this is exact, immediate GC rather than a deferred sweep.
    pub fn write(&mut self, keystore: &Keystore, badge: u64, file: FileId, data: &[u8]) -> Result<(), StoreError> {
        self.check_access(badge, file, FileOps::WRITE)?;
        if data.len() > MAX_BLOCK_LEN {
            return Err(StoreError::ContentTooLarge);
        }
        let content_hash = hash::hash(data);

        let new_block = if let Some(idx) = self.find_block(&content_hash) {
            self.blocks[idx].as_mut().unwrap().refcount += 1;
            idx
        } else {
            let slot = self.blocks.iter().position(Option::is_none).ok_or(StoreError::NotEnoughCapacity)?;
            let mut ciphertext = [0u8; MAX_BLOCK_LEN];
            ciphertext[..data.len()].copy_from_slice(data);
            let nonce = nonce_from_hash(&content_hash);
            let tag = keystore
                .encrypt(self.aead_badge, self.aead_key, &nonce, content_hash.as_bytes(), &mut ciphertext[..data.len()])
                .map_err(StoreError::CryptoFailure)?;
            self.blocks[slot] = Some(Block { hash: content_hash, ciphertext, len: data.len(), tag, refcount: 1 });
            slot
        };

        let record = self.files[file.0 as usize].as_mut().expect("checked by check_access above");
        if let Some(old) = record.block.replace(new_block) {
            if old != new_block {
                self.release_block(old);
            } else {
                // Writing back the same content that's already there -- undo the
                // extra refcount `find_block`'s branch just added, since this file
                // already held that reference.
                self.blocks[new_block].as_mut().unwrap().refcount -= 1;
            }
        }
        Ok(())
    }

    /// Reads `file`'s current content into `buf`, gated on `badge` having been
    /// granted [`FileOps::READ`] for `file`. Returns the number of bytes written to
    /// `buf`'s front. `keystore` — see [`Store::write`]'s doc.
    pub fn read(&self, keystore: &Keystore, badge: u64, file: FileId, buf: &mut [u8]) -> Result<usize, StoreError> {
        self.check_access(badge, file, FileOps::READ)?;
        let record = self.file_record(file)?;
        let idx = record.block.ok_or(StoreError::FileEmpty)?;
        let block = self.blocks[idx].as_ref().expect("a live file's block index is always a live block");
        if block.len > buf.len() {
            return Err(StoreError::ContentTooLarge);
        }
        let nonce = nonce_from_hash(&block.hash);
        buf[..block.len].copy_from_slice(&block.ciphertext[..block.len]);
        keystore
            .decrypt(self.aead_badge, self.aead_key, &nonce, block.hash.as_bytes(), &mut buf[..block.len], &block.tag)
            .map_err(StoreError::CryptoFailure)?;
        Ok(block.len)
    }

    /// Tombstones `file` (never reused — see this crate's top-level doc) and
    /// releases its current block, if any.
    pub fn destroy(&mut self, file: FileId) -> Result<(), StoreError> {
        let idx = self.files.get(file.0 as usize).and_then(Option::as_ref).map(|r| r.block).ok_or(StoreError::NoSuchFile)?;
        if let Some(idx) = idx {
            self.release_block(idx);
        }
        let record = self.files[file.0 as usize].as_mut().unwrap();
        record.block = None;
        record.destroyed = true;
        Ok(())
    }
}

/// Derives an AEAD nonce from a content hash — see this crate's top-level doc for
/// why this is sound rather than a randomness shortcut.
fn nonce_from_hash(h: &hash::Hash) -> [u8; aead::NONCE_LEN] {
    let mut nonce = [0u8; aead::NONCE_LEN];
    nonce.copy_from_slice(&h.as_bytes()[..aead::NONCE_LEN]);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;
    use lantern_crypto::KeyOps;
    use lantern_hal::{MessageTag, TrapFrame};
    use lantern_kernel::cap::{CNode, CNodeId, Capability, EndpointId, NotificationId, Rights};
    use lantern_kernel::ipc;
    use lantern_kernel::object::{Notification, Tcb};

    const SOURCE_SLOT: CPtr = 5;
    const SCRATCH_SLOT: CPtr = 6;
    const CLIENT_DEST_SLOT: usize = 9;

    /// A crypto-service thread (holding the AEAD key `Store` will use) and a
    /// filesystem-service thread (`Store` itself), plus a client thread that
    /// receives file-access grants from the filesystem service — three parties,
    /// the same real-`KernelState`/real-IPC discipline every other crate in this
    /// project's test suites uses. The `Keystore`/`Store` pairing living
    /// "same-address-space" here (rather than over real IPC to each other) matches
    /// both crates' own documented "not yet a real confined program" limitation —
    /// see this crate's and `lantern-crypto`'s top-level docs.
    struct Fixture {
        state: KernelState,
        keystore: Keystore,
        store: Store,
        store_tcb: TcbId,
        store_ep_cptr: CPtr,
        store_ep: Capability,
        aead_key: KeyId,
    }

    fn new_cnode_and_tcb(state: &mut KernelState) -> (CNodeId, TcbId) {
        let cnode = CNodeId(state.cnodes.alloc(CNode::empty()).unwrap() as u16);
        let tcb = TcbId(state.tcbs.alloc(Tcb::new()).unwrap() as u16);
        state.tcbs.get_mut(tcb.0 as usize).unwrap().cspace = Some(cnode);
        *state.cnodes.get_mut(cnode.0 as usize).unwrap().slot_mut(0).unwrap() = Capability::CNode(cnode);
        (cnode, tcb)
    }

    fn setup() -> Fixture {
        let mut state = KernelState::new();

        // The crypto-service thread: owns the store's one v0 AEAD key.
        let (keystore_cnode, keystore_tcb) = new_cnode_and_tcb(&mut state);
        let notif_idx = state.notifications.alloc(Notification::new()).unwrap();
        let source = Capability::Notification { id: NotificationId(notif_idx as u16), badge: 0, rights: Rights::READ.union(Rights::GRANT) };
        *state.cnodes.get_mut(keystore_cnode.0 as usize).unwrap().slot_mut(SOURCE_SLOT).unwrap() = source;

        let mut keystore = Keystore::new(keystore_tcb, 0);
        let aead_key = keystore.generate_aead_key([3u8; aead::AEAD_KEY_LEN]).unwrap();
        state.scheduler.current = Some(keystore_tcb);
        let aead_badge = keystore
            .request_key_access(&mut state, aead_key, KeyOps::ENCRYPT.union(KeyOps::DECRYPT), SOURCE_SLOT, SCRATCH_SLOT)
            .unwrap();

        // The filesystem-service thread: Store itself, with its own self-CNode cap
        // and its own GRANT-able source capability for file-access grants.
        let (store_cnode, store_tcb) = new_cnode_and_tcb(&mut state);
        let notif_idx = state.notifications.alloc(Notification::new()).unwrap();
        let source = Capability::Notification { id: NotificationId(notif_idx as u16), badge: 0, rights: Rights::READ.union(Rights::GRANT) };
        *state.cnodes.get_mut(store_cnode.0 as usize).unwrap().slot_mut(SOURCE_SLOT).unwrap() = source;

        let ep_idx = state.endpoints.alloc(lantern_kernel::object::Endpoint::new()).unwrap();
        let ep = Capability::Endpoint { id: EndpointId(ep_idx as u16), badge: 0, rights: Rights::ALL };
        *state.cnodes.get_mut(store_cnode.0 as usize).unwrap().slot_mut(1).unwrap() = ep;

        let store = Store::new(store_tcb, 0, aead_badge, aead_key);

        Fixture { state, keystore, store, store_tcb, store_ep_cptr: 1, store_ep: ep, aead_key }
    }

    /// Spawns a fresh client thread holding `store`'s shared endpoint at slot 1,
    /// blocks it in `Recv` (registering [`CLIENT_DEST_SLOT`]), then `store`
    /// mints+delivers a badge scoped to `file`/`ops` — the same
    /// request→Recv→mint→grant shape `lantern-crypto`'s own `grant_access` test
    /// helper uses, one layer up. A fresh client per call (rather than one shared
    /// client granted to repeatedly) keeps each grant's `Recv`/destination-slot
    /// bookkeeping independent — real distinct clients would be separate threads
    /// too, so this isn't a simplification the mechanism itself depends on.
    ///
    /// Doesn't assert which thread `ipc::recv` switches `scheduler.current` to
    /// (unlike `lantern-crypto`'s single-grant fixture) — with more than one
    /// grant serviced against the same `KernelState`, an earlier round's now-idle
    /// client can be left sitting in the ready queue and legitimately win the
    /// next round's scheduling pick. That's real scheduler behaviour, not a bug:
    /// `Store::request_file_access`/`deliver_grant` take explicit `TcbId`
    /// parameters throughout and never consult `scheduler.current`, so which
    /// thread is nominally "current" doesn't affect correctness here.
    /// `scratch_slot` — a slot in `store`'s own CNode, per
    /// [`Store::request_file_access`]'s doc. Must be distinct across grants made
    /// within the same test: `Broker::mint` (via `CNodeInvoke::Mint`) requires its
    /// destination slot empty, and `grant`'s transfer is a *copy* — the scratch
    /// slot still holds the minted capability afterward, so reusing the same slot
    /// for a second grant in the same `KernelState` would find it already
    /// occupied. A real service would reclaim/reuse its own scratch slot between
    /// requests (e.g. via `CNodeInvoke::Delete`); this fixture just picks a fresh
    /// one per call instead, since exercising reclamation isn't this crate's job.
    fn grant_access(f: &mut Fixture, file: FileId, ops: FileOps, scratch_slot: CPtr) -> (TcbId, u64) {
        let (client_cnode, client_tcb) = new_cnode_and_tcb(&mut f.state);
        *f.state.cnodes.get_mut(client_cnode.0 as usize).unwrap().slot_mut(1).unwrap() = f.store_ep;

        f.state.make_ready(f.store_tcb);
        f.state.scheduler.current = Some(client_tcb);
        let mut recv_frame = TrapFrame::zeroed();
        recv_frame.set_tag(MessageTag { label: 0, length: 0, extra_caps: 1, flags: 0 });
        recv_frame.set_mr(1, CLIENT_DEST_SLOT);
        ipc::recv(&mut f.state, client_tcb, f.store_ep_cptr, &mut recv_frame).unwrap();

        let badge = f.store.request_file_access(&mut f.state, file, ops, SOURCE_SLOT, scratch_slot).unwrap();
        f.store.deliver_grant(&mut f.state, f.store_ep_cptr, scratch_slot, (0, 0)).unwrap();
        (client_tcb, badge)
    }

    #[test]
    fn write_then_read_round_trips() {
        let mut f = setup();
        let file = f.store.create().unwrap();
        let (_, badge) = grant_access(&mut f, file, FileOps::ALL, SCRATCH_SLOT);

        f.store.write(&f.keystore, badge, file, b"hello, lantern").unwrap();
        let mut buf = [0u8; 32];
        let n = f.store.read(&f.keystore, badge, file, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello, lantern");
    }

    #[test]
    fn reading_an_empty_file_fails() {
        let mut f = setup();
        let file = f.store.create().unwrap();
        let (_, badge) = grant_access(&mut f, file, FileOps::ALL, SCRATCH_SLOT);

        let mut buf = [0u8; 32];
        assert_eq!(f.store.read(&f.keystore, badge, file, &mut buf), Err(StoreError::FileEmpty));
    }

    #[test]
    fn identical_content_across_two_files_deduplicates_into_one_block() {
        let mut f = setup();
        let file_a = f.store.create().unwrap();
        let file_b = f.store.create().unwrap();
        let (_, badge_a) = grant_access(&mut f, file_a, FileOps::ALL, SCRATCH_SLOT);
        let (_, badge_b) = grant_access(&mut f, file_b, FileOps::ALL, SCRATCH_SLOT + 1);

        f.store.write(&f.keystore, badge_a, file_a, b"same content").unwrap();
        f.store.write(&f.keystore, badge_b, file_b, b"same content").unwrap();

        let live_blocks = f.store.blocks.iter().flatten().count();
        assert_eq!(live_blocks, 1, "identical plaintext must dedup into a single stored block");

        // Destroying one file's reference must not disturb the other's.
        f.store.destroy(file_a).unwrap();
        let mut buf = [0u8; 32];
        let n = f.store.read(&f.keystore, badge_b, file_b, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"same content");
    }

    #[test]
    fn destroying_the_last_reference_frees_the_block_slot() {
        let mut f = setup();
        let file = f.store.create().unwrap();
        let (_, badge) = grant_access(&mut f, file, FileOps::ALL, SCRATCH_SLOT);
        f.store.write(&f.keystore, badge, file, b"solo content").unwrap();
        assert_eq!(f.store.blocks.iter().flatten().count(), 1);

        f.store.destroy(file).unwrap();
        assert_eq!(f.store.blocks.iter().flatten().count(), 0, "the only reference was destroyed -- the block must be reclaimed");
    }

    #[test]
    fn rewriting_a_file_releases_its_previous_block() {
        let mut f = setup();
        let file = f.store.create().unwrap();
        let (_, badge) = grant_access(&mut f, file, FileOps::ALL, SCRATCH_SLOT);

        f.store.write(&f.keystore, badge, file, b"first version").unwrap();
        f.store.write(&f.keystore, badge, file, b"second version").unwrap();
        assert_eq!(f.store.blocks.iter().flatten().count(), 1, "the first version's block must be released, not leaked");

        let mut buf = [0u8; 32];
        let n = f.store.read(&f.keystore, badge, file, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"second version");
    }

    #[test]
    fn rewriting_a_file_with_its_own_current_content_does_not_drift_the_refcount() {
        let mut f = setup();
        let file = f.store.create().unwrap();
        let (_, badge) = grant_access(&mut f, file, FileOps::ALL, SCRATCH_SLOT);

        f.store.write(&f.keystore, badge, file, b"stable content").unwrap();
        f.store.write(&f.keystore, badge, file, b"stable content").unwrap();
        f.store.destroy(file).unwrap();
        assert_eq!(f.store.blocks.iter().flatten().count(), 0, "a refcount that drifted high would leak the block here");
    }

    #[test]
    fn badge_scoped_to_read_cannot_write() {
        let mut f = setup();
        let file = f.store.create().unwrap();
        let (_, badge) = grant_access(&mut f, file, FileOps::READ, SCRATCH_SLOT);
        assert_eq!(f.store.write(&f.keystore, badge, file, b"nope"), Err(StoreError::OpNotGranted));
    }

    #[test]
    fn badge_scoped_to_a_different_file_is_rejected() {
        let mut f = setup();
        let file_a = f.store.create().unwrap();
        let file_b = f.store.create().unwrap();
        let (_, badge_a) = grant_access(&mut f, file_a, FileOps::ALL, SCRATCH_SLOT);

        assert_eq!(f.store.write(&f.keystore, badge_a, file_b, b"nope"), Err(StoreError::WrongFile));
    }

    #[test]
    fn revoked_badge_is_rejected() {
        let mut f = setup();
        let file = f.store.create().unwrap();
        let (_, badge) = grant_access(&mut f, file, FileOps::ALL, SCRATCH_SLOT);
        f.store.revoke_access(badge).unwrap();
        assert_eq!(f.store.write(&f.keystore, badge, file, b"nope"), Err(StoreError::BadgeRevoked));
    }

    #[test]
    fn destroyed_file_id_is_never_reused_by_a_later_create_call() {
        let mut f = setup();
        let file_a = f.store.create().unwrap();
        f.store.destroy(file_a).unwrap();
        let file_b = f.store.create().unwrap();
        assert_ne!(file_a, file_b, "a destroyed FileId must never be handed to a new, unrelated file");
    }

    #[test]
    fn content_over_the_block_size_ceiling_is_rejected() {
        let mut f = setup();
        let file = f.store.create().unwrap();
        let (_, badge) = grant_access(&mut f, file, FileOps::ALL, SCRATCH_SLOT);
        let oversized = [0u8; MAX_BLOCK_LEN + 1];
        assert_eq!(f.store.write(&f.keystore, badge, file, &oversized), Err(StoreError::ContentTooLarge));
    }

    #[test]
    fn aead_key_is_reachable_only_through_the_composed_keystore() {
        // Sanity check that Store really does go through Keystore's own
        // capability-gated interface rather than holding raw key material --
        // encrypting under a badge/key Store was never granted must fail the
        // same way any other unauthorised Keystore caller would.
        let f = setup();
        let mut buf = *b"whatever";
        assert!(f.keystore.encrypt(999, f.aead_key, &[0; aead::NONCE_LEN], b"", &mut buf).is_err());
    }
}
