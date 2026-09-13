//! The `store` half of
//! [RFC-0019](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0019-confined-service-call-protocol.md)'s
//! wire protocol ([ADR-0024](https://github.com/lantern-os/lantern-rfcs/blob/main/adr/0024-confined-service-call-protocol.md)):
//! READ/WRITE request parsing and reply construction, as a pure(-ish, modulo
//! `cipher`) function so it's fully testable without a confined program,
//! `Recv`, or a shared `Frame` — the same split
//! [`lantern_crypto::wire`]'s own doc describes for the `keystore` half. A
//! confined `store-service` (`lantern-boot`) pairs [`handle_request`] with
//! [`lantern_abi::frame::Channel`] for the actual I/O.
//!
//! Simpler than the `keystore` half: neither `op` needs its own request/reply
//! framing beyond what [`lantern_abi::frame::Channel`] already provides —
//! **READ**'s request is empty (`arg_len == 0`), its reply is the raw file
//! bytes; **WRITE**'s request *is* the raw file bytes, its reply is
//! header-only. No nonce/AAD/tag byte-packing like `keystore`'s ENCRYPT/
//! DECRYPT needs.
//!
//! **A confined service's request parser is a trust boundary** (RFC-0019's
//! own Motivation) — the badge → [`crate::FileId`] lookup
//! ([`crate::Store::file_for_badge`]) happens before any operation runs, so a
//! request for a badge this store never granted is rejected before `read`/
//! `write` ever touch a block.

use crate::cipher::Cipher;
use crate::{Store, StoreError};

/// Operation codes, per RFC-0019's `store` wire format.
pub const OP_READ: u16 = 1;
pub const OP_WRITE: u16 = 2;

/// Reply status codes, per RFC-0019's four-value error map — identical set to
/// [`lantern_crypto::wire::status`], deliberately not shared as one type: the
/// two crates have no other coupling, and RFC-0019 fixes this as "one
/// protocol" at the byte-format level, not via a shared Rust type.
pub mod status {
    pub const OK: u16 = 0;
    pub const ACCESS: u16 = 1;
    pub const INVALID: u16 = 2;
    pub const FAILED: u16 = 3;
}

/// Handles one already-reassembled request (chunking/framing is
/// [`lantern_abi::frame::Channel`]'s job, not this module's) against `store`,
/// on behalf of `badge` (the kernel-delivered sender identity). `cipher`
/// reaches the store-wide AEAD key `read`/`write` need — a
/// [`crate::cipher::ChannelCipher`] wrapping this service's own granted
/// `Channel` to a confined `keystore-service`, in the real deployment.
/// Writes the reply payload into `reply_buf` and returns `(status, len)`:
/// `reply_buf[..len]` is the reply payload iff `status ==` [`status::OK`];
/// every other status's payload is empty.
pub fn handle_request(
    store: &mut Store,
    cipher: &mut impl Cipher,
    badge: u64,
    op: u16,
    request: &[u8],
    reply_buf: &mut [u8],
) -> (u16, usize) {
    let Some(file) = store.file_for_badge(badge) else {
        return (status::ACCESS, 0);
    };
    match op {
        OP_READ => handle_read(store, cipher, badge, file, reply_buf),
        OP_WRITE => handle_write(store, cipher, badge, file, request),
        _ => (status::INVALID, 0),
    }
}

fn status_for(err: StoreError) -> u16 {
    match err {
        StoreError::UnknownBadge
        | StoreError::BadgeRevoked
        | StoreError::OpNotGranted
        | StoreError::WrongFile
        | StoreError::NoSuchFile
        | StoreError::FileDestroyed => status::ACCESS,
        StoreError::ContentTooLarge => status::INVALID,
        StoreError::NotEnoughCapacity | StoreError::CryptoFailure(_) | StoreError::Channel(_) | StoreError::RemoteCryptoDenied(_) | StoreError::Kernel(_) => {
            status::FAILED
        }
        // `read`'s own caller-buffer-too-small case never reaches here — this
        // handler always passes a full `reply_buf`, never a caller-chosen
        // short one, so a `ContentTooLarge` from `read` can only mean the
        // stored block itself is malformed (unreachable in practice, but
        // mapped the same as the write-side meaning rather than panicking).
        StoreError::FileEmpty => status::OK,
    }
}

/// **READ** — request payload is ignored (`arg_len == 0` per RFC-0019); reply
/// is the file's current plaintext, `status = OK`. An unwritten file replies
/// `OK` with an empty payload (RFC-0019's explicit rule) — v0's whole-file
/// `Store::read` already returns `Ok(0)`... no: it returns
/// `Err(StoreError::FileEmpty)`, mapped to `OK`/empty here specifically, the
/// one place a `StoreError` means success on the wire.
fn handle_read(store: &Store, cipher: &mut impl Cipher, badge: u64, file: crate::FileId, reply_buf: &mut [u8]) -> (u16, usize) {
    match store.read(cipher, badge, file, reply_buf) {
        Ok(len) => (status::OK, len),
        Err(StoreError::FileEmpty) => (status::OK, 0),
        Err(e) => (status_for(e), 0),
    }
}

/// **WRITE** — request payload is the file's new content in full (already
/// reassembled by `Channel::recv_request`); reply is header-only, `status =
/// OK`.
fn handle_write(store: &mut Store, cipher: &mut impl Cipher, badge: u64, file: crate::FileId, request: &[u8]) -> (u16, usize) {
    match store.write(cipher, badge, file, request) {
        Ok(()) => (status::OK, 0),
        Err(e) => (status_for(e), 0),
    }
}

#[cfg(test)]
mod codec_tests {
    use super::*;

    #[test]
    fn op_and_status_codes_match_rfc_0019() {
        assert_eq!(OP_READ, 1);
        assert_eq!(OP_WRITE, 2);
        assert_eq!(status::OK, 0);
        assert_eq!(status::ACCESS, 1);
        assert_eq!(status::INVALID, 2);
        assert_eq!(status::FAILED, 3);
    }

    #[test]
    fn status_for_covers_every_storeerror_variant_without_panicking() {
        // Every real *error* arm at least once — a new `StoreError` variant
        // that isn't matched in `status_for` would fail to compile
        // (non-exhaustive match), not silently fall through.
        // `StoreError::FileEmpty` is deliberately excluded: it's the one
        // `StoreError` that means *success* on the wire (`handle_read`
        // intercepts it before `status_for` ever runs) — covered instead by
        // `read_before_any_write_is_ok_and_empty` below.
        let samples = [
            StoreError::NoSuchFile,
            StoreError::FileDestroyed,
            StoreError::ContentTooLarge,
            StoreError::NotEnoughCapacity,
            StoreError::UnknownBadge,
            StoreError::BadgeRevoked,
            StoreError::OpNotGranted,
            StoreError::WrongFile,
            StoreError::Kernel(lantern_capabilities::SyscallError::IllegalOperation),
            StoreError::Channel(lantern_abi::frame::ChannelError::Malformed),
            StoreError::RemoteCryptoDenied(status::FAILED),
        ];
        for err in samples {
            let s = status_for(err);
            assert!(s == status::ACCESS || s == status::INVALID || s == status::FAILED, "{err:?} -> {s}");
        }
    }
}

#[cfg(all(test, feature = "kernel-backend"))]
mod tests {
    use super::*;
    use crate::cipher::InProcessCipher;
    use crate::FileOps;
    use lantern_capabilities::KernelBackend;
    use lantern_crypto::{aead, KeyId, KeyOps, Keystore};
    use lantern_kernel::cap::{CNode, CNodeId, Capability, NotificationId, Rights, TcbId};
    use lantern_kernel::object::{Notification, Tcb};
    use lantern_kernel::state::KernelState;

    const SOURCE_SLOT: usize = 5;
    const SCRATCH_SLOT: usize = 6;

    fn new_cnode_and_tcb(state: &mut KernelState) -> (CNodeId, TcbId) {
        let cnode = CNodeId(state.cnodes.alloc(CNode::empty()).unwrap() as u16);
        let tcb = TcbId(state.tcbs.alloc(Tcb::new()).unwrap() as u16);
        state.tcbs.get_mut(tcb.0 as usize).unwrap().cspace = Some(cnode);
        *state.cnodes.get_mut(cnode.0 as usize).unwrap().slot_mut(0).unwrap() = Capability::CNode(cnode);
        (cnode, tcb)
    }

    /// A `Store` with one file granted `FileOps::ALL` to a badge, plus the
    /// `Keystore`/AEAD grant its `InProcessCipher` needs — ready to dispatch
    /// through [`handle_request`]. Returned as plain owned values (not a
    /// struct) since every field is borrowed independently by the tests'
    /// locally-constructed `InProcessCipher`.
    fn granted_store() -> (Store, Keystore, u64, KeyId, u64, crate::FileId) {
        let mut state = KernelState::new();
        let (ks_cnode, ks_tcb) = new_cnode_and_tcb(&mut state);
        let notif = state.notifications.alloc(Notification::new()).unwrap();
        *state.cnodes.get_mut(ks_cnode.0 as usize).unwrap().slot_mut(SOURCE_SLOT).unwrap() =
            Capability::Notification { id: NotificationId(notif as u16), badge: 0, rights: Rights::WRITE.union(Rights::GRANT) };

        let mut keystore = Keystore::new(0);
        let aead_key = keystore.generate_aead_key([9u8; aead::AEAD_KEY_LEN]).unwrap();
        state.scheduler.current = Some(ks_tcb);
        let aead_badge = keystore
            .request_key_access(&mut KernelBackend::new(&mut state, ks_tcb), aead_key, KeyOps::ENCRYPT.union(KeyOps::DECRYPT), SOURCE_SLOT, SCRATCH_SLOT)
            .unwrap();

        let (store_cnode, store_tcb) = new_cnode_and_tcb(&mut state);
        let notif = state.notifications.alloc(Notification::new()).unwrap();
        *state.cnodes.get_mut(store_cnode.0 as usize).unwrap().slot_mut(SOURCE_SLOT).unwrap() =
            Capability::Notification { id: NotificationId(notif as u16), badge: 0, rights: Rights::WRITE.union(Rights::GRANT) };

        let mut store = Store::new(0);
        let file = store.create().unwrap();

        state.scheduler.current = Some(store_tcb);
        let file_badge = store
            .request_file_access(&mut KernelBackend::new(&mut state, store_tcb), file, FileOps::ALL, SOURCE_SLOT, SCRATCH_SLOT)
            .unwrap();

        (store, keystore, aead_badge, aead_key, file_badge, file)
    }

    #[test]
    fn unknown_badge_is_rejected_before_any_op_runs() {
        let (mut store, keystore, aead_badge, aead_key, _badge, _file) = granted_store();
        let mut cipher = InProcessCipher::new(&keystore, aead_badge, aead_key);
        let mut reply = [0u8; 64];
        let (status, len) = handle_request(&mut store, &mut cipher, 0xDEAD, OP_READ, &[], &mut reply);
        assert_eq!(status, status::ACCESS);
        assert_eq!(len, 0);
    }

    #[test]
    fn unknown_op_is_invalid() {
        let (mut store, keystore, aead_badge, aead_key, badge, _file) = granted_store();
        let mut cipher = InProcessCipher::new(&keystore, aead_badge, aead_key);
        let mut reply = [0u8; 64];
        let (status, _len) = handle_request(&mut store, &mut cipher, badge, 99, &[], &mut reply);
        assert_eq!(status, status::INVALID);
    }

    #[test]
    fn read_before_any_write_is_ok_and_empty() {
        let (mut store, keystore, aead_badge, aead_key, badge, _file) = granted_store();
        let mut cipher = InProcessCipher::new(&keystore, aead_badge, aead_key);
        let mut reply = [0u8; 64];
        let (status, len) = handle_request(&mut store, &mut cipher, badge, OP_READ, &[], &mut reply);
        assert_eq!(status, status::OK);
        assert_eq!(len, 0);
    }

    #[test]
    fn write_then_read_round_trips() {
        let (mut store, keystore, aead_badge, aead_key, badge, _file) = granted_store();
        let mut cipher = InProcessCipher::new(&keystore, aead_badge, aead_key);
        let mut reply = [0u8; 64];
        let (status, len) = handle_request(&mut store, &mut cipher, badge, OP_WRITE, b"hello, wire", &mut reply);
        assert_eq!(status, status::OK);
        assert_eq!(len, 0);

        let mut reply = [0u8; 64];
        let (status, len) = handle_request(&mut store, &mut cipher, badge, OP_READ, &[], &mut reply);
        assert_eq!(status, status::OK);
        assert_eq!(&reply[..len], b"hello, wire");
    }

    #[test]
    fn write_over_the_block_size_ceiling_is_invalid() {
        let (mut store, keystore, aead_badge, aead_key, badge, _file) = granted_store();
        let mut cipher = InProcessCipher::new(&keystore, aead_badge, aead_key);
        let oversized = [0u8; crate::MAX_BLOCK_LEN + 1];
        let mut reply = [0u8; 64];
        let (status, _len) = handle_request(&mut store, &mut cipher, badge, OP_WRITE, &oversized, &mut reply);
        assert_eq!(status, status::INVALID);
    }
}
