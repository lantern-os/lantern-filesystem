//! What [`crate::Store::write`]/[`crate::Store::read`] need to reach the
//! store-wide AEAD key: [`Cipher`], plus two implementations.
//!
//! [`InProcessCipher`] wraps a direct `&lantern_crypto::Keystore` reference
//! plus the badge/key this store was granted — same-address-space, what every
//! test in this crate and `lantern-runtime`'s `InProcessFilesystem` stand-in
//! use today. [`ChannelCipher`] issues real `Channel::call`s to a confined
//! `keystore-service`, over [`lantern_crypto::wire`]'s
//! `OP_ENCRYPT`/`OP_DECRYPT` codecs (already built and unit-tested there) —
//! what a confined `store-service` (`lantern-boot`'s remaining ADR-0022 Part 1
//! piece for this crate) uses instead. Neither `Cipher` implementation takes a
//! badge or key parameter *per call*: each carries its own binding (a fixed
//! badge/key pair, or a fixed granted `Channel`), the same way a confined
//! `store-service` only ever has *one* such relationship to its keystore,
//! fixed at startup — matching `lantern_capabilities::BrokerBackend`'s own
//! "no backend state on the object it backs" split one layer down.

use lantern_crypto::{aead, KeyId, Keystore};

use crate::{StoreError, MAX_BLOCK_LEN};

/// See the module doc.
pub trait Cipher {
    /// Encrypts `buffer` in place, returning the detached tag.
    fn encrypt(
        &mut self,
        nonce: &[u8; aead::NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<[u8; aead::TAG_LEN], StoreError>;

    /// Decrypts `buffer` in place, checking it against `tag`.
    fn decrypt(
        &mut self,
        nonce: &[u8; aead::NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; aead::TAG_LEN],
    ) -> Result<(), StoreError>;
}

/// An in-process [`Cipher`]: wraps a direct `&Keystore` reference plus the
/// badge/key this store was granted (via
/// [`Keystore::request_key_access`]/`deliver_grant`, with
/// [`lantern_crypto::KeyOps::ENCRYPT`]/[`lantern_crypto::KeyOps::DECRYPT`]
/// both granted — the caller's responsibility, same "caller sets up the
/// precondition" discipline `Store::new`'s own doc used to carry before this
/// moved out to here).
pub struct InProcessCipher<'a> {
    keystore: &'a Keystore,
    badge: u64,
    key: KeyId,
}

impl<'a> InProcessCipher<'a> {
    pub fn new(keystore: &'a Keystore, badge: u64, key: KeyId) -> Self {
        Self { keystore, badge, key }
    }
}

impl Cipher for InProcessCipher<'_> {
    fn encrypt(
        &mut self,
        nonce: &[u8; aead::NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<[u8; aead::TAG_LEN], StoreError> {
        self.keystore.encrypt(self.badge, self.key, nonce, aad, buffer).map_err(StoreError::CryptoFailure)
    }

    fn decrypt(
        &mut self,
        nonce: &[u8; aead::NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; aead::TAG_LEN],
    ) -> Result<(), StoreError> {
        self.keystore.decrypt(self.badge, self.key, nonce, aad, buffer, tag).map_err(StoreError::CryptoFailure)
    }
}

/// Scratch buffer size for `lantern_crypto::wire`'s ENCRYPT/DECRYPT request
/// and reply encoding — comfortably covers v0's fixed [`MAX_BLOCK_LEN`]
/// content plus the nonce/AAD/tag length-prefixing the wire codecs add
/// (`4 + NONCE_LEN + 4 + HASH_LEN + 4 + TAG_LEN` worth of framing, well under
/// 64 bytes), and well under `lantern_abi::frame::FRAME_PAYLOAD` — v0 never
/// needs `Channel::call`'s transparent chunking.
const WIRE_BUF_LEN: usize = MAX_BLOCK_LEN + 64;

/// A [`Cipher`] that reaches its key over IPC: issues real `Channel::call`s
/// to a confined `keystore-service`, using `lantern_crypto::wire`'s
/// `OP_ENCRYPT`/`OP_DECRYPT` request/reply codecs. The badge is implicit in
/// which endpoint `channel` was constructed against — never passed here, per
/// RFC-0019 ("the badge alone identifies `(KeyId, KeyOps)`").
pub struct ChannelCipher<'a> {
    channel: &'a mut lantern_abi::frame::Channel,
}

impl<'a> ChannelCipher<'a> {
    pub fn new(channel: &'a mut lantern_abi::frame::Channel) -> Self {
        Self { channel }
    }
}

impl Cipher for ChannelCipher<'_> {
    fn encrypt(
        &mut self,
        nonce: &[u8; aead::NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<[u8; aead::TAG_LEN], StoreError> {
        let mut request = [0u8; WIRE_BUF_LEN];
        let len =
            lantern_crypto::wire::encode_encrypt_request(nonce, aad, buffer, &mut request).ok_or(StoreError::ContentTooLarge)?;
        let mut reply = [0u8; WIRE_BUF_LEN];
        let (status, reply_len) =
            self.channel.call(lantern_crypto::wire::OP_ENCRYPT, &request[..len], &mut reply).map_err(StoreError::Channel)?;
        if status != lantern_crypto::wire::status::OK {
            return Err(StoreError::RemoteCryptoDenied(status));
        }
        let (tag, ciphertext) = lantern_crypto::wire::decode_encrypt_reply(&reply[..reply_len])
            .ok_or(StoreError::Channel(lantern_abi::frame::ChannelError::Malformed))?;
        if ciphertext.len() != buffer.len() {
            return Err(StoreError::Channel(lantern_abi::frame::ChannelError::Malformed));
        }
        buffer.copy_from_slice(ciphertext);
        Ok(tag)
    }

    fn decrypt(
        &mut self,
        nonce: &[u8; aead::NONCE_LEN],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; aead::TAG_LEN],
    ) -> Result<(), StoreError> {
        let mut request = [0u8; WIRE_BUF_LEN];
        let len = lantern_crypto::wire::encode_decrypt_request(nonce, aad, tag, buffer, &mut request)
            .ok_or(StoreError::ContentTooLarge)?;
        let mut reply = [0u8; WIRE_BUF_LEN];
        let (status, reply_len) =
            self.channel.call(lantern_crypto::wire::OP_DECRYPT, &request[..len], &mut reply).map_err(StoreError::Channel)?;
        if status != lantern_crypto::wire::status::OK {
            return Err(StoreError::RemoteCryptoDenied(status));
        }
        let plaintext = lantern_crypto::wire::decode_decrypt_reply(&reply[..reply_len]);
        if plaintext.len() != buffer.len() {
            return Err(StoreError::Channel(lantern_abi::frame::ChannelError::Malformed));
        }
        buffer.copy_from_slice(plaintext);
        Ok(())
    }
}
