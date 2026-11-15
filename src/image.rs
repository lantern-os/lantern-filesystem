//! The store as one sealed image ([RFC-0031](https://github.com/lantern-os/lantern-rfcs/blob/main/rfcs/0031-storage-a-block-driver-and-the-store-on-disk.md)),
//! what makes its files outlive a reboot.
//!
//! ```text
//! header (sector 0):  "LSTORE01"  seq: u64  body_len: u32  digest: [u8; 32]  tag: [u8; 16]
//! body:               every file's record, then every block (its plaintext hash, length, refcount, AEAD tag, ciphertext)
//! ```
//!
//! `digest` is BLAKE3 over the magic, `seq`, `body_len` and the body; storing it lets a damaged image be refused before
//! any keystore call, but it authenticates nothing by itself. `tag` seals the digest, as computed, under the store's key: the
//! `Cipher`'s AEAD over no plaintext, with the digest as associated data and its first bytes as the nonce. So only a holder
//! of the key can make an image that [`Store::load_image`] accepts. The nonce is the digest's, so two different images never
//! share one (a block's nonce comes from its content hash, which an image's digest prefix won't collide with). Blocks stay
//! sealed as they always were; the seal makes the file table and refcounts authentic too.
//!
//! **Rollback isn't prevented:** an older image, sealed under the same key, still verifies. RFC-0023's checklist has the
//! row: a monotonic counter.

use super::*;

pub const MAGIC: &[u8; 8] = b"LSTORE01";
pub const HEADER_LEN: usize = 8 + 8 + 4 + hash::HASH_LEN + aead::TAG_LEN;
const FILE_LEN: usize = 2;
const BLOCK_LEN: usize = 1 + hash::HASH_LEN + 2 + 4 + aead::TAG_LEN + MAX_BLOCK_LEN;
/// The most an image can be: header, every file, every block at its largest.
pub const IMAGE_MAX: usize = HEADER_LEN + MAX_FILES * FILE_LEN + MAX_BLOCKS * BLOCK_LEN;

const NO_FILE: u8 = 0;
const LIVE: u8 = 1;
const DESTROYED: u8 = 2;
const NO_BLOCK: u8 = 0xff;

fn digest(seq: u64, body: &[u8]) -> hash::Hash {
    let mut hasher = hash::Hasher::new();
    hasher.update(MAGIC).update(&seq.to_le_bytes()).update(&(body.len() as u32).to_le_bytes()).update(body);
    hasher.finalize()
}

fn nonce(digest: &hash::Hash) -> [u8; aead::NONCE_LEN] {
    let mut nonce = [0u8; aead::NONCE_LEN];
    nonce.copy_from_slice(&digest.as_bytes()[..aead::NONCE_LEN]);
    nonce
}

impl Store {
    /// Writes this store's files and blocks as image number `seq` into `out` (at least [`IMAGE_MAX`]), sealed through
    /// `cipher`. Returns its length. Grants aren't in it: they last one boot.
    pub fn save_image(&self, cipher: &mut impl Cipher, seq: u64, out: &mut [u8]) -> Result<usize, StoreError> {
        if out.len() < IMAGE_MAX {
            return Err(StoreError::ContentTooLarge);
        }
        let mut at = HEADER_LEN;
        for file in &self.files {
            let (kind, block) = match file {
                None => (NO_FILE, NO_BLOCK),
                Some(f) => (if f.destroyed { DESTROYED } else { LIVE }, f.block.map_or(NO_BLOCK, |b| b as u8)),
            };
            out[at] = kind;
            out[at + 1] = block;
            at += FILE_LEN;
        }
        for block in &self.blocks {
            match block {
                None => {
                    out[at] = 0;
                    at += 1;
                }
                Some(b) => {
                    out[at] = 1;
                    out[at + 1..at + 33].copy_from_slice(b.hash.as_bytes());
                    out[at + 33..at + 35].copy_from_slice(&(b.len as u16).to_le_bytes());
                    out[at + 35..at + 39].copy_from_slice(&b.refcount.to_le_bytes());
                    out[at + 39..at + 55].copy_from_slice(&b.tag);
                    out[at + 55..at + 55 + b.len].copy_from_slice(&b.ciphertext[..b.len]);
                    at += 55 + b.len;
                }
            }
        }
        let body_len = at - HEADER_LEN;
        let digest = digest(seq, &out[HEADER_LEN..at]);
        let tag = cipher.encrypt(&nonce(&digest), digest.as_bytes(), &mut [])?;
        out[..8].copy_from_slice(MAGIC);
        out[8..16].copy_from_slice(&seq.to_le_bytes());
        out[16..20].copy_from_slice(&(body_len as u32).to_le_bytes());
        out[20..52].copy_from_slice(digest.as_bytes());
        out[52..HEADER_LEN].copy_from_slice(&tag);
        Ok(at)
    }

    /// An image's `seq`, if `bytes` starts like one. Says nothing about whether it verifies.
    pub fn image_seq(bytes: &[u8]) -> Option<u64> {
        (bytes.get(..8)? == MAGIC).then(|| u64::from_le_bytes(bytes[8..16].try_into().unwrap()))
    }

    /// A store from an image [`Store::save_image`] wrote, and its `seq`, only if its digest and seal verify through `cipher`
    /// and its contents are consistent. Anything else is `ImageInvalid`, and nothing of it is used.
    pub fn load_image(self_cnode_cptr: CPtr, cipher: &mut impl Cipher, bytes: &[u8]) -> Result<(Store, u64), StoreError> {
        let seq = Self::image_seq(bytes).ok_or(StoreError::ImageInvalid)?;
        let body_len = u32::from_le_bytes(bytes[16..20].try_into().unwrap()) as usize;
        let body = bytes.get(HEADER_LEN..HEADER_LEN.checked_add(body_len).ok_or(StoreError::ImageInvalid)?).ok_or(StoreError::ImageInvalid)?;
        let computed = digest(seq, body);
        let mut stored = [0u8; hash::HASH_LEN];
        stored.copy_from_slice(&bytes[20..52]);
        if !computed.ct_eq(&hash::Hash::from_bytes(stored)) {
            return Err(StoreError::ImageInvalid);
        }
        let mut tag = [0u8; aead::TAG_LEN];
        tag.copy_from_slice(&bytes[52..HEADER_LEN]);
        cipher.decrypt(&nonce(&computed), computed.as_bytes(), &mut [], &tag).map_err(|_| StoreError::ImageInvalid)?;

        // Authentic: only the key's holder made it. Still checked, so a bug in a writer can't become a bad state here.
        let mut store = Store::new(self_cnode_cptr);
        let bad = StoreError::ImageInvalid;
        let (files, blocks) = body.split_at_checked(MAX_FILES * FILE_LEN).ok_or(bad)?;
        let mut at = 0;
        for slot in store.blocks.iter_mut() {
            match blocks.get(at).ok_or(bad)? {
                0 => at += 1,
                1 => {
                    let b = blocks.get(at..at + 55).ok_or(bad)?;
                    let len = u16::from_le_bytes([b[33], b[34]]) as usize;
                    if len > MAX_BLOCK_LEN {
                        return Err(bad);
                    }
                    let mut hash = [0u8; hash::HASH_LEN];
                    hash.copy_from_slice(&b[1..33]);
                    let mut tag = [0u8; aead::TAG_LEN];
                    tag.copy_from_slice(&b[39..55]);
                    let mut ciphertext = [0u8; MAX_BLOCK_LEN];
                    ciphertext[..len].copy_from_slice(blocks.get(at + 55..at + 55 + len).ok_or(bad)?);
                    let refcount = u32::from_le_bytes(b[35..39].try_into().unwrap());
                    *slot = Some(Block { hash: hash::Hash::from_bytes(hash), ciphertext, len, tag, refcount });
                    at += 55 + len;
                }
                _ => return Err(bad),
            }
        }
        if at != blocks.len() {
            return Err(bad);
        }
        let mut counted = [0u32; MAX_BLOCKS];
        for (slot, record) in store.files.iter_mut().zip(files.chunks_exact(FILE_LEN)) {
            let block = match record[1] {
                NO_BLOCK => None,
                b if (b as usize) < MAX_BLOCKS && store.blocks[b as usize].is_some() => {
                    counted[b as usize] += 1;
                    Some(b as usize)
                }
                _ => return Err(bad),
            };
            *slot = match record[0] {
                NO_FILE if block.is_none() => None,
                LIVE => Some(FileRecord { block, destroyed: false }),
                DESTROYED => Some(FileRecord { block, destroyed: true }),
                _ => return Err(bad),
            };
        }
        // Every block is referenced exactly as often as it says.
        for (block, count) in store.blocks.iter().zip(counted) {
            if block.as_ref().map_or(0, |b| b.refcount) != count {
                return Err(bad);
            }
        }
        Ok((store, seq))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The AEAD itself, under a fixed key: what `InProcessCipher` and `ChannelCipher` reach through the keystore.
    struct TestCipher(aead::AeadKey);

    impl Cipher for TestCipher {
        fn encrypt(&mut self, nonce: &[u8; aead::NONCE_LEN], aad: &[u8], buffer: &mut [u8]) -> Result<[u8; aead::TAG_LEN], StoreError> {
            self.0.encrypt_in_place_detached(nonce, aad, buffer).map_err(|_| StoreError::CryptoFailure(lantern_crypto::KeystoreError::CryptoFailure))
        }
        fn decrypt(&mut self, nonce: &[u8; aead::NONCE_LEN], aad: &[u8], buffer: &mut [u8], tag: &[u8; aead::TAG_LEN]) -> Result<(), StoreError> {
            self.0.decrypt_in_place_detached(nonce, aad, buffer, tag).map_err(|_| StoreError::CryptoFailure(lantern_crypto::KeystoreError::CryptoFailure))
        }
    }

    fn cipher(seed: u8) -> TestCipher {
        TestCipher(aead::AeadKey::from_random_bytes([seed; aead::AEAD_KEY_LEN]))
    }

    /// A store with file 0 holding `content`, sealed as `Store::write` seals it, file 1 empty, and file 2 destroyed.
    fn store(cipher: &mut TestCipher, content: &[u8]) -> Store {
        let mut store = Store::new(0);
        let (a, b, c) = (store.create().unwrap(), store.create().unwrap(), store.create().unwrap());
        let content_hash = hash::hash(content);
        let mut ciphertext = [0u8; MAX_BLOCK_LEN];
        ciphertext[..content.len()].copy_from_slice(content);
        let tag = cipher.encrypt(&nonce_from_hash(&content_hash), content_hash.as_bytes(), &mut ciphertext[..content.len()]).unwrap();
        store.blocks[3] = Some(Block { hash: content_hash, ciphertext, len: content.len(), tag, refcount: 1 });
        store.files[a.0 as usize].as_mut().unwrap().block = Some(3);
        let _ = b;
        store.files[c.0 as usize].as_mut().unwrap().destroyed = true;
        store
    }

    fn plaintext(store: &Store, cipher: &mut TestCipher, file: usize) -> std::vec::Vec<u8> {
        let block = store.blocks[store.files[file].as_ref().unwrap().block.unwrap()].as_ref().unwrap();
        let mut buf = block.ciphertext;
        cipher.decrypt(&nonce_from_hash(&block.hash), block.hash.as_bytes(), &mut buf[..block.len], &block.tag).unwrap();
        buf[..block.len].to_vec()
    }

    extern crate std;

    #[test]
    fn a_saved_store_loads_back_with_its_files_and_their_contents() {
        let mut c = cipher(3);
        let saved = store(&mut c, b"kept across a reboot");
        let mut image = std::vec![0u8; IMAGE_MAX];
        let len = saved.save_image(&mut c, 7, &mut image).unwrap();
        assert_eq!(Store::image_seq(&image), Some(7));
        let (loaded, seq) = Store::load_image(0, &mut c, &image[..len]).unwrap();
        assert_eq!(seq, 7);
        assert_eq!(plaintext(&loaded, &mut c, 0), b"kept across a reboot");
        assert_eq!(loaded.files[1].as_ref().map(|f| (f.block, f.destroyed)), Some((None, false)));
        assert!(loaded.files[2].as_ref().unwrap().destroyed);
        assert!(loaded.files[3].is_none());
        assert_eq!(loaded.blocks[3].as_ref().unwrap().refcount, 1);
    }

    #[test]
    fn any_change_to_an_image_is_refused() {
        let mut c = cipher(3);
        let mut image = std::vec![0u8; IMAGE_MAX];
        let len = store(&mut c, b"x").save_image(&mut c, 1, &mut image).unwrap();
        for at in [9, 17, 30, 60, HEADER_LEN, HEADER_LEN + 1, len - 1] {
            let mut bad = image.clone();
            bad[at] ^= 1;
            assert!(Store::load_image(0, &mut c, &bad[..len]).is_err(), "byte {at}");
        }
        assert!(Store::load_image(0, &mut c, &image[..len - 1]).is_err(), "torn");
        assert!(Store::load_image(0, &mut c, &[0xff; 512]).is_err(), "erased");
        assert!(Store::load_image(0, &mut c, &[]).is_err());
    }

    #[test]
    fn an_image_sealed_under_another_key_is_refused_even_with_a_correct_digest() {
        let mut c = cipher(3);
        let mut image = std::vec![0u8; IMAGE_MAX];
        let len = store(&mut c, b"x").save_image(&mut c, 1, &mut image).unwrap();
        assert_eq!(Store::load_image(0, &mut cipher(9), &image[..len]).err(), Some(StoreError::ImageInvalid));
    }

    #[test]
    fn an_authentic_image_with_inconsistent_contents_is_still_refused() {
        // A writer bug, sealed with the right key: a refcount that doesn't match its references.
        let mut c = cipher(3);
        let mut bad = store(&mut c, b"x");
        bad.blocks[3].as_mut().unwrap().refcount = 2;
        let mut image = std::vec![0u8; IMAGE_MAX];
        let len = bad.save_image(&mut c, 1, &mut image).unwrap();
        assert_eq!(Store::load_image(0, &mut c, &image[..len]).err(), Some(StoreError::ImageInvalid));
    }
}
