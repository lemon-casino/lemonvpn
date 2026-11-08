//! Crypto primitives shared by the protocol outbounds.
//!
//! Blocking and allocation-light on purpose: every helper here is called a
//! handful of times per connection (header sealing, key derivation) or in
//! per-chunk loops, where ring's native AEAD is fast enough.

use aes::cipher::{BlockEncrypt, KeyInit};
use md5::Md5;
use sha3::digest::{ExtendableOutput, Update, XofReader};

/// Lowercase hex of arbitrary bytes.
pub fn hex(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for byte in data {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// The 16 raw bytes of a UUID in its canonical dashed form. The config keeps
/// UUIDs as text, so the outbounds parse them per connection.
pub fn uuid_bytes(text: &str) -> Option<[u8; 16]> {
    let stripped: String = text.chars().filter(|c| *c != '-').collect();
    if stripped.len() != 32 || !stripped.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 16];
    for (slot, chunk) in out.iter_mut().zip(stripped.as_bytes().chunks_exact(2)) {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        *slot = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

/// CRC-32 (IEEE 802.3), as the VMess auth id checksum uses.
pub fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for byte in data {
        crc ^= *byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// FNV-1a 32-bit, as the VMess request header checksum uses.
pub fn fnv1a32(data: &[u8]) -> u32 {
    let mut hash = 0x811C_9DC5u32;
    for byte in data {
        hash ^= *byte as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

/// MD5 of arbitrary bytes. VMess derives its command key with it and
/// Shadowsocks derives cipher keys from passwords (EVP_BytesToKey).
pub fn md5(data: &[u8]) -> [u8; 16] {
    use md5::Digest;
    let mut h = Md5::new();
    Digest::update(&mut h, data);
    h.finalize().into()
}

/// HMAC-SHA256 with ring.
pub fn hmac_sha256(key: &[u8], data: &[&[u8]]) -> [u8; 32] {
    use ring::hmac;
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let tag = hmac::sign(&key, &data.concat());
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    out
}

/// `chain_hash`: the VMess AEAD KDF chain. `chain[0]` is the innermost HMAC
/// key (the salt seed); each further element wraps the previous hash as an
/// HMAC whose "hash function" is the previous level — `H_k(m) = H_{k-1}(opad
/// || H_{k-1}(ipad || m))`. Byte-identical to Xray-core's and sing-vmess's
/// KDF per the vectors in the tests.
fn chain_hash(chain: &[&[u8]], msg: &[u8]) -> [u8; 32] {
    if let [seed] = chain {
        return hmac_sha256(seed, &[msg]);
    }
    let (rest, last) = chain.split_at(chain.len() - 1);
    let (ipad, opad) = hmac_pads(last[0]);
    let mut inner = Vec::with_capacity(64 + msg.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(msg);
    let inner = chain_hash(rest, &inner);
    let mut outer = Vec::with_capacity(64 + 32);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner);
    chain_hash(rest, &outer)
}

/// HMAC ipad/opad blocks for a 64-byte-block hash.
fn hmac_pads(key: &[u8]) -> ([u8; 64], [u8; 64]) {
    let mut padded = [0u8; 64];
    let copied = key.len().min(64);
    padded[..copied].copy_from_slice(&key[..copied]);
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for index in 0..64 {
        ipad[index] ^= padded[index];
        opad[index] ^= padded[index];
    }
    (ipad, opad)
}

const KDF_SALT_SEED: &[u8] = b"VMess AEAD KDF";

/// VMess `KDF(key, salts...)`: the seed salt and each path element form the
/// HMAC chain over the key.
pub fn vmess_kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    let mut chain: Vec<&[u8]> = vec![KDF_SALT_SEED];
    chain.extend_from_slice(path);
    chain_hash(&chain, key)
}

pub fn vmess_kdf16(key: &[u8], path: &[&[u8]]) -> [u8; 16] {
    let full = vmess_kdf(key, path);
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

pub fn vmess_kdf12(key: &[u8], path: &[&[u8]]) -> [u8; 12] {
    let full = vmess_kdf(key, path);
    let mut out = [0u8; 12];
    out.copy_from_slice(&full[..12]);
    out
}

/// One raw AES-128 block encryption, as the VMess auth id needs.
pub fn aes128_ecb_block(key: &[u8; 16], block: &mut [u8; 16]) {
    let cipher = aes::Aes128::new(key.into());
    cipher.encrypt_block(block.into());
}

/// VMess `CreateAuthID`: AES-128-encrypt `ts(8 BE) | rand(4) |
/// crc32(ts|rand)(4 BE)` under the auth-ID key.
pub fn vmess_auth_id(auth_key: &[u8; 16], ts: u64, rand4: &[u8; 4]) -> [u8; 16] {
    let mut block = [0u8; 16];
    block[..8].copy_from_slice(&ts.to_be_bytes());
    block[8..12].copy_from_slice(rand4);
    let crc = crc32_ieee(&block[..12]);
    block[12..].copy_from_slice(&crc.to_be_bytes());
    aes128_ecb_block(auth_key, &mut block);
    block
}

/// The AEAD algorithms the outbounds use, resolved once.
#[derive(Clone, Copy)]
pub enum Aead {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl Aead {
    pub fn algorithm(self) -> &'static ring::aead::Algorithm {
        match self {
            Aead::Aes128Gcm => &ring::aead::AES_128_GCM,
            Aead::Aes256Gcm => &ring::aead::AES_256_GCM,
            Aead::ChaCha20Poly1305 => &ring::aead::CHACHA20_POLY1305,
        }
    }

    pub fn key_len(self) -> usize {
        self.algorithm().key_len()
    }

    pub fn tag_len(self) -> usize {
        self.algorithm().tag_len()
    }
}

/// Encrypts `plaintext` into `nonce || ciphertext || tag` (ring's layout for
/// `seal_in_place_append_tag`).
pub fn seal(algorithm: Aead, key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let key = ring::aead::LessSafeKey::new(
        ring::aead::UnboundKey::new(algorithm.algorithm(), key).expect("aead key length"),
    );
    let mut buffer = plaintext.to_vec();
    key.seal_in_place_append_tag(
        ring::aead::Nonce::try_assume_unique_for_key(nonce).expect("aead nonce length"),
        ring::aead::Aad::empty(),
        &mut buffer,
    )
    .expect("aead seal");
    buffer
}

/// Encrypts with additional authenticated data, returning
/// `ciphertext || tag`.
pub fn seal_aad(
    algorithm: Aead,
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Vec<u8> {
    let key = ring::aead::LessSafeKey::new(
        ring::aead::UnboundKey::new(algorithm.algorithm(), key).expect("aead key length"),
    );
    let mut buffer = plaintext.to_vec();
    key.seal_in_place_append_tag(
        ring::aead::Nonce::try_assume_unique_for_key(nonce).expect("aead nonce length"),
        ring::aead::Aad::from(aad),
        &mut buffer,
    )
    .expect("aead seal");
    buffer
}

/// Decrypts `ciphertext || tag`, returning the plaintext.
pub fn open(algorithm: Aead, key: &[u8], nonce: &[u8], sealed: &[u8]) -> Result<Vec<u8>, String> {
    open_aad(algorithm, key, nonce, sealed, &[])
}

pub fn open_aad(
    algorithm: Aead,
    key: &[u8],
    nonce: &[u8],
    sealed: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    let key = ring::aead::LessSafeKey::new(
        ring::aead::UnboundKey::new(algorithm.algorithm(), key).expect("aead key length"),
    );
    let mut buffer = sealed.to_vec();
    let plaintext = key
        .open_in_place(
            ring::aead::Nonce::try_assume_unique_for_key(nonce).expect("aead nonce length"),
            ring::aead::Aad::from(aad),
            &mut buffer,
        )
        .map_err(|_| "AEAD 解密失败".to_owned())?;
    Ok(plaintext.to_vec())
}

/// Cryptographically random bytes from the operating system.
pub fn random(buffer: &mut [u8]) {
    use ring::rand::{SecureRandom, SystemRandom};
    SystemRandom::new()
        .fill(buffer)
        .expect("system random source");
}

pub fn random_vec(len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    random(&mut out);
    out
}

/// SHA-256 from ring (the hand-rolled one in `sha256` is only needed where
/// ring has no variant, i.e. SHA-224).
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = ring::digest::digest(&ring::digest::SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

/// SHA-1, for the Shadowsocks HKDF. Ring gates it behind a legacy flag.
pub fn sha1(data: &[&[u8]]) -> [u8; 20] {
    let mut context = ring::digest::Context::new(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY);
    for part in data {
        context.update(part);
    }
    let digest = context.finish();
    let mut out = [0u8; 20];
    out.copy_from_slice(digest.as_ref());
    out
}

/// OpenSSL `EVP_BytesToKey(MD5, key_len, iv_len, password, count=1)` with no
/// salt: the Shadowsocks password-to-key derivation.
pub fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(key_len + 16);
    let mut previous: Vec<u8> = Vec::new();
    while out.len() < key_len {
        let mut input = previous.clone();
        input.extend_from_slice(password);
        previous = md5(&input).to_vec();
        out.extend_from_slice(&previous);
    }
    out.truncate(key_len);
    out
}

/// HKDF-SHA1 extract-and-expand (Shadowsocks subkey derivation).
pub fn hkdf_sha1(salt: &[u8], ikm: &[u8], info: &[u8], okm_len: usize) -> Result<Vec<u8>, String> {
    use ring::hkdf;
    // ring's expand takes the desired length as a KeyType; the Algorithm
    // constant would pin the output to one digest block (20 bytes).
    struct Len(usize);
    impl hkdf::KeyType for Len {
        fn len(&self) -> usize {
            self.0
        }
    }
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY, salt);
    let prk = salt.extract(ikm);
    let infos: [&[u8]; 1] = [info];
    let okm = prk
        .expand(&infos, Len(okm_len))
        .map_err(|_| "HKDF 输出长度无效".to_owned())?;
    let mut out = vec![0u8; okm_len];
    okm.fill(&mut out).map_err(|_| "HKDF 填充失败".to_owned())?;
    Ok(out)
}

/// VMess body chunk nonce: the 16-byte IV with its first two bytes replaced
/// by the big-endian chunk counter, truncated to 12.
pub fn vmess_chunk_nonce(iv: &[u8; 16], count: u16) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..2].copy_from_slice(&count.to_be_bytes());
    nonce[2..].copy_from_slice(&iv[2..12]);
    nonce
}

/// VMess body chunk length mask: a SHAKE128 keystream over the direction IV.
pub struct ShakeMask {
    reader: sha3::Shake128Reader,
}

impl ShakeMask {
    pub fn new(iv: &[u8; 16]) -> Self {
        let mut hasher = sha3::Shake128::default();
        hasher.update(iv);
        Self {
            reader: hasher.finalize_xof(),
        }
    }

    pub fn next_mask(&mut self) -> [u8; 2] {
        let mut mask = [0u8; 2];
        self.reader.read(&mut mask);
        mask
    }

    pub fn encode_len(&mut self, size: u16) -> [u8; 2] {
        let mask = self.next_mask();
        let [a, b] = size.to_be_bytes();
        [a ^ mask[0], b ^ mask[1]]
    }

    pub fn decode_len(&mut self, encoded: [u8; 2]) -> u16 {
        let mask = self.next_mask();
        u16::from_be_bytes([encoded[0] ^ mask[0], encoded[1] ^ mask[1]])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Vectors generated from the real Xray-core/sing-vmess Go code
    /// (aead/kdf.go, aead/authid.go) with these fixed inputs.
    #[test]
    fn vmess_kdf_and_auth_id_vectors() {
        let uuid = uuid_bytes("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        // cmd key = MD5(uuid bytes || suffix)
        let cmd_key = md5(&[uuid.as_slice(), b"c48619fe-8f02-49e0-b9e9-edf763e17e21"].concat());
        assert_eq!(hex(&cmd_key), "b50d916ac0cec067981af8e5f38a758f");

        let auth_key = vmess_kdf16(&cmd_key, &[b"AES Auth ID Encryption"]);
        assert_eq!(hex(&auth_key), "1415ba74ca8b3d041a8f583fb4116315");

        let auth_id = vmess_auth_id(&auth_key, 1_700_000_000, &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(hex(&auth_id), "7997d3314952dc37e0b284331b6bb2e7");
    }

    #[test]
    fn checksums_match_known_values() {
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF4_3926);
        assert_eq!(fnv1a32(b""), 0x811C_9DC5);
        assert_eq!(fnv1a32(b"a"), 0xE40C_292C);
    }

    #[test]
    fn gcm_round_trip_and_rejection() {
        let key = [7u8; 16];
        let nonce = [9u8; 12];
        let sealed = seal(Aead::Aes128Gcm, &key, &nonce, b"payload");
        assert_eq!(sealed.len(), 7 + 16);
        assert_eq!(open(Aead::Aes128Gcm, &key, &nonce, &sealed).unwrap(), b"payload");
        let mut tampered = sealed.clone();
        tampered[0] ^= 1;
        assert!(open(Aead::Aes128Gcm, &key, &nonce, &tampered).is_err());
    }

    #[test]
    fn aad_changes_ciphertext_and_verifies() {
        let key = [1u8; 16];
        let nonce = [2u8; 12];
        let plain = seal_aad(Aead::Aes128Gcm, &key, &nonce, b"data", b"pub");
        assert_eq!(open_aad(Aead::Aes128Gcm, &key, &nonce, &plain, b"pub").unwrap(), b"data");
        assert!(open_aad(Aead::Aes128Gcm, &key, &nonce, &plain, b"other").is_err());
    }

    #[test]
    fn evp_bytes_to_key_matches_md5_construction() {
        // With no salt and count=1 the first block is MD5(password) itself;
        // MD5("test") is a well-known digest, so the 16-byte key is exactly it.
        let key = evp_bytes_to_key(b"test", 16);
        assert_eq!(hex(&key), "098f6bcd4621d373cade4e832627b4f6");
        // A 32-byte key continues with MD5(D1 || password).
        let long = evp_bytes_to_key(b"test", 32);
        let d2 = md5(&[key.as_slice(), b"test"].concat());
        assert_eq!(hex(&long[16..]), hex(&d2));
    }

    #[test]
    fn shake_mask_round_trip() {
        let iv = [0x22u8; 16];
        let mut mask = ShakeMask::new(&iv);
        let encoded = mask.encode_len(0x1234);
        assert_ne!(encoded, [0x12, 0x34]);
        let mut mask = ShakeMask::new(&iv);
        assert_eq!(mask.decode_len(encoded), 0x1234);
        // Two encodes consume different keystream bytes.
        let mut mask = ShakeMask::new(&iv);
        let first = mask.encode_len(0x0102);
        let second = mask.encode_len(0x0102);
        assert_ne!(first, second);
        let _ = unhex("00");
    }
}
