// SPDX-License-Identifier: GPL-3.0-or-later
//! Legacy tunnel interoperability, not a cryptographic design for new protocols.
//! See the private artifact evidence and synthetic native-oracle vectors.
use crate::{
    padding::{self, BlockSize},
    CodecError,
};
use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use md5::{Digest, Md5};
use simple_rijndael::{impls::RijndaelCbc, paddings::Padding};
use std::fmt;
use zeroize::Zeroize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherMode {
    Aes128Cbc,
    Rijndael256Cbc,
}
impl CipherMode {
    /// Native constructor selects 32-byte blocks only for capability exactly 1.
    pub fn from_capability(value: u8) -> Self {
        if value == 1 {
            Self::Rijndael256Cbc
        } else {
            Self::Aes128Cbc
        }
    }
    pub fn block_size(self) -> BlockSize {
        match self {
            Self::Aes128Cbc => BlockSize::Bytes16,
            Self::Rijndael256Cbc => BlockSize::Bytes32,
        }
    }
}

/// No errors carry key material, handshake integers or plaintext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    InvalidHandshake,
    InvalidParameters,
    RandomUnavailable,
    InvalidCiphertext,
    CipherFailure,
    Codec(CodecError),
}
impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHandshake => f.write_str("invalid key handshake length"),
            Self::InvalidParameters => f.write_str("unsupported key exchange parameters"),
            Self::RandomUnavailable => f.write_str("operating system randomness unavailable"),
            Self::InvalidCiphertext => f.write_str("invalid encrypted body length"),
            Self::CipherFailure => f.write_str("legacy cipher operation failed"),
            Self::Codec(e) => fmt::Display::fmt(e, f),
        }
    }
}
impl std::error::Error for CryptoError {}
impl From<CodecError> for CryptoError {
    fn from(e: CodecError) -> Self {
        Self::Codec(e)
    }
}

/// Deliberately not Debug: the key must not appear in logs.
pub struct TunnelCipher {
    mode: CipherMode,
    key: [u8; 16],
    iv: [u8; 32],
    maximum: usize,
}
impl Drop for TunnelCipher {
    fn drop(&mut self) {
        self.key.zeroize();
        self.iv.zeroize();
    }
}

impl TunnelCipher {
    fn from_shared(shared: u64, mode: CipherMode, maximum: usize) -> Result<Self, CryptoError> {
        if maximum < mode.block_size().bytes() || maximum > i32::MAX as usize {
            return Err(CodecError::InvalidLimit.into());
        }
        let mut decimal = shared.to_string();
        let key: [u8; 16] = Md5::digest(decimal.as_bytes()).into();
        decimal.zeroize();
        let iv = derive_iv(&key);
        Ok(Self {
            mode,
            key,
            iv,
            maximum,
        })
    }
    pub(crate) fn diagnostic_material(&self) -> (u8, &[u8; 16], &[u8; 32]) {
        (
            if self.mode == CipherMode::Aes128Cbc {
                1
            } else {
                3
            },
            &self.key,
            &self.iv,
        )
    }
    pub fn mode(&self) -> CipherMode {
        self.mode
    }
    /// Pads and encrypts one body. Every call starts again at the session IV.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let padded = padding::pad(plaintext, self.mode.block_size(), self.maximum)?;
        self.crypt_aligned(&padded, false)
    }
    /// Decrypts and strictly validates padding; empty wire bodies are handled
    /// by the channel layer and must not be submitted to this method.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut plain = self.crypt_aligned(ciphertext, true)?;
        let result = padding::unpad(&plain)
            .map(|p| p.to_vec())
            .map_err(CryptoError::from);
        plain.zeroize();
        result
    }
    fn crypt_aligned(&self, input: &[u8], decrypt: bool) -> Result<Vec<u8>, CryptoError> {
        if input.len() > self.maximum {
            return Err(CodecError::PayloadTooLarge {
                length: input.len(),
                maximum: self.maximum,
            }
            .into());
        }
        if input.is_empty() || input.len() % self.mode.block_size().bytes() != 0 {
            return Err(CryptoError::InvalidCiphertext);
        }
        match self.mode {
            CipherMode::Aes128Cbc => {
                let mut output = input.to_vec();
                let n = output.len();
                if decrypt {
                    cbc::Decryptor::<aes::Aes128>::new((&self.key).into(), self.iv[..16].into())
                        .decrypt_padded_mut::<NoPadding>(&mut output)
                        .map_err(|_| CryptoError::CipherFailure)?;
                } else {
                    cbc::Encryptor::<aes::Aes128>::new((&self.key).into(), self.iv[..16].into())
                        .encrypt_padded_mut::<NoPadding>(&mut output, n)
                        .map_err(|_| CryptoError::CipherFailure)?;
                }
                Ok(output)
            }
            CipherMode::Rijndael256Cbc => {
                let cipher = RijndaelCbc::<AlreadyPadded>::new(&self.key, 32)
                    .map_err(|_| CryptoError::CipherFailure)?;
                if decrypt {
                    cipher.decrypt(&self.iv, input.to_vec())
                } else {
                    cipher.encrypt(&self.iv, input.to_vec())
                }
                .map_err(|_| CryptoError::CipherFailure)
            }
        }
    }
}

// Use the upstream CBC implementation, but never its unchecked PKCS7 decoder.
struct AlreadyPadded(usize);
impl Padding for AlreadyPadded {
    fn new(size: usize) -> Self {
        Self(size)
    }
    fn size(&self) -> usize {
        self.0
    }
    fn encode(&self, input: Vec<u8>) -> Vec<u8> {
        input
    }
    fn decode(&self, input: Vec<u8>) -> Result<Vec<u8>, simple_rijndael::Errors> {
        Ok(input)
    }
}

fn derive_iv(key: &[u8; 16]) -> [u8; 32] {
    let mut iv = [0u8; 32];
    for (dst, a, b) in [
        (2, 15, 0),
        (5, 13, 1),
        (8, 15, 14),
        (12, 11, 12),
        (14, 9, 3),
    ] {
        iv[dst] = key[a].wrapping_add(key[b]);
    }
    iv
}

/// Respond to a cmd3 request. Fresh OS randomness replaces the SDK's weak RNG.
/// Returned 16-byte payload must be wrapped in an ordinary cmd3 BasePacket.
pub fn respond_key_exchange(
    request: &[u8],
    mode: CipherMode,
    maximum: usize,
) -> Result<([u8; 16], TunnelCipher), CryptoError> {
    let mut random = [0u8; 4];
    let exponent = loop {
        getrandom::getrandom(&mut random).map_err(|_| CryptoError::RandomUnavailable)?;
        let value = u32::from_le_bytes(random) & 0x7fff_ffff;
        if value != 0 {
            break value as u64;
        }
    };
    random.zeroize();
    respond_with_exponent(request, exponent, mode, maximum)
}

fn respond_with_exponent(
    request: &[u8],
    exponent: u64,
    mode: CipherMode,
    maximum: usize,
) -> Result<([u8; 16], TunnelCipher), CryptoError> {
    if request.len() != 24 {
        return Err(CryptoError::InvalidHandshake);
    }
    let field = |i| i64::from_le_bytes(request[i..i + 8].try_into().unwrap());
    let (p, g, a) = (field(0), field(8), field(16));
    // The native generated parameters are positive 31-bit values. Bound every
    // operand so multiplication is exact and malicious peers cannot trigger
    // recursion, divide-by-zero or signed-overflow behavior from the SDK.
    if !(5..=i32::MAX as i64).contains(&p)
        || p % 2 == 0
        || g < 2
        || g >= p
        || a < 1
        || a >= p
        || exponent == 0
        || exponent > i32::MAX as u64
    {
        return Err(CryptoError::InvalidParameters);
    }
    let public = pow_mod(g as u64, exponent, p as u64);
    let shared = pow_mod(a as u64, exponent, p as u64);
    let mut response = [0u8; 16];
    response[..8].copy_from_slice(&(public as i64).to_le_bytes());
    Ok((response, TunnelCipher::from_shared(shared, mode, maximum)?))
}
fn pow_mod(mut base: u64, mut exponent: u64, modulus: u64) -> u64 {
    let mut result = 1;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = (result * base) % modulus;
        }
        base = (base * base) % modulus;
        exponent >>= 1;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
    #[test]
    fn native_oracle_vectors_both_modes_and_exchange() {
        // Measured by calling original SDK in network-disabled ARM64 oracle.
        // All inputs below were invented; no account or device data involved.
        for line in include_str!("../tests/fixtures/crypto-native-vectors.jsonl").lines() {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            if v["kind"] == "cbc" {
                let mode = if v["mode"] == 1 {
                    CipherMode::Aes128Cbc
                } else {
                    CipherMode::Rijndael256Cbc
                };
                let mut key = [0; 16];
                for (i, k) in key.iter_mut().enumerate() {
                    *k = i as u8;
                }
                let mut iv = [0; 32];
                for (i, k) in iv.iter_mut().enumerate() {
                    *k = (31 - i) as u8;
                }
                let cipher = TunnelCipher {
                    mode,
                    key,
                    iv,
                    maximum: 1024,
                };
                let n = v["n"].as_u64().unwrap() as usize;
                let input: Vec<u8> = (0..n).map(|i| (i * 17 + 3) as u8).collect();
                let expected = hex(v["hex"].as_str().unwrap());
                assert_eq!(cipher.crypt_aligned(&input, false).unwrap(), expected);
                assert_eq!(
                    cipher.crypt_aligned(&input, false).unwrap(),
                    expected,
                    "IV must reset"
                );
                assert_eq!(cipher.crypt_aligned(&expected, true).unwrap(), input);
            } else if v["kind"] == "dh" {
                let get = |s: &str| v[s].as_u64().unwrap();
                assert_eq!(pow_mod(get("g"), get("a"), get("p")), get("A"));
                assert_eq!(pow_mod(get("g"), get("b"), get("p")), get("B"));
                assert_eq!(pow_mod(get("A"), get("b"), get("p")), get("S_b"));
                assert_eq!(pow_mod(get("B"), get("a"), get("p")), get("S_a"));
                let request: Vec<u8> = [get("p"), get("g"), get("A")]
                    .into_iter()
                    .flat_map(u64::to_le_bytes)
                    .collect();
                let (reply, cipher) =
                    respond_with_exponent(&request, get("b"), CipherMode::Aes128Cbc, 1024).unwrap();
                assert_eq!(&reply[..8], get("B").to_le_bytes());
                assert_eq!(&reply[8..], &[0; 8]);
                let digest: [u8; 16] = Md5::digest(get("S_b").to_string()).into();
                assert_eq!(cipher.key, digest);
            }
        }
    }
    #[test]
    fn large_native_oracle_vectors() {
        // SDK oracle also encrypts twice, decrypts and compares all bytes for
        // every length before emitting the synthetic reference ciphertext.
        for line in include_str!("../tests/fixtures/crypto-native-large.jsonl").lines() {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            let mode = if v["mode"] == 1 {
                CipherMode::Aes128Cbc
            } else {
                CipherMode::Rijndael256Cbc
            };
            let cipher = TunnelCipher {
                mode,
                key: std::array::from_fn(|i| i as u8),
                iv: std::array::from_fn(|i| (31 - i) as u8),
                maximum: 65536,
            };
            let n = v["n"].as_u64().unwrap() as usize;
            let plain: Vec<u8> = (0..n).map(|i| (i * 17 + 3) as u8).collect();
            let encrypted = cipher.crypt_aligned(&plain, false).unwrap();
            assert_eq!(
                format!("{:x}", Md5::digest(&encrypted)),
                v["ciphertext_md5"].as_str().unwrap(),
                "native mismatch mode={mode:?} length={n}"
            );
            assert_eq!(cipher.crypt_aligned(&encrypted, true).unwrap(), plain);
            assert_eq!(cipher.crypt_aligned(&plain, false).unwrap(), encrypted);
        }
    }
    #[test]
    fn padding_lengths_limits_and_malformed_inputs() {
        for mode in [CipherMode::Aes128Cbc, CipherMode::Rijndael256Cbc] {
            let cipher = TunnelCipher::from_shared(2, mode, 128).unwrap();
            for n in [0, 1, 15, 16, 31, 32, 63] {
                let plain = vec![7; n];
                let encrypted = cipher.encrypt(&plain).unwrap();
                assert_eq!(cipher.decrypt(&encrypted).unwrap(), plain);
            }
            assert!(cipher.decrypt(&[]).is_err());
            assert!(cipher.decrypt(&[0; 17]).is_err());
            assert!(cipher.encrypt(&[0; 128]).is_err());
            assert!(cipher.decrypt(&[0; 160]).is_err());
            let malformed = cipher
                .crypt_aligned(&vec![0; mode.block_size().bytes()], false)
                .unwrap();
            assert!(cipher.decrypt(&malformed).is_err());
        }
        assert_eq!(
            respond_with_exponent(&[], 1, CipherMode::Aes128Cbc, 128).err(),
            Some(CryptoError::InvalidHandshake)
        );
        for (p, g, a, b) in [
            (0, 5, 8, 1),
            (23, 23, 8, 1),
            (23, 5, 0, 1),
            (23, 5, 8, 0),
            (i64::MAX, 5, 8, 1),
        ] {
            let request: Vec<u8> = [p, g, a].into_iter().flat_map(i64::to_le_bytes).collect();
            assert!(respond_with_exponent(&request, b, CipherMode::Aes128Cbc, 128).is_err());
        }
    }
    #[test]
    fn iv_byte_positions() {
        let key = std::array::from_fn(|i| i as u8);
        let mut expected = [0; 32];
        for (i, v) in [(2, 15), (5, 14), (8, 29), (12, 23), (14, 12)] {
            expected[i] = v;
        }
        assert_eq!(derive_iv(&key), expected);
        assert_eq!(CipherMode::from_capability(1), CipherMode::Rijndael256Cbc);
        assert_eq!(CipherMode::from_capability(0), CipherMode::Aes128Cbc);
        assert_eq!(CipherMode::from_capability(2), CipherMode::Aes128Cbc);
    }
}
