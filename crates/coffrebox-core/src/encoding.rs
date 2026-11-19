use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};

const CROCKFORD_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Fills `buf` with cryptographic entropy through `getrandom`.
pub fn fill_random(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|_| CoreError::Entropy)
}

/// Generates a random UUID v4 using `getrandom` (works on `wasm32`).
pub fn random_uuid_v4() -> Result<Uuid> {
    let mut bytes = [0u8; 16];
    fill_random(&mut bytes)?;
    Ok(uuid::Builder::from_random_bytes(bytes).into_uuid())
}

/// Encodes as canonical Base64url without padding (`=`).
pub fn b64url_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decodes strict Base64url without padding.
pub fn b64url_decode(encoded: &str) -> Result<Vec<u8>> {
    if encoded.contains('=') {
        return Err(CoreError::InvalidFormat("base64url padding is not allowed"));
    }
    URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| CoreError::InvalidFormat("invalid base64url"))
}

pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(sha256_bytes(data))
}

/// Encodes bytes as Crockford Base32 (uppercase, no separators or padding).
pub fn crockford_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut bit_buf: u32 = 0;
    let mut bits_in_buf: u32 = 0;
    for &byte in bytes {
        bit_buf = (bit_buf << 8) | u32::from(byte);
        bits_in_buf += 8;
        while bits_in_buf >= 5 {
            bits_in_buf -= 5;
            out.push(CROCKFORD_ALPHABET[((bit_buf >> bits_in_buf) & 0x1F) as usize] as char);
        }
    }
    if bits_in_buf > 0 {
        out.push(CROCKFORD_ALPHABET[((bit_buf << (5 - bits_in_buf)) & 0x1F) as usize] as char);
    }
    out
}

/// Normalizes typed Crockford Base32 text: ignores hyphens and spaces, accepts lowercase and the
/// aliases `O -> 0`, `I/L -> 1`. Returns `None` if a character is outside the alphabet.
pub fn crockford_normalize(input: &str) -> Option<String> {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if ch == '-' || ch.is_whitespace() {
            continue;
        }
        let v = decode_crockford_char(ch)?;
        out.push(CROCKFORD_ALPHABET[usize::from(v)] as char);
    }
    Some(out)
}

fn decode_crockford_char(ch: char) -> Option<u8> {
    match ch.to_ascii_uppercase() {
        '0' | 'O' => Some(0),
        '1' | 'I' | 'L' => Some(1),
        c => CROCKFORD_ALPHABET
            .iter()
            .position(|&a| a as char == c)
            .map(|i| i as u8),
    }
}

/// Cryptographic password generator without modulo bias (rejection sampling).
pub fn generate_password(length: usize, include_symbols: bool) -> Result<Zeroizing<String>> {
    const ALNUM: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    const WITH_SYM: &[u8] =
        b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*()-_=+";

    if !(8..=256).contains(&length) {
        return Err(CoreError::InvalidFormat(
            "password length must be between 8 and 256",
        ));
    }
    let alphabet = if include_symbols { WITH_SYM } else { ALNUM };
    let n = alphabet.len();
    let limit = 256 - (256 % n);

    let mut out = String::with_capacity(length);
    let mut buf = Zeroizing::new([0u8; 64]);

    while out.len() < length {
        fill_random(&mut buf[..])?;
        for &b in &buf[..] {
            if usize::from(b) < limit {
                out.push(alphabet[usize::from(b) % n] as char);
                if out.len() == length {
                    break;
                }
            }
        }
    }

    Ok(Zeroizing::new(out))
}
