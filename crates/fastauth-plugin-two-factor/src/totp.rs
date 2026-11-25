//! TOTP (RFC 6238) over HMAC-SHA1, and the base32 encoding authenticator apps read secrets in.

use fastauth_core::crypto::ct_eq;
use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// The HOTP value (RFC 4226) for `counter`, zero-padded to `digits` digits.
pub fn hotp(secret: &[u8], counter: u64, digits: u32) -> String {
    let mut mac =
        <Hmac<Sha1> as KeyInit>::new_from_slice(secret).expect("HMAC takes any key length");
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let truncated = u32::from_be_bytes([
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]);
    format!(
        "{:0width$}",
        truncated % 10u32.pow(digits),
        width = digits as usize
    )
}

/// The TOTP code (RFC 6238) for the `period`-second time step containing `unix_time`.
pub fn totp(secret: &[u8], unix_time: u64, period: u64, digits: u32) -> String {
    hotp(secret, unix_time / period, digits)
}

/// The step in `now_step - 1 ..= now_step + 1` whose code is `code`, compared in constant time.
pub(crate) fn matching_step(secret: &[u8], code: &str, now_step: u64, digits: u32) -> Option<u64> {
    let mut found = None;
    for step in now_step.saturating_sub(1)..=now_step + 1 {
        if ct_eq(hotp(secret, step, digits).as_bytes(), code.as_bytes()) {
            found = Some(step);
        }
    }
    found
}

/// RFC 4648 base32 without padding, as `otpauth://` URIs carry secrets.
pub fn base32(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    for chunk in bytes.chunks(5) {
        let mut block = [0u8; 8];
        block[3..3 + chunk.len()].copy_from_slice(chunk);
        let bits = u64::from_be_bytes(block);
        for i in 0..(chunk.len() * 8).div_ceil(5) {
            out.push(char::from(BASE32[((bits >> (35 - i * 5)) & 31) as usize]));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_rfc_6238_sha1_vectors() {
        let secret = b"12345678901234567890";
        for (time, code) in [
            (59, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
            (20_000_000_000, "65353130"),
        ] {
            assert_eq!(totp(secret, time, 30, 8), code, "T = {time}");
        }
    }

    #[test]
    fn matches_rfc_4226_vectors() {
        let codes = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];
        for (counter, code) in codes.into_iter().enumerate() {
            assert_eq!(hotp(b"12345678901234567890", counter as u64, 6), code);
        }
    }

    #[test]
    fn accepts_one_step_either_side() {
        let secret = b"12345678901234567890";
        let code = hotp(secret, 100, 6);
        assert_eq!(matching_step(secret, &code, 99, 6), Some(100));
        assert_eq!(matching_step(secret, &code, 100, 6), Some(100));
        assert_eq!(matching_step(secret, &code, 101, 6), Some(100));
        assert_eq!(matching_step(secret, &code, 102, 6), None);
        assert_eq!(matching_step(secret, &code[..5], 100, 6), None);
    }

    #[test]
    fn base32_matches_rfc_4648_vectors() {
        for (input, encoded) in [
            ("", ""),
            ("f", "MY"),
            ("fo", "MZXQ"),
            ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI"),
        ] {
            assert_eq!(base32(input.as_bytes()), encoded);
        }
    }
}
