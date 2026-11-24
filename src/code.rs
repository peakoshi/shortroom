//! Full room codes (`SR1-...`) and sealed six-symbol short codes (`K7M-2QX`).
//!
//! A [`RoomCode`] carries the host's [`PeerId`], a 128-bit per-room secret, and a
//! CRC-16/CCITT-FALSE check encoded in Crockford base32 (case-insensitive, `O` as `0`, `I`/`L` as
//! `1`, dashes and spaces ignored).
//!
//! A [`ShortCode`] derives an Ed25519 signing seed and a sealing key via PBKDF2-HMAC-SHA256
//! ([`SHORT_ROUNDS`] = 1,000,000 rounds). Each publication generates a fresh 256-bit salt and
//! derives a single-use ChaCha20-Poly1305 key via HKDF-SHA256 so reusing a short code never reuses
//! a `(key, nonce)` pair.

use std::collections::BTreeMap;
use std::num::NonZeroU32;
use std::sync::{Mutex, PoisonError};

use ring::{aead, hkdf, hmac, pbkdf2, rand::SecureRandom as _};

use crate::{Error, PEER_ID_LEN, PeerId};

pub const PREFIX: &str = "SR1";
pub const SECRET_LEN: usize = 16;
pub const SHORT_SYMBOLS: usize = 6;
/// Production PBKDF2-HMAC-SHA256 iteration count for 30-bit short codes.
pub const SHORT_ROUNDS: u32 = 1_000_000;

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const GROUP: usize = 4;
const CODE_BYTES: usize = PEER_ID_LEN + SECRET_LEN + 2;
const SALT: &[u8] = b"shortroom short code v1";
const SIGN_LABEL: &[u8] = b"sign";
const SEAL_LABEL: &[u8] = b"seal";
const SEAL_VERSION: u8 = 1;
const PUBLICATION_SALT_LEN: usize = 32;
const SEAL_HEADER_LEN: usize = 1 + PUBLICATION_SALT_LEN;
const SEAL_TAG_LEN: usize = 16;
const SEAL_RECORD_LEN: usize = SEAL_HEADER_LEN + CODE_BYTES + SEAL_TAG_LEN;
const PUBLICATION_LABEL: &[u8] = b"shortroom publication v1";
const SEAL_AD: &[u8] = b"SR1 room code v1";
const PROOF_LABEL: &[u8] = b"shortroom proof v1";
const PROOF_MSG_LEN: usize = PROOF_LABEL.len() + 2 * PEER_ID_LEN;

#[allow(clippy::cast_possible_truncation)]
const DECODE_TABLE: [u8; 128] = {
    let mut table = [0xFF_u8; 128];
    let mut i = 0;
    while i < ALPHABET.len() {
        let upper = ALPHABET[i];
        table[upper as usize] = i as u8;
        if upper >= b'A' && upper <= b'Z' {
            table[(upper + 32) as usize] = i as u8;
        }
        i += 1;
    }
    table[b'O' as usize] = 0;
    table[b'o' as usize] = 0;
    table[b'I' as usize] = 1;
    table[b'i' as usize] = 1;
    table[b'L' as usize] = 1;
    table[b'l' as usize] = 1;
    table
};

/// CRC-16/CCITT-FALSE lookup table (polynomial 0x1021, initial 0xFFFF).
#[allow(clippy::cast_possible_truncation)]
const CRC16_TABLE: [u16; 256] = {
    let mut table = [0_u16; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = (i as u16) << 8;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 0x8000 == 0 {
                crc << 1
            } else {
                (crc << 1) ^ 0x1021
            };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

/// A host's room code. Its secret is redacted in `Debug`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RoomCode {
    pub host: PeerId,
    pub secret: [u8; SECRET_LEN],
}

impl std::fmt::Debug for RoomCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RoomCode")
            .field("host", &crate::peer_text(&self.host))
            .field("secret", &format_args!(".."))
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum CodeError {
    #[error("not a room code (expected prefix {PREFIX})")]
    Prefix,
    #[error("code contains an invalid character")]
    Symbol,
    #[error("code is incomplete or too long")]
    Length,
    #[error("code checksum failed")]
    Check,
    #[error("no active room found for that short code")]
    NotFound,
    #[error("cryptographic operation failed")]
    Crypto,
}

impl RoomCode {
    pub fn new(host: PeerId) -> Result<Self, CodeError> {
        let mut secret = [0_u8; SECRET_LEN];
        ring::rand::SystemRandom::new()
            .fill(&mut secret)
            .map_err(|_| CodeError::Crypto)?;
        Ok(Self { host, secret })
    }

    fn bytes(&self) -> [u8; CODE_BYTES] {
        let mut bytes = [0_u8; CODE_BYTES];
        bytes[..PEER_ID_LEN].copy_from_slice(&self.host);
        bytes[PEER_ID_LEN..PEER_ID_LEN + SECRET_LEN].copy_from_slice(&self.secret);
        let crc = crc16(&bytes[..PEER_ID_LEN + SECRET_LEN]);
        bytes[PEER_ID_LEN + SECRET_LEN..].copy_from_slice(&crc.to_be_bytes());
        bytes
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, CodeError> {
        if bytes.len() != CODE_BYTES {
            return Err(CodeError::Length);
        }
        let (body, check) = bytes.split_at(PEER_ID_LEN + SECRET_LEN);
        if crc16(body).to_be_bytes() != check {
            return Err(CodeError::Check);
        }
        let mut code = Self {
            host: [0; PEER_ID_LEN],
            secret: [0; SECRET_LEN],
        };
        code.host.copy_from_slice(&body[..PEER_ID_LEN]);
        code.secret.copy_from_slice(&body[PEER_ID_LEN..]);
        Ok(code)
    }

    #[must_use]
    pub fn encode(&self) -> String {
        let raw = self.bytes();
        let sym_len = (CODE_BYTES * 8).div_ceil(5);
        let mut text = String::with_capacity(PREFIX.len() + sym_len + sym_len.div_ceil(GROUP));
        text.push_str(PREFIX);
        let mut buffer = 0_u32;
        let mut bits = 0_u32;
        let mut emitted = 0_usize;
        for byte in raw {
            buffer = (buffer << 8) | u32::from(byte);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                if emitted.is_multiple_of(GROUP) {
                    text.push('-');
                }
                text.push(char::from(ALPHABET[((buffer >> bits) & 0x1f) as usize]));
                emitted += 1;
            }
            buffer &= (1 << bits) - 1;
        }
        if bits > 0 {
            if emitted.is_multiple_of(GROUP) {
                text.push('-');
            }
            text.push(char::from(
                ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize],
            ));
        }
        text
    }

    pub fn decode(text: &str) -> Result<Self, CodeError> {
        let text = text.trim();
        let rest = text
            .get(..PREFIX.len())
            .filter(|prefix| prefix.eq_ignore_ascii_case(PREFIX))
            .and_then(|_| text.get(PREFIX.len()..))
            .ok_or(CodeError::Prefix)?;
        let bytes = base32_decode_exact::<CODE_BYTES>(rest)?;
        Self::from_bytes(&bytes)
    }

    fn proof_message(&self, guest: &PeerId) -> [u8; PROOF_MSG_LEN] {
        let mut msg = [0_u8; PROOF_MSG_LEN];
        msg[..PROOF_LABEL.len()].copy_from_slice(PROOF_LABEL);
        msg[PROOF_LABEL.len()..PROOF_LABEL.len() + PEER_ID_LEN].copy_from_slice(&self.host);
        msg[PROOF_LABEL.len() + PEER_ID_LEN..].copy_from_slice(guest);
        msg
    }

    /// Admission proof bound to this room secret, host id, and `guest`.
    #[must_use]
    pub fn proof(&self, guest: &PeerId) -> [u8; 32] {
        let key = hmac::Key::new(hmac::HMAC_SHA256, &self.secret);
        let message = self.proof_message(guest);
        let mut out = [0_u8; 32];
        out.copy_from_slice(hmac::sign(&key, &message).as_ref());
        out
    }

    /// Constant-time verification of a guest's admission proof.
    #[must_use]
    pub fn verify(&self, guest: &PeerId, proof: &[u8]) -> bool {
        let key = hmac::Key::new(hmac::HMAC_SHA256, &self.secret);
        let message = self.proof_message(guest);
        hmac::verify(&key, &message, proof).is_ok()
    }
}

/// A six-symbol Crockford base32 short code (each entry in `0..32`). Redacted in `Debug`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ShortCode([u8; SHORT_SYMBOLS]);

impl std::fmt::Debug for ShortCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ShortCode(..)")
    }
}

/// Keys derived from a [`ShortCode`]: record signing seed and AEAD sealing key.
pub struct ShortKeys {
    /// Ed25519 seed for the signed short-code record.
    pub signing: [u8; 32],
    seal: [u8; 32],
}

impl std::fmt::Debug for ShortKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ShortKeys(..)")
    }
}

impl ShortCode {
    pub fn random() -> Result<Self, CodeError> {
        let mut bytes = [0_u8; SHORT_SYMBOLS];
        ring::rand::SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| CodeError::Crypto)?;
        Ok(Self(bytes.map(|byte| byte & 0x1f)))
    }

    /// Parse exactly six Crockford base32 symbols, trimming surrounding whitespace and ignoring
    /// ASCII dashes and spaces.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let mut symbols = [0_u8; SHORT_SYMBOLS];
        let mut count = 0_usize;
        for character in text.trim().chars().filter(|c| !matches!(c, '-' | ' ')) {
            *symbols.get_mut(count)? = symbol_value(character)?;
            count += 1;
        }
        (count == SHORT_SYMBOLS).then_some(Self(symbols))
    }

    /// Format as two groups of three symbols (`K7M-2QX`).
    #[must_use]
    pub fn text(&self) -> String {
        let mut text = String::with_capacity(SHORT_SYMBOLS + 1);
        for (index, value) in self.0.iter().enumerate() {
            if index == SHORT_SYMBOLS / 2 {
                text.push('-');
            }
            text.push(char::from(
                ALPHABET.get(usize::from(*value)).copied().unwrap_or(b'0'),
            ));
        }
        text
    }

    /// Derive record keys using [`SHORT_ROUNDS`] PBKDF2-HMAC-SHA256 iterations.
    #[must_use]
    pub fn keys(&self) -> ShortKeys {
        self.keys_with(SHORT_ROUNDS)
    }

    /// Derive record keys using `rounds` PBKDF2 iterations (clamped to at least 1).
    #[must_use]
    pub fn keys_with(&self, rounds: u32) -> ShortKeys {
        let mut master = [0_u8; 32];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            NonZeroU32::new(rounds).unwrap_or(NonZeroU32::MIN),
            SALT,
            &self.0,
            &mut master,
        );
        let key = hmac::Key::new(hmac::HMAC_SHA256, &master);
        let derive = |label: &[u8]| {
            let mut out = [0_u8; 32];
            out.copy_from_slice(hmac::sign(&key, label).as_ref());
            out
        };
        ShortKeys {
            signing: derive(SIGN_LABEL),
            seal: derive(SEAL_LABEL),
        }
    }
}

impl ShortKeys {
    fn aead(&self, salt: &[u8]) -> Result<aead::LessSafeKey, CodeError> {
        let key = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(&self.seal);
        let info = [PUBLICATION_LABEL];
        let material = key
            .expand(&info, &aead::CHACHA20_POLY1305)
            .map_err(|_| CodeError::Crypto)?;
        Ok(aead::LessSafeKey::new(aead::UnboundKey::from(material)))
    }

    /// Seal `code` with a fresh 256-bit publication salt and return Crockford base32 text.
    ///
    /// HKDF derives a unique AEAD key per publication salt, so the zero nonce is never reused.
    pub fn seal(&self, code: &RoomCode) -> Result<String, CodeError> {
        let mut record = [0_u8; SEAL_RECORD_LEN];
        record[0] = SEAL_VERSION;
        let (salt, rest) = record[1..].split_at_mut(PUBLICATION_SALT_LEN);
        ring::rand::SystemRandom::new()
            .fill(salt)
            .map_err(|_| CodeError::Crypto)?;
        let (body, tag_slot) = rest.split_at_mut(CODE_BYTES);
        body.copy_from_slice(&code.bytes());
        let tag = self
            .aead(salt)?
            .seal_in_place_separate_tag(
                aead::Nonce::assume_unique_for_key([0; 12]),
                aead::Aad::from(SEAL_AD),
                body,
            )
            .map_err(|_| CodeError::Crypto)?;
        tag_slot.copy_from_slice(tag.as_ref());
        Ok(base32_encode(&record))
    }

    /// Open a sealed short-code record; returns `None` on bad format, wrong code, or tampering.
    #[must_use]
    pub fn open(&self, sealed: &str) -> Option<RoomCode> {
        let mut record = base32_decode_exact::<SEAL_RECORD_LEN>(sealed).ok()?;
        if record[0] != SEAL_VERSION {
            return None;
        }
        let (salt, ciphertext) = record[1..].split_at_mut(PUBLICATION_SALT_LEN);
        let plain = self
            .aead(salt)
            .ok()?
            .open_in_place(
                aead::Nonce::assume_unique_for_key([0; 12]),
                aead::Aad::from(SEAL_AD),
                ciphertext,
            )
            .ok()?;
        RoomCode::from_bytes(plain).ok()
    }

    /// Withdraw this key's record from `store` without re-running PBKDF2 key derivation.
    pub fn withdraw(&self, store: &dyn ShortStore) -> Result<(), Error> {
        store.publish(self.signing, String::new())
    }
}

pub trait ShortStore {
    /// Publish `value` under `seed`'s signing key; an empty string withdraws the record.
    fn publish(&self, seed: [u8; 32], value: String) -> Result<(), Error>;
    fn resolve(&self, seed: [u8; 32]) -> Result<Option<String>, Error>;
}

/// In-memory [`ShortStore`] for local tests and offline workflows. Redacted in `Debug`.
#[derive(Default)]
pub struct MemoryStore(Mutex<BTreeMap<[u8; 32], String>>);

impl std::fmt::Debug for MemoryStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let entries = self.0.lock().unwrap_or_else(PoisonError::into_inner).len();
        f.debug_struct("MemoryStore")
            .field("entries", &entries)
            .finish_non_exhaustive()
    }
}

impl ShortStore for MemoryStore {
    fn publish(&self, seed: [u8; 32], value: String) -> Result<(), Error> {
        let mut entries = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if value.is_empty() {
            entries.remove(&seed);
        } else {
            entries.insert(seed, value);
        }
        Ok(())
    }

    fn resolve(&self, seed: [u8; 32]) -> Result<Option<String>, Error> {
        Ok(self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&seed)
            .cloned())
    }
}

/// Generate a random [`ShortCode`], seal `code`, and publish it to `store` using [`SHORT_ROUNDS`].
pub fn publish_short(store: &dyn ShortStore, code: &RoomCode) -> Result<ShortCode, Error> {
    publish_short_with_rounds(store, code, SHORT_ROUNDS)
}

/// Like [`publish_short`], with an explicit PBKDF2 round count (primarily for tests).
pub fn publish_short_with_rounds(
    store: &dyn ShortStore,
    code: &RoomCode,
    rounds: u32,
) -> Result<ShortCode, Error> {
    let short = ShortCode::random()?;
    let keys = short.keys_with(rounds);
    let sealed = keys.seal(code)?;
    store.publish(keys.signing, sealed)?;
    Ok(short)
}

/// Withdraw a previously published short code from `store` using [`SHORT_ROUNDS`].
pub fn withdraw_short(store: &dyn ShortStore, short: &ShortCode) -> Result<(), Error> {
    withdraw_short_with_rounds(store, short, SHORT_ROUNDS)
}

/// Like [`withdraw_short`], with an explicit PBKDF2 round count.
pub fn withdraw_short_with_rounds(
    store: &dyn ShortStore,
    short: &ShortCode,
    rounds: u32,
) -> Result<(), Error> {
    let keys = short.keys_with(rounds);
    store.publish(keys.signing, String::new())
}

/// Resolve either a full [`RoomCode`] or a [`ShortCode`] (via `store` and [`SHORT_ROUNDS`]).
pub fn resolve_code(store: &dyn ShortStore, text: &str) -> Result<RoomCode, Error> {
    resolve_code_with_rounds(store, text, SHORT_ROUNDS)
}

/// Like [`resolve_code`], with an explicit PBKDF2 round count (primarily for tests).
pub fn resolve_code_with_rounds(
    store: &dyn ShortStore,
    text: &str,
    rounds: u32,
) -> Result<RoomCode, Error> {
    let Some(short) = ShortCode::parse(text) else {
        return Ok(RoomCode::decode(text)?);
    };
    let keys = short.keys_with(rounds);
    store
        .resolve(keys.signing)?
        .filter(|sealed| !sealed.is_empty())
        .and_then(|sealed| keys.open(&sealed))
        .ok_or(Error::Code(CodeError::NotFound))
}

/// Extract a canonical room code or candidate short code from pasted text, ignoring surrounding
/// punctuation.
///
/// Any standalone 6-character Crockford base32 word (such as `"thanks"`) matches as a candidate
/// short code, so call this on explicit user input rather than arbitrary background text.
#[must_use]
pub fn find_code(text: &str) -> Option<String> {
    if let Some(code) = room_code_in(text) {
        return Some(code.encode());
    }
    if let Some(short) = exact_short_code(text) {
        return Some(short.text());
    }
    short_code_in(text).map(|short| short.text())
}

fn is_dash(character: char) -> bool {
    matches!(character, '-' | '\u{2010}'..='\u{2015}' | '\u{2212}')
}

fn exact_short_code(text: &str) -> Option<ShortCode> {
    let mut symbols = [0_u8; SHORT_SYMBOLS];
    let mut count = 0_usize;
    for character in text.chars().filter(char::is_ascii_alphanumeric) {
        *symbols.get_mut(count)? = symbol_value(character)?;
        count += 1;
    }
    (count == SHORT_SYMBOLS).then_some(ShortCode(symbols))
}

fn room_code_in(text: &str) -> Option<RoomCode> {
    let length = PREFIX.len() + (CODE_BYTES * 8).div_ceil(5);
    let upper = text.to_ascii_uppercase();
    upper.match_indices(PREFIX).find_map(|(start, _)| {
        let mut kept = String::with_capacity(length);
        for character in text.get(start..)?.chars() {
            match character {
                c if c.is_ascii_alphanumeric() => kept.push(c),
                c if c.is_whitespace() || is_dash(c) => {}
                _ => break,
            }
            if kept.len() == length {
                break;
            }
        }
        RoomCode::decode(&kept).ok()
    })
}

fn short_code_in(text: &str) -> Option<ShortCode> {
    let half = SHORT_SYMBOLS / 2;
    let mut prev: Option<(usize, usize)> = None;
    let mut run_start: Option<usize> = None;

    for (index, character) in text.char_indices().chain([(text.len(), ' ')]) {
        match (character.is_ascii_alphanumeric(), run_start) {
            (true, None) => run_start = Some(index),
            (false, Some(start)) => {
                let current = (start, index);
                run_start = None;
                if let Some((p_start, p_end)) = prev
                    && p_end - p_start == half
                    && current.1 - current.0 == half
                    && let Some(gap) = text.get(p_end..current.0)
                    && gap.chars().any(is_dash)
                    && gap.chars().all(|c| c == ' ' || is_dash(c))
                    && let (Some(left), Some(right)) =
                        (text.get(p_start..p_end), text.get(current.0..current.1))
                    && let Some(short) = parse_pair(left, right)
                {
                    return Some(short);
                }
                prev = Some(current);
            }
            _ => {}
        }
    }
    None
}

fn parse_pair(left: &str, right: &str) -> Option<ShortCode> {
    let mut symbols = [0_u8; SHORT_SYMBOLS];
    let mut count = 0_usize;
    for character in left.chars().chain(right.chars()) {
        *symbols.get_mut(count)? = symbol_value(character)?;
        count += 1;
    }
    (count == SHORT_SYMBOLS).then_some(ShortCode(symbols))
}

#[allow(clippy::cast_possible_truncation)]
fn crc16(bytes: &[u8]) -> u16 {
    let mut crc = 0xFFFF_u16;
    for &byte in bytes {
        let index = usize::from(((crc >> 8) as u8) ^ byte);
        crc = (crc << 8) ^ CRC16_TABLE[index];
    }
    crc
}

fn base32_encode(bytes: &[u8]) -> String {
    let mut text = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let (mut buffer, mut bits) = (0_u32, 0_u32);
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            text.push(char::from(ALPHABET[((buffer >> bits) & 0x1f) as usize]));
        }
        buffer &= (1 << bits) - 1;
    }
    if bits > 0 {
        text.push(char::from(
            ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize],
        ));
    }
    text
}

/// Decode exactly `N` bytes of Crockford base32 onto the stack; trailing pad bits must be zero.
fn base32_decode_exact<const N: usize>(text: &str) -> Result<[u8; N], CodeError> {
    let max_symbols = (N * 8).div_ceil(5);
    let mut out = [0_u8; N];
    let (mut buffer, mut bits, mut written, mut symbols) = (0_u32, 0_u32, 0_usize, 0_usize);
    for character in text.chars().filter(|c| !matches!(c, '-' | ' ')) {
        let value = symbol_value(character).ok_or(CodeError::Symbol)?;
        symbols += 1;
        if symbols > max_symbols {
            return Err(CodeError::Length);
        }
        buffer = (buffer << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            let slot = out.get_mut(written).ok_or(CodeError::Length)?;
            *slot = u8::try_from((buffer >> bits) & 0xff).unwrap_or(0);
            written += 1;
            buffer &= (1 << bits) - 1;
        }
    }
    if written != N {
        return Err(CodeError::Length);
    }
    if buffer != 0 {
        return Err(CodeError::Check);
    }
    Ok(out)
}

#[inline]
fn symbol_value(character: char) -> Option<u8> {
    let byte = u32::from(character);
    let value = *DECODE_TABLE.get(usize::try_from(byte).ok()?)?;
    (value != 0xFF).then_some(value)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use proptest::prelude::*;

    use super::*;

    fn sample_code() -> RoomCode {
        RoomCode {
            host: std::array::from_fn(|i| u8::try_from(i * 11 % 256).unwrap()),
            secret: [7; SECRET_LEN],
        }
    }

    #[test]
    fn room_code_round_trips_and_rejects_every_single_symbol_typo() {
        let code = sample_code();
        let text = code.encode();
        assert!(text.starts_with("SR1-"));
        assert_eq!(RoomCode::decode(&text), Ok(code));
        assert_eq!(RoomCode::decode(&text.to_lowercase()), Ok(code));
        assert_eq!(RoomCode::decode(&text.replace('-', " ")), Ok(code));
        assert_eq!(RoomCode::decode("XX1-AAAA"), Err(CodeError::Prefix));
        assert_eq!(
            RoomCode::decode(&text[..text.len() - 1]),
            Err(CodeError::Length)
        );
        assert_eq!(
            RoomCode::decode(&format!("{text}U")),
            Err(CodeError::Symbol)
        );

        for (index, original) in text.char_indices().skip(PREFIX.len()) {
            if original == '-' {
                continue;
            }
            for &replacement in ALPHABET {
                let replacement = char::from(replacement);
                if replacement == original {
                    continue;
                }
                let mut typo = text.clone();
                typo.replace_range(index..=index, &replacement.to_string());
                assert!(RoomCode::decode(&typo).is_err(), "{typo}");
            }
        }
        assert!(!format!("{code:?}").contains("0707"));
    }

    #[test]
    fn find_code_extracts_short_and_full_codes_from_pasted_text() {
        let short = Some("K7M-2QX".to_owned());
        for pasted in [
            "K7M-2QX",
            "k7m 2qx",
            "k7m2qx",
            "\"K7M-2QX\"",
            "`k7m-2qx`",
            "  k7m-2qx\r\n",
            "\u{201c}K7M-2QX\u{201d}",
            "K7M\u{2013}2QX",
            "Code: K7M-2QX",
            "join me with k7m-2qx!",
        ] {
            assert_eq!(find_code(pasted), short, "{pasted:?}");
        }

        let full = sample_code().encode();
        for pasted in [
            full.clone(),
            full.to_lowercase(),
            format!("\"{full}\"\n"),
            format!("`{}`", full.replace('-', " ")),
            format!("{}\n{}", &full[..50], &full[50..]),
            format!("My room: {full} see you there"),
        ] {
            assert_eq!(find_code(&pasted), Some(full.clone()), "{pasted:?}");
        }

        for nothing in [
            "",
            "...",
            "hello there",
            "K7M-2Q",
            "my code is soon",
            "SR1-0000",
        ] {
            assert_eq!(find_code(nothing), None, "{nothing:?}");
        }
    }

    #[test]
    fn proof_binds_secret_host_and_guest() {
        let code = sample_code();
        let guest = [9; PEER_ID_LEN];
        let proof = code.proof(&guest);
        assert!(code.verify(&guest, &proof));
        assert!(!code.verify(&[8; PEER_ID_LEN], &proof));
        assert!(!code.verify(&guest, &proof[..31]));
        let other = RoomCode {
            secret: [6; SECRET_LEN],
            ..code
        };
        assert!(!other.verify(&guest, &proof));
    }

    #[test]
    fn short_code_parses_crockford_aliases_and_rejects_invalid() {
        let short = ShortCode([20, 7, 19, 2, 23, 30]);
        assert_eq!(short.text(), "M7K-2QY");
        assert_eq!(ShortCode::parse("m7k 2qy"), Some(short));
        assert_eq!(ShortCode::parse("OIL-000"), ShortCode::parse("011-000"));
        assert_eq!(ShortCode::parse("M7K-2Q"), None);
        assert_eq!(ShortCode::parse("M7K-2QYZ"), None);
        assert_eq!(ShortCode::parse("M7K-2QU"), None);
        let random = ShortCode::random().unwrap();
        assert_eq!(ShortCode::parse(&random.text()), Some(random));
    }

    #[test]
    fn each_publication_uses_fresh_sealing_material_and_authenticates_all_bytes() {
        let code = sample_code();
        let short = ShortCode([1, 2, 3, 4, 5, 6]);
        let keys = short.keys_with(3);
        let first = keys.seal(&code).unwrap();
        let second = short.keys_with(3).seal(&code).unwrap();
        assert_ne!(first, second);
        assert_eq!(keys.open(&first), Some(code));
        assert_eq!(keys.open(&second), Some(code));

        let other = ShortCode([1, 2, 3, 4, 5, 7]).keys_with(3);
        assert_ne!(other.signing, keys.signing);
        assert_eq!(other.open(&first), None);
        assert_eq!(keys.open("not base32!"), None);
        assert_eq!(keys.open(&first[..first.len() - 2]), None);

        let record = base32_decode_exact::<SEAL_RECORD_LEN>(&first).unwrap();
        assert_eq!(record[0], SEAL_VERSION);
        for index in 0..record.len() {
            let mut tampered = record;
            tampered[index] ^= 1;
            assert!(
                keys.open(&base32_encode(&tampered)).is_none(),
                "byte {index}"
            );
        }
    }

    #[test]
    fn sealed_record_survives_signed_pkarr_packet_wire_format() {
        let code = sample_code();
        let store = MemoryStore::default();
        let short = publish_short_with_rounds(&store, &code, 3).unwrap();
        let keys = short.keys_with(3);
        let sealed = store.resolve(keys.signing).unwrap().unwrap();
        assert!(sealed.len() <= 255);

        let packet = crate::short::packet(&keys.signing, &sealed).unwrap();
        let wire = packet.to_relay_payload();
        let decoded = iroh_dns::pkarr::SignedPacket::from_relay_payload(
            &iroh::SecretKey::from_bytes(&keys.signing).public(),
            &wire,
        )
        .unwrap();
        let fetched = MemoryStore::default();
        fetched
            .publish(keys.signing, crate::short::value(&decoded).unwrap())
            .unwrap();
        assert_eq!(
            resolve_code_with_rounds(&fetched, &short.text(), 3).unwrap(),
            code
        );
    }

    #[test]
    fn pbkdf2_vector_and_production_round_count() {
        let short = ShortCode([0; SHORT_SYMBOLS]);
        let password = hmac::Key::new(hmac::HMAC_SHA256, &[0; SHORT_SYMBOLS]);
        let mut salted = SALT.to_vec();
        salted.extend_from_slice(&1_u32.to_be_bytes());
        let master = hmac::sign(&password, &salted);
        let sign = hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, master.as_ref()),
            SIGN_LABEL,
        );
        assert_eq!(short.keys_with(1).signing.as_slice(), sign.as_ref());
        assert_eq!(SHORT_ROUNDS, 1_000_000);
    }

    #[test]
    fn memory_store_publishes_resolves_and_withdraws() {
        let code = sample_code();
        let store = MemoryStore::default();
        let short = publish_short_with_rounds(&store, &code, 2).unwrap();
        assert_eq!(
            resolve_code_with_rounds(&store, &short.text(), 2).unwrap(),
            code
        );
        assert_eq!(
            resolve_code_with_rounds(&store, &format!("  {}\r\n", short.text()), 2).unwrap(),
            code
        );
        assert_eq!(
            resolve_code_with_rounds(&store, &code.encode(), 2).unwrap(),
            code
        );
        assert!(matches!(
            resolve_code_with_rounds(&store, "ZZZ-ZZZ", 2),
            Err(Error::Code(CodeError::NotFound))
        ));
        assert!(resolve_code_with_rounds(&store, "hello", 2).is_err());

        withdraw_short_with_rounds(&store, &short, 2).unwrap();
        assert_eq!(store.resolve(short.keys_with(2).signing).unwrap(), None);
        assert!(matches!(
            resolve_code_with_rounds(&store, &short.text(), 2),
            Err(Error::Code(CodeError::NotFound))
        ));

        let second = publish_short_with_rounds(&store, &code, 2).unwrap();
        let keys = second.keys_with(2);
        keys.withdraw(&store).unwrap();
        assert_eq!(store.resolve(keys.signing).unwrap(), None);
    }

    #[test]
    fn short_code_and_memory_store_redact_credentials_in_debug() {
        let short = ShortCode([20, 7, 19, 2, 23, 30]);
        assert_eq!(format!("{short:?}"), "ShortCode(..)");

        let store = MemoryStore::default();
        store
            .publish([137_u8; 32], "sealed-secret-blob".into())
            .unwrap();
        let formatted = format!("{store:?}");
        assert!(formatted.contains("entries: 1"), "{formatted}");
        assert!(!formatted.contains("137"), "{formatted}");
        assert!(!formatted.contains("sealed-secret-blob"), "{formatted}");
    }

    #[test]
    fn crc16_table_matches_standard_ccitt_false_check_value() {
        assert_eq!(crc16(b"123456789"), 0x29B1);
    }

    proptest! {
        #[test]
        fn room_code_round_trips_any_host_and_secret(
            host in any::<[u8; PEER_ID_LEN]>(),
            secret in any::<[u8; SECRET_LEN]>(),
        ) {
            let code = RoomCode { host, secret };
            let encoded = code.encode();
            prop_assert_eq!(RoomCode::decode(&encoded), Ok(code));
            prop_assert_eq!(find_code(&format!("join: {encoded}!")), Some(encoded));
        }

        #[test]
        fn find_code_and_decoders_never_panic_on_arbitrary_utf8(input in ".*") {
            let _ = RoomCode::decode(&input);
            let _ = ShortCode::parse(&input);
            let _ = find_code(&input);
        }
    }
}
