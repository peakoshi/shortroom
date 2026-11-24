//! Control-stream framing, compatibility manifests, and room datagram headers.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use bytes::Bytes;
use iroh::endpoint::{RecvStream, SendStream};
use serde::{Deserialize, Serialize};

use crate::MAX_DATAGRAM;

/// Room wire protocol version; hosts refuse any other value.
pub const PROTOCOL: u32 = 1;
pub const KIND_JSON: u8 = 1;
pub const KIND_DATAGRAM: u8 = 2;
/// Maximum serialized JSON control frame size (1 MiB).
pub const MAX_JSON: usize = 1 << 20;
/// Maximum pre-authentication Hello JSON frame size (16 KiB).
pub(crate) const MAX_HELLO_JSON: usize = 16 * 1024;
/// Room datagram header length in bytes: version, source slot, destination slot.
pub const DATAGRAM_HEADER: usize = 3;
/// Leading version byte of every room datagram.
pub const DATAGRAM_VERSION: u8 = 0x01;
/// Sentinel value for an unreadable compatibility field; never matches, not even itself.
pub const UNKNOWN: &str = "unknown";

const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

#[must_use]
pub fn known(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty() && !value.eq_ignore_ascii_case(UNKNOWN)
}

/// Application compatibility manifest checked during room admission.
///
/// `app` and every entry in `fields` are compared byte-exactly; `tags` is compared as an
/// order-independent set. Any empty or [`UNKNOWN`] value fails closed as [`Refusal::Unverified`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Compat {
    pub app: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

impl Compat {
    #[must_use]
    pub fn new(app: impl Into<String>) -> Self {
        Self {
            app: app.into(),
            fields: BTreeMap::new(),
            tags: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.fields.insert(key.into(), value.into());
        self
    }

    #[must_use]
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// First field that either side could not verify, in deterministic comparison order.
    #[must_use]
    pub fn unverified(&self, other: &Self) -> Option<String> {
        if !known(&self.app) || !known(&other.app) {
            return Some("app".to_owned());
        }
        let mut a = self.fields.iter().peekable();
        let mut b = other.fields.iter().peekable();
        loop {
            match (a.peek(), b.peek()) {
                (Some(&(ka, va)), Some(&(kb, vb))) => match ka.cmp(kb) {
                    Ordering::Equal => {
                        if !known(ka) || !known(va) || !known(vb) {
                            return Some(field_label(ka));
                        }
                        a.next();
                        b.next();
                    }
                    Ordering::Less => {
                        if !known(ka) || !known(va) {
                            return Some(field_label(ka));
                        }
                        a.next();
                    }
                    Ordering::Greater => {
                        if !known(kb) || !known(vb) {
                            return Some(field_label(kb));
                        }
                        b.next();
                    }
                },
                (Some(&(ka, va)), None) => {
                    if !known(ka) || !known(va) {
                        return Some(field_label(ka));
                    }
                    a.next();
                }
                (None, Some(&(kb, vb))) => {
                    if !known(kb) || !known(vb) {
                        return Some(field_label(kb));
                    }
                    b.next();
                }
                (None, None) => break,
            }
        }
        if self.tags.iter().chain(&other.tags).any(|t| !known(t)) {
            return Some("tags".to_owned());
        }
        None
    }

    /// First field that prevents `self` and `other` from matching.
    #[must_use]
    pub fn mismatch(&self, other: &Self) -> Option<String> {
        if let Some(field) = self.unverified(other) {
            return Some(field);
        }
        if self.app != other.app {
            return Some("app".to_owned());
        }
        let mut a = self.fields.iter().peekable();
        let mut b = other.fields.iter().peekable();
        loop {
            match (a.peek(), b.peek()) {
                (Some(&(ka, va)), Some(&(kb, vb))) => match ka.cmp(kb) {
                    Ordering::Equal => {
                        if va != vb {
                            return Some(ka.clone());
                        }
                        a.next();
                        b.next();
                    }
                    Ordering::Less => return Some(ka.clone()),
                    Ordering::Greater => return Some(kb.clone()),
                },
                (Some(&(ka, _)), None) => return Some(ka.clone()),
                (None, Some(&(kb, _))) => return Some(kb.clone()),
                (None, None) => break,
            }
        }
        if !tags_equal(&self.tags, &other.tags) {
            return Some("tags".to_owned());
        }
        None
    }
}

fn field_label(key: &str) -> String {
    if known(key) {
        key.to_owned()
    } else {
        "fields".to_owned()
    }
}

fn tags_equal(left: &[String], right: &[String]) -> bool {
    if left == right {
        return true;
    }
    let mut a: Vec<&str> = left.iter().map(String::as_str).collect();
    let mut b: Vec<&str> = right.iter().map(String::as_str).collect();
    a.sort_unstable();
    a.dedup();
    b.sort_unstable();
    b.dedup();
    a == b
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case", tag = "reason", content = "field")]
#[non_exhaustive]
pub enum Refusal {
    #[error("protocol version does not match the host")]
    Protocol,
    #[error("incompatible {0}")]
    Version(String),
    #[error("could not verify {0}")]
    Unverified(String),
    #[error("room code is not valid for this room")]
    Secret,
    #[error("the room is full")]
    Full,
    #[error("you were removed from this room")]
    Kicked,
    #[error("the room is closed to new guests")]
    Closed,
    #[error("invalid join request")]
    BadHello,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    /// Slot number (`1` is the host).
    pub slot: u8,
    pub name: String,
    /// Hex-encoded peer id ([`crate::peer_text`]).
    pub peer: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub(crate) enum Message {
    Hello {
        proto: u32,
        compat: Compat,
        name: String,
        proof: String,
    },
    Welcome {
        slot: u8,
        compat: Compat,
        roster: Vec<Member>,
    },
    Refused {
        #[serde(flatten)]
        refusal: Refusal,
        compat: Compat,
    },
    Roster {
        members: Vec<Member>,
    },
    Request {
        id: u64,
        body: serde_json::Value,
    },
    Reply {
        id: u64,
        body: serde_json::Value,
    },
    RequestBusy {
        id: u64,
    },
    Notice {
        body: serde_json::Value,
    },
    Kick {
        reason: String,
    },
}

#[derive(Debug, PartialEq)]
pub(crate) enum Frame {
    Message(Message),
    Datagram(Bytes),
    /// Pre-validated wire frame (`[kind, len_be_4, payload...]`).
    Encoded(Bytes),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FrameError {
    Closed,
    Invalid,
}

fn length_ok(kind: u8, len: usize) -> bool {
    match kind {
        KIND_JSON => (1..=MAX_JSON).contains(&len),
        KIND_DATAGRAM => (DATAGRAM_HEADER + 1..=DATAGRAM_HEADER + MAX_DATAGRAM).contains(&len),
        _ => false,
    }
}

/// Serialize and frame a JSON control message, enforcing [`MAX_JSON`] before enqueueing.
pub(crate) fn encode_message(message: &Message) -> Option<Bytes> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(&[KIND_JSON, 0, 0, 0, 0]);
    serde_json::to_writer(&mut out, message).ok()?;
    let len = out.len() - 5;
    if !length_ok(KIND_JSON, len) {
        return None;
    }
    out[1..5].copy_from_slice(&u32::try_from(len).ok()?.to_be_bytes());
    Some(Bytes::from(out))
}

#[cfg(test)]
pub(crate) fn encode(frame: &Frame) -> Option<Vec<u8>> {
    match frame {
        Frame::Message(message) => encode_message(message).map(|b| b.to_vec()),
        Frame::Datagram(bytes) => {
            if !length_ok(KIND_DATAGRAM, bytes.len()) {
                return None;
            }
            let mut out = Vec::with_capacity(5 + bytes.len());
            out.push(KIND_DATAGRAM);
            out.extend_from_slice(&u32::try_from(bytes.len()).ok()?.to_be_bytes());
            out.extend_from_slice(bytes);
            Some(out)
        }
        Frame::Encoded(bytes) => Some(bytes.to_vec()),
    }
}

pub(crate) fn decode(kind: u8, payload: Vec<u8>) -> Result<Frame, FrameError> {
    if !length_ok(kind, payload.len()) {
        return Err(FrameError::Invalid);
    }
    match kind {
        KIND_JSON => serde_json::from_slice(&payload)
            .map(Frame::Message)
            .map_err(|_| FrameError::Invalid),
        KIND_DATAGRAM => Ok(Frame::Datagram(Bytes::from(payload))),
        _ => Err(FrameError::Invalid),
    }
}

/// Read one control frame with a custom JSON size cap; header length is checked before allocating.
pub(crate) async fn read_limited(
    recv: &mut RecvStream,
    max_json: usize,
) -> Result<(Frame, usize), FrameError> {
    let mut head = [0_u8; 5];
    recv.read_exact(&mut head)
        .await
        .map_err(|_| FrameError::Closed)?;
    let kind = head[0];
    let len = usize::try_from(u32::from_be_bytes([head[1], head[2], head[3], head[4]]))
        .map_err(|_| FrameError::Invalid)?;
    let valid_len = match kind {
        KIND_JSON => (1..=max_json.min(MAX_JSON)).contains(&len),
        KIND_DATAGRAM => (DATAGRAM_HEADER + 1..=DATAGRAM_HEADER + MAX_DATAGRAM).contains(&len),
        _ => false,
    };
    if !valid_len {
        return Err(FrameError::Invalid);
    }
    let mut payload = vec![0_u8; len];
    recv.read_exact(&mut payload)
        .await
        .map_err(|_| FrameError::Closed)?;
    decode(kind, payload).map(|frame| (frame, len))
}

/// Read one control frame and its wire payload length; header length is checked before allocating.
pub(crate) async fn read(recv: &mut RecvStream) -> Result<(Frame, usize), FrameError> {
    read_limited(recv, MAX_JSON).await
}

pub(crate) async fn write(send: &mut SendStream, frame: &Frame) -> Result<(), FrameError> {
    match frame {
        Frame::Datagram(bytes) => {
            if !length_ok(KIND_DATAGRAM, bytes.len()) {
                return Err(FrameError::Invalid);
            }
            let len = u32::try_from(bytes.len()).map_err(|_| FrameError::Invalid)?;
            let mut head = [0_u8; 5];
            head[0] = KIND_DATAGRAM;
            head[1..5].copy_from_slice(&len.to_be_bytes());
            send.write_all(&head)
                .await
                .map_err(|_| FrameError::Closed)?;
            send.write_all(bytes).await.map_err(|_| FrameError::Closed)
        }
        Frame::Encoded(bytes) => send.write_all(bytes).await.map_err(|_| FrameError::Closed),
        Frame::Message(message) => {
            let bytes = encode_message(message).ok_or(FrameError::Invalid)?;
            send.write_all(&bytes).await.map_err(|_| FrameError::Closed)
        }
    }
}

/// Build a framed room datagram; returns `None` if `payload` is empty or exceeds [`MAX_DATAGRAM`].
#[must_use]
pub fn datagram(src: u8, dst: u8, payload: &[u8]) -> Option<Vec<u8>> {
    if payload.is_empty() || payload.len() > MAX_DATAGRAM {
        return None;
    }
    let mut out = Vec::with_capacity(DATAGRAM_HEADER + payload.len());
    out.extend_from_slice(&[DATAGRAM_VERSION, src, dst]);
    out.extend_from_slice(payload);
    Some(out)
}

pub(crate) fn datagram_bytes(src: u8, dst: u8, payload: &[u8]) -> Option<Bytes> {
    datagram(src, dst, payload).map(Bytes::from)
}

/// Parse a room datagram into `(src, dst, payload)`.
#[must_use]
pub fn parse_datagram(bytes: &[u8]) -> Option<(u8, u8, &[u8])> {
    let (&[version, src, dst], payload) = bytes.split_first_chunk::<DATAGRAM_HEADER>()?;
    (version == DATAGRAM_VERSION && !payload.is_empty() && payload.len() <= MAX_DATAGRAM)
        .then_some((src, dst, payload))
}

/// Encode bytes as lowercase hex.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    let mut out = Vec::with_capacity(bytes.len().saturating_mul(2));
    for &byte in bytes {
        out.push(HEX_LOWER[usize::from(byte >> 4)]);
        out.push(HEX_LOWER[usize::from(byte & 0x0f)]);
    }
    String::from_utf8(out).unwrap_or_default()
}

/// Decode lowercase or uppercase hex into bytes.
#[must_use]
pub fn unhex(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let (pairs, _) = bytes.as_chunks::<2>();
    for pair in pairs {
        let hi = nibble(pair[0])?;
        let lo = nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

#[inline]
fn nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;

    fn sample_compat() -> Compat {
        Compat::new("app/1.0")
            .with_field("assets", "102")
            .with_field("build", "a1b2c3d")
            .with_tag("beta")
            .with_tag("alpha")
    }

    #[test]
    fn compat_compares_fields_deterministically_and_tags_as_sets() {
        let ours = sample_compat();
        let mut theirs = sample_compat();
        theirs.tags.reverse();
        theirs.tags.push("alpha".into());
        assert_eq!(ours.mismatch(&theirs), None);

        theirs.fields.insert("assets".into(), "103".into());
        assert_eq!(ours.mismatch(&theirs).as_deref(), Some("assets"));

        theirs.fields.remove("assets");
        assert_eq!(ours.mismatch(&theirs).as_deref(), Some("assets"));

        let mut extra = sample_compat();
        extra.fields.insert("extra".into(), "1".into());
        assert_eq!(ours.mismatch(&extra).as_deref(), Some("extra"));

        theirs.app = "app/2.0".into();
        assert_eq!(ours.mismatch(&theirs).as_deref(), Some("app"));

        let mut tagged = sample_compat();
        tagged.tags.push("gamma".into());
        assert_eq!(ours.mismatch(&tagged).as_deref(), Some("tags"));
    }

    #[test]
    fn unverified_fields_never_match_even_against_themselves() {
        type Mutator = fn(&mut Compat);
        let cases: [(&str, Mutator); 7] = [
            ("app", |c| c.app = "unknown".into()),
            ("app", |c| c.app = String::new()),
            ("assets", |c| {
                c.fields.insert("assets".into(), "UNKNOWN".into());
            }),
            ("assets", |c| {
                c.fields.insert("assets".into(), "  ".into());
            }),
            ("fields", |c| {
                c.fields.insert(String::new(), "1".into());
            }),
            ("tags", |c| c.tags.push("unknown".into())),
            ("tags", |c| c.tags.push(String::new())),
        ];
        for (expected, mutate) in cases {
            let mut bad = sample_compat();
            mutate(&mut bad);
            assert_eq!(bad.unverified(&bad).as_deref(), Some(expected));
            assert_eq!(bad.mismatch(&bad).as_deref(), Some(expected));
            assert_eq!(sample_compat().unverified(&bad).as_deref(), Some(expected));
        }
    }

    #[test]
    fn frames_and_messages_round_trip_and_refuse_invalid_sizes() {
        let refused = Message::Refused {
            refusal: Refusal::Version("assets".into()),
            compat: sample_compat(),
        };
        let encoded = encode(&Frame::Message(refused.clone())).unwrap();
        assert_eq!(encoded[0], KIND_JSON);
        let json: serde_json::Value = serde_json::from_slice(&encoded[5..]).unwrap();
        assert_eq!(json["t"], "refused");
        assert_eq!(json["reason"], "version");
        assert_eq!(json["field"], "assets");
        match decode(encoded[0], encoded[5..].to_vec()).unwrap() {
            Frame::Message(back) => assert_eq!(back, refused),
            _ => panic!("expected message"),
        }

        let req = Message::Request {
            id: 7,
            body: serde_json::json!({"op": "ping", "seq": 1}),
        };
        let encoded = encode(&Frame::Message(req.clone())).unwrap();
        match decode(encoded[0], encoded[5..].to_vec()).unwrap() {
            Frame::Message(back) => assert_eq!(back, req),
            _ => panic!("expected message"),
        }

        let busy = Message::RequestBusy { id: 9 };
        let encoded = encode(&Frame::Message(busy.clone())).unwrap();
        match decode(encoded[0], encoded[5..].to_vec()).unwrap() {
            Frame::Message(back) => assert_eq!(back, busy),
            _ => panic!("expected message"),
        }

        let oversized = Message::Notice {
            body: serde_json::Value::String("x".repeat(MAX_JSON)),
        };
        assert_eq!(encode_message(&oversized), None);

        let datagram_frame = datagram_bytes(2, 1, b"hello").unwrap();
        let encoded = encode(&Frame::Datagram(datagram_frame.clone())).unwrap();
        assert_eq!(encoded[0], KIND_DATAGRAM);
        match decode(encoded[0], encoded[5..].to_vec()).unwrap() {
            Frame::Datagram(back) => assert_eq!(back, datagram_frame),
            _ => panic!("expected datagram"),
        }

        assert_eq!(decode(99, vec![1]), Err(FrameError::Invalid));
        assert_eq!(decode(KIND_JSON, Vec::new()), Err(FrameError::Invalid));
        assert_eq!(decode(KIND_JSON, b"{".to_vec()), Err(FrameError::Invalid));
        assert_eq!(decode(KIND_DATAGRAM, vec![1, 2]), Err(FrameError::Invalid));
        assert_eq!(
            decode(KIND_DATAGRAM, vec![0; DATAGRAM_HEADER + MAX_DATAGRAM + 1]),
            Err(FrameError::Invalid)
        );
    }

    #[test]
    fn datagram_header_and_hex_round_trip() {
        let packet = datagram(2, 3, b"payload").unwrap();
        assert_eq!(parse_datagram(&packet), Some((2, 3, &b"payload"[..])));
        assert_eq!(datagram(2, 3, &[]), None);
        assert_eq!(datagram(2, 3, &[0; MAX_DATAGRAM + 1]), None);
        assert_eq!(parse_datagram(&[0xFF, 2, 3, 9]), None);
        assert_eq!(parse_datagram(&[DATAGRAM_VERSION, 2, 3]), None);

        let raw = [0x00, 0x0a, 0x7f, 0xde, 0xad, 0xbe, 0xef];
        let encoded = hex(&raw);
        assert_eq!(encoded, "000a7fdeadbeef");
        assert_eq!(unhex(&encoded).as_deref(), Some(&raw[..]));
        assert_eq!(unhex(&encoded.to_uppercase()).as_deref(), Some(&raw[..]));
        assert_eq!(unhex("abc"), None);
        assert_eq!(unhex("zz"), None);
    }
}
