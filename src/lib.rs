//! Short-code P2P QUIC rooms over `iroh`.
//!
//! A [`Node`] opens a [`HostRoom`] whose [`RoomCode`] (`SR1-...`) or six-symbol [`ShortCode`]
//! (`K7M-2QX`) guests resolve and join with via [`Node::join`]. The host verifies each guest's
//! admission proof and [`Compat`] manifest, assigns slots (preserving them across reconnects),
//! routes source-authenticated datagrams in a star topology with automatic control-stream fallback
//! above path MTU, and handles generation-scoped JSON requests and push notices.
#![forbid(unsafe_code)]

pub mod code;
pub mod control;
mod host;
pub mod room;
mod short;

pub use code::{CodeError, MemoryStore, RoomCode, ShortCode, ShortKeys, ShortStore};
pub use control::{Compat, Member, Refusal, UNKNOWN, known};
pub use room::{
    BROADCAST, CountsSnapshot, Datagram, End, GuestEvent, GuestRoom, HOST_SLOT, Hello, HostConfig,
    HostEvent, HostRoom, JoinError, JoinOptions, LinkStats, MAX_NAME, MAX_SLOTS, MemberStatus,
    Node, NodeOptions, ROOM_ALPN, ROOM_BIND_TIMEOUT, RequestToken, close,
};

#[cfg(test)]
mod room_tests;

#[cfg(doctest)]
#[doc = include_str!("../README.md")]
#[allow(dead_code)]
struct ReadmeDoctests;

pub const PEER_ID_LEN: usize = 32;
/// An endpoint identifier (Ed25519 public key bytes).
pub type PeerId = [u8; PEER_ID_LEN];
/// Largest application datagram payload carried in a room.
pub const MAX_DATAGRAM: usize = 1400;

#[derive(Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Relay {
    /// Default public relays and address lookup.
    #[default]
    Default,
    /// A custom HTTPS relay URL (without embedded credentials).
    Custom(String),
    /// No relay and no address lookup: peers dial direct IP addresses only.
    Disabled,
}

impl std::fmt::Debug for Relay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Default => f.write_str("Default"),
            Self::Disabled => f.write_str("Disabled"),
            Self::Custom(url) => f
                .debug_tuple("Custom")
                .field(&short::redacted_url(url))
                .finish(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Path {
    Connecting,
    Direct,
    Relayed,
    Lost,
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("could not start node: {0}")]
    Start(String),
    #[error("invalid relay URL (must be https without credentials)")]
    BadRelay,
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),
    #[error("already hosting a room on this node")]
    AlreadyHosting,
    #[error("request failed: {0}")]
    Request(String),
    #[error("node or room stopped")]
    Stopped,
    #[error("short-code store error: {0}")]
    ShortStore(String),
    #[error(transparent)]
    Code(#[from] CodeError),
}

/// Format a [`PeerId`] as 64 lowercase hex characters.
#[must_use]
pub fn peer_text(id: &PeerId) -> String {
    control::hex(id)
}

/// Parse a 64-character hex [`PeerId`] and check that it is a valid Ed25519 public key.
#[must_use]
pub fn parse_peer(text: &str) -> Option<PeerId> {
    let bytes = control::unhex(text.trim())?;
    let id: PeerId = bytes.try_into().ok()?;
    iroh::EndpointId::from_bytes(&id).ok()?;
    Some(id)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn peer_text_round_trips_valid_keys_and_rejects_malformed_input() {
        let key = iroh::SecretKey::from_bytes(&[7; 32]).public();
        let id = *key.as_bytes();
        let text = peer_text(&id);
        assert_eq!(text.len(), 64);
        assert_eq!(parse_peer(&text), Some(id));
        assert_eq!(parse_peer(&text.to_uppercase()), Some(id));
        assert_eq!(parse_peer(&format!("  {text}\n")), Some(id));
        assert_eq!(parse_peer("not-hex"), None);
        assert_eq!(parse_peer(&text[..62]), None);
    }

    #[test]
    fn relay_debug_strips_credentials_and_query_tokens() {
        let with_creds =
            Relay::Custom("https://alice:hunter2@relay.example:8443/path?tok=xyz".into());
        let formatted = format!("{with_creds:?}");
        assert!(
            formatted.contains("https://relay.example:8443"),
            "{formatted}"
        );
        assert!(!formatted.contains("alice"), "{formatted}");
        assert!(!formatted.contains("hunter2"), "{formatted}");
        assert!(!formatted.contains("tok=xyz"), "{formatted}");
        assert_eq!(
            format!("{:?}", Relay::Custom("not a url".into())),
            "Custom(\"<invalid>\")"
        );
    }
}
