# shortroom

[![crates.io](https://img.shields.io/crates/v/shortroom.svg)](https://crates.io/crates/shortroom)
[![docs.rs](https://img.shields.io/docsrs/shortroom)](https://docs.rs/shortroom)
[![CI](https://github.com/peakoshi/shortroom/actions/workflows/ci.yml/badge.svg)](https://github.com/peakoshi/shortroom/actions/workflows/ci.yml)

Short-code P2P QUIC rooms over [iroh](https://crates.io/crates/iroh).

A host opens a room and hands out either a full Crockford base32 room code (`SR1-...`) or a six-symbol short code (`K7M-2QX`) published as a sealed pkarr TXT record. Guests resolve the code, prove possession of the room secret in constant time, pass an application compatibility check, and exchange authenticated datagrams and JSON control requests in a host-centered star topology.

- Safe Rust only (`#![forbid(unsafe_code)]`).
- Sealed short codes: 1,000,000-round PBKDF2-HMAC-SHA256 + fresh 256-bit salt + HKDF-SHA256 + ChaCha20-Poly1305 AEAD, published as signed pkarr TXT records.
- Authenticated star routing: every datagram's source slot is checked against the peer's QUIC connection; payloads above the current path's QUIC datagram MTU fall back onto the control stream automatically.
- Reconnect slot reservation, stale-connection replacement, kick/ban enforcement, and generation-scoped JSON request/reply (`RequestToken`).
- Synchronous blocking facade owning a bounded background Tokio runtime, usable from game loops or ordinary threads without an outer async runtime.

## Usage

```toml
[dependencies]
shortroom = "0.1"
```

```rust
use std::time::{Duration, Instant};
use shortroom::{
    Compat, HOST_SLOT, Hello, HostConfig, JoinOptions, MemoryStore, Node, NodeOptions, Relay, code,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host_node = Node::start(NodeOptions {
        relay: Relay::Disabled,
        ..NodeOptions::default()
    })?;
    let guest_node = Node::start(NodeOptions {
        relay: Relay::Disabled,
        ..NodeOptions::default()
    })?;

    let deadline = Instant::now() + Duration::from_secs(5);
    while host_node.direct_addrs().is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }

    let compat = Compat::new("demo/1.0").with_field("protocol", "1");
    let room = host_node.host(HostConfig {
        compat: compat.clone(),
        name: "Host".into(),
        capacity: 4,
    })?;

    // Fast in-memory store for offline testing.
    // Over the internet, use `code::publish_short(&host_node, &room.code())`
    // and `code::resolve_code(&guest_node, &typed)` with default `SHORT_ROUNDS`.
    let store = MemoryStore::default();
    let short = code::publish_short_with_rounds(&store, &room.code(), 2)?;
    let resolved = code::resolve_code_with_rounds(&store, &short.text(), 2)?;

    let guest = guest_node.join(
        &resolved,
        &Hello::new(compat, "Guest"),
        &JoinOptions {
            addrs: host_node.direct_addrs(),
            timeout: Duration::from_secs(5),
        },
    )?;

    let deadline = Instant::now() + Duration::from_secs(5);
    let got = loop {
        assert!(room.send(guest.slot(), b"hello"));
        if let Some(d) = guest.recv(Duration::from_millis(100)) {
            break d;
        }
        assert!(Instant::now() < deadline, "datagram timed out");
    };
    assert_eq!((got.src, got.payload.as_slice()), (HOST_SLOT, b"hello".as_slice()));
    Ok(())
}
```

## Security model

- **Host authentication:** `RoomCode` carries the host's 32-byte Ed25519 iroh endpoint id and a fresh 128-bit room secret, protected by CRC-16/CCITT-FALSE against typos.
- **Admission proof:** Guests send `HMAC-SHA256(secret, "shortroom proof v1" || host_id || guest_id)` over TLS-authenticated QUIC, verified in constant time. The secret is never sent on the wire.
- **Short codes:** Six Crockford base32 symbols provide 30 bits of entropy stretched with 1,000,000 rounds of PBKDF2-HMAC-SHA256 using a fixed domain salt, and each publication derives a unique ChaCha20-Poly1305 key via HKDF-SHA256 with a fresh 256-bit salt. Relays store only a public key and ciphertext rather than plaintext, which prevents casual scraping, but the 30-bit fixed-salt space (~2³⁰ × 10⁶ PBKDF2-HMAC-SHA256 evaluations) can be precomputed once in roughly a GPU-day by a motivated observer who collects pkarr keys. Anyone who holds a short code can also derive its record signing key. Treat short codes as convenient invite codes backed by host admission controls (`set_open(false)`, `kick`, `Compat`), and share full `RoomCode` values (`SR1-...`, 128-bit secret) when stronger link confidentiality is required.
- **Datagram authentication:** Every routed datagram's source slot is checked against the QUIC connection it arrived on; spoofed headers are dropped and counted.

## Testing

```sh
cargo test
```

All default tests run locally over loopback with relays disabled and require no internet access. One `#[ignore]` test exercises live public iroh/pkarr relays (`cargo test -- --ignored`).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
