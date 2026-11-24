# Changelog

## 0.1.0

First release.

- Star-topology P2P QUIC rooms built on `iroh` (`Node`, `HostRoom`, `GuestRoom`).
- Sealed six-symbol short codes (`K7M-2QX`) backed by pkarr TXT records (PBKDF2-HMAC-SHA256 + HKDF-SHA256 + ChaCha20-Poly1305) and full Crockford base32 + CRC-16 room codes (`SR1-...`).
- Constant-time HMAC-SHA256 admission proofs, compatibility manifest checks (`Compat`), slot reservation on reconnect, connection replacement, and kick/ban handling.
- Source-slot-authenticated datagram routing with automatic control-stream fallback when payloads exceed path MTU.
- Generation-scoped JSON request/reply (`RequestToken`) and host push notices.
