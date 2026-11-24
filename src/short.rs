//! Signed pkarr DNS TXT records for short room codes.

use std::sync::mpsc as sync;
use std::time::Duration;

use iroh::SecretKey;
use iroh::address_lookup::pkarr::{N0_DNS_PKARR_RELAY_PROD, PkarrRelayClient};
use iroh_dns::pkarr::SignedPacket;
use url::Url;

use crate::Error;

const NAME: &str = "_shortroom";
const TTL: u32 = 300;
const MAX_URL_LEN: usize = 2048;
pub(crate) const LIMIT: Duration = Duration::from_secs(10);

pub(crate) enum Work {
    Publish { seed: [u8; 32], value: String },
    Resolve { seed: [u8; 32] },
}

pub(crate) struct Job {
    pub(crate) work: Work,
    pub(crate) reply: sync::SyncSender<Result<Option<String>, String>>,
}

impl std::fmt::Debug for Job {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self.work {
            Work::Publish { .. } => "Job(publish)",
            Work::Resolve { .. } => "Job(resolve)",
        })
    }
}

pub(crate) fn packet(seed: &[u8; 32], value: &str) -> Result<SignedPacket, String> {
    SignedPacket::from_txt_strings(&SecretKey::from_bytes(seed), NAME, [value], TTL)
        .map_err(|error| error.to_string())
}

pub(crate) fn value(packet: &SignedPacket) -> Option<String> {
    packet.txt_records(NAME).into_iter().next()
}

/// Sanitize a URL for `Debug` output by keeping only scheme, host, and optional port.
pub(crate) fn redacted_url(text: &str) -> String {
    let Ok(url) = Url::parse(text.trim()) else {
        return "<invalid>".to_owned();
    };
    let Some(host) = url.host_str() else {
        return "<invalid>".to_owned();
    };
    match url.port() {
        Some(port) => format!("{}://{host}:{port}", url.scheme()),
        None => format!("{}://{host}", url.scheme()),
    }
}

/// Validate that a relay URL is HTTPS with a host, bounded length, and no embedded credentials.
pub(crate) fn validate_https_url(text: &str) -> Result<Url, Error> {
    let trimmed = text.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_URL_LEN {
        return Err(Error::BadRelay);
    }
    let url: Url = trimmed.parse().map_err(|_| Error::BadRelay)?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none()
    {
        return Err(Error::BadRelay);
    }
    Ok(url)
}

pub(crate) fn relay_url(custom: Option<&str>) -> Result<Url, Error> {
    match custom {
        Some(text) => validate_https_url(text),
        None => validate_https_url(N0_DNS_PKARR_RELAY_PROD),
    }
}

pub(crate) async fn run(client: PkarrRelayClient, job: Job) {
    let Job { work, reply } = job;
    let answer = tokio::time::timeout(LIMIT, async move {
        match work {
            Work::Publish { seed, value } => {
                let packet = packet(&seed, &value)?;
                client
                    .publish(&packet)
                    .await
                    .map(|()| None)
                    .map_err(|error| error.to_string())
            }
            Work::Resolve { seed } => client
                .resolve(SecretKey::from_bytes(&seed).public())
                .await
                .map(|packet| value(&packet))
                .map_err(|error| error.to_string()),
        }
    })
    .await
    .unwrap_or_else(|_| Err("short-code relay timed out".to_owned()));
    let _ = reply.send(answer);
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn signed_packet_round_trips_and_rejects_wrong_key() {
        let seed = [7_u8; 32];
        let packet = packet(&seed, "c2VhbGVkIGNvZGU=").unwrap();
        assert_eq!(value(&packet).as_deref(), Some("c2VhbGVkIGNvZGU="));
        assert_eq!(packet.public_key(), SecretKey::from_bytes(&seed).public());

        let back = SignedPacket::from_relay_payload(
            &SecretKey::from_bytes(&seed).public(),
            &packet.to_relay_payload(),
        )
        .unwrap();
        assert_eq!(value(&back).as_deref(), Some("c2VhbGVkIGNvZGU="));

        assert!(
            SignedPacket::from_relay_payload(
                &SecretKey::from_bytes(&[8_u8; 32]).public(),
                &packet.to_relay_payload(),
            )
            .is_err()
        );
    }

    #[test]
    fn relay_url_validation_enforces_https_without_credentials() {
        assert!(relay_url(None).is_ok_and(|url| url.scheme() == "https"));
        assert!(relay_url(Some("https://relay.example/pkarr")).is_ok());
        for bad in [
            "",
            "http://relay.example",
            "ftp://relay.example",
            "https://user:pass@relay.example",
            "https://user@relay.example",
            "not a url",
            &format!("https://relay.example/{}", "a".repeat(MAX_URL_LEN)),
        ] {
            assert!(
                matches!(relay_url(Some(bad)), Err(Error::BadRelay)),
                "{bad}"
            );
        }
    }
}
