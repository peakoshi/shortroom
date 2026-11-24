//! Star-topology QUIC rooms: [`Node`], [`HostRoom`], and [`GuestRoom`].

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::SocketAddr;
use std::sync::{
    Arc, Condvar, Mutex, PoisonError, Weak,
    atomic::{AtomicU64, Ordering},
    mpsc as sync,
};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use bytes::Bytes;
use iroh::address_lookup::pkarr::PkarrRelayClient;
use iroh::endpoint::{
    Connection, ConnectionError, Incoming, PortmapperConfig, QuicTransportConfig, RecvStream,
    SendDatagramError, SendStream, presets,
};
use iroh::{Endpoint, EndpointAddr, EndpointId, RelayMode, RelayUrl};
use tokio::sync::{Semaphore, mpsc, watch};
use url::Url;

use crate::code::{RoomCode, ShortStore};
use crate::control::{self, Compat, Frame, FrameError, Member, Message, Refusal};
use crate::{Error, Path, PeerId, Relay, short};

/// Default QUIC ALPN for shortroom connections.
pub const ROOM_ALPN: &[u8] = b"shortroom/1";
pub const HOST_SLOT: u8 = 1;
/// Destination slot reaching every other member in the room.
pub const BROADCAST: u8 = 255;
/// Maximum number of slots in a room, including the host.
pub const MAX_SLOTS: u8 = 8;
/// Maximum display name length retained, in Unicode scalar values.
pub const MAX_NAME: usize = 32;
/// Default socket bind timeout used by [`Node::start`].
pub const ROOM_BIND_TIMEOUT: Duration = Duration::from_millis(1800);

const HELLO_LIMIT: Duration = Duration::from_secs(5);
const MAX_HANDSHAKES: usize = 16;
const DELIVER_QUEUE: usize = 512;
const EVENT_QUEUE: usize = 1024;
const MAX_QUEUED_REQUESTS: usize = 256;
const MAX_QUEUED_REQUEST_BYTES: usize = 4 * 1024 * 1024;
const MAX_QUEUED_REFUSALS: usize = 128;
const CONTROL_QUEUE: usize = 128;
const FALLBACK_QUEUE: usize = 256;
const LINGER: Duration = Duration::from_secs(2);
const MAX_CLOSE_REASON_BYTES: usize = 256;
#[allow(clippy::duration_suboptimal_units)]
const MAX_JOIN_TIMEOUT: Duration = Duration::from_secs(86_400);

/// QUIC application close codes used by the room protocol.
pub mod close {
    pub const BYE: u32 = 0;
    pub const INVALID: u32 = 1;
    pub const REFUSED: u32 = 0x10;
    pub const KICKED: u32 = 0x11;
    pub const REPLACED: u32 = 0x12;
    pub const ROOM_CLOSED: u32 = 0x13;
}

#[derive(Clone, Default)]
pub struct NodeOptions {
    pub relay: Relay,
    /// Optional custom HTTPS pkarr relay for short-code records (defaults to iroh's public relay).
    pub pkarr_relay: Option<String>,
    /// Optional Ed25519 secret key seed; keeping one across reconnects preserves the guest's slot.
    pub identity: Option<[u8; 32]>,
    /// Optional custom QUIC ALPN (1..=255 bytes; defaults to [`ROOM_ALPN`]).
    pub alpn: Option<Vec<u8>>,
}

impl std::fmt::Debug for NodeOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let pkarr = self.pkarr_relay.as_deref().map(short::redacted_url);
        f.debug_struct("NodeOptions")
            .field("relay", &self.relay)
            .field("pkarr_relay", &pkarr)
            .field("identity", &self.identity.as_ref().map(|_| "<present>"))
            .field("alpn", &self.alpn)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Datagram {
    pub src: u8,
    pub dst: u8,
    pub payload: Vec<u8>,
}

/// Generation-scoped handle for one guest request. Stale tokens from a replaced connection or
/// another room are rejected by [`HostRoom::reply`].
#[derive(Clone)]
pub struct RequestToken {
    owner: Weak<HostShared>,
    slot: u8,
    generation: u64,
    id: u64,
}

impl RequestToken {
    #[must_use]
    pub fn slot(&self) -> u8 {
        self.slot
    }

    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

impl std::fmt::Debug for RequestToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestToken")
            .field("slot", &self.slot)
            .field("generation", &self.generation)
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl PartialEq for RequestToken {
    fn eq(&self, other: &Self) -> bool {
        self.owner.ptr_eq(&other.owner)
            && self.slot == other.slot
            && self.generation == other.generation
            && self.id == other.id
    }
}

impl Eq for RequestToken {}

#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum HostEvent {
    Joined {
        slot: u8,
        peer: PeerId,
        name: String,
    },
    Left {
        slot: u8,
        peer: PeerId,
    },
    Request {
        request: RequestToken,
        body: serde_json::Value,
    },
    Refused {
        peer: PeerId,
        refusal: Refusal,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum End {
    Left,
    Kicked(String),
    Replaced,
    HostClosed,
    Lost,
}

#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum GuestEvent {
    Roster(Vec<Member>),
    Notice(serde_json::Value),
    Ended(End),
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum JoinError {
    #[error("could not reach the host")]
    Unreachable,
    #[error("{0}")]
    Refused(Refusal, Box<Compat>),
    #[error("connection to host broke while joining")]
    Broken,
    #[error("node stopped")]
    Stopped,
}

#[derive(Debug, Default)]
pub(crate) struct Counts {
    pub(crate) delivered: AtomicU64,
    pub(crate) forwarded: AtomicU64,
    pub(crate) framed: AtomicU64,
    pub(crate) spoofed: AtomicU64,
    pub(crate) dropped: AtomicU64,
    pub(crate) malformed: AtomicU64,
    pub(crate) unroutable: AtomicU64,
    pub(crate) deliver_full: AtomicU64,
    pub(crate) send_full: AtomicU64,
    pub(crate) stream_full: AtomicU64,
    pub(crate) send_failed: AtomicU64,
    pub(crate) evicted_estimate: AtomicU64,
    pub(crate) quic_sent: AtomicU64,
    pub(crate) quic_read: AtomicU64,
    pub(crate) events_dropped: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CountsSnapshot {
    pub delivered: u64,
    pub forwarded: u64,
    pub framed: u64,
    pub spoofed: u64,
    pub dropped: u64,
    pub malformed: u64,
    pub unroutable: u64,
    pub deliver_full: u64,
    pub send_full: u64,
    pub stream_full: u64,
    pub send_failed: u64,
    pub evicted_estimate: u64,
    pub quic_sent: u64,
    pub quic_read: u64,
    pub events_dropped: u64,
}

impl Counts {
    fn snapshot(&self) -> CountsSnapshot {
        CountsSnapshot {
            delivered: self.delivered.load(Ordering::Relaxed),
            forwarded: self.forwarded.load(Ordering::Relaxed),
            framed: self.framed.load(Ordering::Relaxed),
            spoofed: self.spoofed.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            malformed: self.malformed.load(Ordering::Relaxed),
            unroutable: self.unroutable.load(Ordering::Relaxed),
            deliver_full: self.deliver_full.load(Ordering::Relaxed),
            send_full: self.send_full.load(Ordering::Relaxed),
            stream_full: self.stream_full.load(Ordering::Relaxed),
            send_failed: self.send_failed.load(Ordering::Relaxed),
            evicted_estimate: self.evicted_estimate.load(Ordering::Relaxed),
            quic_sent: self.quic_sent.load(Ordering::Relaxed),
            quic_read: self.quic_read.load(Ordering::Relaxed),
            events_dropped: self.events_dropped.load(Ordering::Relaxed),
        }
    }

    fn drop_for(&self, cause: &AtomicU64) {
        cause.fetch_add(1, Ordering::Relaxed);
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }

    fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinkStats {
    pub datagrams_sent: u64,
    pub datagrams_received: u64,
    pub packets_sent: u64,
    pub packets_lost: u64,
    pub probes_lost: u64,
    pub congestion_events: u64,
    pub black_holes: u64,
    pub mtu: u16,
    pub max_datagram: Option<usize>,
}

fn link_stats(connection: &Connection) -> LinkStats {
    let stats = connection.stats();
    let mut link = LinkStats {
        datagrams_sent: stats.frame_tx.datagram,
        datagrams_received: stats.frame_rx.datagram,
        packets_sent: stats.sent_packets,
        packets_lost: stats.lost_packets,
        max_datagram: datagram_limit(connection),
        ..LinkStats::default()
    };
    for path in connection.paths().iter() {
        let pstats = path.stats();
        link.probes_lost = link.probes_lost.saturating_add(pstats.lost_plpmtud_probes);
        link.congestion_events = link
            .congestion_events
            .saturating_add(pstats.congestion_events);
        link.black_holes = link.black_holes.saturating_add(pstats.black_holes_detected);
        if path.is_selected() {
            link.mtu = pstats.current_mtu;
        }
    }
    link
}

fn connection_path(connection: &Connection) -> (Path, Option<u32>) {
    let paths = connection.paths();
    paths.iter().find(iroh::endpoint::Path::is_selected).map_or(
        (Path::Connecting, None),
        |selected| {
            (
                if selected.is_ip() {
                    Path::Direct
                } else {
                    Path::Relayed
                },
                Some(u32::try_from(selected.rtt().as_millis()).unwrap_or(u32::MAX)),
            )
        },
    )
}

struct CloseOnDrop(Connection);

impl Drop for CloseOnDrop {
    fn drop(&mut self) {
        self.0.close(close::BYE.into(), b"closed");
    }
}

/// Condvar-backed bounded queue so timed waits never hold the lock across blocking sleeps.
struct BoundedQueue<T> {
    cap: usize,
    inner: Mutex<VecDeque<T>>,
    ready: Condvar,
}

impl<T> BoundedQueue<T> {
    fn new(cap: usize) -> Self {
        Self {
            cap,
            inner: Mutex::new(VecDeque::new()),
            ready: Condvar::new(),
        }
    }

    fn try_push(&self, item: T) -> bool {
        let mut queue = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        if queue.len() >= self.cap {
            return false;
        }
        queue.push_back(item);
        self.ready.notify_one();
        true
    }

    fn try_pop(&self) -> Option<T> {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop_front()
    }

    fn pop_timeout(&self, timeout: Duration) -> Option<T> {
        let mut queue = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(item) = queue.pop_front() {
            return Some(item);
        }
        if timeout.is_zero() {
            return None;
        }
        let deadline = Instant::now().checked_add(timeout);
        loop {
            let wait = match deadline {
                Some(end) => {
                    let left = end.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return queue.pop_front();
                    }
                    left
                }
                None => Duration::from_secs(3600),
            };
            let (guard, status) = self
                .ready
                .wait_timeout(queue, wait)
                .unwrap_or_else(PoisonError::into_inner);
            queue = guard;
            if let Some(item) = queue.pop_front() {
                return Some(item);
            }
            if status.timed_out() && deadline.is_some() {
                return None;
            }
        }
    }
}

#[derive(Default)]
struct HostEventQueueInner {
    items: VecDeque<(HostEvent, usize)>,
    request_count: usize,
    request_bytes: usize,
    refused_count: usize,
}

impl HostEventQueueInner {
    fn pop(&mut self) -> Option<HostEvent> {
        let (event, req_bytes) = self.items.pop_front()?;
        match event {
            HostEvent::Request { .. } => {
                self.request_count = self.request_count.saturating_sub(1);
                self.request_bytes = self.request_bytes.saturating_sub(req_bytes);
            }
            HostEvent::Refused { .. } => {
                self.refused_count = self.refused_count.saturating_sub(1);
            }
            HostEvent::Joined { .. } | HostEvent::Left { .. } => {}
        }
        Some(event)
    }

    fn evict_refusal(&mut self) -> bool {
        if let Some(pos) = self
            .items
            .iter()
            .position(|(event, _)| matches!(event, HostEvent::Refused { .. }))
        {
            self.items.remove(pos);
            self.refused_count = self.refused_count.saturating_sub(1);
            true
        } else {
            false
        }
    }
}

/// Host event queue with separate caps for requests and unauthenticated refusals so neither can
/// starve or displace `Joined` / `Left` membership transitions.
#[derive(Default)]
struct HostEventQueue {
    inner: Mutex<HostEventQueueInner>,
    ready: Condvar,
}

impl HostEventQueue {
    fn push_membership(&self, event: HostEvent, counts: &Counts) {
        let mut queue = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        if queue.items.len() >= EVENT_QUEUE && !queue.evict_refusal() {
            Counts::bump(&counts.events_dropped);
            return;
        }
        queue.items.push_back((event, 0));
        self.ready.notify_one();
    }

    fn push_refusal(&self, event: HostEvent, counts: &Counts) {
        let mut queue = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        if queue.refused_count >= MAX_QUEUED_REFUSALS || queue.items.len() >= EVENT_QUEUE {
            Counts::bump(&counts.events_dropped);
            return;
        }
        queue.refused_count += 1;
        queue.items.push_back((event, 0));
        self.ready.notify_one();
    }

    fn try_push_request(&self, event: HostEvent, frame_bytes: usize) -> bool {
        let mut queue = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        if queue.items.len() >= EVENT_QUEUE
            || queue.request_count >= MAX_QUEUED_REQUESTS
            || queue.request_bytes.saturating_add(frame_bytes) > MAX_QUEUED_REQUEST_BYTES
        {
            return false;
        }
        queue.request_count += 1;
        queue.request_bytes += frame_bytes;
        queue.items.push_back((event, frame_bytes));
        self.ready.notify_one();
        true
    }

    fn try_pop(&self) -> Option<HostEvent> {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop()
    }

    fn pop_timeout(&self, timeout: Duration) -> Option<HostEvent> {
        let mut queue = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(event) = queue.pop() {
            return Some(event);
        }
        if timeout.is_zero() {
            return None;
        }
        let deadline = Instant::now().checked_add(timeout);
        loop {
            let wait = match deadline {
                Some(end) => {
                    let left = end.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return queue.pop();
                    }
                    left
                }
                None => Duration::from_secs(3600),
            };
            let (guard, status) = self
                .ready
                .wait_timeout(queue, wait)
                .unwrap_or_else(PoisonError::into_inner);
            queue = guard;
            if let Some(event) = queue.pop() {
                return Some(event);
            }
            if status.timed_out() && deadline.is_some() {
                return None;
            }
        }
    }
}

#[derive(Default)]
struct GuestEventQueueInner {
    items: VecDeque<GuestEvent>,
    terminal: Option<End>,
    terminal_delivered: bool,
}

impl GuestEventQueueInner {
    fn pop(&mut self) -> Option<GuestEvent> {
        if let Some(event) = self.items.pop_front() {
            return Some(event);
        }
        if let Some(end) = self.terminal.take() {
            self.terminal_delivered = true;
            return Some(GuestEvent::Ended(end));
        }
        None
    }
}

/// Guest event queue that reserves a slot for the terminal [`GuestEvent::Ended`] event so queue
/// saturation can never drop room-end notification.
#[derive(Default)]
struct GuestEventQueue {
    inner: Mutex<GuestEventQueueInner>,
    ready: Condvar,
}

impl GuestEventQueue {
    fn push(&self, event: GuestEvent, counts: &Counts) {
        let mut queue = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        if queue.items.len() < EVENT_QUEUE {
            queue.items.push_back(event);
            self.ready.notify_one();
        } else {
            Counts::bump(&counts.events_dropped);
        }
    }

    fn push_terminal(&self, end: End) {
        let mut queue = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        if queue.terminal.is_none() && !queue.terminal_delivered {
            queue.terminal = Some(end);
            self.ready.notify_all();
        }
    }

    fn try_pop(&self) -> Option<GuestEvent> {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop()
    }

    fn pop_timeout(&self, timeout: Duration) -> Option<GuestEvent> {
        let mut queue = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(event) = queue.pop() {
            return Some(event);
        }
        if timeout.is_zero() {
            return None;
        }
        let deadline = Instant::now().checked_add(timeout);
        loop {
            let wait = match deadline {
                Some(end) => {
                    let left = end.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return queue.pop();
                    }
                    left
                }
                None => Duration::from_secs(3600),
            };
            let (guard, status) = self
                .ready
                .wait_timeout(queue, wait)
                .unwrap_or_else(PoisonError::into_inner);
            queue = guard;
            if let Some(event) = queue.pop() {
                return Some(event);
            }
            if status.timed_out() && deadline.is_some() {
                return None;
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberStatus {
    pub member: Member,
    pub path: Path,
    pub rtt_ms: Option<u32>,
    pub link: LinkStats,
}

#[derive(Clone, Debug)]
pub struct HostConfig {
    pub compat: Compat,
    pub name: String,
    /// Total slots including the host (`2..=MAX_SLOTS`).
    pub capacity: u8,
}

#[derive(Clone, Debug)]
pub struct Hello {
    pub proto: u32,
    pub compat: Compat,
    pub name: String,
}

impl Hello {
    #[must_use]
    pub fn new(compat: Compat, name: impl Into<String>) -> Self {
        Self {
            proto: control::PROTOCOL,
            compat,
            name: name.into(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct JoinOptions {
    /// Direct host addresses (required when [`Relay::Disabled`]); empty to use relays.
    pub addrs: Vec<SocketAddr>,
    pub timeout: Duration,
}

impl Default for JoinOptions {
    fn default() -> Self {
        Self {
            addrs: Vec::new(),
            timeout: Duration::from_secs(30),
        }
    }
}

fn endpoint_builder(
    relay: Relay,
    alpn: &[u8],
    identity: Option<[u8; 32]>,
) -> Result<iroh::endpoint::Builder, Error> {
    let builder = match relay {
        Relay::Disabled => Endpoint::builder(presets::Minimal)
            .relay_mode(RelayMode::Disabled)
            .portmapper_config(PortmapperConfig::Disabled),
        Relay::Default => Endpoint::builder(presets::N0),
        Relay::Custom(text) => {
            let validated = short::validate_https_url(&text)?;
            let url: RelayUrl = validated.as_str().parse().map_err(|_| Error::BadRelay)?;
            Endpoint::builder(presets::N0).relay_mode(RelayMode::custom([url]))
        }
    };
    let config = QuicTransportConfig::builder()
        .keep_alive_interval(Duration::from_secs(5))
        .max_idle_timeout(Some(
            Duration::from_secs(30)
                .try_into()
                .map_err(|_| Error::Start("invalid idle timeout".into()))?,
        ))
        .max_concurrent_bidi_streams(1_u32.into())
        .max_concurrent_uni_streams(0_u32.into())
        .datagram_receive_buffer_size(Some(32 * 1024))
        .datagram_send_buffer_size(32 * 1024)
        .stream_receive_window((128_u32 * 1024).into())
        .receive_window((128_u32 * 1024).into())
        .send_window(128 * 1024)
        .enable_segmentation_offload(crate::host::segmentation_offload(crate::host::WINDOWS))
        .build();
    let mut builder = builder.alpns(vec![alpn.to_vec()]).transport_config(config);
    if let Some(seed) = identity {
        builder = builder.secret_key(iroh::SecretKey::from_bytes(&seed));
    }
    Ok(builder)
}

/// Process-level QUIC endpoint. Cheap to clone; dropping the last clone closes the endpoint.
///
/// Blocking methods on [`Node`], [`HostRoom`], and [`GuestRoom`] (`start`, `join`, `request`,
/// `event`, `recv`, and [`ShortStore`]) block the calling OS thread; call them via
/// `tokio::task::spawn_blocking` when integrating with an async runtime.
#[derive(Clone, Debug)]
pub struct Node {
    inner: Arc<NodeShared>,
}

struct NodeShared {
    id: PeerId,
    alpn: Vec<u8>,
    pkarr_relay: Url,
    endpoint: Endpoint,
    handle: tokio::runtime::Handle,
    runtime: Mutex<Option<tokio::runtime::Runtime>>,
    hosting: Arc<Mutex<Option<Arc<HostShared>>>>,
}

impl std::fmt::Debug for NodeShared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeShared")
            .field("id", &crate::peer_text(&self.id))
            .field("alpn", &self.alpn)
            .field(
                "pkarr_relay",
                &short::redacted_url(self.pkarr_relay.as_str()),
            )
            .finish_non_exhaustive()
    }
}

fn shutdown_runtime(runtime: tokio::runtime::Runtime, endpoint: &Endpoint) {
    runtime.block_on(async {
        let _ = tokio::time::timeout(Duration::from_millis(500), endpoint.close()).await;
    });
    runtime.shutdown_timeout(Duration::from_millis(200));
}

impl Drop for NodeShared {
    fn drop(&mut self) {
        let endpoint = self.endpoint.clone();
        let Some(runtime) = self
            .runtime
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
        else {
            return;
        };
        // Avoid panicking if the last handle is dropped inside an external Tokio task.
        if tokio::runtime::Handle::try_current().is_ok() {
            let cell = Arc::new(Mutex::new(Some(runtime)));
            let worker_cell = Arc::clone(&cell);
            if std::thread::Builder::new()
                .name("shortroom-stop".into())
                .spawn(move || {
                    if let Some(rt) = worker_cell
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .take()
                    {
                        shutdown_runtime(rt, &endpoint);
                    }
                })
                .is_err()
                && let Some(rt) = cell.lock().unwrap_or_else(PoisonError::into_inner).take()
            {
                rt.shutdown_background();
            }
        } else {
            shutdown_runtime(runtime, &endpoint);
        }
    }
}

impl Node {
    /// Start a node using [`ROOM_BIND_TIMEOUT`]. Returns an error if called inside a Tokio runtime
    /// (use `tokio::task::spawn_blocking`).
    pub fn start(options: NodeOptions) -> Result<Self, Error> {
        Self::start_within(options, ROOM_BIND_TIMEOUT)
    }

    /// Start a node with a custom socket bind timeout.
    pub fn start_within(options: NodeOptions, bind_timeout: Duration) -> Result<Self, Error> {
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(Error::Start(
                "Node::start must be called outside a Tokio runtime".into(),
            ));
        }
        let alpn = match options.alpn {
            Some(bytes) if bytes.is_empty() || bytes.len() > 255 => {
                return Err(Error::InvalidConfig(
                    "ALPN must be between 1 and 255 bytes".into(),
                ));
            }
            Some(bytes) => bytes,
            None => ROOM_ALPN.to_vec(),
        };
        let pkarr_relay = short::relay_url(options.pkarr_relay.as_deref())?;
        let builder = endpoint_builder(options.relay, &alpn, options.identity)?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("shortroom")
            .enable_all()
            .build()
            .map_err(|_| Error::Start("could not start network runtime".into()))?;
        let endpoint = runtime
            .block_on(async { tokio::time::timeout(bind_timeout, builder.bind()).await })
            .map_err(|_| Error::Start("network socket bind timed out".into()))?
            .map_err(|_| Error::Start("could not bind network socket".into()))?;

        let hosting: Arc<Mutex<Option<Arc<HostShared>>>> = Arc::default();
        let accept = endpoint.clone();
        let accept_hosting = hosting.clone();
        runtime.spawn(async move {
            while let Some(incoming) = accept.accept().await {
                let host = accept_hosting
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone();
                if let Some(host) = host
                    && let Ok(permit) = Arc::clone(&host.handshakes).try_acquire_owned()
                {
                    tokio::spawn(serve_guest(host, incoming, permit));
                } else {
                    incoming.refuse();
                }
            }
        });

        Ok(Self {
            inner: Arc::new(NodeShared {
                id: *endpoint.id().as_bytes(),
                alpn,
                pkarr_relay,
                endpoint,
                handle: runtime.handle().clone(),
                runtime: Mutex::new(Some(runtime)),
                hosting,
            }),
        })
    }

    #[must_use]
    pub fn id(&self) -> PeerId {
        self.inner.id
    }

    #[must_use]
    pub fn direct_addrs(&self) -> Vec<SocketAddr> {
        self.inner.endpoint.addr().ip_addrs().copied().collect()
    }

    /// Host a room. At most one active room per node.
    pub fn host(&self, config: HostConfig) -> Result<HostRoom, Error> {
        if !(2..=MAX_SLOTS).contains(&config.capacity) {
            return Err(Error::InvalidConfig(format!(
                "capacity must be between 2 and {MAX_SLOTS}"
            )));
        }
        let code = RoomCode::new(self.inner.id)?;
        let mut hosting = self
            .inner
            .hosting
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if hosting.is_some() {
            return Err(Error::AlreadyHosting);
        }
        let (outgoing, outgoing_rx) = mpsc::channel(DELIVER_QUEUE);
        let shared = Arc::new(HostShared {
            code,
            compat: config.compat,
            capacity: config.capacity,
            state: Mutex::new(HostState {
                open: true,
                name: clean_name(&config.name),
                members: BTreeMap::new(),
                reserved: BTreeMap::new(),
                banned: BTreeSet::new(),
                generation: 0,
            }),
            events: HostEventQueue::default(),
            deliver: BoundedQueue::new(DELIVER_QUEUE),
            counts: Counts::default(),
            handshakes: Arc::new(Semaphore::new(MAX_HANDSHAKES)),
        });
        let sender = shared.clone();
        self.inner.handle.spawn(host_sender(sender, outgoing_rx));
        *hosting = Some(shared.clone());
        Ok(HostRoom {
            node: self.clone(),
            shared,
            outgoing,
        })
    }

    /// Join the room named by `code`. Blocks up to `options.timeout` (clamped at 24 hours).
    /// When calling from an async runtime, run inside `tokio::task::spawn_blocking`.
    pub fn join(
        &self,
        code: &RoomCode,
        hello: &Hello,
        options: &JoinOptions,
    ) -> Result<GuestRoom, JoinError> {
        if code.host == self.inner.id {
            return Err(JoinError::Unreachable);
        }
        let key = EndpointId::from_bytes(&code.host).map_err(|_| JoinError::Unreachable)?;
        let address = EndpointAddr::from_parts(
            key,
            options.addrs.iter().copied().map(iroh::TransportAddr::Ip),
        );
        let proof = control::hex(&code.proof(&self.inner.id));
        let hello_bytes = control::encode_message(&Message::Hello {
            proto: hello.proto,
            compat: hello.compat.clone(),
            name: clean_name(&hello.name),
            proof,
        })
        .ok_or(JoinError::Broken)?;

        let endpoint = self.inner.endpoint.clone();
        let alpn = self.inner.alpn.clone();
        let timeout = options.timeout.min(MAX_JOIN_TIMEOUT);
        let deadline = Instant::now()
            .checked_add(timeout)
            .unwrap_or_else(|| Instant::now() + Duration::from_secs(3600));

        // Spawn on the node's own runtime and wait via sync channel so calling inside another
        // Tokio runtime never panics with nested `block_on`.
        let (done_tx, done_rx) = sync::sync_channel(1);
        self.inner.handle.spawn(async move {
            let _ =
                done_tx.send(join_handshake(endpoint, alpn, address, hello_bytes, deadline).await);
        });

        let (connection, send, recv, slot, compat, roster) =
            done_rx.recv().map_err(|_| JoinError::Stopped)??;

        if !(HOST_SLOT + 1..=MAX_SLOTS).contains(&slot) {
            connection.close(close::INVALID.into(), b"invalid slot");
            return Err(JoinError::Broken);
        }
        let (control_tx, control_rx) = mpsc::channel(CONTROL_QUEUE);
        let (fallback_tx, fallback_rx) = mpsc::channel(FALLBACK_QUEUE);
        let (outgoing, outgoing_rx) = mpsc::channel(DELIVER_QUEUE);
        let shared = Arc::new(GuestShared {
            slot,
            compat,
            connection: connection.clone(),
            roster: Mutex::new(roster),
            ended: Mutex::new(None),
            pending: Mutex::new(BTreeMap::new()),
            next_id: AtomicU64::new(1),
            control: control_tx,
            fallback: fallback_tx,
            events: GuestEventQueue::default(),
            deliver: BoundedQueue::new(DELIVER_QUEUE),
            counts: Counts::default(),
        });
        self.inner.handle.spawn(run_guest(
            shared.clone(),
            send,
            recv,
            control_rx,
            fallback_rx,
            outgoing_rx,
        ));
        Ok(GuestRoom {
            node: self.clone(),
            shared,
            outgoing,
        })
    }

    fn short(&self, work: short::Work) -> Result<Option<String>, Error> {
        let dns = self
            .inner
            .endpoint
            .dns_resolver()
            .map_err(|_| Error::Stopped)?
            .clone();
        let client = PkarrRelayClient::new(
            self.inner.pkarr_relay.clone(),
            self.inner.endpoint.tls_config().clone(),
            dns,
        );
        let (reply, answer) = sync::sync_channel(1);
        self.inner
            .handle
            .spawn(short::run(client, short::Job { work, reply }));
        answer
            .recv_timeout(short::LIMIT + Duration::from_secs(1))
            .map_err(|_| Error::ShortStore("no answer".into()))?
            .map_err(Error::ShortStore)
    }
}

impl ShortStore for Node {
    fn publish(&self, seed: [u8; 32], value: String) -> Result<(), Error> {
        self.short(short::Work::Publish { seed, value }).map(|_| ())
    }

    fn resolve(&self, seed: [u8; 32]) -> Result<Option<String>, Error> {
        self.short(short::Work::Resolve { seed })
    }
}

fn clean_name(name: &str) -> String {
    name.trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_NAME)
        .collect()
}

fn clean_reason(text: &str) -> String {
    text.trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(200)
        .collect()
}

fn truncate_utf8(text: &str, max_bytes: usize) -> &[u8] {
    if text.len() <= max_bytes {
        return text.as_bytes();
    }
    let mut end = max_bytes;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text.as_bytes()[..end]
}

type JoinedStream = (Connection, SendStream, RecvStream, u8, Compat, Vec<Member>);

async fn join_handshake(
    endpoint: Endpoint,
    alpn: Vec<u8>,
    address: EndpointAddr,
    hello_bytes: Bytes,
    deadline: Instant,
) -> Result<JoinedStream, JoinError> {
    let connection = dial(&endpoint, &alpn, address, deadline).await?;
    let opened = tokio::time::timeout_at(deadline.into(), async {
        let (mut send, mut recv) = connection.open_bi().await.map_err(|_| JoinError::Broken)?;
        control::write(&mut send, &Frame::Encoded(hello_bytes))
            .await
            .map_err(|_| JoinError::Broken)?;
        let (first, _) = control::read(&mut recv)
            .await
            .map_err(|_| JoinError::Broken)?;
        Ok::<_, JoinError>((send, recv, first))
    })
    .await;
    match opened {
        Ok(Ok((
            send,
            recv,
            Frame::Message(Message::Welcome {
                slot,
                compat,
                roster,
            }),
        ))) => Ok((connection, send, recv, slot, compat, roster)),
        Ok(Ok((_, _, Frame::Message(Message::Refused { refusal, compat })))) => {
            connection.close(close::BYE.into(), b"refused");
            Err(JoinError::Refused(refusal, Box::new(compat)))
        }
        Ok(Ok(_)) => {
            connection.close(close::INVALID.into(), b"invalid frame");
            Err(JoinError::Broken)
        }
        Ok(Err(error)) => {
            let result = refusal_from_close(&connection).unwrap_or(error);
            connection.close(close::BYE.into(), b"join failed");
            Err(result)
        }
        Err(_) => {
            let result = refusal_from_close(&connection).unwrap_or(JoinError::Unreachable);
            connection.close(close::BYE.into(), b"join timed out");
            Err(result)
        }
    }
}

async fn dial(
    endpoint: &Endpoint,
    alpn: &[u8],
    address: EndpointAddr,
    deadline: Instant,
) -> Result<Connection, JoinError> {
    let mut delay = Duration::from_millis(100);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(JoinError::Unreachable);
        }
        if let Ok(Ok(connection)) = tokio::time::timeout(
            left.min(Duration::from_secs(5)),
            endpoint.connect(address.clone(), alpn),
        )
        .await
        {
            return Ok(connection);
        }
        tokio::time::sleep(delay.min(deadline.saturating_duration_since(Instant::now()))).await;
        delay = (delay * 2).min(Duration::from_secs(2));
    }
}

fn refusal_from_close(connection: &Connection) -> Option<JoinError> {
    match connection.close_reason()? {
        ConnectionError::ApplicationClosed(app) if app.error_code == close::REFUSED.into() => {
            serde_json::from_slice::<Refusal>(&app.reason)
                .ok()
                .map(|refusal| JoinError::Refused(refusal, Box::default()))
        }
        _ => None,
    }
}

fn datagram_limit(connection: &Connection) -> Option<usize> {
    let limit = connection.max_datagram_size();
    #[cfg(test)]
    let limit = limit.map(|size| size.min(1162));
    limit
}

fn send_room_datagram(
    connection: &Connection,
    fallback: &mpsc::Sender<Frame>,
    bytes: Bytes,
    counts: &Counts,
) {
    if datagram_limit(connection).is_some_and(|max| bytes.len() <= max) {
        match queue_datagram(connection, bytes.clone()) {
            Ok(evicted) => {
                Counts::bump(&counts.quic_sent);
                if evicted {
                    Counts::bump(&counts.evicted_estimate);
                }
                return;
            }
            Err(SendDatagramError::TooLarge) => {}
            Err(_) => {
                counts.drop_for(&counts.send_failed);
                return;
            }
        }
    }
    if fallback.try_send(Frame::Datagram(bytes)).is_ok() {
        Counts::bump(&counts.framed);
    } else {
        counts.drop_for(&counts.stream_full);
    }
}

/// Queue a QUIC datagram without blocking; `Ok(true)` indicates the non-blocking probe would have
/// waited, so the discarding send ran and may have evicted older unsent datagrams.
fn queue_datagram(connection: &Connection, bytes: Bytes) -> Result<bool, SendDatagramError> {
    let tried = {
        let send = std::pin::pin!(connection.send_datagram_wait(bytes.clone()));
        send.poll(&mut Context::from_waker(Waker::noop()))
    };
    match tried {
        Poll::Ready(result) => result.map(|()| false),
        Poll::Pending => connection.send_datagram(bytes).map(|()| true),
    }
}

struct HostShared {
    code: RoomCode,
    compat: Compat,
    capacity: u8,
    // Lock order invariant: acquire `state` before `events` when emitting membership transitions.
    state: Mutex<HostState>,
    events: HostEventQueue,
    deliver: BoundedQueue<Datagram>,
    counts: Counts,
    handshakes: Arc<Semaphore>,
}

struct HostState {
    open: bool,
    name: String,
    members: BTreeMap<u8, Joined>,
    reserved: BTreeMap<PeerId, u8>,
    banned: BTreeSet<PeerId>,
    generation: u64,
}

struct Joined {
    peer: PeerId,
    name: String,
    connection: Connection,
    control: mpsc::Sender<Frame>,
    fallback: mpsc::Sender<Frame>,
    roster: watch::Sender<Option<Bytes>>,
    generation: u64,
}

impl HostShared {
    fn lock(&self) -> std::sync::MutexGuard<'_, HostState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn roster(&self, state: &HostState) -> Vec<Member> {
        let mut members = Vec::with_capacity(1 + state.members.len());
        members.push(Member {
            slot: HOST_SLOT,
            name: state.name.clone(),
            peer: crate::peer_text(&self.code.host),
        });
        members.extend(state.members.iter().map(|(&slot, joined)| Member {
            slot,
            name: joined.name.clone(),
            peer: crate::peer_text(&joined.peer),
        }));
        members
    }

    fn broadcast_roster(&self, state: &HostState, except: Option<u8>) {
        let Some(encoded) = control::encode_message(&Message::Roster {
            members: self.roster(state),
        }) else {
            return;
        };
        for (&slot, joined) in &state.members {
            if Some(slot) != except {
                joined.roster.send_replace(Some(encoded.clone()));
            }
        }
    }

    fn admit(
        &self,
        peer: PeerId,
        message: Message,
        connection: &Connection,
        control: &mpsc::Sender<Frame>,
        fallback: &mpsc::Sender<Frame>,
        roster_tx: watch::Sender<Option<Bytes>>,
    ) -> Result<(u8, u64, Vec<Member>), Refusal> {
        let Message::Hello {
            proto,
            compat,
            name,
            proof,
        } = message
        else {
            return Err(Refusal::BadHello);
        };
        if proto != control::PROTOCOL {
            return Err(Refusal::Protocol);
        }
        if !control::unhex(&proof).is_some_and(|proof| self.code.verify(&peer, &proof)) {
            return Err(Refusal::Secret);
        }
        if let Some(field) = self.compat.unverified(&compat) {
            return Err(Refusal::Unverified(field));
        }
        if let Some(field) = self.compat.mismatch(&compat) {
            return Err(Refusal::Version(field));
        }

        let mut state = self.lock();
        if !state.open {
            return Err(Refusal::Closed);
        }
        if state.banned.contains(&peer) {
            return Err(Refusal::Kicked);
        }

        let previous = state
            .members
            .iter()
            .find(|(_, joined)| joined.peer == peer)
            .map(|(&slot, _)| slot);
        if let Some(slot) = previous
            && let Some(old) = state.members.remove(&slot)
        {
            old.connection.close(close::REPLACED.into(), b"replaced");
            self.events
                .push_membership(HostEvent::Left { slot, peer }, &self.counts);
        }

        let free = |slot: &u8| !state.members.contains_key(slot);
        let slot = state
            .reserved
            .get(&peer)
            .copied()
            .filter(free)
            .or_else(|| {
                let reserved: BTreeSet<u8> = state.reserved.values().copied().collect();
                (HOST_SLOT + 1..=self.capacity)
                    .filter(free)
                    .find(|slot| !reserved.contains(slot))
                    .or_else(|| (HOST_SLOT + 1..=self.capacity).find(free))
            })
            .ok_or(Refusal::Full)?;

        state.generation = state.generation.wrapping_add(1);
        let generation = state.generation;
        let name = clean_name(&name);
        state.members.insert(
            slot,
            Joined {
                peer,
                name: name.clone(),
                connection: connection.clone(),
                control: control.clone(),
                fallback: fallback.clone(),
                roster: roster_tx,
                generation,
            },
        );
        // Keep at most one reservation per slot so `reserved` stays bounded by room capacity.
        state
            .reserved
            .retain(|owner, assigned| *owner == peer || *assigned != slot);
        state.reserved.insert(peer, slot);

        self.broadcast_roster(&state, Some(slot));
        let roster = self.roster(&state);
        self.events
            .push_membership(HostEvent::Joined { slot, peer, name }, &self.counts);
        Ok((slot, generation, roster))
    }

    fn leave(&self, slot: u8, generation: u64) {
        let mut state = self.lock();
        if state
            .members
            .get(&slot)
            .is_some_and(|joined| joined.generation == generation)
            && let Some(joined) = state.members.remove(&slot)
        {
            self.broadcast_roster(&state, None);
            self.events.push_membership(
                HostEvent::Left {
                    slot,
                    peer: joined.peer,
                },
                &self.counts,
            );
        }
    }

    fn route(&self, from: u8, generation: Option<u64>, bytes: &Bytes) {
        let Some((src, dst, payload)) = control::parse_datagram(bytes) else {
            self.counts.drop_for(&self.counts.malformed);
            return;
        };
        if src != from {
            self.counts.spoofed.fetch_add(1, Ordering::Relaxed);
            return;
        }

        // Snapshot recipient handles onto the stack and release `HostState` before QUIC sends.
        let mut targets: [Option<(Connection, mpsc::Sender<Frame>)>; MAX_SLOTS as usize] =
            std::array::from_fn(|_| None);
        let mut target_count = 0_usize;
        {
            let state = self.lock();
            if let Some(generation) = generation
                && state
                    .members
                    .get(&from)
                    .is_none_or(|joined| joined.generation != generation)
            {
                self.counts.drop_for(&self.counts.unroutable);
                return;
            }
            for (&slot, joined) in &state.members {
                if slot != from
                    && (dst == slot || dst == BROADCAST)
                    && let Some(entry) = targets.get_mut(target_count)
                {
                    *entry = Some((joined.connection.clone(), joined.fallback.clone()));
                    target_count += 1;
                }
            }
        }

        let mut sent = false;
        if from != HOST_SLOT && (dst == HOST_SLOT || dst == BROADCAST) {
            let datagram = Datagram {
                src,
                dst,
                payload: payload.to_vec(),
            };
            if self.deliver.try_push(datagram) {
                self.counts.delivered.fetch_add(1, Ordering::Relaxed);
            } else {
                self.counts.drop_for(&self.counts.deliver_full);
            }
            sent = true;
        }
        for (connection, fallback) in targets[..target_count].iter_mut().filter_map(Option::take) {
            send_room_datagram(&connection, &fallback, bytes.clone(), &self.counts);
            if from != HOST_SLOT {
                self.counts.forwarded.fetch_add(1, Ordering::Relaxed);
            }
            sent = true;
        }
        if !sent {
            self.counts.drop_for(&self.counts.unroutable);
        }
    }
}

async fn host_sender(shared: Arc<HostShared>, mut outgoing: mpsc::Receiver<Bytes>) {
    while let Some(bytes) = outgoing.recv().await {
        shared.route(HOST_SLOT, None, &bytes);
    }
}

async fn serve_guest(
    shared: Arc<HostShared>,
    incoming: Incoming,
    permit: tokio::sync::OwnedSemaphorePermit,
) {
    let handshake = async {
        let connection = incoming.await.ok()?;
        let (send, mut recv) = connection.accept_bi().await.ok()?;
        let first = control::read_limited(&mut recv, control::MAX_HELLO_JSON)
            .await
            .map(|(frame, _)| frame);
        Some((connection, send, recv, first))
    };
    let Ok(Some((connection, mut send, recv, first))) =
        tokio::time::timeout(HELLO_LIMIT, handshake).await
    else {
        return;
    };

    let peer = *connection.remote_id().as_bytes();
    let (control_tx, control_rx) = mpsc::channel(CONTROL_QUEUE);
    let (fallback_tx, fallback_rx) = mpsc::channel(FALLBACK_QUEUE);
    let (roster_tx, roster_rx) = watch::channel(None);
    let admitted = match first {
        Ok(Frame::Message(message)) => shared.admit(
            peer,
            message,
            &connection,
            &control_tx,
            &fallback_tx,
            roster_tx,
        ),
        _ => Err(Refusal::BadHello),
    };
    let (slot, generation, roster) = match admitted {
        Ok(admitted) => {
            drop(permit);
            admitted
        }
        Err(refusal) => {
            shared.events.push_refusal(
                HostEvent::Refused {
                    peer,
                    refusal: refusal.clone(),
                },
                &shared.counts,
            );
            // Only reveal host Compat after the guest has proven possession of the room secret.
            let disclosed_compat = match refusal {
                Refusal::Version(_) | Refusal::Unverified(_) => shared.compat.clone(),
                _ => Compat::default(),
            };
            let message = Message::Refused {
                refusal: refusal.clone(),
                compat: disclosed_compat,
            };
            // Bound the entire refusal write + linger so a stalled peer cannot hold a permit.
            let _ = tokio::time::timeout(LINGER, async {
                let _ = control::write(&mut send, &Frame::Message(message)).await;
                let _ = send.finish();
                let _ = connection.closed().await;
            })
            .await;
            let reason = serde_json::to_vec(&refusal)
                .ok()
                .filter(|bytes| bytes.len() <= MAX_CLOSE_REASON_BYTES)
                .unwrap_or_default();
            connection.close(close::REFUSED.into(), &reason);
            drop(permit);
            return;
        }
    };

    let _guard = CloseOnDrop(connection.clone());
    let welcome = Message::Welcome {
        slot,
        compat: shared.compat.clone(),
        roster,
    };
    let welcomed = tokio::time::timeout(
        HELLO_LIMIT,
        control::write(&mut send, &Frame::Message(welcome)),
    )
    .await;
    if matches!(welcomed, Ok(Ok(()))) {
        tracing::info!(peer = %connection.remote_id().fmt_short(), slot, "room guest admitted");
        let host = shared.clone();
        let reader = read_guest(&host, slot, generation, &connection, recv, &control_tx);
        let datagrams = async {
            loop {
                let Ok(bytes) = connection.read_datagram().await else {
                    return;
                };
                Counts::bump(&host.counts.quic_read);
                host.route(slot, Some(generation), &bytes);
            }
        };
        tokio::select! {
            () = reader => {}
            () = datagrams => {}
            () = write_host_frames(send, control_rx, fallback_rx, roster_rx) => {}
        }
    }
    shared.leave(slot, generation);
}

async fn read_guest(
    shared: &Arc<HostShared>,
    slot: u8,
    generation: u64,
    connection: &Connection,
    mut recv: RecvStream,
    control: &mpsc::Sender<Frame>,
) {
    loop {
        match control::read(&mut recv).await {
            Ok((Frame::Datagram(bytes), _)) => shared.route(slot, Some(generation), &bytes),
            Ok((Frame::Message(Message::Request { id, body }), frame_bytes)) => {
                let current = {
                    let state = shared.lock();
                    state
                        .members
                        .get(&slot)
                        .is_some_and(|member| member.generation == generation)
                };
                if current {
                    let queued = shared.events.try_push_request(
                        HostEvent::Request {
                            request: RequestToken {
                                owner: Arc::downgrade(shared),
                                slot,
                                generation,
                                id,
                            },
                            body,
                        },
                        frame_bytes,
                    );
                    if !queued
                        && let Some(busy) = control::encode_message(&Message::RequestBusy { id })
                    {
                        let _ = control.try_send(Frame::Encoded(busy));
                    }
                }
            }
            Ok((Frame::Message(_) | Frame::Encoded(_), _)) | Err(FrameError::Invalid) => {
                connection.close(close::INVALID.into(), b"invalid frame");
                return;
            }
            Err(FrameError::Closed) => return,
        }
    }
}

async fn write_host_frames(
    mut send: SendStream,
    mut control: mpsc::Receiver<Frame>,
    mut fallback: mpsc::Receiver<Frame>,
    mut roster: watch::Receiver<Option<Bytes>>,
) {
    let mut roster_open = true;
    let mut fallback_open = true;
    loop {
        tokio::select! {
            biased;
            changed = roster.changed(), if roster_open => {
                if changed.is_err() {
                    // Sender dropped (e.g. during kick); keep draining queued control frames like Kick.
                    roster_open = false;
                    continue;
                }
                let latest = roster.borrow_and_update().clone();
                if let Some(bytes) = latest
                    && control::write(&mut send, &Frame::Encoded(bytes)).await.is_err()
                {
                    return;
                }
            }
            frame = control.recv() => {
                let Some(frame) = frame else { return; };
                if control::write(&mut send, &frame).await.is_err() {
                    return;
                }
            }
            frame = fallback.recv(), if fallback_open => {
                let Some(frame) = frame else {
                    fallback_open = false;
                    continue;
                };
                if control::write(&mut send, &frame).await.is_err() {
                    return;
                }
            }
        }
    }
}

async fn write_guest_frames(
    mut send: SendStream,
    mut control: mpsc::Receiver<Frame>,
    mut fallback: mpsc::Receiver<Frame>,
) {
    let mut fallback_open = true;
    loop {
        tokio::select! {
            biased;
            frame = control.recv() => {
                let Some(frame) = frame else { return; };
                if control::write(&mut send, &frame).await.is_err() {
                    return;
                }
            }
            frame = fallback.recv(), if fallback_open => {
                let Some(frame) = frame else {
                    fallback_open = false;
                    continue;
                };
                if control::write(&mut send, &frame).await.is_err() {
                    return;
                }
            }
        }
    }
}

/// Hosted room handle. Dropping it closes the room and disconnects all guests.
pub struct HostRoom {
    node: Node,
    shared: Arc<HostShared>,
    outgoing: mpsc::Sender<Bytes>,
}

impl std::fmt::Debug for HostRoom {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (open, member_count) = {
            let state = self.shared.lock();
            (state.open, 1 + state.members.len())
        };
        f.debug_struct("HostRoom")
            .field("code", &self.shared.code)
            .field("capacity", &self.shared.capacity)
            .field("open", &open)
            .field("members", &member_count)
            .finish_non_exhaustive()
    }
}

impl HostRoom {
    #[must_use]
    pub fn code(&self) -> RoomCode {
        self.shared.code
    }

    #[must_use]
    pub fn capacity(&self) -> u8 {
        self.shared.capacity
    }

    #[must_use]
    pub fn is_open(&self) -> bool {
        self.shared.lock().open
    }

    #[must_use]
    pub fn try_event(&self) -> Option<HostEvent> {
        self.shared.events.try_pop()
    }

    #[must_use]
    pub fn event(&self, timeout: Duration) -> Option<HostEvent> {
        self.shared.events.pop_timeout(timeout)
    }

    #[must_use]
    pub fn try_recv(&self) -> Option<Datagram> {
        self.shared.deliver.try_pop()
    }

    #[must_use]
    pub fn recv(&self, timeout: Duration) -> Option<Datagram> {
        self.shared.deliver.pop_timeout(timeout)
    }

    /// Queue a datagram from [`HOST_SLOT`] to `dst` (a guest slot or [`BROADCAST`]). Non-blocking.
    #[must_use]
    pub fn send(&self, dst: u8, payload: &[u8]) -> bool {
        queue_outgoing(
            &self.outgoing,
            control::datagram_bytes(HOST_SLOT, dst, payload),
            &self.shared.counts,
        )
    }

    /// Whether `request` still belongs to an admitted connection in this room.
    #[must_use]
    pub fn request_current(&self, request: &RequestToken) -> bool {
        if !request.owner.ptr_eq(&Arc::downgrade(&self.shared)) {
            return false;
        }
        self.shared
            .lock()
            .members
            .get(&request.slot)
            .is_some_and(|member| member.generation == request.generation)
    }

    /// Reply to the exact connection that issued `request`. Returns `false` if the request is
    /// stale, the frame exceeds [`control::MAX_JSON`], or the peer queue is full.
    #[must_use]
    pub fn reply(&self, request: &RequestToken, body: serde_json::Value) -> bool {
        if !request.owner.ptr_eq(&Arc::downgrade(&self.shared)) {
            return false;
        }
        let Some(encoded) = control::encode_message(&Message::Reply {
            id: request.id,
            body,
        }) else {
            return false;
        };
        let state = self.shared.lock();
        state
            .members
            .get(&request.slot)
            .filter(|member| member.generation == request.generation)
            .is_some_and(|member| member.control.try_send(Frame::Encoded(encoded)).is_ok())
    }

    /// Push a JSON notice to `slot` or to every guest via [`BROADCAST`]. Returns `false` if the
    /// frame exceeds [`control::MAX_JSON`] or no recipient could accept it.
    #[must_use]
    pub fn notify(&self, slot: u8, body: &serde_json::Value) -> bool {
        let Some(encoded) = control::encode_message(&Message::Notice { body: body.clone() }) else {
            return false;
        };
        let state = self.shared.lock();
        let mut sent = false;
        for (&member, joined) in &state.members {
            if slot == BROADCAST || slot == member {
                sent |= joined
                    .control
                    .try_send(Frame::Encoded(encoded.clone()))
                    .is_ok();
            }
        }
        sent
    }

    /// Remove `slot` and ban its peer for the lifetime of this room.
    #[must_use]
    pub fn kick(&self, slot: u8, reason: &str) -> bool {
        let mut state = self.shared.lock();
        let Some(joined) = state.members.remove(&slot) else {
            return false;
        };
        state.banned.insert(joined.peer);
        state.reserved.remove(&joined.peer);
        self.shared.broadcast_roster(&state, None);
        self.shared.events.push_membership(
            HostEvent::Left {
                slot,
                peer: joined.peer,
            },
            &self.shared.counts,
        );
        drop(state);

        let reason = clean_reason(reason);
        let queued = control::encode_message(&Message::Kick {
            reason: reason.clone(),
        })
        .is_some_and(|encoded| joined.control.try_send(Frame::Encoded(encoded)).is_ok());
        if queued {
            let connection = joined.connection;
            self.node.inner.handle.spawn(async move {
                let _ = tokio::time::timeout(LINGER, connection.closed()).await;
                connection.close(
                    close::KICKED.into(),
                    truncate_utf8(&reason, MAX_CLOSE_REASON_BYTES),
                );
            });
        } else {
            joined.connection.close(
                close::KICKED.into(),
                truncate_utf8(&reason, MAX_CLOSE_REASON_BYTES),
            );
        }
        true
    }

    pub fn set_open(&self, open: bool) {
        self.shared.lock().open = open;
    }

    #[must_use]
    pub fn members(&self) -> Vec<MemberStatus> {
        // Snapshot connection handles under the lock and read QUIC stats outside it.
        let (host_name, snapshot): (String, Vec<(u8, String, PeerId, Connection)>) = {
            let state = self.shared.lock();
            let list = state
                .members
                .iter()
                .map(|(&slot, joined)| {
                    (
                        slot,
                        joined.name.clone(),
                        joined.peer,
                        joined.connection.clone(),
                    )
                })
                .collect();
            (state.name.clone(), list)
        };
        let mut members = Vec::with_capacity(1 + snapshot.len());
        members.push(MemberStatus {
            member: Member {
                slot: HOST_SLOT,
                name: host_name,
                peer: crate::peer_text(&self.shared.code.host),
            },
            path: Path::Direct,
            rtt_ms: Some(0),
            link: LinkStats::default(),
        });
        for (slot, name, peer, connection) in snapshot {
            let (path, rtt_ms) = connection_path(&connection);
            members.push(MemberStatus {
                member: Member {
                    slot,
                    name,
                    peer: crate::peer_text(&peer),
                },
                path,
                rtt_ms,
                link: link_stats(&connection),
            });
        }
        members
    }

    #[must_use]
    pub fn counts(&self) -> CountsSnapshot {
        self.shared.counts.snapshot()
    }

    #[must_use]
    pub fn node(&self) -> &Node {
        &self.node
    }

    #[cfg(test)]
    pub(crate) fn reserved_len(&self) -> usize {
        self.shared.lock().reserved.len()
    }
}

fn queue_outgoing(outgoing: &mpsc::Sender<Bytes>, bytes: Option<Bytes>, counts: &Counts) -> bool {
    let Some(bytes) = bytes else {
        counts.drop_for(&counts.malformed);
        return false;
    };
    let queued = outgoing.try_send(bytes).is_ok();
    if !queued {
        counts.drop_for(&counts.send_full);
    }
    queued
}

impl Drop for HostRoom {
    fn drop(&mut self) {
        let mut hosting = self
            .node
            .inner
            .hosting
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if hosting
            .as_ref()
            .is_some_and(|host| Arc::ptr_eq(host, &self.shared))
        {
            *hosting = None;
        }
        drop(hosting);
        let mut state = self.shared.lock();
        state.open = false;
        for joined in std::mem::take(&mut state.members).into_values() {
            joined
                .connection
                .close(close::ROOM_CLOSED.into(), b"room closed");
        }
    }
}

type PendingReply = sync::SyncSender<Result<serde_json::Value, Error>>;

struct GuestShared {
    slot: u8,
    compat: Compat,
    connection: Connection,
    roster: Mutex<Vec<Member>>,
    // Lock order invariant: always acquire `ended` before `pending`.
    ended: Mutex<Option<End>>,
    pending: Mutex<BTreeMap<u64, PendingReply>>,
    next_id: AtomicU64,
    control: mpsc::Sender<Frame>,
    fallback: mpsc::Sender<Frame>,
    events: GuestEventQueue,
    deliver: BoundedQueue<Datagram>,
    counts: Counts,
}

impl GuestShared {
    fn accept(&self, bytes: &[u8]) {
        let Some((src, dst, payload)) = control::parse_datagram(bytes) else {
            self.counts.drop_for(&self.counts.malformed);
            return;
        };
        if src == self.slot || !(HOST_SLOT..=MAX_SLOTS).contains(&src) {
            self.counts.spoofed.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if dst != self.slot && dst != BROADCAST {
            self.counts.drop_for(&self.counts.unroutable);
            return;
        }
        let datagram = Datagram {
            src,
            dst,
            payload: payload.to_vec(),
        };
        if self.deliver.try_push(datagram) {
            self.counts.delivered.fetch_add(1, Ordering::Relaxed);
        } else {
            self.counts.drop_for(&self.counts.deliver_full);
        }
    }

    fn end(&self, end: End) {
        let notify = {
            let mut ended = self.ended.lock().unwrap_or_else(PoisonError::into_inner);
            let first = if ended.is_none() {
                *ended = Some(end.clone());
                Some(end)
            } else {
                None
            };
            self.pending
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clear();
            first
        };
        if let Some(end) = notify {
            self.events.push_terminal(end);
        }
    }
}

async fn run_guest(
    shared: Arc<GuestShared>,
    send: SendStream,
    mut recv: RecvStream,
    control_rx: mpsc::Receiver<Frame>,
    fallback_rx: mpsc::Receiver<Frame>,
    mut outgoing: mpsc::Receiver<Bytes>,
) {
    let connection = shared.connection.clone();
    let reader = async {
        loop {
            match control::read(&mut recv).await {
                Ok((Frame::Datagram(bytes), _)) => shared.accept(&bytes),
                Ok((Frame::Message(Message::Roster { members }), _)) => {
                    shared
                        .roster
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .clone_from(&members);
                    shared
                        .events
                        .push(GuestEvent::Roster(members), &shared.counts);
                }
                Ok((Frame::Message(Message::Reply { id, body }), _)) => {
                    if let Some(waiting) = shared
                        .pending
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .remove(&id)
                    {
                        let _ = waiting.try_send(Ok(body));
                    }
                }
                Ok((Frame::Message(Message::RequestBusy { id }), _)) => {
                    if let Some(waiting) = shared
                        .pending
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .remove(&id)
                    {
                        let _ = waiting.try_send(Err(Error::Request("host is busy".into())));
                    }
                }
                Ok((Frame::Message(Message::Notice { body }), _)) => {
                    shared.events.push(GuestEvent::Notice(body), &shared.counts);
                }
                Ok((Frame::Message(Message::Kick { reason }), _)) => {
                    shared.end(End::Kicked(reason));
                    connection.close(close::BYE.into(), b"kicked");
                    return;
                }
                Ok((Frame::Message(_) | Frame::Encoded(_), _)) | Err(FrameError::Invalid) => {
                    connection.close(close::INVALID.into(), b"invalid frame");
                    return;
                }
                Err(FrameError::Closed) => return,
            }
        }
    };
    let datagrams = async {
        loop {
            let Ok(bytes) = connection.read_datagram().await else {
                return;
            };
            Counts::bump(&shared.counts.quic_read);
            shared.accept(&bytes);
        }
    };
    let sender = async {
        while let Some(bytes) = outgoing.recv().await {
            send_room_datagram(&connection, &shared.fallback, bytes, &shared.counts);
        }
    };
    tokio::select! {
        () = reader => {}
        () = datagrams => {}
        () = sender => {}
        () = write_guest_frames(send, control_rx, fallback_rx) => {}
    }

    let reason = tokio::time::timeout(Duration::from_secs(1), connection.closed())
        .await
        .ok();
    let end = match reason {
        Some(ConnectionError::ApplicationClosed(app)) => match app.error_code.into_inner() {
            code if code == u64::from(close::KICKED) => {
                End::Kicked(String::from_utf8_lossy(&app.reason).into_owned())
            }
            code if code == u64::from(close::REPLACED) => End::Replaced,
            code if code == u64::from(close::ROOM_CLOSED) => End::HostClosed,
            _ => End::Lost,
        },
        Some(ConnectionError::LocallyClosed) => End::Left,
        None => {
            connection.close(close::BYE.into(), b"stopped");
            End::Lost
        }
        Some(_) => End::Lost,
    };
    shared.end(end);
}

/// Joined room handle. Dropping it leaves the room cleanly.
pub struct GuestRoom {
    node: Node,
    shared: Arc<GuestShared>,
    outgoing: mpsc::Sender<Bytes>,
}

impl std::fmt::Debug for GuestRoom {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuestRoom")
            .field("slot", &self.shared.slot)
            .field("ended", &self.ended())
            .finish_non_exhaustive()
    }
}

impl GuestRoom {
    #[must_use]
    pub fn slot(&self) -> u8 {
        self.shared.slot
    }

    #[must_use]
    pub fn host_compat(&self) -> &Compat {
        &self.shared.compat
    }

    #[must_use]
    pub fn roster(&self) -> Vec<Member> {
        self.shared
            .roster
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    #[must_use]
    pub fn ended(&self) -> Option<End> {
        self.shared
            .ended
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    #[must_use]
    pub fn path(&self) -> (Path, Option<u32>) {
        if self.shared.connection.close_reason().is_some() {
            (Path::Lost, None)
        } else {
            connection_path(&self.shared.connection)
        }
    }

    #[must_use]
    pub fn try_event(&self) -> Option<GuestEvent> {
        self.shared.events.try_pop()
    }

    #[must_use]
    pub fn event(&self, timeout: Duration) -> Option<GuestEvent> {
        self.shared.events.pop_timeout(timeout)
    }

    #[must_use]
    pub fn try_recv(&self) -> Option<Datagram> {
        self.shared.deliver.try_pop()
    }

    #[must_use]
    pub fn recv(&self, timeout: Duration) -> Option<Datagram> {
        self.shared.deliver.pop_timeout(timeout)
    }

    /// Queue a datagram from this guest's slot to `dst` (another slot or [`BROADCAST`]).
    #[must_use]
    pub fn send(&self, dst: u8, payload: &[u8]) -> bool {
        queue_outgoing(
            &self.outgoing,
            control::datagram_bytes(self.shared.slot, dst, payload),
            &self.shared.counts,
        )
    }

    #[cfg(test)]
    pub(crate) fn send_raw(&self, bytes: Vec<u8>) -> bool {
        self.outgoing.try_send(Bytes::from(bytes)).is_ok()
    }

    /// Send a JSON request to the host and wait up to `timeout` for a reply.
    pub fn request(
        &self,
        body: serde_json::Value,
        timeout: Duration,
    ) -> Result<serde_json::Value, Error> {
        let id = self.shared.next_id.fetch_add(1, Ordering::Relaxed);
        let encoded = control::encode_message(&Message::Request { id, body })
            .ok_or_else(|| Error::Request("request exceeds maximum frame size".into()))?;
        let (reply, answer) = sync::sync_channel(1);
        {
            let ended = self
                .shared
                .ended
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if ended.is_some() {
                return Err(Error::Stopped);
            }
            self.shared
                .pending
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(id, reply);
        }
        if self
            .shared
            .control
            .try_send(Frame::Encoded(encoded))
            .is_err()
        {
            self.forget(id);
            return Err(Error::Request("control queue full".into()));
        }
        let result = answer.recv_timeout(timeout);
        self.forget(id);
        match result {
            Ok(outcome) => outcome,
            Err(sync::RecvTimeoutError::Timeout) => {
                Err(Error::Request("host did not answer in time".into()))
            }
            Err(sync::RecvTimeoutError::Disconnected) => Err(Error::Stopped),
        }
    }

    fn forget(&self, id: u64) {
        self.shared
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&id);
    }

    #[must_use]
    pub fn counts(&self) -> CountsSnapshot {
        self.shared.counts.snapshot()
    }

    #[must_use]
    pub fn link(&self) -> LinkStats {
        link_stats(&self.shared.connection)
    }

    pub fn leave(self) {}

    #[must_use]
    pub fn node(&self) -> &Node {
        &self.node
    }
}

impl Drop for GuestRoom {
    fn drop(&mut self) {
        self.shared.end(End::Left);
        self.shared.connection.close(close::BYE.into(), b"bye");
    }
}
