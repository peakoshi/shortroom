#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::type_complexity
)]

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::json;

use crate::code::{self, MemoryStore, RoomCode};
use crate::control::{self, Compat, MAX_JSON, Refusal};
use crate::room::{
    BROADCAST, CountsSnapshot, Datagram, End, GuestEvent, GuestRoom, HOST_SLOT, Hello, HostConfig,
    HostEvent, HostRoom, JoinError, JoinOptions, MAX_SLOTS, Node, NodeOptions, ROOM_BIND_TIMEOUT,
    RequestToken,
};
use crate::{Error, MAX_DATAGRAM, Relay};

const WAIT: Duration = Duration::from_secs(30);
const TEST_BIND_TIMEOUT: Duration = Duration::from_secs(30);

fn node(identity: Option<[u8; 32]>) -> Node {
    Node::start_within(
        NodeOptions {
            relay: Relay::Disabled,
            identity,
            ..NodeOptions::default()
        },
        TEST_BIND_TIMEOUT,
    )
    .unwrap()
}

fn compat() -> Compat {
    Compat::new("demo/1.0")
        .with_field("build", "f7577b0")
        .with_field("data", "102")
        .with_tag("ext-a@1")
        .with_tag("ext-b@2")
}

fn host(node: &Node, capacity: u8) -> HostRoom {
    node.host(HostConfig {
        compat: compat(),
        name: "Host".into(),
        capacity,
    })
    .unwrap()
}

fn hello(name: &str) -> Hello {
    Hello::new(compat(), name)
}

fn join_options(host: &Node) -> JoinOptions {
    let deadline = Instant::now() + WAIT;
    let mut addrs = host.direct_addrs();
    while addrs.is_empty() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
        addrs = host.direct_addrs();
    }
    assert!(!addrs.is_empty(), "host has no direct address");
    JoinOptions {
        addrs,
        timeout: WAIT,
    }
}

fn join(guest: &Node, room: &HostRoom, host: &Node, name: &str) -> GuestRoom {
    guest
        .join(&room.code(), &hello(name), &join_options(host))
        .unwrap()
}

fn host_event(room: &HostRoom) -> HostEvent {
    room.event(WAIT).expect("a host event")
}

fn joined(room: &HostRoom) -> u8 {
    loop {
        if let HostEvent::Joined { slot, .. } = host_event(room) {
            return slot;
        }
    }
}

fn left(room: &HostRoom, expected: u8) {
    loop {
        if let HostEvent::Left { slot, .. } = host_event(room)
            && slot == expected
        {
            return;
        }
    }
}

fn ended(guest: &GuestRoom) -> End {
    let deadline = Instant::now() + WAIT;
    while Instant::now() < deadline {
        if let Some(GuestEvent::Ended(end)) = guest.event(Duration::from_millis(100)) {
            return end;
        }
    }
    panic!("guest room did not end");
}

fn deliver(
    payload: &[u8],
    send: impl Fn() -> bool,
    recv: impl Fn(Duration) -> Option<Datagram>,
) -> Datagram {
    let deadline = Instant::now() + WAIT;
    while Instant::now() < deadline {
        assert!(send(), "datagram was not queued");
        while let Some(datagram) = recv(Duration::from_millis(100)) {
            if datagram.payload == payload {
                return datagram;
            }
        }
    }
    panic!("no datagram arrived");
}

fn refused(result: Result<GuestRoom, JoinError>) -> (Refusal, Compat) {
    match result {
        Err(JoinError::Refused(refusal, compat)) => (refusal, *compat),
        Err(other) => panic!("expected refusal, got {other:?}"),
        Ok(room) => panic!("expected refusal, got slot {}", room.slot()),
    }
}

fn assert_causes_add_up(counts: CountsSnapshot) {
    assert_eq!(
        counts.dropped,
        counts.malformed
            + counts.unroutable
            + counts.deliver_full
            + counts.send_full
            + counts.stream_full
            + counts.send_failed,
        "{counts:?}"
    );
}

#[test]
fn default_bind_timeout_and_debug_redaction() {
    assert_eq!(ROOM_BIND_TIMEOUT, Duration::from_millis(1800));
    let options = NodeOptions {
        relay: Relay::Custom("https://alice:pw@relay.example/p?token=secret1".into()),
        pkarr_relay: Some("https://bob:pw2@pkarr.example/q?token=secret2".into()),
        identity: Some([137_u8; 32]),
        alpn: None,
    };
    let text = format!("{options:?}");
    assert!(text.contains("identity"));
    assert!(text.contains("https://relay.example"), "{text}");
    assert!(text.contains("https://pkarr.example"), "{text}");
    for leak in ["137", "alice", "pw", "secret1", "bob", "pw2", "secret2"] {
        assert!(!text.contains(leak), "leaked {leak} in {text}");
    }

    let n = Node::start_within(
        NodeOptions {
            relay: Relay::Disabled,
            pkarr_relay: Some("https://pkarr.example/endpoint?token=hidden".into()),
            ..NodeOptions::default()
        },
        TEST_BIND_TIMEOUT,
    )
    .unwrap();
    let node_dbg = format!("{n:?}");
    assert!(node_dbg.contains("https://pkarr.example"), "{node_dbg}");
    assert!(!node_dbg.contains("hidden"), "{node_dbg}");

    let guest_node = node(None);
    let room = host(&n, 4);
    let guest = join(&guest_node, &room, &n, "Guest");
    assert_eq!(joined(&room), 2);
    assert!(room.notify(2, &json!({"secret": "do-not-dump"})));
    let _ = deliver(
        b"payload-secret",
        || guest.send(HOST_SLOT, b"payload-secret"),
        |t| {
            let d = room.recv(t);
            if d.is_some() {
                assert!(!format!("{room:?}").contains("payload-secret"));
                assert!(!format!("{guest:?}").contains("do-not-dump"));
            }
            d
        },
    );
    assert!(!format!("{room:?}").contains("banned"));
    assert!(!format!("{guest:?}").contains("pending"));
}

#[test]
fn invalid_node_and_host_configs_fail_fast() {
    for bad_relay in [
        "not a url",
        "http://relay.example",
        "https://user:secret@relay.example",
    ] {
        assert!(matches!(
            Node::start(NodeOptions {
                relay: Relay::Custom(bad_relay.to_owned()),
                ..NodeOptions::default()
            }),
            Err(Error::BadRelay)
        ));
        assert!(matches!(
            Node::start(NodeOptions {
                relay: Relay::Disabled,
                pkarr_relay: Some(bad_relay.to_owned()),
                ..NodeOptions::default()
            }),
            Err(Error::BadRelay)
        ));
    }
    for bad_alpn in [Vec::new(), vec![b'a'; 256]] {
        assert!(matches!(
            Node::start(NodeOptions {
                relay: Relay::Disabled,
                alpn: Some(bad_alpn),
                ..NodeOptions::default()
            }),
            Err(Error::InvalidConfig(_))
        ));
    }
    let n = node(None);
    for bad_cap in [0, 1, MAX_SLOTS + 1] {
        assert!(matches!(
            n.host(HostConfig {
                compat: compat(),
                name: "Host".into(),
                capacity: bad_cap,
            }),
            Err(Error::InvalidConfig(_))
        ));
    }
}

#[test]
fn start_join_and_drop_inside_tokio_runtime_never_panic() {
    let host_node = node(None);
    let guest_node = node(None);
    let room = host(&host_node, 4);
    let opts = join_options(&host_node);
    let code = room.code();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async move {
        assert!(matches!(
            Node::start(NodeOptions {
                relay: Relay::Disabled,
                ..NodeOptions::default()
            }),
            Err(Error::Start(_))
        ));
        let guest = guest_node
            .join(&code, &hello("AsyncCaller"), &opts)
            .unwrap();
        assert_eq!(guest.slot(), 2);
        drop(guest);
        drop(room);
        drop(guest_node);
        drop(host_node);
    });
}

#[test]
fn duration_max_timeout_does_not_panic() {
    let n = node(None);
    let code = RoomCode::new(n.id()).unwrap();
    let opts = JoinOptions {
        addrs: Vec::new(),
        timeout: Duration::MAX,
    };
    assert!(matches!(
        n.join(&code, &hello("Self"), &opts),
        Err(JoinError::Unreachable)
    ));
}

#[test]
fn nonblocking_poll_does_not_stall_behind_timed_wait() {
    let host_node = node(None);
    let room = Arc::new(host(&host_node, 4));
    let waiter = {
        let room = Arc::clone(&room);
        thread::spawn(move || room.recv(Duration::from_secs(1)))
    };
    thread::sleep(Duration::from_millis(30));
    let started = Instant::now();
    assert!(room.try_recv().is_none());
    assert!(room.try_event().is_none());
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "try_recv stalled for {:?}",
        started.elapsed()
    );
    assert!(waiter.join().unwrap().is_none());
}

#[test]
fn short_code_join_and_both_datagram_framings() {
    let (host_node, guest_node) = (node(None), node(None));
    let room = host(&host_node, 8);
    assert!(room.is_open());
    assert_eq!(room.capacity(), 8);

    let store = MemoryStore::default();
    let short = code::publish_short_with_rounds(&store, &room.code(), 2).unwrap();
    let typed = short.text().to_lowercase().replace('-', " ");
    let found = code::resolve_code_with_rounds(&store, &typed, 2).unwrap();
    assert_eq!(found, room.code());

    let guest = guest_node
        .join(&found, &hello("Guest"), &join_options(&host_node))
        .unwrap();
    assert_eq!(guest.slot(), 2);
    assert_eq!(guest.host_compat(), &compat());
    assert_eq!(
        host_event(&room),
        HostEvent::Joined {
            slot: 2,
            peer: guest_node.id(),
            name: "Guest".into(),
        }
    );
    let names: Vec<_> = guest
        .roster()
        .into_iter()
        .map(|m| (m.slot, m.name))
        .collect();
    assert_eq!(names, [(1, "Host".to_owned()), (2, "Guest".to_owned())]);

    let got = deliver(
        b"from host",
        || room.send(2, b"from host"),
        |t| guest.recv(t),
    );
    assert_eq!(
        (got.src, got.dst, got.payload.as_slice()),
        (HOST_SLOT, 2, &b"from host"[..])
    );
    let got = deliver(
        b"from guest",
        || guest.send(HOST_SLOT, b"from guest"),
        |t| room.recv(t),
    );
    assert_eq!(
        (got.src, got.dst, got.payload.as_slice()),
        (2, HOST_SLOT, &b"from guest"[..])
    );

    let big: Vec<u8> = (0..MAX_DATAGRAM)
        .map(|i| u8::try_from(i % 251).unwrap())
        .collect();
    assert_eq!(
        deliver(&big, || room.send(2, &big), |t| guest.recv(t)).payload,
        big
    );
    assert_eq!(
        deliver(&big, || guest.send(HOST_SLOT, &big), |t| room.recv(t)).payload,
        big
    );
    assert!(room.counts().framed >= 1 && guest.counts().framed >= 1);

    assert!(!guest.send(HOST_SLOT, &[]));
    assert!(!room.send(2, &[0; MAX_DATAGRAM + 1]));

    let members = room.members();
    assert_eq!(members.len(), 2);
    assert_eq!(members[1].member.peer, crate::peer_text(&guest_node.id()));
}

#[test]
fn dropped_datagrams_and_quic_link_stats_reconcile() {
    let (host_node, guest_node) = (node(None), node(None));
    let room = host(&host_node, 8);
    let guest = join(&guest_node, &room, &host_node, "Guest");
    assert_eq!(joined(&room), 2);
    deliver(b"warm", || room.send(2, b"warm"), |t| guest.recv(t));

    assert!(!room.send(2, &[]));
    assert!(room.send(7, b"nobody"));
    let deadline = Instant::now() + WAIT;
    while room.counts().unroutable == 0 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    let counts = room.counts();
    assert_eq!((counts.malformed, counts.unroutable), (1, 1));

    let payload = [0x5A; 1100];
    let burst_deadline = Instant::now() + WAIT;
    while room.counts().evicted_estimate == 0
        && room.counts().send_full == 0
        && Instant::now() < burst_deadline
    {
        for _ in 0..400 {
            let _ = room.send(2, &payload);
        }
        thread::sleep(Duration::from_millis(10));
    }
    let deadline = Instant::now() + WAIT;
    while room.members()[1].link.datagrams_sent < 50 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    while guest.try_recv().is_some() {}

    // Sample QUIC link before app counts on sender, and app counts before link on receiver,
    // so the monotonicity inequalities hold even if in-flight packets are still completing.
    let link = room.members()[1].link;
    let counts = room.counts();
    assert!(
        counts.evicted_estimate > 0 || counts.send_full > 0,
        "{counts:?}"
    );
    assert_causes_add_up(counts);
    assert!(link.datagrams_sent > 0 && link.packets_sent > 0, "{link:?}");
    assert!(
        link.datagrams_sent <= counts.quic_sent,
        "{link:?} {counts:?}"
    );
    assert!(link.mtu > 0 && link.max_datagram.is_some(), "{link:?}");

    let guest_counts = guest.counts();
    let guest_link = guest.link();
    assert!(guest_counts.quic_read > 0, "{guest_counts:?}");
    assert!(guest_counts.quic_read <= guest_link.datagrams_received);
    assert_causes_add_up(guest_counts);
}

#[test]
fn star_forwarding_and_broadcast_stamp_sources() {
    let (host_node, a_node, b_node) = (node(None), node(None), node(None));
    let room = host(&host_node, 8);
    let a = join(&a_node, &room, &host_node, "A");
    assert_eq!(joined(&room), 2);
    let b = join(&b_node, &room, &host_node, "B");
    assert_eq!(joined(&room), 3);

    let deadline = Instant::now() + WAIT;
    while a.roster().len() < 3 && Instant::now() < deadline {
        let _ = a.event(Duration::from_millis(50));
    }
    assert_eq!(a.roster().len(), 3);

    let got = deliver(b"a to b", || a.send(3, b"a to b"), |t| b.recv(t));
    assert_eq!((got.src, got.dst), (2, 3));
    assert!(room.try_recv().is_none());
    assert!(room.counts().forwarded >= 1);

    // Drain any duplicate retries of `"a to b"` before testing B's own broadcast isolation.
    thread::sleep(Duration::from_millis(50));
    while b.try_recv().is_some() {}

    let got = deliver(
        b"b to all",
        || b.send(BROADCAST, b"b to all"),
        |t| a.recv(t),
    );
    assert_eq!((got.src, got.dst), (3, BROADCAST));
    let got = deliver(
        b"b to all",
        || b.send(BROADCAST, b"b to all"),
        |t| room.recv(t),
    );
    assert_eq!(got.src, 3);
    thread::sleep(Duration::from_millis(100));
    while let Some(datagram) = b.try_recv() {
        assert_ne!(datagram.payload, b"b to all");
    }

    let got = deliver(
        b"host to all",
        || room.send(BROADCAST, b"host to all"),
        |t| b.recv(t),
    );
    assert_eq!(got.src, HOST_SLOT);
}

#[test]
fn spoofed_and_malformed_datagrams_are_dropped_by_host() {
    let (host_node, a_node, b_node) = (node(None), node(None), node(None));
    let room = host(&host_node, 8);
    let a = join(&a_node, &room, &host_node, "A");
    let b = join(&b_node, &room, &host_node, "B");
    assert_eq!((a.slot(), b.slot()), (2, 3));

    for _ in 0..20 {
        assert!(a.send_raw(control::datagram(3, HOST_SLOT, b"spoof").unwrap()));
        assert!(a.send_raw(control::datagram(HOST_SLOT, 3, b"spoof").unwrap()));
    }
    let unspoofed = |t| {
        let got = room.recv(t);
        assert!(
            got.as_ref().is_none_or(|d| d.payload != b"spoof"),
            "{got:?}"
        );
        got
    };
    let got = deliver(b"honest", || a.send(HOST_SLOT, b"honest"), unspoofed);
    assert_eq!((got.src, got.payload.as_slice()), (2, &b"honest"[..]));
    while let Some(datagram) = room.try_recv() {
        assert_eq!(datagram.payload, b"honest");
    }
    while let Some(datagram) = b.try_recv() {
        assert_ne!(datagram.payload, b"spoof");
    }
    assert!(room.counts().spoofed >= 1);
    assert_eq!(room.counts().forwarded, 0);

    assert!(a.send_raw(vec![0xFF, 2, 1, 9]));
    let _ = deliver(b"after", || a.send(HOST_SLOT, b"after"), unspoofed);
    assert!(room.counts().dropped >= 1);
}

#[test]
fn unverified_and_mismatched_hellos_are_refused() {
    let (host_node, guest_node) = (node(None), node(None));
    let unknown = Compat::new("unknown");
    let unverified_room = host_node
        .host(HostConfig {
            compat: unknown.clone(),
            name: "Host".into(),
            capacity: 8,
        })
        .unwrap();
    let (refusal, _) = refused(guest_node.join(
        &unverified_room.code(),
        &Hello::new(unknown, "Guest"),
        &join_options(&host_node),
    ));
    assert_eq!(refusal, Refusal::Unverified("app".into()));
    drop(unverified_room);

    let room = host(&host_node, 8);
    let opts = join_options(&host_node);
    let cases: [(fn(&mut Hello), Refusal, bool); 5] = [
        (
            |h| h.compat.app = "demo/2.0".into(),
            Refusal::Version("app".into()),
            true,
        ),
        (
            |h| {
                h.compat.fields.insert("build".into(), "0000000".into());
            },
            Refusal::Version("build".into()),
            true,
        ),
        (
            |h| {
                h.compat.fields.remove("data");
            },
            Refusal::Version("data".into()),
            true,
        ),
        (
            |h| {
                h.compat.tags.pop();
            },
            Refusal::Version("tags".into()),
            true,
        ),
        (|h| h.proto = 99, Refusal::Protocol, false),
    ];
    for (change, expected, should_disclose_compat) in cases {
        let mut h = hello("Mismatched");
        change(&mut h);
        let (refusal, theirs) = refused(guest_node.join(&room.code(), &h, &opts));
        assert_eq!(refusal, expected);
        if should_disclose_compat {
            assert!(theirs == compat() || theirs == Compat::default());
        } else {
            assert_eq!(theirs, Compat::default());
        }
        assert!(
            matches!(host_event(&room), HostEvent::Refused { refusal, .. } if refusal == expected)
        );
    }

    let stale = RoomCode {
        secret: [0; code::SECRET_LEN],
        ..room.code()
    };
    let (refusal, theirs) = refused(guest_node.join(&stale, &hello("Stale"), &opts));
    assert_eq!(refusal, Refusal::Secret);
    assert_eq!(theirs, Compat::default());

    let mut reordered = hello("Reordered");
    reordered.compat.tags.reverse();
    let guest = guest_node.join(&room.code(), &reordered, &opts).unwrap();
    assert_eq!(guest.slot(), 2);
}

#[test]
fn custom_alpn_isolates_nodes() {
    let host_node = Node::start_within(
        NodeOptions {
            relay: Relay::Disabled,
            alpn: Some(b"custom-app/1".to_vec()),
            ..NodeOptions::default()
        },
        TEST_BIND_TIMEOUT,
    )
    .unwrap();
    let wrong_guest = Node::start_within(
        NodeOptions {
            relay: Relay::Disabled,
            alpn: Some(b"other-app/1".to_vec()),
            ..NodeOptions::default()
        },
        TEST_BIND_TIMEOUT,
    )
    .unwrap();
    let matching_guest = Node::start_within(
        NodeOptions {
            relay: Relay::Disabled,
            alpn: Some(b"custom-app/1".to_vec()),
            ..NodeOptions::default()
        },
        TEST_BIND_TIMEOUT,
    )
    .unwrap();

    let room = host(&host_node, 4);
    let mut short_opts = join_options(&host_node);
    short_opts.timeout = Duration::from_secs(1);
    assert!(matches!(
        wrong_guest.join(&room.code(), &hello("Wrong"), &short_opts),
        Err(JoinError::Unreachable | JoinError::Broken)
    ));
    let ok = matching_guest
        .join(&room.code(), &hello("Right"), &join_options(&host_node))
        .unwrap();
    assert_eq!(ok.slot(), 2);
}

#[test]
fn kick_stops_traffic_and_bans_rejoin() {
    let (host_node, a_node, b_node) = (node(None), node(None), node(None));
    let room = host(&host_node, 8);
    let a = join(&a_node, &room, &host_node, "A");
    let b = join(&b_node, &room, &host_node, "B");
    assert_eq!(joined(&room), 2);
    assert_eq!(joined(&room), 3);
    let _ = deliver(b"before", || a.send(HOST_SLOT, b"before"), |t| room.recv(t));

    assert!(room.kick(2, "removed"));
    assert!(!room.kick(2, "again"));
    left(&room, 2);
    assert_eq!(ended(&a), End::Kicked("removed".into()));
    assert_eq!(a.ended(), Some(End::Kicked("removed".into())));
    assert!(matches!(
        a.request(json!({}), Duration::from_millis(100)),
        Err(Error::Stopped)
    ));

    let deadline = Instant::now() + WAIT;
    while b.roster().len() != 2 && Instant::now() < deadline {
        let _ = b.event(Duration::from_millis(50));
    }
    assert_eq!(b.roster().len(), 2);

    while room.try_recv().is_some() {}
    for _ in 0..10 {
        let _ = a.send(HOST_SLOT, b"after kick");
    }
    thread::sleep(Duration::from_millis(200));
    assert!(room.try_recv().is_none());
    drop(a);

    let (refusal, _) = refused(a_node.join(&room.code(), &hello("A"), &join_options(&host_node)));
    assert_eq!(refusal, Refusal::Kicked);

    let got = deliver(
        b"still here",
        || b.send(HOST_SLOT, b"still here"),
        |t| room.recv(t),
    );
    assert_eq!(got.src, 3);
}

#[test]
fn reconnect_reclaims_slot_replaces_stale_and_bounds_reservations() {
    let identity = [42_u8; 32];
    let host_node = node(None);
    let room = host(&host_node, 4);
    let a_node = node(Some(identity));
    let b_node = node(None);
    let a = join(&a_node, &room, &host_node, "A");
    assert_eq!(a.slot(), 2);
    let b = join(&b_node, &room, &host_node, "B");
    assert_eq!(b.slot(), 3);
    assert_eq!(joined(&room), 2);
    assert_eq!(joined(&room), 3);

    a.leave();
    left(&room, 2);
    let c_node = node(None);
    let c = join(&c_node, &room, &host_node, "C");
    assert_eq!(c.slot(), 4);
    assert_eq!(joined(&room), 4);

    let a = join(&a_node, &room, &host_node, "A");
    assert_eq!(a.slot(), 2);
    assert_eq!(joined(&room), 2);

    let restarted = node(Some(identity));
    assert_eq!(restarted.id(), a_node.id());
    let again = join(&restarted, &room, &host_node, "A");
    assert_eq!(again.slot(), 2);
    assert_eq!(ended(&a), End::Replaced);
    assert_eq!(room.members().len(), 4);

    again.leave();
    left(&room, 2);
    for idx in 0..4 {
        let newcomer = node(None);
        let g = join(&newcomer, &room, &host_node, &format!("N{idx}"));
        assert_eq!(g.slot(), 2);
        assert_eq!(joined(&room), 2);
        assert!(room.reserved_len() <= usize::from(room.capacity() - 1));
        g.leave();
        left(&room, 2);
    }
    drop(b);
    drop(c);
}

#[test]
fn oversized_json_messages_are_rejected_without_disconnecting_guests() {
    let (host_node, guest_node) = (node(None), node(None));
    let room = host(&host_node, 4);
    let guest = join(&guest_node, &room, &host_node, "Guest");
    assert_eq!(joined(&room), 2);

    let huge = json!({"blob": "x".repeat(MAX_JSON)});
    assert!(!room.notify(BROADCAST, &huge));
    assert!(matches!(
        guest.request(huge.clone(), Duration::from_secs(1)),
        Err(Error::Request(_))
    ));

    let guest = Arc::new(guest);
    let call = {
        let guest = Arc::clone(&guest);
        thread::spawn(move || guest.request(json!({"op": "ok"}), WAIT))
    };
    let req = loop {
        if let Some(HostEvent::Request { request, .. }) = room.event(WAIT) {
            break request;
        }
    };
    assert!(!room.reply(&req, huge));
    assert!(room.reply(&req, json!({"ok": true})));
    assert_eq!(call.join().unwrap().unwrap(), json!({"ok": true}));
}

#[test]
fn requests_notices_and_generation_isolation() {
    fn next_request(room: &HostRoom, expected_op: &str) -> (RequestToken, serde_json::Value) {
        let deadline = Instant::now() + WAIT;
        while Instant::now() < deadline {
            if let Some(HostEvent::Request { request, body }) =
                room.event(Duration::from_millis(50))
                && body.get("op").and_then(serde_json::Value::as_str) == Some(expected_op)
            {
                return (request, body);
            }
        }
        panic!("no request with op={expected_op} reached host");
    }

    let host_node = node(None);
    let room = host(&host_node, 8);
    let identity = [0x72; 32];
    let old_node = node(Some(identity));
    let old = Arc::new(join(&old_node, &room, &host_node, "Guest"));
    assert_eq!(joined(&room), 2);

    let old_call = {
        let old = Arc::clone(&old);
        thread::spawn(move || old.request(json!({"op": "old"}), WAIT))
    };
    let (retired, body) = next_request(&room, "old");
    assert_eq!(body, json!({"op": "old"}));
    assert!(room.request_current(&retired));

    let replacement_node = node(Some(identity));
    let replacement = Arc::new(join(&replacement_node, &room, &host_node, "Guest"));
    assert_eq!(replacement.slot(), retired.slot());
    assert_eq!(ended(&old), End::Replaced);
    assert!(matches!(old_call.join().unwrap(), Err(Error::Stopped)));

    let replacement_call = {
        let replacement = Arc::clone(&replacement);
        thread::spawn(move || replacement.request(json!({"op": "current"}), WAIT))
    };
    let (current, _) = next_request(&room, "current");
    assert!(!room.request_current(&retired));
    assert!(room.request_current(&current));
    assert!(!room.reply(&retired, json!({"answer": "stale"})));
    assert!(room.reply(&current, json!({"answer": "current"})));
    assert_eq!(
        replacement_call.join().unwrap().unwrap(),
        json!({"answer": "current"})
    );

    assert!(room.notify(BROADCAST, &json!({"event": "started"})));
    let deadline = Instant::now() + WAIT;
    let mut got_notice = false;
    while !got_notice && Instant::now() < deadline {
        if let Some(GuestEvent::Notice(body)) = replacement.try_event() {
            assert_eq!(body, json!({"event": "started"}));
            got_notice = true;
        } else {
            thread::sleep(Duration::from_millis(5));
        }
    }
    assert!(got_notice);

    assert!(matches!(
        replacement.request(json!({"op": "drop"}), Duration::from_millis(150)),
        Err(Error::Request(_))
    ));
    let _ = next_request(&room, "drop");

    let pending_call = {
        let replacement = Arc::clone(&replacement);
        thread::spawn(move || replacement.request(json!({"op": "closing"}), WAIT))
    };
    let _ = next_request(&room, "closing");
    drop(room);
    assert_eq!(ended(&replacement), End::HostClosed);
    assert!(matches!(pending_call.join().unwrap(), Err(Error::Stopped)));
}

#[test]
fn full_closed_and_single_hosted_room_per_node() {
    let (host_node, a_node, b_node) = (node(None), node(None), node(None));
    let room = host(&host_node, 2);
    assert!(matches!(
        host_node.host(HostConfig {
            compat: compat(),
            name: "Second".into(),
            capacity: 4,
        }),
        Err(Error::AlreadyHosting)
    ));

    let a = join(&a_node, &room, &host_node, "A");
    let (refusal, _) = refused(b_node.join(&room.code(), &hello("B"), &join_options(&host_node)));
    assert_eq!(refusal, Refusal::Full);

    room.set_open(false);
    assert!(!room.is_open());
    drop(a);
    left(&room, 2);
    let (refusal, _) = refused(b_node.join(&room.code(), &hello("B"), &join_options(&host_node)));
    assert_eq!(refusal, Refusal::Closed);

    room.set_open(true);
    assert_eq!(join(&b_node, &room, &host_node, "B").slot(), 2);

    drop(room);
    let code = RoomCode::new(host_node.id()).unwrap();
    let mut opts = join_options(&host_node);
    opts.timeout = Duration::from_secs(1);
    assert!(matches!(
        a_node.join(&code, &hello("Late"), &opts),
        Err(JoinError::Unreachable | JoinError::Broken)
    ));
}

#[test]
fn saturated_guest_event_queue_still_delivers_ended() {
    let (host_node, guest_node) = (node(None), node(None));
    let room = host(&host_node, 4);
    let guest = join(&guest_node, &room, &host_node, "Guest");
    assert_eq!(joined(&room), 2);

    for i in 0..1200 {
        let _ = room.notify(2, &json!({"n": i}));
    }
    thread::sleep(Duration::from_millis(100));
    drop(room);

    let deadline = Instant::now() + WAIT;
    let mut saw_ended = None;
    while Instant::now() < deadline {
        if let Some(GuestEvent::Ended(end)) = guest.event(Duration::from_millis(100)) {
            saw_ended = Some(end);
            break;
        }
    }
    assert_eq!(saw_ended, Some(End::HostClosed));
}

#[test]
fn host_request_queue_overload_returns_busy_without_waiting_for_timeout() {
    let (host_node, guest_node) = (node(None), node(None));
    let room = host(&host_node, 4);
    let guest = Arc::new(join(&guest_node, &room, &host_node, "Guest"));
    assert_eq!(joined(&room), 2);

    let chunk = json!({"pad": "a".repeat(512 * 1024)});
    let mut busy_hit = false;
    for _ in 0..16 {
        let started = Instant::now();
        match guest.request(chunk.clone(), Duration::from_millis(80)) {
            Err(Error::Request(msg)) if msg.contains("busy") => {
                assert!(started.elapsed() < Duration::from_secs(2));
                busy_hit = true;
                break;
            }
            Err(Error::Request(_)) => {}
            other => panic!("unexpected result: {other:?}"),
        }
    }
    assert!(busy_hit, "expected host overload to report busy");
}

#[test]
#[ignore = "requires internet access and public relays"]
fn live_public_relay_short_code_join() {
    let host_node = Node::start(NodeOptions::default()).unwrap();
    let guest_node = Node::start(NodeOptions::default()).unwrap();
    let room = host(&host_node, 4);
    let short = code::publish_short(&host_node, &room.code()).unwrap();
    let resolved = code::resolve_code(&guest_node, &short.text()).unwrap();
    assert_eq!(resolved, room.code());
    let guest = guest_node
        .join(&resolved, &hello("Remote"), &JoinOptions::default())
        .unwrap();
    let got = deliver(
        b"ping",
        || room.send(guest.slot(), b"ping"),
        |t| guest.recv(t),
    );
    assert_eq!(got.payload, b"ping");
    code::withdraw_short(&host_node, &short).unwrap();
}
