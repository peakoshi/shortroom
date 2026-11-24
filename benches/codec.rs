#![allow(clippy::expect_used)]

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use shortroom::code::{self, RoomCode, ShortCode};
use shortroom::control::{self, Compat};

fn bench_codes(c: &mut Criterion) {
    let code = RoomCode {
        host: [0x42; shortroom::PEER_ID_LEN],
        secret: [0x19; code::SECRET_LEN],
    };
    let encoded = code.encode();
    let guest = [0x99; shortroom::PEER_ID_LEN];
    let proof = code.proof(&guest);
    let short = ShortCode::parse("K7M-2QX").expect("valid short code");
    let keys = short.keys_with(2);
    let sealed = keys.seal(&code).expect("seal");
    let pasted = format!("join my room with {encoded} tonight!");
    let pasted_short = "join my room with k7m-2qx tonight!";

    c.bench_function("room_code/encode", |b| b.iter(|| black_box(&code).encode()));
    c.bench_function("room_code/decode", |b| {
        b.iter(|| RoomCode::decode(black_box(&encoded)).expect("decode"));
    });
    c.bench_function("room_code/proof", |b| {
        b.iter(|| black_box(&code).proof(black_box(&guest)));
    });
    c.bench_function("room_code/verify", |b| {
        b.iter(|| black_box(&code).verify(black_box(&guest), black_box(&proof)));
    });
    c.bench_function("short_keys/seal", |b| {
        b.iter(|| black_box(&keys).seal(black_box(&code)).expect("seal"));
    });
    c.bench_function("short_keys/open", |b| {
        b.iter(|| black_box(&keys).open(black_box(&sealed)).expect("open"));
    });
    c.bench_function("code/find_full", |b| {
        b.iter(|| code::find_code(black_box(&pasted)));
    });
    c.bench_function("code/find_short", |b| {
        b.iter(|| code::find_code(black_box(pasted_short)));
    });
}

fn bench_control(c: &mut Criterion) {
    let payload = [0x5A_u8; 1024];
    let framed = control::datagram(2, 1, &payload).expect("datagram");
    let peer = [0xAB_u8; 32];
    let peer_hex = control::hex(&peer);
    let left = Compat::new("demo/1.0")
        .with_field("assets", "102")
        .with_field("build", "f7577b0")
        .with_tag("alpha")
        .with_tag("beta");
    let right = Compat::new("demo/1.0")
        .with_field("assets", "102")
        .with_field("build", "f7577b0")
        .with_tag("beta")
        .with_tag("alpha");

    c.bench_function("control/datagram_1k", |b| {
        b.iter(|| control::datagram(2, 1, black_box(&payload)));
    });
    c.bench_function("control/parse_datagram_1k", |b| {
        b.iter(|| control::parse_datagram(black_box(&framed)));
    });
    c.bench_function("control/hex_32", |b| {
        b.iter(|| control::hex(black_box(&peer)));
    });
    c.bench_function("control/unhex_32", |b| {
        b.iter(|| control::unhex(black_box(&peer_hex)));
    });
    c.bench_function("control/compat_mismatch", |b| {
        b.iter(|| black_box(&left).mismatch(black_box(&right)));
    });
}

criterion_group!(benches, bench_codes, bench_control);
criterion_main!(benches);
