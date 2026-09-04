//! L1 微基准（docs/perf.md §1）：帧头编解码 / auth_input / 建帧 / 解密 / AEAD 算法对照。
//! A/B 约束：仅使用 REQ-053 前后签名未变的公开 API——`crypto::seal` 在两侧分别是
//! 旧实现（to_vec 后原地加密）与新 in-place 实现的入口，天然构成跨提交对照；
//! `seal_naive_reference` 为内置旧算法参照，供基线不可得时降级对比。

use chacha20poly1305::aead::{AeadInOut, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use landscape_rill_core::crypto;
use landscape_rill_core::frame::{build_frame, open_frame, MeshFrameHeader};

const KEY_DST: [u8; 32] = [0x11; 32];
const SESSION: [u8; 32] = [0x22; 32];
const SALT: u32 = 0xdead_beef;

fn sample_header(seq: u32) -> MeshFrameHeader {
    MeshFrameHeader {
        to_node_id: 2,
        from_node_id: 1,
        seq,
        ..Default::default()
    }
}

/// naive 参照 = REQ-053 前的 seal 算法（明文整包 to_vec 后原地加密）
fn naive_seal(aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new_from_slice(&SESSION).unwrap();
    let mut buffer = plaintext.to_vec();
    cipher
        .encrypt_in_place(&Nonce::from(crypto::nonce(SALT, 7)), aad, &mut buffer)
        .unwrap();
    buffer
}

fn bench_header(c: &mut Criterion) {
    let h = sample_header(7);
    let mut buf = [0u8; 42];
    h.encode(&mut buf);
    c.bench_function("header/encode", |b| {
        b.iter(|| {
            let mut out = [0u8; 42];
            black_box(&h).encode(&mut out);
            out
        })
    });
    c.bench_function("header/decode", |b| {
        b.iter(|| MeshFrameHeader::decode(black_box(&buf[..])))
    });
    c.bench_function("header/auth_input", |b| {
        b.iter(|| black_box(&h).auth_input())
    });
}

fn bench_frame(c: &mut Criterion) {
    let mut group = c.benchmark_group("frame");
    for size in [64usize, 1400] {
        let payload = vec![0x5au8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("build", size), &payload, |b, p| {
            b.iter(|| {
                build_frame(
                    black_box(&sample_header(3)),
                    black_box(&KEY_DST),
                    black_box(&SESSION),
                    SALT,
                    black_box(p),
                )
            })
        });
        let frame = build_frame(&sample_header(3), &KEY_DST, &SESSION, SALT, &payload).unwrap();
        group.bench_with_input(BenchmarkId::new("open", size), &frame, |b, f| {
            b.iter(|| open_frame(black_box(f), black_box(&KEY_DST), black_box(&SESSION), SALT))
        });
    }
    group.finish();
}

fn bench_seal(c: &mut Criterion) {
    let payload = vec![0x5au8; 1400];
    let h = sample_header(3);
    let ai = h.auth_input();
    let mut group = c.benchmark_group("aead");
    group.throughput(Throughput::Bytes(1400));
    group.bench_function("seal_current", |b| {
        b.iter(|| {
            crypto::seal(
                black_box(&SESSION),
                SALT,
                7,
                black_box(&ai[..]),
                black_box(&payload),
            )
        })
    });
    group.bench_function("seal_naive_reference", |b| {
        b.iter(|| naive_seal(black_box(&ai[..]), black_box(&payload)))
    });
    group.finish();
}

criterion_group!(benches, bench_header, bench_frame, bench_seal);
criterion_main!(benches);
