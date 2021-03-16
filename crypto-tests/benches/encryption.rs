use criterion::{criterion_group, criterion_main, Bencher, BenchmarkId, Criterion};
use crypto_tests::{encrypt_hdr, encrypt_payload};
use crypto_tests::{encrypt_packet, MyNonce};
use ring::aead::BoundKey;
use ring::aead::SealingKey;
use ring::aead::UnboundKey;
use ring::aead::{AES_128_GCM, NONCE_LEN};

pub fn criterion_benchmark(c: &mut Criterion) {
    let key_bytes = [
        10, 141, 102, 148, 37, 119, 128, 179, 47, 14, 68, 0, 205, 28, 26, 149,
    ];
    let nonce = MyNonce {
        nonce: [0; NONCE_LEN],
    };
    let algorithm = &AES_128_GCM;
    let unbound_key = UnboundKey::new(&algorithm, &key_bytes).unwrap();
    let mut key = SealingKey::<MyNonce>::new(unbound_key, nonce);
    let mut header = vec![
        0x57, 0x25, 0xe7, 0x4f, 0x2d, 0x27, 0x5d, 0x12, 0x8b, 0x37, 0xb0, 0x47, 0x04, 0x16, 0x08,
        0xa1, 0x84, 0x23, 0x65, 0xdb, 0xfa, 0xe7,
    ];

    let mut group = c.benchmark_group("payload vs packet encryption");
    for payload in generate_data().iter_mut() {
        group.bench_with_input(
            BenchmarkId::new("payload encryption", payload.len()),
            payload,
            |b, payload| {
                b.iter(|| {
                    encrypt_payload(&mut key, header.clone().as_mut(), payload.clone().as_mut())
                })
            },
        );
        group.bench_with_input(
            BenchmarkId::new("packet encryption", payload.len()),
            payload,
            |b, payload| {
                b.iter(|| {
                    encrypt_packet(&mut key, header.clone().as_mut(), payload.clone().as_mut())
                })
            },
        );
    }
    group.finish();

    let mut group2 = c.benchmark_group("header vs payload encryption");
    for payload in generate_data().iter_mut() {
        group2.bench_with_input(
            BenchmarkId::new("payload encryption", payload.len()),
            payload,
            |b, payload| {
                b.iter(|| {
                    encrypt_payload(&mut key, header.clone().as_mut(), payload.clone().as_mut())
                })
            },
        );
        group2.bench_with_input(
            BenchmarkId::new("header encryption", payload.len()),
            payload,
            |b, payload| b.iter(|| encrypt_hdr(header.clone().as_mut())),
        );
    }
    group2.finish();
}

fn generate_data() -> Vec<Vec<u8>> {
    vec![100, 200, 300, 400, 500, 600, 700, 800, 900, 1000]
        .into_iter()
        .map(|bytes| (0..bytes).map(|_| rand::random::<u8>()).collect())
        .collect()
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
