use criterion::{criterion_group, criterion_main, Bencher, BenchmarkId, Criterion};
use crypto_tests::{decrypt_payload, encrypt_hdr, encrypt_payload};
use crypto_tests::{encrypt_packet, MyNonce};
use ring::aead::quic::{HeaderProtectionKey, AES_128};
use ring::aead::SealingKey;
use ring::aead::UnboundKey;
use ring::aead::{BoundKey, OpeningKey};
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
    let hp_key_bytes = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    let mut hp_key = HeaderProtectionKey::new(&AES_128, &hp_key_bytes).unwrap();
    let mut group = c.benchmark_group("payload vs packet encryption");
    for payload in generate_data().iter_mut() {
        group.bench_with_input(
            BenchmarkId::new("payload encryption", payload.len()),
            payload,
            |b, payload| {
                b.iter(|| {
                    encrypt_payload(payload.clone().as_mut(), header.clone().as_mut(), &mut key)
                })
            },
        );
        group.bench_with_input(
            BenchmarkId::new("packet encryption", payload.len()),
            payload,
            |b, payload| {
                b.iter(|| {
                    encrypt_packet(
                        header.clone().as_mut(),
                        payload.clone().as_mut(),
                        &mut hp_key,
                        &mut key,
                    )
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
                    encrypt_payload(payload.clone().as_mut(), header.clone().as_mut(), &mut key)
                })
            },
        );
        group2.bench_with_input(
            BenchmarkId::new("header encryption", payload.len()),
            payload,
            |b, payload| b.iter(|| encrypt_hdr(header.clone().as_mut(), payload, &mut hp_key)),
        );
    }
    group2.finish();

    let o_nonce = MyNonce {
        nonce: [0; NONCE_LEN],
    };
    let o_unbound_key = UnboundKey::new(&algorithm, &key_bytes).unwrap();
    let mut o_key = OpeningKey::<MyNonce>::new(o_unbound_key, o_nonce);
    let mut group3 = c.benchmark_group("payload encryption vs decryption");
    let mut payloads = generate_data();
    let mut encrypted_payloads = payloads.clone();
    encrypt_payloads(&mut key, &mut header, &mut encrypted_payloads);
    for i in 0..payloads.len() {
        let payload = payloads.get(i).unwrap();
        let encrypted_payload = encrypted_payloads.get(i).unwrap();
        group3.bench_with_input(
            BenchmarkId::new("payload encryption", payload.len()),
            payload,
            |b, payload| {
                b.iter(|| {
                    encrypt_payload(payload.clone().as_mut(), header.clone().as_mut(), &mut key)
                })
            },
        );
        group3.bench_with_input(
            BenchmarkId::new("payload decryption", payload.len()),
            encrypted_payload,
            |b, payload| {
                b.iter(|| {
                    decrypt_payload(
                        &mut o_key,
                        header.clone().as_mut(),
                        encrypted_payload.clone().as_mut(),
                    )
                })
            },
        );
    }
    group3.finish();
}

fn generate_data() -> Vec<Vec<u8>> {
    vec![
        100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1100, 1200, 1300,
    ]
    .into_iter()
    .map(|bytes| (0..bytes).map(|_| rand::random::<u8>()).collect())
    .collect()
}

fn encrypt_payloads(
    key: &mut SealingKey<MyNonce>,
    header: &mut Vec<u8>,
    payloads: &mut Vec<Vec<u8>>,
) {
    payloads
        .into_iter()
        .for_each(|payload| encrypt_payload(payload, header, key));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
