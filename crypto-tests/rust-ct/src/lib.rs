use ring::aead::quic::HeaderProtectionKey;
use ring::aead::Aad;
use ring::aead::Nonce;
use ring::aead::NonceSequence;
use ring::aead::NONCE_LEN;
use ring::aead::{OpeningKey, SealingKey};
use ring::error::Unspecified;

pub struct MyNonce {
    pub nonce: [u8; NONCE_LEN],
    pub counter: u64,
}

impl NonceSequence for MyNonce {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        // XOR the last bytes of the IV with the counter. This is equivalent to
        // left-padding the counter with zero bytes.
        for (a, b) in self.nonce[4..].iter_mut().zip(self.counter.to_be_bytes().iter()) {
            *a ^= b;
        }
        self.counter +=1;
        Ok(Nonce::assume_unique_for_key(self.nonce))
    }
}

pub fn encrypt_hdr(header: &mut Vec<u8>, payload: &[u8], hp_key: &mut HeaderProtectionKey) {
    // in our tests packet number len can be written using 1 byte
    let pn_len = 1;
    let sample = &payload[4 - pn_len..16 + (4 - pn_len)];
    let mask: [u8; 5] = hp_key.new_mask(sample).unwrap();
    let (first, rest) = header.split_at_mut(1);

    first[0] ^= mask[0] & 0x1f;

    let rest_len = rest.len();
    let pn_buf = &mut rest[rest_len - pn_len..];
    for i in 0..pn_len {
        pn_buf[i] ^= mask[i + 1];
    }
}

pub fn encrypt_payload(payload: &mut Vec<u8>, header: &mut Vec<u8>, key: &mut SealingKey<MyNonce>) {
    key.seal_in_place_append_tag(Aad::from(header), payload)
        .unwrap();
}

pub fn encrypt_packet(
    header: &mut Vec<u8>,
    payload: &mut Vec<u8>,
    hp_key: &mut HeaderProtectionKey,
    key: &mut SealingKey<MyNonce>,
) {
    encrypt_payload(payload, header, key);
    encrypt_hdr(header, payload, hp_key);
}

// TODO
// pub fn decrypt_hdr() {
// }

pub fn decrypt_payload(key: &mut OpeningKey<MyNonce>, header: &mut Vec<u8>, payload: &mut Vec<u8>) {
    key.open_in_place(Aad::from(header), payload).unwrap();
}

#[cfg(test)]
mod tests {
    use crate::{encrypt_hdr, encrypt_payload, MyNonce};
    use ring::aead::quic::{HeaderProtectionKey, AES_128};
    use ring::aead::{Aad, BoundKey, OpeningKey, SealingKey, UnboundKey, AES_128_GCM, NONCE_LEN};

    #[test]
    fn test_encrypt_hdr() {
        let payload: Vec<u8> = (0..100).map(|_| rand::random::<u8>()).collect();
        // let key_bytes = [
        //     10, 141, 102, 148, 37, 119, 128, 179, 47, 14, 68, 0, 205, 28, 26, 149,
        // ];
        let hp_key_bytes = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let mut header = vec![
            0x40, 0x25, 0xe7, 0x4f, 0x2d, 0x27, 0x5d, 0x12, 0x8b, 0x37, 0xb0, 0x47, 0x04, 0x16,
            0x08, 0xa1, 0x84, 0x23, 0x65, 0xdb, 0xfa, 0xe7,
        ];
        let mut hp_key = HeaderProtectionKey::new(&AES_128, &hp_key_bytes).unwrap();

        encrypt_hdr(&mut header, &payload, &mut hp_key);
    }

    #[test]
    fn test_decrypt_payload() {
        let payload: Vec<u8> = (0..10).map(|_| rand::random::<u8>()).collect();
        let key_bytes = [
            10, 141, 102, 148, 37, 119, 128, 179, 47, 14, 68, 0, 205, 28, 26, 149,
        ];
        let nonce = MyNonce {
            nonce: [0; NONCE_LEN],
            counter: 0,
        };
        let o_nonce = MyNonce {
            nonce: [0; NONCE_LEN],
            counter: 0,
        };
        let algorithm = &AES_128_GCM;
        let unbound_key = UnboundKey::new(&algorithm, &key_bytes).unwrap();
        let o_unbound_key = UnboundKey::new(&algorithm, &key_bytes).unwrap();
        let mut key = SealingKey::<MyNonce>::new(unbound_key, nonce);
        let mut o_key = OpeningKey::<MyNonce>::new(o_unbound_key, o_nonce);
        let mut header = vec![
            0x40, 0x25, 0xe7, 0x4f, 0x2d, 0x27, 0x5d, 0x12, 0x8b, 0x37, 0xb0, 0x47, 0x04, 0x16,
            0x08, 0xa1, 0x84, 0x23, 0x65, 0xdb, 0xfa, 0xe7,
        ];
        let mut ciphertext = payload.clone();
        encrypt_payload(&mut ciphertext, &mut header, &mut key);
        assert_ne!(payload, ciphertext[..10]);
        let mut plaintext = ciphertext.clone();
        o_key
            .open_in_place(Aad::from(header), &mut plaintext)
            .unwrap();
        assert_ne!(plaintext, ciphertext[..10]);
        assert_eq!(plaintext[..10], payload);
    }
}
