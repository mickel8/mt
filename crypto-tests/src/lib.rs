use ring::aead::Aad;
use ring::aead::Nonce;
use ring::aead::NonceSequence;
use ring::aead::NONCE_LEN;
use ring::aead::{OpeningKey, SealingKey};
use ring::error::Unspecified;

pub struct MyNonce {
    pub nonce: [u8; NONCE_LEN],
}

impl NonceSequence for MyNonce {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        Ok(Nonce::assume_unique_for_key(self.nonce))
    }
}

pub fn encrypt_hdr(header: &mut Vec<u8>) {
    // in our tests packet number len can be written using 1 byte
    let pn_len = 1;
    let mask: [u8; 5] = [147, 92, 196, 81, 197];
    let (mut first, mut rest) = header.split_at_mut(1);

    let first = first.as_mut();

    first[0] ^= mask[0] & 0x1f;

    // let pn_buf = rest.slice_last(pn_len)?;
    let len2 = rest.len();
    let mut pn_buf = &mut rest[len2 - 1..];
    for i in 0..pn_len {
        pn_buf[i] ^= mask[i + 1];
    }
}

pub fn encrypt_payload(key: &mut SealingKey<MyNonce>, header: &mut Vec<u8>, payload: &mut Vec<u8>) {
    key.seal_in_place_append_tag(Aad::from(header), payload)
        .unwrap();
}

pub fn encrypt_packet(key: &mut SealingKey<MyNonce>, header: &mut Vec<u8>, payload: &mut Vec<u8>) {
    encrypt_payload(key, header, payload);
    encrypt_hdr(header);
}

// TODO
// pub fn decrypt_hdr() {
// }

pub fn decrypt_payload(key: &mut OpeningKey<MyNonce>, header: &mut Vec<u8>, payload: &mut Vec<u8>) {
    key.open_in_place(Aad::from(header), payload).unwrap();
}

#[cfg(test)]
mod tests {
    use crate::{encrypt_payload, MyNonce};
    use ring::aead::{Aad, BoundKey, OpeningKey, SealingKey, UnboundKey, AES_128_GCM, NONCE_LEN};

    #[test]
    fn test_decrypt_payload() {
        let payload: Vec<u8> = (0..10).map(|_| rand::random::<u8>()).collect();
        let key_bytes = [
            10, 141, 102, 148, 37, 119, 128, 179, 47, 14, 68, 0, 205, 28, 26, 149,
        ];
        let nonce = MyNonce {
            nonce: [0; NONCE_LEN],
        };
        let o_nonce = MyNonce {
            nonce: [0; NONCE_LEN],
        };
        let algorithm = &AES_128_GCM;
        let unbound_key = UnboundKey::new(&algorithm, &key_bytes).unwrap();
        let o_unbound_key = UnboundKey::new(&algorithm, &key_bytes).unwrap();
        let mut key = SealingKey::<MyNonce>::new(unbound_key, nonce);
        let mut o_key = OpeningKey::<MyNonce>::new(o_unbound_key, o_nonce);
        let mut header = vec![
            0x57, 0x25, 0xe7, 0x4f, 0x2d, 0x27, 0x5d, 0x12, 0x8b, 0x37, 0xb0, 0x47, 0x04, 0x16,
            0x08, 0xa1, 0x84, 0x23, 0x65, 0xdb, 0xfa, 0xe7,
        ];
        let mut ciphertext = payload.clone();
        encrypt_payload(&mut key, &mut header, &mut ciphertext);
        assert_ne!(payload, ciphertext[..10]);
        let mut plaintext = ciphertext.clone();
        o_key
            .open_in_place(Aad::from(header), &mut plaintext)
            .unwrap();
        assert_ne!(plaintext, ciphertext[..10]);
        assert_eq!(plaintext[..10], payload);
    }
}
