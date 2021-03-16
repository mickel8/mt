use ring::aead::Aad;
use ring::aead::Nonce;
use ring::aead::NonceSequence;
use ring::aead::SealingKey;
use ring::aead::NONCE_LEN;
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
