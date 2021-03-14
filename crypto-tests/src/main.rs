use ring::aead::Aad;
use ring::aead::BoundKey;
use ring::aead::Nonce;
use ring::aead::NonceSequence;
use ring::aead::OpeningKey;
use ring::aead::SealingKey;
use ring::aead::UnboundKey;
use ring::aead::{AES_128_GCM, NONCE_LEN};
use ring::error::Unspecified;

fn main() {
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
    let header = [
        0x57, 0x25, 0xe7, 0x4f, 0x2d, 0x27, 0x5d, 0x12, 0x8b, 0x37, 0xb0, 0x47, 0x04, 0x16, 0x08,
        0xa1, 0x84, 0x23, 0x65, 0xdb, 0xfa, 0xe7,
    ];
    let mut payload = vec![
        0x00, 0x00, 0x03, 0x04, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9b, 0x03, 0x08,
        0x00, 0x45, 0x00, 0x03, 0x2d, 0x15, 0xe2, 0x40, 0x00, 0x40, 0x11, 0x23, 0xda, 0x7f, 0x00,
        0x00, 0x01, 0x7f, 0x00, 0x00, 0x03, 0xeb, 0x90, 0x11, 0x51, 0x03, 0x19, 0x01, 0x2f, 0x57,
        0x25, 0xe7, 0x4f, 0x2d, 0x27, 0x5d, 0x12, 0x8b, 0x37, 0xb0, 0x47, 0x04, 0x16, 0x08, 0xa1,
        0x84, 0x23, 0x65, 0xdb, 0xfa, 0xe7, 0xf7, 0xd2, 0xdb, 0x52, 0x91, 0x32, 0xd5, 0x84, 0xc6,
        0xdc, 0x2a, 0xf3, 0x28, 0x53, 0x68, 0xa1, 0xf2, 0xf3, 0xab, 0x7f, 0xc0, 0x0d, 0x41, 0x2a,
        0x97, 0xf6, 0x64, 0x05, 0x83, 0xe4, 0x9f, 0x78, 0xcb, 0x1b, 0x71, 0x58, 0x07, 0x7c, 0x09,
        0xc6, 0xc4, 0x4d, 0x03, 0x83, 0x37, 0x84, 0x26, 0x5f, 0x2d, 0x38, 0x5a, 0xda, 0x3f, 0x15,
        0xe8, 0x2f, 0x40, 0xca, 0xa7, 0xe5, 0x9b, 0xae, 0x18, 0x85, 0x1b, 0xa4, 0xa0, 0xcd, 0xa5,
        0xb6, 0xfd, 0x8f, 0x6c, 0x53, 0x64, 0x85, 0x56, 0xb2, 0xf7, 0x37, 0xf9, 0xce, 0xb4, 0x4f,
        0x0b, 0x94, 0x66, 0x88, 0x09, 0xe9, 0x73, 0x1d, 0x3a, 0xf4, 0xfd, 0x9a, 0x14, 0xe7, 0xeb,
        0x1b, 0xce, 0xe1, 0x6d, 0xba, 0x48, 0x9f, 0x82, 0x2b, 0x9e, 0xde, 0xb5, 0x77, 0xad, 0x98,
        0xe5, 0x2e, 0x4f, 0xb3, 0xcf, 0x16, 0x1e, 0x45, 0x98, 0x91, 0xaa, 0xec, 0x7f, 0xf2, 0x51,
        0x80, 0x55, 0xc7, 0xa5, 0xd8, 0x39, 0xde, 0x85, 0xbc, 0xa2, 0x78, 0x9b, 0x1d, 0xcb, 0xd1,
        0xea, 0x3f, 0x24, 0x2e, 0x40, 0xe3, 0x28, 0xdb, 0xb3, 0x2d, 0xe9, 0x14, 0xde, 0x8c, 0x4f,
        0x4b, 0x82, 0x90, 0x12, 0xea, 0xa5, 0xa1, 0x63, 0x2e, 0xe9, 0x03, 0x30, 0xfd, 0x91, 0x41,
        0x3e, 0x41, 0xb9, 0x7f, 0x00, 0x4b, 0x7d, 0x79, 0xec, 0x4e, 0x4a, 0xa5, 0x22, 0x5b, 0x23,
        0x84, 0xa0, 0xf4, 0x7e, 0x6f, 0x06, 0xd2, 0x9e, 0x23, 0x38, 0x00, 0x2e, 0xc6, 0x26, 0x38,
        0x38, 0xfd, 0xd8, 0x90, 0xd8, 0xcb, 0x21, 0xff, 0x2f, 0x6b, 0xd8, 0xb6, 0x67, 0x06, 0xa9,
        0x47, 0x7f, 0xee, 0x94, 0x4e, 0x6b, 0x75, 0x45, 0x45, 0x9b, 0x51, 0x4c, 0x06, 0xd9, 0xe1,
        0x00, 0xa0, 0xb8, 0xed, 0xd9, 0x9d, 0x1c, 0xa5, 0x88, 0xfa, 0x7a, 0x3f, 0x94, 0x69, 0xcd,
        0xc0, 0xa2, 0x93, 0x48, 0x98, 0xa5, 0x33, 0x61, 0xba, 0xec, 0x61, 0xc5, 0x36, 0x30, 0x92,
        0xa2, 0xc1, 0x6d, 0x2b, 0xb2, 0xde, 0x3e, 0xa3, 0xce, 0x5d, 0xf7, 0xcd, 0x8d, 0xc8, 0x8e,
        0x6b, 0x31, 0xa2, 0xe0, 0x26, 0x18, 0x9d, 0x82, 0x2d, 0x43, 0xc3, 0x85, 0x8d, 0xc8, 0x3e,
        0x9b, 0x9f, 0xd1, 0x31, 0xe3, 0x68, 0x62, 0x42, 0xbd, 0xfd, 0x19, 0xfd, 0x90, 0x36, 0xb2,
        0xb3, 0xbb, 0x4b, 0x38, 0x33, 0x84, 0x51, 0x8a, 0x4c, 0xf4, 0x87, 0x75, 0x22, 0xf8, 0xa1,
        0x2a, 0xab, 0x73, 0x37, 0xe5, 0x88, 0xd0, 0x08, 0x1c, 0xfb, 0x14, 0x5b, 0xe7, 0xfb, 0xd4,
        0x6f, 0x0a, 0xa4, 0xb2, 0x4c, 0x50, 0x8d, 0x55, 0x0e, 0x92, 0x38, 0x29, 0xb1, 0x45, 0xb8,
        0x88, 0x26, 0xe7, 0x90, 0xe9, 0x5f, 0x9d, 0x7c, 0xe8, 0xd0, 0xed, 0x80, 0xcf, 0x31, 0xb4,
        0xa1, 0x92, 0x59, 0x9f, 0x7b, 0xd0, 0xde, 0x4c, 0xe5, 0x6a, 0xf3, 0xf7, 0x55, 0xa8, 0x31,
        0xae, 0x27, 0x0c, 0xe2, 0x75, 0xd3, 0x0f, 0x64, 0x5d, 0xa8, 0xbb, 0x0b, 0x2c, 0xb5, 0xa0,
        0xb8, 0x21, 0x5f, 0xc3, 0x9d, 0xf0, 0x29, 0x3a, 0x18, 0xca, 0x2f, 0x9b, 0x6f, 0xca, 0x01,
        0x8d, 0xe5, 0x16, 0x50, 0x16, 0xa3, 0x72, 0x6a, 0xa5, 0x19, 0xf4, 0xb0, 0xb3, 0xd5, 0x8f,
        0xe6, 0x02, 0x3a, 0x2a, 0xfd, 0x37, 0x5a, 0x1c, 0x60, 0xcf, 0xec, 0xa6, 0x87, 0xeb, 0x63,
        0xaf, 0xcb, 0xba, 0xed, 0x91, 0x78, 0x71, 0x14, 0x2e, 0x47, 0xa2, 0x65, 0xab, 0x33, 0x91,
        0x05, 0xa3, 0x1d, 0x7a, 0x91, 0x9a, 0x60, 0xb2, 0x39, 0x67, 0x7d, 0x87, 0x63, 0x56, 0x01,
        0x62, 0x4a, 0x1c, 0xe8, 0xe0, 0x55, 0x8f, 0x13, 0xa5, 0x23, 0x2d, 0x70, 0x03, 0x21, 0xfb,
        0xb5, 0x1b, 0x4a, 0x11, 0x27, 0x39, 0x49, 0x5e, 0xf3, 0x9b, 0x3b, 0x54, 0xbb, 0x62, 0xbc,
        0x59, 0xfc, 0x66, 0x0a, 0xd0, 0xc3, 0xc3, 0x63, 0xf1, 0x2e, 0xf7, 0x2c, 0x53, 0x23, 0x05,
        0x50, 0x44, 0x1b, 0xf9, 0x00, 0xfc, 0x4d, 0x53, 0xa6, 0x1e, 0xf2, 0x24, 0x55, 0xfc, 0x19,
        0x43, 0x1f, 0xdb, 0x22, 0x25, 0xf6, 0xf1, 0xcd, 0x31, 0x34, 0x4a, 0xdd, 0x34, 0xb1, 0xff,
        0x44, 0xcf, 0xec, 0xb1, 0x78, 0xec, 0x7a, 0xf5, 0x7f, 0x1f, 0x84, 0xb1, 0x03, 0x64, 0x84,
        0x18, 0x21, 0x05, 0x4d, 0x74, 0x75, 0xae, 0xc4, 0x69, 0xdd, 0x11, 0xa4, 0x83, 0x72, 0x89,
        0x04, 0x21, 0xbb, 0x7d, 0x02, 0xd3, 0x11, 0x0e, 0x79, 0xa1, 0x94, 0x05, 0x16, 0xb4, 0xeb,
        0xbd, 0x1d, 0xdf, 0x56, 0xd7, 0x3b, 0x58, 0x50, 0x3e, 0x43, 0x32, 0x96, 0x1b, 0x5c, 0xfc,
        0x78, 0x40, 0x0f, 0x29, 0x3c, 0x69, 0x0c, 0x6b, 0xa4, 0x71, 0x7e, 0xa8, 0x04, 0x08, 0x9b,
        0x00, 0x3a, 0x2d, 0x03, 0xb9, 0x61, 0xe2, 0x4c, 0xb0, 0x49, 0x04, 0xd7, 0x61, 0x89, 0xd2,
        0x93, 0x2a, 0xea, 0x90, 0x13, 0xc6, 0xe2, 0xdf, 0xcc, 0x36, 0x8b, 0x5f, 0xd0, 0xe5, 0xeb,
        0x01, 0x7f, 0x05, 0xe2, 0xf9, 0x3c, 0x8b, 0x74, 0x7b, 0x81, 0xd7, 0xe4, 0xce, 0x4e, 0xa0,
        0x7d, 0xcb, 0xac, 0x98, 0x60, 0x31, 0xe7, 0x50, 0x57, 0x7a, 0xc5, 0xcb, 0x03, 0x41, 0xc7,
        0xd7, 0xc4, 0x36, 0x65, 0x97, 0x23, 0x4f, 0xa5, 0xed, 0x7c, 0xbf, 0x67, 0x74, 0x5b, 0x10,
        0xdf, 0x2a, 0x59, 0xd3, 0x6e, 0x90, 0x94, 0xb0, 0x92, 0x29, 0x71, 0xdf, 0xc3, 0x33, 0xf6,
        0x4d, 0xe0, 0x9d, 0x2b, 0xef, 0xca, 0xf3, 0xf3, 0x68, 0xb7, 0xf9, 0xfc, 0xe1, 0x05, 0xe5,
        0x1e, 0xdb, 0xf0, 0xf9, 0x7e, 0x8c, 0x7c, 0xe2, 0x50, 0x83, 0xa9, 0x57, 0xcf, 0x54, 0x28,
        0x2c, 0xbb, 0x13, 0x96, 0x66, 0x41, 0xaf, 0x00, 0x70, 0xab, 0xae, 0xd5, 0xbf, 0x2f, 0x5d,
        0xe5, 0xa3, 0x50, 0x25,
    ];

    println!("encrypting payload of len: {}", payload.len());
    key.seal_in_place_append_tag(Aad::from(header), &mut payload).unwrap();
    println!("ciphertext len: {}", payload.len());
    o_key.open_in_place(Aad::from(header), &mut payload).unwrap();
}

struct MyNonce {
    nonce: [u8; NONCE_LEN],
}

impl NonceSequence for MyNonce {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        Ok(Nonce::assume_unique_for_key(self.nonce))
    }
}