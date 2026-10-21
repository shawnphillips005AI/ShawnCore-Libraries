// Copyright (c) 2026 Shawn Phillips. All Rights Reserved.
// Dual-licensed under AGPLv3 and Commercial License.

//! Known-answer tests for the classical primitives.
//!
//! Expected values were produced outside this crate: HMAC/HKDF/framing with
//! Python's `hmac`/`hashlib`, ChaCha20 with OpenSSL, and X25519 with an RFC 7748
//! reference ladder. The RFC 4231 case 1 and RFC 7748 section 6.1 values are
//! published vectors. The rest are deterministic vectors, not NIST CAVP/ACVP.

use shawncore_pq_crypto::aead_wrapper::{
    aead_decrypt, aead_decrypt_in_place, aead_encrypt, aead_encrypt_in_place, hkdf_expand_sha384,
    hmac_sha384, AEAD_TAG_SIZE,
};
use shawncore_pq_crypto::ffi_callbacks::shawncore_crypto_register_cache_flush;
use shawncore_pq_crypto::hybrid_kdf::derive_hybrid_key;
use shawncore_pq_crypto::x25519_wrapper::{
    x25519_diffie_hellman, x25519_keygen, X25519Public, X25519Secret,
};

extern "C" fn no_op_cache_flush(_: *const u8, _: usize) {}

// An unregistered cache-flush callback halts by design, so every test registers one.
fn setup() {
    unsafe { shawncore_crypto_register_cache_flush(Some(no_op_cache_flush)) };
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn seq<const N: usize>(start: u8) -> [u8; N] {
    core::array::from_fn(|i| start.wrapping_add(i as u8))
}

#[test]
fn hmac_sha384_rfc4231_case_1() {
    setup();
    let mac = hmac_sha384(&[0x0b; 20], b"Hi There").unwrap();
    assert_eq!(
        mac.as_slice(),
        unhex(
            "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59c\
             faea9ea9076ede7f4af152e8b2fa9cb6"
        )
    );
}

#[test]
fn hmac_sha384_rfc4231_case_2() {
    setup();
    let mac = hmac_sha384(b"Jefe", b"what do ya want for nothing?").unwrap();
    assert_eq!(
        mac.as_slice(),
        unhex(
            "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e\
             8e2240ca5e69e2c78b3239ecfab21649"
        )
    );
}

#[test]
fn hkdf_expand_sha384_vector() {
    setup();
    let prk: [u8; 48] = seq(0x20);
    let mut okm = [0u8; 128];
    hkdf_expand_sha384(&prk, b"shawncore-kat-info", &mut okm).unwrap();
    assert_eq!(
        okm.as_slice(),
        unhex(
            "252452bfd045f913b63b7439dffbc1b3feb434444ad039c230d971fe460572c3\
             bef87da43c786e14c1ff7c97634b56f9d07722221bad46d19d5246072a071cba\
             4a7fdbae36781523730c75b6678ec1cb6a8e6fa6729fdb3e9f1c507e665acb95\
             9e43d4a8398be629cebf549b038be9080211a0c1c3db8ef67264db7e43866370"
        )
    );
}

#[test]
fn hybrid_kdf_vector_and_input_zeroization() {
    setup();
    let mut pq: [u8; 32] = seq(0x00);
    let mut classical: [u8; 32] = seq(0x80);
    let out = derive_hybrid_key(
        &mut pq,
        &mut classical,
        &[0x5a; 32],
        b"shawncore-hybrid-kat",
    )
    .unwrap();
    assert_eq!(
        out.as_slice(),
        unhex(
            "dd1c773e9ce68b64b25b0ef3b9330530c7845486c18b7b5bdac2e40162476369\
             bc9295a6de92f69252f0c84ee48726c5662d1da0a0e706aee355dbc4099063c7\
             243b582deb29aa7045f406bb1009ff41df77fe057e194392275a88321b1f305f\
             99358d503fe2a63861cf42673251842f4fa31a184ddf3775ef982b8dd5712412"
        )
    );
    assert_eq!(pq, [0u8; 32]);
    assert_eq!(classical, [0u8; 32]);
}

const AEAD_PT: &[u8] = b"ShawnCore AEAD known-answer plaintext!";
const AEAD_AAD: &[u8] = b"header-aad";
const AEAD_CT: &str =
    "a4d29693a25891dcc6c5c91bd88e00f43c65a9c914f8144608e0d94e646c10fe37fe9eee02b3";
const AEAD_MAC: &str = "57d7b61d9cb7cb242c7dce55bb2984ee75dd025b9900dca760100dceba156ec9\
                        e36445998dda4bdf5e037ba9f8cd803c";

#[test]
fn aead_vector_both_directions_and_in_place() {
    setup();
    let enc: [u8; 32] = seq(0x00);
    let mac_key: [u8; 32] = seq(0x40);
    let nonce: [u8; 12] = seq(0xa0);

    let mut ct = vec![0u8; AEAD_PT.len()];
    let mut tag = [0u8; AEAD_TAG_SIZE];
    aead_encrypt(&enc, &mac_key, &nonce, AEAD_AAD, AEAD_PT, &mut ct, &mut tag).unwrap();
    assert_eq!(ct, unhex(AEAD_CT));
    assert_eq!(tag.as_slice(), unhex(AEAD_MAC));

    let mut pt = vec![0u8; ct.len()];
    aead_decrypt(&enc, &mac_key, &nonce, AEAD_AAD, &ct, &tag, &mut pt).unwrap();
    assert_eq!(pt, AEAD_PT);

    let mut buf = AEAD_PT.to_vec();
    let mut tag2 = [0u8; AEAD_TAG_SIZE];
    aead_encrypt_in_place(&enc, &mac_key, &nonce, AEAD_AAD, &mut buf, &mut tag2).unwrap();
    assert_eq!(buf, unhex(AEAD_CT));
    assert_eq!(tag2, tag);
    aead_decrypt_in_place(&enc, &mac_key, &nonce, AEAD_AAD, &mut buf, &tag2).unwrap();
    assert_eq!(buf, AEAD_PT);
}

#[test]
fn aead_rejects_every_single_bit_flip_in_tag() {
    setup();
    let enc: [u8; 32] = seq(0x00);
    let mac_key: [u8; 32] = seq(0x40);
    let nonce: [u8; 12] = seq(0xa0);
    let ct = unhex(AEAD_CT);
    let good: [u8; AEAD_TAG_SIZE] = unhex(AEAD_MAC).try_into().unwrap();

    for bit in 0..AEAD_TAG_SIZE * 8 {
        let mut tag = good;
        tag[bit / 8] ^= 1 << (bit % 8);
        let mut pt = vec![0xffu8; ct.len()];
        assert!(aead_decrypt(&enc, &mac_key, &nonce, AEAD_AAD, &ct, &tag, &mut pt).is_err());
        assert!(
            pt.iter().all(|&b| b == 0),
            "plaintext must be wiped on failure"
        );
    }
}

#[test]
fn x25519_rfc7748_section_6_1() {
    setup();
    let a: [u8; 32] = unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        .try_into()
        .unwrap();
    let b: [u8; 32] = unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        .try_into()
        .unwrap();
    let (a_pub, a_sec) = x25519_keygen(&a);
    let (b_pub, b_sec) = x25519_keygen(&b);
    assert_eq!(
        a_pub.0.as_slice(),
        unhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    );
    assert_eq!(
        b_pub.0.as_slice(),
        unhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    );
    let expected = unhex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    assert_eq!(
        x25519_diffie_hellman(&a_sec, &b_pub).unwrap().0.as_slice(),
        expected
    );
    assert_eq!(
        x25519_diffie_hellman(&b_sec, &a_pub).unwrap().0.as_slice(),
        expected
    );
}

#[test]
fn x25519_rejects_zero_and_low_order_points() {
    setup();
    let sk = X25519Secret(seq(0x01));
    assert!(x25519_diffie_hellman(&sk, &X25519Public([0u8; 32])).is_err());

    let mut one = [0u8; 32];
    one[0] = 1;
    assert!(x25519_diffie_hellman(&sk, &X25519Public(one)).is_err());
}
