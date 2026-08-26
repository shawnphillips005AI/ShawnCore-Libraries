#![no_main]

use libfuzzer_sys::fuzz_target;
use shawncore_pq_crypto::ffi::{
    shawncore_crypto_aead_decrypt, shawncore_crypto_aead_encrypt,
};
use shawncore_pq_crypto::ffi_callbacks::shawncore_crypto_register_cache_flush;
use shawncore_pq_crypto::ffi_error::ShawncoreCryptoErr;

extern "C" fn fuzz_cache_flush(_: *const u8, _: usize) {}

fn install_fuzz_callbacks() {
    unsafe {
        shawncore_crypto_register_cache_flush(fuzz_cache_flush);
    }
}

// The harness supplies valid storage for every pointer. Fuzzed lengths are bounded
// to those allocations; invalid null-pointer cases are tested explicitly below.
fuzz_target!(|input: &[u8]| {
    install_fuzz_callbacks();
    const MAX_DATA: usize = 256;
    const MAX_AAD: usize = 128;

    let mut enc_key = [0u8; 32];
    let mut mac_key = [0u8; 32];
    let mut nonce = [0u8; 12];
    let mut aad = [0u8; MAX_AAD];
    let mut ciphertext = [0u8; MAX_DATA];
    let mut mac = [0u8; 48];
    let mut plaintext = [0u8; MAX_DATA];

    for (index, byte) in input.iter().enumerate() {
        match index % 6 {
            0 => enc_key[index / 6 % enc_key.len()] ^= *byte,
            1 => mac_key[index / 6 % mac_key.len()] ^= *byte,
            2 => nonce[index / 6 % nonce.len()] ^= *byte,
            3 => aad[index / 6 % aad.len()] ^= *byte,
            4 => ciphertext[index / 6 % ciphertext.len()] ^= *byte,
            _ => mac[index / 6 % mac.len()] ^= *byte,
        }
    }

    let data_len = input.first().copied().unwrap_or_default() as usize % (MAX_DATA + 1);
    let aad_len = input.get(1).copied().unwrap_or_default() as usize % (MAX_AAD + 1);
    for (index, byte) in input.iter().skip(2).enumerate() {
        plaintext[index % MAX_DATA] ^= *byte;
        aad[index % MAX_AAD] ^= byte.rotate_left((index % 8) as u32);
    }
    let expected_plaintext = plaintext;

    let encrypt_result = unsafe {
        shawncore_crypto_aead_encrypt(
            enc_key.as_ptr(),
            mac_key.as_ptr(),
            nonce.as_ptr(),
            aad.as_ptr(),
            aad_len,
            plaintext.as_ptr(),
            ciphertext.as_mut_ptr(),
            data_len,
            mac.as_mut_ptr(),
        )
    };
    assert_eq!(encrypt_result, ShawncoreCryptoErr::Success);

    let result = unsafe {
        shawncore_crypto_aead_decrypt(
            enc_key.as_ptr(),
            mac_key.as_ptr(),
            nonce.as_ptr(),
            aad.as_ptr(),
            aad_len,
            ciphertext.as_ptr(),
            mac.as_ptr(),
            plaintext.as_mut_ptr(),
            data_len,
        )
    };
    assert_eq!(result, ShawncoreCryptoErr::Success);
    assert_eq!(&plaintext[..data_len], &expected_plaintext[..data_len]);

    if data_len > 0 {
        ciphertext[0] ^= 1;
        let tampered_result = unsafe {
            shawncore_crypto_aead_decrypt(
                enc_key.as_ptr(),
                mac_key.as_ptr(),
                nonce.as_ptr(),
                aad.as_ptr(),
                aad_len,
                ciphertext.as_ptr(),
                mac.as_ptr(),
                plaintext.as_mut_ptr(),
                data_len,
            )
        };
        assert_eq!(tampered_result, ShawncoreCryptoErr::VerificationFailed);
    }

    let alias_len = if data_len == 0 { 1 } else { data_len };
    let alias_result = unsafe {
        shawncore_crypto_aead_encrypt(
            enc_key.as_ptr(),
            mac_key.as_ptr(),
            nonce.as_ptr(),
            aad.as_ptr(),
            aad_len,
            plaintext.as_ptr(),
            plaintext.as_ptr() as *mut u8,
            alias_len,
            mac.as_mut_ptr(),
        )
    };
    assert_eq!(alias_result, ShawncoreCryptoErr::InvalidLength);

    // Null pointers with non-zero lengths must be rejected before dereference.
    let null_result = unsafe {
        shawncore_crypto_aead_decrypt(
            enc_key.as_ptr(),
            mac_key.as_ptr(),
            nonce.as_ptr(),
            core::ptr::null(),
            1,
            ciphertext.as_ptr(),
            mac.as_ptr(),
            plaintext.as_mut_ptr(),
            data_len,
        )
    };
    assert_eq!(null_result, ShawncoreCryptoErr::InvalidLength);
});
