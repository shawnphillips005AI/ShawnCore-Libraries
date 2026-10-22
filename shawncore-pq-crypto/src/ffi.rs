// Copyright (c) 2026 Shawn Phillips. All Rights Reserved.
// Dual-licensed under AGPLv3 and Commercial License.

#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! Foreign Function Interface (FFI) for the Cryptographic Stack.
//!
//! Defines opaque C-callable boundaries for the target host OS. The host must uphold each
//! exported function's documented pointer, lifetime, alignment, ownership, and concurrency
//! preconditions.
//!
//! Session objects are not internally serialized. The host must provide exclusive ownership
//! while invoking operations that mutate a `SessionManager`, including handshake state,
//! replay counters, packet encryption/decryption state, and explicit zeroization.
//!
//! # What is checked and what is not
//! Before any slice is formed or any cryptography runs, every pointer-plus-length pair is
//! checked for a null pointer with a nonzero length, a length above `isize::MAX` (the largest
//! valid Rust slice), a range that wraps the address space, and, per function, a protocol limit
//! (packet data: the ChaCha20 limit; `app_info`: `u32::MAX`). Overlap of ranges where one is
//! written is checked with checked arithmetic, and zero-length ranges never overlap. Whether a
//! non-null address is mapped, live and initialized cannot be determined from the pointer and
//! remains the caller's guarantee. The same rules are written for C callers in `shawncore.h`.

use crate::aead_wrapper::{aead_decrypt, aead_encrypt, hkdf_expand_sha384, hmac_sha384};
use crate::entropy_pool::{GLOBAL_ENTROPY_POOL, GLOBAL_ENTROPY_QUEUE};
use crate::error::CryptoError;
use crate::ffi_error::ShawncoreCryptoErr;
#[cfg(feature = "ml-dsa")]
use crate::ml_dsa_wrapper::{
    ml_dsa_keygen, ml_dsa_sign, ml_dsa_verify, PublicKey87, Signature87, SigningKey87,
    ML_DSA_PUBLICKEY_BYTES, ML_DSA_SIGNATURE_BYTES,
};
use crate::ml_kem_wrapper::{
    ml_kem_decapsulate, ml_kem_encapsulate, ml_kem_keygen, Ciphertext1024, DecapsKey1024,
    PublicKey1024, SharedKey1024, ML_KEM_CIPHERTEXT_BYTES, ML_KEM_PUBLICKEY_BYTES,
};
use crate::session_manager::SessionManager;
use crate::x25519_wrapper::{
    x25519_diffie_hellman, x25519_keygen, X25519Public, X25519Secret, X25519SharedSecret,
    X25519_PUBLICKEY_BYTES,
};

macro_rules! opaque_type_layout {
    ($type:ty, $sizeof:ident, $alignof:ident) => {
        #[doc = concat!("Returns the memory size required to allocate a `", stringify!($type), "`.")]
        #[no_mangle]
        pub extern "C" fn $sizeof() -> usize {
            core::mem::size_of::<$type>()
        }

        #[doc = concat!("Returns the memory alignment required to allocate a `", stringify!($type), "`.")]
        #[no_mangle]
        pub extern "C" fn $alignof() -> usize {
            core::mem::align_of::<$type>()
        }
    };
}

opaque_type_layout!(
    PublicKey1024,
    shawncore_crypto_ml_kem_publickey_sizeof,
    shawncore_crypto_ml_kem_publickey_alignof
);
opaque_type_layout!(
    DecapsKey1024,
    shawncore_crypto_ml_kem_decapskey_sizeof,
    shawncore_crypto_ml_kem_decapskey_alignof
);
opaque_type_layout!(
    SharedKey1024,
    shawncore_crypto_ml_kem_sharedkey_sizeof,
    shawncore_crypto_ml_kem_sharedkey_alignof
);
opaque_type_layout!(
    Ciphertext1024,
    shawncore_crypto_ml_kem_ciphertext_sizeof,
    shawncore_crypto_ml_kem_ciphertext_alignof
);
#[cfg(feature = "ml-dsa")]
opaque_type_layout!(
    PublicKey87,
    shawncore_crypto_ml_dsa_publickey_sizeof,
    shawncore_crypto_ml_dsa_publickey_alignof
);
#[cfg(feature = "ml-dsa")]
opaque_type_layout!(
    SigningKey87,
    shawncore_crypto_ml_dsa_signingkey_sizeof,
    shawncore_crypto_ml_dsa_signingkey_alignof
);
#[cfg(feature = "ml-dsa")]
opaque_type_layout!(
    Signature87,
    shawncore_crypto_ml_dsa_signature_sizeof,
    shawncore_crypto_ml_dsa_signature_alignof
);
opaque_type_layout!(
    X25519Public,
    shawncore_crypto_x25519_publickey_sizeof,
    shawncore_crypto_x25519_publickey_alignof
);
opaque_type_layout!(
    X25519Secret,
    shawncore_crypto_x25519_secret_sizeof,
    shawncore_crypto_x25519_secret_alignof
);
opaque_type_layout!(
    X25519SharedSecret,
    shawncore_crypto_x25519_sharedsecret_sizeof,
    shawncore_crypto_x25519_sharedsecret_alignof
);

// ============================================================================
// Session Manager FFI
// ============================================================================

/// Returns the memory size required to allocate a `SessionManager`.
///
/// # Safety
/// This function has no pointer safety requirements.
#[no_mangle]
pub unsafe extern "C" fn shawncore_crypto_session_manager_sizeof() -> usize {
    core::mem::size_of::<SessionManager>()
}

/// Returns the memory alignment required to allocate a `SessionManager`.
///
/// # Safety
/// This function has no pointer safety requirements.
#[no_mangle]
pub unsafe extern "C" fn shawncore_crypto_session_manager_alignof() -> usize {
    core::mem::align_of::<SessionManager>()
}

/// Initializes a host-allocated `SessionManager`.
///
/// # Safety
/// `manager` must point to a valid, properly aligned, UNINITIALIZED memory region of at least
/// `shawncore_crypto_session_manager_sizeof()` bytes.
#[no_mangle]
pub unsafe extern "C" fn shawncore_crypto_session_manager_init(
    manager: *mut SessionManager,
) -> ShawncoreCryptoErr {
    if manager.is_null() {
        return ShawncoreCryptoErr::InvalidState;
    }
    if !ptr_is_aligned(manager) {
        return ShawncoreCryptoErr::InvalidState;
    }

    unsafe {
        core::ptr::write(manager, SessionManager::new());
    }

    ShawncoreCryptoErr::Success
}

/// Destroys a `SessionManager`, securely zeroizing its contents.
///
/// # Safety
/// `manager` must point to a valid, initialized `SessionManager`.
#[no_mangle]
pub unsafe extern "C" fn shawncore_crypto_session_manager_destroy(
    manager: *mut SessionManager,
) -> ShawncoreCryptoErr {
    if manager.is_null() {
        return ShawncoreCryptoErr::InvalidState;
    }
    if !ptr_is_aligned(manager) {
        return ShawncoreCryptoErr::InvalidState;
    }

    unsafe {
        core::ptr::drop_in_place(manager);
    }

    ShawncoreCryptoErr::Success
}

/// Initiates a hybrid handshake, generating ML-KEM and X25519 keypairs.
///
/// # Safety
/// All pointers must be valid and non-null. `entropy` must point to exactly 96 bytes.
/// Output regions must be distinct and must not overlap `manager` or `entropy`.
#[no_mangle]
/// **Concurrency contract:** one initialized `SessionManager` requires exclusive access while state-mutating work is in progress. The C ABI does not serialize concurrent callers; the host RTOS must provide the required mutex, critical section, or task ownership.
///
/// In particular, callers must not concurrently invoke handshake, encrypt/decrypt, or zeroize operations on the same manager.
///
pub unsafe extern "C" fn shawncore_crypto_session_manager_initiate_handshake(
    manager: *mut SessionManager,
    entropy: *const u8,
    out_ml_kem_pk: *mut PublicKey1024,
    out_x25519_pk: *mut X25519Public,
) -> ShawncoreCryptoErr {
    if manager.is_null() || entropy.is_null() || out_ml_kem_pk.is_null() || out_x25519_pk.is_null()
    {
        return ShawncoreCryptoErr::InvalidState;
    }
    if !ptr_is_aligned(manager) || !ptr_is_aligned(out_ml_kem_pk) || !ptr_is_aligned(out_x25519_pk)
    {
        return ShawncoreCryptoErr::InvalidState;
    }
    if ranges_overlap(
        out_ml_kem_pk,
        core::mem::size_of::<PublicKey1024>(),
        out_x25519_pk,
        core::mem::size_of::<X25519Public>(),
    ) || ranges_overlap(
        manager,
        core::mem::size_of::<SessionManager>(),
        out_ml_kem_pk,
        core::mem::size_of::<PublicKey1024>(),
    ) || ranges_overlap(
        manager,
        core::mem::size_of::<SessionManager>(),
        out_x25519_pk,
        core::mem::size_of::<X25519Public>(),
    ) || ranges_overlap(manager, core::mem::size_of::<SessionManager>(), entropy, 96)
        || ranges_overlap(
            entropy,
            96,
            out_ml_kem_pk,
            core::mem::size_of::<PublicKey1024>(),
        )
        || ranges_overlap(
            entropy,
            96,
            out_x25519_pk,
            core::mem::size_of::<X25519Public>(),
        )
    {
        return ShawncoreCryptoErr::InvalidLength;
    }

    let entropy_ref = unsafe { &*(entropy as *const [u8; 96]) };
    let manager_ref = unsafe { &mut *manager };

    match manager_ref.initiate_handshake(entropy_ref) {
        Ok((ml_kem_pk, x25519_pk)) => {
            unsafe {
                core::ptr::write(out_ml_kem_pk, ml_kem_pk);
                core::ptr::write(out_x25519_pk, x25519_pk);
            }
            ShawncoreCryptoErr::Success
        }
        Err(e) => e.into(),
    }
}

/// Finalizes a hybrid handshake using the peer's public keys and ciphertext.
///
/// # Safety
/// All pointers must be valid and non-null. `salt` and `info` must be valid for their respective lengths.
#[no_mangle]
/// **Concurrency contract:** one initialized `SessionManager` requires exclusive access while state-mutating work is in progress. The C ABI does not serialize concurrent callers; the host RTOS must provide the required mutex, critical section, or task ownership.
///
/// In particular, callers must not concurrently invoke handshake, encrypt/decrypt, or zeroize operations on the same manager.
///
pub unsafe extern "C" fn shawncore_crypto_session_manager_finalize_handshake(
    manager: *mut SessionManager,
    peer_x25519_pk: *const X25519Public,
    ml_kem_ct: *const Ciphertext1024,
    salt: *const u8,
    salt_len: usize,
    info: *const u8,
    info_len: usize,
) -> ShawncoreCryptoErr {
    if manager.is_null() || peer_x25519_pk.is_null() || ml_kem_ct.is_null() {
        return ShawncoreCryptoErr::InvalidState;
    }
    if !ptr_is_aligned(manager) || !ptr_is_aligned(peer_x25519_pk) || !ptr_is_aligned(ml_kem_ct) {
        return ShawncoreCryptoErr::InvalidState;
    }
    if (salt.is_null() && salt_len > 0)
        || (info.is_null() && info_len > 0)
        || !range_ok(salt, salt_len)
        || !range_ok(info, info_len)
    {
        return ShawncoreCryptoErr::InvalidLength;
    }
    if ranges_overlap(
        manager,
        core::mem::size_of::<SessionManager>(),
        peer_x25519_pk,
        core::mem::size_of::<X25519Public>(),
    ) || ranges_overlap(
        manager,
        core::mem::size_of::<SessionManager>(),
        ml_kem_ct,
        core::mem::size_of::<Ciphertext1024>(),
    ) || ranges_overlap(
        manager,
        core::mem::size_of::<SessionManager>(),
        salt,
        salt_len,
    ) || ranges_overlap(
        manager,
        core::mem::size_of::<SessionManager>(),
        info,
        info_len,
    ) {
        return ShawncoreCryptoErr::InvalidLength;
    }

    let manager_ref = unsafe { &mut *manager };
    let peer_x25519_pk_ref = unsafe { &*peer_x25519_pk };
    let ml_kem_ct_ref = unsafe { &*ml_kem_ct };

    let salt_slice = if salt_len > 0 {
        unsafe { core::slice::from_raw_parts(salt, salt_len) }
    } else {
        &[]
    };
    let info_slice = if info_len > 0 {
        unsafe { core::slice::from_raw_parts(info, info_len) }
    } else {
        &[]
    };

    match manager_ref.finalize_handshake(peer_x25519_pk_ref, ml_kem_ct_ref, salt_slice, info_slice)
    {
        Ok(_) => ShawncoreCryptoErr::Success,
        Err(e) => e.into(),
    }
}

/// Encapsulates a shared secret for a peer, generating the ciphertext and our X25519 public key.
///
/// # Safety
/// All pointers must be valid and non-null. `entropy` must point to exactly 64 bytes.
/// Output regions must be distinct and must not overlap any input object.
#[no_mangle]
/// **Concurrency contract:** one initialized `SessionManager` requires exclusive access while state-mutating work is in progress. The C ABI does not serialize concurrent callers; the host RTOS must provide the required mutex, critical section, or task ownership.
///
/// In particular, callers must not concurrently invoke handshake, encrypt/decrypt, or zeroize operations on the same manager.
///
pub unsafe extern "C" fn shawncore_crypto_session_manager_encapsulate_for_peer(
    manager: *mut SessionManager,
    peer_ml_kem_pk: *const PublicKey1024,
    peer_x25519_pk: *const X25519Public,
    entropy: *const u8,
    salt: *const u8,
    salt_len: usize,
    info: *const u8,
    info_len: usize,
    out_ct: *mut Ciphertext1024,
    out_my_x25519_pk: *mut X25519Public,
) -> ShawncoreCryptoErr {
    if manager.is_null()
        || peer_ml_kem_pk.is_null()
        || peer_x25519_pk.is_null()
        || entropy.is_null()
        || out_ct.is_null()
        || out_my_x25519_pk.is_null()
    {
        return ShawncoreCryptoErr::InvalidState;
    }
    if !ptr_is_aligned(manager)
        || !ptr_is_aligned(peer_ml_kem_pk)
        || !ptr_is_aligned(peer_x25519_pk)
        || !ptr_is_aligned(out_ct)
        || !ptr_is_aligned(out_my_x25519_pk)
    {
        return ShawncoreCryptoErr::InvalidState;
    }
    if (salt.is_null() && salt_len > 0)
        || (info.is_null() && info_len > 0)
        || !range_ok(salt, salt_len)
        || !range_ok(info, info_len)
    {
        return ShawncoreCryptoErr::InvalidLength;
    }
    if ranges_overlap(
        out_ct,
        core::mem::size_of::<Ciphertext1024>(),
        out_my_x25519_pk,
        core::mem::size_of::<X25519Public>(),
    ) || ranges_overlap(
        out_ct,
        core::mem::size_of::<Ciphertext1024>(),
        peer_ml_kem_pk,
        core::mem::size_of::<PublicKey1024>(),
    ) || ranges_overlap(
        out_ct,
        core::mem::size_of::<Ciphertext1024>(),
        peer_x25519_pk,
        core::mem::size_of::<X25519Public>(),
    ) || ranges_overlap(
        out_ct,
        core::mem::size_of::<Ciphertext1024>(),
        manager,
        core::mem::size_of::<SessionManager>(),
    ) || ranges_overlap(out_ct, core::mem::size_of::<Ciphertext1024>(), entropy, 64)
        || ranges_overlap(
            out_ct,
            core::mem::size_of::<Ciphertext1024>(),
            salt,
            salt_len,
        )
        || ranges_overlap(
            out_ct,
            core::mem::size_of::<Ciphertext1024>(),
            info,
            info_len,
        )
        || ranges_overlap(
            out_my_x25519_pk,
            core::mem::size_of::<X25519Public>(),
            peer_ml_kem_pk,
            core::mem::size_of::<PublicKey1024>(),
        )
        || ranges_overlap(
            out_my_x25519_pk,
            core::mem::size_of::<X25519Public>(),
            peer_x25519_pk,
            core::mem::size_of::<X25519Public>(),
        )
        || ranges_overlap(
            out_my_x25519_pk,
            core::mem::size_of::<X25519Public>(),
            manager,
            core::mem::size_of::<SessionManager>(),
        )
        || ranges_overlap(
            out_my_x25519_pk,
            core::mem::size_of::<X25519Public>(),
            entropy,
            64,
        )
        || ranges_overlap(
            out_my_x25519_pk,
            core::mem::size_of::<X25519Public>(),
            salt,
            salt_len,
        )
        || ranges_overlap(
            out_my_x25519_pk,
            core::mem::size_of::<X25519Public>(),
            info,
            info_len,
        )
        || ranges_overlap(
            manager,
            core::mem::size_of::<SessionManager>(),
            peer_ml_kem_pk,
            core::mem::size_of::<PublicKey1024>(),
        )
        || ranges_overlap(
            manager,
            core::mem::size_of::<SessionManager>(),
            peer_x25519_pk,
            core::mem::size_of::<X25519Public>(),
        )
        || ranges_overlap(manager, core::mem::size_of::<SessionManager>(), entropy, 64)
        || ranges_overlap(
            manager,
            core::mem::size_of::<SessionManager>(),
            salt,
            salt_len,
        )
        || ranges_overlap(
            manager,
            core::mem::size_of::<SessionManager>(),
            info,
            info_len,
        )
    {
        return ShawncoreCryptoErr::InvalidLength;
    }

    let manager_ref = unsafe { &mut *manager };
    let peer_ml_kem_pk_ref = unsafe { &*peer_ml_kem_pk };
    let peer_x25519_pk_ref = unsafe { &*peer_x25519_pk };
    let entropy_ref = unsafe { &*(entropy as *const [u8; 64]) };

    let salt_slice = if salt_len > 0 {
        unsafe { core::slice::from_raw_parts(salt, salt_len) }
    } else {
        &[]
    };
    let info_slice = if info_len > 0 {
        unsafe { core::slice::from_raw_parts(info, info_len) }
    } else {
        &[]
    };

    // Outputs may be uninitialized host storage: write them only on success, never borrow them.
    let mut ct = Ciphertext1024([0; 1568]);
    let mut my_pk = X25519Public([0; 32]);
    match manager_ref.encapsulate_for_peer(
        peer_ml_kem_pk_ref,
        peer_x25519_pk_ref,
        entropy_ref,
        salt_slice,
        info_slice,
        &mut ct,
        &mut my_pk,
    ) {
        Ok(()) => {
            unsafe {
                core::ptr::write(out_ct, ct);
                core::ptr::write(out_my_x25519_pk, my_pk);
            }
            ShawncoreCryptoErr::Success
        }
        Err(e) => e.into(),
    }
}

/// Whether any two regions overlap where at least one of the pair is writable.
/// Each region is `(address, length, writable)`; zero-length regions never overlap.
#[cfg(feature = "ml-dsa")]
fn writable_regions_overlap(regions: &[(usize, usize, bool)]) -> bool {
    for (index, &(first, first_len, first_mut)) in regions.iter().enumerate() {
        for &(second, second_len, second_mut) in &regions[index + 1..] {
            if (first_mut || second_mut)
                && first_len > 0
                && second_len > 0
                && ranges_overlap(
                    first as *const u8,
                    first_len,
                    second as *const u8,
                    second_len,
                )
            {
                return true;
            }
        }
    }
    false
}

/// Encapsulating side of the authenticated handshake, protocol version 2: derives the session
/// keys and a separate confirmation key, produces a signature and a key-confirmation tag, and
/// leaves the session **unconfirmed** (it refuses all traffic) until
/// `shawncore_crypto_session_manager_confirm_peer_v2` succeeds.
///
/// `peer_verifying_key` is the trust anchor for the key-generating side and must be provisioned
/// out of band. `app_info` is bound into the transcript; `salt` is not (it may be secret) and a
/// salt that differs from the peer's is caught by key confirmation. Outputs are written only on
/// success.
///
/// # Safety
/// All pointers except `salt`/`app_info` (null only with length zero) must be valid, non-null and
/// aligned; `entropy` must point to exactly 64 bytes and `out_confirmation` to 48. Outputs must be
/// **UNINITIALIZED** storage and must not overlap each other, `manager` or any input.
#[no_mangle]
#[cfg(feature = "ml-dsa")]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn shawncore_crypto_session_manager_encapsulate_authenticated_v2(
    manager: *mut SessionManager,
    own_signing_key: *const SigningKey87,
    peer_verifying_key: *const PublicKey87,
    peer_ml_kem_pk: *const PublicKey1024,
    peer_x25519_pk: *const X25519Public,
    entropy: *const u8,
    salt: *const u8,
    salt_len: usize,
    app_info: *const u8,
    app_info_len: usize,
    out_ct: *mut Ciphertext1024,
    out_my_x25519_pk: *mut X25519Public,
    out_signature: *mut Signature87,
    out_confirmation: *mut u8,
) -> ShawncoreCryptoErr {
    if manager.is_null()
        || own_signing_key.is_null()
        || peer_verifying_key.is_null()
        || peer_ml_kem_pk.is_null()
        || peer_x25519_pk.is_null()
        || entropy.is_null()
        || out_ct.is_null()
        || out_my_x25519_pk.is_null()
        || out_signature.is_null()
        || out_confirmation.is_null()
    {
        return ShawncoreCryptoErr::InvalidState;
    }
    if !ptr_is_aligned(manager)
        || !ptr_is_aligned(own_signing_key)
        || !ptr_is_aligned(peer_verifying_key)
        || !ptr_is_aligned(peer_ml_kem_pk)
        || !ptr_is_aligned(peer_x25519_pk)
        || !ptr_is_aligned(out_ct)
        || !ptr_is_aligned(out_my_x25519_pk)
        || !ptr_is_aligned(out_signature)
    {
        return ShawncoreCryptoErr::InvalidState;
    }
    if (salt.is_null() && salt_len > 0)
        || (app_info.is_null() && app_info_len > 0)
        || !range_ok(salt, salt_len)
        || app_info_len > MAX_APP_INFO_LEN
        || !range_ok(app_info, app_info_len)
    {
        return ShawncoreCryptoErr::InvalidLength;
    }
    if writable_regions_overlap(&[
        (
            manager as usize,
            core::mem::size_of::<SessionManager>(),
            true,
        ),
        (
            own_signing_key as usize,
            core::mem::size_of::<SigningKey87>(),
            false,
        ),
        (
            peer_verifying_key as usize,
            core::mem::size_of::<PublicKey87>(),
            false,
        ),
        (
            peer_ml_kem_pk as usize,
            core::mem::size_of::<PublicKey1024>(),
            false,
        ),
        (
            peer_x25519_pk as usize,
            core::mem::size_of::<X25519Public>(),
            false,
        ),
        (entropy as usize, 64, false),
        (salt as usize, salt_len, false),
        (app_info as usize, app_info_len, false),
        (
            out_ct as usize,
            core::mem::size_of::<Ciphertext1024>(),
            true,
        ),
        (
            out_my_x25519_pk as usize,
            core::mem::size_of::<X25519Public>(),
            true,
        ),
        (
            out_signature as usize,
            core::mem::size_of::<Signature87>(),
            true,
        ),
        (out_confirmation as usize, 48, true),
    ]) {
        return ShawncoreCryptoErr::InvalidLength;
    }

    let manager_ref = unsafe { &mut *manager };
    let entropy_ref = unsafe { &*(entropy as *const [u8; 64]) };
    let salt_slice = if salt_len > 0 {
        unsafe { core::slice::from_raw_parts(salt, salt_len) }
    } else {
        &[]
    };
    let app_info_slice = if app_info_len > 0 {
        unsafe { core::slice::from_raw_parts(app_info, app_info_len) }
    } else {
        &[]
    };

    let mut ct = Ciphertext1024([0; 1568]);
    let mut my_pk = X25519Public([0; 32]);
    let mut signature = Signature87([0; 4627]);
    let mut confirmation = [0u8; 48];
    match manager_ref.encapsulate_authenticated(
        unsafe { &*own_signing_key },
        unsafe { &*peer_verifying_key },
        unsafe { &*peer_ml_kem_pk },
        unsafe { &*peer_x25519_pk },
        entropy_ref,
        salt_slice,
        app_info_slice,
        &mut ct,
        &mut my_pk,
        &mut signature,
        &mut confirmation,
    ) {
        Ok(()) => {
            unsafe {
                core::ptr::write(out_ct, ct);
                core::ptr::write(out_my_x25519_pk, my_pk);
                core::ptr::write(out_signature, signature);
                core::ptr::write(out_confirmation.cast::<[u8; 48]>(), confirmation);
            }
            ShawncoreCryptoErr::Success
        }
        Err(e) => e.into(),
    }
}

/// Key-generating side of the authenticated handshake, protocol version 2. Verifies the peer's
/// signature (which covers the transcript and the peer's confirmation tag) before deriving
/// anything; a forged response returns `VerificationFailed` and leaves the pending handshake
/// intact. It then derives the keys and verifies the peer's confirmation tag; a mismatch returns
/// `KeyConfirmationFailed` and consumes the pending handshake. Only a fully verified exchange
/// installs the keys and writes `out_signature` and `out_confirmation`, which must be sent to the
/// peer for `..._confirm_peer_v2`.
///
/// # Safety
/// As for `shawncore_crypto_session_manager_encapsulate_authenticated_v2`; `peer_confirmation` and
/// `out_confirmation` point to 48 bytes, and the outputs must be **UNINITIALIZED** storage that is
/// written only on success.
#[no_mangle]
#[cfg(feature = "ml-dsa")]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn shawncore_crypto_session_manager_finalize_authenticated_v2(
    manager: *mut SessionManager,
    own_signing_key: *const SigningKey87,
    peer_verifying_key: *const PublicKey87,
    peer_x25519_pk: *const X25519Public,
    ml_kem_ct: *const Ciphertext1024,
    peer_signature: *const Signature87,
    peer_confirmation: *const u8,
    salt: *const u8,
    salt_len: usize,
    app_info: *const u8,
    app_info_len: usize,
    out_signature: *mut Signature87,
    out_confirmation: *mut u8,
) -> ShawncoreCryptoErr {
    if manager.is_null()
        || own_signing_key.is_null()
        || peer_verifying_key.is_null()
        || peer_x25519_pk.is_null()
        || ml_kem_ct.is_null()
        || peer_signature.is_null()
        || peer_confirmation.is_null()
        || out_signature.is_null()
        || out_confirmation.is_null()
    {
        return ShawncoreCryptoErr::InvalidState;
    }
    if !ptr_is_aligned(manager)
        || !ptr_is_aligned(own_signing_key)
        || !ptr_is_aligned(peer_verifying_key)
        || !ptr_is_aligned(peer_x25519_pk)
        || !ptr_is_aligned(ml_kem_ct)
        || !ptr_is_aligned(peer_signature)
        || !ptr_is_aligned(out_signature)
    {
        return ShawncoreCryptoErr::InvalidState;
    }
    if (salt.is_null() && salt_len > 0)
        || (app_info.is_null() && app_info_len > 0)
        || !range_ok(salt, salt_len)
        || app_info_len > MAX_APP_INFO_LEN
        || !range_ok(app_info, app_info_len)
    {
        return ShawncoreCryptoErr::InvalidLength;
    }
    if writable_regions_overlap(&[
        (
            manager as usize,
            core::mem::size_of::<SessionManager>(),
            true,
        ),
        (
            own_signing_key as usize,
            core::mem::size_of::<SigningKey87>(),
            false,
        ),
        (
            peer_verifying_key as usize,
            core::mem::size_of::<PublicKey87>(),
            false,
        ),
        (
            peer_x25519_pk as usize,
            core::mem::size_of::<X25519Public>(),
            false,
        ),
        (
            ml_kem_ct as usize,
            core::mem::size_of::<Ciphertext1024>(),
            false,
        ),
        (
            peer_signature as usize,
            core::mem::size_of::<Signature87>(),
            false,
        ),
        (salt as usize, salt_len, false),
        (app_info as usize, app_info_len, false),
        (peer_confirmation as usize, 48, false),
        (
            out_signature as usize,
            core::mem::size_of::<Signature87>(),
            true,
        ),
        (out_confirmation as usize, 48, true),
    ]) {
        return ShawncoreCryptoErr::InvalidLength;
    }

    let manager_ref = unsafe { &mut *manager };
    let salt_slice = if salt_len > 0 {
        unsafe { core::slice::from_raw_parts(salt, salt_len) }
    } else {
        &[]
    };
    let app_info_slice = if app_info_len > 0 {
        unsafe { core::slice::from_raw_parts(app_info, app_info_len) }
    } else {
        &[]
    };

    let mut signature = Signature87([0; 4627]);
    let mut confirmation = [0u8; 48];
    match manager_ref.finalize_authenticated(
        unsafe { &*own_signing_key },
        unsafe { &*peer_verifying_key },
        unsafe { &*peer_x25519_pk },
        unsafe { &*ml_kem_ct },
        unsafe { &*peer_signature },
        unsafe { &*peer_confirmation.cast::<[u8; 48]>() },
        salt_slice,
        app_info_slice,
        &mut signature,
        &mut confirmation,
    ) {
        Ok(()) => {
            unsafe {
                core::ptr::write(out_signature, signature);
                core::ptr::write(out_confirmation.cast::<[u8; 48]>(), confirmation);
            }
            ShawncoreCryptoErr::Success
        }
        Err(e) => e.into(),
    }
}

/// Completes the encapsulating side: verifies the key-generating side's signature (which covers its
/// tag) and its key-confirmation tag and, on success, lets the session carry traffic. The key must
/// be the identity the session was bound to. A bad signature leaves the session unconfirmed (call
/// `..._zeroize` to abandon it); a valid signature with a wrong tag returns
/// `KeyConfirmationFailed` and wipes the session.
///
/// # Safety
/// `manager`, `peer_verifying_key`, `peer_signature` and `peer_confirmation` (48 bytes) must be
/// valid, non-null and, where typed, aligned, and must not overlap.
#[no_mangle]
#[cfg(feature = "ml-dsa")]
pub unsafe extern "C" fn shawncore_crypto_session_manager_confirm_peer_v2(
    manager: *mut SessionManager,
    peer_verifying_key: *const PublicKey87,
    peer_signature: *const Signature87,
    peer_confirmation: *const u8,
) -> ShawncoreCryptoErr {
    if manager.is_null()
        || peer_verifying_key.is_null()
        || peer_signature.is_null()
        || peer_confirmation.is_null()
    {
        return ShawncoreCryptoErr::InvalidState;
    }
    if !ptr_is_aligned(manager)
        || !ptr_is_aligned(peer_verifying_key)
        || !ptr_is_aligned(peer_signature)
    {
        return ShawncoreCryptoErr::InvalidState;
    }
    if writable_regions_overlap(&[
        (
            manager as usize,
            core::mem::size_of::<SessionManager>(),
            true,
        ),
        (
            peer_verifying_key as usize,
            core::mem::size_of::<PublicKey87>(),
            false,
        ),
        (
            peer_signature as usize,
            core::mem::size_of::<Signature87>(),
            false,
        ),
        (peer_confirmation as usize, 48, false),
    ]) {
        return ShawncoreCryptoErr::InvalidLength;
    }

    let manager_ref = unsafe { &mut *manager };
    match manager_ref.confirm_peer(
        unsafe { &*peer_verifying_key },
        unsafe { &*peer_signature },
        unsafe { &*peer_confirmation.cast::<[u8; 48]>() },
    ) {
        Ok(()) => ShawncoreCryptoErr::Success,
        Err(e) => e.into(),
    }
}

/// Explicitly zeroizes the active session key.
///
/// # Safety
/// `manager` must be a valid, non-null pointer.
#[no_mangle]
/// **Concurrency contract:** one initialized `SessionManager` requires exclusive access while state-mutating work is in progress. The C ABI does not serialize concurrent callers; the host RTOS must provide the required mutex, critical section, or task ownership.
///
/// In particular, callers must not concurrently invoke handshake, encrypt/decrypt, or zeroize operations on the same manager.
///
pub unsafe extern "C" fn shawncore_crypto_session_manager_zeroize(
    manager: *mut SessionManager,
) -> ShawncoreCryptoErr {
    if manager.is_null() {
        return ShawncoreCryptoErr::InvalidState;
    }

    if !ptr_is_aligned(manager) {
        return ShawncoreCryptoErr::InvalidState;
    }

    let manager_ref = unsafe { &mut *manager };
    manager_ref.zeroize_session();

    ShawncoreCryptoErr::Success
}

/// Encrypts a packet using the session manager's internal transmit key.
///
/// # Safety
/// `manager`, `plaintext`, `ciphertext`, `out_nonce`, and `out_tag` must be valid.
/// `aad` may be null only when `aad_len` is zero. Output regions must not overlap inputs.
#[no_mangle]
/// **Concurrency contract:** one initialized `SessionManager` requires exclusive access while state-mutating work is in progress. The C ABI does not serialize concurrent callers; the host RTOS must provide the required mutex, critical section, or task ownership.
///
/// In particular, callers must not concurrently invoke handshake, encrypt/decrypt, or zeroize operations on the same manager.
///
pub unsafe extern "C" fn shawncore_crypto_session_manager_encrypt_packet(
    manager: *mut SessionManager,
    aad: *const u8,
    aad_len: usize,
    plaintext: *const u8,
    ciphertext: *mut u8,
    data_len: usize,
    out_nonce: *mut u8,
    out_tag: *mut u8,
) -> ShawncoreCryptoErr {
    if manager.is_null()
        || !ptr_is_aligned(manager)
        || (plaintext.is_null() && data_len > 0)
        || (ciphertext.is_null() && data_len > 0)
        || out_nonce.is_null()
        || out_tag.is_null()
        || (aad.is_null() && aad_len > 0)
        || !range_ok(aad, aad_len)
        || !packet_len_valid(data_len)
        || !range_ok(plaintext, data_len)
        || !range_ok(ciphertext, data_len)
        || session_encrypt_buffers_overlap(
            manager, aad, aad_len, plaintext, ciphertext, data_len, out_nonce, out_tag,
        )
    {
        return ShawncoreCryptoErr::InvalidLength;
    }

    let manager_ref = unsafe { &mut *manager };
    let aad_slice = if aad_len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(aad, aad_len) }
    };
    let plaintext_slice = if data_len > 0 {
        unsafe { core::slice::from_raw_parts(plaintext, data_len) }
    } else {
        &[]
    };
    let ciphertext_slice: &mut [u8] = if data_len > 0 {
        unsafe { core::slice::from_raw_parts_mut(ciphertext, data_len) }
    } else {
        &mut []
    };
    let nonce = unsafe { &mut *(out_nonce as *mut [u8; 12]) };
    let tag = unsafe { &mut *(out_tag as *mut [u8; 48]) };
    match manager_ref.encrypt_packet(aad_slice, plaintext_slice, ciphertext_slice, nonce, tag) {
        Ok(()) => ShawncoreCryptoErr::Success,
        Err(error) => error.into(),
    }
}

/// Authenticates and decrypts a packet using the internal receive key.
///
/// # Safety
/// `manager`, `ciphertext`, `nonce`, `tag`, and `plaintext` must be valid.
/// `aad` may be null only when `aad_len` is zero. Output must not overlap inputs.
#[no_mangle]
/// **Concurrency contract:** one initialized `SessionManager` requires exclusive access while state-mutating work is in progress. The C ABI does not serialize concurrent callers; the host RTOS must provide the required mutex, critical section, or task ownership.
///
/// In particular, callers must not concurrently invoke handshake, encrypt/decrypt, or zeroize operations on the same manager.
///
pub unsafe extern "C" fn shawncore_crypto_session_manager_decrypt_packet(
    manager: *mut SessionManager,
    aad: *const u8,
    aad_len: usize,
    ciphertext: *const u8,
    data_len: usize,
    nonce: *const u8,
    tag: *const u8,
    plaintext: *mut u8,
) -> ShawncoreCryptoErr {
    if manager.is_null()
        || !ptr_is_aligned(manager)
        || (ciphertext.is_null() && data_len > 0)
        || nonce.is_null()
        || tag.is_null()
        || (plaintext.is_null() && data_len > 0)
        || (aad.is_null() && aad_len > 0)
        || !range_ok(aad, aad_len)
        || !packet_len_valid(data_len)
        || !range_ok(ciphertext, data_len)
        || !range_ok(plaintext, data_len)
        || session_decrypt_buffers_overlap(
            manager, aad, aad_len, ciphertext, data_len, nonce, tag, plaintext,
        )
    {
        return ShawncoreCryptoErr::InvalidLength;
    }

    let manager_ref = unsafe { &mut *manager };
    let aad_slice = if aad_len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(aad, aad_len) }
    };
    let ciphertext_slice = if data_len > 0 {
        unsafe { core::slice::from_raw_parts(ciphertext, data_len) }
    } else {
        &[]
    };
    let nonce_ref = unsafe { &*(nonce as *const [u8; 12]) };
    let tag_ref = unsafe { &*(tag as *const [u8; 48]) };
    let plaintext_slice: &mut [u8] = if data_len > 0 {
        unsafe { core::slice::from_raw_parts_mut(plaintext, data_len) }
    } else {
        &mut []
    };
    match manager_ref.decrypt_packet(
        aad_slice,
        ciphertext_slice,
        nonce_ref,
        tag_ref,
        plaintext_slice,
    ) {
        Ok(()) => ShawncoreCryptoErr::Success,
        Err(error) => error.into(),
    }
}

// ============================================================================
// ML-KEM FFI
// ============================================================================

/// Generates an ML-KEM-1024 keypair.
///
/// # Safety
/// `entropy` must point to exactly 64 bytes. `out_pk` and `out_dk` must point to valid,
/// properly aligned, **UNINITIALIZED** storage. Previously initialized output objects must
/// be destroyed with their matching `*_destroy` function before their storage is reused.
#[no_mangle]
pub unsafe extern "C" fn shawncore_crypto_ml_kem_keygen(
    entropy: *const u8,
    out_pk: *mut PublicKey1024,
    out_dk: *mut DecapsKey1024,
) -> ShawncoreCryptoErr {
    if entropy.is_null() || out_pk.is_null() || out_dk.is_null() {
        return ShawncoreCryptoErr::InvalidState;
    }
    if !ptr_is_aligned(out_pk) || !ptr_is_aligned(out_dk) {
        return ShawncoreCryptoErr::InvalidState;
    }

    if ranges_overlap(
        out_pk,
        core::mem::size_of::<PublicKey1024>(),
        out_dk,
        core::mem::size_of::<DecapsKey1024>(),
    ) || ranges_overlap(entropy, 64, out_pk, core::mem::size_of::<PublicKey1024>())
        || ranges_overlap(entropy, 64, out_dk, core::mem::size_of::<DecapsKey1024>())
    {
        return ShawncoreCryptoErr::InvalidLength;
    }

    let entropy_ref = unsafe { &*(entropy as *const [u8; 64]) };

    match ml_kem_keygen(entropy_ref) {
        Ok((pk, dk)) => {
            unsafe {
                core::ptr::write(out_pk, pk);
                core::ptr::write(out_dk, dk);
            }
            ShawncoreCryptoErr::Success
        }
        Err(e) => e.into(),
    }
}

/// Destroys an ML-KEM Decapsulation Key, securely zeroizing it.
///
/// # Safety
/// `dk` must point to a valid, initialized `DecapsKey1024`.
#[no_mangle]
pub unsafe extern "C" fn shawncore_crypto_ml_kem_decapskey_destroy(
    dk: *mut DecapsKey1024,
) -> ShawncoreCryptoErr {
    if dk.is_null() {
        return ShawncoreCryptoErr::InvalidState;
    }
    if !ptr_is_aligned(dk) {
        return ShawncoreCryptoErr::InvalidState;
    }

    unsafe {
        core::ptr::drop_in_place(dk);
    }
    ShawncoreCryptoErr::Success
}

/// Encapsulates a shared secret using ML-KEM-1024.
///
/// # Safety
/// `pk` must point to a valid, initialized, properly aligned public key. `out_shared` and
/// `out_ct` must point to valid, properly aligned, **UNINITIALIZED** storage. Previously
/// initialized output objects must be destroyed/reclaimed before their storage is reused.
/// `entropy` must point to exactly 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn shawncore_crypto_ml_kem_encapsulate(
    pk: *const PublicKey1024,
    entropy: *const u8,
    out_shared: *mut SharedKey1024,
    out_ct: *mut Ciphertext1024,
) -> ShawncoreCryptoErr {
    if pk.is_null() || entropy.is_null() || out_shared.is_null() || out_ct.is_null() {
        return ShawncoreCryptoErr::InvalidState;
    }
    if !ptr_is_aligned(pk) || !ptr_is_aligned(out_shared) || !ptr_is_aligned(out_ct) {
        return ShawncoreCryptoErr::InvalidState;
    }

    if ranges_overlap(
        out_shared,
        core::mem::size_of::<SharedKey1024>(),
        out_ct,
        core::mem::size_of::<Ciphertext1024>(),
    ) || ranges_overlap(
        out_shared,
        core::mem::size_of::<SharedKey1024>(),
        pk,
        core::mem::size_of::<PublicKey1024>(),
    ) || ranges_overlap(
        out_ct,
        core::mem::size_of::<Ciphertext1024>(),
        pk,
        core::mem::size_of::<PublicKey1024>(),
    ) || ranges_overlap(
        out_shared,
        core::mem::size_of::<SharedKey1024>(),
        entropy,
        32,
    ) || ranges_overlap(out_ct, core::mem::size_of::<Ciphertext1024>(), entropy, 32)
    {
        return ShawncoreCryptoErr::InvalidLength;
    }

    let pk_ref = unsafe { &*pk };
    let entropy_ref = unsafe { &*(entropy as *const [u8; 32]) };

    match ml_kem_encapsulate(pk_ref, entropy_ref) {
        Ok((shared, ct)) => {
            unsafe {
                core::ptr::write(out_shared, shared);
                core::ptr::write(out_ct, ct);
            }
            ShawncoreCryptoErr::Success
        }
        Err(e) => e.into(),
    }
}

/// Decapsulates a ciphertext using ML-KEM-1024.
///
/// # Safety
/// `dk` and `ct` must point to valid, initialized, properly aligned objects. `out_shared`
/// must point to valid, properly aligned, **UNINITIALIZED** storage. Destroy/reclaim a prior
/// shared-key object before reusing its storage.
#[no_mangle]
pub unsafe extern "C" fn shawncore_crypto_ml_kem_decapsulate(
    dk: *const DecapsKey1024,
    ct: *const Ciphertext1024,
    out_shared: *mut SharedKey1024,
) -> ShawncoreCryptoErr {
    if dk.is_null() || ct.is_null() || out_shared.is_null() {
        return ShawncoreCryptoErr::InvalidState;
    }
    if !ptr_is_aligned(dk) || !ptr_is_aligned(ct) || !ptr_is_aligned(out_shared) {
        return ShawncoreCryptoErr::InvalidState;
    }

    if ranges_overlap(
        out_shared,
        core::mem::size_of::<SharedKey1024>(),
        dk,
        core::mem::size_of::<DecapsKey1024>(),
    ) || ranges_overlap(
        out_shared,
        core::mem::size_of::<SharedKey1024>(),
        ct,
        core::mem::size_of::<Ciphertext1024>(),
    ) {
        return ShawncoreCryptoErr::InvalidLength;
    }

    let dk_ref = unsafe { &*dk };
    let ct_ref = unsafe { &*ct };

    match ml_kem_decapsulate(dk_ref, ct_ref) {
        Ok(shared) => {
            unsafe {
                core::ptr::write(out_shared, shared);
            }
            ShawncoreCryptoErr::Success
        }
        Err(e) => e.into(),
    }
}

/// Destroys an ML-KEM Shared Key, securely zeroizing it.
///
/// # Safety
/// `sk` must point to a valid, initialized `SharedKey1024`.
#[no_mangle]
pub unsafe extern "C" fn shawncore_crypto_ml_kem_sharedkey_destroy(
    sk: *mut SharedKey1024,
) -> ShawncoreCryptoErr {
    if sk.is_null() {
        return ShawncoreCryptoErr::InvalidState;
    }
    if !ptr_is_aligned(sk) {
        return ShawncoreCryptoErr::InvalidState;
    }

    unsafe {
        core::ptr::drop_in_place(sk);
    }
    ShawncoreCryptoErr::Success
}

// ============================================================================
// ML-DSA FFI
// ============================================================================

/// Generates an ML-DSA-87 keypair.
///
/// # Safety
/// `seed` must point to exactly 32 bytes. `out_pk` and `out_sk` must point to valid,
/// properly aligned, **UNINITIALIZED** storage. Previously initialized output objects must
/// be destroyed with their matching `*_destroy` function before their storage is reused.
#[no_mangle]
#[cfg(feature = "ml-dsa")]
pub unsafe extern "C" fn shawncore_crypto_ml_dsa_keygen(
    seed: *const u8,
    out_pk: *mut PublicKey87,
    out_sk: *mut SigningKey87,
) -> ShawncoreCryptoErr {
    if seed.is_null() || out_pk.is_null() || out_sk.is_null() {
        return ShawncoreCryptoErr::InvalidState;
    }
    if !ptr_is_aligned(out_pk) || !ptr_is_aligned(out_sk) {
        return ShawncoreCryptoErr::InvalidState;
    }

    if ranges_overlap(
        out_pk,
        core::mem::size_of::<PublicKey87>(),
        out_sk,
        core::mem::size_of::<SigningKey87>(),
    ) || ranges_overlap(seed, 32, out_pk, core::mem::size_of::<PublicKey87>())
        || ranges_overlap(seed, 32, out_sk, core::mem::size_of::<SigningKey87>())
    {
        return ShawncoreCryptoErr::InvalidLength;
    }

    let seed_ref = unsafe { &*(seed as *const [u8; 32]) };

    match ml_dsa_keygen(seed_ref) {
        Ok((pk, sk)) => {
            unsafe {
                core::ptr::write(out_pk, pk);
                core::ptr::write(out_sk, sk);
            }
            ShawncoreCryptoErr::Success
        }
        Err(e) => e.into(),
    }
}

/// Destroys an ML-DSA Signing Key, securely zeroizing it.
///
/// # Safety
/// `sk` must point to a valid, initialized `SigningKey87`.
#[no_mangle]
#[cfg(feature = "ml-dsa")]
pub unsafe extern "C" fn shawncore_crypto_ml_dsa_signingkey_destroy(
    sk: *mut SigningKey87,
) -> ShawncoreCryptoErr {
    if sk.is_null() {
        return ShawncoreCryptoErr::InvalidState;
    }
    if !ptr_is_aligned(sk) {
        return ShawncoreCryptoErr::InvalidState;
    }

    unsafe {
        core::ptr::drop_in_place(sk);
    }
    ShawncoreCryptoErr::Success
}

/// Signs a message using ML-DSA-87.
///
/// # Safety
/// `sk` must point to a valid, initialized, properly aligned signing key. `out_sig` must
/// point to valid, properly aligned, **UNINITIALIZED** storage. A prior initialized signature
/// value must be reclaimed before its storage is reused. `msg` must be valid for `msg_len`
/// and may be null when `msg_len` is zero.
#[no_mangle]
#[cfg(feature = "ml-dsa")]
pub unsafe extern "C" fn shawncore_crypto_ml_dsa_sign(
    sk: *const SigningKey87,
    msg: *const u8,
    msg_len: usize,
    out_sig: *mut Signature87,
) -> ShawncoreCryptoErr {
    if sk.is_null() || (msg.is_null() && msg_len > 0) || out_sig.is_null() {
        return ShawncoreCryptoErr::InvalidState;
    }
    if !range_ok(msg, msg_len) {
        return ShawncoreCryptoErr::InvalidLength;
    }
    if !ptr_is_aligned(sk) || !ptr_is_aligned(out_sig) {
        return ShawncoreCryptoErr::InvalidState;
    }

    if ranges_overlap(
        out_sig,
        core::mem::size_of::<Signature87>(),
        sk,
        core::mem::size_of::<SigningKey87>(),
    ) || ranges_overlap(out_sig, core::mem::size_of::<Signature87>(), msg, msg_len)
    {
        return ShawncoreCryptoErr::InvalidLength;
    }

    let sk_ref = unsafe { &*sk };
    let msg_slice = if msg_len > 0 {
        unsafe { core::slice::from_raw_parts(msg, msg_len) }
    } else {
        &[]
    };

    match ml_dsa_sign(sk_ref, msg_slice) {
        Ok(sig) => {
            unsafe {
                core::ptr::write(out_sig, sig);
            }
            ShawncoreCryptoErr::Success
        }
        Err(e) => e.into(),
    }
}

/// Verifies an ML-DSA-87 signature.
///
/// # Safety
/// `pk` and `sig` must be valid and non-null. `msg` must be valid for `msg_len`
/// and may be null when `msg_len` is zero.
#[no_mangle]
#[cfg(feature = "ml-dsa")]
pub unsafe extern "C" fn shawncore_crypto_ml_dsa_verify(
    pk: *const PublicKey87,
    msg: *const u8,
    msg_len: usize,
    sig: *const Signature87,
) -> ShawncoreCryptoErr {
    if pk.is_null() || (msg.is_null() && msg_len > 0) || sig.is_null() {
        return ShawncoreCryptoErr::InvalidState;
    }
    if !range_ok(msg, msg_len) {
        return ShawncoreCryptoErr::InvalidLength;
    }
    if !ptr_is_aligned(pk) || !ptr_is_aligned(sig) {
        return ShawncoreCryptoErr::InvalidState;
    }

    let pk_ref = unsafe { &*pk };
    let sig_ref = unsafe { &*sig };
    let msg_slice = if msg_len > 0 {
        unsafe { core::slice::from_raw_parts(msg, msg_len) }
    } else {
        &[]
    };

    match ml_dsa_verify(pk_ref, msg_slice, sig_ref) {
        Ok(_) => ShawncoreCryptoErr::Success,
        Err(e) => e.into(),
    }
}

// ============================================================================
// X25519 FFI
// ============================================================================

/// Generates an X25519 keypair.
///
/// # Safety
/// `entropy` must point to exactly 32 bytes. `out_pk` and `out_sk` must point to valid,
/// properly aligned, **UNINITIALIZED** storage. A previously initialized secret key must be
/// destroyed with `shawncore_crypto_x25519_secret_destroy` before its storage is reused.
#[no_mangle]
pub unsafe extern "C" fn shawncore_crypto_x25519_keygen(
    entropy: *const u8,
    out_pk: *mut X25519Public,
    out_sk: *mut X25519Secret,
) -> ShawncoreCryptoErr {
    if entropy.is_null() || out_pk.is_null() || out_sk.is_null() {
        return ShawncoreCryptoErr::InvalidState;
    }
    if !ptr_is_aligned(out_pk) || !ptr_is_aligned(out_sk) {
        return ShawncoreCryptoErr::InvalidState;
    }

    if ranges_overlap(
        out_pk,
        core::mem::size_of::<X25519Public>(),
        out_sk,
        core::mem::size_of::<X25519Secret>(),
    ) || ranges_overlap(entropy, 32, out_pk, core::mem::size_of::<X25519Public>())
        || ranges_overlap(entropy, 32, out_sk, core::mem::size_of::<X25519Secret>())
    {
        return ShawncoreCryptoErr::InvalidLength;
    }

    let entropy_ref = unsafe { &*(entropy as *const [u8; 32]) };
    let (pk, sk) = x25519_keygen(entropy_ref);

    unsafe {
        core::ptr::write(out_pk, pk);
        core::ptr::write(out_sk, sk);
    }

    ShawncoreCryptoErr::Success
}

/// Destroys an X25519 Secret Key, securely zeroizing it.
///
/// # Safety
/// `sk` must point to a valid, initialized `X25519Secret`.
#[no_mangle]
pub unsafe extern "C" fn shawncore_crypto_x25519_secret_destroy(
    sk: *mut X25519Secret,
) -> ShawncoreCryptoErr {
    if sk.is_null() {
        return ShawncoreCryptoErr::InvalidState;
    }
    if !ptr_is_aligned(sk) {
        return ShawncoreCryptoErr::InvalidState;
    }

    unsafe {
        core::ptr::drop_in_place(sk);
    }
    ShawncoreCryptoErr::Success
}

/// Performs an X25519 Diffie-Hellman key exchange.
///
/// # Safety
/// `sk` and `peer_pk` must point to valid, initialized, properly aligned objects. `out_shared`
/// must point to valid, properly aligned, **UNINITIALIZED** storage. Reclaim a prior initialized
/// shared secret before reusing its storage.
#[no_mangle]
pub unsafe extern "C" fn shawncore_crypto_x25519_diffie_hellman(
    sk: *const X25519Secret,
    peer_pk: *const X25519Public,
    out_shared: *mut X25519SharedSecret,
) -> ShawncoreCryptoErr {
    if sk.is_null() || peer_pk.is_null() || out_shared.is_null() {
        return ShawncoreCryptoErr::InvalidState;
    }
    if !ptr_is_aligned(sk) || !ptr_is_aligned(peer_pk) || !ptr_is_aligned(out_shared) {
        return ShawncoreCryptoErr::InvalidState;
    }

    if ranges_overlap(
        out_shared,
        core::mem::size_of::<X25519SharedSecret>(),
        sk,
        core::mem::size_of::<X25519Secret>(),
    ) || ranges_overlap(
        out_shared,
        core::mem::size_of::<X25519SharedSecret>(),
        peer_pk,
        core::mem::size_of::<X25519Public>(),
    ) {
        return ShawncoreCryptoErr::InvalidLength;
    }

    let sk_ref = unsafe { &*sk };
    let peer_pk_ref = unsafe { &*peer_pk };

    match x25519_diffie_hellman(sk_ref, peer_pk_ref) {
        Ok(shared) => {
            unsafe {
                core::ptr::write(out_shared, shared);
            }
            ShawncoreCryptoErr::Success
        }
        Err(e) => e.into(),
    }
}

/// Destroys an X25519 Shared Secret, securely zeroizing it.
///
/// # Safety
/// `ss` must point to a valid, initialized `X25519SharedSecret`.
#[no_mangle]
pub unsafe extern "C" fn shawncore_crypto_x25519_sharedsecret_destroy(
    ss: *mut X25519SharedSecret,
) -> ShawncoreCryptoErr {
    if ss.is_null() {
        return ShawncoreCryptoErr::InvalidState;
    }
    if !ptr_is_aligned(ss) {
        return ShawncoreCryptoErr::InvalidState;
    }

    unsafe {
        core::ptr::drop_in_place(ss);
    }
    ShawncoreCryptoErr::Success
}

// ============================================================================
// Wire Encoding FFI
// ============================================================================
//
// Handshake values that must cross a link are opaque to C, so each one exposes a
// fixed-length wire codec here. Secret key material is deliberately excluded:
// decapsulation keys, signing keys, and shared secrets have no export path.

fn ml_kem_ciphertext_encode(value: &Ciphertext1024) -> [u8; ML_KEM_CIPHERTEXT_BYTES] {
    value.0
}

fn ml_kem_ciphertext_decode(
    bytes: &[u8; ML_KEM_CIPHERTEXT_BYTES],
) -> Result<Ciphertext1024, CryptoError> {
    Ok(Ciphertext1024(*bytes))
}

fn x25519_publickey_encode(value: &X25519Public) -> [u8; X25519_PUBLICKEY_BYTES] {
    value.0
}

fn x25519_publickey_decode(
    bytes: &[u8; X25519_PUBLICKEY_BYTES],
) -> Result<X25519Public, CryptoError> {
    Ok(X25519Public(*bytes))
}

#[cfg(feature = "ml-dsa")]
fn ml_dsa_signature_encode(value: &Signature87) -> [u8; ML_DSA_SIGNATURE_BYTES] {
    value.0
}

#[cfg(feature = "ml-dsa")]
fn ml_dsa_signature_decode(
    bytes: &[u8; ML_DSA_SIGNATURE_BYTES],
) -> Result<Signature87, CryptoError> {
    Ok(Signature87(*bytes))
}

macro_rules! wire_codec {
    ($type:ty, $len:expr, $len_fn:ident, $to_fn:ident, $from_fn:ident, $encode:path, $decode:path) => {
        #[doc = concat!("Returns the wire-encoded length in bytes of a `", stringify!($type), "`.")]
        #[no_mangle]
        pub extern "C" fn $len_fn() -> usize {
            $len
        }

        #[doc = concat!("Writes the wire encoding of a `", stringify!($type), "` into `out`.")]
        ///
        /// `out_len` must equal the value reported by the matching `_encoded_len`
        /// function. The in-memory object may be larger than its encoding.
        ///
        /// # Safety
        /// `value` must point to a valid, initialized object of this type. `out` must
        /// be writable for `out_len` bytes and must not overlap `value`.
        #[no_mangle]
        pub unsafe extern "C" fn $to_fn(
            value: *const $type,
            out: *mut u8,
            out_len: usize,
        ) -> ShawncoreCryptoErr {
            if value.is_null() || out.is_null() {
                return ShawncoreCryptoErr::InvalidState;
            }
            if !ptr_is_aligned(value) {
                return ShawncoreCryptoErr::InvalidState;
            }
            if out_len != $len {
                return ShawncoreCryptoErr::InvalidLength;
            }
            if ranges_overlap(value, core::mem::size_of::<$type>(), out, out_len) {
                return ShawncoreCryptoErr::InvalidLength;
            }

            let encoded = $encode(unsafe { &*value });
            unsafe {
                core::ptr::copy_nonoverlapping(encoded.as_ptr(), out, $len);
            }
            ShawncoreCryptoErr::Success
        }

        #[doc = concat!("Reconstructs a `", stringify!($type), "` from its wire encoding.")]
        ///
        /// Decoding validates length and structure only. It does not authenticate the
        /// peer; binding a key to an identity belongs to the caller's protocol layer.
        ///
        /// # Safety
        /// `bytes` must be readable for `len` bytes. `out` must point to writable
        /// storage with this type's size and alignment, must not overlap `bytes`, and
        /// is fully overwritten on success and left unmodified on failure.
        #[no_mangle]
        pub unsafe extern "C" fn $from_fn(
            bytes: *const u8,
            len: usize,
            out: *mut $type,
        ) -> ShawncoreCryptoErr {
            if bytes.is_null() || out.is_null() {
                return ShawncoreCryptoErr::InvalidState;
            }
            if !ptr_is_aligned(out) {
                return ShawncoreCryptoErr::InvalidState;
            }
            if len != $len {
                return ShawncoreCryptoErr::InvalidLength;
            }
            if ranges_overlap(bytes, len, out, core::mem::size_of::<$type>()) {
                return ShawncoreCryptoErr::InvalidLength;
            }

            let input = unsafe { &*(bytes as *const [u8; $len]) };
            match $decode(input) {
                Ok(value) => {
                    unsafe {
                        core::ptr::write(out, value);
                    }
                    ShawncoreCryptoErr::Success
                }
                Err(e) => e.into(),
            }
        }
    };
}

wire_codec!(
    PublicKey1024,
    ML_KEM_PUBLICKEY_BYTES,
    shawncore_crypto_ml_kem_publickey_encoded_len,
    shawncore_crypto_ml_kem_publickey_to_bytes,
    shawncore_crypto_ml_kem_publickey_from_bytes,
    PublicKey1024::to_bytes,
    PublicKey1024::from_bytes
);
wire_codec!(
    Ciphertext1024,
    ML_KEM_CIPHERTEXT_BYTES,
    shawncore_crypto_ml_kem_ciphertext_encoded_len,
    shawncore_crypto_ml_kem_ciphertext_to_bytes,
    shawncore_crypto_ml_kem_ciphertext_from_bytes,
    ml_kem_ciphertext_encode,
    ml_kem_ciphertext_decode
);
wire_codec!(
    X25519Public,
    X25519_PUBLICKEY_BYTES,
    shawncore_crypto_x25519_publickey_encoded_len,
    shawncore_crypto_x25519_publickey_to_bytes,
    shawncore_crypto_x25519_publickey_from_bytes,
    x25519_publickey_encode,
    x25519_publickey_decode
);
#[cfg(feature = "ml-dsa")]
wire_codec!(
    PublicKey87,
    ML_DSA_PUBLICKEY_BYTES,
    shawncore_crypto_ml_dsa_publickey_encoded_len,
    shawncore_crypto_ml_dsa_publickey_to_bytes,
    shawncore_crypto_ml_dsa_publickey_from_bytes,
    PublicKey87::to_bytes,
    PublicKey87::from_bytes
);
#[cfg(feature = "ml-dsa")]
wire_codec!(
    Signature87,
    ML_DSA_SIGNATURE_BYTES,
    shawncore_crypto_ml_dsa_signature_encoded_len,
    shawncore_crypto_ml_dsa_signature_to_bytes,
    shawncore_crypto_ml_dsa_signature_from_bytes,
    ml_dsa_signature_encode,
    ml_dsa_signature_decode
);

// ============================================================================
// AEAD & KDF FFI
// ============================================================================

#[inline]
fn ptr_is_aligned<T>(ptr: *const T) -> bool {
    (ptr as usize).is_multiple_of(core::mem::align_of::<T>())
}

/// Largest length a Rust slice may have; a larger length cannot describe any valid range.
const MAX_SLICE_LEN: usize = isize::MAX as usize;

/// The authenticated transcript length-prefixes `app_info` with 32 bits.
#[cfg(feature = "ml-dsa")]
const MAX_APP_INFO_LEN: usize = u32::MAX as usize;

/// Whether `len` may be passed to `core::slice::from_raw_parts` at all.
#[inline]
fn slice_len_valid(len: usize) -> bool {
    len <= MAX_SLICE_LEN
}

/// Whether `ptr`/`len` can describe one slice: the length is within Rust's limit and the range
/// does not wrap the address space. Whether the memory is mapped and live is the caller's duty.
#[inline]
fn range_ok(ptr: *const u8, len: usize) -> bool {
    slice_len_valid(len) && (len == 0 || (ptr as usize).checked_add(len).is_some())
}

/// Whether one ChaCha20 key and nonce can process `len` bytes (the 32-bit block counter limit).
#[inline]
fn packet_len_valid(len: usize) -> bool {
    slice_len_valid(len) && len as u64 <= crate::aead_wrapper::CHACHA20_MAX_BYTES
}

fn ranges_overlap<T, U>(
    first: *const T,
    first_len: usize,
    second: *const U,
    second_len: usize,
) -> bool {
    // A zero-length range denotes no memory, whatever address accompanies it.
    if first_len == 0 || second_len == 0 {
        return false;
    }
    let Some(first_end) = (first as usize).checked_add(first_len) else {
        return true;
    };
    let Some(second_end) = (second as usize).checked_add(second_len) else {
        return true;
    };

    (first as usize) < second_end && (second as usize) < first_end
}

#[allow(clippy::too_many_arguments)]
fn session_encrypt_buffers_overlap(
    manager: *const SessionManager,
    aad: *const u8,
    aad_len: usize,
    plaintext: *const u8,
    ciphertext: *mut u8,
    data_len: usize,
    out_nonce: *mut u8,
    out_tag: *mut u8,
) -> bool {
    let manager_size = core::mem::size_of::<SessionManager>();
    ranges_overlap(manager, manager_size, aad, aad_len)
        || ranges_overlap(manager, manager_size, plaintext, data_len)
        || ranges_overlap(manager, manager_size, ciphertext, data_len)
        || ranges_overlap(manager, manager_size, out_nonce, 12)
        || ranges_overlap(manager, manager_size, out_tag, 48)
        || ranges_overlap(ciphertext, data_len, aad, aad_len)
        || ranges_overlap(ciphertext, data_len, plaintext, data_len)
        || ranges_overlap(ciphertext, data_len, out_nonce, 12)
        || ranges_overlap(ciphertext, data_len, out_tag, 48)
        || ranges_overlap(out_nonce, 12, aad, aad_len)
        || ranges_overlap(out_nonce, 12, plaintext, data_len)
        || ranges_overlap(out_nonce, 12, out_tag, 48)
        || ranges_overlap(out_tag, 48, aad, aad_len)
        || ranges_overlap(out_tag, 48, plaintext, data_len)
}

#[allow(clippy::too_many_arguments)]
fn session_decrypt_buffers_overlap(
    manager: *const SessionManager,
    aad: *const u8,
    aad_len: usize,
    ciphertext: *const u8,
    data_len: usize,
    nonce: *const u8,
    tag: *const u8,
    plaintext: *mut u8,
) -> bool {
    let manager_size = core::mem::size_of::<SessionManager>();
    ranges_overlap(manager, manager_size, aad, aad_len)
        || ranges_overlap(manager, manager_size, ciphertext, data_len)
        || ranges_overlap(manager, manager_size, nonce, 12)
        || ranges_overlap(manager, manager_size, tag, 48)
        || ranges_overlap(manager, manager_size, plaintext, data_len)
        || ranges_overlap(plaintext, data_len, aad, aad_len)
        || ranges_overlap(plaintext, data_len, ciphertext, data_len)
        || ranges_overlap(plaintext, data_len, nonce, 12)
        || ranges_overlap(plaintext, data_len, tag, 48)
}

#[allow(clippy::too_many_arguments)]
fn aead_encrypt_buffers_overlap(
    enc_key: *const u8,
    mac_key: *const u8,
    nonce: *const u8,
    aad: *const u8,
    aad_len: usize,
    plaintext: *const u8,
    ciphertext: *mut u8,
    out_mac: *mut u8,
    data_len: usize,
) -> bool {
    ranges_overlap(ciphertext, data_len, enc_key, 32)
        || ranges_overlap(ciphertext, data_len, mac_key, 32)
        || ranges_overlap(ciphertext, data_len, nonce, 12)
        || ranges_overlap(ciphertext, data_len, aad, aad_len)
        || ranges_overlap(ciphertext, data_len, plaintext, data_len)
        || ranges_overlap(out_mac, 48, enc_key, 32)
        || ranges_overlap(out_mac, 48, mac_key, 32)
        || ranges_overlap(out_mac, 48, nonce, 12)
        || ranges_overlap(out_mac, 48, aad, aad_len)
        || ranges_overlap(out_mac, 48, plaintext, data_len)
        || ranges_overlap(out_mac, 48, ciphertext, data_len)
}

#[allow(clippy::too_many_arguments)]
fn aead_decrypt_buffers_overlap(
    enc_key: *const u8,
    mac_key: *const u8,
    nonce: *const u8,
    aad: *const u8,
    aad_len: usize,
    ciphertext: *const u8,
    mac: *const u8,
    plaintext: *mut u8,
    data_len: usize,
) -> bool {
    ranges_overlap(plaintext, data_len, enc_key, 32)
        || ranges_overlap(plaintext, data_len, mac_key, 32)
        || ranges_overlap(plaintext, data_len, nonce, 12)
        || ranges_overlap(plaintext, data_len, aad, aad_len)
        || ranges_overlap(plaintext, data_len, ciphertext, data_len)
        || ranges_overlap(plaintext, data_len, mac, 48)
}

/// Computes an HMAC-SHA384 tag.
///
/// # Safety
/// `key` and `out_mac` must be valid and non-null. `key` must point to 32 bytes. `data` must be valid for `data_len`.
/// `data` may be null when `data_len` is zero.
/// `out_mac` must point to 48 bytes.
#[no_mangle]
pub unsafe extern "C" fn shawncore_crypto_hmac_sha384(
    key: *const u8,
    data: *const u8,
    data_len: usize,
    out_mac: *mut u8,
) -> ShawncoreCryptoErr {
    if key.is_null() || (data.is_null() && data_len > 0) || out_mac.is_null() {
        return ShawncoreCryptoErr::InvalidState;
    }
    if !range_ok(data, data_len) {
        return ShawncoreCryptoErr::InvalidLength;
    }
    if ranges_overlap(out_mac, 48, key, 32) || ranges_overlap(out_mac, 48, data, data_len) {
        return ShawncoreCryptoErr::InvalidLength;
    }

    let key_slice = unsafe { core::slice::from_raw_parts(key, 32) };
    let data_slice = if data_len > 0 {
        unsafe { core::slice::from_raw_parts(data, data_len) }
    } else {
        &[]
    };
    let out_mac_slice = unsafe { &mut *(out_mac as *mut [u8; 48]) };

    match hmac_sha384(key_slice, data_slice) {
        Ok(mac) => {
            out_mac_slice.copy_from_slice(&mac);
            ShawncoreCryptoErr::Success
        }
        Err(e) => e.into(),
    }
}

/// Expands a pseudorandom key using HKDF-SHA384.
///
/// # Safety
/// All pointers must be valid and non-null. `prk` must point to 48 bytes. `info` must be valid for `info_len`.
/// `out` must be valid for `out_len`.
#[no_mangle]
pub unsafe extern "C" fn shawncore_crypto_hkdf_expand_sha384(
    prk: *const u8,
    info: *const u8,
    info_len: usize,
    out: *mut u8,
    out_len: usize,
) -> ShawncoreCryptoErr {
    if prk.is_null() || (info.is_null() && info_len > 0) || (out.is_null() && out_len > 0) {
        return ShawncoreCryptoErr::InvalidState;
    }
    if !range_ok(info, info_len) || !range_ok(out, out_len) {
        return ShawncoreCryptoErr::InvalidLength;
    }
    if ranges_overlap(out, out_len, prk, 48) || ranges_overlap(out, out_len, info, info_len) {
        return ShawncoreCryptoErr::InvalidLength;
    }

    let prk_slice = unsafe { core::slice::from_raw_parts(prk, 48) };
    let info_slice = if info_len > 0 {
        unsafe { core::slice::from_raw_parts(info, info_len) }
    } else {
        &[]
    };
    let out_slice: &mut [u8] = if out_len > 0 {
        unsafe { core::slice::from_raw_parts_mut(out, out_len) }
    } else {
        &mut []
    };

    match hkdf_expand_sha384(prk_slice, info_slice, out_slice) {
        Ok(_) => ShawncoreCryptoErr::Success,
        Err(e) => e.into(),
    }
}

/// Performs Authenticated Encryption with Associated Data (AEAD) using ChaCha20 and HMAC-SHA384.
///
/// # Safety
/// All pointers must be valid and non-null. `enc_key` and `mac_key` must point to 32 bytes.
/// `nonce` must point to 12 bytes. `aad` must be valid for `aad_len`.
/// `plaintext` and `ciphertext` must be valid for `data_len`. `out_mac` must point to 48 bytes.
/// Input and output regions must not overlap. The nonce must be unique for each
/// encryption using a given key pair.
#[no_mangle]
pub unsafe extern "C" fn shawncore_crypto_aead_encrypt(
    enc_key: *const u8,
    mac_key: *const u8,
    nonce: *const u8,
    aad: *const u8,
    aad_len: usize,
    plaintext: *const u8,
    ciphertext: *mut u8,
    data_len: usize,
    out_mac: *mut u8,
) -> ShawncoreCryptoErr {
    if enc_key.is_null()
        || mac_key.is_null()
        || nonce.is_null()
        || (plaintext.is_null() && data_len > 0)
        || (ciphertext.is_null() && data_len > 0)
        || out_mac.is_null()
    {
        return ShawncoreCryptoErr::InvalidState;
    }
    if (aad.is_null() && aad_len > 0)
        || !range_ok(aad, aad_len)
        || !packet_len_valid(data_len)
        || !range_ok(plaintext, data_len)
        || !range_ok(ciphertext, data_len)
    {
        return ShawncoreCryptoErr::InvalidLength;
    }
    if aead_encrypt_buffers_overlap(
        enc_key, mac_key, nonce, aad, aad_len, plaintext, ciphertext, out_mac, data_len,
    ) {
        return ShawncoreCryptoErr::InvalidLength;
    }

    let enc_key_ref = unsafe { &*(enc_key as *const [u8; 32]) };
    let mac_key_ref = unsafe { &*(mac_key as *const [u8; 32]) };
    let nonce_ref = unsafe { &*(nonce as *const [u8; 12]) };
    let aad_slice = if aad_len > 0 {
        unsafe { core::slice::from_raw_parts(aad, aad_len) }
    } else {
        &[]
    };
    let pt_slice = if data_len > 0 {
        unsafe { core::slice::from_raw_parts(plaintext, data_len) }
    } else {
        &[]
    };
    let ct_slice: &mut [u8] = if data_len > 0 {
        unsafe { core::slice::from_raw_parts_mut(ciphertext, data_len) }
    } else {
        &mut []
    };
    let out_mac_ref = unsafe { &mut *(out_mac as *mut [u8; 48]) };

    match aead_encrypt(
        enc_key_ref,
        mac_key_ref,
        nonce_ref,
        aad_slice,
        pt_slice,
        ct_slice,
        out_mac_ref,
    ) {
        Ok(_) => ShawncoreCryptoErr::Success,
        Err(e) => e.into(),
    }
}

/// Performs Authenticated Decryption with Associated Data (AEAD) using ChaCha20 and HMAC-SHA384.
///
/// # Safety
/// All pointers must be valid and non-null. `enc_key` and `mac_key` must point to 32 bytes.
/// `nonce` must point to 12 bytes. `aad` must be valid for `aad_len`.
/// `ciphertext` and `plaintext` must be valid for `data_len`. `mac` must point to 48 bytes.
/// Input and output regions must not overlap.
#[no_mangle]
pub unsafe extern "C" fn shawncore_crypto_aead_decrypt(
    enc_key: *const u8,
    mac_key: *const u8,
    nonce: *const u8,
    aad: *const u8,
    aad_len: usize,
    ciphertext: *const u8,
    mac: *const u8,
    plaintext: *mut u8,
    data_len: usize,
) -> ShawncoreCryptoErr {
    if enc_key.is_null()
        || mac_key.is_null()
        || nonce.is_null()
        || (ciphertext.is_null() && data_len > 0)
        || mac.is_null()
        || (plaintext.is_null() && data_len > 0)
    {
        return ShawncoreCryptoErr::InvalidState;
    }
    if (aad.is_null() && aad_len > 0)
        || !range_ok(aad, aad_len)
        || !packet_len_valid(data_len)
        || !range_ok(ciphertext, data_len)
        || !range_ok(plaintext, data_len)
    {
        return ShawncoreCryptoErr::InvalidLength;
    }
    if aead_decrypt_buffers_overlap(
        enc_key, mac_key, nonce, aad, aad_len, ciphertext, mac, plaintext, data_len,
    ) {
        return ShawncoreCryptoErr::InvalidLength;
    }

    let enc_key_ref = unsafe { &*(enc_key as *const [u8; 32]) };
    let mac_key_ref = unsafe { &*(mac_key as *const [u8; 32]) };
    let nonce_ref = unsafe { &*(nonce as *const [u8; 12]) };
    let aad_slice = if aad_len > 0 {
        unsafe { core::slice::from_raw_parts(aad, aad_len) }
    } else {
        &[]
    };
    let ct_slice = if data_len > 0 {
        unsafe { core::slice::from_raw_parts(ciphertext, data_len) }
    } else {
        &[]
    };
    let mac_ref = unsafe { &*(mac as *const [u8; 48]) };
    let pt_slice: &mut [u8] = if data_len > 0 {
        unsafe { core::slice::from_raw_parts_mut(plaintext, data_len) }
    } else {
        &mut []
    };

    match aead_decrypt(
        enc_key_ref,
        mac_key_ref,
        nonce_ref,
        aad_slice,
        ct_slice,
        mac_ref,
        pt_slice,
    ) {
        Ok(_) => ShawncoreCryptoErr::Success,
        Err(e) => e.into(),
    }
}

// ============================================================================
// Entropy Ingestion FFI
// ============================================================================

/// Pushes a 32-byte chunk of entropy into the global asynchronous entropy queue.
///
/// # Safety
/// `chunk` must be a valid, non-null pointer to exactly 32 bytes of memory.
/// Calls must be serialized to one entropy-queue producer, including across ISR
/// contexts. The host is responsible for supplying actual unpredictable entropy.
#[no_mangle]
pub unsafe extern "C" fn shawncore_crypto_entropy_push(chunk: *const u8) -> ShawncoreCryptoErr {
    if chunk.is_null() {
        return ShawncoreCryptoErr::InvalidState;
    }

    let chunk_ref = unsafe { &*(chunk as *const [u8; 32]) };
    if chunk_ref.iter().all(|&byte| byte == 0) || chunk_ref.iter().all(|&byte| byte == 0xFF) {
        return ShawncoreCryptoErr::InvalidState;
    }

    match unsafe { GLOBAL_ENTROPY_QUEUE.push(chunk_ref) } {
        Ok(_) => ShawncoreCryptoErr::Success,
        Err(e) => e.into(),
    }
}

/// Drains the global entropy queue and mixes it into the global entropy pool.
///
/// # WARNING: NMI DEADLOCK VECTOR
///
/// `shawncore_crypto_entropy_push` is lock-free for one serialized producer. It
/// must not be called concurrently from multiple ISR or thread contexts.
/// This function acquires a spinlock and MUST NOT be called from a Non-Maskable
/// Interrupt (NMI) or ARM Fast Interrupt (FIQ). Call it from a standard thread
/// or Deferred Procedure Call (DPC) context after the interrupt has been deferred.
///
/// # Safety
/// This function has no pointer safety requirements. The caller must obey the
/// execution-context restriction above.
#[no_mangle]
pub unsafe extern "C" fn shawncore_crypto_entropy_mix() -> ShawncoreCryptoErr {
    GLOBAL_ENTROPY_POOL.mix_entropy();
    ShawncoreCryptoErr::Success
}

/// Software cryptographic self-test suite.
///
/// Executes known-answer tests for SHA-384, HMAC-SHA384, HKDF-SHA384, X25519, and the
/// ChaCha20 keystream. The cache-flush callback must be registered first because the
/// HMAC/HKDF/AEAD paths invoke it. ML-KEM and ML-DSA are not covered. This validates the
/// linked software cryptographic paths; it does not claim FIPS certification, a formal
/// power-on test, or physical-silicon verification.
#[no_mangle]
pub extern "C" fn shawncore_crypto_self_test() -> ShawncoreCryptoErr {
    use sha2::{Digest, Sha384};
    use subtle::ConstantTimeEq;

    // 1. SHA-384("abc") — NIST FIPS 180-4.
    let mut hasher = Sha384::new();
    hasher.update(b"abc");
    let digest = hasher.finalize();
    let sha_expected = [
        0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50,
        0x07, 0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63, 0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff,
        0x5b, 0xed, 0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba, 0xec, 0xa1, 0x34,
        0xc8, 0x25, 0xa7,
    ];
    if digest.as_slice().ct_eq(&sha_expected).unwrap_u8() != 1 {
        return ShawncoreCryptoErr::VerificationFailed;
    }

    // 2. HMAC-SHA384 with a 32-byte 0x0b key and "Hi There".
    let hmac_key = [0x0b; 32];
    let hmac_expected = [
        0xc3, 0xf1, 0x61, 0x59, 0x43, 0xd1, 0xdd, 0x07, 0xa8, 0x3b, 0xb6, 0x44, 0xb9, 0x7f, 0xb3,
        0xdc, 0x2b, 0x8a, 0x93, 0x6a, 0xa5, 0x38, 0x9d, 0xe2, 0xa3, 0xe9, 0xdd, 0x91, 0xbc, 0x3b,
        0xae, 0x0d, 0x0c, 0x30, 0x33, 0x4a, 0x30, 0x17, 0x33, 0xaa, 0x54, 0xed, 0x5e, 0x1f, 0x07,
        0x69, 0xe8, 0x68,
    ];
    let hmac_result = match hmac_sha384(&hmac_key, b"Hi There") {
        Ok(value) => value,
        Err(_) => return ShawncoreCryptoErr::VerificationFailed,
    };
    if hmac_result.ct_eq(&hmac_expected).unwrap_u8() != 1 {
        return ShawncoreCryptoErr::VerificationFailed;
    }

    // 3. HKDF-Expand-SHA384 using a deterministic PRK.
    let prk = [0x0b; 48];
    let hkdf_expected = [
        0xaf, 0x5e, 0x50, 0x8e, 0xb4, 0xbb, 0xde, 0x0b, 0xc4, 0xef, 0xeb, 0x3b, 0x15, 0x31, 0xe9,
        0x5b, 0x93, 0x34, 0x7f, 0x29, 0x2d, 0x76, 0xc1, 0x57, 0x4e, 0x6c, 0x42, 0xad, 0x47, 0xc0,
        0x17, 0x88,
    ];
    let mut hkdf_output = [0u8; 32];
    if hkdf_expand_sha384(&prk, b"test", &mut hkdf_output).is_err() {
        return ShawncoreCryptoErr::VerificationFailed;
    }
    if hkdf_output.ct_eq(&hkdf_expected).unwrap_u8() != 1 {
        return ShawncoreCryptoErr::VerificationFailed;
    }

    // 4. X25519 deterministic KAT.
    let alice_seed = [0x42; 32];
    let bob_seed = [0x24; 32];
    let (alice_public, alice_secret) = x25519_keygen(&alice_seed);
    let (bob_public, _) = x25519_keygen(&bob_seed);
    let x25519_expected = [
        0x07, 0x91, 0x1f, 0xea, 0x37, 0x85, 0xe6, 0xcd, 0x67, 0x63, 0xe1, 0xfd, 0x5d, 0xab, 0x46,
        0x1f, 0xc0, 0x8a, 0x68, 0x41, 0xaf, 0x21, 0xdb, 0x4a, 0x8a, 0xc7, 0xb7, 0xf9, 0x9b, 0x64,
        0x10, 0x3a,
    ];
    let x25519_result = match x25519_diffie_hellman(&alice_secret, &bob_public) {
        Ok(value) => value,
        Err(_) => return ShawncoreCryptoErr::VerificationFailed,
    };
    if x25519_result.0.ct_eq(&x25519_expected).unwrap_u8() != 1 {
        return ShawncoreCryptoErr::VerificationFailed;
    }

    let _ = alice_public;

    // 5. ChaCha20 keystream through the AEAD cipher path (RFC 8439 A.1 test vector #1:
    // zero key, zero nonce, block counter 0; cross-checked with OpenSSL).
    let chacha_expected: [u8; 64] = [
        0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd,
        0x28, 0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a, 0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77,
        0x0d, 0xc7, 0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d, 0x77, 0x24, 0xe0, 0x3f, 0xb8,
        0xd8, 0x4a, 0x37, 0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c, 0xc3, 0x87, 0xb6, 0x69,
        0xb2, 0xee, 0x65, 0x86,
    ];
    let mut keystream = [0u8; 64];
    let mut unused_tag = [0u8; 48];
    if aead_encrypt(
        &[0u8; 32],
        &[0u8; 32],
        &[0u8; 12],
        &[],
        &[0u8; 64],
        &mut keystream,
        &mut unused_tag,
    )
    .is_err()
        || keystream.ct_eq(&chacha_expected).unwrap_u8() != 1
    {
        return ShawncoreCryptoErr::VerificationFailed;
    }

    ShawncoreCryptoErr::Success
}

#[cfg(test)]
mod wire_codec_tests {
    use super::*;
    use core::mem::MaybeUninit;

    fn install_callbacks() {
        crate::test_support::install_callbacks();
    }

    /// Decoding an encoded ML-KEM key must yield a key that encapsulates to a secret
    /// the original decapsulation key recovers. Byte equality alone would not prove this.
    #[test]
    fn ml_kem_publickey_survives_a_wire_round_trip() {
        install_callbacks();
        let entropy = [7u8; 64];
        let (pk, dk) = crate::ml_kem_wrapper::ml_kem_keygen(&entropy).unwrap();

        let mut encoded = [0u8; ML_KEM_PUBLICKEY_BYTES];
        assert_eq!(
            unsafe {
                shawncore_crypto_ml_kem_publickey_to_bytes(&pk, encoded.as_mut_ptr(), encoded.len())
            },
            ShawncoreCryptoErr::Success
        );

        let mut decoded = MaybeUninit::<PublicKey1024>::uninit();
        assert_eq!(
            unsafe {
                shawncore_crypto_ml_kem_publickey_from_bytes(
                    encoded.as_ptr(),
                    encoded.len(),
                    decoded.as_mut_ptr(),
                )
            },
            ShawncoreCryptoErr::Success
        );
        let decoded = unsafe { decoded.assume_init() };

        assert_eq!(decoded.to_bytes(), encoded);

        let (shared, ciphertext) =
            crate::ml_kem_wrapper::ml_kem_encapsulate(&decoded, &[3u8; 32]).unwrap();
        let recovered = crate::ml_kem_wrapper::ml_kem_decapsulate(&dk, &ciphertext).unwrap();
        assert_eq!(shared.0, recovered.0);
    }

    #[test]
    fn ml_kem_ciphertext_survives_a_wire_round_trip() {
        install_callbacks();
        let (pk, dk) = crate::ml_kem_wrapper::ml_kem_keygen(&[9u8; 64]).unwrap();
        let (shared, ciphertext) = crate::ml_kem_wrapper::ml_kem_encapsulate(&pk, &[5u8; 32])
            .expect("encapsulation must succeed");

        let mut encoded = [0u8; ML_KEM_CIPHERTEXT_BYTES];
        assert_eq!(
            unsafe {
                shawncore_crypto_ml_kem_ciphertext_to_bytes(
                    &ciphertext,
                    encoded.as_mut_ptr(),
                    encoded.len(),
                )
            },
            ShawncoreCryptoErr::Success
        );

        let mut decoded = MaybeUninit::<Ciphertext1024>::uninit();
        assert_eq!(
            unsafe {
                shawncore_crypto_ml_kem_ciphertext_from_bytes(
                    encoded.as_ptr(),
                    encoded.len(),
                    decoded.as_mut_ptr(),
                )
            },
            ShawncoreCryptoErr::Success
        );
        let decoded = unsafe { decoded.assume_init() };

        let recovered = crate::ml_kem_wrapper::ml_kem_decapsulate(&dk, &decoded).unwrap();
        assert_eq!(shared.0, recovered.0);
    }

    #[test]
    fn x25519_publickey_survives_a_wire_round_trip() {
        install_callbacks();
        let (alice_pk, alice_sk) = crate::x25519_wrapper::x25519_keygen(&[0x11; 32]);
        let (bob_pk, bob_sk) = crate::x25519_wrapper::x25519_keygen(&[0x22; 32]);

        let mut encoded = [0u8; X25519_PUBLICKEY_BYTES];
        assert_eq!(
            unsafe {
                shawncore_crypto_x25519_publickey_to_bytes(
                    &bob_pk,
                    encoded.as_mut_ptr(),
                    encoded.len(),
                )
            },
            ShawncoreCryptoErr::Success
        );

        let mut decoded = MaybeUninit::<X25519Public>::uninit();
        assert_eq!(
            unsafe {
                shawncore_crypto_x25519_publickey_from_bytes(
                    encoded.as_ptr(),
                    encoded.len(),
                    decoded.as_mut_ptr(),
                )
            },
            ShawncoreCryptoErr::Success
        );
        let decoded = unsafe { decoded.assume_init() };

        let from_decoded = crate::x25519_wrapper::x25519_diffie_hellman(&alice_sk, &decoded)
            .expect("diffie-hellman with the decoded key must succeed");
        let from_peer = crate::x25519_wrapper::x25519_diffie_hellman(&bob_sk, &alice_pk)
            .expect("diffie-hellman must succeed");
        assert_eq!(from_decoded.0, from_peer.0);
    }

    /// Runs on an explicit large stack: an ML-DSA-87 verifying key is 73,856 bytes and a
    /// signing key is 104,640 bytes in memory, and an unoptimized build copies them on move.
    #[test]
    #[cfg(feature = "ml-dsa")]
    fn ml_dsa_publickey_and_signature_survive_a_wire_round_trip() {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(ml_dsa_wire_round_trip)
            .expect("test thread must spawn")
            .join()
            .expect("test thread must not panic");
    }

    #[cfg(feature = "ml-dsa")]
    fn ml_dsa_wire_round_trip() {
        install_callbacks();
        let (pk, sk) = crate::ml_dsa_wrapper::ml_dsa_keygen(&[0x3C; 32]).unwrap();
        let message = b"telemetry frame";
        let signature = crate::ml_dsa_wrapper::ml_dsa_sign(&sk, message).unwrap();

        let mut encoded_pk = [0u8; ML_DSA_PUBLICKEY_BYTES];
        assert_eq!(
            unsafe {
                shawncore_crypto_ml_dsa_publickey_to_bytes(
                    &pk,
                    encoded_pk.as_mut_ptr(),
                    encoded_pk.len(),
                )
            },
            ShawncoreCryptoErr::Success
        );
        let mut decoded_pk = MaybeUninit::<PublicKey87>::uninit();
        assert_eq!(
            unsafe {
                shawncore_crypto_ml_dsa_publickey_from_bytes(
                    encoded_pk.as_ptr(),
                    encoded_pk.len(),
                    decoded_pk.as_mut_ptr(),
                )
            },
            ShawncoreCryptoErr::Success
        );
        let decoded_pk = unsafe { decoded_pk.assume_init() };

        let mut encoded_sig = [0u8; ML_DSA_SIGNATURE_BYTES];
        assert_eq!(
            unsafe {
                shawncore_crypto_ml_dsa_signature_to_bytes(
                    &signature,
                    encoded_sig.as_mut_ptr(),
                    encoded_sig.len(),
                )
            },
            ShawncoreCryptoErr::Success
        );
        let mut decoded_sig = MaybeUninit::<Signature87>::uninit();
        assert_eq!(
            unsafe {
                shawncore_crypto_ml_dsa_signature_from_bytes(
                    encoded_sig.as_ptr(),
                    encoded_sig.len(),
                    decoded_sig.as_mut_ptr(),
                )
            },
            ShawncoreCryptoErr::Success
        );
        let decoded_sig = unsafe { decoded_sig.assume_init() };

        assert!(crate::ml_dsa_wrapper::ml_dsa_verify(&decoded_pk, message, &decoded_sig).is_ok());

        let mut tampered = decoded_sig;
        tampered.0[0] ^= 1;
        assert!(crate::ml_dsa_wrapper::ml_dsa_verify(&decoded_pk, message, &tampered).is_err());
    }

    #[test]
    fn encoded_lengths_match_the_published_wire_sizes() {
        assert_eq!(shawncore_crypto_ml_kem_publickey_encoded_len(), 1568);
        assert_eq!(shawncore_crypto_ml_kem_ciphertext_encoded_len(), 1568);
        assert_eq!(shawncore_crypto_x25519_publickey_encoded_len(), 32);
        #[cfg(feature = "ml-dsa")]
        {
            assert_eq!(shawncore_crypto_ml_dsa_publickey_encoded_len(), 2592);
            assert_eq!(shawncore_crypto_ml_dsa_signature_encoded_len(), 4627);
        }
    }

    #[test]
    fn wire_codec_rejects_misaligned_typed_outputs() {
        install_callbacks();
        let mut raw = [0u8; core::mem::size_of::<PublicKey1024>() + 64];
        let misaligned = unsafe { raw.as_mut_ptr().add(1).cast::<PublicKey1024>() };
        let encoded = [0u8; ML_KEM_PUBLICKEY_BYTES];

        assert_eq!(
            unsafe {
                shawncore_crypto_ml_kem_publickey_from_bytes(
                    encoded.as_ptr(),
                    encoded.len(),
                    misaligned,
                )
            },
            ShawncoreCryptoErr::InvalidState
        );
    }

    #[test]
    fn wire_codec_rejects_null_wrong_length_and_overlap() {
        install_callbacks();
        let (pk, _dk) = crate::ml_kem_wrapper::ml_kem_keygen(&[1u8; 64]).unwrap();
        let mut buffer = [0u8; ML_KEM_PUBLICKEY_BYTES];

        assert_eq!(
            unsafe {
                shawncore_crypto_ml_kem_publickey_to_bytes(
                    core::ptr::null(),
                    buffer.as_mut_ptr(),
                    buffer.len(),
                )
            },
            ShawncoreCryptoErr::InvalidState
        );
        assert_eq!(
            unsafe {
                shawncore_crypto_ml_kem_publickey_to_bytes(&pk, core::ptr::null_mut(), buffer.len())
            },
            ShawncoreCryptoErr::InvalidState
        );
        assert_eq!(
            unsafe { shawncore_crypto_ml_kem_publickey_to_bytes(&pk, buffer.as_mut_ptr(), 1567) },
            ShawncoreCryptoErr::InvalidLength
        );

        // Encoding into the object's own storage must be refused, not silently corrupt it.
        assert_eq!(
            unsafe {
                shawncore_crypto_ml_kem_publickey_to_bytes(
                    &pk,
                    (&pk as *const PublicKey1024).cast::<u8>().cast_mut(),
                    ML_KEM_PUBLICKEY_BYTES,
                )
            },
            ShawncoreCryptoErr::InvalidLength
        );

        let mut out = MaybeUninit::<PublicKey1024>::uninit();
        assert_eq!(
            unsafe {
                shawncore_crypto_ml_kem_publickey_from_bytes(
                    core::ptr::null(),
                    ML_KEM_PUBLICKEY_BYTES,
                    out.as_mut_ptr(),
                )
            },
            ShawncoreCryptoErr::InvalidState
        );
        assert_eq!(
            unsafe {
                shawncore_crypto_ml_kem_publickey_from_bytes(
                    buffer.as_ptr(),
                    ML_KEM_PUBLICKEY_BYTES + 1,
                    out.as_mut_ptr(),
                )
            },
            ShawncoreCryptoErr::InvalidLength
        );
    }

    #[test]
    fn session_manager_init_rejects_misaligned_storage() {
        let mut raw = [0u8; core::mem::size_of::<SessionManager>() + 64];
        let misaligned = unsafe { raw.as_mut_ptr().add(1).cast::<SessionManager>() };

        assert_eq!(
            unsafe { shawncore_crypto_session_manager_init(misaligned) },
            ShawncoreCryptoErr::InvalidState
        );
    }

    #[test]
    fn self_test_passes_with_cache_callback_registered() {
        install_callbacks();
        assert_eq!(shawncore_crypto_self_test(), ShawncoreCryptoErr::Success);
    }

    #[test]
    fn encapsulate_for_peer_rejects_misaligned_typed_pointers() {
        assert!(core::mem::align_of::<SessionManager>() > 1);
        assert!(core::mem::align_of::<PublicKey1024>() > 1);

        let mut manager_raw = [0u8; core::mem::size_of::<SessionManager>() + 64];
        let pk_raw = [0u8; core::mem::size_of::<PublicKey1024>() + 64];
        let mut manager = MaybeUninit::<SessionManager>::uninit();
        let pk = MaybeUninit::<PublicKey1024>::uninit();
        let x25519_pk = X25519Public([0x11; 32]);
        let entropy = [0x22u8; 64];
        let mut out_ct = Ciphertext1024([0; 1568]);
        let mut out_pk = X25519Public([0; 32]);

        let mut call = |manager: *mut SessionManager, peer_pk: *const PublicKey1024| unsafe {
            shawncore_crypto_session_manager_encapsulate_for_peer(
                manager,
                peer_pk,
                &x25519_pk,
                entropy.as_ptr(),
                core::ptr::null(),
                0,
                core::ptr::null(),
                0,
                &mut out_ct,
                &mut out_pk,
            )
        };

        let misaligned_manager =
            unsafe { manager_raw.as_mut_ptr().add(1).cast::<SessionManager>() };
        assert_eq!(
            call(misaligned_manager, pk.as_ptr()),
            ShawncoreCryptoErr::InvalidState
        );

        let misaligned_pk = unsafe { pk_raw.as_ptr().add(1).cast::<PublicKey1024>() };
        assert_eq!(
            call(manager.as_mut_ptr(), misaligned_pk),
            ShawncoreCryptoErr::InvalidState
        );
        assert_eq!(out_ct.0, [0; 1568]);
    }

    #[test]
    fn aead_overlap_matrix_rejects_all_output_aliases() {
        let mut buf = [0u8; 128];
        let base = buf.as_mut_ptr();
        let enc_key = base;
        let mac_key = base.wrapping_add(32);
        let nonce = base.wrapping_add(64);
        let aad = base.wrapping_add(80);
        let plaintext = base.wrapping_add(96);
        let ciphertext = plaintext;
        let out_mac = base.wrapping_add(16);

        assert!(aead_encrypt_buffers_overlap(
            enc_key, mac_key, nonce, aad, 4, plaintext, ciphertext, out_mac, 16
        ));
        assert!(aead_decrypt_buffers_overlap(
            enc_key, mac_key, nonce, aad, 4, plaintext, ciphertext, plaintext, 16
        ));
    }

    #[test]
    fn ranges_overlap_zero_length_cases() {
        let mut bytes = [0u8; 32];
        let p = bytes.as_mut_ptr();
        assert!(!ranges_overlap(p, 0, p, 32));
        assert!(!ranges_overlap(p, 32, p, 0));
        assert!(!ranges_overlap(p, 0, p.wrapping_add(16), 0));
        assert!(ranges_overlap(p, 32, p.wrapping_add(31), 1));
        assert!(!ranges_overlap(p, 16, p.wrapping_add(16), 16));
    }

    #[test]
    fn ml_kem_encapsulation_rejects_output_overlapping_public_key() {
        install_callbacks();
        let (mut pk, _dk) = crate::ml_kem_wrapper::ml_kem_keygen(&[0x6A; 64]).unwrap();
        let expected_pk = pk.to_bytes();
        let pk_ptr = core::ptr::addr_of_mut!(pk);
        let entropy = [0x3D; 32];
        let mut ciphertext = MaybeUninit::<Ciphertext1024>::uninit();
        let mut shared = MaybeUninit::<SharedKey1024>::uninit();

        assert_eq!(
            unsafe {
                shawncore_crypto_ml_kem_encapsulate(
                    pk_ptr.cast_const(),
                    entropy.as_ptr(),
                    pk_ptr.cast(),
                    ciphertext.as_mut_ptr(),
                )
            },
            ShawncoreCryptoErr::InvalidLength
        );
        assert_eq!(pk.to_bytes(), expected_pk);

        assert_eq!(
            unsafe {
                shawncore_crypto_ml_kem_encapsulate(
                    pk_ptr.cast_const(),
                    entropy.as_ptr(),
                    shared.as_mut_ptr(),
                    pk_ptr.cast(),
                )
            },
            ShawncoreCryptoErr::InvalidLength
        );
        assert_eq!(pk.to_bytes(), expected_pk);
    }
}

#[cfg(test)]
mod adversarial_ffi_tests {
    use super::*;
    use core::mem::MaybeUninit;

    /// A non-null, aligned address that is never dereferenced because the call must fail first.
    const BOGUS: usize = 8;

    #[test]
    fn absurd_lengths_are_rejected_before_any_dereference() {
        crate::test_support::install_callbacks();
        let bogus = BOGUS as *const u8;
        let bogus_mut = BOGUS as *mut u8;
        let key = [1u8; 32];
        let mac_key = [2u8; 32];
        let nonce = [3u8; 12];
        let mut tag = [0u8; 48];
        let mut manager = MaybeUninit::<SessionManager>::uninit();

        assert_eq!(
            unsafe {
                shawncore_crypto_aead_encrypt(
                    key.as_ptr(),
                    mac_key.as_ptr(),
                    nonce.as_ptr(),
                    bogus,
                    usize::MAX,
                    bogus,
                    bogus_mut,
                    usize::MAX,
                    tag.as_mut_ptr(),
                )
            },
            ShawncoreCryptoErr::InvalidLength
        );
        assert_eq!(
            unsafe {
                shawncore_crypto_aead_decrypt(
                    key.as_ptr(),
                    mac_key.as_ptr(),
                    nonce.as_ptr(),
                    bogus,
                    usize::MAX,
                    bogus,
                    tag.as_ptr(),
                    bogus_mut,
                    usize::MAX,
                )
            },
            ShawncoreCryptoErr::InvalidLength
        );
        assert_eq!(
            unsafe {
                shawncore_crypto_hmac_sha384(key.as_ptr(), bogus, usize::MAX, tag.as_mut_ptr())
            },
            ShawncoreCryptoErr::InvalidLength
        );
        assert_eq!(
            unsafe {
                shawncore_crypto_hkdf_expand_sha384(
                    [0u8; 48].as_ptr(),
                    bogus,
                    usize::MAX,
                    bogus_mut,
                    usize::MAX,
                )
            },
            ShawncoreCryptoErr::InvalidLength
        );
        let mut nonce_out = [0u8; 12];
        assert_eq!(
            unsafe {
                shawncore_crypto_session_manager_encrypt_packet(
                    manager.as_mut_ptr(),
                    bogus,
                    usize::MAX,
                    bogus,
                    bogus_mut,
                    usize::MAX,
                    nonce_out.as_mut_ptr(),
                    tag.as_mut_ptr(),
                )
            },
            ShawncoreCryptoErr::InvalidLength
        );
        assert_eq!(
            unsafe {
                shawncore_crypto_session_manager_decrypt_packet(
                    manager.as_mut_ptr(),
                    bogus,
                    usize::MAX,
                    bogus,
                    usize::MAX,
                    nonce.as_ptr(),
                    tag.as_ptr(),
                    bogus_mut,
                )
            },
            ShawncoreCryptoErr::InvalidLength
        );
    }

    #[test]
    fn oversized_hkdf_request_fails_and_releases_no_key_material() {
        crate::test_support::install_callbacks();
        let prk = [0x42u8; 48];
        let mut out = std::vec![0xAAu8; 255 * 48 + 1];

        assert_ne!(
            unsafe {
                shawncore_crypto_hkdf_expand_sha384(
                    prk.as_ptr(),
                    core::ptr::null(),
                    0,
                    out.as_mut_ptr(),
                    out.len(),
                )
            },
            ShawncoreCryptoErr::Success
        );
        assert!(out.iter().all(|&byte| byte == 0));

        let mut max = std::vec![0u8; 255 * 48];
        assert_eq!(
            unsafe {
                shawncore_crypto_hkdf_expand_sha384(
                    prk.as_ptr(),
                    core::ptr::null(),
                    0,
                    max.as_mut_ptr(),
                    max.len(),
                )
            },
            ShawncoreCryptoErr::Success
        );
    }

    #[test]
    fn null_pointers_are_rejected_by_every_session_entry_point() {
        crate::test_support::install_callbacks();
        let mut manager = MaybeUninit::<SessionManager>::uninit();
        let m = manager.as_mut_ptr();
        assert_eq!(
            unsafe { shawncore_crypto_session_manager_init(m) },
            ShawncoreCryptoErr::Success
        );

        let entropy96 = [0x11u8; 96];
        let mut ml_kem_pk = MaybeUninit::<PublicKey1024>::uninit();
        let mut x_pk = MaybeUninit::<X25519Public>::uninit();
        let mut ct = MaybeUninit::<Ciphertext1024>::uninit();
        let mut nonce = [0u8; 12];
        let mut tag = [0u8; 48];
        let mut buf = [0u8; 4];

        let null_err = ShawncoreCryptoErr::InvalidState;
        unsafe {
            assert_eq!(
                shawncore_crypto_session_manager_init(core::ptr::null_mut()),
                null_err
            );
            assert_eq!(
                shawncore_crypto_session_manager_destroy(core::ptr::null_mut()),
                null_err
            );
            assert_eq!(
                shawncore_crypto_session_manager_zeroize(core::ptr::null_mut()),
                null_err
            );
            assert_eq!(
                shawncore_crypto_session_manager_initiate_handshake(
                    core::ptr::null_mut(),
                    entropy96.as_ptr(),
                    ml_kem_pk.as_mut_ptr(),
                    x_pk.as_mut_ptr()
                ),
                null_err
            );
            assert_eq!(
                shawncore_crypto_session_manager_initiate_handshake(
                    m,
                    core::ptr::null(),
                    ml_kem_pk.as_mut_ptr(),
                    x_pk.as_mut_ptr()
                ),
                null_err
            );
            assert_eq!(
                shawncore_crypto_session_manager_initiate_handshake(
                    m,
                    entropy96.as_ptr(),
                    core::ptr::null_mut(),
                    x_pk.as_mut_ptr()
                ),
                null_err
            );
            assert_eq!(
                shawncore_crypto_session_manager_initiate_handshake(
                    m,
                    entropy96.as_ptr(),
                    ml_kem_pk.as_mut_ptr(),
                    core::ptr::null_mut()
                ),
                null_err
            );
            assert_eq!(
                shawncore_crypto_session_manager_finalize_handshake(
                    m,
                    core::ptr::null(),
                    ct.as_ptr(),
                    core::ptr::null(),
                    0,
                    core::ptr::null(),
                    0
                ),
                null_err
            );
            assert_eq!(
                shawncore_crypto_session_manager_finalize_handshake(
                    m,
                    x_pk.as_ptr(),
                    core::ptr::null(),
                    core::ptr::null(),
                    0,
                    core::ptr::null(),
                    0
                ),
                null_err
            );
            assert_eq!(
                shawncore_crypto_session_manager_finalize_handshake(
                    m,
                    x_pk.as_ptr(),
                    ct.as_ptr(),
                    core::ptr::null(),
                    1,
                    core::ptr::null(),
                    0
                ),
                ShawncoreCryptoErr::InvalidLength
            );
            assert_eq!(
                shawncore_crypto_session_manager_encapsulate_for_peer(
                    m,
                    ml_kem_pk.as_ptr(),
                    x_pk.as_ptr(),
                    core::ptr::null(),
                    core::ptr::null(),
                    0,
                    core::ptr::null(),
                    0,
                    ct.as_mut_ptr(),
                    x_pk.as_mut_ptr()
                ),
                null_err
            );
            assert_eq!(
                shawncore_crypto_session_manager_encrypt_packet(
                    m,
                    core::ptr::null(),
                    1,
                    buf.as_ptr(),
                    buf.as_mut_ptr(),
                    0,
                    nonce.as_mut_ptr(),
                    tag.as_mut_ptr()
                ),
                ShawncoreCryptoErr::InvalidLength
            );
            assert_eq!(
                shawncore_crypto_session_manager_decrypt_packet(
                    m,
                    core::ptr::null(),
                    0,
                    core::ptr::null(),
                    1,
                    nonce.as_ptr(),
                    tag.as_ptr(),
                    buf.as_mut_ptr()
                ),
                ShawncoreCryptoErr::InvalidLength
            );
            // A freshly initialized, unestablished session must refuse traffic.
            assert_ne!(
                shawncore_crypto_session_manager_encrypt_packet(
                    m,
                    core::ptr::null(),
                    0,
                    buf.as_ptr().add(0),
                    buf.as_mut_ptr().add(0),
                    0,
                    nonce.as_mut_ptr(),
                    tag.as_mut_ptr()
                ),
                ShawncoreCryptoErr::Success
            );
            assert_eq!(
                shawncore_crypto_session_manager_destroy(m),
                ShawncoreCryptoErr::Success
            );
        }
    }

    #[test]
    fn entropy_push_rejects_null_and_degenerate_chunks() {
        assert_eq!(
            unsafe { shawncore_crypto_entropy_push(core::ptr::null()) },
            ShawncoreCryptoErr::InvalidState
        );
        assert_eq!(
            unsafe { shawncore_crypto_entropy_push([0u8; 32].as_ptr()) },
            ShawncoreCryptoErr::InvalidState
        );
        assert_eq!(
            unsafe { shawncore_crypto_entropy_push([0xFFu8; 32].as_ptr()) },
            ShawncoreCryptoErr::InvalidState
        );
    }
}

#[cfg(all(test, feature = "ml-dsa"))]
mod authenticated_ffi_tests {
    use super::*;
    use core::mem::MaybeUninit;

    fn big_stack(test: impl FnOnce() + Send + 'static) {
        std::thread::Builder::new()
            .stack_size(64 << 20)
            .spawn(move || {
                crate::test_support::install_callbacks();
                test();
            })
            .unwrap()
            .join()
            .unwrap();
    }

    fn encrypt_status(manager: &mut SessionManager) -> ShawncoreCryptoErr {
        let mut nonce = [0u8; 12];
        let mut tag = [0u8; 48];
        let mut wire = [0u8; 5];
        unsafe {
            shawncore_crypto_session_manager_encrypt_packet(
                manager,
                core::ptr::null(),
                0,
                b"hello".as_ptr(),
                wire.as_mut_ptr(),
                5,
                nonce.as_mut_ptr(),
                tag.as_mut_ptr(),
            )
        }
    }

    #[test]
    fn c_abi_authenticated_handshake_round_trips_and_reports_distinct_failures() {
        big_stack(|| {
            let (k_vk, k_sk) = ml_dsa_keygen(&[0x41; 32]).unwrap();
            let (e_vk, e_sk) = ml_dsa_keygen(&[0x42; 32]).unwrap();
            let (_m_vk, m_sk) = ml_dsa_keygen(&[0x4D; 32]).unwrap();
            let mut keygen = SessionManager::new();
            let mut encap = SessionManager::new();
            let mut mitm = SessionManager::new();

            let mut ek = MaybeUninit::<PublicKey1024>::uninit();
            let mut xk = MaybeUninit::<X25519Public>::uninit();
            let entropy96 = [0x11u8; 96];
            assert_eq!(
                unsafe {
                    shawncore_crypto_session_manager_initiate_handshake(
                        &mut keygen,
                        entropy96.as_ptr(),
                        ek.as_mut_ptr(),
                        xk.as_mut_ptr(),
                    )
                },
                ShawncoreCryptoErr::Success
            );
            let (ek, xk) = unsafe { (ek.assume_init(), xk.assume_init()) };

            let entropy64 = [0x22u8; 64];
            let reply = |manager: &mut SessionManager, signer: &SigningKey87, salt: &[u8]| {
                let mut ct = MaybeUninit::<Ciphertext1024>::uninit();
                let mut xe = MaybeUninit::<X25519Public>::uninit();
                let mut sig = MaybeUninit::<Signature87>::uninit();
                let mut tag = [0u8; 48];
                let status = unsafe {
                    shawncore_crypto_session_manager_encapsulate_authenticated_v2(
                        manager,
                        signer,
                        &k_vk,
                        &ek,
                        &xk,
                        entropy64.as_ptr(),
                        salt.as_ptr(),
                        salt.len(),
                        b"app".as_ptr(),
                        3,
                        ct.as_mut_ptr(),
                        xe.as_mut_ptr(),
                        sig.as_mut_ptr(),
                        tag.as_mut_ptr(),
                    )
                };
                assert_eq!(status, ShawncoreCryptoErr::Success);
                unsafe { (ct.assume_init(), xe.assume_init(), sig.assume_init(), tag) }
            };
            let finalize = |keygen: &mut SessionManager, r: &(_, _, _, [u8; 48]), salt: &[u8]| {
                let mut out = MaybeUninit::<Signature87>::uninit();
                let mut out_tag = [0u8; 48];
                let status = unsafe {
                    shawncore_crypto_session_manager_finalize_authenticated_v2(
                        keygen,
                        &k_sk,
                        &e_vk,
                        &r.1,
                        &r.0,
                        &r.2,
                        r.3.as_ptr(),
                        salt.as_ptr(),
                        salt.len(),
                        b"app".as_ptr(),
                        3,
                        out.as_mut_ptr(),
                        out_tag.as_mut_ptr(),
                    )
                };
                (status, out, out_tag)
            };

            // An intermediary with its own identity is rejected and writes nothing.
            let forged = reply(&mut mitm, &m_sk, b"salt");
            let (status, _unwritten, _) = finalize(&mut keygen, &forged, b"salt");
            assert_eq!(status, ShawncoreCryptoErr::VerificationFailed);

            // A salt mismatch is an authentic peer with a different key: a distinct code, and the
            // pending handshake is consumed.
            let genuine = reply(&mut encap, &e_sk, b"salt");
            let (status, _unwritten, _) = finalize(&mut keygen, &genuine, b"other");
            assert_eq!(status, ShawncoreCryptoErr::KeyConfirmationFailed);
            assert_eq!(
                encrypt_status(&mut keygen),
                ShawncoreCryptoErr::InvalidState
            );
            let (status, _, _) = finalize(&mut keygen, &genuine, b"salt");
            assert_eq!(status, ShawncoreCryptoErr::InvalidState);

            // Recovery with a fresh handshake.
            let mut keygen = SessionManager::new();
            let mut encap = SessionManager::new();
            let mut ek2 = MaybeUninit::<PublicKey1024>::uninit();
            let mut xk2 = MaybeUninit::<X25519Public>::uninit();
            assert_eq!(
                unsafe {
                    shawncore_crypto_session_manager_initiate_handshake(
                        &mut keygen,
                        [0x12u8; 96].as_ptr(),
                        ek2.as_mut_ptr(),
                        xk2.as_mut_ptr(),
                    )
                },
                ShawncoreCryptoErr::Success
            );
            let (ek2, xk2) = unsafe { (ek2.assume_init(), xk2.assume_init()) };
            let mut ct = MaybeUninit::<Ciphertext1024>::uninit();
            let mut xe = MaybeUninit::<X25519Public>::uninit();
            let mut sig = MaybeUninit::<Signature87>::uninit();
            let mut tag = [0u8; 48];
            assert_eq!(
                unsafe {
                    shawncore_crypto_session_manager_encapsulate_authenticated_v2(
                        &mut encap,
                        &e_sk,
                        &k_vk,
                        &ek2,
                        &xk2,
                        entropy64.as_ptr(),
                        b"salt".as_ptr(),
                        4,
                        b"app".as_ptr(),
                        3,
                        ct.as_mut_ptr(),
                        xe.as_mut_ptr(),
                        sig.as_mut_ptr(),
                        tag.as_mut_ptr(),
                    )
                },
                ShawncoreCryptoErr::Success
            );
            let genuine = unsafe { (ct.assume_init(), xe.assume_init(), sig.assume_init(), tag) };
            let (status, out, out_tag) = finalize(&mut keygen, &genuine, b"salt");
            assert_eq!(status, ShawncoreCryptoErr::Success);
            let keygen_signature = unsafe { out.assume_init() };

            assert_eq!(
                encrypt_status(&mut encap),
                ShawncoreCryptoErr::InvalidState,
                "an unconfirmed session refuses traffic"
            );
            let mut bad_tag = out_tag;
            bad_tag[0] ^= 1;
            assert_eq!(
                unsafe {
                    shawncore_crypto_session_manager_confirm_peer_v2(
                        &mut encap,
                        &k_vk,
                        &keygen_signature,
                        bad_tag.as_ptr(),
                    )
                },
                ShawncoreCryptoErr::VerificationFailed,
                "the tag is covered by the signature, so tampering is a signature failure"
            );
            assert_eq!(
                unsafe {
                    shawncore_crypto_session_manager_confirm_peer_v2(
                        &mut encap,
                        &k_vk,
                        &keygen_signature,
                        out_tag.as_ptr(),
                    )
                },
                ShawncoreCryptoErr::Success
            );
            assert_eq!(encrypt_status(&mut encap), ShawncoreCryptoErr::Success);
        });
    }

    #[test]
    fn authenticated_entry_points_reject_null_misaligned_and_overlapping_arguments() {
        big_stack(|| {
            let (vk, sk) = ml_dsa_keygen(&[0x41; 32]).unwrap();
            let mut manager = SessionManager::new();
            let sig = Signature87([0; 4627]);
            let x = X25519Public([1; 32]);
            let ct = Ciphertext1024([2; 1568]);
            let peer_tag = [0u8; 48];
            let mut out = Signature87([0; 4627]);
            let mut out_tag = [0u8; 48];
            let mut raw = [0u8; core::mem::size_of::<SessionManager>() + 64];
            let misaligned = unsafe { raw.as_mut_ptr().add(1).cast::<SessionManager>() };
            let (null_state, bad_len) = (
                ShawncoreCryptoErr::InvalidState,
                ShawncoreCryptoErr::InvalidLength,
            );

            let finalize = |m: *mut SessionManager,
                            peer_sig: *const Signature87,
                            peer_tag: *const u8,
                            salt: *const u8,
                            salt_len: usize,
                            out: *mut Signature87,
                            out_tag: *mut u8| unsafe {
                shawncore_crypto_session_manager_finalize_authenticated_v2(
                    m,
                    &sk,
                    &vk,
                    &x,
                    &ct,
                    peer_sig,
                    peer_tag,
                    salt,
                    salt_len,
                    core::ptr::null(),
                    0,
                    out,
                    out_tag,
                )
            };
            let null = core::ptr::null::<u8>();
            let tag = peer_tag.as_ptr();
            let otag = out_tag.as_mut_ptr();
            assert_eq!(
                finalize(core::ptr::null_mut(), &sig, tag, null, 0, &mut out, otag),
                null_state
            );
            assert_eq!(
                finalize(
                    &mut manager,
                    core::ptr::null(),
                    tag,
                    null,
                    0,
                    &mut out,
                    otag
                ),
                null_state
            );
            assert_eq!(
                finalize(&mut manager, &sig, null, null, 0, &mut out, otag),
                null_state,
                "null peer confirmation"
            );
            assert_eq!(
                finalize(
                    &mut manager,
                    &sig,
                    tag,
                    null,
                    0,
                    core::ptr::null_mut(),
                    otag
                ),
                null_state
            );
            assert_eq!(
                finalize(
                    &mut manager,
                    &sig,
                    tag,
                    null,
                    0,
                    &mut out,
                    core::ptr::null_mut()
                ),
                null_state,
                "null confirmation output"
            );
            assert_eq!(
                finalize(misaligned, &sig, tag, null, 0, &mut out, otag),
                null_state
            );
            assert_eq!(
                finalize(&mut manager, &sig, tag, null, 1, &mut out, otag),
                bad_len
            );
            // An output aliasing an input must be refused before any write.
            let alias = core::ptr::addr_of!(out);
            assert_eq!(
                finalize(&mut manager, alias, tag, null, 0, &mut out, otag),
                bad_len
            );
            assert_eq!(
                finalize(&mut manager, &sig, otag, null, 0, &mut out, otag),
                bad_len,
                "confirmation output aliasing the peer confirmation"
            );
            // No pending handshake: a well-formed call fails closed.
            assert_eq!(
                finalize(&mut manager, &sig, tag, null, 0, &mut out, otag),
                ShawncoreCryptoErr::InvalidState
            );

            let confirm = |m: *mut SessionManager, s: *const Signature87, t: *const u8| unsafe {
                shawncore_crypto_session_manager_confirm_peer_v2(m, &vk, s, t)
            };
            assert_eq!(confirm(core::ptr::null_mut(), &sig, tag), null_state);
            assert_eq!(confirm(&mut manager, &sig, null), null_state);
            assert_eq!(
                confirm(&mut manager, &sig, tag),
                ShawncoreCryptoErr::InvalidState
            );
            assert_eq!(
                confirm(&mut manager, core::ptr::addr_of!(manager).cast(), tag),
                bad_len
            );
        });
    }
}

/// Variable-length input bounds, zero-length semantics and failure-output behavior of the C ABI.
#[cfg(test)]
mod boundary_tests {
    use super::*;
    use core::mem::MaybeUninit;
    use core::sync::atomic::{AtomicBool, Ordering};

    const OVER_SLICE_LIMIT: usize = isize::MAX as usize + 1;

    // High and unmapped: [HIGH, HIGH + 2^63) wraps nothing and overlaps no live object, and it is
    // never dereferenced once the length bound is enforced.
    const HIGH: usize = 0x7fff_ffff_ffff_f000;

    fn high() -> *const u8 {
        HIGH as *const u8
    }

    #[test]
    fn length_bounds_are_exact() {
        assert!(slice_len_valid(0));
        assert!(slice_len_valid(isize::MAX as usize));
        assert!(!slice_len_valid(isize::MAX as usize + 1));
        assert!(!slice_len_valid(usize::MAX));
        assert!(packet_len_valid(
            crate::aead_wrapper::CHACHA20_MAX_BYTES as usize
        ));
        assert!(!packet_len_valid(
            crate::aead_wrapper::CHACHA20_MAX_BYTES as usize + 1
        ));
        #[cfg(feature = "ml-dsa")]
        {
            assert!(MAX_APP_INFO_LEN == u32::MAX as usize);
        }
    }

    #[test]
    fn lengths_beyond_the_slice_limit_are_rejected_before_any_slice_is_formed() {
        crate::test_support::install_callbacks();
        let key = [0x11u8; 48];
        let mut mac = [0u8; 48];
        let mut manager = MaybeUninit::<SessionManager>::uninit();
        assert_eq!(
            unsafe { shawncore_crypto_session_manager_init(manager.as_mut_ptr()) },
            ShawncoreCryptoErr::Success
        );
        let m = manager.as_mut_ptr();
        let invalid = ShawncoreCryptoErr::InvalidLength;

        assert_eq!(
            unsafe {
                shawncore_crypto_hmac_sha384(
                    key.as_ptr(),
                    high(),
                    OVER_SLICE_LIMIT,
                    mac.as_mut_ptr(),
                )
            },
            invalid,
            "hmac data_len"
        );
        assert_eq!(
            unsafe {
                shawncore_crypto_hkdf_expand_sha384(
                    key.as_ptr(),
                    high(),
                    OVER_SLICE_LIMIT,
                    mac.as_mut_ptr(),
                    mac.len(),
                )
            },
            invalid,
            "hkdf info_len"
        );
        assert_eq!(
            unsafe {
                shawncore_crypto_hkdf_expand_sha384(
                    key.as_ptr(),
                    core::ptr::null(),
                    0,
                    high().cast_mut(),
                    OVER_SLICE_LIMIT,
                )
            },
            invalid,
            "hkdf out_len"
        );

        let (enc, macky, nonce) = ([1u8; 32], [2u8; 32], [3u8; 12]);
        let (mut ct, pt) = ([0u8; 4], [0u8; 4]);
        assert_eq!(
            unsafe {
                shawncore_crypto_aead_encrypt(
                    enc.as_ptr(),
                    macky.as_ptr(),
                    nonce.as_ptr(),
                    high(),
                    OVER_SLICE_LIMIT,
                    pt.as_ptr(),
                    ct.as_mut_ptr(),
                    4,
                    mac.as_mut_ptr(),
                )
            },
            invalid,
            "aead_encrypt aad_len"
        );
        assert_eq!(
            unsafe {
                shawncore_crypto_aead_decrypt(
                    enc.as_ptr(),
                    macky.as_ptr(),
                    nonce.as_ptr(),
                    high(),
                    OVER_SLICE_LIMIT,
                    pt.as_ptr(),
                    mac.as_ptr(),
                    ct.as_mut_ptr(),
                    4,
                )
            },
            invalid,
            "aead_decrypt aad_len"
        );

        let mut out_nonce = [0u8; 12];
        assert_eq!(
            unsafe {
                shawncore_crypto_session_manager_encrypt_packet(
                    m,
                    high(),
                    OVER_SLICE_LIMIT,
                    pt.as_ptr(),
                    ct.as_mut_ptr(),
                    4,
                    out_nonce.as_mut_ptr(),
                    mac.as_mut_ptr(),
                )
            },
            invalid,
            "encrypt_packet aad_len"
        );
        assert_eq!(
            unsafe {
                shawncore_crypto_session_manager_decrypt_packet(
                    m,
                    high(),
                    OVER_SLICE_LIMIT,
                    pt.as_ptr(),
                    4,
                    nonce.as_ptr(),
                    mac.as_ptr(),
                    ct.as_mut_ptr(),
                )
            },
            invalid,
            "decrypt_packet aad_len"
        );

        let x = X25519Public([1; 32]);
        let kem_ct = Ciphertext1024([2; 1568]);
        assert_eq!(
            unsafe {
                shawncore_crypto_session_manager_finalize_handshake(
                    m,
                    &x,
                    &kem_ct,
                    high(),
                    OVER_SLICE_LIMIT,
                    core::ptr::null(),
                    0,
                )
            },
            invalid,
            "finalize_handshake salt_len"
        );
        assert_eq!(
            unsafe {
                shawncore_crypto_session_manager_finalize_handshake(
                    m,
                    &x,
                    &kem_ct,
                    core::ptr::null(),
                    0,
                    high(),
                    OVER_SLICE_LIMIT,
                )
            },
            invalid,
            "finalize_handshake info_len"
        );
    }

    #[cfg(feature = "ml-dsa")]
    #[test]
    fn signature_and_authenticated_entry_points_reject_oversized_lengths() {
        crate::test_support::install_callbacks();
        std::thread::Builder::new()
            .stack_size(64 << 20)
            .spawn(|| {
                crate::test_support::install_callbacks();
                let (vk, sk) = ml_dsa_keygen(&[0x41; 32]).unwrap();
                let sig = Signature87([0; 4627]);
                let mut out_sig = MaybeUninit::<Signature87>::uninit();
                let invalid = ShawncoreCryptoErr::InvalidLength;
                assert_eq!(
                    unsafe {
                        shawncore_crypto_ml_dsa_sign(
                            &sk,
                            high(),
                            OVER_SLICE_LIMIT,
                            out_sig.as_mut_ptr(),
                        )
                    },
                    invalid,
                    "sign msg_len"
                );
                assert_eq!(
                    unsafe { shawncore_crypto_ml_dsa_verify(&vk, high(), OVER_SLICE_LIMIT, &sig) },
                    invalid,
                    "verify msg_len"
                );

                let mut manager = MaybeUninit::<SessionManager>::uninit();
                assert_eq!(
                    unsafe { shawncore_crypto_session_manager_init(manager.as_mut_ptr()) },
                    ShawncoreCryptoErr::Success
                );
                let (ek, _) = crate::ml_kem_wrapper::ml_kem_keygen(&[3; 64]).unwrap();
                let x = X25519Public([9; 32]);
                let entropy = [0x22u8; 64];
                let mut ct = MaybeUninit::<Ciphertext1024>::uninit();
                let mut xe = MaybeUninit::<X25519Public>::uninit();
                let mut tag = [0u8; 48];
                let mut out_tag = [0u8; 48];
                for (name, salt, salt_len, app, app_len) in [
                    ("salt_len", high(), OVER_SLICE_LIMIT, core::ptr::null(), 0),
                    (
                        "app_info_len above the 32-bit transcript prefix",
                        core::ptr::null(),
                        0,
                        high(),
                        u32::MAX as usize + 1,
                    ),
                ] {
                    assert_eq!(
                        unsafe {
                            shawncore_crypto_session_manager_encapsulate_authenticated_v2(
                                manager.as_mut_ptr(),
                                &sk,
                                &vk,
                                &ek,
                                &x,
                                entropy.as_ptr(),
                                salt,
                                salt_len,
                                app,
                                app_len,
                                ct.as_mut_ptr(),
                                xe.as_mut_ptr(),
                                out_sig.as_mut_ptr(),
                                tag.as_mut_ptr(),
                            )
                        },
                        invalid,
                        "encapsulate {name}"
                    );
                    assert_eq!(
                        unsafe {
                            shawncore_crypto_session_manager_finalize_authenticated_v2(
                                manager.as_mut_ptr(),
                                &sk,
                                &vk,
                                &x,
                                ct.as_ptr(),
                                &sig,
                                tag.as_ptr(),
                                salt,
                                salt_len,
                                app,
                                app_len,
                                out_sig.as_mut_ptr(),
                                out_tag.as_mut_ptr(),
                            )
                        },
                        invalid,
                        "finalize {name}"
                    );
                }
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[cfg(feature = "ml-dsa")]
    #[test]
    fn a_range_that_wraps_the_address_space_is_rejected_where_no_overlap_check_exists() {
        crate::test_support::install_callbacks();
        std::thread::Builder::new()
            .stack_size(64 << 20)
            .spawn(|| {
                crate::test_support::install_callbacks();
                let (vk, _) = ml_dsa_keygen(&[0x41; 32]).unwrap();
                let sig = Signature87([0; 4627]);
                // 32 bytes starting 16 below the top of the address space cannot be one object.
                let wrapping = (usize::MAX - 15) as *const u8;
                assert_eq!(
                    unsafe { shawncore_crypto_ml_dsa_verify(&vk, wrapping, 32, &sig) },
                    ShawncoreCryptoErr::InvalidLength
                );
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn a_zero_length_range_never_overlaps_anything() {
        let mut bytes = [0u8; 32];
        let p = bytes.as_mut_ptr();
        assert!(!ranges_overlap(p.wrapping_add(16), 0, p, 32));
        assert!(!ranges_overlap(p, 32, p.wrapping_add(16), 0));
        assert!(!ranges_overlap(p.wrapping_add(8), 0, p.wrapping_add(8), 0));
        assert!(ranges_overlap(p, 32, p.wrapping_add(31), 1));
    }

    #[test]
    fn a_zero_length_input_may_point_inside_an_output_buffer() {
        crate::test_support::install_callbacks();
        let mut region = [0u8; 80];
        let (key, rest) = region.split_at_mut(32);
        let out = rest.as_mut_ptr();
        // Empty data whose (meaningless) pointer lies inside the MAC output must not be an alias.
        assert_eq!(
            unsafe { shawncore_crypto_hmac_sha384(key.as_ptr(), out.wrapping_add(8), 0, out) },
            ShawncoreCryptoErr::Success
        );
    }

    #[test]
    fn the_cache_flush_callback_is_never_called_for_an_empty_range() {
        static SAW_EMPTY: AtomicBool = AtomicBool::new(false);
        fn hook(_: *const u8, len: usize) {
            if len == 0 {
                SAW_EMPTY.store(true, Ordering::SeqCst);
            }
        }
        let _guard = crate::test_support::hook_guard();
        crate::test_support::install_callbacks();
        SAW_EMPTY.store(false, Ordering::SeqCst);
        crate::test_support::set_cache_flush_hook(Some(hook));

        let (enc, mac_key, nonce) = ([1u8; 32], [2u8; 32], [3u8; 12]);
        let mut tag = [0u8; 48];
        crate::aead_wrapper::aead_encrypt(&enc, &mac_key, &nonce, b"", b"", &mut [], &mut tag)
            .unwrap();
        crate::aead_wrapper::aead_decrypt(&enc, &mac_key, &nonce, b"", b"", &tag, &mut []).unwrap();
        crate::test_support::set_cache_flush_hook(None);

        assert!(
            !SAW_EMPTY.load(Ordering::SeqCst),
            "a host cache-maintenance callback received a zero-length range"
        );
    }

    #[test]
    fn failed_packet_calls_leave_outputs_as_documented() {
        crate::test_support::install_callbacks();
        let mut manager = MaybeUninit::<SessionManager>::uninit();
        assert_eq!(
            unsafe { shawncore_crypto_session_manager_init(manager.as_mut_ptr()) },
            ShawncoreCryptoErr::Success
        );
        let m = manager.as_mut_ptr();
        let (mut ct, mut nonce, mut tag) = ([0xA5u8; 8], [0xA5u8; 12], [0xA5u8; 48]);
        let pt = [7u8; 8];

        // No session: refused before any output is touched.
        assert_eq!(
            unsafe {
                shawncore_crypto_session_manager_encrypt_packet(
                    m,
                    core::ptr::null(),
                    0,
                    pt.as_ptr(),
                    ct.as_mut_ptr(),
                    8,
                    nonce.as_mut_ptr(),
                    tag.as_mut_ptr(),
                )
            },
            ShawncoreCryptoErr::InvalidState
        );
        assert_eq!((ct, nonce, tag), ([0xA5; 8], [0xA5; 12], [0xA5; 48]));

        let mut plain = [0xA5u8; 8];
        assert_eq!(
            unsafe {
                shawncore_crypto_session_manager_decrypt_packet(
                    m,
                    core::ptr::null(),
                    0,
                    pt.as_ptr(),
                    8,
                    nonce.as_ptr(),
                    tag.as_ptr(),
                    plain.as_mut_ptr(),
                )
            },
            ShawncoreCryptoErr::InvalidState
        );
        assert_eq!(plain, [0xA5; 8]);

        // Raw AEAD with a wrong tag: the plaintext buffer is wiped, never left partially decrypted.
        let (enc, mac_key, aead_nonce) = ([1u8; 32], [2u8; 32], [3u8; 12]);
        assert_eq!(
            unsafe {
                shawncore_crypto_aead_decrypt(
                    enc.as_ptr(),
                    mac_key.as_ptr(),
                    aead_nonce.as_ptr(),
                    core::ptr::null(),
                    0,
                    pt.as_ptr(),
                    tag.as_ptr(),
                    plain.as_mut_ptr(),
                    8,
                )
            },
            ShawncoreCryptoErr::VerificationFailed
        );
        assert_eq!(plain, [0; 8]);
    }

    /// Pins the error-code rules written in shawncore.h so the header cannot drift from the code.
    #[test]
    fn rejected_arguments_return_the_codes_the_header_documents() {
        crate::test_support::install_callbacks();
        use ShawncoreCryptoErr::{HkdfError, InvalidLength, InvalidState};
        let (key, mut out) = ([1u8; 48], [0u8; 48]);
        let (enc, mac_key, nonce) = ([1u8; 32], [2u8; 32], [3u8; 12]);
        let (mut buf, data) = ([0u8; 4], [0u8; 4]);
        let null = core::ptr::null::<u8>();
        let mut manager = MaybeUninit::<SessionManager>::uninit();
        assert_eq!(
            unsafe { shawncore_crypto_session_manager_init(manager.as_mut_ptr()) },
            ShawncoreCryptoErr::Success
        );
        let x = X25519Public([1; 32]);
        let kem_ct = Ciphertext1024([2; 1568]);

        // NULL data pointer with a nonzero length: INVALID_STATE for the stateless functions.
        assert_eq!(
            unsafe { shawncore_crypto_hmac_sha384(key.as_ptr(), null, 1, out.as_mut_ptr()) },
            InvalidState
        );
        assert_eq!(
            unsafe {
                shawncore_crypto_hkdf_expand_sha384(key.as_ptr(), null, 1, out.as_mut_ptr(), 8)
            },
            InvalidState
        );
        assert_eq!(
            unsafe {
                shawncore_crypto_aead_encrypt(
                    enc.as_ptr(),
                    mac_key.as_ptr(),
                    nonce.as_ptr(),
                    null,
                    0,
                    null,
                    buf.as_mut_ptr(),
                    4,
                    out.as_mut_ptr(),
                )
            },
            InvalidState,
            "plaintext"
        );
        // ... but INVALID_LENGTH for aad, salt and info.
        assert_eq!(
            unsafe {
                shawncore_crypto_aead_encrypt(
                    enc.as_ptr(),
                    mac_key.as_ptr(),
                    nonce.as_ptr(),
                    null,
                    1,
                    data.as_ptr(),
                    buf.as_mut_ptr(),
                    4,
                    out.as_mut_ptr(),
                )
            },
            InvalidLength,
            "aad"
        );
        assert_eq!(
            unsafe {
                shawncore_crypto_session_manager_finalize_handshake(
                    manager.as_mut_ptr(),
                    &x,
                    &kem_ct,
                    null,
                    1,
                    null,
                    0,
                )
            },
            InvalidLength,
            "salt"
        );
        // NULL or misaligned object pointers: INVALID_STATE, except the session packet functions.
        assert_eq!(
            unsafe {
                shawncore_crypto_session_manager_finalize_handshake(
                    core::ptr::null_mut(),
                    &x,
                    &kem_ct,
                    null,
                    0,
                    null,
                    0,
                )
            },
            InvalidState
        );
        let mut nonce_out = [0u8; 12];
        let misaligned = core::ptr::without_provenance_mut::<SessionManager>(1);
        for manager_ptr in [core::ptr::null_mut(), misaligned] {
            assert_eq!(
                unsafe {
                    shawncore_crypto_session_manager_encrypt_packet(
                        manager_ptr,
                        null,
                        0,
                        data.as_ptr(),
                        buf.as_mut_ptr(),
                        4,
                        nonce_out.as_mut_ptr(),
                        out.as_mut_ptr(),
                    )
                },
                InvalidLength,
                "packet functions report every rejected argument as INVALID_LENGTH"
            );
        }
        // A request beyond the HKDF output limit is an HKDF error and zeroes the output.
        let mut long = std::vec![0xAAu8; 255 * 48 + 1];
        assert_eq!(
            unsafe {
                shawncore_crypto_hkdf_expand_sha384(
                    key.as_ptr(),
                    null,
                    0,
                    long.as_mut_ptr(),
                    long.len(),
                )
            },
            HkdfError
        );
        assert!(long.iter().all(|&byte| byte == 0));
    }

    #[test]
    fn repeated_init_zeroize_and_destroy_are_deterministic() {
        crate::test_support::install_callbacks();
        let mut manager = MaybeUninit::<SessionManager>::uninit();
        let m = manager.as_mut_ptr();
        let mut buf = [0u8; 4];
        let (mut nonce, mut tag) = ([0u8; 12], [0u8; 48]);
        let ok = ShawncoreCryptoErr::Success;

        assert_eq!(unsafe { shawncore_crypto_session_manager_init(m) }, ok);
        assert_eq!(unsafe { shawncore_crypto_session_manager_zeroize(m) }, ok);
        assert_eq!(unsafe { shawncore_crypto_session_manager_zeroize(m) }, ok);
        assert_eq!(unsafe { shawncore_crypto_session_manager_destroy(m) }, ok);
        assert_eq!(unsafe { shawncore_crypto_session_manager_destroy(m) }, ok);
        assert_eq!(
            unsafe {
                shawncore_crypto_session_manager_encrypt_packet(
                    m,
                    core::ptr::null(),
                    0,
                    [0u8; 4].as_ptr(),
                    buf.as_mut_ptr(),
                    4,
                    nonce.as_mut_ptr(),
                    tag.as_mut_ptr(),
                )
            },
            ShawncoreCryptoErr::InvalidState,
            "a destroyed session carries no traffic"
        );
        // Re-initialization after destroy yields a fresh, empty manager.
        assert_eq!(unsafe { shawncore_crypto_session_manager_init(m) }, ok);
        assert_eq!(unsafe { shawncore_crypto_session_manager_destroy(m) }, ok);
    }
}
