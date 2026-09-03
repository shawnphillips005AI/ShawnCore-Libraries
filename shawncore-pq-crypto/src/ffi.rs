#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! Foreign Function Interface (FFI) for the Cryptographic Stack.
//! Defines opaque C-callable boundaries for the MarTac host OS. The host must
//! uphold each exported function's documented pointer, lifetime, alignment,
//! ownership, and concurrency preconditions.

use crate::aead_wrapper::{aead_decrypt, aead_encrypt, hkdf_expand_sha384, hmac_sha384};
use crate::entropy_pool::{GLOBAL_ENTROPY_POOL, GLOBAL_ENTROPY_QUEUE};
use crate::error::CryptoError;
use crate::ffi_error::ShawncoreCryptoErr;
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
opaque_type_layout!(
    PublicKey87,
    shawncore_crypto_ml_dsa_publickey_sizeof,
    shawncore_crypto_ml_dsa_publickey_alignof
);
opaque_type_layout!(
    SigningKey87,
    shawncore_crypto_ml_dsa_signingkey_sizeof,
    shawncore_crypto_ml_dsa_signingkey_alignof
);
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
    if (salt.is_null() && salt_len > 0) || (info.is_null() && info_len > 0) {
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
    if (salt.is_null() && salt_len > 0) || (info.is_null() && info_len > 0) {
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

    let out_ct_ref = unsafe { &mut *out_ct };
    let out_my_x25519_pk_ref = unsafe { &mut *out_my_x25519_pk };
    match manager_ref.encapsulate_for_peer(
        peer_ml_kem_pk_ref,
        peer_x25519_pk_ref,
        entropy_ref,
        salt_slice,
        info_slice,
        out_ct_ref,
        out_my_x25519_pk_ref,
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
pub unsafe extern "C" fn shawncore_crypto_session_manager_zeroize(
    manager: *mut SessionManager,
) -> ShawncoreCryptoErr {
    if manager.is_null() {
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
        || (plaintext.is_null() && data_len > 0)
        || (ciphertext.is_null() && data_len > 0)
        || out_nonce.is_null()
        || out_tag.is_null()
        || (aad.is_null() && aad_len > 0)
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
        || (ciphertext.is_null() && data_len > 0)
        || nonce.is_null()
        || tag.is_null()
        || (plaintext.is_null() && data_len > 0)
        || (aad.is_null() && aad_len > 0)
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
/// All pointers must be valid and non-null. `entropy` must point to exactly 64 bytes.
/// Output regions must be distinct and must not overlap `entropy`.
#[no_mangle]
pub unsafe extern "C" fn shawncore_crypto_ml_kem_keygen(
    entropy: *const u8,
    out_pk: *mut PublicKey1024,
    out_dk: *mut DecapsKey1024,
) -> ShawncoreCryptoErr {
    if entropy.is_null() || out_pk.is_null() || out_dk.is_null() {
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
    unsafe {
        core::ptr::drop_in_place(dk);
    }
    ShawncoreCryptoErr::Success
}

/// Encapsulates a shared secret using ML-KEM-1024.
///
/// # Safety
/// All pointers must be valid and non-null. `entropy` must point to exactly 32 bytes.
/// Output regions must be distinct and must not overlap `pk` or `entropy`.
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
/// All pointers must be valid and non-null.
#[no_mangle]
pub unsafe extern "C" fn shawncore_crypto_ml_kem_decapsulate(
    dk: *const DecapsKey1024,
    ct: *const Ciphertext1024,
    out_shared: *mut SharedKey1024,
) -> ShawncoreCryptoErr {
    if dk.is_null() || ct.is_null() || out_shared.is_null() {
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
/// All pointers must be valid and non-null. `seed` must point to exactly 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn shawncore_crypto_ml_dsa_keygen(
    seed: *const u8,
    out_pk: *mut PublicKey87,
    out_sk: *mut SigningKey87,
) -> ShawncoreCryptoErr {
    if seed.is_null() || out_pk.is_null() || out_sk.is_null() {
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
pub unsafe extern "C" fn shawncore_crypto_ml_dsa_signingkey_destroy(
    sk: *mut SigningKey87,
) -> ShawncoreCryptoErr {
    if sk.is_null() {
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
/// `sk` and `out_sig` must be valid and non-null. `msg` must be valid for `msg_len`
/// and may be null when `msg_len` is zero.
#[no_mangle]
pub unsafe extern "C" fn shawncore_crypto_ml_dsa_sign(
    sk: *const SigningKey87,
    msg: *const u8,
    msg_len: usize,
    out_sig: *mut Signature87,
) -> ShawncoreCryptoErr {
    if sk.is_null() || (msg.is_null() && msg_len > 0) || out_sig.is_null() {
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
pub unsafe extern "C" fn shawncore_crypto_ml_dsa_verify(
    pk: *const PublicKey87,
    msg: *const u8,
    msg_len: usize,
    sig: *const Signature87,
) -> ShawncoreCryptoErr {
    if pk.is_null() || (msg.is_null() && msg_len > 0) || sig.is_null() {
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
/// All pointers must be valid and non-null. `entropy` must point to exactly 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn shawncore_crypto_x25519_keygen(
    entropy: *const u8,
    out_pk: *mut X25519Public,
    out_sk: *mut X25519Secret,
) -> ShawncoreCryptoErr {
    if entropy.is_null() || out_pk.is_null() || out_sk.is_null() {
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
    unsafe {
        core::ptr::drop_in_place(sk);
    }
    ShawncoreCryptoErr::Success
}

/// Performs an X25519 Diffie-Hellman key exchange.
///
/// # Safety
/// All pointers must be valid and non-null.
#[no_mangle]
pub unsafe extern "C" fn shawncore_crypto_x25519_diffie_hellman(
    sk: *const X25519Secret,
    peer_pk: *const X25519Public,
    out_shared: *mut X25519SharedSecret,
) -> ShawncoreCryptoErr {
    if sk.is_null() || peer_pk.is_null() || out_shared.is_null() {
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

fn ml_dsa_signature_encode(value: &Signature87) -> [u8; ML_DSA_SIGNATURE_BYTES] {
    value.0
}

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
wire_codec!(
    PublicKey87,
    ML_DSA_PUBLICKEY_BYTES,
    shawncore_crypto_ml_dsa_publickey_encoded_len,
    shawncore_crypto_ml_dsa_publickey_to_bytes,
    shawncore_crypto_ml_dsa_publickey_from_bytes,
    PublicKey87::to_bytes,
    PublicKey87::from_bytes
);
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

fn ranges_overlap<T, U>(
    first: *const T,
    first_len: usize,
    second: *const U,
    second_len: usize,
) -> bool {
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
    if aad.is_null() && aad_len > 0 {
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
    if aad.is_null() && aad_len > 0 {
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

#[cfg(test)]
mod wire_codec_tests {
    use super::*;
    use crate::ffi_callbacks::shawncore_crypto_register_cache_flush;
    use core::mem::MaybeUninit;

    extern "C" fn test_cache_flush(_: *const u8, _: usize) {}

    fn install_callbacks() {
        unsafe { shawncore_crypto_register_cache_flush(Some(test_cache_flush)) };
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
    fn ml_dsa_publickey_and_signature_survive_a_wire_round_trip() {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(ml_dsa_wire_round_trip)
            .expect("test thread must spawn")
            .join()
            .expect("test thread must not panic");
    }

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
        assert_eq!(shawncore_crypto_ml_dsa_publickey_encoded_len(), 2592);
        assert_eq!(shawncore_crypto_ml_dsa_signature_encoded_len(), 4627);
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
