#![deny(clippy::pedantic, clippy::nursery)]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

//! Foreign Function Interface (FFI) for the Cryptographic Stack.
//! Provides safe, opaque C-callable boundaries for the MarTac host OS.
//! Prevents cross-boundary Undefined Behavior (UB) by encapsulating all
//! complex Rust types and returning C-compatible error codes.

use crate::aead_wrapper::{aead_decrypt, aead_encrypt, hkdf_expand_sha384, hmac_sha384};
use crate::entropy_pool::{GLOBAL_ENTROPY_POOL, GLOBAL_ENTROPY_QUEUE};
use crate::ffi_error::ShawncoreCryptoErr;
use crate::ml_dsa_wrapper::{
    ml_dsa_keygen, ml_dsa_sign, ml_dsa_verify, PublicKey87, Signature87, SigningKey87,
};
use crate::ml_kem_wrapper::{
    ml_kem_decapsulate, ml_kem_encapsulate, ml_kem_keygen, Ciphertext1024, DecapsKey1024,
    PublicKey1024, SharedKey1024,
};
use crate::session_manager::SessionManager;
use crate::x25519_wrapper::{
    x25519_diffie_hellman, x25519_keygen, X25519Public, X25519Secret, X25519SharedSecret,
};

// ============================================================================
// Session Manager FFI
// ============================================================================

/// Returns the memory size required to allocate a `SessionManager`.
#[no_mangle]
pub unsafe extern "C" fn shawncore_crypto_session_manager_sizeof() -> usize {
    core::mem::size_of::<SessionManager>()
}

/// Returns the memory alignment required to allocate a `SessionManager`.
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
    ) || ranges_overlap(
        entropy,
        96,
        out_ml_kem_pk,
        core::mem::size_of::<PublicKey1024>(),
    ) || ranges_overlap(
        entropy,
        96,
        out_x25519_pk,
        core::mem::size_of::<X25519Public>(),
    ) {
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

    match manager_ref.finalize_handshake(
        peer_x25519_pk_ref,
        ml_kem_ct_ref,
        salt_slice,
        info_slice,
    ) {
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
        out_my_x25519_pk,
        core::mem::size_of::<X25519Public>(),
        peer_x25519_pk,
        core::mem::size_of::<X25519Public>(),
    ) || ranges_overlap(
        out_ct,
        core::mem::size_of::<Ciphertext1024>(),
        peer_x25519_pk,
        core::mem::size_of::<X25519Public>(),
    ) || ranges_overlap(
        out_my_x25519_pk,
        core::mem::size_of::<X25519Public>(),
        peer_ml_kem_pk,
        core::mem::size_of::<PublicKey1024>(),
    ) || ranges_overlap(
        out_ct,
        core::mem::size_of::<Ciphertext1024>(),
        manager,
        core::mem::size_of::<SessionManager>(),
    ) || ranges_overlap(
        out_my_x25519_pk,
        core::mem::size_of::<X25519Public>(),
        manager,
        core::mem::size_of::<SessionManager>(),
    ) || ranges_overlap(out_ct, core::mem::size_of::<Ciphertext1024>(), entropy, 64)
        || ranges_overlap(
            out_my_x25519_pk,
            core::mem::size_of::<X25519Public>(),
            entropy,
            64,
        )
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
            salt,
            salt_len,
        )
        || ranges_overlap(
            out_my_x25519_pk,
            core::mem::size_of::<X25519Public>(),
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

    match manager_ref.encapsulate_for_peer(
        peer_ml_kem_pk_ref,
        peer_x25519_pk_ref,
        entropy_ref,
        salt_slice,
        info_slice,
    ) {
        Ok((ct, my_x25519_pk)) => {
            unsafe {
                core::ptr::write(out_ct, ct);
                core::ptr::write(out_my_x25519_pk, my_x25519_pk);
            }
            ShawncoreCryptoErr::Success
        }
        Err(e) => e.into(),
    }
}

/// Retrieves the active 32-byte session key.
///
/// # Safety
/// `manager` and `out_key` must be valid, non-null pointers. `out_key` must point to 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn shawncore_crypto_session_manager_get_tx_key(
    manager: *const SessionManager,
    out_key: *mut u8,
) -> ShawncoreCryptoErr {
    if manager.is_null() || out_key.is_null() {
        return ShawncoreCryptoErr::InvalidState;
    }
    if ranges_overlap(manager, core::mem::size_of::<SessionManager>(), out_key, 32) {
        return ShawncoreCryptoErr::InvalidLength;
    }

    let manager_ref = unsafe { &*manager };
    let out_key_ref = unsafe { &mut *(out_key as *mut [u8; 32]) };

    match manager_ref.get_tx_key(out_key_ref) {
        Ok(_) => ShawncoreCryptoErr::Success,
        Err(e) => e.into(),
    }
}

/// Retrieves the active 32-byte receive key.
///
/// # Safety
/// `manager` and `out_key` must be valid, non-null pointers. `out_key` must point to 32 bytes.
#[no_mangle]
pub unsafe extern "C" fn shawncore_crypto_session_manager_get_rx_key(
    manager: *const SessionManager,
    out_key: *mut u8,
) -> ShawncoreCryptoErr {
    if manager.is_null() || out_key.is_null() {
        return ShawncoreCryptoErr::InvalidState;
    }

    if ranges_overlap(manager, core::mem::size_of::<SessionManager>(), out_key, 32) {
        return ShawncoreCryptoErr::InvalidLength;
    }

    let manager_ref = unsafe { &*manager };
    let out_key_ref = unsafe { &mut *(out_key as *mut [u8; 32]) };

    match manager_ref.get_rx_key(out_key_ref) {
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
/// All pointers must be valid and non-null. `msg` must be valid for `msg_len`.
#[no_mangle]
pub unsafe extern "C" fn shawncore_crypto_ml_dsa_sign(
    sk: *const SigningKey87,
    msg: *const u8,
    msg_len: usize,
    out_sig: *mut Signature87,
) -> ShawncoreCryptoErr {
    if sk.is_null() || msg.is_null() || out_sig.is_null() {
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
    let msg_slice = unsafe { core::slice::from_raw_parts(msg, msg_len) };

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
/// All pointers must be valid and non-null. `msg` must be valid for `msg_len`.
#[no_mangle]
pub unsafe extern "C" fn shawncore_crypto_ml_dsa_verify(
    pk: *const PublicKey87,
    msg: *const u8,
    msg_len: usize,
    sig: *const Signature87,
) -> ShawncoreCryptoErr {
    if pk.is_null() || msg.is_null() || sig.is_null() {
        return ShawncoreCryptoErr::InvalidState;
    }

    let pk_ref = unsafe { &*pk };
    let sig_ref = unsafe { &*sig };
    let msg_slice = unsafe { core::slice::from_raw_parts(msg, msg_len) };

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
/// All pointers must be valid and non-null. `key` must point to 32 bytes. `data` must be valid for `data_len`.
/// `out_mac` must point to 48 bytes.
#[no_mangle]
pub unsafe extern "C" fn shawncore_crypto_hmac_sha384(
    key: *const u8,
    data: *const u8,
    data_len: usize,
    out_mac: *mut u8,
) -> ShawncoreCryptoErr {
    if key.is_null() || data.is_null() || out_mac.is_null() {
        return ShawncoreCryptoErr::InvalidState;
    }
    if ranges_overlap(out_mac, 48, key, 32) || ranges_overlap(out_mac, 48, data, data_len) {
        return ShawncoreCryptoErr::InvalidLength;
    }

    let key_slice = unsafe { core::slice::from_raw_parts(key, 32) };
    let data_slice = unsafe { core::slice::from_raw_parts(data, data_len) };
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
    if prk.is_null() || (info.is_null() && info_len > 0) || out.is_null() {
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
    let out_slice = unsafe { core::slice::from_raw_parts_mut(out, out_len) };

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
/// Input and output regions must not overlap.
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
        || plaintext.is_null()
        || ciphertext.is_null()
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
    let pt_slice = unsafe { core::slice::from_raw_parts(plaintext, data_len) };
    let ct_slice = unsafe { core::slice::from_raw_parts_mut(ciphertext, data_len) };
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
        || ciphertext.is_null()
        || mac.is_null()
        || plaintext.is_null()
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
    let ct_slice = unsafe { core::slice::from_raw_parts(ciphertext, data_len) };
    let mac_ref = unsafe { &*(mac as *const [u8; 48]) };
    let pt_slice = unsafe { core::slice::from_raw_parts_mut(plaintext, data_len) };

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
#[no_mangle]
pub unsafe extern "C" fn shawncore_crypto_entropy_push(chunk: *const u8) -> ShawncoreCryptoErr {
    if chunk.is_null() {
        return ShawncoreCryptoErr::InvalidState;
    }

    let chunk_ref = unsafe { &*(chunk as *const [u8; 32]) };

    match GLOBAL_ENTROPY_QUEUE.push(chunk_ref) {
        Ok(_) => ShawncoreCryptoErr::Success,
        Err(e) => e.into(),
    }
}

/// Drains the global entropy queue and mixes it into the global entropy pool.
///
/// # WARNING: NMI DEADLOCK VECTOR
///
/// `shawncore_crypto_entropy_push` is lock-free and safe for use from any ISR.
/// This function acquires a spinlock and MUST NOT be called from a Non-Maskable
/// Interrupt (NMI) or ARM Fast Interrupt (FIQ). Call it from a standard thread
/// or Deferred Procedure Call (DPC) context after the interrupt has been deferred.
#[no_mangle]
pub unsafe extern "C" fn shawncore_crypto_entropy_mix() -> ShawncoreCryptoErr {
    GLOBAL_ENTROPY_POOL.mix_entropy();
    ShawncoreCryptoErr::Success
}
