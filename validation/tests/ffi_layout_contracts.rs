// # shawncore-ffi-layout-contracts-v2
// Host-side ABI layout contracts. These compare exported C ABI size/alignment
// functions against the exact public Rust types they describe.

use shawncore_pq_crypto::ffi::{
    shawncore_crypto_ml_dsa_publickey_alignof, shawncore_crypto_ml_dsa_publickey_sizeof,
    shawncore_crypto_ml_dsa_signature_alignof, shawncore_crypto_ml_dsa_signature_sizeof,
    shawncore_crypto_ml_dsa_signingkey_alignof, shawncore_crypto_ml_dsa_signingkey_sizeof,
    shawncore_crypto_ml_kem_ciphertext_alignof, shawncore_crypto_ml_kem_ciphertext_sizeof,
    shawncore_crypto_ml_kem_decapskey_alignof, shawncore_crypto_ml_kem_decapskey_sizeof,
    shawncore_crypto_ml_kem_publickey_alignof, shawncore_crypto_ml_kem_publickey_sizeof,
    shawncore_crypto_ml_kem_sharedkey_alignof, shawncore_crypto_ml_kem_sharedkey_sizeof,
    shawncore_crypto_session_manager_alignof, shawncore_crypto_session_manager_sizeof,
    shawncore_crypto_x25519_publickey_alignof, shawncore_crypto_x25519_publickey_sizeof,
    shawncore_crypto_x25519_secret_alignof, shawncore_crypto_x25519_secret_sizeof,
    shawncore_crypto_x25519_sharedsecret_alignof, shawncore_crypto_x25519_sharedsecret_sizeof,
};
use shawncore_pq_crypto::ml_dsa_wrapper::{PublicKey87, Signature87, SigningKey87};
use shawncore_pq_crypto::ml_kem_wrapper::{
    Ciphertext1024, DecapsKey1024, PublicKey1024, SharedKey1024,
};
use shawncore_pq_crypto::session_manager::SessionManager;
use shawncore_pq_crypto::x25519_wrapper::{X25519Public, X25519Secret, X25519SharedSecret};
use shawncore_rtos_sync::ffi::{
    shawncore_rtos_fft_result_alignof, shawncore_rtos_fft_result_sizeof,
    shawncore_rtos_ringbuffer_ew_slot_alignof, shawncore_rtos_ringbuffer_ew_slot_sizeof,
    shawncore_rtos_spsc_fft_slot_alignof, shawncore_rtos_spsc_fft_slot_sizeof,
    shawncore_rtos_spsc_telemetry_slot_alignof, shawncore_rtos_spsc_telemetry_slot_sizeof,
    shawncore_rtos_tcb_alignof, shawncore_rtos_tcb_sizeof, shawncore_rtos_telemetry_event_alignof,
    shawncore_rtos_telemetry_event_sizeof, EwCommand, FftResult, SpscQueueFftSlot,
    SpscQueueTelemetrySlot,
};
use shawncore_rtos_sync::spsc_queue::CacheAlignedSlot;
use shawncore_rtos_sync::tcb::Tcb;
use shawncore_rtos_sync::telemetry_queue::TelemetryEvent;

fn assert_layout(
    size: usize,
    align: usize,
    expected_size: usize,
    expected_align: usize,
    label: &str,
) {
    assert_eq!(size, expected_size, "{label}: size mismatch");
    assert_eq!(align, expected_align, "{label}: alignment mismatch");
    assert!(
        align.is_power_of_two(),
        "{label}: alignment is not a power of two"
    );
    assert!(size >= align, "{label}: size is smaller than alignment");
    assert_eq!(
        size % align,
        0,
        "{label}: size is not a multiple of alignment"
    );
}

fn assert_ffi_layout(
    size_fn: extern "C" fn() -> usize,
    align_fn: extern "C" fn() -> usize,
    expected_size: usize,
    expected_align: usize,
    label: &str,
) {
    assert_layout(size_fn(), align_fn(), expected_size, expected_align, label);
}

unsafe fn assert_unsafe_ffi_layout(
    size_fn: unsafe extern "C" fn() -> usize,
    align_fn: unsafe extern "C" fn() -> usize,
    expected_size: usize,
    expected_align: usize,
    label: &str,
) {
    assert_layout(size_fn(), align_fn(), expected_size, expected_align, label);
}

#[test]
fn crypto_ffi_layouts_match_rust_types() {
    assert_ffi_layout(
        shawncore_crypto_ml_kem_publickey_sizeof,
        shawncore_crypto_ml_kem_publickey_alignof,
        core::mem::size_of::<PublicKey1024>(),
        core::mem::align_of::<PublicKey1024>(),
        "ML-KEM PublicKey1024",
    );
    assert_ffi_layout(
        shawncore_crypto_ml_kem_decapskey_sizeof,
        shawncore_crypto_ml_kem_decapskey_alignof,
        core::mem::size_of::<DecapsKey1024>(),
        core::mem::align_of::<DecapsKey1024>(),
        "ML-KEM DecapsKey1024",
    );
    assert_ffi_layout(
        shawncore_crypto_ml_kem_sharedkey_sizeof,
        shawncore_crypto_ml_kem_sharedkey_alignof,
        core::mem::size_of::<SharedKey1024>(),
        core::mem::align_of::<SharedKey1024>(),
        "ML-KEM SharedKey1024",
    );
    assert_ffi_layout(
        shawncore_crypto_ml_kem_ciphertext_sizeof,
        shawncore_crypto_ml_kem_ciphertext_alignof,
        core::mem::size_of::<Ciphertext1024>(),
        core::mem::align_of::<Ciphertext1024>(),
        "ML-KEM Ciphertext1024",
    );
    assert_ffi_layout(
        shawncore_crypto_ml_dsa_publickey_sizeof,
        shawncore_crypto_ml_dsa_publickey_alignof,
        core::mem::size_of::<PublicKey87>(),
        core::mem::align_of::<PublicKey87>(),
        "ML-DSA PublicKey87",
    );
    assert_ffi_layout(
        shawncore_crypto_ml_dsa_signingkey_sizeof,
        shawncore_crypto_ml_dsa_signingkey_alignof,
        core::mem::size_of::<SigningKey87>(),
        core::mem::align_of::<SigningKey87>(),
        "ML-DSA SigningKey87",
    );
    assert_ffi_layout(
        shawncore_crypto_ml_dsa_signature_sizeof,
        shawncore_crypto_ml_dsa_signature_alignof,
        core::mem::size_of::<Signature87>(),
        core::mem::align_of::<Signature87>(),
        "ML-DSA Signature87",
    );
    assert_ffi_layout(
        shawncore_crypto_x25519_publickey_sizeof,
        shawncore_crypto_x25519_publickey_alignof,
        core::mem::size_of::<X25519Public>(),
        core::mem::align_of::<X25519Public>(),
        "X25519 Public",
    );
    assert_ffi_layout(
        shawncore_crypto_x25519_secret_sizeof,
        shawncore_crypto_x25519_secret_alignof,
        core::mem::size_of::<X25519Secret>(),
        core::mem::align_of::<X25519Secret>(),
        "X25519 Secret",
    );
    assert_ffi_layout(
        shawncore_crypto_x25519_sharedsecret_sizeof,
        shawncore_crypto_x25519_sharedsecret_alignof,
        core::mem::size_of::<X25519SharedSecret>(),
        core::mem::align_of::<X25519SharedSecret>(),
        "X25519 SharedSecret",
    );
    unsafe {
        assert_unsafe_ffi_layout(
            shawncore_crypto_session_manager_sizeof,
            shawncore_crypto_session_manager_alignof,
            core::mem::size_of::<SessionManager>(),
            core::mem::align_of::<SessionManager>(),
            "SessionManager",
        );
    }
}

#[test]
fn rtos_ffi_layouts_match_rust_types() {
    assert_ffi_layout(
        shawncore_rtos_tcb_sizeof,
        shawncore_rtos_tcb_alignof,
        core::mem::size_of::<Tcb>(),
        core::mem::align_of::<Tcb>(),
        "Tcb",
    );
    assert_ffi_layout(
        shawncore_rtos_telemetry_event_sizeof,
        shawncore_rtos_telemetry_event_alignof,
        core::mem::size_of::<TelemetryEvent>(),
        core::mem::align_of::<TelemetryEvent>(),
        "TelemetryEvent",
    );
    assert_ffi_layout(
        shawncore_rtos_fft_result_sizeof,
        shawncore_rtos_fft_result_alignof,
        core::mem::size_of::<FftResult>(),
        core::mem::align_of::<FftResult>(),
        "FftResult",
    );
    assert_ffi_layout(
        shawncore_rtos_spsc_telemetry_slot_sizeof,
        shawncore_rtos_spsc_telemetry_slot_alignof,
        core::mem::size_of::<SpscQueueTelemetrySlot>(),
        core::mem::align_of::<SpscQueueTelemetrySlot>(),
        "SpscQueueTelemetrySlot",
    );
    assert_ffi_layout(
        shawncore_rtos_spsc_fft_slot_sizeof,
        shawncore_rtos_spsc_fft_slot_alignof,
        core::mem::size_of::<SpscQueueFftSlot>(),
        core::mem::align_of::<SpscQueueFftSlot>(),
        "SpscQueueFftSlot",
    );
    assert_ffi_layout(
        shawncore_rtos_ringbuffer_ew_slot_sizeof,
        shawncore_rtos_ringbuffer_ew_slot_alignof,
        core::mem::size_of::<CacheAlignedSlot<EwCommand>>(),
        core::mem::align_of::<CacheAlignedSlot<EwCommand>>(),
        "CacheAlignedSlot<EwCommand>",
    );
}
