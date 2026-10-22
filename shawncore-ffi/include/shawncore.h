// Copyright (c) 2026 Shawn Phillips. All Rights Reserved.
// Dual-licensed under AGPLv3 and Commercial License.

#ifndef SHAWNCORE_H
#define SHAWNCORE_H

/*
 * C99/C11 and C++ interface for libshawncore_ffi.a.
 *
 * Opaque objects must be allocated with the matching sizeof/alignof functions,
 * initialized exactly once, and destroyed only after concurrent users stop.
 * Host code owns pointer validity, storage lifetime, callback lifetime, and
 * platform cache/DMA maintenance.
 *
 * A pointer paired with a zero length may be NULL, and a zero-length range is
 * never treated as overlapping anything; all other data pointers must be
 * non-NULL, correctly aligned, and valid for the complete call.
 * Unless a function explicitly states otherwise, input, output, opaque-control,
 * and backing-storage ranges must be mutually non-overlapping. Queue and DMA
 * initializers require separate control-object and backing-storage allocations.
 * Callback registration accepts NULL to clear a callback. Register or replace
 * callbacks only while no operation can invoke them. Registered callbacks must
 * remain valid until all possible invocations have stopped; they must not
 * unwind, throw, longjmp, re-enter a ShawnCore function, or otherwise escape
 * through Rust. Registration publishes only the function pointer: the library
 * keeps no callback context and cannot extend the lifetime of the code, so
 * quiescence is the host's duty. Each library (shawncore_crypto_*, shawncore_rtos_*)
 * has its own registry; register what each one needs. A required callback that is
 * missing halts the caller after invoking that library's panic hook.
 * The cache-flush callback is never invoked with a zero-length range.
 *
 * What the library can and cannot check. It rejects NULL, misalignment, lengths
 * outside the limits below, and overlapping ranges, using checked arithmetic. It
 * cannot tell whether a non-NULL address is mapped, live, initialized, or large
 * enough: that is the caller's guarantee, and the library never reads or writes
 * beyond the length it is given. An address range that wraps the address space is
 * rejected as overlapping.
 *
 * Length limits (checked before any memory is read or any cryptography runs;
 * violation returns *_INVALID_LENGTH and changes nothing):
 *   - every pointer+length pair: length <= PTRDIFF_MAX (INTPTR_MAX), the largest
 *     range a Rust slice, or a C object, may have. The caller owns that much valid
 *     memory whenever the length is nonzero.
 *   - packet and AEAD data_len: <= 64 * (2^32 - 1) bytes, the ChaCha20 limit for
 *     one key and nonce. aad_len has no cryptographic limit beyond the above.
 *   - app_info_len (authenticated handshake): <= UINT32_MAX, the width of its
 *     transcript length prefix.
 *   - hkdf_expand_sha384 out_len: up to 255 * 48 = 12240 bytes succeeds; a longer
 *     request fails with HKDF_ERROR and the output is zeroed. salt, info and msg
 *     lengths have no protocol limit; processing time is linear in them.
 *
 * Error codes. A NULL or misaligned object pointer returns INVALID_STATE (crypto) or
 * INVALID_MEMORY (rtos). A NULL data pointer paired with a nonzero length returns
 * INVALID_STATE from hmac, hkdf, ml_dsa sign/verify and for the plaintext, ciphertext and tag
 * of the raw aead functions, and INVALID_LENGTH for aad and for the handshake salt, info and
 * app_info. The session
 * packet functions are the exception: they return INVALID_LENGTH for every rejected argument,
 * including a NULL or misaligned manager. Overlap, a length outside the limits above, and an
 * address range that wraps the address space are INVALID_LENGTH everywhere. Functions that
 * return a value instead of a status return 0 (rtos tcb_get_rsp) or the caller's rsp unchanged
 * (rtos scheduler_tick) for a NULL or misaligned argument. An output is defined only after
 * SUCCESS, with two deliberate exceptions: an authenticated decrypt, session or raw, that
 * fails MAC verification overwrites the plaintext buffer with zeros, and an oversized hkdf
 * request zeroes its output. A decrypt rejected earlier (no session, replayed or out-of-window
 * nonce, bad length) leaves the plaintext buffer untouched.
 */

#include <stddef.h>
#include <stdint.h>

/* Keep in step with the crate version; validation/tests/ffi_layout_contracts.rs checks it. */
#define SHAWNCORE_VERSION_MAJOR 12
#define SHAWNCORE_VERSION_MINOR 3
#define SHAWNCORE_VERSION_PATCH 11
#define SHAWNCORE_VERSION_STRING "12.3.11"

#if defined(_MSC_VER)
#define SHAWNCORE_ALIGNAS(bytes) __declspec(align(bytes))
#else
#define SHAWNCORE_ALIGNAS(bytes) __attribute__((aligned(bytes)))
#endif

/*
 * Fixed-length array parameters. C99/C11 compilers see `[static n]`, which lets
 * them diagnose null or short arguments; C++ and MSVC do not accept that syntax
 * and see a plain `[n]`. The callee's contract is the same either way.
 */
#if defined(__cplusplus) || defined(_MSC_VER)
#define SHAWNCORE_MIN_LEN(n) n
#else
#define SHAWNCORE_MIN_LEN(n) static n
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef enum shawncore_crypto_err {
    SHAWNCORE_CRYPTO_SUCCESS = 0,
    SHAWNCORE_CRYPTO_INVALID_STATE = 1,
    SHAWNCORE_CRYPTO_INVALID_LENGTH = 2,
    SHAWNCORE_CRYPTO_HKDF_ERROR = 3,
    SHAWNCORE_CRYPTO_VERIFICATION_FAILED = 4,
    SHAWNCORE_CRYPTO_ENTROPY_STARVATION = 5,
    SHAWNCORE_CRYPTO_ENTROPY_BUSY = 6,
    SHAWNCORE_CRYPTO_KEY_CONFIRMATION_FAILED = 7,
    SHAWNCORE_CRYPTO_PANIC = 99
} shawncore_crypto_err;

typedef enum shawncore_rtos_err {
    SHAWNCORE_RTOS_SUCCESS = 0,
    SHAWNCORE_RTOS_OUT_OF_MEMORY = 1,
    SHAWNCORE_RTOS_ADDRESS_OUT_OF_BOUNDS = 2,
    SHAWNCORE_RTOS_INVALID_ALIGNMENT = 3,
    SHAWNCORE_RTOS_LOCK_CONTENTION = 4,
    SHAWNCORE_RTOS_DOUBLE_FREE = 5,
    SHAWNCORE_RTOS_NOT_INITIALIZED = 6,
    SHAWNCORE_RTOS_ALREADY_INITIALIZED = 7,
    SHAWNCORE_RTOS_QUEUE_FULL = 8,
    SHAWNCORE_RTOS_INVALID_MEMORY = 9,
    SHAWNCORE_RTOS_TASK_FAULT = 10,
    SHAWNCORE_RTOS_INVALID_STATE = 11,
    SHAWNCORE_RTOS_QUEUE_EMPTY = 12,
    SHAWNCORE_RTOS_PANIC = 99
} shawncore_rtos_err;

typedef struct shawncore_crypto_session_manager shawncore_crypto_session_manager;
typedef struct shawncore_crypto_ml_kem_publickey shawncore_crypto_ml_kem_publickey;
typedef struct shawncore_crypto_ml_kem_decapskey shawncore_crypto_ml_kem_decapskey;
typedef struct shawncore_crypto_ml_kem_sharedkey shawncore_crypto_ml_kem_sharedkey;
typedef struct shawncore_crypto_ml_kem_ciphertext shawncore_crypto_ml_kem_ciphertext;
#ifndef SHAWNCORE_LITE
/* ML-DSA opaque types omitted from the Lite ABI. */
typedef struct shawncore_crypto_ml_dsa_publickey shawncore_crypto_ml_dsa_publickey;
typedef struct shawncore_crypto_ml_dsa_signingkey shawncore_crypto_ml_dsa_signingkey;
typedef struct shawncore_crypto_ml_dsa_signature shawncore_crypto_ml_dsa_signature;
#endif /* SHAWNCORE_LITE */
typedef struct shawncore_crypto_x25519_publickey shawncore_crypto_x25519_publickey;
typedef struct shawncore_crypto_x25519_secret shawncore_crypto_x25519_secret;
typedef struct shawncore_crypto_x25519_sharedsecret shawncore_crypto_x25519_sharedsecret;

typedef void (*shawncore_panic_callback)(void);
typedef uintptr_t (*shawncore_disable_interrupts_callback)(void);
typedef void (*shawncore_restore_interrupts_callback)(uintptr_t saved_state);
typedef void (*shawncore_cache_callback)(const uint8_t *ptr, size_t len);
typedef uint64_t (*shawncore_monotonic_clock_callback)(void);
typedef void (*shawncore_watchdog_callback)(void);

void shawncore_crypto_register_panic_hook(shawncore_panic_callback callback);
void shawncore_crypto_register_disable_interrupts(shawncore_disable_interrupts_callback callback);
void shawncore_crypto_register_restore_interrupts(shawncore_restore_interrupts_callback callback);
void shawncore_crypto_register_cache_flush(shawncore_cache_callback callback);

/* Software known-answer self-test: SHA-384, HMAC-SHA384, HKDF-Expand-SHA384, X25519, ChaCha20 keystream.
 * Register the cache-flush callback first: the HMAC/HKDF/AEAD paths call it, and an unregistered callback halts.
 * No ML-KEM or ML-DSA vector is included. This is not FIPS 140-3 certification or a hardware POST. */
shawncore_crypto_err shawncore_crypto_self_test(void);

/* Session input buffers and mutable session/output objects must not overlap. */
size_t shawncore_crypto_session_manager_sizeof(void);
size_t shawncore_crypto_session_manager_alignof(void);
shawncore_crypto_err shawncore_crypto_session_manager_init(shawncore_crypto_session_manager *manager);
shawncore_crypto_err shawncore_crypto_session_manager_destroy(shawncore_crypto_session_manager *manager);
shawncore_crypto_err shawncore_crypto_session_manager_initiate_handshake(
    shawncore_crypto_session_manager *manager,
    const uint8_t entropy[SHAWNCORE_MIN_LEN(96)],
    shawncore_crypto_ml_kem_publickey *out_ml_kem_pk,
    shawncore_crypto_x25519_publickey *out_x25519_pk);
shawncore_crypto_err shawncore_crypto_session_manager_finalize_handshake(
    shawncore_crypto_session_manager *manager,
    const shawncore_crypto_x25519_publickey *peer_x25519_pk,
    const shawncore_crypto_ml_kem_ciphertext *ml_kem_ct,
    const uint8_t *salt,
    size_t salt_len,
    const uint8_t *info,
    size_t info_len);
shawncore_crypto_err shawncore_crypto_session_manager_encapsulate_for_peer(
    shawncore_crypto_session_manager *manager,
    const shawncore_crypto_ml_kem_publickey *peer_ml_kem_pk,
    const shawncore_crypto_x25519_publickey *peer_x25519_pk,
    const uint8_t entropy[SHAWNCORE_MIN_LEN(64)],
    const uint8_t *salt,
    size_t salt_len,
    const uint8_t *info,
    size_t info_len,
    shawncore_crypto_ml_kem_ciphertext *out_ct,
    shawncore_crypto_x25519_publickey *out_my_x25519_pk);
shawncore_crypto_err shawncore_crypto_session_manager_zeroize(shawncore_crypto_session_manager *manager);
shawncore_crypto_err shawncore_crypto_session_manager_encrypt_packet(
    shawncore_crypto_session_manager *manager,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *plaintext,
    uint8_t *ciphertext,
    size_t data_len,
    uint8_t out_nonce[SHAWNCORE_MIN_LEN(12)],
    uint8_t out_tag[SHAWNCORE_MIN_LEN(48)]);
shawncore_crypto_err shawncore_crypto_session_manager_decrypt_packet(
    shawncore_crypto_session_manager *manager,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *ciphertext,
    size_t data_len,
    const uint8_t nonce[SHAWNCORE_MIN_LEN(12)],
    const uint8_t tag[SHAWNCORE_MIN_LEN(48)],
    uint8_t *plaintext);

size_t shawncore_crypto_ml_kem_publickey_sizeof(void);
size_t shawncore_crypto_ml_kem_publickey_alignof(void);
size_t shawncore_crypto_ml_kem_decapskey_sizeof(void);
size_t shawncore_crypto_ml_kem_decapskey_alignof(void);
size_t shawncore_crypto_ml_kem_sharedkey_sizeof(void);
size_t shawncore_crypto_ml_kem_sharedkey_alignof(void);
size_t shawncore_crypto_ml_kem_ciphertext_sizeof(void);
size_t shawncore_crypto_ml_kem_ciphertext_alignof(void);
shawncore_crypto_err shawncore_crypto_ml_kem_keygen(
    const uint8_t entropy[SHAWNCORE_MIN_LEN(64)],
    shawncore_crypto_ml_kem_publickey *out_pk,
    shawncore_crypto_ml_kem_decapskey *out_dk);
shawncore_crypto_err shawncore_crypto_ml_kem_decapskey_destroy(shawncore_crypto_ml_kem_decapskey *dk);
/* Outputs must not overlap pk, entropy, or each other. */
shawncore_crypto_err shawncore_crypto_ml_kem_encapsulate(
    const shawncore_crypto_ml_kem_publickey *pk,
    const uint8_t entropy[SHAWNCORE_MIN_LEN(32)],
    shawncore_crypto_ml_kem_sharedkey *out_shared,
    shawncore_crypto_ml_kem_ciphertext *out_ct);
shawncore_crypto_err shawncore_crypto_ml_kem_decapsulate(
    const shawncore_crypto_ml_kem_decapskey *dk,
    const shawncore_crypto_ml_kem_ciphertext *ct,
    shawncore_crypto_ml_kem_sharedkey *out_shared);
shawncore_crypto_err shawncore_crypto_ml_kem_sharedkey_destroy(shawncore_crypto_ml_kem_sharedkey *shared);

#ifndef SHAWNCORE_LITE
/* ML-DSA primary C API: omitted from Lite ABI. */
size_t shawncore_crypto_ml_dsa_publickey_sizeof(void);
size_t shawncore_crypto_ml_dsa_publickey_alignof(void);
size_t shawncore_crypto_ml_dsa_signingkey_sizeof(void);
size_t shawncore_crypto_ml_dsa_signingkey_alignof(void);
size_t shawncore_crypto_ml_dsa_signature_sizeof(void);
size_t shawncore_crypto_ml_dsa_signature_alignof(void);
shawncore_crypto_err shawncore_crypto_ml_dsa_keygen(
    const uint8_t seed[SHAWNCORE_MIN_LEN(32)],
    shawncore_crypto_ml_dsa_publickey *out_pk,
    shawncore_crypto_ml_dsa_signingkey *out_sk);
shawncore_crypto_err shawncore_crypto_ml_dsa_signingkey_destroy(shawncore_crypto_ml_dsa_signingkey *sk);
shawncore_crypto_err shawncore_crypto_ml_dsa_sign(
    const shawncore_crypto_ml_dsa_signingkey *sk,
    const uint8_t *msg,
    size_t msg_len,
    shawncore_crypto_ml_dsa_signature *out_sig);
shawncore_crypto_err shawncore_crypto_ml_dsa_verify(
    const shawncore_crypto_ml_dsa_publickey *pk,
    const uint8_t *msg,
    size_t msg_len,
    const shawncore_crypto_ml_dsa_signature *sig);

/*
 * Authenticated handshake, protocol version 2 (signed transcript plus explicit key confirmation,
 * mutual). The unauthenticated functions above are unchanged and offer no peer authentication.
 * Each side holds its own ML-DSA signing key and a trust anchor (the peer's verifying key)
 * provisioned out of band. Four properties come from four mechanisms and are not interchangeable:
 * identity (signatures under role-specific FIPS 204 contexts), key agreement (the hybrid exchange,
 * whose HKDF info is the signed binding), key confirmation (HMAC-SHA384 tags under a confirmation
 * key expanded from the same PRK), and authorization (a session carries traffic only after the
 * steps above succeeded on that side).
 *
 *   key-generating side:  initiate_handshake            -> sends ml_kem_pk, x25519_pk
 *   encapsulating side:   encapsulate_authenticated_v2  -> sends ct, x25519_pk, signature, tag
 *                         (keys derived, session UNCONFIRMED: it refuses all traffic)
 *   key-generating side:  finalize_authenticated_v2     -> verifies signature, derives keys,
 *                         verifies tag, THEN installs keys; sends signature, tag
 *   encapsulating side:   confirm_peer_v2               -> verifies signature and tag, session usable
 *
 * `app_info` must be equal on both sides and is bound into the transcript. `salt` must be equal
 * too; it is NOT placed in the transcript (it may be a secret), and a mismatch is reported as
 * SHAWNCORE_CRYPTO_KEY_CONFIRMATION_FAILED. Error meaning: VERIFICATION_FAILED is a bad signature
 * or identity (nothing changes, so a forgery cannot consume pending state); KEY_CONFIRMATION_FAILED
 * is an authentic peer whose derived key differs (the pending handshake or session is wiped).
 * Outputs are written only on success. The `_v2` names replace the version 1 functions, which
 * lacked key confirmation and are not interoperable. This protocol has not been formally analyzed
 * or independently reviewed. Not available in the Lite configuration.
 */
shawncore_crypto_err shawncore_crypto_session_manager_encapsulate_authenticated_v2(
    shawncore_crypto_session_manager *manager,
    const shawncore_crypto_ml_dsa_signingkey *own_signing_key,
    const shawncore_crypto_ml_dsa_publickey *peer_verifying_key,
    const shawncore_crypto_ml_kem_publickey *peer_ml_kem_pk,
    const shawncore_crypto_x25519_publickey *peer_x25519_pk,
    const uint8_t entropy[SHAWNCORE_MIN_LEN(64)],
    const uint8_t *salt,
    size_t salt_len,
    const uint8_t *app_info,
    size_t app_info_len,
    shawncore_crypto_ml_kem_ciphertext *out_ct,
    shawncore_crypto_x25519_publickey *out_my_x25519_pk,
    shawncore_crypto_ml_dsa_signature *out_signature,
    uint8_t out_confirmation[SHAWNCORE_MIN_LEN(48)]);
shawncore_crypto_err shawncore_crypto_session_manager_finalize_authenticated_v2(
    shawncore_crypto_session_manager *manager,
    const shawncore_crypto_ml_dsa_signingkey *own_signing_key,
    const shawncore_crypto_ml_dsa_publickey *peer_verifying_key,
    const shawncore_crypto_x25519_publickey *peer_x25519_pk,
    const shawncore_crypto_ml_kem_ciphertext *ml_kem_ct,
    const shawncore_crypto_ml_dsa_signature *peer_signature,
    const uint8_t peer_confirmation[SHAWNCORE_MIN_LEN(48)],
    const uint8_t *salt,
    size_t salt_len,
    const uint8_t *app_info,
    size_t app_info_len,
    shawncore_crypto_ml_dsa_signature *out_signature,
    uint8_t out_confirmation[SHAWNCORE_MIN_LEN(48)]);
shawncore_crypto_err shawncore_crypto_session_manager_confirm_peer_v2(
    shawncore_crypto_session_manager *manager,
    const shawncore_crypto_ml_dsa_publickey *peer_verifying_key,
    const shawncore_crypto_ml_dsa_signature *peer_signature,
    const uint8_t peer_confirmation[SHAWNCORE_MIN_LEN(48)]);

#endif /* SHAWNCORE_LITE */
size_t shawncore_crypto_x25519_publickey_sizeof(void);
size_t shawncore_crypto_x25519_publickey_alignof(void);
size_t shawncore_crypto_x25519_secret_sizeof(void);
size_t shawncore_crypto_x25519_secret_alignof(void);
size_t shawncore_crypto_x25519_sharedsecret_sizeof(void);
size_t shawncore_crypto_x25519_sharedsecret_alignof(void);
shawncore_crypto_err shawncore_crypto_x25519_keygen(
    const uint8_t entropy[SHAWNCORE_MIN_LEN(32)],
    shawncore_crypto_x25519_publickey *out_pk,
    shawncore_crypto_x25519_secret *out_sk);
shawncore_crypto_err shawncore_crypto_x25519_secret_destroy(shawncore_crypto_x25519_secret *sk);
shawncore_crypto_err shawncore_crypto_x25519_diffie_hellman(
    const shawncore_crypto_x25519_secret *sk,
    const shawncore_crypto_x25519_publickey *peer_pk,
    shawncore_crypto_x25519_sharedsecret *out_shared);
shawncore_crypto_err shawncore_crypto_x25519_sharedsecret_destroy(shawncore_crypto_x25519_sharedsecret *shared);

/*
 * Wire codecs.
 *
 * Handshake values that cross a link are opaque in memory and larger than their
 * encodings, so each exposes a fixed-length codec. Pass a buffer whose length
 * equals the matching *_encoded_len() value; any other length is rejected.
 * Buffers must not overlap the object. Decoding validates length and structure
 * only: it does not authenticate a peer.
 *
 * Secret material is deliberately not exportable. Decapsulation keys, signing
 * keys, and shared secrets have no serialization entry point.
 */
size_t shawncore_crypto_ml_kem_publickey_encoded_len(void);   /* 1568 */
shawncore_crypto_err shawncore_crypto_ml_kem_publickey_to_bytes(
    const shawncore_crypto_ml_kem_publickey *value,
    uint8_t *out,
    size_t out_len);
shawncore_crypto_err shawncore_crypto_ml_kem_publickey_from_bytes(
    const uint8_t *bytes,
    size_t len,
    shawncore_crypto_ml_kem_publickey *out);

size_t shawncore_crypto_ml_kem_ciphertext_encoded_len(void);  /* 1568 */
shawncore_crypto_err shawncore_crypto_ml_kem_ciphertext_to_bytes(
    const shawncore_crypto_ml_kem_ciphertext *value,
    uint8_t *out,
    size_t out_len);
shawncore_crypto_err shawncore_crypto_ml_kem_ciphertext_from_bytes(
    const uint8_t *bytes,
    size_t len,
    shawncore_crypto_ml_kem_ciphertext *out);

size_t shawncore_crypto_x25519_publickey_encoded_len(void);   /* 32 */
shawncore_crypto_err shawncore_crypto_x25519_publickey_to_bytes(
    const shawncore_crypto_x25519_publickey *value,
    uint8_t *out,
    size_t out_len);
shawncore_crypto_err shawncore_crypto_x25519_publickey_from_bytes(
    const uint8_t *bytes,
    size_t len,
    shawncore_crypto_x25519_publickey *out);

#ifndef SHAWNCORE_LITE
/* ML-DSA wire C API: omitted from Lite ABI. */
size_t shawncore_crypto_ml_dsa_publickey_encoded_len(void);   /* 2592 */
shawncore_crypto_err shawncore_crypto_ml_dsa_publickey_to_bytes(
    const shawncore_crypto_ml_dsa_publickey *value,
    uint8_t *out,
    size_t out_len);
shawncore_crypto_err shawncore_crypto_ml_dsa_publickey_from_bytes(
    const uint8_t *bytes,
    size_t len,
    shawncore_crypto_ml_dsa_publickey *out);

size_t shawncore_crypto_ml_dsa_signature_encoded_len(void);   /* 4627 */
shawncore_crypto_err shawncore_crypto_ml_dsa_signature_to_bytes(
    const shawncore_crypto_ml_dsa_signature *value,
    uint8_t *out,
    size_t out_len);
shawncore_crypto_err shawncore_crypto_ml_dsa_signature_from_bytes(
    const uint8_t *bytes,
    size_t len,
    shawncore_crypto_ml_dsa_signature *out);

#endif /* SHAWNCORE_LITE */
shawncore_crypto_err shawncore_crypto_hmac_sha384(
    const uint8_t key[SHAWNCORE_MIN_LEN(32)],
    const uint8_t *data,
    size_t data_len,
    uint8_t out_mac[SHAWNCORE_MIN_LEN(48)]);
shawncore_crypto_err shawncore_crypto_hkdf_expand_sha384(
    const uint8_t prk[SHAWNCORE_MIN_LEN(48)],
    const uint8_t *info,
    size_t info_len,
    uint8_t *out,
    size_t out_len);
/* The nonce must be unique for every encryption under a given key pair. */
shawncore_crypto_err shawncore_crypto_aead_encrypt(
    const uint8_t enc_key[SHAWNCORE_MIN_LEN(32)],
    const uint8_t mac_key[SHAWNCORE_MIN_LEN(32)],
    const uint8_t nonce[SHAWNCORE_MIN_LEN(12)],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *plaintext,
    uint8_t *ciphertext,
    size_t data_len,
    uint8_t out_mac[SHAWNCORE_MIN_LEN(48)]);
shawncore_crypto_err shawncore_crypto_aead_decrypt(
    const uint8_t enc_key[SHAWNCORE_MIN_LEN(32)],
    const uint8_t mac_key[SHAWNCORE_MIN_LEN(32)],
    const uint8_t nonce[SHAWNCORE_MIN_LEN(12)],
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *ciphertext,
    const uint8_t mac[SHAWNCORE_MIN_LEN(48)],
    uint8_t *plaintext,
    size_t data_len);
shawncore_crypto_err shawncore_crypto_entropy_push(const uint8_t chunk[SHAWNCORE_MIN_LEN(32)]);
shawncore_crypto_err shawncore_crypto_entropy_mix(void);

/*
 * SPSC queues and the ring buffer require one stable producer and one stable
 * consumer. Page alignment is a storage requirement only, not DMA pinning.
 * Register and validate target-specific cache callbacks before DMA-visible use.
 */
typedef struct shawncore_rtos_scheduler shawncore_rtos_scheduler;
typedef struct shawncore_rtos_dmapool2k shawncore_rtos_dmapool2k;
typedef struct shawncore_rtos_spsc_telemetry shawncore_rtos_spsc_telemetry;
typedef struct shawncore_rtos_ringbuffer_ew shawncore_rtos_ringbuffer_ew;
typedef struct shawncore_rtos_spsc_fft shawncore_rtos_spsc_fft;
typedef struct shawncore_rtos_state_machine shawncore_rtos_state_machine;
typedef struct shawncore_rtos_latency_tracker shawncore_rtos_latency_tracker;

typedef struct SHAWNCORE_ALIGNAS(64) shawncore_rtos_tcb {
    uint64_t entry_point;
    uint64_t stack_base;
    size_t stack_size;
    uint64_t rsp;
    uint8_t priority;
    uint8_t reserved[7];
    uint64_t stack_canary;
} shawncore_rtos_tcb;

typedef struct SHAWNCORE_ALIGNAS(64) shawncore_rtos_telemetry_event {
    uint32_t event_id;
    uint8_t padding[4];
    uint64_t timestamp;
    uint8_t payload[48];
} shawncore_rtos_telemetry_event;

typedef struct shawncore_rtos_ew_command {
    uint8_t mode;
    uint8_t padding[7];
    uint64_t target_freq;
    uint64_t target_bw;
} shawncore_rtos_ew_command;

typedef struct SHAWNCORE_ALIGNAS(64) shawncore_rtos_fft_result {
    uint32_t snr_db;
    uint8_t reserved[4];
    uint64_t center_freq;
    uint64_t bandwidth;
    uint64_t timestamp;
    uint8_t padding[32];
} shawncore_rtos_fft_result;

void shawncore_rtos_register_panic_hook(shawncore_panic_callback callback);
void shawncore_rtos_register_disable_interrupts(shawncore_disable_interrupts_callback callback);
void shawncore_rtos_register_restore_interrupts(shawncore_restore_interrupts_callback callback);
void shawncore_rtos_register_read_monotonic_clock(shawncore_monotonic_clock_callback callback);
void shawncore_rtos_register_cache_invalidate(shawncore_cache_callback callback);
void shawncore_rtos_register_cache_flush(shawncore_cache_callback callback);
void shawncore_rtos_register_pet_watchdog(shawncore_watchdog_callback callback);

size_t shawncore_rtos_tcb_sizeof(void);
size_t shawncore_rtos_tcb_alignof(void);
size_t shawncore_rtos_telemetry_event_sizeof(void);
size_t shawncore_rtos_telemetry_event_alignof(void);
size_t shawncore_rtos_fft_result_sizeof(void);
size_t shawncore_rtos_fft_result_alignof(void);
size_t shawncore_rtos_spsc_telemetry_slot_sizeof(void);
size_t shawncore_rtos_spsc_telemetry_slot_alignof(void);
size_t shawncore_rtos_ringbuffer_ew_slot_sizeof(void);
size_t shawncore_rtos_ringbuffer_ew_slot_alignof(void);
size_t shawncore_rtos_spsc_fft_slot_sizeof(void);
size_t shawncore_rtos_spsc_fft_slot_alignof(void);

size_t shawncore_rtos_scheduler_sizeof(void);
size_t shawncore_rtos_scheduler_alignof(void);
shawncore_rtos_err shawncore_rtos_scheduler_init(shawncore_rtos_scheduler *scheduler);
shawncore_rtos_err shawncore_rtos_scheduler_destroy(shawncore_rtos_scheduler *scheduler);
shawncore_rtos_err shawncore_rtos_tcb_new(
    uint64_t entry_point,
    uint64_t stack_base,
    size_t stack_size,
    uint64_t initial_rsp,
    uint8_t priority,
    shawncore_rtos_tcb *out_tcb);
uint64_t shawncore_rtos_tcb_get_rsp(const shawncore_rtos_tcb *tcb);
shawncore_rtos_err shawncore_rtos_tcb_set_rsp(shawncore_rtos_tcb *tcb, uint64_t rsp);
shawncore_rtos_err shawncore_rtos_scheduler_create_task(
    shawncore_rtos_scheduler *scheduler,
    const shawncore_rtos_tcb *tcb,
    uint64_t canary_value);
/* Task stack memory must be mapped, writable, owned by the task, and live. */
uint64_t shawncore_rtos_scheduler_tick(shawncore_rtos_scheduler *scheduler, uint64_t current_rsp);
shawncore_rtos_err shawncore_rtos_scheduler_set_critical_task_mask(
    shawncore_rtos_scheduler *scheduler,
    uint16_t critical_task_mask);
shawncore_rtos_err shawncore_rtos_scheduler_task_check_in(
    shawncore_rtos_scheduler *scheduler,
    uint8_t priority);

size_t shawncore_rtos_dmapool2k_sizeof(void);
size_t shawncore_rtos_dmapool2k_alignof(void);
shawncore_rtos_err shawncore_rtos_dmapool2k_init(
    shawncore_rtos_dmapool2k *pool,
    void *memory_base,
    size_t size_in_bytes);
/* Free only after any device has released the allocation to the CPU. */
shawncore_rtos_err shawncore_rtos_dmapool2k_destroy(shawncore_rtos_dmapool2k *pool);
/* Result pointers must not overlap the pool or each other. */
shawncore_rtos_err shawncore_rtos_dmapool2k_allocate(
    const shawncore_rtos_dmapool2k *pool,
    size_t *out_idx,
    uint64_t *out_generation,
    uint8_t **out_ptr);
shawncore_rtos_err shawncore_rtos_dmapool2k_free(
    const shawncore_rtos_dmapool2k *pool,
    size_t buffer_idx,
    uint64_t generation);

size_t shawncore_rtos_spsc_telemetry_sizeof(void);
size_t shawncore_rtos_spsc_telemetry_alignof(void);
shawncore_rtos_err shawncore_rtos_spsc_telemetry_init(
    shawncore_rtos_spsc_telemetry *queue,
    void *memory_base,
    size_t size_in_bytes);
shawncore_rtos_err shawncore_rtos_spsc_telemetry_destroy(shawncore_rtos_spsc_telemetry *queue);
shawncore_rtos_err shawncore_rtos_spsc_telemetry_push(
    const shawncore_rtos_spsc_telemetry *queue,
    const shawncore_rtos_telemetry_event *event);
/* out_event must not overlap queue. */
shawncore_rtos_err shawncore_rtos_spsc_telemetry_pop(
    const shawncore_rtos_spsc_telemetry *queue,
    shawncore_rtos_telemetry_event *out_event);

size_t shawncore_rtos_ringbuffer_ew_sizeof(void);
size_t shawncore_rtos_ringbuffer_ew_alignof(void);
shawncore_rtos_err shawncore_rtos_ringbuffer_ew_init(
    shawncore_rtos_ringbuffer_ew *ring_buffer,
    void *memory_base,
    size_t size_in_bytes);
shawncore_rtos_err shawncore_rtos_ringbuffer_ew_destroy(shawncore_rtos_ringbuffer_ew *ring_buffer);
shawncore_rtos_err shawncore_rtos_ringbuffer_ew_push(
    const shawncore_rtos_ringbuffer_ew *ring_buffer,
    const shawncore_rtos_ew_command *item);
/* out_item must not overlap ring_buffer. */
shawncore_rtos_err shawncore_rtos_ringbuffer_ew_pop(
    const shawncore_rtos_ringbuffer_ew *ring_buffer,
    shawncore_rtos_ew_command *out_item);
shawncore_rtos_err shawncore_rtos_ringbuffer_ew_peek(
    const shawncore_rtos_ringbuffer_ew *ring_buffer,
    shawncore_rtos_ew_command *out_item);

size_t shawncore_rtos_spsc_fft_sizeof(void);
size_t shawncore_rtos_spsc_fft_alignof(void);
shawncore_rtos_err shawncore_rtos_spsc_fft_init(
    shawncore_rtos_spsc_fft *queue,
    void *memory_base,
    size_t size_in_bytes);
shawncore_rtos_err shawncore_rtos_spsc_fft_destroy(shawncore_rtos_spsc_fft *queue);
shawncore_rtos_err shawncore_rtos_spsc_fft_push(
    const shawncore_rtos_spsc_fft *queue,
    const shawncore_rtos_fft_result *item);
/* out_item must not overlap queue. */
shawncore_rtos_err shawncore_rtos_spsc_fft_pop(
    const shawncore_rtos_spsc_fft *queue,
    shawncore_rtos_fft_result *out_item);

size_t shawncore_rtos_state_machine_sizeof(void);
size_t shawncore_rtos_state_machine_alignof(void);
shawncore_rtos_err shawncore_rtos_state_machine_init(shawncore_rtos_state_machine *machine);
shawncore_rtos_err shawncore_rtos_state_machine_destroy(shawncore_rtos_state_machine *machine);
shawncore_rtos_err shawncore_rtos_state_machine_try_advance(
    const shawncore_rtos_state_machine *machine,
    uint8_t target_state);

size_t shawncore_rtos_latency_tracker_sizeof(void);
size_t shawncore_rtos_latency_tracker_alignof(void);
shawncore_rtos_err shawncore_rtos_latency_tracker_init(shawncore_rtos_latency_tracker *tracker);
shawncore_rtos_err shawncore_rtos_latency_tracker_destroy(shawncore_rtos_latency_tracker *tracker);
shawncore_rtos_err shawncore_rtos_latency_tracker_mark_start(
    const shawncore_rtos_latency_tracker *tracker,
    uint64_t current_timestamp);
shawncore_rtos_err shawncore_rtos_latency_tracker_mark_end(
    const shawncore_rtos_latency_tracker *tracker,
    uint64_t current_timestamp);

#ifdef __cplusplus
}
#endif

#endif
