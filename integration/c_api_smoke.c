// Copyright (c) 2026 Shawn Phillips. All Rights Reserved.
// Dual-licensed under AGPLv3 and Commercial License.

#include "shawncore.h"

_Static_assert(sizeof(shawncore_rtos_tcb) == 64, "TCB ABI changed");
_Static_assert(_Alignof(shawncore_rtos_tcb) == 64, "TCB alignment changed");
_Static_assert(sizeof(shawncore_rtos_telemetry_event) == 64, "telemetry ABI changed");
_Static_assert(_Alignof(shawncore_rtos_telemetry_event) == 64, "telemetry alignment changed");
_Static_assert(sizeof(shawncore_rtos_ew_command) == 24, "EW command ABI changed");
_Static_assert(sizeof(shawncore_rtos_fft_result) == 64, "FFT ABI changed");
_Static_assert(_Alignof(shawncore_rtos_fft_result) == 64, "FFT alignment changed");

/* Field offsets are pinned here and, with the same literals, against the Rust types by
   validation/tests/ffi_layout_contracts.rs::c_header_struct_offsets_match_rust_types. */
_Static_assert(offsetof(shawncore_rtos_tcb, entry_point) == 0, "TCB entry_point offset");
_Static_assert(offsetof(shawncore_rtos_tcb, stack_base) == 8, "TCB stack_base offset");
_Static_assert(offsetof(shawncore_rtos_tcb, stack_size) == 16, "TCB stack_size offset");
_Static_assert(offsetof(shawncore_rtos_tcb, rsp) == 24, "TCB rsp offset");
_Static_assert(offsetof(shawncore_rtos_tcb, priority) == 32, "TCB priority offset");
_Static_assert(offsetof(shawncore_rtos_tcb, stack_canary) == 40, "TCB stack_canary offset");
_Static_assert(offsetof(shawncore_rtos_telemetry_event, event_id) == 0, "event_id offset");
_Static_assert(offsetof(shawncore_rtos_telemetry_event, timestamp) == 8, "timestamp offset");
_Static_assert(offsetof(shawncore_rtos_telemetry_event, payload) == 16, "payload offset");
_Static_assert(_Alignof(shawncore_rtos_ew_command) == 8, "EW command alignment");
_Static_assert(offsetof(shawncore_rtos_ew_command, mode) == 0, "EW mode offset");
_Static_assert(offsetof(shawncore_rtos_ew_command, target_freq) == 8, "EW target_freq offset");
_Static_assert(offsetof(shawncore_rtos_ew_command, target_bw) == 16, "EW target_bw offset");
_Static_assert(offsetof(shawncore_rtos_fft_result, snr_db) == 0, "FFT snr_db offset");
_Static_assert(offsetof(shawncore_rtos_fft_result, center_freq) == 8, "FFT center_freq offset");
_Static_assert(offsetof(shawncore_rtos_fft_result, bandwidth) == 16, "FFT bandwidth offset");
_Static_assert(offsetof(shawncore_rtos_fft_result, timestamp) == 24, "FFT timestamp offset");

/* The C view of every header-defined struct must equal what the library reports. */
static int header_structs_match_the_library(void)
{
    return shawncore_rtos_tcb_sizeof() == sizeof(shawncore_rtos_tcb) &&
           shawncore_rtos_tcb_alignof() == _Alignof(shawncore_rtos_tcb) &&
           shawncore_rtos_telemetry_event_sizeof() == sizeof(shawncore_rtos_telemetry_event) &&
           shawncore_rtos_telemetry_event_alignof() == _Alignof(shawncore_rtos_telemetry_event) &&
           shawncore_rtos_fft_result_sizeof() == sizeof(shawncore_rtos_fft_result) &&
           shawncore_rtos_fft_result_alignof() == _Alignof(shawncore_rtos_fft_result) &&
           shawncore_rtos_ringbuffer_ew_slot_sizeof() >= sizeof(shawncore_rtos_ew_command);
}

static void no_op_cache_callback(const uint8_t *ptr, size_t len)
{
    (void)ptr;
    (void)len;
}

/*
 * Drives a full hybrid handshake between two session managers, passing every
 * public value through its wire encoding exactly as a link layer would.
 * Returns 0 on success.
 */
static int wire_handshake_round_trip(void)
{
    static _Alignas(64) uint8_t responder_storage[8192];
    static _Alignas(64) uint8_t initiator_storage[8192];
    static _Alignas(64) uint8_t ml_kem_pk_storage[4096];
    static _Alignas(64) uint8_t ml_kem_pk_decoded[4096];
    static _Alignas(64) uint8_t x25519_pk_storage[256];
    static _Alignas(64) uint8_t x25519_pk_decoded[256];
    static _Alignas(64) uint8_t ct_storage[2048];
    static _Alignas(64) uint8_t ct_decoded[2048];
    static _Alignas(64) uint8_t peer_x25519_storage[256];
    static _Alignas(64) uint8_t peer_x25519_decoded[256];

    static uint8_t ml_kem_wire[1568];
    static uint8_t x25519_wire[32];
    static uint8_t ct_wire[1568];
    static uint8_t peer_x25519_wire[32];

    uint8_t responder_entropy[96];
    uint8_t initiator_entropy[64];
    uint8_t plaintext[32];
    uint8_t ciphertext[32];
    uint8_t recovered[32];
    uint8_t nonce[12];
    uint8_t tag[48];

    shawncore_crypto_session_manager *responder = (shawncore_crypto_session_manager *)responder_storage;
    shawncore_crypto_session_manager *initiator = (shawncore_crypto_session_manager *)initiator_storage;
    shawncore_crypto_ml_kem_publickey *pk = (shawncore_crypto_ml_kem_publickey *)ml_kem_pk_storage;
    shawncore_crypto_ml_kem_publickey *pk2 = (shawncore_crypto_ml_kem_publickey *)ml_kem_pk_decoded;
    shawncore_crypto_x25519_publickey *xpk = (shawncore_crypto_x25519_publickey *)x25519_pk_storage;
    shawncore_crypto_x25519_publickey *xpk2 = (shawncore_crypto_x25519_publickey *)x25519_pk_decoded;
    shawncore_crypto_ml_kem_ciphertext *ct = (shawncore_crypto_ml_kem_ciphertext *)ct_storage;
    shawncore_crypto_ml_kem_ciphertext *ct2 = (shawncore_crypto_ml_kem_ciphertext *)ct_decoded;
    shawncore_crypto_x25519_publickey *peer = (shawncore_crypto_x25519_publickey *)peer_x25519_storage;
    shawncore_crypto_x25519_publickey *peer2 = (shawncore_crypto_x25519_publickey *)peer_x25519_decoded;

    if (shawncore_crypto_session_manager_sizeof() > sizeof(responder_storage) ||
        shawncore_crypto_ml_kem_publickey_sizeof() > sizeof(ml_kem_pk_storage) ||
        shawncore_crypto_ml_kem_ciphertext_sizeof() > sizeof(ct_storage) ||
        shawncore_crypto_x25519_publickey_sizeof() > sizeof(x25519_pk_storage)) {
        return 1;
    }
    if (shawncore_crypto_ml_kem_publickey_encoded_len() != sizeof(ml_kem_wire) ||
        shawncore_crypto_ml_kem_ciphertext_encoded_len() != sizeof(ct_wire) ||
        shawncore_crypto_x25519_publickey_encoded_len() != sizeof(x25519_wire)) {
        return 2;
    }

    for (size_t i = 0; i < sizeof(responder_entropy); i++) {
        responder_entropy[i] = (uint8_t)(i + 1);
    }
    for (size_t i = 0; i < sizeof(initiator_entropy); i++) {
        initiator_entropy[i] = (uint8_t)(0xC0 ^ i);
    }
    for (size_t i = 0; i < sizeof(plaintext); i++) {
        plaintext[i] = (uint8_t)i;
    }

    if (shawncore_crypto_session_manager_init(responder) != SHAWNCORE_CRYPTO_SUCCESS ||
        shawncore_crypto_session_manager_init(initiator) != SHAWNCORE_CRYPTO_SUCCESS) {
        return 3;
    }

    /* Responder publishes its hybrid public keys. */
    if (shawncore_crypto_session_manager_initiate_handshake(responder, responder_entropy, pk, xpk) !=
        SHAWNCORE_CRYPTO_SUCCESS) {
        return 4;
    }

    /* Serialize onto the "wire", then rebuild on the initiator side. */
    if (shawncore_crypto_ml_kem_publickey_to_bytes(pk, ml_kem_wire, sizeof(ml_kem_wire)) !=
            SHAWNCORE_CRYPTO_SUCCESS ||
        shawncore_crypto_x25519_publickey_to_bytes(xpk, x25519_wire, sizeof(x25519_wire)) !=
            SHAWNCORE_CRYPTO_SUCCESS ||
        shawncore_crypto_ml_kem_publickey_from_bytes(ml_kem_wire, sizeof(ml_kem_wire), pk2) !=
            SHAWNCORE_CRYPTO_SUCCESS ||
        shawncore_crypto_x25519_publickey_from_bytes(x25519_wire, sizeof(x25519_wire), xpk2) !=
            SHAWNCORE_CRYPTO_SUCCESS) {
        return 5;
    }

    /* Initiator encapsulates against the decoded keys only. */
    if (shawncore_crypto_session_manager_encapsulate_for_peer(
            initiator, pk2, xpk2, initiator_entropy, NULL, 0, NULL, 0, ct, peer) !=
        SHAWNCORE_CRYPTO_SUCCESS) {
        return 6;
    }

    if (shawncore_crypto_ml_kem_ciphertext_to_bytes(ct, ct_wire, sizeof(ct_wire)) !=
            SHAWNCORE_CRYPTO_SUCCESS ||
        shawncore_crypto_x25519_publickey_to_bytes(peer, peer_x25519_wire, sizeof(peer_x25519_wire)) !=
            SHAWNCORE_CRYPTO_SUCCESS ||
        shawncore_crypto_ml_kem_ciphertext_from_bytes(ct_wire, sizeof(ct_wire), ct2) !=
            SHAWNCORE_CRYPTO_SUCCESS ||
        shawncore_crypto_x25519_publickey_from_bytes(
            peer_x25519_wire, sizeof(peer_x25519_wire), peer2) != SHAWNCORE_CRYPTO_SUCCESS) {
        return 7;
    }

    /* Responder completes the handshake from decoded wire values only. */
    if (shawncore_crypto_session_manager_finalize_handshake(responder, peer2, ct2, NULL, 0, NULL, 0) !=
        SHAWNCORE_CRYPTO_SUCCESS) {
        return 8;
    }

    /* Initiator encrypts, responder decrypts: proves both derived the same keys. */
    if (shawncore_crypto_session_manager_encrypt_packet(
            initiator, NULL, 0, plaintext, ciphertext, sizeof(plaintext), nonce, tag) !=
        SHAWNCORE_CRYPTO_SUCCESS) {
        return 9;
    }
    if (shawncore_crypto_session_manager_decrypt_packet(
            responder, NULL, 0, ciphertext, sizeof(ciphertext), nonce, tag, recovered) !=
        SHAWNCORE_CRYPTO_SUCCESS) {
        return 10;
    }
    for (size_t i = 0; i < sizeof(plaintext); i++) {
        if (recovered[i] != plaintext[i]) {
            return 11;
        }
    }

    /* A replayed packet must be rejected. */
    if (shawncore_crypto_session_manager_decrypt_packet(
            responder, NULL, 0, ciphertext, sizeof(ciphertext), nonce, tag, recovered) ==
        SHAWNCORE_CRYPTO_SUCCESS) {
        return 12;
    }

    shawncore_crypto_session_manager_destroy(responder);
    shawncore_crypto_session_manager_destroy(initiator);
    return 0;
}

#ifndef SHAWNCORE_LITE
/*
 * Authenticated handshake: the responder trusts the initiator's verifying key and vice versa.
 * An intermediary with its own identity must be rejected, the unconfirmed initiator must refuse
 * traffic, and only after confirm_peer_v2 may packets flow. Returns 0 on success.
 */
static int authenticated_handshake_round_trip(void)
{
    static _Alignas(64) uint8_t sk_resp[120000], sk_init[120000], sk_mall[120000];
    static _Alignas(64) uint8_t vk_resp[90000], vk_init[90000], vk_mall[90000];
    static _Alignas(64) uint8_t sig_i[8192], sig_i_decoded[8192], sig_m[8192], sig_r[8192];
    static _Alignas(64) uint8_t mgr_resp[8192], mgr_init[8192], mgr_mall[8192];
    static _Alignas(64) uint8_t mgr_salt_a[8192], mgr_salt_b[8192];
    static _Alignas(64) uint8_t pk_store[4096], xpk_store[256], ct_store[2048], peer_x_store[256];
    static _Alignas(64) uint8_t ct_m_store[2048], peer_x_m_store[256];
    static uint8_t sig_wire[4627];

    uint8_t seed_resp[32], seed_init[32], seed_mall[32];
    uint8_t resp_entropy[96], init_entropy[64], mall_entropy[64];
    uint8_t plaintext[16], ciphertext[16], recovered[16], nonce[12], tag[48];
    static const uint8_t salt[] = {'s', 'a', 'l', 't'};
    static const uint8_t other_salt[] = {'s', 'a', 'l', 't', '2'};
    static const uint8_t app[] = {'a', 'p', 'p'};
    uint8_t tag_i[48], tag_r[48], tag_m[48];

    shawncore_crypto_ml_dsa_signingkey *rsk = (shawncore_crypto_ml_dsa_signingkey *)sk_resp;
    shawncore_crypto_ml_dsa_signingkey *isk = (shawncore_crypto_ml_dsa_signingkey *)sk_init;
    shawncore_crypto_ml_dsa_signingkey *msk = (shawncore_crypto_ml_dsa_signingkey *)sk_mall;
    shawncore_crypto_ml_dsa_publickey *rvk = (shawncore_crypto_ml_dsa_publickey *)vk_resp;
    shawncore_crypto_ml_dsa_publickey *ivk = (shawncore_crypto_ml_dsa_publickey *)vk_init;
    shawncore_crypto_ml_dsa_publickey *mvk = (shawncore_crypto_ml_dsa_publickey *)vk_mall;
    shawncore_crypto_ml_dsa_signature *sigi = (shawncore_crypto_ml_dsa_signature *)sig_i;
    shawncore_crypto_ml_dsa_signature *sigi2 = (shawncore_crypto_ml_dsa_signature *)sig_i_decoded;
    shawncore_crypto_ml_dsa_signature *sigm = (shawncore_crypto_ml_dsa_signature *)sig_m;
    shawncore_crypto_ml_dsa_signature *sigr = (shawncore_crypto_ml_dsa_signature *)sig_r;
    shawncore_crypto_session_manager *resp = (shawncore_crypto_session_manager *)mgr_resp;
    shawncore_crypto_session_manager *init = (shawncore_crypto_session_manager *)mgr_init;
    shawncore_crypto_session_manager *mall = (shawncore_crypto_session_manager *)mgr_mall;
    shawncore_crypto_session_manager *salt_a = (shawncore_crypto_session_manager *)mgr_salt_a;
    shawncore_crypto_session_manager *salt_b = (shawncore_crypto_session_manager *)mgr_salt_b;
    shawncore_crypto_ml_kem_publickey *pk = (shawncore_crypto_ml_kem_publickey *)pk_store;
    shawncore_crypto_x25519_publickey *xpk = (shawncore_crypto_x25519_publickey *)xpk_store;
    shawncore_crypto_ml_kem_ciphertext *ct = (shawncore_crypto_ml_kem_ciphertext *)ct_store;
    shawncore_crypto_x25519_publickey *peer_x = (shawncore_crypto_x25519_publickey *)peer_x_store;
    shawncore_crypto_ml_kem_ciphertext *ct_m = (shawncore_crypto_ml_kem_ciphertext *)ct_m_store;
    shawncore_crypto_x25519_publickey *peer_x_m = (shawncore_crypto_x25519_publickey *)peer_x_m_store;

    if (shawncore_crypto_ml_dsa_signingkey_sizeof() > sizeof(sk_resp) ||
        shawncore_crypto_ml_dsa_publickey_sizeof() > sizeof(vk_resp) ||
        shawncore_crypto_ml_dsa_signature_sizeof() > sizeof(sig_r) ||
        shawncore_crypto_ml_dsa_signature_encoded_len() != sizeof(sig_wire) ||
        shawncore_crypto_session_manager_sizeof() > sizeof(mgr_resp)) {
        return 101;
    }
    for (size_t i = 0; i < 32; i++) {
        seed_resp[i] = (uint8_t)(0x41 + i);
        seed_init[i] = (uint8_t)(0x82 + i);
        seed_mall[i] = (uint8_t)(0xC3 + i);
    }
    for (size_t i = 0; i < sizeof(resp_entropy); i++) {
        resp_entropy[i] = (uint8_t)(i + 7);
    }
    for (size_t i = 0; i < sizeof(init_entropy); i++) {
        init_entropy[i] = (uint8_t)(0x30 ^ i);
        mall_entropy[i] = (uint8_t)(0x5A + i);
    }
    for (size_t i = 0; i < sizeof(plaintext); i++) {
        plaintext[i] = (uint8_t)(0xA0 + i);
    }

    if (shawncore_crypto_ml_dsa_keygen(seed_resp, rvk, rsk) != SHAWNCORE_CRYPTO_SUCCESS ||
        shawncore_crypto_ml_dsa_keygen(seed_init, ivk, isk) != SHAWNCORE_CRYPTO_SUCCESS ||
        shawncore_crypto_ml_dsa_keygen(seed_mall, mvk, msk) != SHAWNCORE_CRYPTO_SUCCESS) {
        return 102;
    }
    if (shawncore_crypto_session_manager_init(resp) != SHAWNCORE_CRYPTO_SUCCESS ||
        shawncore_crypto_session_manager_init(init) != SHAWNCORE_CRYPTO_SUCCESS ||
        shawncore_crypto_session_manager_init(mall) != SHAWNCORE_CRYPTO_SUCCESS) {
        return 103;
    }

    if (shawncore_crypto_session_manager_initiate_handshake(resp, resp_entropy, pk, xpk) !=
        SHAWNCORE_CRYPTO_SUCCESS) {
        return 104;
    }

    /* An intermediary answers with its own identity; the responder must refuse it. */
    if (shawncore_crypto_session_manager_encapsulate_authenticated_v2(
            mall, msk, rvk, pk, xpk, mall_entropy, salt, sizeof salt, app, sizeof app, ct_m,
            peer_x_m, sigm, tag_m) != SHAWNCORE_CRYPTO_SUCCESS) {
        return 105;
    }
    if (shawncore_crypto_session_manager_finalize_authenticated_v2(
            resp, rsk, ivk, peer_x_m, ct_m, sigm, tag_m, salt, sizeof salt, app, sizeof app, sigr,
            tag_r) != SHAWNCORE_CRYPTO_VERIFICATION_FAILED) {
        return 106;
    }

    /* The genuine initiator; its signature travels through the wire codec. */
    if (shawncore_crypto_session_manager_encapsulate_authenticated_v2(
            init, isk, rvk, pk, xpk, init_entropy, salt, sizeof salt, app, sizeof app, ct, peer_x,
            sigi, tag_i) != SHAWNCORE_CRYPTO_SUCCESS) {
        return 107;
    }
    if (shawncore_crypto_ml_dsa_signature_to_bytes(sigi, sig_wire, sizeof sig_wire) !=
            SHAWNCORE_CRYPTO_SUCCESS ||
        shawncore_crypto_ml_dsa_signature_from_bytes(sig_wire, sizeof sig_wire, sigi2) !=
            SHAWNCORE_CRYPTO_SUCCESS) {
        return 108;
    }

    /* The unconfirmed initiator refuses to send. */
    if (shawncore_crypto_session_manager_encrypt_packet(
            init, NULL, 0, plaintext, ciphertext, sizeof plaintext, nonce, tag) ==
        SHAWNCORE_CRYPTO_SUCCESS) {
        return 109;
    }

    if (shawncore_crypto_session_manager_finalize_authenticated_v2(
            resp, rsk, ivk, peer_x, ct, sigi2, tag_i, salt, sizeof salt, app, sizeof app, sigr,
            tag_r) != SHAWNCORE_CRYPTO_SUCCESS) {
        return 110;
    }
    /* A signature from the wrong identity must not confirm the session. */
    if (shawncore_crypto_session_manager_confirm_peer_v2(init, mvk, sigr, tag_r) ==
        SHAWNCORE_CRYPTO_SUCCESS) {
        return 111;
    }
    /* A tampered key-confirmation tag is covered by the signature: a signature failure. */
    tag_r[0] ^= 1;
    if (shawncore_crypto_session_manager_confirm_peer_v2(init, rvk, sigr, tag_r) !=
        SHAWNCORE_CRYPTO_VERIFICATION_FAILED) {
        return 115;
    }
    tag_r[0] ^= 1;
    if (shawncore_crypto_session_manager_confirm_peer_v2(init, rvk, sigr, tag_r) !=
        SHAWNCORE_CRYPTO_SUCCESS) {
        return 112;
    }

    if (shawncore_crypto_session_manager_encrypt_packet(
            init, NULL, 0, plaintext, ciphertext, sizeof plaintext, nonce, tag) !=
            SHAWNCORE_CRYPTO_SUCCESS ||
        shawncore_crypto_session_manager_decrypt_packet(
            resp, NULL, 0, ciphertext, sizeof ciphertext, nonce, tag, recovered) !=
            SHAWNCORE_CRYPTO_SUCCESS) {
        return 113;
    }
    for (size_t i = 0; i < sizeof plaintext; i++) {
        if (recovered[i] != plaintext[i]) {
            return 114;
        }
    }

    /*
     * Different salts: the transcript does not contain the salt, so signatures verify and only
     * key confirmation can notice. The responder must report that distinct error and must not
     * end up with a usable session.
     */
    if (shawncore_crypto_session_manager_init(salt_a) != SHAWNCORE_CRYPTO_SUCCESS ||
        shawncore_crypto_session_manager_init(salt_b) != SHAWNCORE_CRYPTO_SUCCESS ||
        shawncore_crypto_session_manager_initiate_handshake(salt_a, resp_entropy, pk, xpk) !=
            SHAWNCORE_CRYPTO_SUCCESS ||
        shawncore_crypto_session_manager_encapsulate_authenticated_v2(
            salt_b, isk, rvk, pk, xpk, init_entropy, salt, sizeof salt, app, sizeof app, ct, peer_x,
            sigi, tag_i) != SHAWNCORE_CRYPTO_SUCCESS) {
        return 116;
    }
    if (shawncore_crypto_session_manager_finalize_authenticated_v2(
            salt_a, rsk, ivk, peer_x, ct, sigi, tag_i, other_salt, sizeof other_salt, app,
            sizeof app, sigr, tag_r) != SHAWNCORE_CRYPTO_KEY_CONFIRMATION_FAILED) {
        return 117;
    }
    if (shawncore_crypto_session_manager_encrypt_packet(
            salt_a, NULL, 0, plaintext, ciphertext, sizeof plaintext, nonce, tag) ==
        SHAWNCORE_CRYPTO_SUCCESS) {
        return 118;
    }

    shawncore_crypto_session_manager_destroy(resp);
    shawncore_crypto_session_manager_destroy(init);
    shawncore_crypto_session_manager_destroy(mall);
    shawncore_crypto_session_manager_destroy(salt_a);
    shawncore_crypto_session_manager_destroy(salt_b);
    shawncore_crypto_ml_dsa_signingkey_destroy(rsk);
    shawncore_crypto_ml_dsa_signingkey_destroy(isk);
    shawncore_crypto_ml_dsa_signingkey_destroy(msk);
    return 0;
}
#endif /* SHAWNCORE_LITE */

int main(void)
{
    uint8_t enc_key[32] = {0};
    uint8_t mac_key[32] = {0};
    uint8_t nonce[12] = {0};
    uint8_t tag[48] = {0};
    uint8_t prk[48] = {0};
    /* The null-rejection contract is exercised at runtime. The deliberate null
       is kept in a volatile pointer so the compiler cannot reject it at
       compile time via -Wnonnull on the [static 32] parameter. */
    uint8_t *volatile null_chunk = NULL;

    if (shawncore_crypto_session_manager_sizeof() == 0 ||
        shawncore_crypto_ml_kem_publickey_alignof() == 0 ||
        shawncore_rtos_scheduler_sizeof() == 0 ||
        shawncore_rtos_spsc_fft_slot_sizeof() == 0 ||
        !header_structs_match_the_library()) {
        return 1;
    }
    if (shawncore_crypto_entropy_push(null_chunk) != SHAWNCORE_CRYPTO_INVALID_STATE ||
        shawncore_rtos_scheduler_init(NULL) != SHAWNCORE_RTOS_INVALID_MEMORY ||
        shawncore_rtos_scheduler_set_critical_task_mask(NULL, 0) != SHAWNCORE_RTOS_INVALID_MEMORY) {
        return 2;
    }

    shawncore_crypto_register_cache_flush(no_op_cache_callback);
    if (shawncore_crypto_aead_encrypt(enc_key, mac_key, nonce, NULL, 0, NULL, NULL, 0, tag) !=
            SHAWNCORE_CRYPTO_SUCCESS ||
        shawncore_crypto_aead_decrypt(enc_key, mac_key, nonce, NULL, 0, NULL, tag, NULL, 0) !=
            SHAWNCORE_CRYPTO_SUCCESS ||
        shawncore_crypto_hkdf_expand_sha384(prk, NULL, 0, NULL, 0) != SHAWNCORE_CRYPTO_SUCCESS) {
        return 3;
    }

    /* Wire codecs must reject null, wrong length, and overlap. */
    if (shawncore_crypto_ml_kem_publickey_to_bytes(NULL, prk, 1568) != SHAWNCORE_CRYPTO_INVALID_STATE ||
        shawncore_crypto_x25519_publickey_from_bytes(NULL, 32, NULL) != SHAWNCORE_CRYPTO_INVALID_STATE) {
        return 4;
    }

    /* Boundary contract: lengths past PTRDIFF_MAX are refused before any memory is touched, so
       the address below (never mapped, never dereferenced) is safe to pass; a zero-length
       NULL is accepted. */
    {
        const uint8_t *unmapped = (const uint8_t *)(uintptr_t)0x7ffffffff000u;
        uint8_t mac[48];
        if (shawncore_crypto_hmac_sha384(prk, unmapped, (size_t)INTPTR_MAX + 1u, mac) !=
                SHAWNCORE_CRYPTO_INVALID_LENGTH ||
            shawncore_crypto_hkdf_expand_sha384(prk, unmapped, (size_t)INTPTR_MAX + 1u, mac,
                                                sizeof mac) != SHAWNCORE_CRYPTO_INVALID_LENGTH ||
            shawncore_crypto_hmac_sha384(prk, NULL, 0, mac) != SHAWNCORE_CRYPTO_SUCCESS) {
            return 7;
        }
    }

    if (wire_handshake_round_trip() != 0) {
        return 5;
    }
#ifndef SHAWNCORE_LITE
    if (authenticated_handshake_round_trip() != 0) {
        return 6;
    }
#endif

    return 0;
}
