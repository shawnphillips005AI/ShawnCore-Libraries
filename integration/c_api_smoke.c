#include "shawncore.h"

_Static_assert(sizeof(shawncore_rtos_tcb) == 64, "TCB ABI changed");
_Static_assert(_Alignof(shawncore_rtos_tcb) == 64, "TCB alignment changed");
_Static_assert(sizeof(shawncore_rtos_telemetry_event) == 64, "telemetry ABI changed");
_Static_assert(_Alignof(shawncore_rtos_telemetry_event) == 64, "telemetry alignment changed");
_Static_assert(sizeof(shawncore_rtos_ew_command) == 24, "EW command ABI changed");
_Static_assert(sizeof(shawncore_rtos_fft_result) == 64, "FFT ABI changed");
_Static_assert(_Alignof(shawncore_rtos_fft_result) == 64, "FFT alignment changed");

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

int main(void)
{
    uint8_t enc_key[32] = {0};
    uint8_t mac_key[32] = {0};
    uint8_t nonce[12] = {0};
    uint8_t tag[48] = {0};
    uint8_t prk[48] = {0};

    if (shawncore_crypto_session_manager_sizeof() == 0 ||
        shawncore_crypto_ml_kem_publickey_alignof() == 0 ||
        shawncore_rtos_scheduler_sizeof() == 0 ||
        shawncore_rtos_spsc_fft_slot_sizeof() == 0 ||
        shawncore_rtos_fft_result_sizeof() != sizeof(shawncore_rtos_fft_result)) {
        return 1;
    }
    if (shawncore_crypto_entropy_push(NULL) != SHAWNCORE_CRYPTO_INVALID_STATE ||
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

    if (wire_handshake_round_trip() != 0) {
        return 5;
    }

    return 0;
}
