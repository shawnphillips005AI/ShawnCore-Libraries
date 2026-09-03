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

    return 0;
}
