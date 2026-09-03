#ifndef SHAWNCORE_H
#define SHAWNCORE_H

/*
 * C11 interface for libshawncore_ffi.a.
 *
 * Opaque objects must be allocated with the matching sizeof/alignof functions,
 * initialized exactly once, and destroyed only after concurrent users stop.
 * Host code owns pointer validity, storage lifetime, callback lifetime, and
 * platform cache/DMA maintenance.
 */

#include <stddef.h>
#include <stdint.h>

#if defined(_MSC_VER)
#define SHAWNCORE_ALIGNAS(bytes) __declspec(align(bytes))
#else
#define SHAWNCORE_ALIGNAS(bytes) __attribute__((aligned(bytes)))
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
typedef struct shawncore_crypto_ml_dsa_publickey shawncore_crypto_ml_dsa_publickey;
typedef struct shawncore_crypto_ml_dsa_signingkey shawncore_crypto_ml_dsa_signingkey;
typedef struct shawncore_crypto_ml_dsa_signature shawncore_crypto_ml_dsa_signature;
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

size_t shawncore_crypto_session_manager_sizeof(void);
size_t shawncore_crypto_session_manager_alignof(void);
shawncore_crypto_err shawncore_crypto_session_manager_init(shawncore_crypto_session_manager *manager);
shawncore_crypto_err shawncore_crypto_session_manager_destroy(shawncore_crypto_session_manager *manager);
shawncore_crypto_err shawncore_crypto_session_manager_initiate_handshake(
    shawncore_crypto_session_manager *manager,
    const uint8_t *entropy,
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
    const uint8_t *entropy,
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
    uint8_t *out_nonce,
    uint8_t *out_tag);
shawncore_crypto_err shawncore_crypto_session_manager_decrypt_packet(
    shawncore_crypto_session_manager *manager,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *ciphertext,
    size_t data_len,
    const uint8_t *nonce,
    const uint8_t *tag,
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
    const uint8_t *entropy,
    shawncore_crypto_ml_kem_publickey *out_pk,
    shawncore_crypto_ml_kem_decapskey *out_dk);
shawncore_crypto_err shawncore_crypto_ml_kem_decapskey_destroy(shawncore_crypto_ml_kem_decapskey *dk);
shawncore_crypto_err shawncore_crypto_ml_kem_encapsulate(
    const shawncore_crypto_ml_kem_publickey *pk,
    const uint8_t *entropy,
    shawncore_crypto_ml_kem_sharedkey *out_shared,
    shawncore_crypto_ml_kem_ciphertext *out_ct);
shawncore_crypto_err shawncore_crypto_ml_kem_decapsulate(
    const shawncore_crypto_ml_kem_decapskey *dk,
    const shawncore_crypto_ml_kem_ciphertext *ct,
    shawncore_crypto_ml_kem_sharedkey *out_shared);
shawncore_crypto_err shawncore_crypto_ml_kem_sharedkey_destroy(shawncore_crypto_ml_kem_sharedkey *shared);

size_t shawncore_crypto_ml_dsa_publickey_sizeof(void);
size_t shawncore_crypto_ml_dsa_publickey_alignof(void);
size_t shawncore_crypto_ml_dsa_signingkey_sizeof(void);
size_t shawncore_crypto_ml_dsa_signingkey_alignof(void);
size_t shawncore_crypto_ml_dsa_signature_sizeof(void);
size_t shawncore_crypto_ml_dsa_signature_alignof(void);
shawncore_crypto_err shawncore_crypto_ml_dsa_keygen(
    const uint8_t *seed,
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

size_t shawncore_crypto_x25519_publickey_sizeof(void);
size_t shawncore_crypto_x25519_publickey_alignof(void);
size_t shawncore_crypto_x25519_secret_sizeof(void);
size_t shawncore_crypto_x25519_secret_alignof(void);
size_t shawncore_crypto_x25519_sharedsecret_sizeof(void);
size_t shawncore_crypto_x25519_sharedsecret_alignof(void);
shawncore_crypto_err shawncore_crypto_x25519_keygen(
    const uint8_t *entropy,
    shawncore_crypto_x25519_publickey *out_pk,
    shawncore_crypto_x25519_secret *out_sk);
shawncore_crypto_err shawncore_crypto_x25519_secret_destroy(shawncore_crypto_x25519_secret *sk);
shawncore_crypto_err shawncore_crypto_x25519_diffie_hellman(
    const shawncore_crypto_x25519_secret *sk,
    const shawncore_crypto_x25519_publickey *peer_pk,
    shawncore_crypto_x25519_sharedsecret *out_shared);
shawncore_crypto_err shawncore_crypto_x25519_sharedsecret_destroy(shawncore_crypto_x25519_sharedsecret *shared);

shawncore_crypto_err shawncore_crypto_hmac_sha384(
    const uint8_t *key,
    const uint8_t *data,
    size_t data_len,
    uint8_t *out_mac);
shawncore_crypto_err shawncore_crypto_hkdf_expand_sha384(
    const uint8_t *prk,
    const uint8_t *info,
    size_t info_len,
    uint8_t *out,
    size_t out_len);
shawncore_crypto_err shawncore_crypto_aead_encrypt(
    const uint8_t *enc_key,
    const uint8_t *mac_key,
    const uint8_t *nonce,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *plaintext,
    uint8_t *ciphertext,
    size_t data_len,
    uint8_t *out_mac);
shawncore_crypto_err shawncore_crypto_aead_decrypt(
    const uint8_t *enc_key,
    const uint8_t *mac_key,
    const uint8_t *nonce,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *ciphertext,
    const uint8_t *mac,
    uint8_t *plaintext,
    size_t data_len);
shawncore_crypto_err shawncore_crypto_entropy_push(const uint8_t *chunk);
shawncore_crypto_err shawncore_crypto_entropy_mix(void);

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
uint64_t shawncore_rtos_scheduler_tick(shawncore_rtos_scheduler *scheduler, uint64_t current_rsp);
shawncore_rtos_err shawncore_rtos_scheduler_task_check_in(
    shawncore_rtos_scheduler *scheduler,
    uint8_t priority);

size_t shawncore_rtos_dmapool2k_sizeof(void);
size_t shawncore_rtos_dmapool2k_alignof(void);
shawncore_rtos_err shawncore_rtos_dmapool2k_init(
    shawncore_rtos_dmapool2k *pool,
    void *memory_base,
    size_t size_in_bytes);
shawncore_rtos_err shawncore_rtos_dmapool2k_destroy(shawncore_rtos_dmapool2k *pool);
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
