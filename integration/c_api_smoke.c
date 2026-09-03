#include "shawncore.h"

_Static_assert(sizeof(shawncore_rtos_tcb) == 64, "TCB ABI changed");
_Static_assert(_Alignof(shawncore_rtos_tcb) == 64, "TCB alignment changed");
_Static_assert(sizeof(shawncore_rtos_telemetry_event) == 64, "telemetry ABI changed");
_Static_assert(_Alignof(shawncore_rtos_telemetry_event) == 64, "telemetry alignment changed");
_Static_assert(sizeof(shawncore_rtos_ew_command) == 24, "EW command ABI changed");
_Static_assert(sizeof(shawncore_rtos_fft_result) == 64, "FFT ABI changed");
_Static_assert(_Alignof(shawncore_rtos_fft_result) == 64, "FFT alignment changed");

int main(void)
{
    return shawncore_crypto_session_manager_sizeof() == 0 ||
                   shawncore_crypto_ml_kem_publickey_alignof() == 0 ||
                   shawncore_rtos_scheduler_sizeof() == 0 ||
                   shawncore_rtos_spsc_fft_slot_sizeof() == 0 ||
                   shawncore_rtos_fft_result_sizeof() != sizeof(shawncore_rtos_fft_result)
               ? 1
               : 0;
}
