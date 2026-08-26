/*
 * MarTac HAL integration stubs (COMPILE-ONLY, NOT FOR PRODUCTION).
 *
 * These functions intentionally contain no platform behavior. Replace every body
 * with the board-approved implementation and register the callbacks before
 * invoking crypto or RTOS code. Shipping this file as the platform HAL is a
 * release blocker: zero timestamps disable telemetry and the security callbacks
 * do not provide real interrupt, cache, stack, or panic handling.
 */

#include <stddef.h>
#include <stdint.h>

/* Rust callback registration entry points. */
extern void shawncore_crypto_register_panic_hook(void (*callback)(void));
extern void shawncore_crypto_register_disable_interrupts(uintptr_t (*callback)(void));
extern void shawncore_crypto_register_restore_interrupts(void (*callback)(uintptr_t));
extern void shawncore_crypto_register_cache_flush(void (*callback)(const uint8_t *, size_t));
extern void shawncore_crypto_register_stack_wipe(void (*callback)(uint64_t));
extern void shawncore_rtos_register_disable_interrupts(uintptr_t (*callback)(void));
extern void shawncore_rtos_register_restore_interrupts(void (*callback)(uintptr_t));
extern void shawncore_rtos_register_read_monotonic_clock(uint64_t (*callback)(void));

void host_panic_handler(void)
{
    /*
     * Replace with the MarTac fault path: capture immutable diagnostics,
     * disable unsafe peripherals, and enter the platform fail-safe state.
     * This function must not return or unwind into Rust.
     */
    for (;;) {
        /* ARM Cortex-R: insert approved fault/interrupt masking instructions.
         * RISC-V: insert the approved machine/supervisor interrupt shutdown. */
    }
}

uintptr_t host_disable_interrupts(void)
{
    /*
     * ARM Cortex-R: insert firmware-approved CPSID/interrupt-controller save
     * sequence and return the exact prior interrupt state.
     * RISC-V: save mstatus/sstatus and mask interrupts using approved assembly.
     */
    return 0;
}

void host_restore_interrupts(uintptr_t saved_state)
{
    (void)saved_state;
    /*
     * ARM Cortex-R: restore the saved interrupt-controller/CPSR state.
     * RISC-V: restore the saved mstatus/sstatus value with approved assembly.
     */
}

void host_cache_flush(const uint8_t *ptr, size_t len)
{
    (void)ptr;
    (void)len;
    /*
     * ARM Cortex-R: perform the required D-cache clean/invalidate sequence,
     * including DSB/ISB barriers, for the supplied DMA range.
     * RISC-V: use the board cache-maintenance primitive and required fences.
     */
}

void host_stack_wipe(uint64_t stack_base)
{
    (void)stack_base;
    /*
     * ARM Cortex-R: call the approved assembly routine that wipes the defined
     * stack range without clobbering the return path.
     * RISC-V: use the approved stack-wipe assembly routine and fence sequence.
     */
}

uint64_t host_read_monotonic_clock(void)
{
    /*
     * ARM Cortex-R: read the architected generic timer or approved RTOS clock.
     * RISC-V: read the approved time source, applying the platform ordering
     * requirements. The returned value must be monotonic and use documented
     * units/frequency.
     */
    return 0;
}

void martac_hal_register_callbacks(void)
{
    shawncore_crypto_register_panic_hook(host_panic_handler);
    shawncore_crypto_register_disable_interrupts(host_disable_interrupts);
    shawncore_crypto_register_restore_interrupts(host_restore_interrupts);
    shawncore_crypto_register_cache_flush(host_cache_flush);
    shawncore_crypto_register_stack_wipe(host_stack_wipe);
    shawncore_rtos_register_disable_interrupts(host_disable_interrupts);
    shawncore_rtos_register_restore_interrupts(host_restore_interrupts);
    shawncore_rtos_register_read_monotonic_clock(host_read_monotonic_clock);
}
