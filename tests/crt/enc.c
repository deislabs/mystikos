// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include "run_t.h"

extern int oe_host_printf(const char* fmt, ...);

#define PRINTF oe_host_printf

typedef long (*syscall_callback_t)(long n, long params[6]);

long _syscall(long n, long params[6])
{
#if 0
    PRINTF("syscall: n=%ld\n", n);
#endif

    if (n == 1000)
    {
        PRINTF("trace: %s\n", (const char*)params[0]);
    }
    else if (n == 1001)
    {
        PRINTF("trace: %s=%p\n", (const char*)params[0], (void*)params[1]);
    }
}

static void _enter_crt(void)
{
    extern void* __oe_get_isolated_image_entry_point(void);
    extern const void* __oe_get_isolated_image_base();
    typedef void (*enter_t)(
        void* stack,
        const void* elf64_phdr,
        syscall_callback_t callback);

    enter_t enter = __oe_get_isolated_image_entry_point();
    oe_assert(enter);

    const void* elf64_phdr = __oe_get_isolated_image_base();

    (*enter)(NULL, elf64_phdr, _syscall);
}

int run_ecall(void)
{
    _enter_crt();
    return 0;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    16*4096, /* NumHeapPages */
    4096, /* NumStackPages */
    2);   /* NumTCS */
