// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/*
  position            content                     size (bytes) + comment
  ------------------------------------------------------------------------
  stack pointer ->  [ argc = number of args ]     4
                    [ argv[0] (pointer) ]         4   (program name)
                    [ argv[1] (pointer) ]         4
                    [ argv[..] (pointer) ]        4 * x
                    [ argv[n - 1] (pointer) ]     4
                    [ argv[n] (pointer) ]         4   (= NULL)

                    [ envp[0] (pointer) ]         4
                    [ envp[1] (pointer) ]         4
                    [ envp[..] (pointer) ]        4
                    [ envp[term] (pointer) ]      4   (= NULL)

                    [ auxv[0] (Elf32_auxv_t) ]    8
                    [ auxv[1] (Elf32_auxv_t) ]    8
                    [ auxv[..] (Elf32_auxv_t) ]   8
                    [ auxv[term] (Elf32_auxv_t) ] 8   (= AT_NULL vector)

                    [ padding ]                   0 - 16

                    [ argument ASCIIZ strings ]   >= 0
                    [ environment ASCIIZ str. ]   >= 0

  (0xbffffffc)      [ end marker ]                4   (= NULL)

  (0xc0000000)      < bottom of stack >           0   (virtual)
*/

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
