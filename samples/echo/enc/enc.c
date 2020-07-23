// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include "calls_t.h"

extern int oe_host_printf(const char* fmt, ...);

uint64_t rdtsc(void)
{
    uint32_t a = 0, d = 0;

    /* RDTSC requires SGX-2 */
    asm volatile ("rdtsc" : "=a"(a), "=d"(d));
    return (((uint64_t) d << 32) | a);
}

int echo_ecall(char* msg)
{
    int ret;

    if (echo_ocall(&ret, msg) != OE_OK)
        return -1;

    oe_host_printf("rdtsc()=%lu\n", rdtsc());

    return ret;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    2);   /* NumTCS */
