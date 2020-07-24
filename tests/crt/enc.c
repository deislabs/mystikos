// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include "run_t.h"

extern int oe_host_printf(const char* fmt, ...);

#define PRINTF oe_host_printf

int run_ecall(void)
{
    PRINTF("=== hello\n");

    return 0;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    16*4096, /* NumHeapPages */
    4096, /* NumStackPages */
    2);   /* NumTCS */
