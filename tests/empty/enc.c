// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include "run_t.h"

int run_ecall(void)
{
    return 0;
}

OE_SET_ENCLAVE_SGX(
    1,         /* ProductID */
    1,         /* SecurityVersion */
    true,      /* Debug */
    16 * 4096, /* NumHeapPages */
    4096,      /* NumStackPages */
    2);        /* NumTCS */
