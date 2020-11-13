// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include "calls_t.h"

extern int oe_host_printf(const char* fmt, ...);

int echo_ecall(char* msg)
{
    int ret;

    if (echo_ocall(&ret, msg) != OE_OK)
        return -1;

    return ret;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    2);   /* NumTCS */
