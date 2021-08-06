// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <openenclave/enclave.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* non-public OE functions */
extern const void* __oe_get_enclave_start_address(void);
extern const void* __oe_get_enclave_base_address(void);

#define ENCLAVE_START_ADDRESS 0x000000800000 /* fixed at 8mb */
#define ENCLAVE_BASE_ADDRESS 0x0

void test_zerobase(void)
{
#ifdef MYST_ENABLE_ZERO_BASE_ENCLAVES
    const void* start_address = __oe_get_enclave_start_address();
    printf("=== enclave_start_address=%p\n", start_address);
    assert(start_address == (void*)ENCLAVE_START_ADDRESS);

    const void* base_address = __oe_get_enclave_base_address();
    printf("=== enclave_base_address=%p\n", base_address);
    assert(base_address == (void*)ENCLAVE_BASE_ADDRESS);
#endif

    printf("=== passed test (%s)\n", __FUNCTION__);
}

int main(int argc, const char* argv[])
{
    const char* target = getenv("MYST_TARGET");

    if (strcmp(target, "sgx") == 0)
        test_zerobase();

    printf("=== passed test (%s)\n", argv[0]);

    return 0;
}
