// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <stdio.h>
#include <string.h>

/* non-public OE functions */
extern const void* __oe_get_enclave_start_address(void);
extern const void* __oe_get_enclave_base_address(void);

void test_zerobase(void)
{
    const void* start_address = __oe_get_enclave_start_address();
    printf("=== enclave_start_address=%p\n", start_address);

    const void* base_address = __oe_get_enclave_base_address();
    printf("=== enclave_base_address=%p\n", base_address);
}

int main(int argc, const char* argv[], const char* envp[])
{
    printf("\n");

    for (int i = 0; i < argc; i++)
        printf("argv[%d]=%s\n", i, argv[i]);

    printf("\n");

    for (int i = 0; envp[i] != NULL; i++)
        printf("envp[%d]=%s\n", i, envp[i]);

    printf("\n");

    printf("=== Hello World!\n\n");

    if (strstr(argv[1], "zero-base"))
        test_zerobase();

    return 0;
}
