// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <libos/file.h>
#include <openenclave/host.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "calls_u.h"

int main(int argc, const char* argv[])
{
    oe_result_t r;
    oe_enclave_t* enclave = NULL;
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;
    const uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;
    int retval;
    void* cpio_data = NULL;
    size_t cpio_size;
    bool load_from_memory = false;

    if (argc != 3 && argc != 4)
    {
        fprintf(
            stderr, "Usage: %s ENCLAVE_PATH CPIO_PATH [mem|file]\n", argv[0]);
        return 1;
    }

    if (argc == 4)
    {
        if (strcmp(argv[3], "mem") == 0)
        {
            load_from_memory = true;
        }
        else if (strcmp(argv[3], "file") != 0)
        {
            fprintf(
                stderr,
                "%s: argument must be 'mem' or 'file': %s\n",
                argv[0],
                argv[3]);
            exit(1);
        }
    }

    r = oe_create_calls_enclave(argv[1], type, flags, NULL, 0, &enclave);
    if (r != OE_OK)
    {
        fprintf(stderr, "%s: oe_create_cpio_enclave(): %u\n", argv[0], r);
        exit(1);
    }

    if (libos_load_file(argv[2], &cpio_data, &cpio_size) != 0)
    {
        fprintf(stderr, "%s: failed to load file: %s\n", argv[0], argv[2]);
        exit(1);
    }

    r = cpio_ecall(enclave, &retval, cpio_data, cpio_size, load_from_memory);
    if (r != OE_OK)
    {
        fprintf(stderr, "%s: cpio_ecall(): %u\n", argv[0], r);
        exit(1);
    }

    r = oe_terminate_enclave(enclave);
    if (r != OE_OK)
    {
        fprintf(stderr, "%s: oe_terminate_enclave(): %u\n", argv[0], r);
        exit(1);
    }

    printf("=== passed test (cpio: load from %s)\n", argv[3]);

    return 0;
}
