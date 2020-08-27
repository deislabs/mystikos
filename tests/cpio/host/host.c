// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>
#include "calls_u.h"

static int _load_file(const char* path, void** data_out, size_t* size_out)
{
    int ret = -1;
    FILE* is = NULL;
    void* data = NULL;
    size_t size;

    if (data_out)
        *data_out = NULL;

    if (size_out)
        *size_out = 0;

    /* Check parameters */
    if (!path || !data_out || !size_out)
        goto done;

    /* Get size of this file */
    {
        struct stat buf;

        if (stat(path, &buf) != 0)
            goto done;

        size = buf.st_size;
    }

    /* Allocate memory */
    if (!(data = malloc(size)))
        goto done;

    /* Open the file */
    if (!(is = fopen(path, "rb")))
        goto done;

    /* Read file into memory */
    if (fread(data, 1, size, is) != size)
        goto done;

    *size_out = size;
    *data_out = data;
    data = NULL;
    ret = 0;

done:

    if (data)
        free(data);

    if (is)
        fclose(is);

    return ret;
}

int main(int argc, const char* argv[])
{
    oe_result_t r;
    oe_enclave_t* enclave = NULL;
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;
    const uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;
    int retval;
    void* cpio_data = NULL;
    size_t cpio_size;

    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH CPIO_PATH\n", argv[0]);
        return 1;
    }

    r = oe_create_calls_enclave(argv[1], type, flags, NULL, 0, &enclave);
    if (r != OE_OK)
    {
        fprintf(stderr, "%s: oe_create_cpio_enclave(): %u\n", argv[0], r);
        exit(1);
    }

    if (_load_file(argv[2], &cpio_data, &cpio_size) != 0)
    {
        fprintf(stderr, "%s: failed to load file: %s\n", argv[0], argv[2]);
        exit(1);
    }

    r = cpio_ecall(enclave, &retval, cpio_data, cpio_size);
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

    printf("=== passed test (cpio)\n");

    return 0;
}
