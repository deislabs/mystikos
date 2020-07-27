// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include "oelrun_t.h"
#include <stdio.h>
#include <string.h>

extern int oe_host_printf(const char* fmt, ...);

static int _deserialize_args(
    const void* args,
    size_t args_size,
    const char* argv[],
    size_t argv_size)
{
    int ret = -1;
    size_t n = 0;
    const char* p = (const char*)args;
    const char* end = (const char*)args + args_size;

    while (p != end)
    {
        if (n == argv_size)
            goto done;

        argv[n++] = p;
        p += strlen(p) + 1;
    }

    argv[n] = NULL;
    ret = 0;

done:
    return ret;
}

static void _dump_argv(const char* argv[])
{
    for (int i = 0; argv[i]; i++)
        printf("argv[%d]=%s\n", i, argv[i]);
}

int oelrun_enter_ecall(
    const char* rootfs,
    const void* args,
    size_t args_size,
    const void* env,
    size_t env_size)
{
    int ret = -1;
    const char* argv[64];
    size_t argv_size = sizeof(argv) / sizeof(argv[0]);

    if (!rootfs || !args || !args_size)
        goto done;

    if (!env || !env_size)
        goto done;

    if (_deserialize_args(args, args_size, argv, argv_size) != 0)
        goto done;

    _dump_argv(argv);

    oe_host_printf("********* oelrun_ecall()\n");

    ret = 0;

done:
    return ret;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    2);   /* NumTCS */
