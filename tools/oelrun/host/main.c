// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <stdio.h>
#include <libgen.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <limits.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <unistd.h>
#include "oelrun_u.h"

static char _arg0[PATH_MAX];

__attribute__((format(printf, 1, 2)))
static void _err(const char* fmt, ...)
{
    va_list ap;

    fprintf(stderr, "%s: error: ", _arg0);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");

    exit(1);
}

static bool _is_dir(const char* path)
{
    struct stat buf;

    if (stat(path, &buf) != 0)
        return false;

    return S_ISDIR(buf.st_mode);
}

static int _serialize_args(
    const char* argv[],
    void** args_out,
    size_t* args_size_out)
{
    int ret = -1;
    void* args = NULL;
    size_t args_size = 0;

    if (args_out)
        *args_out = NULL;

    if (args_size_out)
        *args_size_out = 0;

    if (!argv || !args_out || !args_size_out)
        goto done;

    /* Determine the size of the output buffer */
    for (size_t i = 0; argv[i]; i++)
        args_size += strlen(argv[i]) + 1;

    if (!(args = malloc(args_size)))
        goto done;

    memset(args, 0, args_size);

    /* Copy the strings */
    {
        uint8_t* p = args;

        for (size_t i = 0; argv[i]; i++)
        {
            size_t n = strlen(argv[i]) + 1;

            memcpy(p, argv[i], n);
            p += n;
        }
    }

    *args_out = args;
    args = NULL;
    *args_size_out = args_size;
    ret = 0;

done:

    if (args)
        free(args);

    return ret;
}

int main(int argc, const char* argv[])
{
    oe_result_t r;
    oe_enclave_t* enclave = NULL;
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;
    const uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;
    int retval;
    char dir[PATH_MAX];
    char liboelenc[PATH_MAX];
    char liboelcrt[PATH_MAX];
    char path[PATH_MAX];
    void* args = NULL;
    size_t args_size;

    if (argc < 3)
    {
        fprintf(stderr, "Usage: %s <rootfs> <program> <program-arg>...\n",
            argv[0]);
        return 1;
    }

    const char* rootfs = argv[1];
    const char* program = argv[2];

    if (!_is_dir(rootfs))
        _err("rootfs dir not found: %s", rootfs);

    if (program[0] != '/')
        _err("program must be an absolute path: %s", rootfs);

    /* Get the full path of argv[0] */
    if (!realpath(argv[0], _arg0))
        _err("failed to resolve the full path of argv[0]");

    /* Get the directory that contains argv[0] */
    strcpy(dir, _arg0);
    dirname(dir);

    /* Find liboelenc.so and liboelcrt.so */
    {
        int n;

        n = snprintf(liboelenc, sizeof(liboelenc), "%s/enc/liboelenc.so", dir);
        if (n >= sizeof liboelenc)
            _err("buffer overflow when forming liboelenc.so path");

        n = snprintf(liboelcrt, sizeof(liboelcrt), "%s/enc/liboelcrt.so", dir);
        if (n >= sizeof liboelcrt)
            _err("buffer overflow when forming liboelcrt.so path");

        if (access(liboelenc, R_OK) != 0)
            _err("cannot find: %s", liboelenc);

        if (access(liboelcrt, R_OK) != 0)
            _err("cannot find: %s", liboelcrt);
    }

    /* Format path to pass to oe_create_enclave() */
    {
        int n;

        n = snprintf(path, sizeof(path), "%s:%s", liboelenc, liboelcrt);
        if (n >= sizeof path)
            _err("buffer overflow when forming enclave path");
    }

    /* Load the enclave (including liboelenc.so and liboelcrt.so) */
    r = oe_create_oelrun_enclave(path, type, flags, NULL, 0, &enclave);
    if (r != OE_OK)
        _err("failed to load enclave: result=%s", oe_result_str(r));

    /* Serialize the argv[] strings */
    if (_serialize_args(argv + 2, &args, &args_size) != 0)
        _err("failed to serialize argv srings");

    const char env[] = "PATH=/bin\0HOME=/root";

    /* Enter the enclave and run the program */
    r = oelrun_enter_ecall(
        enclave, &retval, rootfs, args, args_size, env, sizeof(env));
    if (r != OE_OK)
        _err("failed to enter enclave: result=%s", oe_result_str(r));

    /* Terminate the enclave */
    r = oe_terminate_enclave(enclave);
    if (r != OE_OK)
        _err("failed to terminate enclave: reuslt=%s", oe_result_str(r));

    printf("success\n");

    free(args);

    return retval;
}
