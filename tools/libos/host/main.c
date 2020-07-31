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
#include "libos_u.h"

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

static int _which(const char* program, char buf[PATH_MAX])
{
    int ret = -1;
    char path[PATH_MAX];

    if (buf)
        *buf = '\0';

    if (!program || !buf)
        goto done;

    /* If the program has slashes the use realpath */
    if (strchr(program, '/'))
    {
        char current[PATH_MAX];

        if (!realpath(program, current))
            goto done;

        if (access(current, X_OK) == 0)
        {
            strcpy(buf, current);
            ret = 0;
            goto done;
        }

        goto done;
    }

    /* Get the PATH environment variable */
    {
        const char* p;

        if (!(p = getenv("PATH")) || strlen(p) >= PATH_MAX)
            goto done;

        strcpy(path, p);
    }

    /* Search the PATH for the program */
    {
        char* p;
        char* save;

        for (p = strtok_r(path, ":", &save); p; p = strtok_r(NULL, ":", &save))
        {
            char current[PATH_MAX];
            int n;

            n = snprintf(current, sizeof(current), "%s/%s", p, program);
            if (n >= sizeof(current))
                goto done;

            if (access(current, X_OK) == 0)
            {
                strcpy(buf, current);
                ret = 0;
                goto done;
            }
        }
    }

    /* not found */

done:
    return ret;
}

static int _get_opt(
    int* argc,
    const char* argv[],
    const char* opt,
    const char** optarg)
{
    size_t olen = strlen(opt);

    if (optarg)
        *optarg = NULL;

    if (!opt)
        _err("unexpected");


    for (int i = 0; i < *argc; )
    {
        if (strcmp(argv[i], opt) == 0)
        {
            if (optarg)
            {
                if (i + 1 == *argc)
                    _err("%s: missing option argument", opt);

                *optarg = argv[i+1];
                memmove(&argv[i], &argv[i+2], (*argc - i - 1) * sizeof(char*));
                (*argc) -= 2;
                return 0;
            }
            else
            {
                memmove(&argv[i], &argv[i+1], (*argc - i) * sizeof(char*));
                (*argc)--;
                return 0;
            }
        }
        else if (strncmp(argv[i], opt, olen) == 0 && argv[i][olen] == '=')
        {
            if (!optarg)
                _err("%s: extraneous '='", opt);

            *optarg = &argv[i][olen + 1];
            memmove(&argv[i], &argv[i+1], (*argc - i) * sizeof(char*));
            (*argc)--;
            return 0;
        }
        else
        {
            i++;
        }
    }

    /* Not found! */
    return -1;
}

#define USAGE "\
\n\
Usage: %s [options] <rootfs> <program> <args...>\n\
\n\
Options:\n\
	--help - print this help message\n\
	--trace-syscalls - trace system calls\n\
\n\
"

int main(int argc, const char* argv[])
{
    oe_result_t r;
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;
    oe_enclave_t* enclave;
    const uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;
    int retval;
    char dir[PATH_MAX];
    char rootfs[PATH_MAX];
    char libosenc[PATH_MAX];
    char liboscrt[PATH_MAX];
    char path[PATH_MAX];
    void* args = NULL;
    size_t args_size;
    struct libos_options options;

    /* Get the full path of argv[0] */
    if (_which(argv[0], _arg0) != 0)
    {
        fprintf(stderr, "%s: failed to get full path of argv[0]\n", argv[0]);
        return 1;
    }

    /* Get options */
    {
        /* Get --trace-syscalls option */
        if (_get_opt(&argc, argv, "--trace-syscalls", NULL) == 0)
            options.trace_syscalls = true;
    }

    if (argc < 3)
    {
        fprintf(stderr, USAGE, argv[0]);
        return 1;
    }

    const char* program = argv[2];

    if (!realpath(argv[1], rootfs) != 0)
        _err("failed to resovle rootfs directory: %s", argv[1]);

    if (!_is_dir(rootfs))
        _err("rootfs dir not found: %s", rootfs);

    if (program[0] != '/')
        _err("program must be an absolute path: %s", rootfs);

    /* Get the directory that contains argv[0] */
    strcpy(dir, _arg0);
    dirname(dir);

    /* Find libosenc.so and liboscrt.so */
    {
        int n;

        n = snprintf(libosenc, sizeof(libosenc), "%s/enc/libosenc.so", dir);
        if (n >= sizeof libosenc)
            _err("buffer overflow when forming libosenc.so path");

        n = snprintf(liboscrt, sizeof(liboscrt), "%s/enc/liboscrt.so", dir);
        if (n >= sizeof liboscrt)
            _err("buffer overflow when forming liboscrt.so path");

        if (access(libosenc, R_OK) != 0)
            _err("cannot find: %s", libosenc);

        if (access(liboscrt, R_OK) != 0)
            _err("cannot find: %s", liboscrt);
    }

    /* Format path to pass to oe_create_enclave() */
    {
        int n;

        n = snprintf(path, sizeof(path), "%s:%s", libosenc, liboscrt);
        if (n >= sizeof path)
            _err("buffer overflow when forming enclave path");
    }

    /* Load the enclave (including libosenc.so and liboscrt.so) */
    r = oe_create_libos_enclave(path, type, flags, NULL, 0, &enclave);
    if (r != OE_OK)
        _err("failed to load enclave: result=%s", oe_result_str(r));

    /* Serialize the argv[] strings */
    if (_serialize_args(argv + 2, &args, &args_size) != 0)
        _err("failed to serialize argv srings");

    const char env[] = "PATH=/bin\0HOME=/root";

    /* Enter the enclave and run the program */
    r = libos_enter_ecall(
        enclave, &retval, &options, rootfs, args, args_size, env, sizeof(env));
    if (r != OE_OK)
        _err("failed to enter enclave: result=%s", oe_result_str(r));

    /* Terminate the enclave */
    r = oe_terminate_enclave(enclave);
    if (r != OE_OK)
        _err("failed to terminate enclave: reuslt=%s", oe_result_str(r));

    free(args);

    return retval;
}
