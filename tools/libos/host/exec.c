// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
#include <openenclave/host.h>
#include <libos/elf.h>
#include <libos/strings.h>
#include <sys/stat.h>
#include <limits.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <libgen.h>
#include "utils.h"
#include "libos_u.h"
#include "regions.h"


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

static int _load_file(const char* path, size_t extra_space, void** data_out, size_t* size_out)
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
    if (!(data = malloc(size + extra_space)))
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

int _exec(int argc, const char* argv[])
{
    oe_result_t r;
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;
    oe_enclave_t* enclave;
    uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;
    int retval;
    char dir[PATH_MAX];
    char libosenc[PATH_MAX];
    char liboscrt[PATH_MAX];
    void* args = NULL;
    size_t args_size;
    struct libos_options options;
    elf_image_t crt_image;
    char crt_path[PATH_MAX];
    void* rootfs_data = NULL;
    size_t rootfs_size;

    assert(strcmp(argv[1], "exec") == 0);

    /* Get options */
    {
        /* Get --trace-syscalls option */
        if (_get_opt(&argc, argv, "--trace-syscalls", NULL) == 0 ||
            _get_opt(&argc, argv, "--strace", NULL) == 0)
        {
            options.trace_syscalls = true;
        }

        /* Get --real-syscalls option */
        if (_get_opt(&argc, argv, "--real-syscalls", NULL) == 0)
            options.real_syscalls = true;
    }

    if (options.real_syscalls)
    {
        flags |= OE_ENCLAVE_FLAG_SIMULATE;
    }

    if (argc < 4)
    {
        fprintf(stderr, "Usage: %s %s <rootfs> <program> <args...>\n",
            argv[0], argv[1]);
        return 1;
    }

    const char* rootfs = argv[2];
    const char* program = argv[3];

    if (_load_file(rootfs, 0, &rootfs_data, &rootfs_size) != 0)
        _err("failed to load load rootfs: %s", rootfs);

    if (program[0] != '/')
        _err("program must be an absolute path: %s", program);

    /* Get the directory that contains argv[0] */
    strcpy(dir, get_program_file());
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

    /* Load the C runtime ELF image into memory */
    if (elf_image_load(liboscrt, &crt_image) != 0)
        _err("failed to load C runtime image: %s", liboscrt);

    if (LIBOS_STRLCPY(crt_path, liboscrt) >= sizeof(crt_path))
        _err("path is too long: %s", liboscrt);

    set_region_details(&crt_image, crt_path, rootfs_data, rootfs_size);

    /* Load the enclave: calls oe_region_add_regions() */
    r = oe_create_libos_enclave(libosenc, type, flags, NULL, 0, &enclave);
    if (r != OE_OK)
        _err("failed to load enclave: result=%s", oe_result_str(r));

    /* Serialize the argv[] strings */
    if (_serialize_args(argv + 3, &args, &args_size) != 0)
        _err("failed to serialize argv stings");

    const char env[] = "PATH=/bin\0HOME=/root";

    /* Enter the enclave and run the program */
    r = libos_enter_ecall(
        enclave,
        &retval,
        &options,
        args,
        args_size,
        env,
        sizeof(env));
    if (r != OE_OK)
        _err("failed to enter enclave: result=%s", oe_result_str(r));

    /* Terminate the enclave */
    r = oe_terminate_enclave(enclave);
    if (r != OE_OK)
        _err("failed to terminate enclave: result=%s", oe_result_str(r));

    free(args);
    free(rootfs_data);
    elf_image_free(&crt_image);

    return retval;
}
