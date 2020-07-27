// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/mount.h>
#include <oel/syscall.h>
#include <oel/mmanutils.h>
#include <oel/elfutils.h>
#include "oelrun_t.h"

static const size_t MMAN_SIZE = 16 * 1024 * 1024;

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

static int _count_args(const char* args[])
{
    size_t n = 0;

    for (size_t i = 0; args[i]; i++)
        n++;

    return n;
}

static void _dump_args(const char* args[])
{
    for (int i = 0; args[i]; i++)
        printf("args[%d]=%s\n", i, args[i]);
}

static void _setup_hostfs(void)
{
    if (oe_load_module_host_file_system() != OE_OK)
    {
        fprintf(stderr, "oe_load_module_host_file_system() failed\n");
        assert(0);
    }

    if (mount("/", "/", OE_HOST_FILE_SYSTEM, 0, NULL) != 0)
    {
        fprintf(stderr, "mount() failed\n");
        assert(0);
    }
}

static void _teardown_hostfs(void)
{
    if (umount("/") != 0)
    {
        fprintf(stderr, "umount() failed\n");
        assert(0);
    }
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
    const char* envp[64];
    size_t envp_size = sizeof(envp) / sizeof(envp[0]);

    if (!rootfs || !args || !args_size || !env || !env_size)
        goto done;

    if (_deserialize_args(args, args_size, argv + 1, argv_size - 1) != 0)
        goto done;

    if (_deserialize_args(env, env_size, envp, envp_size) != 0)
        goto done;

    argv[0] = "liboelenc.so";

#ifdef TRACE
    _dump_args(argv);
    _dump_args(envp);
#endif

    if (oel_setup_mman(MMAN_SIZE) != 0)
    {
        fprintf(stderr, "_setup_mman() failed\n");
        assert(0);
    }

#ifdef TRACE
    printf("rootfs=%s\n", rootfs);
#endif

    _setup_hostfs();

    oel_set_rootfs(rootfs);

    const int argc = _count_args(argv);
    const int envc = _count_args(envp);
    ret = elf_enter_crt(argc, argv, envc, envp);

    _teardown_hostfs();
    oel_teardown_mman();

done:
    return ret;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    16*4096, /* NumHeapPages */
    4096, /* NumStackPages */
    8);   /* NumTCS */
