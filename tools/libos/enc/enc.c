// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/mount.h>
#include <libos/syscall.h>
#include <stdlib.h>
#include <libos/mmanutils.h>
#include <libos/elfutils.h>
#include <libos/ramfs.h>
#include <libos/mount.h>
#include <libos/file.h>
#include <libos/cpio.h>
#include "libos_t.h"

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

static size_t _count_args(const char* args[])
{
    size_t n = 0;

    for (size_t i = 0; args[i]; i++)
        n++;

    return n;
}

#if 0
static void _dump_args(const char* args[])
{
    printf("args=%p\n", args);
    for (int i = 0; args[i]; i++)
        printf("args[%d]=%s\n", i, args[i]);
}
#endif

static libos_fs_t* _fs;

static void _setup_ramfs(void)
{
    if (libos_init_ramfs(&_fs) != 0)
    {
        fprintf(stderr, "failed to initialize the ramfs\n");
        abort();
    }

    if (libos_mount(_fs, "/") != 0)
    {
        fprintf(stderr, "failed to mount ramfs\n");
        abort();
    }

    if (libos_mkdir("/libos", 777) != 0)
    {
        fprintf(stderr, "failed create the /libos directory\n");
        abort();
    }

    if (libos_mkdir("/libos/tmp", 777) != 0)
    {
        fprintf(stderr, "failed create the /libos/tmp directory\n");
        abort();
    }

    /* Create /proc/self/fd directory */
    /* TODO: implement libos_mkdir_recursive() */
    {
        if (libos_mkdir("/proc", 777) != 0)
        {
            fprintf(stderr, "failed create the /proc directory\n");
            abort();
        }

        if (libos_mkdir("/proc/self", 777) != 0)
        {
            fprintf(stderr, "failed create the /proc/self directory\n");
            abort();
        }

        if (libos_mkdir("/proc/self/fd", 777) != 0)
        {
            fprintf(stderr, "failed create the /proc/self/fd directory\n");
            abort();
        }
    }
}

static void _teardown_ramfs(void)
{
    if ((*_fs->fs_release)(_fs) != 0)
    {
        fprintf(stderr, "failed to release ramfs\n");
        abort();
    }
}

static void _setup_sockets(void)
{
    if (oe_load_module_host_socket_interface() != OE_OK)
    {
        fprintf(stderr, "oe_load_module_host_socket_interface() failed\n");
        assert(0);
    }
}

ssize_t _writen(int fd, const void* data, size_t size)
{
    int ret = -1;
    const uint8_t* p = (const uint8_t*)data;
    size_t r = size;

    while (r > 0)
    {
        ssize_t n;

        if ((n = libos_write(fd, p, r)) <= 0)
        {
            goto done;
        }

        p += n;
        r -= (size_t)n;
    }

    ret = 0;

done:
    return ret;
}

static int _create_cpio_file(const char* path, const char* data, size_t size)
{
    int ret = -1;
    int fd = -1;

    if (!path || !data || !size)
        goto done;

    if ((fd = libos_open(path, O_WRONLY | O_CREAT, 0666)) < 0)
        goto done;

    if (_writen(fd, data, size) != 0)
        goto done;

    ret = 0;

done:

    if (fd >= 0)
        libos_close(fd);

    return ret;
}

int libos_enter_ecall(
    struct libos_options* options,
    const void* rootfs_data,
    size_t rootfs_size,
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
    const char rootfs_path[] = "/libos/tmp/rootfs.cpio";

    if (!rootfs_data || !rootfs_size)
        goto done;

    if (!args || !args_size || !env || !env_size)
        goto done;

    if (_deserialize_args(args, args_size, argv + 1, argv_size - 1) != 0)
        goto done;

    if (_deserialize_args(env, env_size, envp, envp_size) != 0)
        goto done;

    argv[0] = "libosenc.so";

    if (options)
        libos_trace_syscalls(options->trace_syscalls);

#ifdef TRACE
    _dump_args(argv);
    _dump_args(envp);
#endif

    if (libos_setup_mman(MMAN_SIZE) != 0)
    {
        fprintf(stderr, "_setup_mman() failed\n");
        assert(0);
    }

    _setup_ramfs();

    if (_create_cpio_file(rootfs_path, rootfs_data, rootfs_size) != 0)
    {
        fprintf(stderr, "failed to create %s\n", rootfs_path);
        assert(0);
    }

    assert(libos_access(rootfs_path, R_OK) == 0);

    /* unpack the cpio archive */
    if (libos_cpio_unpack(rootfs_path, "/") != 0)
    {
        fprintf(stderr, "failed to unpack: %s\n", rootfs_path);
        assert(0);
    }

    _setup_sockets();

    const size_t argc = _count_args(argv);
    const size_t envc = _count_args(envp);
    ret = elf_enter_crt(argc, argv, envc, envp);

    _teardown_ramfs();
    libos_teardown_mman();

done:
    return ret;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    8*4096, /* NumHeapPages */
    1024, /* NumStackPages */
    4);   /* NumTCS */
