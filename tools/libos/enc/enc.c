// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/bits/sgx/region.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sys/mount.h>
#include <libos/syscall.h>
#include <stdlib.h>
#include <libos/mmanutils.h>
#include <libos/elfutils.h>
#include <libos/ramfs.h>
#include <libos/mount.h>
#include <libos/file.h>
#include <libos/cpio.h>
#include <libos/trace.h>
#include "libos_t.h"
#include "../shared.h"

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

    if (libos_mkdir("/tmp", 777) != 0)
    {
        fprintf(stderr, "failed create the /tmp directory\n");
        abort();
    }

    if (libos_mkdirhier("/proc/self/fd", 777) != 0)
    {
        fprintf(stderr, "failed create the /proc/self/fd directory\n");
        abort();
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
    const char rootfs_path[] = "/tmp/rootfs.cpio";
    const void* crt_image_base;
    const void* rootfs_data;
    size_t rootfs_size;

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

    /* Fetch the rootfs image */
    {
        extern const void* __oe_get_enclave_base(void);
        oe_region_t region;
        const uint8_t* enclave_base;

        if (!(enclave_base = __oe_get_enclave_base()))
        {
            fprintf(stderr, "__oe_get_enclave_base() failed\n");
            assert(0);
        }

        if (oe_region_get(ROOTFS_REGION_ID, &region) != OE_OK)
        {
            fprintf(stderr, "failed to get crt region\n");
            assert(0);
        }

        rootfs_data = enclave_base + region.vaddr;
        rootfs_size = region.size;
    }

    if (_create_cpio_file(rootfs_path, rootfs_data, rootfs_size) != 0)
    {
        fprintf(stderr, "failed to create %s\n", rootfs_path);
        assert(0);
    }

    assert(libos_access(rootfs_path, R_OK) == 0);

    /* unpack the cpio archive */
    {
        const bool trace = libos_get_trace();

        libos_set_trace(false);

        if (libos_cpio_unpack(rootfs_path, "/") != 0)
        {
            fprintf(stderr, "failed to unpack: %s\n", rootfs_path);
            assert(0);
        }

        libos_set_trace(trace);
    }

    /* Set up the standard directories (some may already exist) */
    {
        libos_set_trace(false);
        libos_mkdir("/tmp", 777);
        libos_mkdir("/proc", 777);
        libos_mkdir("/proc/self", 777);
        libos_mkdir("/proc/self/fd", 777);
        libos_set_trace(true);
    }

    _setup_sockets();

    /* Find the base address of the C runtime ELF image */
    {
        extern const void* __oe_get_enclave_base(void);
        oe_region_t region;
        const uint8_t* enclave_base;

        if (!(enclave_base = __oe_get_enclave_base()))
        {
            fprintf(stderr, "__oe_get_enclave_base() failed\n");
            assert(0);
        }

        if (oe_region_get(CRT_REGION_ID, &region) != OE_OK)
        {
            fprintf(stderr, "failed to get crt region\n");
            assert(0);
        }

        crt_image_base = enclave_base + region.vaddr;
    }

    const size_t argc = _count_args(argv);
    const size_t envc = _count_args(envp);
    ret = elf_enter_crt(crt_image_base, argc, argv, envc, envp);

    _teardown_ramfs();
    libos_teardown_mman();

done:
    return ret;
}

_Static_assert(sizeof(struct libos_timespec) == sizeof(struct timespec), "");

/* ATTN: replace this with clock ticks implementation */
/* This overrides the weak version in liboskernel.a */
long libos_syscall_clock_gettime(clockid_t clk_id, struct timespec* tp_)
{
    int retval = -1;
    struct libos_timespec* tp = (struct libos_timespec*)tp_;

    if (libos_clock_gettime_ocall(&retval, clk_id, tp) != OE_OK)
        return -EINVAL;

    return (long)retval;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    8*4096, /* NumHeapPages */
    1024, /* NumStackPages */
    4);   /* NumTCS */
