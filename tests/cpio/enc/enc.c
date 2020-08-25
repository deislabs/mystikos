// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include "calls_t.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <libos/file.h>
#include <libos/ramfs.h>
#include <libos/mount.h>
#include <libos/file.h>
#include <libos/cpio.h>
#include <libos/lsr.h>
#include <libos/trace.h>
#include <libos/atexit.h>

extern int oe_host_printf(const char* fmt, ...);

uint64_t rdtsc(void)
{
    uint32_t a = 0, d = 0;

    /* RDTSC requires SGX-2 */
    asm volatile ("rdtsc" : "=a"(a), "=d"(d));
    return (((uint64_t) d << 32) | a);
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

static size_t _fsize(const char* path)
{
    struct stat buf;

    if (libos_stat(path, &buf) != 0)
        return (size_t)-1;

    return (size_t)buf.st_size;
}

static const char* _paths[] =
{
    "/tmp/out/run",
    "/tmp/out/mount",
    "/tmp/out/empty",
    "/tmp/out/paths",
    "/tmp/out/cpio.bak",
    "/tmp/out/lthread",
    "/tmp/out/wake",
    "/tmp/out/cpio",
    "/tmp/out/mman",
    "/tmp/out/Makefile",
    "/tmp/out/fs",
    "/tmp/out/echo",
    "/tmp/out/run/run.edl",
    "/tmp/out/run/host.c",
    "/tmp/out/run/Makefile",
    "/tmp/out/mount/enc.c",
    "/tmp/out/mount/Makefile",
    "/tmp/out/empty/enc.c",
    "/tmp/out/empty/Makefile",
    "/tmp/out/paths/enc.c",
    "/tmp/out/paths/Makefile",
    "/tmp/out/cpio.bak/enc.c",
    "/tmp/out/cpio.bak/Makefile",
    "/tmp/out/lthread/enc.c",
    "/tmp/out/lthread/Makefile",
    "/tmp/out/wake/enc.c",
    "/tmp/out/wake/Makefile",
    "/tmp/out/cpio/host",
    "/tmp/out/cpio/calls.edl",
    "/tmp/out/cpio/enc",
    "/tmp/out/cpio/Makefile",
    "/tmp/out/cpio/host/host.c",
    "/tmp/out/cpio/host/Makefile",
    "/tmp/out/cpio/enc/enc.c",
    "/tmp/out/cpio/enc/Makefile",
    "/tmp/out/mman/main.c",
    "/tmp/out/mman/enc.c",
    "/tmp/out/mman/mman.c",
    "/tmp/out/mman/Makefile",
    "/tmp/out/fs/enc.c",
    "/tmp/out/fs/Makefile",
    "/tmp/out/echo/host",
    "/tmp/out/echo/calls.edl",
    "/tmp/out/echo/enc",
    "/tmp/out/echo/Makefile",
    "/tmp/out/echo/host/host.c",
    "/tmp/out/echo/host/Makefile",
    "/tmp/out/echo/enc/enc.c",
    "/tmp/out/echo/enc/Makefile",
};

static const size_t _npaths = sizeof(_paths) / sizeof(_paths[0]);

int cpio_ecall(const void* cpio_data, size_t cpio_size)
{
    libos_fs_t* fs;

    assert(libos_init_ramfs(&fs) == 0);
    assert(libos_mount(fs, "/") == 0);

    assert(libos_mkdirhier("/proc/self/fd", 0777) == 0);

    /* create the /tmp directory */
    assert(libos_mkdir("/tmp", 0777) == 0);
    assert(libos_mkdir("/tmp/out", 0777) == 0);

    /* create /tmp/cpio */
    assert(_create_cpio_file("/tmp/cpio", cpio_data, cpio_size) == 0);
    assert(libos_access("/tmp/cpio", R_OK) == 0);
    assert(_fsize("/tmp/cpio") == cpio_size);

    /* unpack the cpio archive */
    const bool trace = libos_get_trace();
    libos_set_trace(false);
    assert(libos_cpio_unpack("/tmp/cpio", "/tmp/out") == 0);
    libos_set_trace(trace);

    libos_strarr_t paths = LIBOS_STRARR_INITIALIZER;
    assert(libos_lsr("/tmp/out", &paths) == 0);

    assert(_npaths == paths.size);

    for (size_t i = 0; i < paths.size; i++)
        assert(strcmp(paths.data[i], _paths[i]) == 0);

    assert((*fs->fs_release)(fs) == 0);

    libos_strarr_release(&paths);

    libos_call_atexit_functions();

    return 0;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    2);   /* NumTCS */
