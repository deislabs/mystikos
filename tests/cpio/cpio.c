// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libos/atexit.h>
#include <libos/cpio.h>
#include <libos/file.h>
#include <libos/lsr.h>
#include <libos/mount.h>
#include <libos/ramfs.h>
#include <libos/trace.h>

extern int oe_host_printf(const char* fmt, ...);

uint64_t rdtsc(void)
{
    uint32_t a = 0, d = 0;

    /* RDTSC requires SGX-2 */
    asm volatile("rdtsc" : "=a"(a), "=d"(d));
    return (((uint64_t)d << 32) | a);
}

ssize_t _writen(int fd, const void* data, size_t size)
{
    int ret = -1;
    const uint8_t* p = (const uint8_t*)data;
    size_t r = size;

    while (r > 0)
    {
        ssize_t n;

        if ((n = write(fd, p, r)) <= 0)
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

    if ((fd = open(path, O_WRONLY | O_CREAT, 0666)) < 0)
        goto done;

    if (_writen(fd, data, size) != 0)
        goto done;

    ret = 0;

done:

    if (fd >= 0)
        close(fd);

    return ret;
}

static size_t _fsize(const char* path)
{
    struct stat buf;

    if (stat(path, &buf) != 0)
        return (size_t)-1;

    return (size_t)buf.st_size;
}

static const char* _paths[] = {
    "run",
    "mount",
    "empty",
    "paths",
    "cpio.bak",
    "lthread",
    "wake",
    "cpio",
    "mman",
    "Makefile",
    "fs",
    "echo",
    "run/run.edl",
    "run/host.c",
    "run/Makefile",
    "mount/enc.c",
    "mount/Makefile",
    "empty/enc.c",
    "empty/Makefile",
    "paths/enc.c",
    "paths/Makefile",
    "cpio.bak/enc.c",
    "cpio.bak/Makefile",
    "lthread/enc.c",
    "lthread/Makefile",
    "wake/enc.c",
    "wake/Makefile",
    "cpio/host",
    "cpio/calls.edl",
    "cpio/enc",
    "cpio/Makefile",
    "cpio/host/host.c",
    "cpio/host/Makefile",
    "cpio/enc/enc.c",
    "cpio/enc/Makefile",
    "mman/main.c",
    "mman/enc.c",
    "mman/mman.c",
    "mman/Makefile",
    "fs/enc.c",
    "fs/Makefile",
    "echo/host",
    "echo/calls.edl",
    "echo/enc",
    "echo/Makefile",
    "echo/host/host.c",
    "echo/host/Makefile",
    "echo/enc/enc.c",
    "echo/enc/Makefile",
};

static const size_t _npaths = sizeof(_paths) / sizeof(_paths[0]);

void test(const void* cpio_data, size_t cpio_size, bool load_from_memory)
{
    char template[] = "/tmp/libosXXXXXX";
    char* tmpdir;

    assert((tmpdir = mkdtemp(template)) != NULL);

    if (load_from_memory)
    {
        if (libos_cpio_mem_unpack(cpio_data, cpio_size, tmpdir, NULL) != 0)
        {
            assert(false);
        }
    }
    else
    {
        char path[PATH_MAX];

        /* create temporary cpio file */
        snprintf(path, sizeof(path), "%s/cpio-archive", tmpdir);
        assert(_create_cpio_file(path, cpio_data, cpio_size) == 0);
        assert(access(path, R_OK) == 0);
        assert(_fsize(path) == cpio_size);

        /* unpack the cpio archive */
        assert(libos_cpio_unpack(path, tmpdir) == 0);

        unlink(path);
    }

    libos_strarr_t paths = LIBOS_STRARR_INITIALIZER;
    assert(libos_lsr(tmpdir, &paths, true) == 0);
    libos_strarr_sort(&paths);

    /* create sorted paths array */
    libos_strarr_t sorted = LIBOS_STRARR_INITIALIZER;
    {
        for (size_t i = 0; i < _npaths; i++)
            assert(libos_strarr_append(&sorted, _paths[i]) == 0);

        libos_strarr_sort(&sorted);
    }

    assert(sorted.size == paths.size);

    for (size_t i = 0; i < paths.size; i++)
    {
        char tmp[PATH_MAX];
        snprintf(tmp, sizeof(tmp), "%s/%s", tmpdir, sorted.data[i]);

        if (strcmp(paths.data[i], tmp) != 0)
        {
            fprintf(stderr, "compare: {%s} != {%s}\n", paths.data[i], tmp);
            assert(false);
        }
    }

    libos_strarr_release(&paths);
    libos_strarr_release(&sorted);
}

int main(int argc, const char* argv[])
{
    void* data;
    size_t size;
    bool load_from_memory = true;

    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <cpio-archive> <mem|file>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[2], "mem") == 0)
    {
        load_from_memory = true;
    }
    else if (strcmp(argv[2], "file") == 0)
    {
        load_from_memory = false;
    }
    else
    {
        fprintf(stderr, "bad argument: %s\n", argv[2]);
        return 1;
    }

    if (libos_load_file(argv[1], &data, &size) != 0)
        assert(false);

    assert(data != NULL);
    assert(size != 0);
    test(data, size, load_from_memory);

    free(data);

    printf("=== passed test (%s)\n", argv[0]);
    return 0;
}
