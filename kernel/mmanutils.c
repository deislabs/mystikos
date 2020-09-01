#include <libos/mmanutils.h>
#include <libos/file.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <libos/deprecated.h>
#include <libos/malloc.h>
#include <libos/strings.h>
#include <libos/assert.h>

static libos_mman_t _mman;
static void* _mman_start;
static size_t _mman_size;
static void* _mman_end;

int libos_setup_mman(void* data, size_t size)
{
    int ret = -1;

    /* Need room for at least one data page and two guard pages */
    if (!data || (size < (3 * PAGE_SIZE)))
        goto done;

    /* Layout: <guard><pages...><guard> */
    _mman_start = (uint8_t*)data + PAGE_SIZE;
    _mman_end = (uint8_t*)data + size - PAGE_SIZE;
    _mman_size = size - (2 * PAGE_SIZE);

    if (libos_mman_init(&_mman, (uintptr_t)_mman_start, _mman_size) != 0)
        goto done;

    _mman.scrub = true;

    libos_mman_set_sanity(&_mman, true);

    ret = 0;

done:
    return ret;
}

int libos_teardown_mman(void)
{
    libos_assert(libos_mman_is_sane(&_mman));
    return 0;
}

static ssize_t _map_file_onto_memory(
    int fd,
    off_t offset,
    void* data,
    size_t size)
{
    ssize_t ret = -1;
    ssize_t bytes_read = 0;
    off_t save_pos;

    if (fd < 0 || !data || !size)
        goto done;

    /* save the current file position */
    if ((save_pos = libos_lseek(fd, 0, SEEK_CUR)) == (off_t)-1)
        goto done;

    /* seek start of file */
    if (libos_lseek(fd, offset, SEEK_SET) == (off_t)-1)
        goto done;

    /* read file onto memory */
    {
        char buf[BUFSIZ];
        ssize_t n;
        uint8_t* p = data;
        size_t r = size;

        while ((n = libos_read(fd, buf, sizeof buf)) > 0)
        {
            /* if copy would write past end of data */
            if (r < (size_t)n)
            {
                libos_memcpy(p, buf, r);
                break;
            }

            libos_memcpy(p, buf, (size_t)n);
            p += n;
            r -= (size_t)n;
            bytes_read += n;
        }
    }

    /* restore the file position */
    if (libos_lseek(fd, save_pos, SEEK_SET) == (off_t)-1)
        goto done;

    ret = bytes_read;

done:
    return ret;
}

#if 0
static void _check_zeros(const uint8_t* p, size_t n)
{
    while (n--)
    {
        if (*p++)
        {
            fprintf(stderr, "_check_zeros() failed\n");
            exit(1);
        }
    }
}
#endif

void* libos_mmap(
    void* addr,
    size_t length,
    int prot,
    int flags,
    int fd,
    off_t offset)
{
    void* ptr = (void*)-1;

    (void)flags;

    if (fd >= 0 && addr)
    {
        ssize_t n;

#if 0
        libos_printf("addr: [%016lX][%016lX]\n", (long)addr, length);
#endif

        if ((n = _map_file_onto_memory(fd, offset, addr, length)) < 0)
            return (void*)-1;

        void* end = (uint8_t*)addr + length;
        libos_assert(addr >= _mman_start && addr <= _mman_end);
        libos_assert(end >= _mman_start && end <= _mman_end);

        // ISSUE: call mmap or mremap here so that this range refers to
        // a mapped region.

        return addr;
    }

    int tflags = LIBOS_MAP_ANONYMOUS | LIBOS_MAP_PRIVATE;

    if (libos_mman_map(&_mman, addr, length, prot, tflags, &ptr) != 0)
    {
        libos_printf("libos_mman_map: error: %s\n", _mman.err);
        return (void*)-1;
    }

    if (fd >= 0 && !addr)
    {
        ssize_t n;

        if ((n = _map_file_onto_memory(fd, offset, ptr, length)) < 0)
            return (void*)-1;
    }

    void* end = (uint8_t*)ptr + length;
    libos_assert(ptr >= _mman_start && ptr <= _mman_end);
    libos_assert(end >= _mman_start && end <= _mman_end);

    return ptr;
}

int libos_munmap(void* addr, size_t length)
{
    return libos_mman_munmap(&_mman, addr, length);
}

long libos_syscall_brk(void* addr)
{
    void* ptr = NULL;

    /* Ignore return value (ptr is set to the current brk value on failure) */
    libos_mman_brk(&_mman, addr, &ptr);

    return (long)ptr;
}
