#include <libos/mmanutils.h>
#include <libos/file.h>
#include <stdlib.h>
#include <limits.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

static libos_mman_t _mman;
static void* _mman_start;
static void* _mman_end;

static uint8_t GUARD_CHAR = 0xAA;

static int _check_guard(const void* p)
{
    for (size_t i = 0; i < PAGE_SIZE; i++)
    {
        if (((uint8_t*)p)[i] != GUARD_CHAR)
            return -1;
    }

    return 0;
}

static void _dump(uint8_t* p, size_t n)
{
    while (n--)
        printf("%02X", *p++);

    printf("\n");
}

int libos_setup_mman(size_t size)
{
    int ret = -1;
    void* base;
    void* ptr;

    /* Allocate aligned pages */
    if (!(ptr = memalign(OE_PAGE_SIZE, PAGE_SIZE + size + PAGE_SIZE)))
        goto done;

    base = (uint8_t*)ptr + PAGE_SIZE;

    _mman_start = base;
    _mman_end = (uint8_t*)base + size;

    /* Set the guard pages */
    memset((uint8_t*)_mman_start - PAGE_SIZE, GUARD_CHAR, PAGE_SIZE);
    memset((uint8_t*)_mman_end, GUARD_CHAR, PAGE_SIZE);

    if (libos_mman_init(&_mman, (uintptr_t)base, size) != 0)
        goto done;

    _mman.scrub = true;

    libos_mman_set_sanity(&_mman, true);

    ret = 0;

done:
    return ret;
}

int libos_teardown_mman(void)
{
    assert(libos_mman_is_sane(&_mman));

    /* Check the start guard page */
    if (_check_guard((uint8_t*)_mman_start - PAGE_SIZE) != 0)
    {
        fprintf(stderr, "bad mman start guard page\n");
        _dump((uint8_t*)_mman_start - PAGE_SIZE, PAGE_SIZE);
        assert(false);
    }

    /* Check the end guard page */
    if (_check_guard(_mman_end) != 0)
    {
        fprintf(stderr, "bad mman end guard page\n");
        _dump(_mman_end, PAGE_SIZE);
        assert(false);
    }

    free((uint8_t*)_mman.base - PAGE_SIZE);
    return 0;
}

#if 0
static void _write_file(const char* path, const void* data, size_t size)
{
    int fd;
    const uint8_t* p = (const uint8_t*)data;
    size_t r = size;
    ssize_t n;

    if ((fd = open(path, O_CREAT|O_WRONLY|O_TRUNC, 0666)) < 0)
    {
        fprintf(stderr, "open failed: %s\n", path);
        exit(1);
    }

    while ((n = write(fd, p, r)) > 0)
    {
        p += n;
        r -= n;
    }

    if (r != 0)
    {
        fprintf(stderr, "write failed: %s\n", path);
        exit(1);
    }

    close(fd);
}
#endif

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
                memcpy(p, buf, r);
                break;
            }

            memcpy(p, buf, (size_t)n);
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

void* libos_mmap(
    void *addr,
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
        printf("addr: [%016lX][%016lX]\n", (long)addr, length);
#endif

        if ((n = _map_file_onto_memory(fd, offset, addr, length)) < 0)
            return (void*)-1;

        void* end = (uint8_t*)addr + length;
        assert(addr >= _mman_start && addr <= _mman_end);
        assert(end >= _mman_start && end <= _mman_end);

        // ISSUE: call mmap or mremap here so that this range refers to
        // a mapped region.

        return addr;
    }

    int tflags = LIBOS_MAP_ANONYMOUS | LIBOS_MAP_PRIVATE;

    if (libos_mman_map(&_mman, addr, length, prot, tflags, &ptr) != 0)
    {
        printf("libos_mman_map: error: %s\n", _mman.err);
        return (void*)-1;
    }

    if (fd >= 0 && !addr)
    {
        ssize_t n;

        if ((n = _map_file_onto_memory(fd, offset, ptr, length)) < 0)
            return (void*)-1;
    }

    void* end = (uint8_t*)ptr + length;
    assert(ptr >= _mman_start && ptr <= _mman_end);
    assert(end >= _mman_start && end <= _mman_end);

    return ptr;
}
