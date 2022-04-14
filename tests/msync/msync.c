// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

static void _passed(const char* name)
{
    printf("=== passed test (%s)\n", name);
}

static int _writen(int fd, const void* data, size_t size)
{
    ssize_t ret = -1;
    const uint8_t* p = (const uint8_t*)data;
    size_t r = size;

    while (r > 0)
    {
        ssize_t n = write(fd, p, r);

        if (n == 0)
            break;
        else if (n < 0)
            goto done;

        p += n;
        r -= (size_t)n;
    }

    ret = 0;

done:

    return ret;
}

static int _readn(int fd, void* data, size_t size)
{
    ssize_t ret = -1;
    uint8_t* p = (uint8_t*)data;
    size_t r = size;

    while (r > 0)
    {
        ssize_t n = read(fd, p, r);

        if (n <= 0)
            goto done;

        p += n;
        r -= (size_t)n;
    }

    ret = 0;

done:

    return ret;
}

static bool _check_page(uint8_t page[PAGE_SIZE], uint8_t byte)
{
    for (size_t i = 0; i < PAGE_SIZE; i++)
    {
        if (page[i] != byte)
            return false;
    }

    return true;
}

static void test_msync()
{
    const size_t num_pages = 8;
    uint8_t page[PAGE_SIZE];
    int fd;
    struct stat st;

    /* create a new file */
    assert((fd = open("/tmp/msync", O_CREAT | O_TRUNC | O_RDWR, 0666)) >= 0);

    /* create a file where each page is filled with a specific byte value */
    for (size_t i = 0; i < num_pages; i++)
    {
        const uint8_t byte = (uint8_t)i;
        memset(page, byte, sizeof(page));
        assert(_writen(fd, page, sizeof(page)) == 0);
    }

    /* check the size of the file */
    assert(fstat(fd, &st) == 0);
    assert(st.st_size == num_pages * sizeof(page));

    /* map the file onto memory */
    const size_t length = st.st_size;
    const int prot = PROT_READ | PROT_WRITE;
    const int flags = MAP_PRIVATE;
    uint8_t* addr = mmap(NULL, length, prot, flags, fd, 0);
    assert(addr != MAP_FAILED);

    /* check that the memory mapped image matches the file */
    for (size_t i = 0; i < num_pages; i++)
    {
        /* check that the current page consists of the given byte */
        uint8_t* p = addr + (i * PAGE_SIZE);
        const uint8_t byte = (uint8_t)i;
        assert(_check_page(p, byte) == true);
    }

    /* update the memory mapped image by changing the page byte values */
    for (size_t i = 0; i < num_pages; i++)
    {
        uint8_t* p = addr + (i * PAGE_SIZE);
        const uint8_t byte = (uint8_t)(i + 1);
        memset(p, byte, PAGE_SIZE);
    }

    /* sync the pages back to disk one page at a time */
    for (size_t i = 0; i < num_pages; i++)
    {
        uint8_t* p = addr + (i * PAGE_SIZE);
        assert(msync(p, PAGE_SIZE, MS_SYNC) == 0);
    }

    // remove the memory mappings in an irregular order to this has many
    // cases in the mman implementation as possible.
    {
#if 1
        size_t indices[] = {
            0,
            3,
            5,
            7,
            2,
            4,
            6,
            1,
        };
        assert(sizeof(indices) / sizeof(indices[0]) == num_pages);

        for (size_t i = 0; i < num_pages; i++)
        {
            size_t index = indices[i];
            uint8_t* p = addr + index * PAGE_SIZE;
            assert(munmap(p, PAGE_SIZE) == 0);
        }
#else
        assert(munmap(addr, length) == 0);
#endif
    }

    /* close the file (which implicitly removes the file mapping) */
    assert(close(fd) == 0);

    /* reopen the file and check that it has actually changed */
    {
        assert((fd = open("/tmp/msync", O_RDONLY)) >= 0);

        for (size_t i = 0; i < num_pages; i++)
        {
            const uint8_t byte = (uint8_t)(i + 1);
            memset(page, 0, sizeof(page));
            assert(_readn(fd, page, PAGE_SIZE) == 0);
            assert(_check_page(page, byte) == true);
        }

        assert(close(fd) == 0);
    }

    _passed(__FUNCTION__);
}

static void test_msync_closed_read_fd()
{
    int fd = creat("/tmp/datafile", 0666);
    write(fd, "abcdefghijklmnopqrstuvwxyz", 27);
    close(fd);

    fd = open("/tmp/datafile", O_CLOEXEC);
    void* p = mmap(NULL, PAGE_SIZE, PROT_READ, MAP_SHARED, fd, 0);
    assert(p != MAP_FAILED);
    close(fd);
    int ret = msync(p, PAGE_SIZE, MS_SYNC | MS_INVALIDATE);
    assert(ret == 0 && errno == 0);
    assert(unlink("/tmp/datafile") == 0);
    munmap(p, PAGE_SIZE);
    _passed(__FUNCTION__);
}

static void test_msync_closed_rw_fd()
{
    int fd = creat("/tmp/datafile", 0666);
    write(fd, "abcdefghijklmnopqrstuvwxyz", 27);
    close(fd);

    fd = open("/tmp/datafile", O_RDWR | O_CLOEXEC);
    void* p = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    assert(p != MAP_FAILED);
    close(fd);

    char* cp = p;
    memcpy(cp, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 27);
    int ret = msync(p, PAGE_SIZE, MS_SYNC | MS_INVALIDATE);
    assert(ret == 0 && errno == 0);

    char buf[27];
    fd = open("/tmp/datafile", O_RDONLY);
    read(fd, buf, 27);
    assert(strcmp(buf, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") == 0);
    assert(unlink("/tmp/datafile") == 0);
    munmap(p, PAGE_SIZE);
    _passed(__FUNCTION__);
}

int main(int argc, const char* argv[])
{
    test_msync();
    test_msync_closed_read_fd();
    test_msync_closed_rw_fd();
    _passed(argv[0]);
    return 0;
}
