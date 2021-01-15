// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <stdlib.h>

#include <myst/file.h>
#include <myst/mmanutils.h>
#include <myst/strings.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <myst/process.h>
#include <myst/eraise.h>

#define SCRUB

static myst_mman_t _mman;
static void* _mman_start;
static size_t _mman_size;
static void* _mman_end;

int myst_setup_mman(void* data, size_t size)
{
    int ret = -1;

    /* Need room for at least one data page and two guard pages */
    if (!data || (size < (3 * PAGE_SIZE)))
        goto done;

    /* Layout: <guard><pages...><guard> */
    _mman_start = (uint8_t*)data + PAGE_SIZE;
    _mman_end = (uint8_t*)data + size - PAGE_SIZE;
    _mman_size = size - (2 * PAGE_SIZE);

    if (myst_mman_init(&_mman, (uintptr_t)_mman_start, _mman_size) != 0)
        goto done;

#ifdef SCRUB
    /* Scrubbing unmapped memory causes memory reads due to musl libc */
    _mman.scrub = true;
#endif

#ifdef SANITY
    myst_mman_set_sanity(&_mman, true);
#endif

    ret = 0;

done:
    return ret;
}

int myst_teardown_mman(void)
{
    assert(myst_mman_is_sane(&_mman));
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
    if ((save_pos = lseek(fd, 0, SEEK_CUR)) == (off_t)-1)
        goto done;

    /* seek start of file */
    if (lseek(fd, offset, SEEK_SET) == (off_t)-1)
        goto done;

    /* read file onto memory */
    {
        char buf[BUFSIZ];
        ssize_t n;
        uint8_t* p = data;
        size_t r = size;

        while ((n = read(fd, buf, sizeof buf)) > 0)
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
    if (lseek(fd, save_pos, SEEK_SET) == (off_t)-1)
        goto done;

    ret = bytes_read;

done:
    return ret;
}

void* myst_mmap(
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

        if ((n = _map_file_onto_memory(fd, offset, addr, length)) < 0)
            return (void*)-1;

        void* end = (uint8_t*)addr + length;
        assert(addr >= _mman_start && addr <= _mman_end);
        assert(end >= _mman_start && end <= _mman_end);

        // ATTN: call mmap or mremap here so that this range refers to
        // a mapped region.

        return addr;
    }

    int tflags = MYST_MAP_ANONYMOUS | MYST_MAP_PRIVATE;

    if (myst_mman_mmap(&_mman, addr, length, prot, tflags, &ptr) != 0)
        return (void*)-1;

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

void* myst_mremap(
    void* old_address,
    size_t old_size,
    size_t new_size,
    int flags,
    void* new_address)
{
    void* p;
    int r;

    if (new_address)
        return (void*)-EINVAL;

    r = myst_mman_mremap(&_mman, old_address, old_size, new_size, flags, &p);

    if (r != 0)
        return (void*)(long)r;

    return p;
}

int myst_munmap(void* addr, size_t length)
{
    int ret = myst_mman_munmap(&_mman, addr, length);

#if 0
    /* ATTN-2AA04DD0: fails during process cleanup */
    if (ret != 0)
    {
        printf("*** MUNMAP: ret=%d err=%s\n", ret, _mman.err);
    }
#endif

    return ret;
}

long myst_syscall_brk(void* addr)
{
    void* ptr = NULL;

    /* Ignore return value (ptr is set to the current brk value on failure) */
    myst_mman_brk(&_mman, addr, &ptr);

    return (long)ptr;
}

int myst_get_total_ram(size_t* size)
{
    return myst_mman_total_size(&_mman, size);
}

int myst_get_free_ram(size_t* size)
{
    return myst_mman_free_size(&_mman, size);
}

typedef struct myst_process_mapping myst_process_mapping_t;

struct myst_process_mapping
{
    myst_process_mapping_t* next;
    pid_t pid;
    void* addr;
    size_t size;
};

static myst_process_mapping_t* _mappings;
static myst_spinlock_t _mappings_lock;

/* keep track of mappings made by this process */
int myst_register_process_mapping(pid_t pid, void* addr, size_t size)
{
    int ret = 0;
    myst_process_mapping_t* m = NULL;

    if (pid < 0 || !addr || (addr == (void*)-1) || !size)
        ERAISE(-EINVAL);

    if (!(m = calloc(1, sizeof(myst_process_mapping_t))))
        ERAISE(-ENOMEM);

    m->pid = pid;
    m->addr = addr;
    m->size = size;

    myst_spin_lock(&_mappings_lock);
    {
        m->next = _mappings;
        _mappings = m;
    }
    myst_spin_unlock(&_mappings_lock);

done:

    return ret;
}

/* release mappings made the given process */
int myst_release_process_mappings(pid_t pid)
{
    int ret = 0;

    if (pid < 0)
        ERAISE(-EINVAL);

    myst_spin_lock(&_mappings_lock);
    {
        myst_process_mapping_t* prev = NULL;
        myst_process_mapping_t* next = NULL;

        for (myst_process_mapping_t* p = _mappings; p; p = next)
        {
            next = p->next;

            if (p->pid == pid)
            {
                myst_munmap(p->addr, p->size);

                if (prev)
                    prev->next = next;
                else
                    _mappings = next;

                free(p);
            }
            else
            {
                prev = p;
            }

            p = next;
        }
    }
    myst_spin_unlock(&_mappings_lock);

done:
    return ret;
}
