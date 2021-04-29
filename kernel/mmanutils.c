// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <myst/eraise.h>
#include <myst/file.h>
#include <myst/mmanutils.h>
#include <myst/panic.h>
#include <myst/process.h>
#include <myst/round.h>
#include <myst/strings.h>
#include <myst/syscall.h>

#define SCRUB

static myst_mman_t _mman;
static void* _mman_start;
static size_t _mman_size;
static void* _mman_end;

/* msync mappings are created by mmap() and released with munmap() */
typedef struct msync_mapping
{
    struct msync_mapping* next;
    int fd;
    off_t offset;
    void* addr;
    size_t length;
} msync_mapping_t;

/* linked list of msync mappings */
static msync_mapping_t* _msync_mappings;
static myst_spinlock_t _msync_mappings_lock = MYST_SPINLOCK_INITIALIZER;

static uint8_t* _min_ptr(uint8_t* x, uint8_t* y)
{
    return (x < y) ? x : y;
}

static uint8_t* _max_ptr(uint8_t* x, uint8_t* y)
{
    return (x > y) ? x : y;
}

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

static msync_mapping_t* _new_msync_mapping(
    int fd,
    off_t offset,
    void* addr,
    size_t length)
{
    msync_mapping_t* m;

    if (!(m = calloc(1, sizeof(msync_mapping_t))))
        return NULL;

    m->fd = fd;
    m->offset = offset;
    m->addr = addr;
    m->length = length;

    return m;
}

static ssize_t _map_file_onto_memory(
    int fd,
    off_t offset,
    void* addr,
    size_t length,
    int mmap_flags)
{
    ssize_t ret = 0;
    ssize_t bytes_read = 0;
    int flags;
    struct vars
    {
        char buf[BUFSIZ];
    };
    struct vars* v = NULL;

    if (fd < 0 || !addr || !length)
        ERAISE(-EINVAL);

    if (!(v = malloc(sizeof(struct vars))))
        ERAISE(-ENOMEM);

    // ATTN: generate EACCES error if non-regular file or file not opened
    // for write when mmap_flags has MMAP_WRITE.

    /* read file onto memory */
    {
        ssize_t n;
        uint8_t* p = addr;
        size_t r = length;
        size_t o = offset;

        while ((n = pread(fd, v->buf, sizeof v->buf, o)) > 0)
        {
            /* if copy would write past end of buffer */
            if (r < (size_t)n)
            {
                memcpy(p, v->buf, r);
                break;
            }

            memcpy(p, v->buf, (size_t)n);
            p += n;
            o += n;
            r -= (size_t)n;
            bytes_read += n;
        }
    }

    /* get the fd flags */
    ECHECK(flags = myst_syscall_fcntl(fd, F_GETFL, 0));

    /* if file is writable, then create msync mappings for msync() */
    if ((mmap_flags & MAP_SHARED) && flags & (O_RDWR | O_WRONLY))
    {
        myst_spin_lock(&_msync_mappings_lock);
        {
            msync_mapping_t* m;

            /* create a new msync mapping */
            if (!(m = _new_msync_mapping(fd, offset, addr, length)))
            {
                myst_spin_unlock(&_msync_mappings_lock);
                ERAISE(-ENOMEM);
            }

            /* add the new mysnc mapping to the list */
            m->next = _msync_mappings;
            _msync_mappings = m;
        }
        myst_spin_unlock(&_msync_mappings_lock);
    }

    ret = bytes_read;

done:

    if (v)
        free(v);

    return ret;
}

/* ATTN-A: fix return types for this function */
void* myst_mmap(
    void* addr,
    size_t length,
    int prot,
    int flags,
    int fd,
    off_t offset)
{
    void* ptr = (void*)-1;
    int r;

    (void)flags;

    // Linux ignores fd when the MAP_ANONYMOUS flag is present
    if (flags & MAP_ANONYMOUS)
        fd = -1;

    /* check file permissions upfront */
    if (fd >= 0)
    {
        long flags;
        struct stat buf;

        /* fail if not a regular file */
        if (myst_syscall_fstat(fd, &buf) != 0 || !S_ISREG(buf.st_mode))
            return (void*)-1;

        /* get the file open flags */
        if ((flags = myst_syscall_fcntl(fd, F_GETFL, 0)) < 0)
            return (void*)-1;

        /* if file is not open for read */
        if ((flags & O_WRONLY))
            return (void*)-1;

        /* MAP_SHARED & PROT_WRITE set, but fd is not open for read-write */
        if ((flags & MAP_SHARED) && (prot & PROT_WRITE) && !(flags & O_RDWR))
            return (void*)-1;
    }

    if (fd >= 0 && addr)
    {
        ssize_t n;
        if ((n = _map_file_onto_memory(fd, offset, addr, length, flags)) < 0)
            return (void*)-1;

        void* end = (uint8_t*)addr + length;
        assert(addr >= _mman_start && addr <= _mman_end);
        assert(end >= _mman_start && end <= _mman_end);

        // ATTN: call mmap or mremap here so that this range refers to
        // a mapped region.

        return addr;
    }

    int tflags = MYST_MAP_ANONYMOUS | MYST_MAP_PRIVATE;

    if ((r = myst_mman_mmap(&_mman, addr, length, prot, tflags, &ptr)) < 0)
        return (void*)(long)r;

    if (fd >= 0 && !addr)
    {
        ssize_t n;

        if ((n = _map_file_onto_memory(fd, offset, ptr, length, flags)) < 0)
            return (void*)(long)-n;
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

MYST_UNUSED
static void _dump_msync_mappings(void)
{
    for (msync_mapping_t* p = _msync_mappings; p; p = p->next)
    {
        printf("[%p][%zu][%zu]\n", p->addr, p->length, p->length / 4096);
    }

    printf("\n");
}

/* release msync mappings that are contained in the range [addr:addr+length] */
static int _release_msync_mappings(void* addr, size_t length)
{
    int ret = 0;

    myst_spin_lock(&_msync_mappings_lock);
    {
        msync_mapping_t* p = _msync_mappings;
        msync_mapping_t* prev = NULL;

        while (p)
        {
            msync_mapping_t* next = p->next;
            uint8_t* lo = addr;
            uint8_t* hi = (uint8_t*)addr + length;
            uint8_t* plo = p->addr;
            uint8_t* phi = (uint8_t*)p->addr + p->length;
            uint8_t* maxlo = _max_ptr(lo, plo);
            uint8_t* minhi = _min_ptr(hi, phi);

            /* if there is an overlap */
            if (maxlo < minhi)
            {
                size_t llength = maxlo - plo;
                size_t rlength = phi - minhi;
                size_t roffset = p->offset + (minhi - plo);

                //     .........
                // ..........
                //
                // .........
                //     ..........

                // left range:  [plo:llength]
                // right range: [maxhi:rlength]

                if (llength && rlength)
                {
                    // printf("case1: split\n");
                    msync_mapping_t* rm;

                    /* create the right mapping */
                    if (!(rm = _new_msync_mapping(
                              p->fd,
                              roffset,   /* offset */
                              minhi,     /* addr */
                              rlength))) /* length */
                    {
                        ERAISE(-ENOMEM);
                    }

                    /* insert right mapping into list */
                    rm->next = p->next;
                    p->next = rm;

                    /* update the left mapping length */
                    p->length = llength;
                    prev = rm;
                }
                else if (llength)
                {
                    // printf("case2: left\n");

                    /* update the left mapping length */
                    p->length = llength;
                    prev = p;
                }
                else if (rlength)
                {
                    // printf("case3: right\n");
                    p->offset = roffset;
                    p->addr = minhi;
                    p->length = rlength;
                    prev = p;
                }
                else
                {
                    // printf("case4: remove\n");
                    if (prev)
                        prev->next = p->next;
                    else
                        _msync_mappings = p->next;

                    free(p);
                }
            }
            else
            {
                prev = p;
            }

            p = next;
        }
    }
    myst_spin_unlock(&_msync_mappings_lock);

    goto done;

done:
    return ret;
}

int myst_munmap(void* addr, size_t length)
{
    int ret = 0;

    /* address cannot be null and must be aligned on a page boundary */
    if (!addr || ((uint64_t)addr % PAGE_SIZE) || !length)
        ERAISE(-EINVAL);

    /* align length to a page boundary */
    ECHECK(myst_round_up(length, PAGE_SIZE, &length));

    ECHECK(myst_mman_munmap(&_mman, addr, length));

    ECHECK(_release_msync_mappings(addr, length));

#if 0
    // ATTN-2AA04DD0: fails during process cleanup for unknown reasons. When
    // the process is created, we call myst_register_process_mapping() to keep
    // track of the mapping so that it can be released when the process exist
    // by calling myst_release_process_mappings(), where this failure occurs.
    // This probably because the mappings are overlapping and some where
    // already partially released by the application. In any case, more
    // investigation is need to find a root cause. This is only a problem after
    // a posix_spawn().
    if (ret != 0)
    {
        printf("*** MUNMAP: ret=%d err=%s\n", ret, _mman.err);
    }
#endif

done:
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

static int _sync_file(int fd, off_t offset, const void* addr, size_t length)
{
    int ret = 0;
    const uint8_t* p = (const uint8_t*)addr;
    size_t r = length;
    off_t o = offset;

    while (r > 0)
    {
        ssize_t n = pwrite(fd, p, r, o);

        if (n == 0)
            break;
        else if (n < 0)
            ERAISE(n);

        p += n;
        o += n;
        r -= (size_t)n;
    }

done:
    return ret;
}

int myst_msync(void* addr, size_t length, int flags)
{
    int ret = 0;
    const int mask = MS_SYNC | MS_ASYNC | MS_INVALIDATE;

    /* reject bad parameters and unknown flags */
    if (!addr || !length || (flags & ~mask))
        ERAISE(-EINVAL);

    /* fail if both MS_SYNC and MS_ASYNC are both present */
    if ((flags & MS_SYNC) && (flags & MS_ASYNC))
        ERAISE(-EINVAL);

    // Note: Asynchronous sync (MS_ASYNC) is not supported so all syncs are
    // treated as though they were non-asynchronous (MS_SYNC). The caller will
    // be unable to detect any difference in behavior.

    // Note: experimentation reveals that Linux invalidates other mappings
    // of the same file, whether  MS_INVALIDATE is present or not (meaning
    // that they too are updated to reflect the contents of the file with
    // or without the MS_INVALIDATE flag).

    myst_spin_lock(&_msync_mappings_lock);
    {
        /* flush any msync mappings contained by this address range */
        for (msync_mapping_t* p = _msync_mappings; p; p = p->next)
        {
            uint8_t* lo = addr;
            uint8_t* hi = (uint8_t*)addr + length;
            uint8_t* plo = p->addr;
            uint8_t* phi = (uint8_t*)p->addr + p->length;
            uint8_t* maxlo = _max_ptr(lo, plo);
            uint8_t* minhi = _min_ptr(hi, phi);

            // [AAAAAAAAAAAAAAAAA]
            //       [MMMMMMMMMMMMMMMMMMMMM]
            //       ^           ^
            //      maxlo      minhi
            //
            //       [AAAAAAAAAAAAAAAAA]
            // [MMMMMMMMMMMMMMM]
            //       ^         ^
            //      maxlo     minhi

            if (maxlo < minhi)
            {
                ECHECK(_sync_file(
                    p->fd,                     /* fd */
                    p->offset + (maxlo - plo), /* offset */
                    maxlo,                     /* addr */
                    minhi - maxlo));           /* length */
            }
        }

        // ATTN: currently msync() does not update other mappings of the same
        // file. This would involve refreshing those mappings from the file
        // blocks. This case may be rare since it would require mapping the
        // same file to different memory regions.
    }
    myst_spin_unlock(&_msync_mappings_lock);

done:
    return ret;
}

/* notified on close to remove msync mappings involving fd */
void myst_mman_close_notify(int fd)
{
    int flags;
    struct stat buf;

    /* get the file open flags */
    if (fd < 0 || (flags = myst_syscall_fcntl(fd, F_GETFL, 0)) < 0)
        return;

    /* only do this for regular files */
    if (myst_syscall_fstat(fd, &buf) != 0 || !S_ISREG(buf.st_mode))
        return;

    /* if file is open for write */
    if (flags & (O_RDWR | O_WRONLY))
    {
        myst_spin_lock(&_msync_mappings_lock);
        {
            msync_mapping_t* p = _msync_mappings;
            msync_mapping_t* prev = NULL;

            while (p)
            {
                msync_mapping_t* next = p->next;

                if (p->fd == fd)
                {
                    if (prev)
                        prev->next = p->next;
                    else
                        _msync_mappings = p->next;

                    free(p);
                }
                else
                {
                    prev = p;
                }

                p = next;
            }
        }
        myst_spin_unlock(&_msync_mappings_lock);
    }
}

void myst_mman_stats(myst_mman_stats_t* buf)
{
    buf->total_size = _mman.end - _mman.start;
    buf->brk_size = _mman.brk - _mman.start;
    buf->map_size = _mman.end - _mman.map;
    buf->free_size = _mman.map - _mman.brk;
    buf->used_size = buf->brk_size + buf->map_size;
}
