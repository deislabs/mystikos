// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <myst/atexit.h>
#include <myst/eraise.h>
#include <myst/fdtable.h>
#include <myst/file.h>
#include <myst/kernel.h>
#include <myst/malloc.h>
#include <myst/mman.h>
#include <myst/mmanutils.h>
#include <myst/mutex.h>
#include <myst/once.h>
#include <myst/panic.h>
#include <myst/printf.h>
#include <myst/process.h>
#include <myst/refstr.h>
#include <myst/round.h>
#include <myst/strings.h>
#include <myst/syscall.h>
#include <myst/trace.h>

MYST_PRINTF_FORMAT(2, 3)
int asprintf(char** strp, const char* fmt, ...);

#define SCRUB

static myst_mman_t _mman;
static void* _mman_start;
static size_t _mman_size;
static void* _mman_end;

typedef struct vectors
{
    myst_fdmapping_t* fdmappings;
    size_t fdmappings_count;
    uint32_t* pids;
    size_t pids_count;
} vectors_t;

static vectors_t _get_vectors(void)
{
    vectors_t v;
    v.fdmappings = __myst_kernel_args.fdmappings_data;
    v.fdmappings_count =
        __myst_kernel_args.fdmappings_size / sizeof(myst_fdmapping_t);
    v.pids = __myst_kernel_args.mman_pids_data;
    v.pids_count = __myst_kernel_args.mman_pids_size / sizeof(uint32_t);

    return v;
}

static int _fd_to_pathname(int fd, char pathname[PATH_MAX])
{
    int ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_fs_t* fs;
    myst_file_t* file;

    ECHECK(myst_fdtable_get_file(fdtable, fd, &fs, &file));
    ECHECK((*fs->fs_realpath)(fs, file, pathname, PATH_MAX));

done:
    return ret;
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

/* get the page index of the given address and check for bounds violations */
static ssize_t _get_page_index(const void* addr, size_t length)
{
    ssize_t ret = 0;
    uint64_t addr_start = (uint64_t)addr;
    uint64_t mman_start = (uint64_t)_mman_start;
    size_t mman_size = _mman_size;
    const uint64_t addr_end;
    const size_t mman_end;

    if (!addr || !length)
        ERAISE(-EINVAL);

    if (((uint64_t)addr % PAGE_SIZE) || (length % PAGE_SIZE))
        ERAISE(-EINVAL);

    if (__builtin_add_overflow(addr_start, length, &addr_end))
        ERAISE(-ERANGE);

    if (__builtin_add_overflow(mman_start, mman_size, &mman_end))
        ERAISE(-ERANGE);

    if (!(addr_start >= mman_start && addr_end <= mman_end))
        ERAISE(-EINVAL);

    ret = (addr_start - mman_start) / PAGE_SIZE;

done:
    return ret;
}

static void _free_fdmappings_pathnames(void* arg)
{
    uint8_t* addr = (uint8_t*)_mman.map;
    size_t length = ((uint8_t*)_mman.end) - addr;
    size_t index;
    vectors_t v = _get_vectors();

    (void)arg;

    myst_round_up(length, PAGE_SIZE, &length);
    index = _get_page_index(addr, length);
    assert(index >= 0);
    size_t count = length / PAGE_SIZE;

    for (size_t i = index; i < index + count; i++)
    {
        myst_fdmapping_t* p = &v.fdmappings[i];

        if (p->pathname)
        {
            myst_refstr_unref(p->pathname);
            p->pathname = NULL;
        }
    }
}

static myst_once_t _install_free_fdmappings_pathnames_once;

static void _install_free_fdmappings_pathnames(void)
{
    myst_atexit(_free_fdmappings_pathnames, NULL);
}

static int _add_file_mapping(int fd, off_t offset, void* addr, size_t length)
{
    int ret = 0;
    size_t index;
    vectors_t v = _get_vectors();
    struct locals
    {
        char pathname[PATH_MAX];
    };
    struct locals* locals = NULL;
    myst_refstr_t* pathname = NULL;

    myst_once(
        &_install_free_fdmappings_pathnames_once,
        _install_free_fdmappings_pathnames);

    if (fd < 0 || offset < 0 || !addr || !length)
        ERAISE(-EINVAL);

    if (!(locals = calloc(1, sizeof(struct locals))))
        ERAISE(-ENOMEM);

    ECHECK(_fd_to_pathname(fd, locals->pathname));

    /* make a reference-counted version of the pathname */
    if (!(pathname = myst_refstr_dup(locals->pathname)))
    {
        assert("out of memory" == NULL);
        ERAISE(-ENOMEM);
    }

    ECHECK(myst_round_up(length, PAGE_SIZE, &length));
    ECHECK((index = _get_page_index(addr, length)));

    myst_rspin_lock(&_mman.lock);
    {
        const size_t count = length / PAGE_SIZE;
        uint64_t off = offset;

        for (size_t i = index; i < index + count; i++)
        {
            myst_fdmapping_t* p = &v.fdmappings[i];

            /* ATTN: the entry might already be in use for unknown reasons */
            if (p->used == MYST_FDMAPPING_USED)
            {
                myst_refstr_unref(p->pathname);
                p->pathname = NULL;
            }

            p->used = MYST_FDMAPPING_USED;
            p->fd = fd;
            p->offset = off;
            myst_refstr_ref(p->pathname = pathname);
            off += PAGE_SIZE;
        }
    }
    myst_rspin_unlock(&_mman.lock);

done:

    if (locals)
        free(locals);

    myst_refstr_unref(pathname);

    return ret;
}

static ssize_t _map_file_onto_memory(
    int fd,
    off_t offset,
    void* addr,
    size_t length)
{
    ssize_t ret = 0;
    ssize_t bytes_read = 0;
    struct locals
    {
        char buf[BUFSIZ];
    };
    struct locals* locals = NULL;

    if (fd < 0 || !addr || !length || offset % PAGE_SIZE)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    /* read file onto memory */
    {
        ssize_t n;
        uint8_t* p = addr;
        size_t r = length;
        size_t o = offset;

        while ((n = pread(fd, locals->buf, sizeof locals->buf, o)) > 0)
        {
            /* if copy would write past end of buffer */
            if (r < (size_t)n)
            {
                memcpy(p, locals->buf, r);
                break;
            }

            memcpy(p, locals->buf, (size_t)n);
            p += n;
            o += n;
            r -= (size_t)n;
            bytes_read += n;
        }
    }

    ECHECK(_add_file_mapping(fd, offset, addr, length));

    ret = bytes_read;

done:

    if (locals)
        free(locals);

    return ret;
}

long myst_mmap(
    void* addr,
    size_t length,
    int prot,
    int flags,
    int fd,
    off_t offset)
{
    long ret = -1;

    /* fail if length is zero. Note that the page-alignment will
     * be enforced by myst_mman_mprotect and myst_mman_mmap */
    if (!length)
        ERAISE(-EINVAL);

    /* check for invalid PROT bits */
    if (prot & (~MYST_PROT_MMAP_MASK))
        ERAISE(-EINVAL);

    /* Linux ignores fd when the MAP_ANONYMOUS flag is present */
    if (flags & MAP_ANONYMOUS)
        fd = -1;
    /* fail if fd is negative when the MAP_ANONYMOUS flag is not present */
    else if (fd < 0)
        ERAISE(-EBADF);

    /* check file permissions upfront */
    if (fd >= 0)
    {
        long flags;
        struct stat buf;

        // ATTN: Use EBADF and EACCES for fd validation failures. This may not
        // conform the Linux kernel behavior.

        /* fail if not a regular file */
        if (myst_syscall_fstat(fd, &buf) != 0 || !S_ISREG(buf.st_mode))
            ERAISE(-EBADF);

        /* get the file open flags */
        if ((flags = myst_syscall_fcntl(fd, F_GETFL, 0)) < 0)
            ERAISE(-EBADF);

        /* if file is not open for read */
        if ((flags & O_WRONLY))
            ERAISE(-EACCES);

        /* MAP_SHARED & PROT_WRITE set, but fd is not open for read-write */
        if ((flags & MAP_SHARED) && (prot & PROT_WRITE) && !(flags & O_RDWR))
            ERAISE(-EACCES);
    }

    if (fd >= 0 && addr)
    {
        // ATTN: call mmap or mremap here so that this range refers to
        // a mapped region.
        // ATTN: Use the error code returned by lower-level functions. This may
        // not conform the Linux kernel behavior.

        /* rely on myst_mman_mprotect to validate the addr */
        ECHECK(
            myst_mman_mprotect(&_mman, addr, length, prot | MYST_PROT_WRITE));

        ECHECK(_map_file_onto_memory(fd, offset, addr, length));

        if (!(prot & MYST_PROT_WRITE))
            ECHECK(myst_mman_mprotect(&_mman, addr, length, prot));

        ret = (long)addr;
    }
    else
    {
        int tflags = 0;

        if (flags & MYST_MAP_FIXED)
            tflags = MYST_MAP_ANONYMOUS | MYST_MAP_PRIVATE | MYST_MAP_FIXED;
        else
            tflags = MYST_MAP_ANONYMOUS | MYST_MAP_PRIVATE;

        ECHECK(
            myst_mman_mmap(&_mman, addr, length, prot, tflags, (void**)&ret));

        if (fd >= 0 && !addr)
        {
            // ATTN: Use the error code returned by lower-level functions. This
            // may not conform the Linux kernel behavior.

            /* rely on myst_mman_mprotect to validate the ret */
            if (!(prot & MYST_PROT_WRITE))
                ECHECK(myst_mman_mprotect(
                    &_mman, (void*)ret, length, prot | MYST_PROT_WRITE));
            else
            {
                /* validate the ret if the myst_mman_mprotect is not called */
                uintptr_t end;

                if ((uintptr_t)ret < _mman.start)
                    ERAISE(-EINVAL);

                if ((__builtin_add_overflow((uintptr_t)ret, length, &end)) ||
                    (end > _mman.end))
                    ERAISE(-EINVAL);
            }

            ECHECK(_map_file_onto_memory(fd, offset, (void*)ret, length));

            if (!(prot & MYST_PROT_WRITE))
                ECHECK(myst_mman_mprotect(&_mman, (void*)ret, length, prot));
        }
    }

    void* end = (void*)(ret + length);
    assert((void*)ret >= _mman_start && (void*)ret <= _mman_end);
    assert(end >= _mman_start && end <= _mman_end);

done:
    return ret;
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

int myst_mprotect(const void* addr, const size_t len, const int prot)
{
    if (!addr)
        return -EINVAL;

    /* check for invalid PROT bits */
    if (prot & (~MYST_PROT_MPROTECT_MASK))
        return -EINVAL;
    /* PROT cannot have both PROT_GROWSDOWN and MYST_PROT_GROWSUP bits set */
    if ((prot & MYST_PROT_GROWSDOWN) && (prot & MYST_PROT_GROWSUP))
        return -EINVAL;

    /* Current implementation for mprotect ignore bits beyond
       PROT_READ|PROT_WRITE|PROT_EXEC
    */
    return (myst_mman_mprotect(&_mman, (void*)addr, len, prot));
}

/* release msync mappings that are contained in the range [addr:addr+length] */
static int _remove_file_mappings(void* addr, size_t length)
{
    int ret = 0;
    size_t index;
    vectors_t v = _get_vectors();

    if (!addr || !length)
        ERAISE(-EINVAL);

    ECHECK(myst_round_up(length, PAGE_SIZE, &length));
    ECHECK((index = _get_page_index(addr, length)));

    myst_rspin_lock(&_mman.lock);
    {
        const size_t count = length / PAGE_SIZE;

        for (size_t i = index; i < index + count; i++)
        {
            myst_fdmapping_t* p = &v.fdmappings[index];

            /* remove this fd-mapping */
            p->used = 0;
            p->fd = 0;
            p->offset = 0;
            myst_refstr_unref(p->pathname);
            p->pathname = NULL;
        }
    }
    myst_rspin_unlock(&_mman.lock);

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

    ECHECK(_remove_file_mappings(addr, length));

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

/* release mappings owned by the given process */
int myst_release_process_mappings(pid_t pid)
{
    int ret = 0;

    if (pid <= 0)
        ERAISE(-EINVAL);

    {
        uint8_t* addr = (uint8_t*)_mman.map;
        size_t length = ((uint8_t*)_mman.end) - addr;
        size_t index;
        vectors_t v = _get_vectors();

        assert(v.pids_count == v.fdmappings_count);

        ECHECK(myst_round_up(length, PAGE_SIZE, &length));
        ECHECK((index = _get_page_index(addr, length)));
        size_t count = length / PAGE_SIZE;

        assert(index < v.pids_count);
        assert(index + count <= v.pids_count);

        myst_rspin_lock(&_mman.lock);
        {
            for (size_t i = index; i < index + count;)
            {
                if (v.pids[i] == (uint32_t)pid)
                {
                    size_t n = 1;
                    size_t len;

                    myst_fdmapping_t* p = &v.fdmappings[i];
                    myst_refstr_unref(p->pathname);
                    p->pathname = NULL;

                    /* count consecutive pages with same pid */
                    for (size_t j = i + 1; j < index + count; j++)
                    {
                        if (v.pids[j] != (uint32_t)pid)
                        {
                            break;
                        }

                        myst_fdmapping_t* p = &v.fdmappings[j];
                        myst_refstr_unref(p->pathname);
                        p->pathname = NULL;

                        n++;
                    }

                    len = n * PAGE_SIZE;

                    if (myst_munmap(addr, len) != 0)
                    {
#if 0
                        assert("myst_munmap() failed" == NULL);
                        myst_rspin_unlock(&_mman.lock);
                        ERAISE(-EINVAL);
#endif
                    }

                    i += n;
                    addr += len;
                    length -= len;
                }
                else
                {
                    i++;
                    addr += PAGE_SIZE;
                    length -= PAGE_SIZE;
                }
            }
        }
        myst_rspin_unlock(&_mman.lock);
    }

done:
    return ret;
}

static int _format_proc_maps_entry(
    const void* addr,
    size_t length,
    int prot,
    int flags,
    size_t offset,
    const char* pathname,
    char** str_out)
{
    int ret = 0;
    char* str = NULL;

    /* unused */
    (void)flags;

    if (str_out)
        *str_out = NULL;

    // ATTN: device and inode number are not reported.
    // Shared or private perms bit is always marked 'p',
    // as MAP_SHARED is not supported.
    if (asprintf(
            &str,
            "%08lx-%08lx %c%c%cp %08lx 00:00 0 %s\n",
            (long)addr,
            (long)addr + length,
            prot & PROT_READ ? 'r' : '-',
            prot & PROT_WRITE ? 'w' : '-',
            prot & PROT_EXEC ? 'x' : '-',
            offset,
            pathname) < 0)
    {
        ERAISE(-ENOMEM);
    }

    *str_out = str;
    str = NULL;

done:

    if (str)
        free(str);

    return ret;
}

int proc_pid_maps_vcallback(myst_buf_t* vbuf)
{
    int ret = 0;
    pid_t pid = myst_getpid();
    struct locals
    {
        char realpath[PATH_MAX];
        char maps_entry[48 + PATH_MAX];
    }* locals = NULL;

    if (!vbuf)
        ERAISE(-EINVAL);

    if (!(locals = calloc(1, sizeof(struct locals))))
        ERAISE(-ENOMEM);

    myst_buf_clear(vbuf);

    {
        uint8_t* addr = (uint8_t*)_mman.map;
        size_t length = ((uint8_t*)_mman.end) - addr;
        size_t index;
        vectors_t v = _get_vectors();

        assert(v.pids_count == v.fdmappings_count);

        ECHECK(myst_round_up(length, PAGE_SIZE, &length));
        ECHECK((index = _get_page_index(addr, length)));
        size_t count = length / PAGE_SIZE;

        assert(index < v.pids_count);
        assert(index + count <= v.pids_count);

        myst_rspin_lock(&_mman.lock);
        {
            for (size_t i = index; i < index + count;)
            {
                if (v.pids[i] == (uint32_t)pid)
                {
                    size_t n = 1;
                    size_t len;
                    int fd = v.fdmappings[i].fd;

                    uint32_t used = v.fdmappings[i].used;
                    uint64_t offset = v.fdmappings[i].offset;
                    myst_refstr_t* pathname = v.fdmappings[i].pathname;
                    int prot = 0;
                    bool consistent = false;
                    char* str;
                    int flags = 0;

                    if (myst_mman_get_prot(
                            &_mman, addr, PAGE_SIZE, &prot, &consistent) != 0)
                    {
                        assert("myst_mman_get_prot() failed\n");
                    }

                    /* count consecutive pages with same traits */
                    for (size_t j = i + 1; j < index + count; j++)
                    {
                        int tmp_prot = 0;

                        /* if the pid changes */
                        if (v.pids[j] != (uint32_t)pid)
                            break;

                        if (v.fdmappings[i].used != used)
                            break;

                        /* if the fd changes */
                        if (v.fdmappings[j].fd != fd)
                            break;

                        if (myst_mman_get_prot(
                                &_mman,
                                addr + (n * PAGE_SIZE),
                                PAGE_SIZE,
                                &tmp_prot,
                                &consistent) != 0)
                        {
                            assert("myst_mman_get_prot() failed\n");
                        }

                        if (tmp_prot != prot)
                            break;

                        n++;
                    }

                    len = n * PAGE_SIZE;

                    if (!used)
                        fd = -1;

                    /* format the output */
                    if (_format_proc_maps_entry(
                            addr,
                            len,
                            prot,
                            flags,
                            offset,
                            (pathname ? pathname->data : ""),
                            &str) == 0)
                    {
                        ECHECK(myst_buf_insert(vbuf, 0, str, strlen(str)));
                        free(str);
                    }

                    i += n;
                    addr += len;
                    length -= len;
                }
                else
                {
                    i++;
                    addr += PAGE_SIZE;
                    length -= PAGE_SIZE;
                }
            }
        }
        myst_rspin_unlock(&_mman.lock);
    }

done:

    if (ret != 0)
        myst_buf_release(vbuf);

    if (locals)
        free(locals);

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
    size_t index;
    vectors_t v = _get_vectors();
    const int mask = MS_SYNC | MS_ASYNC | MS_INVALIDATE;

    /* reject bad parameters and unknown flags */
    if (!addr || !length || (flags & ~mask))
        ERAISE(-EINVAL);

    /* fail if both MS_SYNC and MS_ASYNC are both present */
    if ((flags & MS_SYNC) && (flags & MS_ASYNC))
        ERAISE(-EINVAL);

    ECHECK(myst_round_up(length, PAGE_SIZE, &length));
    ECHECK((index = _get_page_index(addr, length)));

    myst_rspin_lock(&_mman.lock);
    {
        const size_t n = length / PAGE_SIZE;
        const uint8_t* page = addr;

        for (size_t i = index; i < index + n; i++)
        {
            myst_fdmapping_t* p = &v.fdmappings[i];

            if (p->used == MYST_FDMAPPING_USED)
                ECHECK(_sync_file(p->fd, p->offset, page, PAGE_SIZE));

            page += PAGE_SIZE;
        }
    }
    myst_rspin_unlock(&_mman.lock);

done:
    return ret;
}

/* notified on close to clear msync mappings involving fd */
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
        myst_rspin_lock(&_mman.lock);
        uint8_t* addr = (uint8_t*)_mman.map;
        size_t length = ((uint8_t*)_mman.end) - addr;
        myst_rspin_unlock(&_mman.lock);

        vectors_t v = _get_vectors();
        size_t index = _get_page_index(addr, length);
        myst_assume(index >= 0);

        myst_rspin_lock(&_mman.lock);
        {
            const size_t count = length / PAGE_SIZE;
            myst_fdmapping_t* p = &v.fdmappings[index];
            const myst_fdmapping_t* end = p + count;
            size_t bytes_remaining = count * sizeof(myst_fdmapping_t);

            while (p < end)
            {
                // Efficiently skip over zero-valued bytes. In-use fdmappings
                // begin with a non-zero byte.
                if ((p = myst_memcchr(p, '\0', bytes_remaining)) == NULL)
                    break;

                if (p->used == MYST_FDMAPPING_USED && p->fd == fd)
                {
                    myst_refstr_unref(p->pathname);
                    memset(p, 0, sizeof(myst_fdmapping_t));
                }

                p++;
                bytes_remaining -= sizeof(myst_fdmapping_t);
            }
        }
        myst_rspin_unlock(&_mman.lock);
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

typedef enum mman_pids_op
{
    MMAN_PIDS_OP_SET,
    MMAN_PIDS_OP_TEST,
} mman_pids_op_t;

static long _handle_mman_pids_op(
    mman_pids_op_t op,
    const void* addr,
    size_t length,
    pid_t pid)
{
    long ret = 0;
    vectors_t v = _get_vectors();
    bool locked = false;
    size_t index;
    size_t count;

    // myst_set_trace(true);

    if (!addr || pid < 0)
        ERAISE(-EINVAL);

    /* addr must be aligned on a page boundary */
    if ((uint64_t)addr % PAGE_SIZE)
        ERAISE(-EINVAL);

    /* round length up to the next multiple of the page boundary */
    ECHECK(myst_round_up(length, PAGE_SIZE, &length));

    myst_rspin_lock(&_mman.lock);
    locked = true;

    ECHECK((index = _get_page_index(addr, length)));
    count = length / PAGE_SIZE;

    assert(index < v.pids_count);
    assert(index + count <= v.pids_count);

    if ((size_t)index >= v.pids_count)
        ERAISE(-ERANGE);

    if (index + count >= v.pids_count)
        ERAISE(-ERANGE);

    /* ATTN: optimize to use 64bit ops */
    switch (op)
    {
        case MMAN_PIDS_OP_SET:
        {
            if (pid == 0)
            {
                memset(&v.pids[index], 0, count * sizeof(uint32_t));
            }
            else
            {
                /* Update the associated elements of pids[] */
                for (size_t i = index; i < index + count; i++)
                {
                    v.pids[i] = pid;
                }
            }

            break;
        }
        case MMAN_PIDS_OP_TEST:
        {
            ssize_t n = 0;

            /* Test the associated elements of pids[] */
            for (size_t i = index; i < index + count; i++)
            {
                if (v.pids[i] != (uint32_t)pid)
                    break;

                n++;
            }

            ret = n * PAGE_SIZE;
            break;
        }
        default:
        {
            ERAISE(-EINVAL);
            break;
        }
    }

done:

    if (locked)
        myst_rspin_unlock(&_mman.lock);

    // myst_set_trace(false);
    return ret;
}

// This function should only be called when carrying out mmap/mremap/munmap
// syscalls on behalf of the application. The kernel should never mark its own
// memory pages as being owned by any process. Else, when the process exits,
// kernel memory objects would be freed.
int myst_mman_pids_set(const void* addr, size_t length, pid_t pid)
{
    return (int)_handle_mman_pids_op(MMAN_PIDS_OP_SET, addr, length, pid);
}

ssize_t myst_mman_pids_test(const void* addr, size_t length, pid_t pid)
{
    return _handle_mman_pids_op(MMAN_PIDS_OP_TEST, addr, length, pid);
}
