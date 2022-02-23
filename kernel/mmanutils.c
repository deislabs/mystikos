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
#include <myst/procfs.h>
#include <myst/refstr.h>
#include <myst/round.h>
#include <myst/strings.h>
#include <myst/syscall.h>
#include <myst/trace.h>

MYST_PRINTF_FORMAT(2, 3)
int asprintf(char** strp, const char* fmt, ...);

/* Scrubbing the unmapped memory (marking with a fixed pattern) has significant
 * performance impact in SGX mode, if the EPC is small. Scrubbing should not be
 * enabled unless the performance impact is not a concern */
//#define SCRUB

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

MYST_INLINE void _rlock(bool* locked)
{
    assert(*locked == false);
    myst_rspin_lock(&_mman.lock);
    *locked = true;
}

MYST_INLINE void _runlock(bool* locked)
{
    if (*locked)
    {
        myst_rspin_unlock(&_mman.lock);
        *locked = false;
    }
}

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

ssize_t _skip_unused_fdmappings(
    const myst_fdmapping_t* fdmappings,
    size_t i,
    size_t n)
{
    const myst_fdmapping_t* start = &fdmappings[i];
    const myst_fdmapping_t* p = start;
    const myst_fdmapping_t* end = &fdmappings[n];
    const size_t nbytes = (end - p) * sizeof(myst_fdmapping_t);

    // Efficiently skip over zero-characters 128-bits at a time. Note that
    // the first bytes of an in-use fd-mapping is non-zero because the
    // used field is MYST_FDMAPPING_USED (where all bytes are non-zero).
    if ((p = myst_memcchr(p, '\0', nbytes)) == NULL)
        return n;

    return i + (p - start);
}

size_t _skip_zero_pids(const uint32_t* pids, size_t i, size_t n)
{
    const uint32_t* start = &pids[i];
    const uint32_t* p = start;
    const uint32_t* end = &pids[n];
    const size_t nbytes = (end - p) * sizeof(uint32_t);

    /* efficiently skip over zero-characters 128-bits at a time */
    if ((p = myst_memcchr(p, '\0', nbytes)) == NULL)
        return n;

    /* align for uint32_t (clear the 2 least-signifiant bits) */
    p = (void*)((uintptr_t)p & 0xfffffffffffffffc);

    return i + (p - start);
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
    size_t n = index + count;

    for (size_t i = index; i < n; i++)
    {
        if ((i = _skip_unused_fdmappings(v.fdmappings, i, n)) == n)
        {
            /* there are no more in-use fd-mappings */
            break;
        }

        myst_fdmapping_t* p = &v.fdmappings[i];

        if (p->pathname)
        {
            myst_refstr_unref(p->pathname);
            p->pathname = NULL;
        }
    }
}

static myst_once_t _free_fdmappings_pathnames_atexit_once;

static void _free_fdmappings_pathnames_atexit(void)
{
    myst_atexit(_free_fdmappings_pathnames, NULL);
}

static int _add_file_mapping(int fd, off_t offset, void* addr, size_t length)
{
    int ret = 0;
    int dupfd;
    bool locked = false;
    size_t index;
    vectors_t v = _get_vectors();
    struct locals
    {
        char pathname[PATH_MAX];
    };
    struct locals* locals = NULL;
    myst_refstr_t* pathname = NULL;

    if (fd < 0 || offset < 0 || !addr || !length)
        ERAISE(-EINVAL);

    if (!(locals = calloc(1, sizeof(struct locals))))
        ERAISE(-ENOMEM);

    /* register the cleanup function for fd-mapping pathnames with atxit() */
    myst_once(
        &_free_fdmappings_pathnames_atexit_once,
        _free_fdmappings_pathnames_atexit);

    ECHECK(_fd_to_pathname(fd, locals->pathname));

    /* make a reference-counted version of the pathname */
    if (!(pathname = myst_refstr_dup(locals->pathname)))
        ERAISE(-ENOMEM);

    /* duplicate fd */
    if ((dupfd = myst_syscall_dup(fd)) == -1)
        ERAISE(dupfd);

    ECHECK(myst_round_up(length, PAGE_SIZE, &length));
    ECHECK((index = _get_page_index(addr, length)));

    _rlock(&locked);
    {
        const size_t count = length / PAGE_SIZE;
        uint64_t off = offset;

        for (size_t i = index; i < index + count; i++)
        {
            myst_fdmapping_t* p = &v.fdmappings[i];

            // The musl libc program loader maps an ELF image onto memory and
            // then calls mmap() on the second page of that memory to change
            // permissions. It is unclear why mprotect() could not be used but
            // we allow mapping over an existing file mapping for this reason.
            if (p->used == MYST_FDMAPPING_USED)
            {
                myst_refstr_unref(p->pathname);
                p->pathname = NULL;
            }

            p->used = MYST_FDMAPPING_USED;
            p->fd = dupfd;
            p->offset = off;
            myst_refstr_ref(p->pathname = pathname);
            off += PAGE_SIZE;
        }
    }
    _runlock(&locked);

done:

    _runlock(&locked);

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

        /* fail if not a regular file or character device(some apps map
         * /dev/zero) */
        if (myst_syscall_fstat(fd, &buf) != 0 ||
            !(S_ISREG(buf.st_mode) || S_ISCHR(buf.st_mode)))
            ERAISE(-EBADF);

        /* get the file open flags */
        if ((flags = myst_syscall_fcntl(fd, F_GETFL, 0)) < 0)
            ERAISE(-EBADF);

        /* operation not allowed on fd opened with O_PATH*/
        if (flags & O_PATH)
            ERAISE(-EBADF);

        /* if file is not open for read */
        if (flags & O_WRONLY)
            ERAISE(-EACCES);

        /* MAP_SHARED & PROT_WRITE set, but fd is not open for read-write */
        if ((flags & MAP_SHARED) && (prot & PROT_WRITE) && !(flags & O_RDWR))
            ERAISE(-EACCES);
    }

    /* Check if posix shm file */
    /* addr hint is not allowed for POSIX shm memory */
    if (fd >= 0 && !addr && myst_is_posix_shm_file_handle(fd, flags))
    {
        ECHECK((
            ret = myst_posix_shm_handle_mmap(fd, addr, length, offset, flags)));
    }
    else if (fd >= 0 && addr)
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

    /* POSIX shm doesn't support mremap yet */
    if (myst_is_address_within_shmem(old_address, old_size))
    {
        return (void*)-EINVAL;
    }

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

    /* Protection bits are per-process. As we are single process on the host,
     * supporting mprotect for memory shared between two process threads becomes
     * tricky. For now, we bail out and treat mprotect as a NOP.
     * */
    if (myst_is_address_within_shmem(addr, len))
    {
        return 0;
    }
    else
    {
        /* Current implementation for mprotect ignore bits beyond
            PROT_READ|PROT_WRITE|PROT_EXEC
        */
        return (myst_mman_mprotect(&_mman, (void*)addr, len, prot));
    }
}

typedef struct fdlist
{
    int fd;
    struct fdlist* next;
} fdlist_t;

fdlist_t* get_tail(fdlist_t* node)
{
    fdlist_t* prev = NULL;
    while (node)
    {
        prev = node;
        node = node->next;
    }
    return prev;
}

/* release msync mappings that are contained in the range [addr:addr+length] */
static int _remove_file_mappings(void* addr, size_t length, fdlist_t** head_out)
{
    int ret = 0;
    size_t index;
    vectors_t v = _get_vectors();
    bool locked = false;
    fdlist_t* head = NULL;

    if (head_out)
        *head_out = NULL;

    if (!addr || !length || !head_out)
        ERAISE(-EINVAL);

    ECHECK(myst_round_up(length, PAGE_SIZE, &length));
    ECHECK((index = _get_page_index(addr, length)));

    _rlock(&locked);
    {
        const size_t count = length / PAGE_SIZE;
        int prev_cleared_fd = -1;

        for (size_t i = index; i < index + count; i++)
        {
            /* remove any fd-mapping (it is okay if it does exist) */
            myst_fdmapping_t* p = &v.fdmappings[i];

            /* add fd's for in-use mappings to a list. add only for the first
             * page of
             * interval mapped with same fd. The fd list will be closed by the
             * caller outside the mman lock. */
            if (p->used == MYST_FDMAPPING_USED && p->fd != prev_cleared_fd)
            {
                fdlist_t* fd_node;

                if ((fd_node = calloc(1, sizeof(fdlist_t))) == NULL)
                {
                    _runlock(&locked);
                    ERAISE(-ENOMEM);
                }

                fd_node->fd = prev_cleared_fd = p->fd;
                if (!head)
                    head = fd_node;
                else
                {
                    fd_node->next = head;
                    head = fd_node;
                }
            }

            // clear fd mapping
            p->used = 0;
            p->fd = 0;
            p->offset = 0;
            myst_refstr_unref(p->pathname);
            p->pathname = NULL;
        }
    }
    _runlock(&locked);

    *head_out = head;
    head = NULL;

done:

    while (head)
    {
        fdlist_t* next = head->next;
        free(head);
        head = next;
    }

    return ret;
}

static void _close_file_handles(fdlist_t* head)
{
    while (head)
    {
        fdlist_t* next = head->next;
        myst_syscall_close(head->fd);
        free(head);
        head = next;
    }
}

int __myst_munmap(void* addr, size_t length, fdlist_t** head_out)
{
    int ret = 0;
    bool locked = false;

    /* address cannot be null and must be aligned on a page boundary */
    if (!addr || ((uint64_t)addr % PAGE_SIZE) || !length)
        ERAISE(-EINVAL);

    /* align length to a page boundary */
    ECHECK(myst_round_up(length, PAGE_SIZE, &length));

    _rlock(&locked);
    ECHECK(myst_mman_munmap(&_mman, addr, length));
    ECHECK(_remove_file_mappings(addr, length, head_out));
    _runlock(&locked);

done:
    _runlock(&locked);
    return ret;
}

int myst_munmap(void* addr, size_t length)
{
    int ret = 0;
    fdlist_t* head = NULL;

    ECHECK(__myst_munmap(addr, length, &head));

    // close file handles outside of mman lock
    _close_file_handles(head);

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
    bool locked = false;
    fdlist_t* catchall = NULL;

    assert(pid > 0);

    if (pid <= 0)
        ERAISE(-EINVAL);

    /* Release posix shared memory mappings for this process */
    myst_posix_shm_handle_release_mappings(pid);

    /* Scan entire pids vector range for process-owned memory */
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

        _rlock(&locked);
        {
            const size_t n = index + count;

            for (size_t i = index; i < n;)
            {
                /* skip over consecutive zero pids */
                {
                    size_t r;

                    if ((r = _skip_zero_pids(v.pids, i, n)) == n)
                    {
                        /* there were no more non-zero pids */
                        break;
                    }

                    /* if zero pids were skipped */
                    if (r != i)
                    {
                        size_t len = (r - i) * PAGE_SIZE;
                        addr += len;
                        i = r;
                    }
                }

                if (v.pids[i] == (uint32_t)pid)
                {
                    size_t m = 1;
                    size_t len;

                    myst_fdmapping_t* p = &v.fdmappings[i];

                    if (p->pathname)
                    {
                        myst_refstr_unref(p->pathname);
                        p->pathname = NULL;
                    }

                    /* count consecutive pages with same pid */
                    for (size_t j = i + 1; j < n; j++)
                    {
                        if (v.pids[j] != (uint32_t)pid)
                        {
                            break;
                        }

                        myst_fdmapping_t* p = &v.fdmappings[j];

                        if (p->pathname)
                        {
                            myst_refstr_unref(p->pathname);
                            p->pathname = NULL;
                        }

                        m++;
                    }

                    len = m * PAGE_SIZE;

                    fdlist_t* unmap_fds = NULL;
                    if (__myst_munmap(addr, len, &unmap_fds) != 0)
                    {
                        /* The unmap operation is not expected to fail, even for
                         * shared memory between a parent process and a child
                         * process, due to fork/vfork without exec, in which
                         * case, the shared memory should be registered as owned
                         * by the parent process, and released as part of parent
                         * process shutdown, with the expectation that the child
                         * process shut downs first  */

                        // myst_eprintf("myst_munmap() %p failed, pid=%d.
                        // len=0x%lx err=%s\n", addr, pid, len, _mman.err);
                        assert("myst_munmap() failed" == NULL);
                        ERAISE(-EINVAL);
                    }

                    // prepend any fds returned by munmap to catchall list
                    if (unmap_fds)
                    {
                        if (catchall)
                        {
                            fdlist_t* tail = get_tail(unmap_fds);
                            tail->next = catchall;
                        }
                        catchall = unmap_fds;
                    }

                    /* always clear the pid vector */
                    myst_mman_pids_set(addr, len, 0);

                    i += m;
                    addr += len;
                }
                else
                {
                    i++;
                    addr += PAGE_SIZE;
                }
            }
        }
        _runlock(&locked);
    }

done:

    _runlock(&locked);

    // close file handles outside of mman lock
    _close_file_handles(catchall);

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

int proc_pid_maps_vcallback(
    myst_file_t* self,
    myst_buf_t* vbuf,
    const char* entrypath)
{
    (void)self;
    int ret = 0;
    bool locked = false;
    pid_t pid = 0;
    struct locals
    {
        char realpath[PATH_MAX];
        char maps_entry[48 + PATH_MAX];
    }* locals = NULL;
    myst_process_t* process;

    myst_spin_lock(&myst_process_list_lock);

    if (!vbuf && !entrypath)
        ERAISE(-EINVAL);

    if (!(locals = calloc(1, sizeof(struct locals))))
        ERAISE(-ENOMEM);

    process = myst_procfs_path_to_process(entrypath);

    if (process == NULL)
        ERAISE(-EINVAL);

    pid = process->pid;

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

        _rlock(&locked);
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

                        if (v.fdmappings[j].used != used)
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
                        if (myst_buf_insert(vbuf, 0, str, strlen(str)) < 0)
                            ERAISE(-ENOMEM);
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
        _runlock(&locked);
    }

done:
    _runlock(&locked);

    myst_spin_unlock(&myst_process_list_lock);

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
    bool locked = false;
    size_t index;
    vectors_t v = _get_vectors();
    const int mask = MS_SYNC | MS_ASYNC | MS_INVALIDATE;
    size_t rounded_up_length;

    /* reject bad parameters and unknown flags */
    if (!addr || ((uint64_t)addr % PAGE_SIZE) || !length || (flags & ~mask))
        ERAISE(-EINVAL);

    /* fail if both MS_SYNC and MS_ASYNC are both present */
    if ((flags & MS_SYNC) && (flags & MS_ASYNC))
        ERAISE(-EINVAL);

    ECHECK(myst_round_up(length, PAGE_SIZE, &rounded_up_length));
    ECHECK((index = _get_page_index(addr, rounded_up_length)));

    _rlock(&locked);
    {
        int prot;
        bool consistent;
        const size_t n = rounded_up_length / PAGE_SIZE;
        uint8_t* page = addr;

        for (size_t i = index; i < index + n; i++)
        {
            myst_fdmapping_t* p = &v.fdmappings[i];

            if (p->used == MYST_FDMAPPING_USED)
            {
                ECHECK(myst_mman_get_prot(
                    &_mman, page, PAGE_SIZE, &prot, &consistent));
                if (prot & PROT_WRITE)
                    ECHECK(_sync_file(
                        p->fd,
                        p->offset,
                        page,
                        length > PAGE_SIZE ? PAGE_SIZE : length));
            }

            page += PAGE_SIZE;
            length -= PAGE_SIZE;
        }
    }
    _runlock(&locked);

done:
    _runlock(&locked);

    return ret;
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

    if (!addr || pid < 0)
        ERAISE(-EINVAL);

    /* addr must be aligned on a page boundary */
    if ((uint64_t)addr % PAGE_SIZE)
        ERAISE(-EINVAL);

    /* round length up to the next multiple of the page boundary */
    ECHECK(myst_round_up(length, PAGE_SIZE, &length));

    _rlock(&locked);

    ECHECK((ssize_t)(index = _get_page_index(addr, length)));
    count = length / PAGE_SIZE;

    if ((size_t)index >= v.pids_count)
        ERAISE(-ERANGE);

    if (index + count > v.pids_count)
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
    _runlock(&locked);

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

bool myst_is_bad_addr(const void* addr, size_t length, int prot)
{
    bool ret = true;

    if (!addr)
        goto done;

/* ATTN: temporay workaround to relax the bad addr check. Can be
 * removed once ensuring the user signal handling code does not use
 * kstack */
#ifndef MYST_RELAX_BAD_ADDR_CHECK
    if (__myst_kernel_args.nobrk)
    {
        /* pid test is only supported if the nobrk option is enabled as
         * the pid vector does not track memory allocated via brk */

        uint64_t page_addr = myst_round_down_to_page_size((uint64_t)addr);

        /* round up the length (including the zero case) to PAGE_SIZE */
        if (myst_round_up(length ? length : 1, PAGE_SIZE, &length) < 0)
            goto done;

        /* check if the pages within the address range are unmapped (i.e.,
         * associated pid is zero). */
        if (myst_mman_pids_test((const void*)page_addr, length, 0) > 0)
            goto done;

        /* check for the page permissions */
        {
            bool consistent;
            int prot_mask;

            if (myst_mman_get_prot(
                    &_mman, (void*)page_addr, length, &prot_mask, &consistent) <
                0)
                goto done;

            if (!consistent || !(prot & prot_mask))
                goto done;
        }
    }
    else
#else
    /* avoid the unused-parameter warnings */
    (void)length;
    (void)prot;
#endif
    {
        /* fallback to simple memory range check if the nobrk option is not
         * enabled */
        if (!myst_is_addr_within_kernel(addr))
            goto done;
    }

    ret = false;

done:
    return ret;
}

void myst_mman_lock(void)
{
    myst_rspin_lock(&_mman.lock);
}

void myst_mman_unlock(void)
{
    myst_rspin_unlock(&_mman.lock);
}
