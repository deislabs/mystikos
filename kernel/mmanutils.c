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
#include <myst/lockfs.h>
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
#include <myst/sharedmem.h>
#include <myst/strings.h>
#include <myst/syscall.h>
#include <myst/syslog.h>
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

MYST_INLINE void _fslock(bool* locked)
{
    assert(*locked == false);
    myst_lockfs_lock();
    *locked = true;
}

MYST_INLINE void _fsunlock(bool* locked)
{
    if (*locked)
    {
        myst_lockfs_unlock();
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

static __inline__ size_t _min_size(size_t x, size_t y)
{
    return x < y ? x : y;
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

    if (!addr && !length)
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

static myst_list_t mman_file_handles;
static myst_once_t _free_mman_file_handles_atexit_once;

static void _free_mman_file_handles_atexit(void)
{
    myst_atexit((void (*)(void*))myst_list_free, &mman_file_handles);
}

static ino_t _get_inode(myst_fs_t* fs, myst_file_t* file)
{
    assert(fs && file);
    struct stat statbuf;
    fs->fs_fstat(fs, file, &statbuf);
    return statbuf.st_ino;
}

long myst_mman_file_handle_get(int fd, mman_file_handle_t** file_handle_out)
{
    long ret = 0;
    myst_fs_t* fs;
    myst_file_t *file, *file_out;
    mman_file_handle_t* file_handle = NULL;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    struct locals
    {
        char pathname[PATH_MAX];
        char suffix[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!file_handle_out)
        ERAISE(-EINVAL);

    *file_handle_out = NULL;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    if (!(file_handle = calloc(1, sizeof(mman_file_handle_t))))
        ERAISE(-ENOMEM);

    /* register the cleanup function for mman owned file handles with atexit()
     */
    myst_once(
        &_free_mman_file_handles_atexit_once, _free_mman_file_handles_atexit);

    // get a dup file handle which the mman will use
    // for msync and /proc/[pid]/maps
    ECHECK(myst_fdtable_get_file(fdtable, fd, &fs, &file));
    ECHECK((*fs->fs_dup)(fs, file, &file_out));

    file_handle->fs = fs;
    file_handle->file = file_out;
    file_handle->inode = _get_inode(fs, file);
    myst_list_prepend(&mman_file_handles, &file_handle->base);

    *file_handle_out = file_handle;
    file_handle = NULL;

done:

    if (locals)
        free(locals);

    if (file_handle)
        free(file_handle);

    return ret;
}

void myst_mman_file_handle_put(mman_file_handle_t* file_handle)
{
    assert(file_handle);
    if (--file_handle->npages <= 0)
    {
        myst_list_remove(&mman_file_handles, &file_handle->base);
        file_handle->fs->fs_close(file_handle->fs, file_handle->file);
        free(file_handle);
    }
}

bool mman_file_handle_eq(mman_file_handle_t* f1, mman_file_handle_t* f2)
{
    if (!f1 && !f2)
        return true;
    if (!f1 || !f2)
        return false;
    if (f1->fs == f2->fs && f1->inode == f2->inode)
        return true;
    return false;
}

size_t myst_mman_backing_file_size(mman_file_handle_t* file_handle)
{
    assert(file_handle);
    struct stat statbuf;
    assert(
        (file_handle->fs->fs_fstat)(
            file_handle->fs, file_handle->file, &statbuf) == 0);
    return statbuf.st_size;
}

static int _add_file_mapping(int fd, off_t offset, void* addr, size_t length)
{
    int ret = 0;
    bool locked = false;
    size_t index, file_size;
    vectors_t v = _get_vectors();
    mman_file_handle_t* file_handle = NULL;

    if (fd < 0 || offset < 0 || !addr || !length)
        ERAISE(-EINVAL);

    ECHECK(myst_round_up(length, PAGE_SIZE, &length));
    ECHECK((index = _get_page_index(addr, length)));

    ECHECK(myst_mman_file_handle_get(fd, &file_handle));

    file_size = myst_mman_backing_file_size(file_handle);

    _rlock(&locked);
    {
        const size_t count = length / PAGE_SIZE;
        uint64_t off = offset;

        for (size_t i = index; i < index + count; i++)
        {
            myst_fdmapping_t* p = &v.fdmappings[i];

            assert(
                (p->used && p->mman_file_handle) ||
                (!p->used && !p->mman_file_handle));

            // The musl libc program loader maps an ELF image onto memory and
            // then calls mmap() on the second page of that memory to change
            // permissions. It is unclear why mprotect() could not be used but
            // we allow mapping over an existing file mapping for this reason.
            // Avoid overwriting file handle if the fdmapping entry also points
            // to the same file.
            if (!p->used ||
                !mman_file_handle_eq(p->mman_file_handle, file_handle))
            {
                if (p->mman_file_handle)
                    myst_mman_file_handle_put(p->mman_file_handle);
                p->mman_file_handle = file_handle;
                file_handle->npages++;
            }
            p->used = MYST_FDMAPPING_USED;
            p->filesz = file_size;
            p->offset = off;
            off += PAGE_SIZE;
        }
    }
    _runlock(&locked);

done:

    _runlock(&locked);

    // if file handle was not used
    if (!file_handle->npages)
        myst_mman_file_handle_put(file_handle);

    return ret;
}

typedef struct fdlist
{
    mman_file_handle_t* mman_file_handle;
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

        for (size_t i = index; i < index + count; i++)
        {
            /* remove any fd-mapping (it is okay if it does exist) */
            myst_fdmapping_t* p = &v.fdmappings[i];

            assert(
                (p->used && p->mman_file_handle) ||
                (!p->used && !p->mman_file_handle));

            if (p->used == MYST_FDMAPPING_USED)
            {
                if (p->mman_file_handle->npages > 1)
                {
                    myst_mman_file_handle_put(p->mman_file_handle);
                }
                // if last page, defer filesystem close as this can cause mman
                // and lockfs locks to deadlock. file handles are appended to a
                // list which is closed later when outside of the mman lock.
                else
                {
                    fdlist_t* fd_node;

                    if ((fd_node = calloc(1, sizeof(fdlist_t))) == NULL)
                    {
                        _runlock(&locked);
                        ERAISE(-ENOMEM);
                    }

                    fd_node->mman_file_handle = p->mman_file_handle;

                    if (!head)
                        head = fd_node;
                    else
                    {
                        fd_node->next = head;
                        head = fd_node;
                    }
                }
            }

            // clear fd mapping
            memset(p, 0, sizeof(myst_fdmapping_t));
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
        myst_mman_file_handle_put(head->mman_file_handle);
        free(head);
        head = next;
    }
}

static int _move_file_mapping(
    void* old_addr,
    size_t old_size,
    void* new_addr,
    size_t new_size)
{
    int ret = 0;
    bool locked = false;

    if (!old_addr || !old_size || !new_addr || !new_size)
        ERAISE(-EINVAL);

    if (old_addr == new_addr)
    {
        // Case: Grow in-place
        if (old_size <= new_size)
            // We don't need update file mappings vector here as the new region
            // does not correspond to the file.
            goto done;
        else // Shrink in-place
        {
            fdlist_t* file_handle_head;

            size_t num_reclaim_pages =
                myst_round_down_to_page_size(old_size - new_size);
            uint64_t reclaim_start_addr = (uint64_t)new_addr + new_size;
            ECHECK(myst_round_up(
                reclaim_start_addr, PAGE_SIZE, &reclaim_start_addr));
            _remove_file_mappings(
                (void*)reclaim_start_addr,
                num_reclaim_pages,
                &file_handle_head);
            _close_file_handles(file_handle_head);
        }
    }
    else // mapping got moved
    {
        assert(old_size < new_size);

        size_t old_index, new_index, i, j;
        vectors_t v = _get_vectors();

        ECHECK(myst_round_up(old_size, PAGE_SIZE, &old_size));
        ECHECK((old_index = _get_page_index(old_addr, old_size)));
        ECHECK(myst_round_up(new_size, PAGE_SIZE, &new_size));
        ECHECK((new_index = _get_page_index(new_addr, new_size)));

        _rlock(&locked);
        {
            const size_t count = old_size / PAGE_SIZE;

            for (i = old_index, j = new_index; i < old_index + count; i++, j++)
            {
                myst_fdmapping_t* p = &v.fdmappings[i];
                myst_fdmapping_t* q = &v.fdmappings[j];

                assert(
                    (p->used && p->mman_file_handle) ||
                    (!p->used && !p->mman_file_handle));
                assert(!q->used && !q->mman_file_handle);

                if (p->used)
                {
                    q->used = MYST_FDMAPPING_USED;
                    q->offset = p->offset;
                    q->mman_file_handle = p->mman_file_handle;

                    // clear fdmapping for old page
                    memset(p, 0, sizeof(myst_fdmapping_t));
                }
            }
        }
        _runlock(&locked);
    }

done:
    _runlock(&locked);

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

static int _mmap_fd_checks(int prot, int flags, int fd)
{
    long ret = 0;

    /* fail if fd is negative when the MAP_ANONYMOUS flag is not present */
    if (!(flags & MAP_ANONYMOUS) && fd < 0)
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

done:
    return ret;
}

void update_mem_usage(long length)
{
    long new_usage = _mman.current_usage + length;
    if(new_usage > _mman.peak_usage)
    {
        _mman.peak_usage = new_usage;
    }

    _mman.current_usage = new_usage;
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
    bool locked = false, fs_locked = false;

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

    if (fd >= 0)
        _fslock(&fs_locked);
    _rlock(&locked);

    ECHECK(_mmap_fd_checks(prot, flags, fd));

    /* Case: POSIX shared memory file mapping */
    if (fd >= 0 && !addr && myst_is_posix_shm_file_handle(fd, flags))
    {
        /* If the file descriptor is a POSIX shm file and addr hint is provided:
            MAP_PRIVATE - will fail in myst_posix_shm_handle_mmap param
           validation. MAP_SHARED - we don't support addr hint for shared
           mappings. Already handled in the syscall handler _SYS_mmap.
        */
        /* Right now that case falls through into the next else and fails in
         * myst_mman_map */

        ECHECK((
            ret = myst_posix_shm_handle_mmap(fd, addr, length, offset, flags)));
    }
    /* Case: File mapping && no addr hint. Map file onto existing mapping.
    Process owns [addr,addr+length] was checked in the syscall handler _SYS_mmap
    */
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
    // Cases:
    //    Anonymous mapping(MAP_ANON) && addr hint: only page protection
    //    update in myst_mman_mmap epilogue.
    //
    //    No addr hint: allocation, VADS list and page prot vector update.
    //        Anonymous mapping.
    //        File mapping: map file onto memory, fdmapping vector update.
    //
    //        For the non addr hint case, if MAP_SHARED is passed: add to shared
    //        memory list.
    else
    {
        int tflags = 0;

        if (flags & MYST_MAP_FIXED)
            tflags = MYST_MAP_ANONYMOUS | MYST_MAP_PRIVATE | MYST_MAP_FIXED;
        else
            tflags = MYST_MAP_ANONYMOUS | MYST_MAP_PRIVATE;

        ECHECK(
            myst_mman_mmap(&_mman, addr, length, prot, tflags, (void**)&ret));

        //Update mem usage myst_mmap
        if (__myst_kernel_args.perf)
            update_mem_usage(length);

        // ATTN: For failures in the rest of the function, do we need to return
        // the allocated memory
        if (fd >= 0)
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

        if (ret && (flags & MAP_SHARED))
            ECHECK(myst_shmem_register_mapping(fd, (void*)ret, length, offset));
    }

    void* end = (void*)(ret + length);
    assert((void*)ret >= _mman_start && (void*)ret <= _mman_end);
    assert(end >= _mman_start && end <= _mman_end);

done:

    _runlock(&locked);
    _fsunlock(&fs_locked);
    return ret;
}

void* myst_mremap(
    void* old_address,
    size_t old_size,
    size_t new_size,
    int flags,
    void* new_address)
{
    long ret = 0;
    void* p;
    shared_mapping_t* shm_mapping = NULL;
    bool locked = false, fs_locked = false;

    if (new_address)
        ERAISE(-EINVAL);

    if (new_size < old_size)
        _fslock(&fs_locked);

    _rlock(&locked);
    /* If we are here, ownership check in the syscall handler has passed. We
     * still need to call the shared memory ownership check routine to get
     * the shared mapping object. */
    int lookup_ret = myst_addr_within_process_owned_shmem(
        old_address, old_size, 0, &shm_mapping);

    if (lookup_ret == 1)
    {
        if (!myst_shmem_can_mremap(shm_mapping, old_address, old_size))
        {
            MYST_WLOG("Unsupported mremap operation detected. For shared "
                      "mappings, mremap is only allowed if there is a single "
                      "user of the mapping.\n");
            ERAISE(-EINVAL);
        }
    }
    // bubble-up errors.
    else if (lookup_ret < 0)
        ERAISE(lookup_ret);
    // ATTN:
    // For in-kernel users of mremap like dlmalloc, lookup_ret will be 0.
    // TODO: check lookup_ret should not be 0 for calls from _SYS_mremap.

    ECHECK(
        myst_mman_mremap(&_mman, old_address, old_size, new_size, flags, &p));

    //Update mem usage myst_mman_mremap
    if (__myst_kernel_args.perf)
        update_mem_usage((long)new_size - (long)old_size);

    // fixup shared mapping
    if (shm_mapping)
    {
        myst_shmem_mremap_update(shm_mapping, p, new_size);
    }

    ECHECK(_move_file_mapping(old_address, old_size, p, new_size));

    ret = (long)p;

done:
    _runlock(&locked);
    _fsunlock(&fs_locked);

    return (void*)ret;
}

int myst_mprotect(const void* addr, const size_t len, const int prot)
{
    int ret = 0;
    shared_mapping_t* shm_mapping;
    bool locked = false;

    if (!addr)
        return -EINVAL;

    /* check for invalid PROT bits */
    if (prot & (~MYST_PROT_MPROTECT_MASK))
        return -EINVAL;

    /* PROT cannot have both PROT_GROWSDOWN and MYST_PROT_GROWSUP bits set */
    if ((prot & MYST_PROT_GROWSDOWN) && (prot & MYST_PROT_GROWSUP))
        return -EINVAL;

    // we don't support changing protection left of addr
    assert(!(prot & MYST_PROT_GROWSDOWN));

    _rlock(&locked);
    {
        int lookup_ret =
            myst_addr_within_process_owned_shmem(addr, len, 0, &shm_mapping);

        if (lookup_ret == 1)
        {
            if (!myst_shmem_can_mprotect(shm_mapping, (void*)addr, len))
            {
                MYST_WLOG(
                    "Unsupported mprotect operation detected. For shared "
                    "mappings, mprotect is only allowed if there is a single "
                    "user of the mapping. Mystikos relies on host for page "
                    "protection. On x86-64 and Linux, page protection is per "
                    "address space. As we "
                    "are single process on the host, supporting mprotect for "
                    "memory shared between two process threads becomes "
                    "difficult.\n");
                ERAISE(-EINVAL);
            }
        }
        else if (lookup_ret < 0)
            ERAISE(lookup_ret);
    }

    {
        /* Current implementation for mprotect ignore bits beyond
            PROT_READ|PROT_WRITE|PROT_EXEC
        */
        ECHECK(myst_mman_mprotect(&_mman, (void*)addr, len, prot));
    }

done:

    _runlock(&locked);
    return ret;
}

int __myst_munmap(void* addr, size_t length, fdlist_t** head_out)
{
    int ret = 0;

    /* address cannot be null and must be aligned on a page boundary */
    if (!addr || ((uint64_t)addr % PAGE_SIZE) || !length)
        ERAISE(-EINVAL);

    /* align length to a page boundary */
    ECHECK(myst_round_up(length, PAGE_SIZE, &length));

    ECHECK(myst_mman_munmap(&_mman, addr, length));

    //Update mem usage myst_mman_munmap
    if (__myst_kernel_args.perf)
        update_mem_usage(-1 * (long)length);

    ECHECK(_remove_file_mappings(addr, length, head_out));

done:
    return ret;
}

int myst_munmap(void* addr, size_t length)
{
    int ret = 0;
    fdlist_t* head = NULL;
    bool locked = false;

    /* File system lock is acquired in the syscall handler. dlmalloc calls to
     * myst_mmap/munmap already acquire the mman lock. Acquiring the file system
     * lock here can lead to deadlock. The assumption is that in-kernel usages
     * never do file mappings. */
    _rlock(&locked);
    ECHECK(__myst_munmap(addr, length, &head));
    _close_file_handles(head);

done:
    _runlock(&locked);
    return ret;
}

int myst_munmap_and_pids_clear_atomic(void* addr, size_t length)
{
    int ret = 0;
    fdlist_t* head = NULL;
    bool locked = false;

    _rlock(&locked);
    ECHECK(__myst_munmap(addr, length, &head));
    myst_mman_pids_set(addr, length, 0);
    _close_file_handles(head);

done:
    _runlock(&locked);
    return ret;
}

long myst_syscall_brk(void* addr)
{
    void* ptr = NULL;

    /* Ignore return value (ptr is set to the current brk value on failure) */
    myst_mman_brk(&_mman, addr, &ptr);

    return (long)ptr;
}

int myst_get_peak_memory_usage(long* size)
{
    return myst_mman_peak_memory_usage(&_mman, size);
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
    bool locked = false, fs_locked = false;
    fdlist_t* catchall = NULL;

    assert(pid > 0);

    /* Acquire filesystem lock, as writeback may happen for process owned
     * MAP_SHARED mappings. */
    _fslock(&fs_locked);
    _rlock(&locked);

    /* Release shared memory mappings for this process */
    ECHECK(myst_shmem_handle_release_mappings(pid));

    /* Scan entire pids vector range for process-owned MAP_PRIVATE memory */
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

                    /* count consecutive pages with same pid */
                    for (size_t j = i + 1; j < n; j++)
                    {
                        if (v.pids[j] != (uint32_t)pid)
                        {
                            break;
                        }
                        m++;
                    }

                    len = m * PAGE_SIZE;

                    fdlist_t* unmap_fds = NULL;
                    /* ATTN: remove code for closing file handles outside mman
                     * lock.
                     */
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
                        // We are really expecting for this to not fail. Failing
                        // will cause mman and lockfs lock to be un-acquirable
                        // by other threads for posterity.
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
    }

done:

    _runlock(&locked);
    // ATTN: not required now.
    // close file handles outside of mman lock
    _close_file_handles(catchall);
    _fsunlock(&fs_locked);

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
    bool locked = false, fs_locked = false;
    pid_t pid = 0;
    struct locals
    {
        char realpath[PATH_MAX];
    }* locals = NULL;
    myst_process_t* process;

    myst_spin_lock(&myst_process_list_lock);
    /* We already hold the lockfs lock, as this function is called on an
    open("/proc/[pid]/maps"). lockfs lock is recursive, so it doesn't hurt to
    re-acquire. */
    _fslock(&fs_locked);

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

        size_t last_page_idx_plus_one = index + count;
        assert(index < v.pids_count);
        assert(last_page_idx_plus_one == v.pids_count);

        _rlock(&locked);
        {
            for (size_t i = index; i < last_page_idx_plus_one;)
            {
                if (v.pids[i] == (uint32_t)pid)
                {
                    size_t n = 1; // tracks page span with same traits
                    mman_file_handle_t* file_handle =
                        v.fdmappings[i].mman_file_handle;

                    uint32_t used = v.fdmappings[i].used;
                    uint64_t offset = v.fdmappings[i].offset;

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
                    for (size_t j = i + 1; j < last_page_idx_plus_one; j++)
                    {
                        int tmp_prot = 0;

                        /* if the pid changes */
                        if (v.pids[j] != (uint32_t)pid)
                            break;

                        if (v.fdmappings[j].used != used)
                            break;

                        /* if the file changes */
                        if (!mman_file_handle_eq(
                                v.fdmappings[j].mman_file_handle, file_handle))
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

                    if (used)
                    {
                        ECHECK(file_handle->fs->fs_realpath(
                            file_handle->fs,
                            file_handle->file,
                            locals->realpath,
                            PATH_MAX));
                    }

                    /* format the output */
                    if (_format_proc_maps_entry(
                            addr,
                            n * PAGE_SIZE,
                            prot,
                            flags,
                            offset,
                            (used ? locals->realpath : ""),
                            &str) == 0)
                    {
                        if (myst_buf_insert(vbuf, 0, str, strlen(str)) < 0)
                            ERAISE(-ENOMEM);
                        free(str);
                    }

                    i += n;
                    addr += n * PAGE_SIZE;
                    length -= n * PAGE_SIZE;
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
    _fsunlock(&fs_locked);
    myst_spin_unlock(&myst_process_list_lock);

    if (ret != 0)
        myst_buf_release(vbuf);

    if (locals)
        free(locals);

    return ret;
}

static int _sync_file(
    mman_file_handle_t* file_handle,
    off_t offset,
    const void* addr,
    size_t length)
{
    int ret = 0;
    const uint8_t* p = (const uint8_t*)addr;
    size_t r = length;
    off_t o = offset;

    while (r > 0)
    {
        ssize_t n = (file_handle->fs->fs_pwrite)(
            file_handle->fs, file_handle->file, p, r, o);

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
    bool locked = false, fs_locked = false;
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

    _fslock(&fs_locked);
    _rlock(&locked);
    {
        int prot;
        bool consistent;
        const size_t n = rounded_up_length / PAGE_SIZE;
        uint8_t* page = addr;

        for (size_t i = index; i < index + n; i++)
        {
            myst_fdmapping_t* p = &v.fdmappings[i];

            if (p->used == MYST_FDMAPPING_USED && p->offset < p->filesz)
            {
                ECHECK(myst_mman_get_prot(
                    &_mman, page, PAGE_SIZE, &prot, &consistent));

                if (prot & PROT_WRITE)
                {
                    size_t num_bytes_to_write = _min_size(
                        p->filesz - p->offset, _min_size(PAGE_SIZE, length));
                    ECHECK(_sync_file(
                        p->mman_file_handle,
                        p->offset,
                        page,
                        num_bytes_to_write));
                }
            }

            page += PAGE_SIZE;
            length -= PAGE_SIZE;
        }
    }

done:
    _runlock(&locked);
    _fsunlock(&fs_locked);

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

map_type_t myst_process_owns_mem_range(
    const void* addr,
    size_t length,
    bool private_only)
{
    bool locked = false;
    map_type_t map_type = NONE;
    pid_t pid = myst_getpid();
    uint64_t page_addr = myst_round_down_to_page_size((uint64_t)addr);

    /*
    Account for memory range covered due to rounding down start address.
    Example case: p1 owns 0x1000-0x2000
    Query for: 0x1001, 4096 = false
    Query for: 0x1001, 4095 = true
    */
    length += (uint64_t)addr % PAGE_SIZE;

    /* Round up the length (including the zero case) to PAGE_SIZE. If length is
     * 0, still check if the page pointed by addr is owned by the process.
     */
    if (myst_round_up(length ? length : 1, PAGE_SIZE, &length) < 0)
        return NONE;

    _rlock(&locked);
    /* check for MAP_PRIVATE mappings */
    ssize_t test_ret = myst_mman_pids_test((const void*)page_addr, length, pid);
    if (test_ret == (ssize_t)length)
    {
        map_type = PRIVATE;
        goto done;
    }

    // ATTN: fail if test_ret > 0? Case where memory region is partially owned
    // by pid.

    /* check for MAP_SHARED mappings */
    if (!private_only)
    {
        int ret = myst_addr_within_process_owned_shmem(
            (void*)page_addr, length, pid, NULL);
        if (ret == 1)
        {
            map_type = SHARED;
            goto done;
        }
    }

done:

    _runlock(&locked);
    return map_type;
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

        if (!myst_process_owns_mem_range(addr, length, NULL))
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

const char* myst_mman_prot_to_string(int prot)
{
    switch (prot)
    {
        case 0:
            return "PROT_NONE";
        case 1:
            return "PROT_READ";
        case 2:
            return "PROT_WRITE";
        case 3:
            return "PROT_READ|PROT_WRITE";
        case 4:
            return "PROT_EXEC";
        case 5:
            return "PROT_READ|PROT_EXEC";
        case 7:
            return "PROT_READ|PROT_WRITE|PROT_EXEC";
        default:
            return "unknown";
    }
}

const char* myst_mman_flags_to_string(int flags)
{
    switch (flags)
    {
        case MYST_MAP_SHARED:
            return "MAP_SHARED";
        case MYST_MAP_PRIVATE:
            return "MAP_PRIVATE";
        case MYST_MAP_FIXED:
            return "MAP_FIXED";
        case MYST_MAP_ANONYMOUS:
            return "MAP_ANONYMOUS";
        case MYST_MAP_SHARED | MYST_MAP_ANONYMOUS:
            return "MAP_SHARED|MAP_ANONYMOUS";
        case MYST_MAP_FIXED | MYST_MAP_PRIVATE:
            return "MAP_FIXED|MAP_PRIVATE";
        case MYST_MAP_ANONYMOUS | MYST_MAP_PRIVATE:
            return "MAP_ANONYMOUS|MAP_PRIVATE";
        case MYST_MAP_FIXED | MYST_MAP_ANONYMOUS | MYST_MAP_PRIVATE:
            return "MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE";
        default:
            return "unknown";
    }
}

int myst_maccess(const void* addr, size_t length, int prot)
{
    return myst_mman_maccess(&_mman, addr, length, prot);
}
