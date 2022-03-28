// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <myst/atexit.h>
#include <myst/eraise.h>
#include <myst/file.h>
#include <myst/fs.h>
#include <myst/list.h>
#include <myst/mount.h>
#include <myst/once.h>
#include <myst/panic.h>
#include <myst/printf.h>
#include <myst/process.h>
#include <myst/ramfs.h>
#include <myst/round.h>
#include <myst/rspinlock.h>
#include <myst/sharedmem.h>
#include <myst/syscall.h>
#include <myst/syslog.h>
#include <stdbool.h>
#include <sys/mman.h>

//#define TRACE
//#define PARTIAL_MAPPING
/**
 * POSIX Shared Memory
 *
 * Leverage ramfs to implement POSIX Shared Memory semantics.
 *
 * Simple usage example:
 *
 * int fd = shm_open("foo", O_CREAT|O_RDWR , (S_IRUSR|S_IWUSR));
 * ftruncate(fd, SHM_SIZE);
 * char *addr = mmap(0, SHM_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
 *
 * For mmap's related to files opened via shm_open, pointer to the underlying
 * file buffer is returned. ramfs files use myst_buf_t to store the data.
 *
 * Because a pointer to myst_buf_t is passed to the userspace, buffer resize
 * operations can be supported safely only when there are no active mappings
 * against the corresponding shmfs file.
 *
 */

typedef struct proc_w_count
{
    myst_list_node_t base;
    pid_t pid;
    int nmaps; // per-process refcount. process can mmap shm region multiple
               // times.
} proc_w_count_t;

typedef enum
{
    SHMEM_NONE,
    SHMEM_ANON,
    SHMEM_REG_FILE,
    SHMEM_POSIX_SHM
} shmem_type_t;

typedef struct shared_mapping
{
    myst_list_node_t base;
    myst_list_t sharers; // processes sharing this mapping
    void* start_addr;
    size_t length;
    mman_file_handle_t* file_handle;
    size_t offset;
    shmem_type_t type;
} shared_mapping_t;

static myst_list_t _shared_mappings;
static myst_rspinlock_t _shared_mappings_lock;
static myst_fs_t* _posix_shmfs;

static int _add_proc_to_sharers(shared_mapping_t* sm, pid_t pid);

int shmfs_setup()
{
    int ret = 0;

    if (myst_init_ramfs(
            myst_mount_resolve, &_posix_shmfs, MYST_POSIX_SHMFS_DEV_NUM) != 0)
    {
        myst_eprintf("failed initialize the shm file system\n");
        ERAISE(-EINVAL);
    }

    ECHECK(set_overrides_for_special_fs(_posix_shmfs));

    if (mkdir("/dev/shm", 0777) != 0)
    {
        myst_eprintf("cannot create mount point for shmfs\n");
        ERAISE(-EINVAL);
    }

    if (myst_mount(_posix_shmfs, "/", "/dev/shm", false) != 0)
    {
        myst_eprintf("cannot mount shm file system\n");
        ERAISE(-EINVAL);
    }

done:
    return ret;
}

int shmfs_teardown()
{
    if ((*_posix_shmfs->fs_release)(_posix_shmfs) != 0)
    {
        myst_eprintf("failed to release shmfs\n");
        return -1;
    }

    return 0;
}

#ifdef TRACE
static const char* shmem_type_to_string(shmem_type_t mem_type)
{
    switch (mem_type)
    {
        case SHMEM_NONE:
            return "SHMEM_NONE";
        case SHMEM_ANON:
            return "ANON";
        case SHMEM_REG_FILE:
            return "REG_FILE";
        case SHMEM_POSIX_SHM:
            return "POSIX_SHM_FILE";
        default:
            return "UNKNOWN";
    }
}
static void _dump_shared_mappings(char* msg)
{
    if (msg)
        printf("\n%s\n", msg);

    myst_rspin_lock(&_shared_mappings_lock);
    shared_mapping_t* sm = (shared_mapping_t*)_shared_mappings.head;
    if (sm)
    {
        printf("Shared memory mappings: \n");
        printf("==================================== \n");
    }
    else
    {
        printf("No shared mappings.\n");
    }
    while (sm)
    {
        printf(
            "start_addr=%p length=%ld nusers=%ld type=%s\n",
            sm->start_addr,
            sm->type == SHMEM_POSIX_SHM
                ? myst_mman_backing_file_size(sm->file_handle)
                : sm->length,
            sm->sharers.size,
            shmem_type_to_string(sm->type));
        printf("sharer pids: [ ");
        {
            proc_w_count_t* pn = (proc_w_count_t*)sm->sharers.head;
            while (pn)
            {
                printf(" [pid=%d nmaps=%d] ", pn->pid, pn->nmaps);
                pn = (proc_w_count_t*)pn->base.next;
            }
            printf("]\n");
        }

        sm = (shared_mapping_t*)sm->base.next;
        printf("==================================== \n\n");
    }
    myst_rspin_unlock(&_shared_mappings_lock);
}
#endif

static bool _is_posix_shm_mapping(shared_mapping_t* sm)
{
    if (sm && sm->type == SHMEM_POSIX_SHM)
    {
        assert(sm->file_handle->fs == _posix_shmfs);
        return true;
    }
    return false;
}

static int _get_ptr_to_file_data(int fd, void** addr_out)
{
    int ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_fs_t* fs;
    myst_file_t* file;

    ECHECK(myst_fdtable_get_file(fdtable, fd, &fs, &file));
    ECHECK((*fs->fs_file_data_buf)(fs, file, addr_out));

done:
    return ret;
}

bool myst_is_posix_shm_file_handle(int fd, int flags)
{
    if (fd >= 0 && (flags & MAP_SHARED))
    {
        struct stat buf;
        if (myst_syscall_fstat(fd, &buf) == 0 &&
            buf.st_dev == MYST_POSIX_SHMFS_DEV_NUM)
            return true;
    }
    return false;
}

static int _notify_shmfs_active(mman_file_handle_t* file_handle, bool active)
{
    assert(file_handle && _posix_shmfs == file_handle->fs);
    return (*_posix_shmfs->fs_file_mapping_notify)(
        _posix_shmfs, file_handle->file, active);
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

static proc_w_count_t* _lookup_sharers_by_pid(shared_mapping_t* sm, pid_t pid)
{
    proc_w_count_t* pn = (proc_w_count_t*)sm->sharers.head;
    while (pn)
    {
        if (pn->pid == pid)
            return pn;
        pn = (proc_w_count_t*)pn->base.next;
    }
    return NULL;
}

static bool _decr_pid_from_sharers(shared_mapping_t* sm, pid_t pid)
{
    proc_w_count_t* pn = _lookup_sharers_by_pid(sm, pid);
    if (pn)
    {
        if (--pn->nmaps == 0)
        {
            myst_list_remove(&sm->sharers, &pn->base);
            free(pn);
        }
        return true;
    }
    return false;
}

static bool _remove_pid_from_sharers(shared_mapping_t* sm, pid_t pid)
{
    proc_w_count_t* pn = _lookup_sharers_by_pid(sm, pid);
    if (pn)
    {
        myst_list_remove(&sm->sharers, &pn->base);
        free(pn);
        return true;
    }
    return false;
}

static int _add_proc_to_sharers(shared_mapping_t* sm, pid_t pid)
{
    int ret = 0;
    proc_w_count_t* pn = _lookup_sharers_by_pid(sm, pid);

    if (!pn)
    {
        if (!(pn = calloc(1, sizeof(proc_w_count_t))))
        {
            myst_rspin_unlock(&_shared_mappings_lock);
            ERAISE(-ENOMEM);
        }
        pn->pid = pid;
        pn->nmaps = 1;
        myst_list_append(&sm->sharers, &pn->base);
        pn = NULL;
    }
    else
    {
        pn->nmaps++;
    }

done:

    if (pn)
        free(pn);

    return ret;
}

static int _lookup_shmem_map(
    const void* start_addr,
    const size_t len,
    shared_mapping_t** sm_out)
{
    int ret = 0;

    if (sm_out)
        *sm_out = NULL;

    void* end_addr = (char*)start_addr + len;
    shared_mapping_t* sm = (shared_mapping_t*)_shared_mappings.head;
    while (sm)
    {
        size_t rounded_up_sm_length =
            sm->type == SHMEM_POSIX_SHM
                ? myst_mman_backing_file_size(sm->file_handle)
                : sm->length;
        myst_round_up(rounded_up_sm_length, PAGE_SIZE, &rounded_up_sm_length);
        void* sm_end_addr = (char*)sm->start_addr + rounded_up_sm_length;

        bool start_addr_within_range =
            (sm->start_addr <= start_addr && start_addr < sm_end_addr);
        bool end_addr_within_range =
            (sm->start_addr < end_addr && end_addr <= sm_end_addr);

        if (start_addr_within_range && end_addr_within_range)
        {
            *sm_out = sm;
            goto done;
        }
        else if (start_addr_within_range || end_addr_within_range)
        {
            // partial overlap with shared memory region. some address range
            // specified by input params is either before or after this shared
            // memory mapping.
            //           [sssssssssssssssssss]
            // [uuuuuuuuuuuuuuuuu]
            // or
            //           [sssssssssssssssssss]
            //                          [uuuuuuuuuuuuuuuuu]
            MYST_ELOG(
                "Memory range specified by user partially overlaps with a "
                "shared memory region.\naddr=%p length=%ld\n",
                start_addr,
                len);
            myst_panic("Unsupported.\n");
        }
        // else no overlap at all, keep searching
        sm = (shared_mapping_t*)sm->base.next;
    }

done:
    return ret;
}

bool myst_is_address_within_shmem(
    const void* addr,
    const size_t length,
    shared_mapping_t** sm_out)
{
    if (sm_out)
        *sm_out = NULL;
    myst_rspin_lock(&_shared_mappings_lock);
    shared_mapping_t* sm;
    _lookup_shmem_map(addr, length, &sm);
    myst_rspin_unlock(&_shared_mappings_lock);

    if (sm)
    {
        if (sm_out)
            *sm_out = sm;
        return true;
    }

    return false;
}

bool myst_addr_within_process_owned_shmem(
    const void* addr,
    const size_t length,
    pid_t pid)
{
    shared_mapping_t* sm;
    if (!pid)
        pid = myst_getpid();

    if (myst_is_address_within_shmem(addr, length, &sm) &&
        _lookup_sharers_by_pid(sm, pid))
        return true;

    return false;
}

long myst_posix_shm_handle_mmap(
    int fd,
    void* addr,
    size_t length,
    off_t offset,
    int flags)
{
    long ret = -1;
    void* buf_data_addr;
    mman_file_handle_t* file_handle;

#ifdef TRACE
    _dump_shared_mappings("mmap entry");
#endif

    /* addr hint is not supported yet */
    if (addr || !(flags & MAP_SHARED) || offset % PAGE_SIZE)
        ERAISE(-EINVAL);

    // get a file handle
    ECHECK(myst_mman_file_handle_get(fd, &file_handle));

    // get pointer to the start of the data portion of the file
    ECHECK(_get_ptr_to_file_data(fd, &buf_data_addr));

    // check [offset, offset+length] range is within file limits
    {
        size_t backing_file_size = myst_mman_backing_file_size(file_handle);

        void* file_end_addr = (char*)buf_data_addr + backing_file_size;
        void* request_end_addr = (char*)buf_data_addr + offset + length;

        if ((size_t)offset > backing_file_size ||
            request_end_addr > file_end_addr)
            ERAISE(-EINVAL);

        if (offset != 0 && length < backing_file_size)
        {
            MYST_ELOG(
                "\nPOSIX SHM files don't allow non-zero offset or mapping the "
                "file partially.\nActual offset=%ld length=%ld\nExpected "
                "offset=0 length=%ld",
                offset,
                length,
                backing_file_size);
            myst_panic("Unsupported");
        }
    }

    // get or create shared mapping
    myst_rspin_lock(&_shared_mappings_lock);
    shared_mapping_t* sm = (shared_mapping_t*)_shared_mappings.head;

    // Check for existing mapping
    while (sm)
    {
        if (mman_file_handle_eq(sm->file_handle, file_handle))
        {
            assert(sm->start_addr == buf_data_addr);
            ECHECK_LABEL(_add_proc_to_sharers(sm, myst_getpid()), unlock);
            myst_rspin_unlock(&_shared_mappings_lock);
            ret = (long)((int8_t*)sm->start_addr + offset);
            goto done;
        }
        sm = (shared_mapping_t*)sm->base.next;
    }

    // Create a new shared mapping
    shared_mapping_t* new_sm;
    {
        if (!(new_sm = calloc(1, sizeof(shared_mapping_t))))
        {
            myst_rspin_unlock(&_shared_mappings_lock);
            ERAISE(-ENOMEM);
        }
        new_sm->file_handle = file_handle;
        new_sm->start_addr = buf_data_addr;
        new_sm->type = SHMEM_POSIX_SHM;
        // notify fs that mapping is active
        ECHECK_LABEL(_notify_shmfs_active(new_sm->file_handle, true), unlock);
        ECHECK_LABEL(_add_proc_to_sharers(new_sm, myst_getpid()), unlock);

        myst_list_append(&_shared_mappings, &new_sm->base);
        new_sm->file_handle->npages++; // mark file handle active
        ret = (long)((char*)new_sm->start_addr + offset);
        new_sm = NULL;
    }

unlock:
    if (new_sm)
        free(new_sm);

    myst_rspin_unlock(&_shared_mappings_lock);

done:

    // if failed or found existing mapping
    if (file_handle && !file_handle->npages)
    {
        myst_mman_file_handle_put(file_handle);
    }
#ifdef TRACE
    _dump_shared_mappings("mmap exit");
#endif

    return ret;
}

int myst_shmem_register_mapping(
    int fd,
    void* addr,
    size_t length,
    size_t offset)
{
    int ret = 0;
    shared_mapping_t* new_sm = NULL;
    mman_file_handle_t* file_handle = NULL;
    myst_rspin_lock(&_shared_mappings_lock);
    // Create a new shared mapping
    {
        if (!(new_sm = calloc(1, sizeof(shared_mapping_t))))
        {
            myst_rspin_unlock(&_shared_mappings_lock);
            ERAISE(-ENOMEM);
        }
        new_sm->start_addr = addr;
        new_sm->length = length;
        new_sm->type = fd == -1 ? SHMEM_ANON : SHMEM_REG_FILE;
        ECHECK_LABEL(_add_proc_to_sharers(new_sm, myst_getpid()), unlock);
        if (new_sm->type == SHMEM_REG_FILE)
        {
            new_sm->offset = offset;
            ECHECK(myst_mman_file_handle_get(fd, &file_handle));
            new_sm->file_handle = file_handle;
            new_sm->file_handle->npages = 1; // mark as in-use
        }
        myst_list_append(&_shared_mappings, &new_sm->base);
        new_sm = NULL;
    }

unlock:

    if (new_sm)
        free(new_sm);

    if (file_handle && !file_handle->npages)
    {
        myst_mman_file_handle_put(file_handle);
    }

    myst_rspin_unlock(&_shared_mappings_lock);

#ifdef TRACE
    _dump_shared_mappings("regular mmap exit");
#endif

done:
    return ret;
}

static __inline__ size_t _min_size(size_t x, size_t y)
{
    return x < y ? x : y;
}

static int __shm_unmap(shared_mapping_t* sm, void* addr, size_t length)
{
    int ret = 0;
    if (_is_posix_shm_mapping(sm))
    {
        _notify_shmfs_active(sm->file_handle, false);
        myst_mman_file_handle_put(sm->file_handle);
    }
    else
    {
        if (sm->type == SHMEM_REG_FILE)
        {
            size_t file_size = myst_mman_backing_file_size(sm->file_handle);

            if (sm->offset < file_size)
            {
                ECHECK(myst_msync(
                    addr, _min_size(file_size - sm->offset, length), MS_SYNC));
            }
            myst_mman_file_handle_put(sm->file_handle);
        }
        ECHECK(myst_munmap(addr, length));
    }

done:
    return ret;
}

int myst_shmem_handle_munmap(void* addr, size_t length, bool* is_shmem)
{
    int ret = 0;

    if (!is_shmem)
        ERAISE(-EINVAL);

    *is_shmem = false;

    myst_rspin_lock(&_shared_mappings_lock);
    {
        shared_mapping_t* sm;
        // lookup fails for munmaps overlapping partially with a shared memory
        // object
        ECHECK_LABEL(_lookup_shmem_map(addr, length, &sm), unlock);
        if (sm)
        {
            if (sm->start_addr != addr && sm->length != length)
            {
                MYST_ELOG(
                    "Partial munmaps of shared memory are not "
                    "allowed.\nActual: addr=%p length=%ld\nExpected: addr=%p "
                    "length=%ld\n",
                    addr,
                    length,
                    sm->start_addr,
                    sm->length);
                myst_panic("Unsupported.\n");
            }

            *is_shmem = true;
            if (!_decr_pid_from_sharers(sm, myst_getpid()))
            {
                // if pid is not in sharers, process is trying to munmap memory
                // not associated with it
                ERAISE(-EINVAL);
            }
            // For last reference to shared mapping, delete mapping
            if (sm->sharers.size == 0)
            {
                ECHECK_LABEL(__shm_unmap(sm, addr, length), unlock);
                myst_list_remove(&_shared_mappings, &sm->base);
#ifdef TRACE
                _dump_shared_mappings("Shared memory munmap:");
#endif
                free(sm);
            }
        }
    }
unlock:
    myst_rspin_unlock(&_shared_mappings_lock);

done:

    return ret;
}

int myst_posix_shm_handle_release_mappings(pid_t pid)
{
#ifdef TRACE
    printf("pid=%d\n", pid);
    _dump_shared_mappings("At process release entry");
#endif

    myst_rspin_lock(&_shared_mappings_lock);
    {
        shared_mapping_t* sm = (shared_mapping_t*)_shared_mappings.head;
        while (sm)
        {
            if (_remove_pid_from_sharers(sm, pid))
            {
                // For last reference to shared mapping, delete mapping
                if (sm->sharers.size == 0)
                {
                    assert(__shm_unmap(sm, sm->start_addr, sm->length) == 0);
                    myst_list_remove(&_shared_mappings, &sm->base);
                    void* next_sm = sm->base.next;
                    free(sm);
                    sm = next_sm;
                    continue;
                }
            }
            sm = (shared_mapping_t*)sm->base.next;
        }
    }
    myst_rspin_unlock(&_shared_mappings_lock);

#ifdef TRACE
    _dump_shared_mappings("At process release exit");
#endif

    return 0;
}

int myst_posix_shm_share_mappings(pid_t childpid)
{
    int ret = 0;
    pid_t self = myst_getpid();

    myst_rspin_lock(&_shared_mappings_lock);
    {
        shared_mapping_t* sm = (shared_mapping_t*)_shared_mappings.head;
        while (sm)
        {
            proc_w_count_t* pn = _lookup_sharers_by_pid(sm, self);
            if (pn)
                ECHECK(_add_proc_to_sharers(sm, childpid));
            sm = (shared_mapping_t*)sm->base.next;
        }
    }

done:
    myst_rspin_unlock(&_shared_mappings_lock);

    return ret;
}

bool myst_shmem_can_mremap(shared_mapping_t* sm)
{
    assert(sm);
    if ((sm->type == SHMEM_REG_FILE || sm->type == SHMEM_ANON) &&
        sm->sharers.size == 1)
        return true;
    return false;
}

void myst_shmem_mremap_update(
    shared_mapping_t* sm,
    void* new_addr,
    size_t new_size)
{
    assert(sm);
    sm->start_addr = new_addr;
    sm->length = new_size;

    // TODO: if file backed, fdmapping also needs to be updated
}