// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <myst/eraise.h>
#include <myst/file.h>
#include <myst/fs.h>
#include <myst/list.h>
#include <myst/mount.h>
#include <myst/posixshmman.h>
#include <myst/printf.h>
#include <myst/process.h>
#include <myst/ramfs.h>
#include <myst/rspinlock.h>
#include <myst/syscall.h>
#include <stdbool.h>
#include <sys/mman.h>

//#define TRACE

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
    myst_fs_t* fs;
    myst_file_t* file;
    size_t offset;
    shmem_type_t shmem_type;
    void* object; // TODO deprecate
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

static size_t _get_backing_file_size(void* object);
#ifdef TRACE
static void _dump_shared_mappings(char* msg)
{
    if (msg)
        printf("\n%s\n", msg);

    myst_rspin_lock(&_shared_mappings_lock);
    shared_mapping_t* sm = (shared_mapping_t*)_shared_mappings.head;
    if (sm)
    {
        printf("POSIX Shared memory mappings: \n");
        printf("==================================== \n");
    }
    else
    {
        printf("No POSIX shared mappings.\n");
    }
    while (sm)
    {
        printf(
            "start_addr=%p length=%ld nusers=%ld\n",
            sm->start_addr,
            sm->shmem_type == SHMEM_POSIX_SHM
                ? _get_backing_file_size(sm->object)
                : sm->length,
            sm->sharers.size);
        printf("sharer pids: [ ");
        {
            proc_w_count_t* pn = (proc_w_count_t*)sm->sharers.head;
            while (pn)
            {
                printf("pid=%d nmaps=%d", pn->pid, pn->nmaps);
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
    if (sm && sm->shmem_type == SHMEM_POSIX_SHM)
        return true;
    return false;
}

static int _fd_to_inode_and_buf_data(int fd, void** object_out, void** addr_out)
{
    int ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_fs_t* fs;
    myst_file_t* file;

    ECHECK(myst_fdtable_get_file(fdtable, fd, &fs, &file));
    ECHECK((*fs->fs_file_inode_and_buf_data)(fs, file, object_out, addr_out));

done:
    return ret;
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

    // get a dup file handle which the mman will use
    // for msync and /proc/[pid]/maps
    ECHECK(myst_fdtable_get_file(fdtable, fd, &fs, &file));
    ECHECK((*fs->fs_dup)(fs, file, &file_out));

    file_handle->fs = fs;
    file_handle->file = file_out;
    file_handle->inode = _get_inode(fs, file);

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
        file_handle->fs->fs_close(file_handle->fs, file_handle->file);
        free(file_handle);
    }
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

static int _notify_shmfs_active(void* object, bool active)
{
    assert(object);
    return (*_posix_shmfs->fs_file_mapping_notify)(
        _posix_shmfs, object, active);
}

static size_t _get_backing_file_size(void* object)
{
    assert(object);
    size_t size;
    assert((*_posix_shmfs->fs_file_size)(_posix_shmfs, object, &size) == 0);
    return size;
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

static bool _lookup_and_decr_pid_from_sharers(shared_mapping_t* sm, pid_t pid)
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

static bool _lookup_and_remove_pid_from_sharers(shared_mapping_t* sm, pid_t pid)
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
    }
    else
    {
        pn->nmaps++;
    }

done:
    return ret;
}

static int _lookup_shm_by_addr_len(
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
        size_t sm_length = sm->shmem_type == SHMEM_POSIX_SHM
                               ? _get_backing_file_size(sm->object)
                               : sm->length;
        void* sm_end_addr = (char*)sm->start_addr + sm_length;
        bool start_addr_within_range =
            (start_addr >= sm->start_addr && start_addr < sm_end_addr);
        bool end_addr_within_range =
            (end_addr > sm->start_addr && end_addr <= sm_end_addr);

        if (start_addr_within_range && end_addr_within_range)
        {
            *sm_out = sm;
            goto done;
        }
        else if (start_addr_within_range || end_addr_within_range)
        {
            // partial overlap with shared memory file. some address range
            // specified by input params is either before or after this shared
            // memory mapping.
            //           [sssssssssssssssssss]
            // [uuuuuuuuuuuuuuuuu]
            // or
            //           [sssssssssssssssssss]
            //                          [uuuuuuuuuuuuuuuuu]
            ERAISE(-EINVAL);
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
    _lookup_shm_by_addr_len(addr, length, &sm);
    myst_rspin_unlock(&_shared_mappings_lock);

    if (sm)
    {
        if (sm_out)
            *sm_out = sm;
        return true;
    }

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
    void* object_addr;

#ifdef TRACE
    _dump_shared_mappings("in mmap entry");
#endif

    /* addr hint is not supported yet */
    if (addr || !(flags & MAP_SHARED) || offset % PAGE_SIZE)
        ERAISE(-EINVAL);

    // get underlying inode and file buffer pointer
    ECHECK(_fd_to_inode_and_buf_data(fd, &object_addr, &buf_data_addr));

    // check [offset, offset+length] range is within file limits
    {
        size_t backing_file_size = _get_backing_file_size(object_addr);
        void* file_end_addr = (char*)buf_data_addr + backing_file_size;
        void* request_end_addr = (char*)buf_data_addr + offset + length;

        if ((size_t)offset > backing_file_size ||
            request_end_addr > file_end_addr)
            ERAISE(-EINVAL);
    }

    // get or create shared mapping
    myst_rspin_lock(&_shared_mappings_lock);
    shared_mapping_t* sm = (shared_mapping_t*)_shared_mappings.head;

    // Check for existing mapping
    while (sm)
    {
        if (sm->object == object_addr)
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
    {
        shared_mapping_t* new_sm;
        if (!(new_sm = calloc(1, sizeof(shared_mapping_t))))
        {
            myst_rspin_unlock(&_shared_mappings_lock);
            ERAISE(-ENOMEM);
        }
        new_sm->object = object_addr;
        new_sm->start_addr = buf_data_addr;
        new_sm->shmem_type = SHMEM_POSIX_SHM;
        ECHECK_LABEL(_add_proc_to_sharers(new_sm, myst_getpid()), unlock);

        myst_list_append(&_shared_mappings, &new_sm->base);

        // notify fs that mapping is active
        ECHECK_LABEL(_notify_shmfs_active(object_addr, true), unlock);
        ret = (long)((char*)new_sm->start_addr + offset);
    }

unlock:
    myst_rspin_unlock(&_shared_mappings_lock);

done:

#ifdef TRACE
    _dump_shared_mappings("in mmap exit");
#endif

    return ret;
}

int myst_shmem_register_mapping(int fd, void* addr, size_t length)
{
    int ret = 0;

    myst_rspin_lock(&_shared_mappings_lock);
    // Create a new shared mapping
    {
        shared_mapping_t* new_sm;
        if (!(new_sm = calloc(1, sizeof(shared_mapping_t))))
        {
            myst_rspin_unlock(&_shared_mappings_lock);
            ERAISE(-ENOMEM);
        }
        new_sm->start_addr = addr;
        new_sm->length = length;
        new_sm->shmem_type = fd == -1 ? SHMEM_ANON : SHMEM_REG_FILE;
        ECHECK_LABEL(_add_proc_to_sharers(new_sm, myst_getpid()), unlock);

        myst_list_append(&_shared_mappings, &new_sm->base);
    }

unlock:
    myst_rspin_unlock(&_shared_mappings_lock);

#ifdef TRACE
    _dump_shared_mappings("in regular mmap exit");
#endif

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
        ECHECK_LABEL(_lookup_shm_by_addr_len(addr, length, &sm), unlock);
        if (sm)
        {
            *is_shmem = true;
            if (!_lookup_and_decr_pid_from_sharers(sm, myst_getpid()))
            {
                // if pid is not in sharers, process is trying to munmap memory
                // not associated with it
                ERAISE(-EINVAL);
            }
            // For last reference to shared mapping, delete mapping
            if (sm->sharers.size == 0)
            {
                if (_is_posix_shm_mapping(sm))
                    ret = _notify_shmfs_active(sm->object, false);
                else
                {
                    ECHECK_LABEL(myst_msync(addr, length, MS_SYNC), unlock);
                    ECHECK_LABEL(myst_munmap(addr, length), unlock);
                }
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
            if (_lookup_and_remove_pid_from_sharers(sm, pid))
            {
                // For last reference to shared mapping, delete mapping
                if (sm->sharers.size == 0)
                {
                    if (_is_posix_shm_mapping(sm))
                        _notify_shmfs_active(sm->object, false);
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
    if ((sm->shmem_type == SHMEM_REG_FILE || sm->shmem_type == SHMEM_ANON) &&
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
}