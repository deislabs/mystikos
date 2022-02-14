#include <myst/eraise.h>
#include <myst/fs.h>
#include <myst/list.h>
#include <myst/mmanutils.h>
#include <myst/process.h>
#include <myst/spinlock.h>
#include <myst/syscall.h>
#include <stdbool.h>
#include <sys/mman.h>

//#define TRACE

typedef struct proc_and_fd
{
    myst_list_node_t base;
    pid_t pid;
} proc_and_fd_t;

typedef struct shared_mapping
{
    myst_list_node_t base;
    char path[PATH_MAX];
    off_t offset;
    void* object;
    void* addr;
    size_t length;
    int nusers;
    myst_list_t sharers;
} shared_mapping_t;

static myst_list_t _shared_mappings;
static myst_spinlock_t _shared_mappings_lock;
static myst_fs_t* _posix_shmfs;

#ifdef TRACE
static void _dump_shared_mappings(char* msg)
{
    if (msg)
        printf("\n%s\n", msg);

    myst_spin_lock(&_shared_mappings_lock);
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
            "addr=%p length=%ld nusers=%ld\n",
            sm->addr,
            sm->length,
            sm->sharers.size);
        printf("sharer pids: [ ");
        {
            proc_and_fd_t* pfd = (proc_and_fd_t*)sm->sharers.head;
            while (pfd)
            {
                printf("%d ", pfd->pid);
                pfd = (proc_and_fd_t*)pfd->base.next;
            }
            printf("]\n");
        }

        sm = (shared_mapping_t*)sm->base.next;
        printf("==================================== \n\n");
    }
    myst_spin_unlock(&_shared_mappings_lock);
}
#endif

static int _fd_to_file_data_ptr(int fd, void** object_out, void** addr_out)
{
    int ret = 0;
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_fs_t* fs;
    myst_file_t* file;

    ECHECK(myst_fdtable_get_file(fdtable, fd, &fs, &file));
    ECHECK((*fs->fs_file_data_ptr)(fs, file, object_out, addr_out));

    if (!_posix_shmfs)
        _posix_shmfs = fs;

done:
    return ret;
}

bool myst_is_posix_shm_request(int fd, int flags)
{
    if (fd >= 0 && (flags & MAP_SHARED))
    {
        struct stat buf;
        if (myst_syscall_fstat(fd, &buf) == 0 && buf.st_dev == 9)
            return true;
    }
    return false;
}

static int _notify_shmfs_active(void* object, bool active)
{
    return (*_posix_shmfs->fs_file_mapping_notify)(
        _posix_shmfs, object, active);
}

static proc_and_fd_t* _lookup_sharers_by_pid(shared_mapping_t* sm, pid_t pid)
{
    proc_and_fd_t* pfd = (proc_and_fd_t*)sm->sharers.head;
    while (pfd)
    {
        if (pfd->pid == pid)
            return pfd;
        pfd = (proc_and_fd_t*)pfd->base.next;
    }
    return NULL;
}

static bool _lookup_and_remove_pid_from_sharers(shared_mapping_t* sm, pid_t pid)
{
    proc_and_fd_t* pfd = _lookup_sharers_by_pid(sm, pid);
    if (pfd)
    {
        myst_list_remove(&sm->sharers, &pfd->base);
        free(pfd);
        return true;
    }
    return false;
}

static int _add_proc_to_sharers(shared_mapping_t* sm, pid_t pid)
{
    int ret = 0;
    proc_and_fd_t* pfd = _lookup_sharers_by_pid(sm, pid);

    if (!pfd)
    {
        if (!(pfd = calloc(1, sizeof(proc_and_fd_t))))
        {
            myst_spin_unlock(&_shared_mappings_lock);
            ERAISE(-ENOMEM);
        }
        pfd->pid = pid;
        myst_list_append(&sm->sharers, &pfd->base);
    }

done:
    return ret;
}

static shared_mapping_t* _lookup_shm_by_addr_len(
    const void* addr,
    const size_t len)
{
    shared_mapping_t* sm = (shared_mapping_t*)_shared_mappings.head;
    while (sm)
    {
        if (addr == sm->addr && len == sm->length)
        {
            return sm;
        }
        sm = (shared_mapping_t*)sm->base.next;
    }
    return NULL;
}

bool myst_is_address_within_shmem(const void* addr, const size_t length)
{
    myst_spin_lock(&_shared_mappings_lock);
    shared_mapping_t* sm = _lookup_shm_by_addr_len(addr, length);
    myst_spin_unlock(&_shared_mappings_lock);

    if (sm)
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
    void* file_addr;
    void* object_addr;

#ifdef TRACE
    _dump_shared_mappings("in mmap entry");
#endif

    /* addr hint is not supported yet */
    if (addr || !(flags & MAP_SHARED))
        ERAISE(-EINVAL);

    // get underlying inode and file buffer pointer
    ECHECK(_fd_to_file_data_ptr(fd, &object_addr, &file_addr));

    // get or create shared mapping
    myst_spin_lock(&_shared_mappings_lock);
    shared_mapping_t* sm = (shared_mapping_t*)_shared_mappings.head;
    // Check for existing mapping
    while (sm)
    {
        // TODO: Handle different offset or length
        if (sm->object == object_addr && sm->addr == file_addr &&
            offset == sm->offset && length == sm->length)
        {
            ECHECK(_add_proc_to_sharers(sm, myst_getpid()));
            myst_spin_unlock(&_shared_mappings_lock);
            ret = (long)sm->addr;
            goto done;
        }
        sm = (shared_mapping_t*)sm->base.next;
    }

    // Create a new shared mapping
    {
        shared_mapping_t* new_sm;
        if (!(new_sm = calloc(1, sizeof(shared_mapping_t))))
        {
            myst_spin_unlock(&_shared_mappings_lock);
            ERAISE(-ENOMEM);
        }
        new_sm->object = object_addr;
        new_sm->addr = file_addr;
        new_sm->offset = offset;
        new_sm->length = length;
        ECHECK(_add_proc_to_sharers(new_sm, myst_getpid()));

        myst_list_append(&_shared_mappings, &new_sm->base);

        // notify fs that mapping is active
        ECHECK(_notify_shmfs_active(object_addr, true));
        ret = (long)new_sm->addr;
    }

    myst_spin_unlock(&_shared_mappings_lock);

done:

#ifdef TRACE
    _dump_shared_mappings("in mmap exit");
#endif

    return ret;
}

int myst_posix_shm_handle_munmap(void* addr, size_t length, bool* is_posix_shm)
{
    int ret = 0;

    if (!is_posix_shm)
        ERAISE(-EINVAL);

    *is_posix_shm = false;

    myst_spin_lock(&_shared_mappings_lock);
    {
        shared_mapping_t* sm = _lookup_shm_by_addr_len(addr, length);
        if (sm)
        {
            *is_posix_shm = true;
            assert(_lookup_and_remove_pid_from_sharers(sm, myst_getpid()));
            // For last reference to shared mapping, delete mapping
            if (sm->sharers.size == 0)
            {
                ret = _notify_shmfs_active(sm->object, false);
                myst_list_remove(&_shared_mappings, &sm->base);
                free(sm);
            }
        }
    }
    myst_spin_unlock(&_shared_mappings_lock);

done:

#ifdef TRACE
    _dump_shared_mappings("At munmap hook exit");
#endif
    return ret;
}

int myst_posix_shm_handle_release_mappings(pid_t pid)
{
#ifdef TRACE
    _dump_shared_mappings("At process release entry");
#endif

    myst_spin_lock(&_shared_mappings_lock);
    {
        shared_mapping_t* sm = (shared_mapping_t*)_shared_mappings.head;
        while (sm)
        {
            if (_lookup_and_remove_pid_from_sharers(sm, pid))
            {
                // For last reference to shared mapping, delete mapping
                if (sm->sharers.size == 0)
                {
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
    myst_spin_unlock(&_shared_mappings_lock);

#ifdef TRACE
    _dump_shared_mappings("At process release exit");
#endif

    return 0;
}
