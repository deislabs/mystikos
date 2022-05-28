// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <myst/atexit.h>
#include <myst/eraise.h>
#include <myst/fdtable.h>
#include <myst/once.h>
#include <myst/panic.h>
#include <myst/pipedev.h>
#include <myst/process.h>
#include <myst/spinlock.h>
#include <myst/strings.h>
#include <myst/syscall.h>
#include <myst/thread.h>
#include <myst/ttydev.h>

int myst_fdtable_create(myst_fdtable_t** fdtable_out)
{
    int ret = 0;
    myst_fdtable_t* fdtable = NULL;

    if (fdtable_out)
        *fdtable_out = NULL;

    if (!fdtable_out)
        ERAISE(-EINVAL);

    /* allocate the new fdtable for this process */
    if (!(fdtable = calloc(1, sizeof(myst_fdtable_t))))
        ERAISE(-ENOMEM);

    *fdtable_out = fdtable;
    fdtable = NULL;

done:

    if (fdtable)
        free(fdtable);

    return ret;
}

int myst_fdtable_clone(myst_fdtable_t* fdtable, myst_fdtable_t** fdtable_out)
{
    int ret = 0;
    myst_fdtable_t* new_fdtable = NULL;

    if (fdtable_out)
        *fdtable_out = NULL;

    if (!fdtable || !fdtable_out)
        ERAISE(-EINVAL);

    /* allocate the new fdtable */
    if (!(new_fdtable = calloc(1, sizeof(myst_fdtable_t))))
        ERAISE(-ENOMEM);

    myst_spin_lock(&fdtable->lock);
    {
        for (int i = 0; i < MYST_FDTABLE_SIZE; i++)
        {
            const myst_fdtable_entry_t* entry = &fdtable->entries[i];

            if (entry->type != MYST_FDTABLE_TYPE_NONE)
            {
                myst_fdtable_entry_t* new_entry = &new_fdtable->entries[i];
                myst_fdops_t* fdops = entry->device;
                void* object;
                long r;
                int fdflags = 0;

                /* Save the file descriptor flags (for pipes only) */
                if (entry->type != MYST_FDTABLE_TYPE_NONE)
                {
                    fdflags =
                        (*fdops->fd_fcntl)(fdops, entry->object, F_GETFD, 0);
                }

                /* Duplicate the object */
                if ((r = (*fdops->fd_dup)(fdops, entry->object, &object)) != 0)
                {
                    myst_spin_unlock(&fdtable->lock);
                    ERAISE(r);
                }

                /* Propagate the file descriptor flags (for pipes only) */
                if (entry->type != MYST_FDTABLE_TYPE_NONE && fdflags >= 0)
                    (*fdops->fd_fcntl)(fdops, object, F_SETFD, fdflags);

                new_entry->type = entry->type;
                new_entry->device = entry->device;
                new_entry->object = object;
            }
        }
    }
    myst_spin_unlock(&fdtable->lock);

    *fdtable_out = new_fdtable;
    new_fdtable = NULL;

done:

    if (new_fdtable)
        free(new_fdtable);

    return ret;
}

int myst_fdtable_cloexec(myst_fdtable_t* fdtable)
{
    int ret = 0;

    if (!fdtable)
        ERAISE(-EINVAL);

    myst_spin_lock(&fdtable->lock);
    {
        /* close any file descriptors with FD_CLOEXEC flag */
        for (int i = 0; i < MYST_FDTABLE_SIZE; i++)
        {
            myst_fdtable_entry_t* entry = &fdtable->entries[i];

            if (entry->type != MYST_FDTABLE_TYPE_NONE)
            {
                myst_fdops_t* fdops = entry->device;
                int r = (*fdops->fd_fcntl)(fdops, entry->object, F_GETFD, 0);

                if (r < 0)
                {
                    myst_spin_unlock(&fdtable->lock);
                    ERAISE(r);
                }

                if ((r & FD_CLOEXEC))
                {
                    (*fdops->fd_close)(fdops, entry->object);

                    if (entry->type == MYST_FDTABLE_TYPE_FILE)
                    {
                        myst_remove_fd_link(i);
                    }

                    memset(entry, 0, sizeof(myst_fdtable_entry_t));
                }
            }
        }
    }
    myst_spin_unlock(&fdtable->lock);

done:

    return ret;
}

int myst_fdtable_free(myst_fdtable_t* fdtable)
{
    int ret = 0;

    if (!fdtable)
        ERAISE(-EINVAL);

    /* Close all objects */
    for (int i = 0; i < MYST_FDTABLE_SIZE; i++)
    {
        myst_fdtable_entry_t* entry = &fdtable->entries[i];

        if (entry->type != MYST_FDTABLE_TYPE_NONE)
        {
            myst_fdops_t* fdops = entry->device;
            (*fdops->fd_close)(fdops, entry->object);

            if (entry->type == MYST_FDTABLE_TYPE_FILE)
            {
                myst_remove_fd_link(i);
            }

            memset(entry, 0, sizeof(myst_fdtable_entry_t));
        }
    }

    /* Files are released by ramfs */
    memset(fdtable, 0, sizeof(myst_fdtable_t));
    free(fdtable);

done:
    return ret;
}

int myst_fdtable_interrupt(myst_fdtable_t* fdtable)
{
    int ret = 0;

    if (!fdtable)
        ERAISE(-EINVAL);

    /* Close all objects */
    for (int i = 0; i < MYST_FDTABLE_SIZE; i++)
    {
        myst_fdtable_entry_t* entry = &fdtable->entries[i];

        if (entry->type == MYST_FDTABLE_TYPE_PIPE)
        {
            myst_fdops_t* fdops = entry->device;
            (*fdops->fd_interrupt)(fdops, entry->object);
        }
    }

done:
    return ret;
}

int myst_fdtable_assign(
    myst_fdtable_t* fdtable,
    myst_fdtable_type_t type,
    void* device,
    void* object)
{
    int ret = 0;

    if (!fdtable || !object)
        ERAISE(-EINVAL);

    myst_spin_lock(&fdtable->lock);
    {
        /* Use the first available entry */
        for (int i = 0; i < MYST_FDTABLE_SIZE; i++)
        {
            myst_fdtable_entry_t* entry = &fdtable->entries[i];

            if (entry->type == MYST_FDTABLE_TYPE_NONE)
            {
                entry->type = type;
                entry->device = device;
                entry->object = object;
                ret = i;
                myst_spin_unlock(&fdtable->lock);
                goto done;
            }
        }
    }
    myst_spin_unlock(&fdtable->lock);

    ERAISE(-EMFILE);

done:

    return ret;
}

int myst_fdtable_dup(
    myst_fdtable_t* fdtable,
    myst_dup_type_t duptype,
    int oldfd,
    int newfd,
    int flags)
{
    int ret = 0;
    bool locked = false;
    bool use_next_available_fd = false;
    bool set_cloexec = false;
    size_t start_fd = 0;

    if (!fdtable)
        ERAISE(-EINVAL);

    if (!myst_valid_fd(oldfd))
        ERAISE(-EINVAL);

    switch (duptype)
    {
        case MYST_DUP:
        {
            if (newfd != -1 || flags != -1)
                ERAISE(-EINVAL);

            use_next_available_fd = true;
            break;
        }
        case MYST_DUP2:
        {
            if (!myst_valid_fd(newfd) || flags != -1)
                ERAISE(-EINVAL);

            break;
        }
        case MYST_DUP3:
        {
            if (!myst_valid_fd(newfd) || oldfd == newfd)
                ERAISE(-EINVAL);

            if (flags != O_CLOEXEC && flags != 0)
                ERAISE(-EINVAL);

            set_cloexec = true;
            break;
        }
        case MYST_DUPFD:
        {
            if (!myst_valid_fd(newfd))
                ERAISE(-EINVAL);

            use_next_available_fd = true;
            start_fd = newfd;
            break;
        }
        case MYST_DUPFD_CLOEXEC:
        {
            if (!myst_valid_fd(newfd))
                ERAISE(-EINVAL);

            flags = O_CLOEXEC;
            use_next_available_fd = true;
            start_fd = newfd;
            set_cloexec = true;
            break;
        }
    }

    myst_spin_lock(&fdtable->lock);
    locked = true;

    {
        myst_fdtable_entry_t* old = &fdtable->entries[oldfd];
        myst_fdtable_entry_t* new = NULL;
        myst_fdops_t* old_fdops = old->device;
        void* newobj;
        int r;

        if (old->type == MYST_FDTABLE_TYPE_NONE)
            ERAISE(-EBADF);

        if (newfd == oldfd) /* dup2() */
        {
            /* sucessful no-op case */
            ret = newfd;
            goto done;
        }

        if (use_next_available_fd)
        {
            /* find the first free file descriptor */
            for (size_t i = start_fd; i < MYST_COUNTOF(fdtable->entries); i++)
            {
                myst_fdtable_entry_t* p = &fdtable->entries[i];

                if (p->type == MYST_FDTABLE_TYPE_NONE)
                {
                    new = p;
                    newfd = i;
                    break;
                }
            }

            if (!new)
                ERAISE(-EMFILE);
        }
        else
        {
            new = &fdtable->entries[newfd];

            /* if new entry is not empty, close the descriptor */
            if (new->type != MYST_FDTABLE_TYPE_NONE)
            {
                myst_fdops_t* new_fdops = new->device;
                (new_fdops->fd_close)(new->device, new->object);

                if (new->type == MYST_FDTABLE_TYPE_FILE)
                {
                    myst_remove_fd_link(newfd);
                }
            }
        }

        /* dup the old object */
        if ((r = (old_fdops->fd_dup)(old->device, old->object, &newobj)) != 0)
            ERAISE(r);

        if (set_cloexec && flags == O_CLOEXEC)
            (*old_fdops->fd_fcntl)(old_fdops, newobj, F_SETFD, FD_CLOEXEC);

        new->type = old->type;
        new->device = old->device;
        new->object = newobj;

        // add /proc/self/fd/[fd] entry only for files
        // ATTN: update once pipes can be accessed by pathnames, GH #46
        if (newfd != oldfd && new->type == MYST_FDTABLE_TYPE_FILE)
        {
            myst_fs_t* newfs = (myst_fs_t*)new->device;
            if ((ret = myst_add_fd_link(newfs, new->object, newfd)) < 0)
            {
                myst_fdtable_remove(fdtable, newfd);
                (*newfs->fs_close)(newfs, new->object);
                ERAISE(ret);
            }
        }

        ret = newfd;
    }

done:

    if (locked)
        myst_spin_unlock(&fdtable->lock);

    return ret;
}

int myst_fdtable_remove(myst_fdtable_t* fdtable, int fd)
{
    int ret = 0;

    if (!fdtable)
        ERAISE(-EINVAL);

    if (fd < 0 || fd >= MYST_FDTABLE_SIZE)
        ERAISE(-EINVAL);

    myst_spin_lock(&fdtable->lock);
    memset(&fdtable->entries[fd], 0, sizeof(myst_fdtable_entry_t));
    myst_spin_unlock(&fdtable->lock);

done:
    return ret;
}

int myst_fdtable_get(
    myst_fdtable_t* fdtable,
    int fd,
    myst_fdtable_type_t type,
    void** device,
    void** object)
{
    int ret = 0;

    if (!fdtable || !device || !object)
        ERAISE(-EINVAL);

    if (!(fd >= 0 && fd < MYST_FDTABLE_SIZE))
        ERAISE(-EBADF);

    if (type == MYST_FDTABLE_TYPE_NONE)
        ERAISE(-EINVAL);

    myst_spin_lock(&fdtable->lock);
    {
        myst_fdtable_entry_t* entry = &fdtable->entries[fd];

        if (entry->type != type || !(entry->object && entry->device))
        {
            myst_fdtable_type_t actual_type = entry->type;
            myst_spin_unlock(&fdtable->lock);

            // If the client gave us a handle that is not a socket we need to
            // return ENOTSOCK. If the socket has been closed or not used then
            // we return EBADF
            if ((type == MYST_FDTABLE_TYPE_SOCK) &&
                (actual_type != MYST_FDTABLE_TYPE_SOCK) &&
                (actual_type != MYST_FDTABLE_TYPE_NONE))
                ERAISE(-ENOTSOCK);
            else
                ERAISE(-EBADF);
        }

        *device = entry->device;
        *object = entry->object;
    }
    myst_spin_unlock(&fdtable->lock);

done:

    return ret;
}

int myst_fdtable_get_any(
    myst_fdtable_t* fdtable,
    int fd,
    myst_fdtable_type_t* type,
    void** device,
    void** object)
{
    int ret = 0;

    if (type)
        *type = MYST_FDTABLE_TYPE_NONE;

    if (!fdtable || !type || !device || !object)
        ERAISE(-EINVAL);

    if (!(fd >= 0 && fd < MYST_FDTABLE_SIZE))
        ERAISE(-EBADF);

    myst_spin_lock(&fdtable->lock);
    {
        myst_fdtable_entry_t* entry = &fdtable->entries[fd];

        if (entry->type == MYST_FDTABLE_TYPE_NONE)
        {
            myst_spin_unlock(&fdtable->lock);
            ERAISE(-EBADF);
        }

        *type = entry->type;
        *device = entry->device;
        *object = entry->object;
    }
    myst_spin_unlock(&fdtable->lock);

done:

    return ret;
}

myst_fdtable_t* myst_fdtable_current(void)
{
    myst_process_t* process = myst_process_self();
    myst_assume(process->fdtable);
    return process->fdtable;
}

static const char* _type_name(myst_fdtable_type_t type)
{
    switch (type)
    {
        case MYST_FDTABLE_TYPE_TTY:
            return "tty";
        case MYST_FDTABLE_TYPE_FILE:
            return "file";
        case MYST_FDTABLE_TYPE_PIPE:
            return "pipe";
        case MYST_FDTABLE_TYPE_SOCK:
            return "sock";
        case MYST_FDTABLE_TYPE_EPOLL:
            return "epoll";
        case MYST_FDTABLE_TYPE_INOTIFY:
            return "inotify";
        case MYST_FDTABLE_TYPE_EVENTFD:
            return "eventfd";
        case MYST_FDTABLE_TYPE_NONE:
            return "none";
    }

    return "none";
}

int myst_fdtable_list(const myst_fdtable_t* fdtable)
{
    int ret = 0;
    struct locals
    {
        char linkpath[PATH_MAX];
        char buf[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!fdtable)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    for (int i = 0; i < MYST_FDTABLE_SIZE; i++)
    {
        const myst_fdtable_entry_t* entry = &fdtable->entries[i];

        if (entry->type != MYST_FDTABLE_TYPE_NONE)
        {
            pid_t pid = myst_getpid();
            ssize_t m;

            printf("%d: %s", i, _type_name(entry->type));

            if (entry->type == MYST_FDTABLE_TYPE_FILE)
            {
                const size_t n = sizeof(locals->linkpath);
                if (snprintf(locals->linkpath, n, "/proc/%d/fd/%d", pid, i) >=
                    (int)n)
                {
                    ERAISE(-ENAMETOOLONG);
                }

                if ((m = myst_syscall_readlink(
                         locals->linkpath, locals->buf, sizeof(locals->buf))) <
                    0)
                {
                    ERAISE(-ENAMETOOLONG);
                }
                printf(" (%s)", locals->buf);
            }

            printf("\n");
        }
    }

    printf("\n");

done:

    if (locals)
        free(locals);

    return ret;
}

long myst_fdtable_sync(myst_fdtable_t* fdtable)
{
    long ret = 0;
    bool locked = false;

    if (!fdtable)
        ERAISE(-EINVAL);

    myst_spin_lock(&fdtable->lock);
    locked = true;

    {
        for (int i = 0; i < MYST_FDTABLE_SIZE; i++)
        {
            const myst_fdtable_entry_t* entry = &fdtable->entries[i];

            if (entry->type == MYST_FDTABLE_TYPE_FILE)
            {
                myst_fs_t* fs = entry->device;
                myst_file_t* file = entry->object;
                ECHECK(fs->fs_fsync(fs, file));
            }
        }
    }

done:

    if (locked)
        myst_spin_unlock(&fdtable->lock);

    return ret;
}

ssize_t myst_fdtable_count(const myst_fdtable_t* fdtable)
{
    ssize_t ret = 0;
    ssize_t count = 0;

    if (!fdtable)
        ERAISE(-EINVAL);

    myst_spin_lock(&((myst_fdtable_t*)fdtable)->lock);
    {
        for (int i = 0; i < MYST_FDTABLE_SIZE; i++)
        {
            const myst_fdtable_entry_t* entry = &fdtable->entries[i];

            if (entry->type == MYST_FDTABLE_TYPE_NONE)
                count++;
        }
    }
    myst_spin_unlock(&((myst_fdtable_t*)fdtable)->lock);

    ret = count;

done:
    return ret;
}

int myst_fdtable_update_sock_entry(
    myst_fdtable_t* fdtable,
    int fd,
    myst_sockdev_t* device,
    myst_sock_t* new_sock)
{
    int ret = 0;

    if (!fdtable || !device || !new_sock)
        ERAISE(-EINVAL);

    if (!(fd >= 0 && fd < MYST_FDTABLE_SIZE))
        ERAISE(-EBADF);

    myst_spin_lock(&fdtable->lock);
    {
        myst_fdtable_entry_t* entry = &fdtable->entries[fd];

        if (entry->type != MYST_FDTABLE_TYPE_SOCK ||
            !(entry->device && entry->object))
        {
            myst_spin_unlock(&fdtable->lock);
            ERAISE(-ENOTSOCK);
        }

        entry->device = device;
        entry->object = new_sock;
    }
    myst_spin_unlock(&fdtable->lock);

done:

    return ret;
}
