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
#include <myst/spinlock.h>
#include <myst/strings.h>
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

                if ((r = (*fdops->fd_dup)(fdops, entry->object, &object)) != 0)
                {
                    myst_spin_unlock(&fdtable->lock);
                    ERAISE(r);
                }

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
            ERAISE(-ENOENT);

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
        ERAISE(-EINVAL);

    if (type == MYST_FDTABLE_TYPE_NONE)
        ERAISE(-EINVAL);

    myst_spin_lock(&fdtable->lock);
    {
        myst_fdtable_entry_t* entry = &fdtable->entries[fd];

        if (entry->type != type || !(entry->object && entry->device))
        {
            myst_spin_unlock(&fdtable->lock);
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
            ERAISE(-ENOENT);
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
    myst_thread_t* thread = myst_thread_self();
    myst_assume(thread->fdtable);
    return thread->fdtable;
}
