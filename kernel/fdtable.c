// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libos/atexit.h>
#include <libos/eraise.h>
#include <libos/fdtable.h>
#include <libos/once.h>
#include <libos/panic.h>
#include <libos/pipedev.h>
#include <libos/spinlock.h>
#include <libos/strings.h>
#include <libos/thread.h>
#include <libos/ttydev.h>

static bool _valid_fd(int fd)
{
    return fd >= 0 && fd < FDTABLE_SIZE;
}

int libos_fdtable_create(libos_fdtable_t** fdtable_out)
{
    int ret = 0;
    libos_fdtable_t* fdtable = NULL;

    if (fdtable_out)
        *fdtable_out = NULL;

    if (!fdtable_out)
        ERAISE(-EINVAL);

    /* allocate the new fdtable for this process */
    if (!(fdtable = calloc(1, sizeof(libos_fdtable_t))))
        ERAISE(-ENOMEM);

    *fdtable_out = fdtable;
    fdtable = NULL;

done:

    if (fdtable)
        free(fdtable);

    return ret;
}

int libos_fdtable_clone(libos_fdtable_t* fdtable, libos_fdtable_t** fdtable_out)
{
    int ret = 0;
    libos_fdtable_t* new_fdtable = NULL;

    if (fdtable_out)
        *fdtable_out = NULL;

    if (!fdtable || !fdtable_out)
        ERAISE(-EINVAL);

    /* allocate the new fdtable */
    if (!(new_fdtable = calloc(1, sizeof(libos_fdtable_t))))
        ERAISE(-ENOMEM);

    libos_spin_lock(&fdtable->lock);
    {
        for (int i = 0; i < FDTABLE_SIZE; i++)
        {
            const libos_fdtable_entry_t* entry = &fdtable->entries[i];

            if (entry->type != LIBOS_FDTABLE_TYPE_NONE)
            {
                libos_fdtable_entry_t* new_entry = &new_fdtable->entries[i];
                libos_fdops_t* fdops = entry->device;
                void* object;
                long r;

                if ((r = (*fdops->fd_dup)(fdops, entry->object, &object)) != 0)
                {
                    libos_spin_unlock(&fdtable->lock);
                    ERAISE(r);
                }

                new_entry->type = entry->type;
                new_entry->device = entry->device;
                new_entry->object = object;
            }
        }
    }
    libos_spin_unlock(&fdtable->lock);

    *fdtable_out = new_fdtable;
    new_fdtable = NULL;

done:

    if (new_fdtable)
        free(new_fdtable);

    return ret;
}

int libos_fdtable_cloexec(libos_fdtable_t* fdtable)
{
    int ret = 0;

    if (!fdtable)
        ERAISE(-EINVAL);

    libos_spin_lock(&fdtable->lock);
    {
        /* close any file descriptors with FD_CLOEXEC flag */
        for (int i = 0; i < FDTABLE_SIZE; i++)
        {
            libos_fdtable_entry_t* entry = &fdtable->entries[i];

            if (entry->type != LIBOS_FDTABLE_TYPE_NONE)
            {
                libos_fdops_t* fdops = entry->device;
                int r = (*fdops->fd_fcntl)(fdops, entry->object, F_GETFD, 0);

                if (r < 0)
                {
                    libos_spin_unlock(&fdtable->lock);
                    ERAISE(r);
                }

                if ((r & FD_CLOEXEC))
                {
                    (*fdops->fd_close)(fdops, entry->object);

                    if (entry->type == LIBOS_FDTABLE_TYPE_FILE)
                    {
                        libos_fs_t* fs = entry->device;
                        libos_file_t* file = entry->object;
                        libos_remove_fd_link(fs, file, i);
                    }

                    memset(entry, 0, sizeof(libos_fdtable_entry_t));
                }
            }
        }
    }
    libos_spin_unlock(&fdtable->lock);

done:
    return ret;
}

int libos_fdtable_free(libos_fdtable_t* fdtable)
{
    int ret = 0;

    if (!fdtable)
        ERAISE(-EINVAL);

    /* Close all objects */
    for (int i = 0; i < FDTABLE_SIZE; i++)
    {
        libos_fdtable_entry_t* entry = &fdtable->entries[i];

        if (entry->type != LIBOS_FDTABLE_TYPE_NONE)
        {
            libos_fdops_t* fdops = entry->device;
            (*fdops->fd_close)(fdops, entry->object);

            if (entry->type == LIBOS_FDTABLE_TYPE_FILE)
            {
                libos_fs_t* fs = entry->device;
                libos_file_t* file = entry->object;
                libos_remove_fd_link(fs, file, i);
            }

            memset(entry, 0, sizeof(libos_fdtable_entry_t));
        }
    }

    /* Files are released by ramfs */
    memset(fdtable, 0, sizeof(libos_fdtable_t));
    free(fdtable);

done:
    return ret;
}

int libos_fdtable_assign(
    libos_fdtable_t* fdtable,
    libos_fdtable_type_t type,
    void* device,
    void* object)
{
    int ret = 0;

    if (!fdtable || !object)
        ERAISE(-EINVAL);

    libos_spin_lock(&fdtable->lock);
    {
        /* Use the first available entry */
        for (int i = 0; i < FDTABLE_SIZE; i++)
        {
            libos_fdtable_entry_t* entry = &fdtable->entries[i];

            if (entry->type == LIBOS_FDTABLE_TYPE_NONE)
            {
                entry->type = type;
                entry->device = device;
                entry->object = object;
                ret = i;
                libos_spin_unlock(&fdtable->lock);
                goto done;
            }
        }
    }
    libos_spin_unlock(&fdtable->lock);

    ERAISE(-EMFILE);

done:

    return ret;
}

int libos_fdtable_dup(
    libos_fdtable_t* fdtable,
    libos_dup_type_t duptype,
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

    if (!_valid_fd(oldfd))
        ERAISE(-EINVAL);

    switch (duptype)
    {
        case LIBOS_DUP:
        {
            if (newfd != -1 || flags != -1)
                ERAISE(-EINVAL);

            use_next_available_fd = true;
            break;
        }
        case LIBOS_DUP2:
        {
            if (!_valid_fd(newfd) || flags != -1)
                ERAISE(-EINVAL);

            break;
        }
        case LIBOS_DUP3:
        {
            if (!_valid_fd(newfd) || oldfd == newfd)
                ERAISE(-EINVAL);

            if (flags != O_CLOEXEC && flags != 0)
                ERAISE(-EINVAL);

            set_cloexec = true;
            break;
        }
        case LIBOS_DUPFD:
        {
            if (!_valid_fd(newfd))
                ERAISE(-EINVAL);

            use_next_available_fd = true;
            start_fd = newfd;
            break;
        }
        case LIBOS_DUPFD_CLOEXEC:
        {
            if (!_valid_fd(newfd))
                ERAISE(-EINVAL);

            flags = O_CLOEXEC;
            use_next_available_fd = true;
            start_fd = newfd;
            set_cloexec = true;
            break;
        }
    }

    libos_spin_lock(&fdtable->lock);
    locked = true;

    {
        libos_fdtable_entry_t* old = &fdtable->entries[oldfd];
        libos_fdtable_entry_t* new = NULL;
        libos_fdops_t* old_fdops = old->device;
        void* newobj;
        int r;

        if (old->type == LIBOS_FDTABLE_TYPE_NONE)
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
            for (size_t i = start_fd; i < LIBOS_COUNTOF(fdtable->entries); i++)
            {
                libos_fdtable_entry_t* p = &fdtable->entries[i];

                if (p->type == LIBOS_FDTABLE_TYPE_NONE)
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
            if (new->type != LIBOS_FDTABLE_TYPE_NONE)
            {
                libos_fdops_t* new_fdops = new->device;
                (new_fdops->fd_close)(new->device, new->object);

                if (new->type == LIBOS_FDTABLE_TYPE_FILE)
                {
                    libos_fs_t* fs = new->device;
                    libos_file_t* file = new->object;
                    libos_remove_fd_link(fs, file, newfd);
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
        libos_spin_unlock(&fdtable->lock);

    return ret;
}

int libos_fdtable_remove(libos_fdtable_t* fdtable, int fd)
{
    int ret = 0;

    if (!fdtable)
        ERAISE(-EINVAL);

    if (fd < 0 || fd >= FDTABLE_SIZE)
        ERAISE(-EINVAL);

    libos_spin_lock(&fdtable->lock);
    memset(&fdtable->entries[fd], 0, sizeof(libos_fdtable_entry_t));
    libos_spin_unlock(&fdtable->lock);

done:
    return ret;
}

int libos_fdtable_get(
    libos_fdtable_t* fdtable,
    int fd,
    libos_fdtable_type_t type,
    void** device,
    void** object)
{
    int ret = 0;

    if (!fdtable || !device || !object)
        ERAISE(-EINVAL);

    if (!(fd >= 0 && fd < FDTABLE_SIZE))
        ERAISE(-EINVAL);

    if (type == LIBOS_FDTABLE_TYPE_NONE)
        ERAISE(-EINVAL);

    libos_spin_lock(&fdtable->lock);
    {
        libos_fdtable_entry_t* entry = &fdtable->entries[fd];

        if (entry->type != type || !(entry->object && entry->device))
        {
            libos_spin_unlock(&fdtable->lock);
            ERAISE(-ENOENT);
        }

        *device = entry->device;
        *object = entry->object;
    }
    libos_spin_unlock(&fdtable->lock);

done:

    return ret;
}

int libos_fdtable_get_any(
    libos_fdtable_t* fdtable,
    int fd,
    libos_fdtable_type_t* type,
    void** device,
    void** object)
{
    int ret = 0;

    if (type)
        *type = LIBOS_FDTABLE_TYPE_NONE;

    if (!fdtable || !type || !device || !object)
        ERAISE(-EINVAL);

    if (!(fd >= 0 && fd < FDTABLE_SIZE))
        ERAISE(-EINVAL);

    libos_spin_lock(&fdtable->lock);
    {
        libos_fdtable_entry_t* entry = &fdtable->entries[fd];

        if (entry->type == LIBOS_FDTABLE_TYPE_NONE)
        {
            libos_spin_unlock(&fdtable->lock);
            ERAISE(-ENOENT);
        }

        *type = entry->type;
        *device = entry->device;
        *object = entry->object;
    }
    libos_spin_unlock(&fdtable->lock);

done:

    return ret;
}

libos_fdtable_t* libos_fdtable_current(void)
{
    libos_thread_t* thread = libos_thread_self();
    libos_assume(thread->fdtable);
    return thread->fdtable;
}
