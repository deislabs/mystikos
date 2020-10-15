#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libos/atexit.h>
#include <libos/eraise.h>
#include <libos/fdtable.h>
#include <libos/once.h>
#include <libos/pipedev.h>
#include <libos/spinlock.h>
#include <libos/strings.h>
#include <libos/thread.h>

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
            libos_fdtable_entry_t* new_entry = &new_fdtable->entries[i];

            /* ATTN: only pipes are inherited from the parent process */
            if (entry->type == LIBOS_FDTABLE_TYPE_PIPE)
            {
                libos_pipedev_t* pipedev = entry->device;
                libos_pipe_t* pipe = entry->object;
                ;
                libos_pipe_t* new_pipe;

                if (libos_pipedev_clone_pipe(pipedev, pipe, &new_pipe) != 0)
                {
                    libos_spin_unlock(&fdtable->lock);
                    ERAISE(-ENOMEM);
                }

                new_entry->type = LIBOS_FDTABLE_TYPE_PIPE;
                new_entry->device = pipedev;
                new_entry->object = new_pipe;
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

    /* Close any pipes that are marked O_CLOEXEC */
    for (int i = 0; i < FDTABLE_SIZE; i++)
    {
        libos_fdtable_entry_t* entry = &fdtable->entries[i];

        if (entry->type == LIBOS_FDTABLE_TYPE_PIPE)
        {
            if (entry->device && entry->object)
            {
                libos_pipedev_t* pd = entry->device;
                libos_pipe_t* pipe = entry->object;
                int flags = (*pd->pd_fcntl)(pd, pipe, F_GETFD, 0);

                if ((flags & O_CLOEXEC))
                {
                    (*pd->pd_close)(pd, pipe);
                    memset(entry, 0, sizeof(libos_fdtable_entry_t));
                }
            }
        }
    }

done:
    return ret;
}

int libos_fdtable_free(libos_fdtable_t* fdtable)
{
    int ret = 0;

    if (!fdtable)
        ERAISE(-EINVAL);

    /* Close any pipes */
    for (int i = 0; i < FDTABLE_SIZE; i++)
    {
        libos_fdtable_entry_t* entry = &fdtable->entries[i];

        if (entry->type == LIBOS_FDTABLE_TYPE_PIPE)
        {
            if (entry->device && entry->object)
            {
                libos_pipedev_t* pd = entry->device;
                libos_pipe_t* pipe = entry->object;
                (*pd->pd_close)(pd, pipe);
            }

            memset(entry, 0, sizeof(libos_fdtable_entry_t));
        }
    }

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
    int fd;
    bool locked = false;

    if (!fdtable || !object)
        ERAISE(-EINVAL);

    libos_spin_lock(&fdtable->lock);
    locked = true;

    /* Find an available entry */
    for (int i = 0; i < FDTABLE_SIZE; i++)
    {
        if (fdtable->entries[i].object == NULL)
        {
            fd = i + FD_OFFSET;
            fdtable->entries[i].type = type;
            fdtable->entries[i].device = device;
            fdtable->entries[i].object = object;
            ret = fd;
            goto done;
        }
    }

    ERAISE(-ENOENT);

done:

    if (locked)
        libos_spin_unlock(&fdtable->lock);

    return ret;
}

int libos_fdtable_remove(libos_fdtable_t* fdtable, int fd)
{
    int ret = 0;
    bool locked = false;
    size_t index;

    if (!fdtable)
        ERAISE(-EINVAL);

    if (fd < FD_OFFSET || (fd >= (FD_OFFSET + FDTABLE_SIZE)))
        ERAISE(-EBADF);

    libos_spin_lock(&fdtable->lock);
    locked = true;

    index = fd - FD_OFFSET;
    memset(&fdtable->entries[index], 0, sizeof(libos_fdtable_entry_t));

done:

    if (locked)
        libos_spin_unlock(&fdtable->lock);

    return ret;
}

/* ATTN: consider implementing in terms of libos_fdtable_get_any() */
int libos_fdtable_get(
    libos_fdtable_t* fdtable,
    int fd,
    libos_fdtable_type_t type,
    void** device,
    void** object)
{
    int ret = 0;
    size_t index;
    bool locked = false;

    if (!fdtable || !device || !object)
        ERAISE(-EINVAL);

    if (fd < FD_OFFSET || (fd >= (FD_OFFSET + FDTABLE_SIZE)))
        ERAISE(-EBADF);

    libos_spin_lock(&fdtable->lock);
    locked = true;

    index = fd - FD_OFFSET;

    if (!fdtable->entries[index].object)
        ERAISE(-ENOENT);

    if (fdtable->entries[index].type != type)
        ERAISE(-ENOENT);

    if (!fdtable->entries[index].device)
        ERAISE(-ENOENT);

    *device = fdtable->entries[index].device;
    *object = fdtable->entries[index].object;

done:

    if (locked)
        libos_spin_unlock(&fdtable->lock);

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
    size_t index;
    bool locked = false;

    if (!fdtable || !type || !device || !object)
        ERAISE(-EINVAL);

    if (fd < FD_OFFSET || (fd >= (FD_OFFSET + FDTABLE_SIZE)))
        ERAISE(-EBADF);

    libos_spin_lock(&fdtable->lock);
    locked = true;

    index = fd - FD_OFFSET;

    if (!fdtable->entries[index].object)
        ERAISE(-ENOENT);

    if (!fdtable->entries[index].device)
        ERAISE(-ENOENT);

    *type = fdtable->entries[index].type;
    *device = fdtable->entries[index].device;
    *object = fdtable->entries[index].object;

done:

    if (locked)
        libos_spin_unlock(&fdtable->lock);

    return ret;
}

libos_fdtable_t* libos_fdtable_current(void)
{
    libos_thread_t* thread = libos_thread_self();
    libos_assume(thread->fdtable);
    return thread->fdtable;
}
