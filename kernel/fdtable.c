#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <libos/atexit.h>
#include <libos/eraise.h>
#include <libos/once.h>
#include <libos/spinlock.h>
#include <libos/strings.h>
#include "fdtable.h"

typedef struct fdtable_entry
{
    bool used;
    libos_fdtable_type_t type;
    int fd;
    void* device; /* example: libos_fs_t */
    void* object; /* example: libos_file_t */
} fdtable_entry_t;

static fdtable_entry_t* _fdtable[FDTABLE_SIZE];
static libos_spinlock_t _lock;
static libos_once_t _once;

static void _atexit_function(void* arg)
{
    (void)arg;

    for (size_t i = 0; i < FDTABLE_SIZE; i++)
    {
        if (_fdtable[i])
            free(_fdtable[i]);
    }
}

static void _once_function(void)
{
    libos_atexit(_atexit_function, NULL);
}

bool libos_is_libos_fd(int fd)
{
    return fd >= FD_OFFSET && fd <= (FD_OFFSET + FDTABLE_SIZE);
}

int libos_fdtable_add(libos_fdtable_type_t type, void* device, void* object)
{
    int ret = 0;
    int fd;
    bool locked = false;

    if (!device || !object)
        ERAISE(-EINVAL);

    libos_once(&_once, _once_function);

    libos_spin_lock(&_lock);
    locked = true;

    /* Find an available entry */
    for (int i = 0; i < FDTABLE_SIZE; i++)
    {
        if (!_fdtable[i])
        {
            if (!(_fdtable[i] = calloc(1, sizeof(fdtable_entry_t))))
                ERAISE(-ENOMEM);

            fd = i + FD_OFFSET;
            _fdtable[i]->used = true;
            _fdtable[i]->type = type;
            _fdtable[i]->fd = fd;
            _fdtable[i]->device = device;
            _fdtable[i]->object = object;
            ret = fd;
            goto done;
        }
    }

done:

    if (locked)
        libos_spin_unlock(&_lock);

    return ret;
}

int libos_fdtable_remove(int fd)
{
    int ret = 0;
    bool locked = false;

    if (fd < 0)
        ERAISE(-EBADF);

    libos_spin_lock(&_lock);
    locked = true;

    /* Find and clear the entry */
    for (int i = 0; i < FDTABLE_SIZE; i++)
    {
        if (_fdtable[i] && _fdtable[i]->fd == fd)
        {
            free(_fdtable[i]);
            _fdtable[i] = NULL;
            goto done;
        }
    }

    /* Not found */
    ERAISE(-ENOENT);

done:

    if (locked)
        libos_spin_unlock(&_lock);

    return ret;
}

int libos_fdtable_find(
    int fd,
    libos_fdtable_type_t type,
    void** device,
    void** object)
{
    int ret = 0;
    size_t index;
    bool locked = false;

    if (fd < FD_OFFSET || (fd >= (FDTABLE_SIZE + FD_OFFSET)))
        ERAISE(-EINVAL);

    if (!device || !object)
        ERAISE(-EINVAL);

    index = (size_t)(fd - FD_OFFSET);

    if (index >= FDTABLE_SIZE)
        ERAISE(-EINVAL);

    libos_spin_lock(&_lock);
    locked = true;

    if (!_fdtable[index])
        ERAISE(-ENOENT);

    if (_fdtable[index]->type != type)
        ERAISE(-ENOENT);

    if (_fdtable[index]->fd != fd)
        ERAISE(-ENOENT);

    if (!_fdtable[index]->device)
        ERAISE(-ENOENT);

    if (!_fdtable[index]->object)
        ERAISE(-ENOENT);

    *device = _fdtable[index]->device;
    *object = _fdtable[index]->object;

done:

    if (locked)
        libos_spin_unlock(&_lock);

    return ret;
}
