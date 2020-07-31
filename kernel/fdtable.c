#include <stdbool.h>
#include "fdtable.h"
#include "eraise.h"

#define FDTABLE_SIZE 1024

/* Offset file descriptors to avoid conflicts with host descriptors */
#define FD_OFFSET 1024

typedef struct libos_fdtable_entry
{
    bool used;
    libos_fdtable_type_t type;
    int fd;
    void* object;
}
libos_fdtable_entry_t;

static libos_fdtable_entry_t _fdtable[FDTABLE_SIZE];

int libos_fdtable_add(libos_fdtable_type_t type, void* object)
{
    int ret = 0;
    int fd;

    if (!object)
        ERAISE(EINVAL);

    /* Find an available entry */
    for (int i = 0; i < FDTABLE_SIZE; i++)
    {
        if (!_fdtable[i].used)
        {
            fd = i + FD_OFFSET;
            _fdtable[i].used = true;
            _fdtable[i].type = type;
            _fdtable[i].fd = fd;
            _fdtable[i].object = object;
            ret = fd;
            goto done;
        }
    }

done:
    return ret;
}

int libos_fdtable_find(int fd, libos_fdtable_type_t type, void** object)
{
    int ret = 0;
    size_t index;

    if (fd < FD_OFFSET || (fd >= (FDTABLE_SIZE + FD_OFFSET)) || !object)
        ERAISE(EINVAL);

    index = (size_t)(fd - FD_OFFSET);

    if (index >= FDTABLE_SIZE)
        ERAISE(EINVAL);

    if (!_fdtable[index].used)
        ERAISE(ENOENT);

    if (_fdtable[index].type != type)
        ERAISE(ENOENT);

    if (_fdtable[index].fd != fd)
        ERAISE(ENOENT);

    if (!_fdtable[index].object)
        ERAISE(ENOENT);

    *object = _fdtable[index].object;

done:
    return ret;
}
