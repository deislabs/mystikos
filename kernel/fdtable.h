// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_FDTABLE_H
#define _MYST_FDTABLE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define FDTABLE_SIZE 128
#define FD_OFFSET 1024

typedef enum myst_fdtable_type
{
    MYST_FDTABLE_TYPE_FILE,
} myst_fdtable_type_t;

bool myst_is_myst_fd(int fd);

/* return a file descriptor */
int myst_fdtable_add(myst_fdtable_type_t type, void* device, void* object);

int myst_fdtable_remove(int fd);

int myst_fdtable_find(
    int fd,
    myst_fdtable_type_t type,
    void** device,
    void** object);

#endif /* _MYST_FDTABLE_H */
