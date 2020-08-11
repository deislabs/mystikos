// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _LIBOS_FDTABLE_H
#define _LIBOS_FDTABLE_H

#include <stddef.h>
#include <stdint.h>

#define FDTABLE_SIZE 1024
#define FD_OFFSET 1024

typedef enum libos_fdtable_type
{
    LIBOS_FDTABLE_TYPE_FILE,
}
libos_fdtable_type_t;

bool libos_is_libos_fd(int fd);

/* return a file descriptor */
int libos_fdtable_add(
    libos_fdtable_type_t type,
    void* device,
    void* object);

int libos_fdtable_remove(int fd);

int libos_fdtable_find(
    int fd,
    libos_fdtable_type_t type,
    void** device,
    void** object);

#endif /* _LIBOS_FDTABLE_H */
