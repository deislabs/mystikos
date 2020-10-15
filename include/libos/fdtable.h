// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _LIBOS_FDTABLE_H
#define _LIBOS_FDTABLE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <libos/defs.h>
#include <libos/spinlock.h>

#define FDTABLE_SIZE 1024
#define FD_OFFSET 1024

typedef enum libos_fdtable_type
{
    LIBOS_FDTABLE_TYPE_FILE,
    LIBOS_FDTABLE_TYPE_PIPE,
    LIBOS_FDTABLE_TYPE_SOCKET,
} libos_fdtable_type_t;

typedef struct libos_fdtable_entry
{
    libos_fdtable_type_t type;
    void* device; /* example: libos_fs_t */
    void* object; /* example: libos_file_t */
} libos_fdtable_entry_t;

typedef struct libos_fdtable
{
    libos_fdtable_entry_t entries[FDTABLE_SIZE];
    libos_spinlock_t lock;
} libos_fdtable_t;

int libos_fdtable_create(libos_fdtable_t** fdtable_out);

int libos_fdtable_cloexec(libos_fdtable_t* fdtable);

int libos_fdtable_free(libos_fdtable_t* fdtable);

/* returns a file descriptor */
int libos_fdtable_assign(
    libos_fdtable_t* libos_fdtable,
    libos_fdtable_type_t type,
    void* device,
    void* object);

int libos_fdtable_remove(libos_fdtable_t* libos_fdtable, int fd);

int libos_fdtable_get(
    libos_fdtable_t* libos_fdtable,
    int fd,
    libos_fdtable_type_t type,
    void** device,
    void** object);

int libos_fdtable_get_any(
    libos_fdtable_t* libos_fdtable,
    int fd,
    libos_fdtable_type_t* type,
    void** device,
    void** object);

LIBOS_INLINE bool libos_is_libos_fd(int fd)
{
    return fd >= FD_OFFSET && fd <= (FD_OFFSET + FDTABLE_SIZE);
}

/* get the fdtable for the current thread */
libos_fdtable_t* libos_fdtable_current(void);

int libos_fdtable_clone(
    libos_fdtable_t* fdtable,
    libos_fdtable_t** fdtable_out);

#endif /* _LIBOS_FDTABLE_H */
