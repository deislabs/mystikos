// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _LIBOS_FDTABLE_H
#define _LIBOS_FDTABLE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#include <libos/defs.h>
#include <libos/fs.h>
#include <libos/pipedev.h>
#include <libos/sockdev.h>
#include <libos/spinlock.h>
#include <libos/ttydev.h>
#include <libos/epolldev.h>

#define LIBOS_FDTABLE_SIZE 1024

typedef enum libos_fdtable_type
{
    LIBOS_FDTABLE_TYPE_NONE,
    LIBOS_FDTABLE_TYPE_TTY,
    LIBOS_FDTABLE_TYPE_FILE,
    LIBOS_FDTABLE_TYPE_PIPE,
    LIBOS_FDTABLE_TYPE_SOCK,
    LIBOS_FDTABLE_TYPE_EPOLL,
} libos_fdtable_type_t;

typedef struct libos_fdtable_entry
{
    libos_fdtable_type_t type;
    void* device; /* example: libos_fs_t */
    void* object; /* example: libos_file_t */
} libos_fdtable_entry_t;

typedef struct libos_fdtable
{
    libos_fdtable_entry_t entries[LIBOS_FDTABLE_SIZE];
    libos_spinlock_t lock;
} libos_fdtable_t;

int libos_fdtable_create(libos_fdtable_t** fdtable_out);

int libos_fdtable_cloexec(libos_fdtable_t* fdtable);

int libos_fdtable_free(libos_fdtable_t* fdtable);

/* returns a file descriptor */
int libos_fdtable_assign(
    libos_fdtable_t* fdtable,
    libos_fdtable_type_t type,
    void* device,
    void* object);

typedef enum
{
    LIBOS_DUP,           /* dup() */
    LIBOS_DUP2,          /* dup2() */
    LIBOS_DUP3,          /* dup3() */
    LIBOS_DUPFD,         /* fcntl(fd, DUPFD) */
    LIBOS_DUPFD_CLOEXEC, /* fcntl(fd, DUPFD_CLOEXEC) */
} libos_dup_type_t;

int libos_fdtable_dup(
    libos_fdtable_t* fdtable,
    libos_dup_type_t duptype,
    int oldfd,
    int newfd,
    int flags); /* O_CLOEXEC */

int libos_fdtable_remove(libos_fdtable_t* fdtable, int fd);

int libos_fdtable_get(
    libos_fdtable_t* fdtable,
    int fd,
    libos_fdtable_type_t type,
    void** device,
    void** object);

LIBOS_INLINE int libos_fdtable_get_tty(
    libos_fdtable_t* fdtable,
    int fd,
    libos_ttydev_t** device,
    libos_tty_t** tty)
{
    const libos_fdtable_type_t type = LIBOS_FDTABLE_TYPE_TTY;
    return libos_fdtable_get(fdtable, fd, type, (void**)device, (void**)tty);
}

LIBOS_INLINE int libos_fdtable_get_sock(
    libos_fdtable_t* fdtable,
    int fd,
    libos_sockdev_t** device,
    libos_sock_t** sock)
{
    const libos_fdtable_type_t type = LIBOS_FDTABLE_TYPE_SOCK;
    return libos_fdtable_get(fdtable, fd, type, (void**)device, (void**)sock);
}

LIBOS_INLINE int libos_fdtable_get_epoll(
    libos_fdtable_t* fdtable,
    int fd,
    libos_epolldev_t** device,
    libos_epoll_t** epoll)
{
    const libos_fdtable_type_t type = LIBOS_FDTABLE_TYPE_EPOLL;
    return libos_fdtable_get(fdtable, fd, type, (void**)device, (void**)epoll);
}

LIBOS_INLINE int libos_fdtable_get_file(
    libos_fdtable_t* fdtable,
    int fd,
    libos_fs_t** fs,
    libos_file_t** file)
{
    const libos_fdtable_type_t type = LIBOS_FDTABLE_TYPE_FILE;
    return libos_fdtable_get(fdtable, fd, type, (void**)fs, (void**)file);
}

LIBOS_INLINE int libos_fdtable_get_pipe(
    libos_fdtable_t* fdtable,
    int fd,
    libos_pipedev_t** device,
    libos_pipe_t** pipe)
{
    const libos_fdtable_type_t type = LIBOS_FDTABLE_TYPE_PIPE;
    return libos_fdtable_get(fdtable, fd, type, (void**)device, (void**)pipe);
}

int libos_fdtable_get_any(
    libos_fdtable_t* fdtable,
    int fd,
    libos_fdtable_type_t* type,
    void** device,
    void** object);

/* get the fdtable for the current thread */
libos_fdtable_t* libos_fdtable_current(void);

int libos_fdtable_clone(
    libos_fdtable_t* fdtable,
    libos_fdtable_t** fdtable_out);

LIBOS_INLINE bool libos_valid_fd(int fd)
{
    return fd >= 0 && fd < LIBOS_FDTABLE_SIZE;
}

#endif /* _LIBOS_FDTABLE_H */
