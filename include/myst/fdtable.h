// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef _MYST_FDTABLE_H
#define _MYST_FDTABLE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#include <myst/defs.h>
#include <myst/epolldev.h>
#include <myst/eventfddev.h>
#include <myst/fs.h>
#include <myst/inotifydev.h>
#include <myst/pipedev.h>
#include <myst/sockdev.h>
#include <myst/spinlock.h>
#include <myst/ttydev.h>

#define MYST_FDTABLE_SIZE 2048

typedef enum myst_fdtable_type
{
    MYST_FDTABLE_TYPE_NONE,
    MYST_FDTABLE_TYPE_TTY,
    MYST_FDTABLE_TYPE_FILE,
    MYST_FDTABLE_TYPE_PIPE,
    MYST_FDTABLE_TYPE_SOCK,
    MYST_FDTABLE_TYPE_EPOLL,
    MYST_FDTABLE_TYPE_INOTIFY,
    MYST_FDTABLE_TYPE_EVENTFD,
} myst_fdtable_type_t;

typedef struct myst_fdtable_entry
{
    myst_fdtable_type_t type;
    void* device; /* example: myst_fs_t */
    void* object; /* example: myst_file_t */
} myst_fdtable_entry_t;

typedef struct myst_fdtable
{
    myst_fdtable_entry_t entries[MYST_FDTABLE_SIZE];
    myst_spinlock_t lock;
} myst_fdtable_t;

int myst_fdtable_create(myst_fdtable_t** fdtable_out);

int myst_fdtable_cloexec(myst_fdtable_t* fdtable);

int myst_fdtable_free(myst_fdtable_t* fdtable);

int myst_fdtable_interrupt(myst_fdtable_t* fdtable);

/* returns a file descriptor */
int myst_fdtable_assign(
    myst_fdtable_t* fdtable,
    myst_fdtable_type_t type,
    void* device,
    void* object);

typedef enum
{
    MYST_DUP,           /* dup() */
    MYST_DUP2,          /* dup2() */
    MYST_DUP3,          /* dup3() */
    MYST_DUPFD,         /* fcntl(fd, DUPFD) */
    MYST_DUPFD_CLOEXEC, /* fcntl(fd, DUPFD_CLOEXEC) */
} myst_dup_type_t;

int myst_fdtable_dup(
    myst_fdtable_t* fdtable,
    myst_dup_type_t duptype,
    int oldfd,
    int newfd,
    int flags); /* O_CLOEXEC */

int myst_fdtable_remove(myst_fdtable_t* fdtable, int fd);

int myst_fdtable_get(
    myst_fdtable_t* fdtable,
    int fd,
    myst_fdtable_type_t type,
    void** device,
    void** object);

MYST_INLINE int myst_fdtable_get_tty(
    myst_fdtable_t* fdtable,
    int fd,
    myst_ttydev_t** device,
    myst_tty_t** tty)
{
    const myst_fdtable_type_t type = MYST_FDTABLE_TYPE_TTY;
    return myst_fdtable_get(fdtable, fd, type, (void**)device, (void**)tty);
}

MYST_INLINE int myst_fdtable_get_sock(
    myst_fdtable_t* fdtable,
    int fd,
    myst_sockdev_t** device,
    myst_sock_t** sock)
{
    const myst_fdtable_type_t type = MYST_FDTABLE_TYPE_SOCK;
    return myst_fdtable_get(fdtable, fd, type, (void**)device, (void**)sock);
}

MYST_INLINE int myst_fdtable_get_epoll(
    myst_fdtable_t* fdtable,
    int fd,
    myst_epolldev_t** device,
    myst_epoll_t** epoll)
{
    const myst_fdtable_type_t type = MYST_FDTABLE_TYPE_EPOLL;
    return myst_fdtable_get(fdtable, fd, type, (void**)device, (void**)epoll);
}

MYST_INLINE int myst_fdtable_get_file(
    myst_fdtable_t* fdtable,
    int fd,
    myst_fs_t** fs,
    myst_file_t** file)
{
    const myst_fdtable_type_t type = MYST_FDTABLE_TYPE_FILE;
    return myst_fdtable_get(fdtable, fd, type, (void**)fs, (void**)file);
}

MYST_INLINE int myst_fdtable_get_pipe(
    myst_fdtable_t* fdtable,
    int fd,
    myst_pipedev_t** device,
    myst_pipe_t** pipe)
{
    const myst_fdtable_type_t type = MYST_FDTABLE_TYPE_PIPE;
    return myst_fdtable_get(fdtable, fd, type, (void**)device, (void**)pipe);
}

MYST_INLINE int myst_fdtable_get_inotify(
    myst_fdtable_t* fdtable,
    int fd,
    myst_inotifydev_t** device,
    myst_inotify_t** inotify)
{
    const myst_fdtable_type_t type = MYST_FDTABLE_TYPE_INOTIFY;
    return myst_fdtable_get(fdtable, fd, type, (void**)device, (void**)inotify);
}

MYST_INLINE int myst_fdtable_get_eventfd(
    myst_fdtable_t* fdtable,
    int fd,
    myst_eventfddev_t** device,
    myst_eventfd_t** eventfd)
{
    const myst_fdtable_type_t type = MYST_FDTABLE_TYPE_EVENTFD;
    return myst_fdtable_get(fdtable, fd, type, (void**)device, (void**)eventfd);
}

int myst_fdtable_get_any(
    myst_fdtable_t* fdtable,
    int fd,
    myst_fdtable_type_t* type,
    void** device,
    void** object);

/* get the fdtable for the current thread */
myst_fdtable_t* myst_fdtable_current(void);

int myst_fdtable_clone(myst_fdtable_t* fdtable, myst_fdtable_t** fdtable_out);

MYST_INLINE bool myst_valid_fd(int fd)
{
    return fd >= 0 && fd < MYST_FDTABLE_SIZE;
}

int myst_fdtable_list(const myst_fdtable_t* fdtable);

long myst_fdtable_sync(myst_fdtable_t* fdtable);

ssize_t myst_fdtable_count(const myst_fdtable_t* fdtable);

int myst_fdtable_update_sock_entry(
    myst_fdtable_t* fdtable,
    int fd,
    myst_sockdev_t* device,
    myst_sock_t* new_sock);

#endif /* _MYST_FDTABLE_H */
