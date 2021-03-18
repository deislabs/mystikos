// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <myst/assume.h>
#include <myst/bufalloc.h>
#include <myst/epolldev.h>
#include <myst/eraise.h>
#include <myst/fdtable.h>
#include <myst/id.h>
#include <myst/list.h>
#include <myst/spinlock.h>
#include <myst/syscall.h>
#include <myst/tcall.h>

#define MAGIC 0xc436d7e6

typedef struct epoll_entry epoll_entry_t;

struct epoll_entry
{
    /* these leading fields align with the same fields in myst_list_node_t */
    epoll_entry_t* prev;
    epoll_entry_t* next;
    int fd;
    struct epoll_event event;
};

struct myst_epoll
{
    uint32_t magic; /* MAGIC */
    int flags;      /* flags passed to epoll_create1() or set by fcntl() */
    myst_spinlock_t lock;
    myst_list_t list;
};

static epoll_entry_t* _find(myst_epoll_t* epoll, int fd)
{
    for (epoll_entry_t* p = (epoll_entry_t*)epoll->list.head; p; p = p->next)
    {
        if (p->fd == fd)
            return p;
    }

    return NULL;
}

static bool _valid_epoll(const myst_epoll_t* epoll)
{
    return epoll && epoll->magic == MAGIC;
}

static int _ed_epoll_create1(
    myst_epolldev_t* epolldev,
    int flags,
    myst_epoll_t** epoll_out)
{
    int ret = 0;
    myst_epoll_t* epoll = NULL;

    if (epoll_out)
        *epoll_out = NULL;

    if (!epolldev || !epoll_out)
        ERAISE(-EINVAL);

    /* Create the epoll implementation structure */
    {
        if (!(epoll = calloc(1, sizeof(myst_epoll_t))))
            ERAISE(-ENOMEM);

        epoll->magic = MAGIC;
        epoll->flags = flags;
    }

    *epoll_out = epoll;
    epoll = NULL;

done:

    if (epoll)
        free(epoll);

    return ret;
}

static int _ed_epoll_ctl(
    myst_epolldev_t* epolldev,
    myst_epoll_t* epoll,
    int op,
    int fd,
    struct epoll_event* event)
{
    ssize_t ret = 0;
    bool locked = false;

    if (!epolldev || !_valid_epoll(epoll) || !event)
        ERAISE(-EBADF);

    if (!myst_valid_fd(fd))
        ERAISE(-EBADF);

    myst_spin_lock(&epoll->lock);
    locked = true;

    /* handle the operation */
    switch (op)
    {
        case EPOLL_CTL_ADD:
        {
            epoll_entry_t* entry;

            /* fail if entry already exists for this fd */
            if (_find(epoll, fd))
                ERAISE(-EEXIST);

            if (!(entry = calloc(1, sizeof(epoll_entry_t))))
                ERAISE(-ENOMEM);

            /* Initialize the entry */
            entry->fd = fd;
            entry->event = *event;

            /* add the entry to the list */
            myst_list_append(&epoll->list, (myst_list_node_t*)entry);

            break;
        }
        case EPOLL_CTL_MOD:
        {
            epoll_entry_t* entry;

            /* fail if entry not found */
            if (!(entry = _find(epoll, fd)))
                ERAISE(-ENOENT);

            /* update the event */
            entry->event = *event;
            break;
        }
        case EPOLL_CTL_DEL:
        {
            epoll_entry_t* entry = NULL;

            /* fail if entry not found */
            if (!(entry = _find(epoll, fd)))
                ERAISE(-ENOENT);

            myst_list_remove(&epoll->list, (myst_list_node_t*)entry);
            free(entry);
            break;
        }
        default:
        {
            ERAISE(-EINVAL);
        }
    }

done:

    if (locked)
        myst_spin_unlock(&epoll->lock);

    return ret;
}

static int _ed_epoll_wait(
    myst_epolldev_t* epolldev,
    myst_epoll_t* epoll,
    struct epoll_event* events,
    int maxevents,
    int timeout) /* milliseconds */
{
    int ret = 0;
    bool locked = false;
    nfds_t nfds;
    struct pollfd buf[16];
    const size_t buflen = sizeof(buf);
    struct pollfd* fds = NULL;
    int n;

    if (!epolldev || !epoll || !events || maxevents < 0)
        ERAISE(-EINVAL);

    myst_spin_lock(&epoll->lock);
    locked = true;

    /* Prune the interested FDs that have been closed */
    {
        myst_fdtable_t* fdtable = NULL;
        myst_fdtable_type_t type;
        myst_fdops_t* fdops;
        void* object;

        if (!(fdtable = myst_fdtable_current()))
            ERAISE(-ENOSYS);

        for (epoll_entry_t* src = (epoll_entry_t*)epoll->list.head; src;)
        {
            epoll_entry_t* next = src->next;
            if (myst_fdtable_get_any(
                    fdtable, src->fd, &type, (void**)&fdops, (void**)&object))
            {
                myst_list_remove(&epoll->list, (myst_list_node_t*)src);
                free(src);
            }
            src = next;
        }
    }

    /* Get the number of events */
    nfds = epoll->list.size;

    /* allocates the fds array */
    if (!(fds = myst_buf_calloc(buf, buflen, nfds, sizeof(struct pollfd))))
        ERAISE(-ENOMEM);

    /* convert from epoll-set to poll-set */
    {
        const epoll_entry_t* src = (epoll_entry_t*)epoll->list.head;

        for (size_t i = 0; i < nfds; i++)
        {
            struct pollfd* dest = &fds[i];

            dest->fd = src->fd;

            if (src->event.events & EPOLLIN)
                dest->events |= POLLIN;

            if (src->event.events & EPOLLOUT)
                dest->events |= POLLOUT;

            if (src->event.events & EPOLLRDHUP)
                dest->events |= POLLRDHUP;

            if (src->event.events & EPOLLPRI)
                dest->events |= POLLPRI;

            if (src->event.events & EPOLLERR)
                dest->events |= POLLERR;

            if (src->event.events & EPOLLHUP)
                dest->events |= POLLHUP;

            /* ATTN: EPOLLET not supported */
            /* ATTN: EPOLLONESHOT not supported */
            /* ATTN: EPOLLWAKEUP not supported */
            /* ATTN: EPOLLEXCLUSIVE not supported */

            src = src->next;
        }
    }

    myst_spin_unlock(&epoll->lock);
    locked = false;

    ECHECK((n = myst_syscall_poll(fds, nfds, timeout)));

    /* this should never happen */
    if ((size_t)n > nfds)
        ERAISE(-EINVAL);

    myst_spin_lock(&epoll->lock);
    locked = true;

    /* convert from poll-set back to epoll-set */
    {
        int nevents = 0;
        const epoll_entry_t* ent = (epoll_entry_t*)epoll->list.head;

        for (size_t i = 0; i < nfds; i++)
        {
            const struct pollfd* src = &fds[i];

            if (src->revents)
            {
                struct epoll_event* dest;

                if (nevents >= maxevents)
                    break;

                dest = &events[nevents++];

                if (src->events & POLLIN)
                    dest->events |= EPOLLIN;

                if (src->events & POLLOUT)
                    dest->events |= EPOLLOUT;

                if (src->events & POLLRDHUP)
                    dest->events |= EPOLLRDHUP;

                if (src->events & POLLPRI)
                    dest->events |= EPOLLPRI;

                if (src->events & POLLERR)
                    dest->events |= EPOLLERR;

                if (src->events & POLLHUP)
                    dest->events |= EPOLLHUP;

                dest->data = ent->event.data;
            }

            ent = ent->next;
        }

        ret = nevents;
    }

done:

    if (fds)
        myst_buf_free(buf, fds);

    if (locked)
        myst_spin_unlock(&epoll->lock);

    return ret;
}

static ssize_t _ed_read(
    myst_epolldev_t* epolldev,
    myst_epoll_t* epoll,
    void* buf,
    size_t count)
{
    ssize_t ret = 0;

    if (!epolldev || !_valid_epoll(epoll))
        ERAISE(-EBADF);

    if (!buf && count)
        ERAISE(-EINVAL);

    ERAISE(-ENOTSUP);

done:
    return ret;
}

static ssize_t _ed_write(
    myst_epolldev_t* epolldev,
    myst_epoll_t* epoll,
    const void* buf,
    size_t count)
{
    ssize_t ret = 0;

    if (!epolldev || !_valid_epoll(epoll))
        ERAISE(-EBADF);

    if (!buf && count)
        ERAISE(-EINVAL);

    ERAISE(-ENOTSUP);

done:
    return ret;
}

static ssize_t _ed_readv(
    myst_epolldev_t* epolldev,
    myst_epoll_t* epoll,
    const struct iovec* iov,
    int iovcnt)
{
    ssize_t ret = 0;

    (void)iov;
    (void)iovcnt;

    if (!epolldev || !_valid_epoll(epoll))
        ERAISE(-EINVAL);

    ERAISE(-ENOTSUP);

done:

    return ret;
}

static ssize_t _ed_writev(
    myst_epolldev_t* epolldev,
    myst_epoll_t* epoll,
    const struct iovec* iov,
    int iovcnt)
{
    ssize_t ret = 0;

    (void)iov;
    (void)iovcnt;

    if (!epolldev || !_valid_epoll(epoll))
        ERAISE(-EINVAL);

    ERAISE(-ENOTSUP);

done:

    return ret;
}

static int _ed_fstat(
    myst_epolldev_t* epolldev,
    myst_epoll_t* epoll,
    struct stat* statbuf)
{
    int ret = 0;
    struct stat buf;

    if (!epolldev || !_valid_epoll(epoll) || !statbuf)
        ERAISE(-EINVAL);

    memset(&buf, 0, sizeof(buf));
    buf.st_dev = 13; /* magic number for epoll device */
    buf.st_ino = (ino_t)epoll;
    buf.st_mode = S_IRUSR | S_IWUSR;
    buf.st_nlink = 1;
    buf.st_uid = MYST_DEFAULT_UID;
    buf.st_gid = MYST_DEFAULT_GID;
    buf.st_rdev = 0;
    buf.st_size = 0;
    buf.st_blksize = 4096;
    buf.st_blocks = 0;
    memset(&buf.st_atim, 0, sizeof(buf.st_atim));
    memset(&buf.st_mtim, 0, sizeof(buf.st_mtim));
    memset(&buf.st_ctim, 0, sizeof(buf.st_ctim));

    *statbuf = buf;

done:
    return ret;
}

static int _ed_fcntl(
    myst_epolldev_t* epolldev,
    myst_epoll_t* epoll,
    int cmd,
    long arg)
{
    int ret = 0;

    if (!epolldev || !_valid_epoll(epoll))
        ERAISE(-EINVAL);

    switch (cmd)
    {
        case F_SETFD:
        {
            if (arg != FD_CLOEXEC && arg != 0)
                ERAISE(-EINVAL);

            epoll->flags = arg;
            goto done;
        }
        case F_GETFD:
        {
            ret = epoll->flags;
            goto done;
        }
        default:
        {
            ERAISE(-ENOTSUP);
        }
    }

done:
    return ret;
}

static int _ed_ioctl(
    myst_epolldev_t* epolldev,
    myst_epoll_t* epoll,
    unsigned long request,
    long arg)
{
    int ret = 0;

    (void)request;
    (void)arg;

    if (!epolldev || !_valid_epoll(epoll))
        ERAISE(-EBADF);

    ERAISE(-ENOTSUP);

done:

    return ret;
}

static int _ed_dup(
    myst_epolldev_t* epolldev,
    const myst_epoll_t* epoll,
    myst_epoll_t** epoll_out)
{
    int ret = 0;

    if (epoll_out)
        *epoll_out = NULL;

    if (!epolldev || !_valid_epoll(epoll) || !epoll_out)
        ERAISE(-EINVAL);

    /* ATTN: dup() not supported for epoll objects */
    ERAISE(-ENOTSUP);

done:

    return ret;
}

static int _ed_close(myst_epolldev_t* epolldev, myst_epoll_t* epoll)
{
    int ret = 0;

    if (!epolldev || !_valid_epoll(epoll))
        ERAISE(-EBADF);

    memset(epoll, 0, sizeof(myst_epoll_t));
    free(epoll);

done:

    return ret;
}

static int _ed_target_fd(myst_epolldev_t* epolldev, myst_epoll_t* epoll)
{
    int ret = 0;

    if (!epolldev || !_valid_epoll(epoll))
        ERAISE(-EINVAL);

    ret = -ENOTSUP;

done:
    return ret;
}

static int _ed_get_events(myst_epolldev_t* epolldev, myst_epoll_t* epoll)
{
    int ret = 0;

    if (!epolldev || !_valid_epoll(epoll))
        ERAISE(-EINVAL);

    ret = -ENOTSUP;

done:
    return ret;
}

extern myst_epolldev_t* myst_epolldev_get(void)
{
    // clang-format-off
    static myst_epolldev_t _epolldev = {
        {
            .fd_read = (void*)_ed_read,
            .fd_write = (void*)_ed_write,
            .fd_readv = (void*)_ed_readv,
            .fd_writev = (void*)_ed_writev,
            .fd_fstat = (void*)_ed_fstat,
            .fd_fcntl = (void*)_ed_fcntl,
            .fd_ioctl = (void*)_ed_ioctl,
            .fd_dup = (void*)_ed_dup,
            .fd_close = (void*)_ed_close,
            .fd_target_fd = (void*)_ed_target_fd,
            .fd_get_events = (void*)_ed_get_events,
        },
        .ed_epoll_create1 = _ed_epoll_create1,
        .ed_epoll_ctl = _ed_epoll_ctl,
        .ed_epoll_wait = _ed_epoll_wait,
        .ed_read = _ed_read,
        .ed_write = _ed_write,
        .ed_readv = _ed_readv,
        .ed_writev = _ed_writev,
        .ed_fstat = _ed_fstat,
        .ed_fcntl = _ed_fcntl,
        .ed_ioctl = _ed_ioctl,
        .ed_dup = _ed_dup,
        .ed_close = _ed_close,
        .ed_target_fd = _ed_target_fd,
        .ed_get_events = _ed_get_events,
    };
    // clang-format-on

    return &_epolldev;
}
