// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <myst/assume.h>
#include <myst/eraise.h>
#include <myst/id.h>
#include <myst/tcall.h>
#include <myst/ttydev.h>

#include <myst/process.h>

#define MAGIC 0xc436d7e6

struct myst_tty
{
    uint32_t magic; /* MAGIC */
    int fd;         /* STDIN_FILENO | STDOUT_FILENO | STDERR_FILENO */
    int flags;
    int fdflags; /* file descriptor flags: FD_CLOEXEC */
};

MYST_INLINE bool _valid_tty(const myst_tty_t* tty)
{
    return tty && tty->magic == MAGIC;
}

static int _td_create(myst_ttydev_t* ttydev, int fd, myst_tty_t** tty_out)
{
    int ret = 0;
    myst_tty_t* tty = NULL;

    if (tty_out)
        *tty_out = NULL;

    if (!ttydev || !tty_out || (fd < STDIN_FILENO || fd > STDERR_FILENO))
        ERAISE(-EINVAL);

    /* Create the tty implementation structure */
    {
        if (!(tty = calloc(1, sizeof(myst_tty_t))))
            ERAISE(-ENOMEM);

        tty->magic = MAGIC;
        tty->fd = fd;
    }

    *tty_out = tty;
    tty = NULL;

done:

    if (tty)
        free(tty);

    return ret;
}

static ssize_t _td_read(
    myst_ttydev_t* ttydev,
    myst_tty_t* tty,
    void* buf,
    size_t count)
{
    ssize_t ret = 0;

    if (!ttydev || !_valid_tty(tty))
        ERAISE(-EBADF);

    if (!buf && count)
        ERAISE(-EINVAL);

    if (count == 0)
        goto done;

    ERAISE(myst_tcall_read_console(tty->fd, buf, count));
done:
    return ret;
}

static ssize_t _td_write(
    myst_ttydev_t* ttydev,
    myst_tty_t* tty,
    const void* buf,
    size_t count)
{
    ssize_t ret = 0;

    if (!ttydev || !_valid_tty(tty))
        ERAISE(-EBADF);

    if (!buf && count)
        ERAISE(-EINVAL);

    if (count == 0)
        goto done;

    ERAISE(myst_tcall_write_console(tty->fd, buf, count));
done:
    return ret;
}

static ssize_t _td_readv(
    myst_ttydev_t* ttydev,
    myst_tty_t* tty,
    const struct iovec* iov,
    int iovcnt)
{
    ssize_t ret = 0;

    if (!ttydev || !_valid_tty(tty))
        ERAISE(-EINVAL);

    ret = myst_fdops_readv(&ttydev->fdops, tty, iov, iovcnt);
    ECHECK(ret);

done:

    return ret;
}

static ssize_t _td_writev(
    myst_ttydev_t* ttydev,
    myst_tty_t* tty,
    const struct iovec* iov,
    int iovcnt)
{
    ssize_t ret = 0;

    if (!ttydev || !_valid_tty(tty))
        ERAISE(-EINVAL);

    ret = myst_fdops_writev(&ttydev->fdops, tty, iov, iovcnt);
    ECHECK(ret);

done:

    return ret;
}

static int _td_fstat(
    myst_ttydev_t* ttydev,
    myst_tty_t* tty,
    struct stat* statbuf)
{
    int ret = 0;
    struct stat buf;

    if (!ttydev || !_valid_tty(tty) || !statbuf)
        ERAISE(-EINVAL);

    memset(&buf, 0, sizeof(buf));
    buf.st_dev = 22; /* TTY device */
    buf.st_ino = (ino_t)tty;
    buf.st_mode = S_IFCHR | S_IRUSR;
    if (tty->fd != STDIN_FILENO)
        buf.st_mode |= S_IWUSR;
    buf.st_nlink = 1;
    buf.st_uid = MYST_DEFAULT_UID;
    buf.st_gid = MYST_DEFAULT_GID;
    buf.st_rdev = 0;
    buf.st_size = 0;
    buf.st_blksize = 1024;
    buf.st_blocks = 0;
    memset(&buf.st_atim, 0, sizeof(buf.st_atim));
    memset(&buf.st_mtim, 0, sizeof(buf.st_mtim));
    memset(&buf.st_ctim, 0, sizeof(buf.st_ctim));

    *statbuf = buf;

done:
    return ret;
}

static int _td_fcntl(myst_ttydev_t* ttydev, myst_tty_t* tty, int cmd, long arg)
{
    int ret = 0;

    if (!ttydev || !_valid_tty(tty))
        ERAISE(-EINVAL);

    switch (cmd)
    {
        case F_SETFD:
        {
            if (arg != FD_CLOEXEC && arg != 0)
                ERAISE(-EINVAL);

            tty->fdflags = arg;
            goto done;
        }
        case F_GETFD:
        {
            ret = tty->fdflags;
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

static int _td_ioctl(
    myst_ttydev_t* ttydev,
    myst_tty_t* tty,
    unsigned long request,
    long arg)
{
    int ret = 0;

    if (!ttydev || !_valid_tty(tty))
        ERAISE(-EBADF);

    if (request == TIOCGWINSZ)
    {
        struct winsize
        {
            unsigned short int ws_row;
            unsigned short int ws_col;
            unsigned short int ws_xpixel;
            unsigned short int ws_ypixel;
        };
        struct winsize* p;

        if (!(p = (struct winsize*)arg))
            ERAISE(-EINVAL);

        p->ws_row = 24;
        p->ws_col = 80;
        p->ws_xpixel = 0;
        p->ws_ypixel = 0;

        ret = 0;
        goto done;
    }
    else if(request == TIOCGPGRP)//0x0000540F  TIOCGPGRP              pid_t *
    {
        myst_process_t* self = myst_process_self();

        pid_t *argp;
        if (!(argp = (pid_t *)arg))
            ERAISE(-EINVAL);

        argp = &self->pgid;

        ret = 0;
        goto done;
    }
    else if(request == TIOCSPGRP)//0x00005410  TIOCSPGRP              const pid_t *
    {
        myst_process_t* self = myst_process_self();
        pid_t *argp = (pid_t *)arg;

        self->pgid = *argp;

        ret = 0;
        goto done;
    }
    /** These are additional ioctl system calls made by bash
     * 0x00005401  TCGETS
     * 0x00005414  TIOCSWINSZ
     * 0x00005403  TCSETSW
     * */
    else
    {
        ERAISE(-ENOTSUP);
    }

done:

    return ret;
}

static int _td_dup(
    myst_ttydev_t* ttydev,
    const myst_tty_t* tty,
    myst_tty_t** tty_out)
{
    int ret = 0;
    myst_tty_t* new_tty = NULL;

    if (tty_out)
        *tty_out = NULL;

    if (!ttydev || !_valid_tty(tty) || !tty_out)
        ERAISE(-EINVAL);

    if (!(new_tty = calloc(1, sizeof(myst_tty_t))))
        ERAISE(-ENOMEM);

    *new_tty = *tty;

    *tty_out = new_tty;

    /* file descriptor flags are not propagated */
    new_tty->fdflags = 0;

    new_tty = NULL;

done:

    if (new_tty)
        free(new_tty);

    return ret;
}

static int _td_close(myst_ttydev_t* ttydev, myst_tty_t* tty)
{
    int ret = 0;

    if (!ttydev || !_valid_tty(tty))
        ERAISE(-EBADF);

    memset(tty, 0, sizeof(myst_tty_t));
    free(tty);

done:

    return ret;
}

static int _td_target_fd(myst_ttydev_t* ttydev, myst_tty_t* tty)
{
    int ret = 0;

    if (!ttydev || !_valid_tty(tty))
        ERAISE(-EINVAL);

    ret = -ENOTSUP;

done:
    return ret;
}

static int _td_get_events(myst_ttydev_t* ttydev, myst_tty_t* tty)
{
    int ret = 0;

    if (!ttydev || !_valid_tty(tty))
        ERAISE(-EINVAL);

    if ((tty->fd == STDOUT_FILENO) || (tty->fd == STDERR_FILENO))
        ret |= POLLOUT;
    else
        ret = -ENOTSUP;

done:
    return ret;
}

extern myst_ttydev_t* myst_ttydev_get(void)
{
    // clang-format-off
    static myst_ttydev_t _ttydev = {
        {
            .fd_read = (void*)_td_read,
            .fd_write = (void*)_td_write,
            .fd_readv = (void*)_td_readv,
            .fd_writev = (void*)_td_writev,
            .fd_fstat = (void*)_td_fstat,
            .fd_fcntl = (void*)_td_fcntl,
            .fd_ioctl = (void*)_td_ioctl,
            .fd_dup = (void*)_td_dup,
            .fd_close = (void*)_td_close,
            .fd_target_fd = (void*)_td_target_fd,
            .fd_get_events = (void*)_td_get_events,
        },
        .td_create = _td_create,
        .td_read = _td_read,
        .td_write = _td_write,
        .td_readv = _td_readv,
        .td_writev = _td_writev,
        .td_fstat = _td_fstat,
        .td_fcntl = _td_fcntl,
        .td_ioctl = _td_ioctl,
        .td_dup = _td_dup,
        .td_close = _td_close,
        .td_target_fd = _td_target_fd,
        .td_get_events = _td_get_events,
    };
    // clang-format-on

    return &_ttydev;
}
