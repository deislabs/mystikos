#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>

#include <myst/defs.h>
#include <myst/eraise.h>
#include <myst/inotifydev.h>

#define MAGIC 0x223b6b68

// examples:
//     https://www.thegeekstuff.com/2010/04/inotify-c-program-example
//     https://man7.org/tlpi/code/online/diff/inotify/demo_inotify.c.html

struct myst_inotify
{
    uint32_t magic;
    int flags;
};

MYST_INLINE bool _valid_inotify(const myst_inotify_t* obj)
{
    return obj && obj->magic == MAGIC;
}

static int _id_inotify_init1(
    myst_inotifydev_t* dev,
    int flags,
    myst_inotify_t** obj_out)
{
    int ret = 0;
    const int mask = IN_NONBLOCK | IN_CLOEXEC;
    myst_inotify_t* obj = NULL;

    if (obj_out)
        *obj_out = NULL;

    if (!dev || (flags & ~mask) || !obj_out)
        ERAISE(-EINVAL);

    if (!(obj = calloc(1, sizeof(myst_inotify_t))))
        ERAISE(-ENOMEM);

    obj->magic = MAGIC;
    obj->flags = flags;

    *obj_out = obj;
    obj = NULL;

done:

    if (obj)
        free(obj);

    return ret;
}

static ssize_t _id_read(
    myst_inotifydev_t* dev,
    myst_inotify_t* obj,
    void* buf,
    size_t count)
{
    (void)dev;
    (void)obj;
    (void)buf;
    (void)count;
    return -EINVAL;
}

static ssize_t _id_write(
    myst_inotifydev_t* dev,
    myst_inotify_t* obj,
    const void* buf,
    size_t count)
{
    (void)dev;
    (void)obj;
    (void)buf;
    (void)count;
    return -EINVAL;
}

static ssize_t _id_readv(
    myst_inotifydev_t* dev,
    myst_inotify_t* obj,
    const struct iovec* iov,
    int iovcnt)
{
    (void)dev;
    (void)obj;
    (void)iov;
    (void)iovcnt;
    return -EINVAL;
}

static ssize_t _id_writev(
    myst_inotifydev_t* dev,
    myst_inotify_t* obj,
    const struct iovec* iov,
    int iovcnt)
{
    (void)dev;
    (void)obj;
    (void)iov;
    (void)iovcnt;
    return -EINVAL;
}

static int _id_fstat(
    myst_inotifydev_t* dev,
    myst_inotify_t* obj,
    struct stat* statbuf)
{
    (void)dev;
    (void)obj;
    (void)statbuf;
    return -EINVAL;
}

static int _id_fcntl(
    myst_inotifydev_t* dev,
    myst_inotify_t* obj,
    int cmd,
    long arg)
{
    (void)dev;
    (void)obj;
    (void)cmd;
    (void)arg;
    return -EINVAL;
}

static int _id_ioctl(
    myst_inotifydev_t* dev,
    myst_inotify_t* obj,
    unsigned long request,
    long arg)
{
    int ret = 0;

    (void)arg;

    if (!dev || !_valid_inotify(obj))
        ERAISE(-EBADF);

    if (request == TIOCGWINSZ)
        ERAISE(-EINVAL);

    ERAISE(-ENOTSUP);

done:

    return ret;
}

static int _id_dup(
    myst_inotifydev_t* dev,
    const myst_inotify_t* obj,
    myst_inotify_t** inotify_out)
{
    (void)dev;
    (void)obj;
    (void)inotify_out;
    return -EINVAL;
}

static int _id_close(myst_inotifydev_t* dev, myst_inotify_t* obj)
{
    int ret = 0;

    if (!dev || !_valid_inotify(obj))
        ERAISE(-EINVAL);

    memset(obj, 0, sizeof(myst_inotify_t));
    free(obj);

done:
    return ret;
}

static int _id_target_fd(myst_inotifydev_t* dev, myst_inotify_t* obj)
{
    int ret = 0;

    if (!dev || !_valid_inotify(obj))
        ERAISE(-EINVAL);

    ret = -ENOTSUP;

done:
    return ret;
}

static int _id_get_events(myst_inotifydev_t* dev, myst_inotify_t* obj)
{
    (void)dev;
    (void)obj;
    return -EINVAL;
}

static int _id_inotify_add_watch(
    myst_inotifydev_t* dev,
    myst_inotify_t* obj,
    const char* pathname,
    uint32_t mask)
{
    (void)dev;
    (void)obj;
    (void)pathname;
    (void)mask;
    return -EINVAL;
}

static int _id_inotify_rm_watch(
    myst_inotifydev_t* dev,
    myst_inotify_t* obj,
    int wd)
{
    (void)dev;
    (void)obj;
    (void)wd;
    return -EINVAL;
}

myst_inotifydev_t* myst_inotifydev_get(void)
{
    // clang-format off
    static myst_inotifydev_t _pipdev =
    {
        {
            .fd_read = (void*)_id_read,
            .fd_write = (void*)_id_write,
            .fd_readv = (void*)_id_readv,
            .fd_writev = (void*)_id_writev,
            .fd_fstat = (void*)_id_fstat,
            .fd_fcntl = (void*)_id_fcntl,
            .fd_ioctl = (void*)_id_ioctl,
            .fd_dup = (void*)_id_dup,
            .fd_close = (void*)_id_close,
            .fd_target_fd = (void*)_id_target_fd,
            .fd_get_events = (void*)_id_get_events,
        },
        .id_inotify_init1 = _id_inotify_init1,
        .id_read = _id_read,
        .id_write = _id_write,
        .id_readv = _id_readv,
        .id_writev = _id_writev,
        .id_fstat = _id_fstat,
        .id_fcntl = _id_fcntl,
        .id_ioctl = _id_ioctl,
        .id_dup = _id_dup,
        .id_close = _id_close,
        .id_target_fd = _id_target_fd,
        .id_get_events = _id_get_events,
        .id_inotify_add_watch = _id_inotify_add_watch,
        .id_inotify_rm_watch = _id_inotify_rm_watch,
    };
    // clang-format on

    return &_pipdev;
}
