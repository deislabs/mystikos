// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#include <myst/buf.h>
#include <myst/bufu64.h>
#include <myst/devfs.h>
#include <myst/eraise.h>
#include <myst/file.h>
#include <myst/fs.h>
#include <myst/mount.h>
#include <myst/panic.h>
#include <myst/printf.h>
#include <myst/ramfs.h>
#include <myst/tcall.h>

/*************************************
 * callbacks
 * ***********************************/
static int _ignore_read_cb(void* buf, size_t count)
{
    (void)buf;
    (void)count;

    return 0; // EOF
}

static int _ignore_write_cb(const void* buf, size_t count)
{
    (void)buf;
    (void)count;

    return count;
}

static int _zero_read_cb(void* buf, size_t count)
{
    ssize_t ret = 0;

    if (!buf && count)
        ERAISE(-EFAULT);

    if (!buf && !count)
        goto done;

    memset(buf, 0, count);

    ret = count;

done:
    return ret;
}

static int _urandom_read_cb(void* buf, size_t count)
{
    ssize_t ret = 0;

    if (!buf && count)
        ERAISE(-EFAULT);

    if (!buf && !count)
        return 0;

    if (myst_tcall_random(buf, count) != 0)
        ERAISE(-EIO);

    ret = (ssize_t)count;

done:
    return ret;
}

/*****************************
 * devfs setup and teardown
 * ***************************/

static myst_fs_t* _devfs;

int devfs_setup()
{
    int ret = 0;

    if (myst_init_ramfs(myst_mount_resolve, &_devfs) != 0)
    {
        myst_eprintf("failed initialize the dev file system\n");
        ERAISE(-EINVAL);
    }

    if (myst_mkdirhier("/dev", 777) != 0)
    {
        myst_eprintf("cannot create mount point for devfs\n");
        ERAISE(-EINVAL);
    }

    if (myst_mount(_devfs, "/", "/dev") != 0)
    {
        myst_eprintf("cannot mount dev file system\n");
        ERAISE(-EINVAL);
    }

    /* Create standard /dev files */

    /* /dev/urandom */
    {
        myst_vcallback_t v_cb;
        v_cb.rw_callbacks.read_cb = _urandom_read_cb;
        v_cb.rw_callbacks.write_cb = _ignore_write_cb;

        myst_create_virtual_file(
            _devfs, "/urandom", S_IFREG | S_IRUSR | S_IWUSR, v_cb, RW);
    }

    /* /dev/random - same as /dev/urandom */
    {
        myst_vcallback_t v_cb;
        v_cb.rw_callbacks.read_cb = _urandom_read_cb;
        v_cb.rw_callbacks.write_cb = _ignore_write_cb;

        myst_create_virtual_file(
            _devfs, "/random", S_IFREG | S_IRUSR | S_IWUSR, v_cb, RW);
    }

    /* /dev/null */
    {
        myst_vcallback_t v_cb;
        v_cb.rw_callbacks.read_cb = _ignore_read_cb;
        v_cb.rw_callbacks.write_cb = _ignore_write_cb;

        myst_create_virtual_file(
            _devfs, "/null", S_IFREG | S_IRUSR | S_IWUSR, v_cb, RW);
    }

    /* /dev/zero */
    {
        myst_vcallback_t v_cb;
        v_cb.rw_callbacks.read_cb = _zero_read_cb;
        v_cb.rw_callbacks.write_cb = _ignore_write_cb;

        myst_create_virtual_file(
            _devfs, "/zero", S_IFREG | S_IRUSR | S_IWUSR, v_cb, RW);
    }

    /* /dev/fd symlink */
    _devfs->fs_symlink(_devfs, "/proc/self/fd", "/fd");

done:
    return ret;
}

int devfs_teardown()
{
    if ((*_devfs->fs_release)(_devfs) != 0)
    {
        myst_eprintf("failed to release devfs\n");
        return -1;
    }

    return 0;
}
