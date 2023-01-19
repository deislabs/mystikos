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
#include <myst/lockfs.h>
#include <myst/mount.h>
#include <myst/panic.h>
#include <myst/printf.h>
#include <myst/ramfs.h>
#include <myst/tcall.h>

static myst_fs_t* _devfs;

struct pty_pair
{
    char* path_master;
    char* path_slave;
    myst_file_t* file_master;
    myst_file_t* file_slave;
    int slaveID;
    struct pty_pair* next;
};

static struct pty_pair* _pty_pairs = NULL;

static int _nextSlaveID = 0;

/*************************************
 * callbacks
 * ***********************************/
static int _ignore_read_cb(myst_file_t* self, void* buf, size_t count)
{
    (void)self;
    (void)buf;
    (void)count;

    return 0; // EOF
}

static int _ignore_write_cb(myst_file_t* self, const void* buf, size_t count)
{
    (void)self;
    (void)buf;
    (void)count;

    return count;
}

static int _zero_read_cb(myst_file_t* self, void* buf, size_t count)
{
    (void)self;
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

static int _urandom_read_cb(myst_file_t* self, void* buf, size_t count)
{
    (void)self;
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

static struct pty_pair* _find_paired_master_by_path(const char* path)
{
    for (struct pty_pair* tmp = _pty_pairs; tmp; tmp = tmp->next)
    {
        if (strcmp(path, tmp->path_slave) == 0)
            return tmp;
    }
    return NULL;
}

static int _open_slave_pty_cb(
    myst_file_t* file,
    myst_buf_t* buf,
    const char* path)
{
    (void)buf;
    int ret = 0;
    // find the paired master based on path
    struct pty_pair* pair = _find_paired_master_by_path(path);
    if (pair == NULL)
        ERAISE(-ENXIO);
    pair->file_slave = file;

done:
    return ret;
}

static int _close_pty_file_cb(myst_file_t* file)
{
    int ret = 0;
    // free the pair
    struct pty_pair* prev = NULL;
    for (struct pty_pair* tmp = _pty_pairs; tmp; tmp = tmp->next)
    {
        if (tmp->file_master == file || tmp->file_slave == file)
        {
            if (prev)
                prev->next = tmp->next;
            else
                _pty_pairs = _pty_pairs->next;

            free(tmp->path_master);
            free(tmp->path_slave);
            free(tmp);
            break;
        }
        prev = tmp;
    }

    return ret;
}

static int _read_master_pty_cb(myst_file_t* file, void* buf, size_t count)
{
    int ret = 0;
    for (struct pty_pair* tmp = _pty_pairs; tmp; tmp = tmp->next)
    {
        if (tmp->file_master == file)
        {
            ret = myst_read_stateful_virtual_file(tmp->file_slave, buf, count);
            goto done;
        }
    }

    ERAISE(-EINVAL); /* can't find the paired slave PTY device */

done:
    return ret;
}

static int _read_slave_pty_cb(myst_file_t* file, void* buf, size_t count)
{
    int ret = 0;
    for (struct pty_pair* tmp = _pty_pairs; tmp; tmp = tmp->next)
    {
        if (tmp->file_slave == file)
        {
            ret = myst_read_stateful_virtual_file(tmp->file_master, buf, count);
            goto done;
        }
    }
    ERAISE(-EINVAL); /* can't find the paired master PTY device */

done:
    return ret;
}

static int _write_pty_cb(myst_file_t* file, const void* buf, size_t count)
{
    return myst_write_stateful_virtual_file(file, buf, count);
}

static int _open_master_pty_cb(
    myst_file_t* file,
    myst_buf_t* buf,
    const char* path)
{
    (void)buf;
    int ret = 0;
    char tmp[64];
    myst_vcallback_t v_cb = {0};
    struct pty_pair* pair = calloc(1, sizeof(struct pty_pair));
    if (pair == NULL)
        ERAISE(-ENOMEM);

    if ((pair->path_master = strdup(path)) == NULL)
        ERAISE(-ENOMEM);

    pair->slaveID = _nextSlaveID++;
    snprintf(tmp, sizeof(tmp), "/pts/%d", pair->slaveID);

    if ((pair->path_slave = strdup(tmp)) == NULL)
        ERAISE(-ENOMEM);

    pair->file_master = file;
    pair->next = _pty_pairs;
    _pty_pairs = pair;

    v_cb.open_cb = _open_slave_pty_cb;
    v_cb.close_cb = _close_pty_file_cb;
    v_cb.read_cb = _read_slave_pty_cb;
    v_cb.write_cb = _write_pty_cb;

    ECHECK(myst_create_virtual_file(
        _devfs, tmp, S_IFCHR | S_IRUSR | S_IWUSR, v_cb));

done:
    return ret;
}
/*****************************
 * devfs setup and teardown
 * ***************************/
int devfs_setup()
{
    int ret = 0;

    if (myst_init_ramfs(myst_mount_resolve, &_devfs, RAMFS_DEVFS) != 0)
    {
        myst_eprintf("failed initialize the dev file system\n");
        ERAISE(-EINVAL);
    }

    ECHECK(set_overrides_for_special_fs(_devfs));

    if (myst_mkdirhier("/dev", 0777) != 0)
    {
        myst_eprintf("cannot create mount point for devfs\n");
        ERAISE(-EINVAL);
    }

    if (myst_mount(_devfs, "/", "/dev", false) != 0)
    {
        myst_eprintf("cannot mount dev file system\n");
        ERAISE(-EINVAL);
    }

    /* Create standard /dev files */
    ECHECK(myst_mkdirhier("/dev/pts", 0777));

    /* /dev/urandom */
    {
        myst_vcallback_t v_cb = {0};
        v_cb.read_cb = _urandom_read_cb;
        v_cb.write_cb = _ignore_write_cb;

        myst_create_virtual_file(
            _devfs, "/urandom", S_IFCHR | S_IRUSR | S_IWUSR, v_cb);
    }

    /* /dev/random - same as /dev/urandom */
    {
        myst_vcallback_t v_cb = {0};
        v_cb.read_cb = _urandom_read_cb;
        v_cb.write_cb = _ignore_write_cb;

        myst_create_virtual_file(
            _devfs, "/random", S_IFCHR | S_IRUSR | S_IWUSR, v_cb);
    }

    /* /dev/null */
    {
        myst_vcallback_t v_cb = {0};
        v_cb.read_cb = _ignore_read_cb;
        v_cb.write_cb = _ignore_write_cb;

        myst_create_virtual_file(
            _devfs, "/null", S_IFCHR | S_IRUSR | S_IWUSR, v_cb);
    }

    /* /dev/zero */
    {
        myst_vcallback_t v_cb = {0};
        v_cb.read_cb = _zero_read_cb;
        v_cb.write_cb = _ignore_write_cb;

        myst_create_virtual_file(
            _devfs, "/zero", S_IFCHR | S_IRUSR | S_IWUSR, v_cb);
    }

    /* /dev/ptmx */
    {
        myst_vcallback_t v_cb = {0};
        v_cb.open_cb = _open_master_pty_cb;
        v_cb.close_cb = _close_pty_file_cb;
        v_cb.read_cb = _read_master_pty_cb;
        v_cb.write_cb = _write_pty_cb;

        myst_create_virtual_file(
            _devfs, "/ptmx", S_IFCHR | S_IRUSR | S_IWUSR, v_cb);
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

int devfs_get_pts_id(myst_file_t* file, int* id)
{
    for (struct pty_pair* tmp = _pty_pairs; tmp; tmp = tmp->next)
    {
        if (tmp->file_master == file)
        {
            *id = tmp->slaveID;
            return 0;
        }
    }
    return -ENOENT;
}

bool devfs_is_pty_pts_device(myst_file_t* file)
{
    for (struct pty_pair* tmp = _pty_pairs; tmp; tmp = tmp->next)
    {
        if (tmp->file_master == file || tmp->file_slave == file)
            return true;
    }
    return false;
}
