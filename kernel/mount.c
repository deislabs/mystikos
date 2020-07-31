#include "mount.h"
#include "eraise.h"
#include <libos/spinlock.h>

#if 0

#define MOUNT_TABLE_SIZE 64

typedef struct _mount_point
{
    char* path;
    size_t path_size;
    libos_fs_t* fs;
    uint32_t flags;
} mount_point_t;

static mount_point_t _mount_table[MOUNT_TABLE_SIZE];
size_t _mount_table_size = 0;
static libos_spinlock_t _lock = LIBOS_SPINLOCK_INITIALIZER;

static bool _installed_free_mount_table = false;

static void _free_mount_table(void)
{
    for (size_t i = 0; i < _mount_table_size; i++)
        libos_free(_mount_table[i].path);
}

int libos_mount_resolve(
    const char* path,
    char suffix[PATH_MAX],
    libos_fs_t** fs)
{
    int ret = 0;
    size_t match_len = 0;
    libos_syscall_path_t realpath;
    bool locked = false;

    if (fs)
        *fs = NULL;

    if (!path || !suffix)
        ERAISE(EINVAL);

    /* Find the real path (the absolute non-relative path). */
    if (!libos_realpath(path, &realpath))
        OE_RAISE_ERRNO(libos_errno);

    libos_spin_lock(&_lock);
    locked = true;

    /* Find the longest binding point that contains this path. */
    for (size_t i = 0; i < _mount_table_size; i++)
    {
        size_t len = libos_strlen(_mount_table[i].path);
        const char* mpath = _mount_table[i].path;

        if (mpath[0] == '/' && mpath[1] == '\0')
        {
            if (len > match_len)
            {
                libos_strlcpy(suffix, realpath.buf, OE_PATH_MAX);
                match_len = len;
                ret = _mount_table[i].fs;
            }
        }
        else if (
            libos_strncmp(mpath, realpath.buf, len) == 0 &&
            (realpath.buf[len] == '/' || realpath.buf[len] == '\0'))
        {
            if (len > match_len)
            {
                libos_strlcpy(suffix, realpath.buf + len, OE_PATH_MAX);

                if (*suffix == '\0')
                    libos_strlcpy(suffix, "/", OE_PATH_MAX);

                match_len = len;
                ret = _mount_table[i].fs;
            }
        }
    }

    if (locked)
    {
        libos_spin_unlock(&_lock);
        locked = false;
    }

    if (!ret)
        OE_RAISE_ERRNO_MSG(OE_ENOENT, "path=%s", path);

done:

    if (locked)
        libos_spin_unlock(&_lock);

    return ret;
}

int libos_mount(
    const char* source,
    const char* target,
    const char* filesystemtype,
    unsigned long mountflags,
    const void* data)
{
    int ret = -1;
    libos_fs_t* device = NULL;
    libos_fs_t* new_device = NULL;
    bool locked = false;
    libos_syscall_path_t target_path;
    mount_point_t mount_point = {0};

    if (!target || !filesystemtype)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Normalize the target path. */
    {
        if (!libos_realpath(target, &target_path))
            OE_RAISE_ERRNO(OE_EINVAL);

        target = target_path.buf;
    }

    /* Note: Normalization of source path is left to the external device
     * as it may not be a path internal to the enclave.
     */

    /* Resolve the device for the given filesystemtype. */
    device = libos_fs_table_find(filesystemtype, OE_DEVICE_TYPE_FILE_SYSTEM);
    if (!device)
        OE_RAISE_ERRNO_MSG(OE_ENODEV, "filesystemtype=%s", filesystemtype);

    /* Be sure the full_target directory exists (if not root). */
    if (libos_strcmp(target, "/") != 0)
    {
        struct libos_stat_t buf;
        int retval = -1;

        /**
         * libos_stat tries to do a mount resolution, but the directory is not yet
         * mounted. As a result, we must call the filesystem's stat
         * implementation directly.
         */
        if ((retval = device->ops.fs.stat(device, target, &buf)) != 0)
            OE_RAISE_ERRNO(libos_errno);

        if (!OE_S_ISDIR(buf.st_mode))
            OE_RAISE_ERRNO(OE_ENOTDIR);
    }

    /* Lock the mount table. */
    libos_spin_lock(&_lock);
    locked = true;

    /* Install _free_mount_table() if not already installed. */
    if (_installed_free_mount_table == false)
    {
        libos_atexit(_free_mount_table);
        _installed_free_mount_table = true;
    }

    /* Fail if mount table exhausted. */
    if (_mount_table_size == MOUNT_TABLE_SIZE)
        OE_RAISE_ERRNO(OE_ENOMEM);

    /* Reject duplicate mount paths. */
    for (size_t i = 0; i < _mount_table_size; i++)
    {
        if (libos_strcmp(_mount_table[i].path, target) == 0)
            OE_RAISE_ERRNO(OE_EEXIST);
    }

    /* Clone the device. */
    if (device->ops.fs.clone(device, &new_device) != 0)
        OE_RAISE_ERRNO(libos_errno);

    /* Assign and initialize new mount point. */
    {
        if (!(mount_point.path = libos_strdup(target)))
            OE_RAISE_ERRNO(OE_ENOMEM);

        mount_point.path_size = libos_strlen(target) + 1;
        mount_point.fs = new_device;
        mount_point.flags = 0;
    }

    /* Notify the device that it has been mounted. */
    if (new_device->ops.fs.mount(
            new_device, source, target, filesystemtype, mountflags, data) != 0)
    {
        goto done;
    }

    _mount_table[_mount_table_size++] = mount_point;
    new_device = NULL;
    mount_point.path = NULL;
    ret = 0;

done:

    if (mount_point.path)
        libos_free(mount_point.path);

    if (locked)
        libos_spin_unlock(&_lock);

    if (new_device)
        new_device->ops.device.release(new_device);

    return ret;
}

#endif
