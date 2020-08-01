#include <stdlib.h>
#include <libos/realpath.h>
#include <libos/spinlock.h>
#include <string.h>
#include <libos/mount.h>
#include "eraise.h"
#include "eraise.h"

#define MOUNT_TABLE_SIZE 64

typedef struct mount_table_entry
{
    char* path;
    size_t path_size;
    libos_fs_t* fs;
    uint32_t flags;
} mount_table_entry_t;

static mount_table_entry_t _mount_table[MOUNT_TABLE_SIZE];
static size_t _mount_table_size = 0;
static libos_spinlock_t _lock = LIBOS_SPINLOCK_INITIALIZER;

static bool _installed_free_mount_table = false;

static void _free_mount_table(void)
{
    for (size_t i = 0; i < _mount_table_size; i++)
        free(_mount_table[i].path);
}

int libos_mount_resolve(
    const char* path,
    char suffix[PATH_MAX],
    libos_fs_t** fs_out)
{
    int ret = 0;
    size_t match_len = 0;
    libos_path_t realpath;
    bool locked = false;
    libos_fs_t* fs = NULL;

    if (fs_out)
        *fs_out = NULL;

    if (!path || !suffix)
        ERAISE(-EINVAL);

    /* Find the real path (the absolute non-relative path). */
    ECHECK(libos_realpath(path, &realpath));

    libos_spin_lock(&_lock);
    locked = true;

    /* Find the longest binding point that contains this path. */
    for (size_t i = 0; i < _mount_table_size; i++)
    {
        size_t len = strlen(_mount_table[i].path);
        const char* mpath = _mount_table[i].path;

        if (mpath[0] == '/' && mpath[1] == '\0')
        {
            if (len > match_len)
            {
                strlcpy(suffix, realpath.buf, PATH_MAX);
                match_len = len;
                fs = _mount_table[i].fs;
            }
        }
        else if (strncmp(mpath, realpath.buf, len) == 0 &&
            (realpath.buf[len] == '/' || realpath.buf[len] == '\0'))
        {
            if (len > match_len)
            {
                strlcpy(suffix, realpath.buf + len, PATH_MAX);

                if (*suffix == '\0')
                    strlcpy(suffix, "/", PATH_MAX);

                match_len = len;
                fs = _mount_table[i].fs;
            }
        }
    }

    if (locked)
    {
        libos_spin_unlock(&_lock);
        locked = false;
    }

    if (!fs)
        ERAISE(-ENOENT);

    *fs_out = fs;

done:

    if (locked)
        libos_spin_unlock(&_lock);

    return ret;
}

int libos_mount(libos_fs_t* fs, const char* target)
{
    int ret = -1;
    bool locked = false;
    libos_path_t target_buf;
    mount_table_entry_t mount_table_entry = {0};

    if (!fs || !target)
        ERAISE(-EINVAL);

    /* Normalize the target path */
    {
        ECHECK(libos_realpath(target, &target_buf));
        target = target_buf.buf;
    }

    /* Be sure the target directory exists (if not root) */
    if (strcmp(target, "/") != 0)
    {
        struct stat buf;
        char suffix[PATH_MAX];
        libos_fs_t* parent;

        /* Find the file system onto which the mount will occur */
        ECHECK(libos_mount_resolve(target, suffix, &parent));

        ECHECK((*parent->fs_stat)(parent, target, &buf));

        if (!S_ISDIR(buf.st_mode))
            ERAISE(-ENOTDIR);
    }

    /* Lock the mount table. */
    libos_spin_lock(&_lock);
    locked = true;

    /* Install _free_mount_table() if not already installed. */
    if (_installed_free_mount_table == false)
    {
        extern int oe_atexit(void (*function)(void));
        oe_atexit(_free_mount_table);
        _installed_free_mount_table = true;
    }

    /* Fail if mount table exhausted. */
    if (_mount_table_size == MOUNT_TABLE_SIZE)
        ERAISE(-ENOMEM);

    /* Reject duplicate mount paths. */
    for (size_t i = 0; i < _mount_table_size; i++)
    {
        if (strcmp(_mount_table[i].path, target) == 0)
            ERAISE(-EEXIST);
    }

    /* Assign and initialize new mount point. */
    {
        if (!(mount_table_entry.path = strdup(target)))
            ERAISE(-ENOMEM);

        mount_table_entry.path_size = strlen(target) + 1;
        mount_table_entry.fs = fs;
        mount_table_entry.flags = 0;
    }

    _mount_table[_mount_table_size++] = mount_table_entry;
    mount_table_entry.path = NULL;
    ret = 0;

done:

    if (mount_table_entry.path)
        free(mount_table_entry.path);

    if (locked)
        libos_spin_unlock(&_lock);

    return ret;
}
