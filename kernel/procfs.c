// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <myst/eraise.h>
#include <myst/file.h>
#include <myst/fs.h>
#include <myst/kernel.h>
#include <myst/mmanutils.h>
#include <myst/mount.h>
#include <myst/printf.h>
#include <myst/process.h>
#include <myst/procfs.h>

static myst_fs_t* _procfs;

int procfs_setup()
{
    int ret = 0;
    char* fdpath = NULL;

    if (myst_init_ramfs(myst_mount_resolve, &_procfs) != 0)
    {
        myst_eprintf("failed initialize the proc file system\n");
        ERAISE(-EINVAL);
    }

    if (myst_mkdirhier("/proc", 777) != 0)
    {
        myst_eprintf("cannot create mount point for procfs\n");
        ERAISE(-EINVAL);
    }

    if (myst_mount(_procfs, "/", "/proc") != 0)
    {
        myst_eprintf("cannot mount proc file system\n");
        ERAISE(-EINVAL);
    }

    /* Create /proc/[pid]/fd directory for main thread */
    if (asprintf(&fdpath, "/proc/%d/fd", myst_getpid()) < 0)
    {
        myst_eprintf("%s(%u): out of memory\n", __FILE__, __LINE__);
        ERAISE(-ENOMEM);
    }

    if (myst_mkdirhier(fdpath, 777) != 0)
    {
        myst_eprintf("cannot create the /proc/[pid]/fd directory\n");
        ERAISE(-EINVAL);
    }

done:

    if (fdpath)
        free(fdpath);

    return ret;
}

int procfs_teardown()
{
    if ((*_procfs->fs_release)(_procfs) != 0)
    {
        myst_eprintf("failed to release procfs\n");
        return -1;
    }

    return 0;
}

int procfs_pid_cleanup(pid_t pid)
{
    int ret = 0;
    char* pid_dir_path = NULL;

    if (!pid)
        ERAISE(-EINVAL);

    if (asprintf(&pid_dir_path, "/%d", pid) < 0)
        ERAISE(-ENOMEM);

    ECHECK(myst_release_tree(_procfs, pid_dir_path));

done:

    if (pid_dir_path)
        free(pid_dir_path);

    return ret;
}

static int _meminfo_vcallback(myst_buf_t* vbuf)
{
    int ret = 0;
    size_t totalram;
    size_t freeram;

    ECHECK(myst_get_total_ram(&totalram));
    ECHECK(myst_get_free_ram(&freeram));

    myst_buf_clear(vbuf);
    char tmp[128];
    const size_t n = sizeof(tmp);
    snprintf(tmp, n, "MemTotal:       %lu\n", totalram);
    myst_buf_append(vbuf, tmp, strlen(tmp));
    snprintf(tmp, n, "MemFree:        %lu\n", freeram);
    myst_buf_append(vbuf, tmp, strlen(tmp));

done:
    return ret;
}

static int _self_vcallback(myst_buf_t* vbuf)
{
    int ret = 0;
    char* linkpath = NULL;

    if (asprintf(&linkpath, "/proc/%d", myst_getpid()) < 0)
        ERAISE(-ENOMEM);

    myst_buf_clear(vbuf);
    myst_buf_append(vbuf, linkpath, strlen(linkpath));

done:

    if (linkpath)
        free(linkpath);

    return ret;
}

int create_proc_root_entries()
{
    int ret = 0;

    /* Create /proc/meminfo */
    ECHECK(myst_create_virtual_file(
        _procfs, "/meminfo", S_IFREG, _meminfo_vcallback));

    /* Create /proc/self */
    ECHECK(
        myst_create_virtual_file(_procfs, "/self", S_IFLNK, _self_vcallback));

done:
    return ret;
}
