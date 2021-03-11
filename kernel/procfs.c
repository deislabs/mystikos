// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
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
    char fdpath[PATH_MAX];
    const size_t n = sizeof(fdpath);
    snprintf(fdpath, n, "/proc/%d/fd", myst_getpid());
    if (myst_mkdirhier(fdpath, 777) != 0)
    {
        myst_eprintf("cannot create the /proc/[pid]/fd directory\n");
        ERAISE(-EINVAL);
    }

done:
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
    char pid_exe_path[PATH_MAX];
    char pid_dir_path[PATH_MAX];

    if (!pid)
        ERAISE(-EINVAL);

    snprintf(pid_exe_path, sizeof(pid_exe_path), "/proc/%d/exe", pid);
    ECHECK(_procfs->fs_unlink(_procfs, pid_exe_path));

    snprintf(pid_dir_path, sizeof(pid_dir_path), "/proc/%d", pid);
    ECHECK(_procfs->fs_rmdir(_procfs, pid_exe_path));

done:
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
    char linkpath[PATH_MAX];
    const size_t n = sizeof(linkpath);
    snprintf(linkpath, n, "/proc/%d", myst_getpid());
    myst_buf_clear(vbuf);
    myst_buf_append(vbuf, linkpath, sizeof(linkpath));
    return 0;
}

int create_proc_root_entries()
{
    int ret;

    /* Create /proc/meminfo */
    ECHECK(myst_create_virtual_file(_procfs, "/meminfo", S_IFREG, _meminfo_vcallback));

    /* Create /proc/self */
    ECHECK(myst_create_virtual_file(_procfs, "/self", S_IFLNK, _self_vcallback));

done:
    return ret;
}