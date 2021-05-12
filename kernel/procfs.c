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
static char* _cpuinfo_buf = NULL;

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

    /* Create pid specific entries for main thread */
    ECHECK(procfs_pid_setup(myst_getpid()));

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

    /* free cached cpuinfo information */
    free(_cpuinfo_buf);

    return 0;
}

int procfs_pid_setup(pid_t pid)
{
    int ret = 0;
    struct locals
    {
        char fdpath[PATH_MAX];
        char mapspath[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    /* Create /proc/[pid]/fd directory */
    {
        int n = snprintf(
            locals->fdpath, sizeof(locals->fdpath), "/proc/%d/fd", pid);

        if (n >= (int)sizeof(locals->fdpath))
            ERAISE(-ERANGE);

        ECHECK(myst_mkdirhier(locals->fdpath, 777));
    }

    /* maps entry */
    {
        int n = snprintf(
            locals->mapspath, sizeof(locals->mapspath), "/%d/maps", pid);

        if (n >= (int)sizeof(locals->mapspath))
            ERAISE(-ERANGE);

        myst_vcallback_t v_cb;
        v_cb.open_cb = proc_pid_maps_vcallback;
        ECHECK(myst_create_virtual_file(
            _procfs, locals->mapspath, S_IFREG | S_IRUSR, v_cb, OPEN));
    }

done:

    if (locals)
        free(locals);

    return ret;
}

int procfs_pid_cleanup(pid_t pid)
{
    int ret = 0;

    struct locals
    {
        char pid_dir_path[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    if (!pid)
        ERAISE(-EINVAL);

    snprintf(locals->pid_dir_path, sizeof(locals->pid_dir_path), "/%d", pid);
    ECHECK(myst_release_tree(_procfs, locals->pid_dir_path));

done:

    if (locals)
        free(locals);

    return ret;
}

static int _meminfo_vcallback(myst_buf_t* vbuf)
{
    int ret = 0;
    size_t totalram;
    size_t freeram;

    if (!vbuf)
        ERAISE(-EINVAL);

    ECHECK(myst_get_total_ram(&totalram));
    ECHECK(myst_get_free_ram(&freeram));

    myst_buf_clear(vbuf);
    char tmp[128];
    const size_t n = sizeof(tmp);
    snprintf(tmp, n, "MemTotal:       %lu\n", totalram);
    ECHECK(myst_buf_append(vbuf, tmp, strlen(tmp)));
    snprintf(tmp, n, "MemFree:        %lu\n", freeram);
    ECHECK(myst_buf_append(vbuf, tmp, strlen(tmp)));

done:

    if (ret != 0)
        myst_buf_release(vbuf);

    return ret;
}

static int _self_vcallback(myst_buf_t* vbuf)
{
    int ret = 0;
    struct locals
    {
        char linkpath[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!vbuf)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    const size_t n = sizeof(locals->linkpath);
    snprintf(locals->linkpath, n, "/proc/%d", myst_getpid());
    myst_buf_clear(vbuf);
    ECHECK(myst_buf_append(vbuf, locals->linkpath, sizeof(locals->linkpath)));

done:

    if (ret != 0)
        myst_buf_release(vbuf);

    if (locals)
        free(locals);

    return ret;
}

static int _cpuinfo_vcallback(myst_buf_t* vbuf)
{
    int ret = 0;

    if (!vbuf)
        ERAISE(-EINVAL);

    /* On first call, fetch cpuinfo from host and cache it */
    if (!_cpuinfo_buf)
    {
        int size = myst_tcall_cpuinfo_size();

        if (size <= 0)
            ERAISE(-EINVAL);

        // Linux x86 arch does not null terminate /proc/cpuinfo,
        // allocate extra byte for null termination character.
        if (!(_cpuinfo_buf = malloc(size + 1)))
            ERAISE(-ENOMEM);

        ECHECK(myst_tcall_get_cpuinfo(_cpuinfo_buf, size));
        _cpuinfo_buf[size] = 0;
    }

    myst_buf_clear(vbuf);
    ECHECK(myst_buf_append(vbuf, _cpuinfo_buf, strlen(_cpuinfo_buf) + 1));

done:

    return ret;
}

int create_proc_root_entries()
{
    int ret = 0;

    /* Create /proc/meminfo */
    {
        myst_vcallback_t v_cb;
        v_cb.open_cb = _meminfo_vcallback;
        ECHECK(myst_create_virtual_file(
            _procfs, "/meminfo", S_IFREG | S_IRUSR, v_cb, OPEN));
    }

    /* Create /proc/cpuinfo */
    {
        myst_vcallback_t v_cb;
        v_cb.open_cb = _cpuinfo_vcallback;
        ECHECK(myst_create_virtual_file(
            _procfs, "/cpuinfo", S_IFREG | S_IRUSR, v_cb, OPEN));
    }

    /* Create /proc/self */
    {
        myst_vcallback_t v_cb;
        v_cb.open_cb = _self_vcallback;
        ECHECK(myst_create_virtual_file(_procfs, "/self", S_IFLNK, v_cb, OPEN));
    }

done:
    return ret;
}
