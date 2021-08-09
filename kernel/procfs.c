// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <myst/eraise.h>
#include <myst/file.h>
#include <myst/fs.h>
#include <myst/hostfile.h>
#include <myst/kernel.h>
#include <myst/mmanutils.h>
#include <myst/mount.h>
#include <myst/printf.h>
#include <myst/process.h>
#include <myst/procfs.h>
#include <myst/strings.h>
#include <myst/times.h>

static int _status_vcallback(myst_buf_t* vbuf, char* entrypath);
static int _stat_vcallback(myst_buf_t* vbuf, char* entrypath);

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

    ECHECK(set_overrides_for_special_fs(_procfs));

    if (myst_mkdirhier("/proc", 777) != 0)
    {
        myst_eprintf("cannot create mount point for procfs\n");
        ERAISE(-EINVAL);
    }

    if (myst_mount(_procfs, "/", "/proc", false) != 0)
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
        char statuspath[PATH_MAX];
        char statpath[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    /* Create /proc/[pid]/fd directory */
    {
        ECHECK(myst_snprintf(
            locals->fdpath, sizeof(locals->fdpath), "/proc/%d/fd", pid));

        ECHECK(myst_mkdirhier(locals->fdpath, 777));
    }

    /* maps entry */
    {
        ECHECK(myst_snprintf(
            locals->mapspath, sizeof(locals->mapspath), "/%d/maps", pid));

        myst_vcallback_t v_cb;
        v_cb.open_cb = proc_pid_maps_vcallback;
        ECHECK(myst_create_virtual_file(
            _procfs, locals->mapspath, S_IFREG | S_IRUSR, v_cb, OPEN));
    }

    /* status entry */
    {
        ECHECK(myst_snprintf(
            locals->statuspath, sizeof(locals->statuspath), "/%d/status", pid));

        myst_vcallback_t v_cb;
        v_cb.open_cb = _status_vcallback;
        ECHECK(myst_create_virtual_file(
            _procfs, locals->statuspath, S_IFREG | S_IRUSR, v_cb, OPEN));
    }

    /* stat entry */
    {
        ECHECK(myst_snprintf(
            locals->statpath, sizeof(locals->statpath), "/%d/stat", pid));

        myst_vcallback_t v_cb;
        v_cb.open_cb = _stat_vcallback;
        ECHECK(myst_create_virtual_file(
            _procfs, locals->statpath, S_IFREG | S_IRUSR, v_cb, OPEN));
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

    ECHECK(myst_snprintf(
        locals->pid_dir_path, sizeof(locals->pid_dir_path), "/%d", pid));
    ECHECK(myst_release_tree(_procfs, locals->pid_dir_path));

done:

    if (locals)
        free(locals);

    return ret;
}

static int _meminfo_vcallback(myst_buf_t* vbuf, char* entrypath)
{
    int ret = 0;
    size_t totalram;
    size_t freeram;
    size_t cached = 0;

    (void)entrypath;

    if (!vbuf)
        ERAISE(-EINVAL);

    ECHECK(myst_get_total_ram(&totalram));
    ECHECK(myst_get_free_ram(&freeram));

    myst_buf_clear(vbuf);
    char tmp[128];
    const size_t n = sizeof(tmp);
    ECHECK(myst_snprintf(tmp, n, "MemTotal:       %lu\n", totalram));
    ECHECK(myst_buf_append(vbuf, tmp, strlen(tmp)));
    ECHECK(myst_snprintf(tmp, n, "MemFree:        %lu\n", freeram));
    ECHECK(myst_buf_append(vbuf, tmp, strlen(tmp)));
    ECHECK(myst_snprintf(tmp, n, "Cached:         %lu\n", cached));
    ECHECK(myst_buf_append(vbuf, tmp, strlen(tmp)));

done:

    if (ret != 0)
        myst_buf_release(vbuf);

    return ret;
}

static int _self_vcallback(myst_buf_t* vbuf, char* entrypath)
{
    int ret = 0;
    struct locals
    {
        char linkpath[PATH_MAX];
    };
    struct locals* locals = NULL;

    (void)entrypath;

    if (!vbuf)
        ERAISE(-EINVAL);

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    const size_t n = sizeof(locals->linkpath);
    ECHECK(myst_snprintf(locals->linkpath, n, "/proc/%d", myst_getpid()));
    myst_buf_clear(vbuf);
    ECHECK(myst_buf_append(vbuf, locals->linkpath, sizeof(locals->linkpath)));

done:

    if (ret != 0)
        myst_buf_release(vbuf);

    if (locals)
        free(locals);

    return ret;
}

#define CPUINFO_STR "/proc/cpuinfo"
static int _cpuinfo_vcallback(myst_buf_t* vbuf, char* entrypath)
{
    int ret = 0;
    void* buf = NULL;
    size_t buf_size;

    (void)entrypath;

    if (!vbuf)
        ERAISE(-EINVAL);

    /* On first call, fetch cpuinfo from host and cache it */
    if (!_cpuinfo_buf)
    {
        ECHECK(myst_load_host_file(CPUINFO_STR, &buf, &buf_size));

        if (buf_size <= 0)
            ERAISE(-EINVAL);

        _cpuinfo_buf = buf;
        buf = NULL;
    }

    myst_buf_clear(vbuf);
    ECHECK(myst_buf_append(vbuf, _cpuinfo_buf, strlen(_cpuinfo_buf) + 1));

done:

    if (buf)
        free(buf);

    return ret;
}

#define STATUS_STR "/proc/%d/status"

static int _is_process_traced(char* host_status_buf)
{
    assert(host_status_buf);

    char* token;
    char* save;
    const char TracerPid[] = "TracerPid:";

    token = strtok_r(host_status_buf, "\n", &save);

    while (token != NULL)
    {
        if (strspn(token, TracerPid) == (sizeof(TracerPid) - 1))
        {
            char* tracer_pid = token + sizeof(TracerPid) - 1;
            return atoi(tracer_pid);
        }

        token = strtok_r(NULL, "\n", &save);
    }
    return 0;
}

static int _status_vcallback(myst_buf_t* vbuf, char* entrypath)
{
    int ret = 0;
    struct locals
    {
        char status_path[PATH_MAX];
        myst_thread_t* curr_thread;
        myst_thread_t* curr_process_thread;
        char* _host_status_buf;
    };
    struct locals* locals = NULL;
    void* buf = NULL;
    size_t buf_size;

    (void)entrypath;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    if (!vbuf)
        ERAISE(-EINVAL);

    locals->curr_thread = myst_thread_self();
    locals->curr_process_thread = myst_find_process_thread(locals->curr_thread);

    ECHECK(myst_snprintf(
        locals->status_path,
        sizeof(locals->status_path),
        STATUS_STR,
        locals->curr_thread->target_tid));

    /* load the file into memory */
    {
        ECHECK(myst_load_host_file(locals->status_path, &buf, &buf_size));

        if (buf_size <= 0)
            ERAISE(-EINVAL);

        locals->_host_status_buf = buf;
        buf = NULL;
    }

    myst_buf_clear(vbuf);
    char tmp[128];

    ECHECK(myst_snprintf(
        tmp, sizeof(tmp), "Name:\t%s\n", locals->curr_thread->name));
    ECHECK(myst_buf_append(vbuf, tmp, strlen(tmp)));
    ECHECK(myst_snprintf(
        tmp,
        sizeof(tmp),
        "Umask:\t%#04o\n",
        locals->curr_process_thread->main.umask));
    ECHECK(myst_buf_append(vbuf, tmp, strlen(tmp)));
    ECHECK(myst_snprintf(
        tmp, sizeof(tmp), "Tgid:\t%d\n", locals->curr_thread->pid));
    ECHECK(myst_buf_append(vbuf, tmp, strlen(tmp)));
    ECHECK(myst_snprintf(
        tmp, sizeof(tmp), "Pid:\t%d\n", locals->curr_thread->pid));
    ECHECK(myst_buf_append(vbuf, tmp, strlen(tmp)));
    ECHECK(myst_snprintf(
        tmp, sizeof(tmp), "PPid:\t%d\n", locals->curr_thread->ppid));
    ECHECK(myst_buf_append(vbuf, tmp, strlen(tmp)));

    /* Mystikos doesn't know about the tracer process, so we return self pid if
     * the thread is being traced */
    ECHECK(myst_snprintf(
        tmp,
        sizeof(tmp),
        "TracerPid:\t%d\n",
        _is_process_traced(locals->_host_status_buf) ? locals->curr_thread->pid
                                                     : 0));
    ECHECK(myst_buf_append(vbuf, tmp, strlen(tmp)));

    ECHECK(myst_snprintf(
        tmp,
        sizeof(tmp),
        "Uid:\t%d\t%d\t%d\t%d\n",
        locals->curr_thread->uid,
        locals->curr_thread->euid,
        locals->curr_thread->savuid,
        locals->curr_thread->fsuid));
    ECHECK(myst_buf_append(vbuf, tmp, strlen(tmp)));
    ECHECK(myst_snprintf(
        tmp,
        sizeof(tmp),
        "Gid:\t%d\t%d\t%d\t%d\n",
        locals->curr_thread->gid,
        locals->curr_thread->egid,
        locals->curr_thread->savgid,
        locals->curr_thread->fsgid));
    ECHECK(myst_buf_append(vbuf, tmp, strlen(tmp)));

    /* TODO: memory, signal, capability and cpu related fields*/

done:
    if (locals && locals->_host_status_buf)
        free(locals->_host_status_buf);

    if (locals)
        free(locals);

    if (buf)
        free(buf);

    return ret;
}

static int parse_pid(char* entrypath)
{
    int ret = 0;
    char** toks = NULL;
    size_t ntoks = 0;
    /* Split the path into tokens */
    ECHECK(myst_strsplit(entrypath, "/", &toks, &ntoks));

    assert(ntoks >= 2);
    ret = atoi(toks[0]);

done:
    if (toks)
        free(toks);
    return ret;
}

static int _stat_vcallback(myst_buf_t* vbuf, char* entrypath)
{
    int ret = 0;
    struct locals
    {
        myst_thread_t* process_thread;
    };
    struct locals* locals = NULL;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    if (!vbuf)
        ERAISE(-EINVAL);

    locals->process_thread = myst_find_thread(parse_pid(entrypath));
    assert(myst_is_process_thread(locals->process_thread));

    myst_buf_clear(vbuf);
    char tmp[128];

    ECHECK(myst_snprintf(
        tmp,
        sizeof(tmp),
        "%d (%s) V %d %d %d ",
        locals->process_thread->pid,
        locals->process_thread->name,
        // state
        locals->process_thread->ppid,
        locals->process_thread->main.pgid,
        locals->process_thread->sid));
    ECHECK(myst_buf_append(vbuf, tmp, strlen(tmp)));

    // tty_nr tpgid flags minflt cminflt majflt cmajflt
    ECHECK(myst_snprintf(tmp, sizeof(tmp), "0 0 0 0 0 0 0 "));
    ECHECK(myst_buf_append(vbuf, tmp, strlen(tmp)));

    // utime stime cutime cstime
    ECHECK(myst_snprintf(tmp, sizeof(tmp), "0 0 0 0 "));
    ECHECK(myst_buf_append(vbuf, tmp, strlen(tmp)));

    // priority nice num_threads itrealvalue
    ECHECK(myst_snprintf(tmp, sizeof(tmp), "0 0 0 0 "));
    ECHECK(myst_buf_append(vbuf, tmp, strlen(tmp)));

    // starttime vsize rss rsslim
    ECHECK(myst_snprintf(
        tmp,
        sizeof(tmp),
        "%llu 0 0 0 ",
        timespec_to_nanos(&locals->process_thread->start_ts)));
    ECHECK(myst_buf_append(vbuf, tmp, strlen(tmp)));

    // startcode endcode startstack kstkesp kstkeip
    ECHECK(myst_snprintf(tmp, sizeof(tmp), "0 0 0 0 0 "));
    ECHECK(myst_buf_append(vbuf, tmp, strlen(tmp)));

    // signal blocked sigignore sigcatch
    ECHECK(myst_snprintf(tmp, sizeof(tmp), "0 0 0 0 "));
    ECHECK(myst_buf_append(vbuf, tmp, strlen(tmp)));

    // wchan nswap cnswap exit_signal processor rt_priority
    // policy delayacct_blkio_ticks guest_time cguest_time
    ECHECK(myst_snprintf(tmp, sizeof(tmp), "0 0 0 0 0 0 0 0 0 0 "));
    ECHECK(myst_buf_append(vbuf, tmp, strlen(tmp)));

    // start_data end_data start_brk arg_start arg_end
    // env_start env_end exit_code
    ECHECK(myst_snprintf(tmp, sizeof(tmp), "0 0 0 0 0 0 0 0\n"));
    ECHECK(myst_buf_append(vbuf, tmp, strlen(tmp)));

done:

    if (locals)
        free(locals);

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
