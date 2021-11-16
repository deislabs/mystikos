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
#include <myst/syscall.h>
#include <myst/times.h>

static int _status_vcallback(
    myst_file_t* file,
    myst_buf_t* vbuf,
    const char* entrypath);
static int _pid_stat_vcallback(
    myst_file_t* file,
    myst_buf_t* vbuf,
    const char* entrypath);

static myst_fs_t* _procfs;
static char* _cpuinfo_buf = NULL;

static struct timespec monotime_at_boot_ts;

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

    myst_syscall_clock_gettime(CLOCK_MONOTONIC, &monotime_at_boot_ts);

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
        char tmp_path[PATH_MAX];
    };
    struct locals* locals = NULL;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    /* Create /proc/[pid]/fd directory */
    {
        ECHECK(myst_snprintf(
            locals->tmp_path, sizeof(locals->tmp_path), "/proc/%d/fd", pid));

        ECHECK(myst_mkdirhier(locals->tmp_path, 777));
    }

    /* maps entry */
    {
        ECHECK(myst_snprintf(
            locals->tmp_path, sizeof(locals->tmp_path), "/%d/maps", pid));

        myst_vcallback_t v_cb = {0};
        v_cb.open_cb = proc_pid_maps_vcallback;
        ECHECK(myst_create_virtual_file(
            _procfs, locals->tmp_path, S_IFREG | S_IRUSR, v_cb));
    }

    /* status entry */
    {
        ECHECK(myst_snprintf(
            locals->tmp_path, sizeof(locals->tmp_path), "/%d/status", pid));

        myst_vcallback_t v_cb = {0};
        v_cb.open_cb = _status_vcallback;
        ECHECK(myst_create_virtual_file(
            _procfs, locals->tmp_path, S_IFREG | S_IRUSR, v_cb));
    }

    /* stat entry */
    {
        ECHECK(myst_snprintf(
            locals->tmp_path, sizeof(locals->tmp_path), "/%d/stat", pid));

        myst_vcallback_t v_cb = {0};
        v_cb.open_cb = _pid_stat_vcallback;
        ECHECK(myst_create_virtual_file(
            _procfs, locals->tmp_path, S_IFREG | S_IRUSR, v_cb));
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
    ECHECK(_procfs->fs_release_tree(_procfs, locals->pid_dir_path));

done:

    if (locals)
        free(locals);

    return ret;
}

static int _meminfo_vcallback(
    myst_file_t* self,
    myst_buf_t* vbuf,
    const char* entrypath)
{
    (void)self;
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

static int _self_vcallback(
    myst_file_t* self,
    myst_buf_t* vbuf,
    const char* entrypath)
{
    (void)self;
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
static int _cpuinfo_vcallback(
    myst_file_t* self,
    myst_buf_t* vbuf,
    const char* entrypath)
{
    (void)self;
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

static int _stat_vcallback(
    myst_file_t* self,
    myst_buf_t* vbuf,
    const char* entrypath)
{
    (void)self;
    int ret = 0;

    (void)entrypath;

    if (!vbuf)
        ERAISE(-EINVAL);

    myst_buf_clear(vbuf);
    char tmp[128];
    const size_t n = sizeof(tmp);

    ECHECK(myst_snprintf(tmp, n, "cpu  0 0 0 0 0 0 0 0 0 0\n"));
    ECHECK(myst_buf_append(vbuf, tmp, strlen(tmp)));

    ECHECK(myst_snprintf(tmp, n, "intr 0\n"));
    ECHECK(myst_buf_append(vbuf, tmp, strlen(tmp)));

    ECHECK(myst_snprintf(tmp, n, "nctxt 0\n"));
    ECHECK(myst_buf_append(vbuf, tmp, strlen(tmp)));

    ECHECK(myst_snprintf(
        tmp, n, "btime %llu\n", __myst_kernel_args.start_time_sec));
    ECHECK(myst_buf_append(vbuf, tmp, strlen(tmp)));

    ECHECK(myst_snprintf(tmp, n, "processes 1\n"));
    ECHECK(myst_buf_append(vbuf, tmp, strlen(tmp)));

    ECHECK(
        myst_snprintf(tmp, n, "procs_running %llu\n", myst_get_num_threads()));
    ECHECK(myst_buf_append(vbuf, tmp, strlen(tmp)));

    ECHECK(myst_snprintf(tmp, n, "procs_blocked 0\n"));
    ECHECK(myst_buf_append(vbuf, tmp, strlen(tmp)));

    ECHECK(myst_snprintf(tmp, n, "softirq 0 0 0 0 0 0 0 0 0 0 0\n"));
    ECHECK(myst_buf_append(vbuf, tmp, strlen(tmp)));

done:

    if (ret != 0)
        myst_buf_release(vbuf);

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

static int _status_vcallback(
    myst_file_t* file,
    myst_buf_t* vbuf,
    const char* entrypath)
{
    (void)file;
    int ret = 0;
    struct locals
    {
        char status_path[PATH_MAX];
        char* _host_status_buf;
    };
    struct locals* locals = NULL;
    void* buf = NULL;
    size_t buf_size;
    myst_process_t* process;

    myst_spin_lock(&myst_process_list_lock);

    if (!(locals = calloc(1, sizeof(struct locals))))
        ERAISE(-ENOMEM);

    if (!vbuf || !entrypath)
        ERAISE(-EINVAL);

    process = myst_procfs_path_to_process(entrypath);

    if (process == NULL)
        ERAISE(-EINVAL);

    ECHECK(myst_snprintf(
        locals->status_path,
        sizeof(locals->status_path),
        STATUS_STR,
        process->main_process_thread->target_tid));

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
        tmp, sizeof(tmp), "Name:\t%s\n", process->main_process_thread->name));
    ECHECK(myst_buf_append(vbuf, tmp, strlen(tmp)));
    ECHECK(myst_snprintf(tmp, sizeof(tmp), "Umask:\t%#04o\n", process->umask));
    ECHECK(myst_buf_append(vbuf, tmp, strlen(tmp)));
    ECHECK(myst_snprintf(tmp, sizeof(tmp), "Tgid:\t%d\n", process->pid));
    ECHECK(myst_buf_append(vbuf, tmp, strlen(tmp)));
    ECHECK(myst_snprintf(tmp, sizeof(tmp), "Pid:\t%d\n", process->pid));
    ECHECK(myst_buf_append(vbuf, tmp, strlen(tmp)));
    ECHECK(myst_snprintf(tmp, sizeof(tmp), "PPid:\t%d\n", process->ppid));
    ECHECK(myst_buf_append(vbuf, tmp, strlen(tmp)));

    /* Mystikos doesn't know about the tracer process, so we return self pid if
     * the thread is being traced */
    ECHECK(myst_snprintf(
        tmp,
        sizeof(tmp),
        "TracerPid:\t%d\n",
        _is_process_traced(locals->_host_status_buf) ? process->pid : 0));
    ECHECK(myst_buf_append(vbuf, tmp, strlen(tmp)));

    ECHECK(myst_snprintf(
        tmp,
        sizeof(tmp),
        "Uid:\t%d\t%d\t%d\t%d\n",
        process->main_process_thread->uid,
        process->main_process_thread->euid,
        process->main_process_thread->savuid,
        process->main_process_thread->fsuid));
    ECHECK(myst_buf_append(vbuf, tmp, strlen(tmp)));
    ECHECK(myst_snprintf(
        tmp,
        sizeof(tmp),
        "Gid:\t%d\t%d\t%d\t%d\n",
        process->main_process_thread->gid,
        process->main_process_thread->egid,
        process->main_process_thread->savgid,
        process->main_process_thread->fsgid));
    ECHECK(myst_buf_append(vbuf, tmp, strlen(tmp)));

    /* TODO: memory, signal, capability and cpu related fields*/

done:

    myst_spin_unlock(&myst_process_list_lock);

    if (locals && locals->_host_status_buf)
        free(locals->_host_status_buf);

    if (locals)
        free(locals);

    if (buf)
        free(buf);

    return ret;
}

static char get_process_state(myst_process_t* process)
{
    if (myst_is_zombied_process(process))
        return 'Z';

    if (process->main_process_thread->signal.waiting_on_event)
        return 'S';

    // ATTN: Support other process states
    return 'R';
}

// clock ticks per second.
// ATTN: can be retrieved by sysconf(_SC_CLK_TCK) ?
#define TICK_RATE 100

static int _pid_stat_vcallback(
    myst_file_t* file,
    myst_buf_t* vbuf,
    const char* entrypath)
{
    (void)file;
    int ret = 0;
    myst_process_t* process;

    myst_spin_lock(&myst_process_list_lock);

    if (!vbuf || !entrypath)
        ERAISE(-EINVAL);

    process = myst_procfs_path_to_process(entrypath);

    if (process == NULL)
        ERAISE(-EINVAL);

    myst_buf_clear(vbuf);
    char tmp[128];

    ECHECK(myst_snprintf(
        tmp,
        sizeof(tmp),
        "%d (%s) %c %d %d %d ",
        process->pid,
        process->main_process_thread->name,
        get_process_state(process),
        process->ppid,
        process->pgid,
        process->sid));
    ECHECK(myst_buf_append(vbuf, tmp, strlen(tmp)));

    // tty_nr tpgid flags minflt cminflt majflt cmajflt
    ECHECK(myst_snprintf(tmp, sizeof(tmp), "0 0 0 0 0 0 0 "));
    ECHECK(myst_buf_append(vbuf, tmp, strlen(tmp)));

    // utime stime cutime cstime
    // ATTN: update utime stime once GH #688 is fixed.
    ECHECK(myst_snprintf(tmp, sizeof(tmp), "0 0 0 0 "));
    ECHECK(myst_buf_append(vbuf, tmp, strlen(tmp)));

    // priority nice num_threads itrealvalue
    ECHECK(myst_snprintf(tmp, sizeof(tmp), "0 0 0 0 "));
    ECHECK(myst_buf_append(vbuf, tmp, strlen(tmp)));

    {
        // starttime = proc start time - kernel boot time, in ticks
        // Assuming 100 clock ticks/sec
        long pst = timespec_to_nanos(&process->main_process_thread->start_ts);
        long kbt = timespec_to_nanos(&monotime_at_boot_ts);
        long diff_in_ticks = (pst - kbt) / (NANO_IN_SECOND / TICK_RATE);

        // starttime vsize rss rsslim
        ECHECK(myst_snprintf(tmp, sizeof(tmp), "%llu 0 0 0 ", diff_in_ticks));
        ECHECK(myst_buf_append(vbuf, tmp, strlen(tmp)));
    }

    // startcode endcode startstack kstkesp kstkeip
    ECHECK(myst_snprintf(tmp, sizeof(tmp), "0 0 0 0 0 "));
    ECHECK(myst_buf_append(vbuf, tmp, strlen(tmp)));

    // signal blocked sigignore sigcatch
    ECHECK(myst_snprintf(
        tmp,
        sizeof(tmp),
        "%lu %lu 0 0 ",
        process->main_process_thread->signal.pending,
        process->main_process_thread->signal.mask));
    ECHECK(myst_buf_append(vbuf, tmp, strlen(tmp)));

    // wchan nswap cnswap exit_signal processor rt_priority
    // policy delayacct_blkio_ticks guest_time cguest_time
    ECHECK(myst_snprintf(tmp, sizeof(tmp), "0 0 0 0 0 0 0 0 0 0 "));
    ECHECK(myst_buf_append(vbuf, tmp, strlen(tmp)));

    // start_data end_data start_brk arg_start arg_end
    // env_start env_end exit_code
    ECHECK(myst_snprintf(
        tmp, sizeof(tmp), "0 0 0 0 0 0 0 %d\n", process->exit_status));
    ECHECK(myst_buf_append(vbuf, tmp, strlen(tmp)));

done:

    myst_spin_unlock(&myst_process_list_lock);

    return ret;
}

int create_proc_root_entries()
{
    int ret = 0;

    /* Create /proc/meminfo */
    {
        myst_vcallback_t v_cb = {0};
        v_cb.open_cb = _meminfo_vcallback;
        ECHECK(myst_create_virtual_file(
            _procfs, "/meminfo", S_IFREG | S_IRUSR, v_cb));
    }

    /* Create /proc/cpuinfo */
    {
        myst_vcallback_t v_cb = {0};
        v_cb.open_cb = _cpuinfo_vcallback;
        ECHECK(myst_create_virtual_file(
            _procfs, "/cpuinfo", S_IFREG | S_IRUSR, v_cb));
    }

    /* Create /proc/self */
    {
        myst_vcallback_t v_cb = {0};
        v_cb.open_cb = _self_vcallback;
        ECHECK(myst_create_virtual_file(_procfs, "/self", S_IFLNK, v_cb));
    }

    /* Create /proc/stat */
    {
        myst_vcallback_t v_cb = {0};
        v_cb.open_cb = _stat_vcallback;
        ECHECK(myst_create_virtual_file(
            _procfs, "/stat", S_IFREG | S_IRUSR, v_cb));
    }

done:
    return ret;
}

myst_process_t* myst_procfs_path_to_process(const char* entrypath)
{
    myst_process_t* ret = NULL;
    int pid = 0;
    char** toks = NULL;
    size_t ntoks = 0;
    char* path_copy = strdup(entrypath);

    if (path_copy == NULL)
        goto done;

    if (myst_strsplit(path_copy, "/", &toks, &ntoks) != 0)
        goto done;

    /* path should atleast contain pid and leaf entry */
    assert(ntoks >= 2);
    pid = atoi(toks[0]);

    ret = myst_find_process_from_pid(pid, true);

done:

    if (path_copy)
        free(path_copy);

    if (toks)
        free(toks);

    return ret;
}
