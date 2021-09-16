// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <myst/atexit.h>
#include <myst/clock.h>
#include <myst/cpio.h>
#include <myst/crash.h>
#include <myst/debugmalloc.h>
#include <myst/devfs.h>
#include <myst/eraise.h>
#include <myst/errno.h>
#include <myst/exec.h>
#include <myst/fdtable.h>
#include <myst/file.h>
#include <myst/fs.h>
#include <myst/fsgs.h>
#include <myst/hex.h>
#include <myst/hostfile.h>
#include <myst/hostfs.h>
#include <myst/id.h>
#include <myst/initfini.h>
#include <myst/kernel.h>
#include <myst/listener.h>
#include <myst/mmanutils.h>
#include <myst/mount.h>
#include <myst/options.h>
#include <myst/panic.h>
#include <myst/printf.h>
#include <myst/process.h>
#include <myst/procfs.h>
#include <myst/pubkey.h>
#include <myst/ramfs.h>
#include <myst/signal.h>
#include <myst/strings.h>
#include <myst/syscall.h>
#include <myst/thread.h>
#include <myst/time.h>
#include <myst/times.h>
#include <myst/tlscert.h>
#include <myst/trace.h>
#include <myst/ttydev.h>
#include <myst/uid_gid.h>

static myst_fs_t* _fs;

long myst_tcall(long n, long params[6])
{
    void* fs = NULL;

    if (__options.have_syscall_instruction)
    {
        fs = myst_get_fsbase();
        myst_set_fsbase(myst_get_gsbase());
    }

    long ret = (__myst_kernel_args.tcall)(n, params);

    if (fs)
        myst_set_fsbase(fs);

    return ret;
}

static int _process_mount_configuration(myst_mounts_config_t* mounts)
{
    size_t i;
    int ret = 0;

    /* TARGETS MUST VALIDATE CONFIGURATION BEFORE ENTERING KERNEL BY
     * CALLING myst_validate_mount_config(
     */

    for (i = 0; i < mounts->mounts_count; i++)
    {
        ret = myst_syscall_mount(
            mounts->mounts[i].source,
            mounts->mounts[i].target,
            mounts->mounts[i].fs_type,
            0,
            NULL,
            true);
        if (ret != 0)
        {
            myst_eprintf(
                "kernel: cannot add extra mount. source=%s, target=%s, "
                "type: %s, return=%d\n",
                mounts->mounts[i].source,
                mounts->mounts[i].target,
                mounts->mounts[i].fs_type,
                ret);
            ERAISE(ret);
        }
    }
done:
    return ret;
}

static int _copy_host_etc_files()
{
    int ret = 0;
    int fd = -1;
    const char* resolv_file = "/etc/resolv.conf";
    void* buf = NULL;
    size_t buf_size;
    struct stat statbuf;

    ECHECK(myst_load_host_file(resolv_file, &buf, &buf_size));

    if (stat(resolv_file, &statbuf) == 0)
    {
        if ((myst_syscall_unlink(resolv_file)) < 0)
        {
            myst_eprintf("kernel: failed to unlink file %s\n", resolv_file);
            ERAISE(-EINVAL);
        }
    }
    else
    {
        if (stat("/etc", &statbuf) == -1)
        {
            if ((myst_mkdirhier("/etc", 0755)) != 0)
            {
                myst_eprintf("kernel: failed to mkdir /etc\n");
                ERAISE(-EINVAL);
            }
        }
        else if (!S_ISDIR(statbuf.st_mode))
        {
            if ((myst_syscall_unlink("/etc")) < 0)
            {
                myst_eprintf("kernel: failed to unlink file /etc\n");
                ERAISE(-EINVAL);
            }
            if ((myst_mkdirhier("/etc", 0755)) != 0)
            {
                myst_eprintf("kernel: failed to mkdir /etc\n");
                ERAISE(-EINVAL);
            }
        }
    }
    if ((fd = creat(resolv_file, 0644)) < 0)
    {
        myst_eprintf("kernel: failed to open file %s\n", resolv_file);
        ERAISE(-EINVAL);
    }
    if ((myst_write_file_fd(fd, buf, buf_size)) < 0)
    {
        myst_eprintf("kernel: failed to write to file %s\n", resolv_file);
        ERAISE(-EINVAL);
    }

done:

    if (fd != -1)
        close(fd);

    if (buf)
        free(buf);

    return ret;
}

static int _setup_tty(void)
{
    int ret = 0;
    myst_ttydev_t* ttydev = myst_ttydev_get();
    myst_fdtable_t* fdtable = myst_fdtable_current();
    myst_tty_t* stdin_tty;
    myst_tty_t* stdout_tty;
    myst_tty_t* stderr_tty;
    int fd;

    if ((*ttydev->td_create)(ttydev, STDIN_FILENO, &stdin_tty) != 0)
    {
        myst_eprintf("kernel: failed to create stdin device\n");
        ERAISE(-EINVAL);
    }

    if ((*ttydev->td_create)(ttydev, STDOUT_FILENO, &stdout_tty) != 0)
    {
        myst_eprintf("kernel: failed to create stdout device\n");
        ERAISE(-EINVAL);
    }

    if ((*ttydev->td_create)(ttydev, STDERR_FILENO, &stderr_tty) != 0)
    {
        myst_eprintf("kernel: failed to create stderr device\n");
        ERAISE(-EINVAL);
    }

    ECHECK(
        (fd = myst_fdtable_assign(
             fdtable, MYST_FDTABLE_TYPE_TTY, ttydev, stdin_tty)));

    if (fd != STDIN_FILENO)
    {
        myst_eprintf("kernel: failed to assign stdin fd\n");
        ERAISE(-EINVAL);
    }

    ECHECK(
        (fd = myst_fdtable_assign(
             fdtable, MYST_FDTABLE_TYPE_TTY, ttydev, stdout_tty)));

    if (fd != STDOUT_FILENO)
    {
        myst_eprintf("kernel: failed to assign stdout fd\n");
        ERAISE(-EINVAL);
    }

    ECHECK(
        (fd = myst_fdtable_assign(
             fdtable, MYST_FDTABLE_TYPE_TTY, ttydev, stderr_tty)));

    if (fd != STDERR_FILENO)
    {
        myst_eprintf("kernel: failed to assign stderr fd\n");
        ERAISE(-EINVAL);
    }

done:
    return ret;
}

static myst_fs_t* _tmpfs = NULL;

#ifdef USE_TMPFS

static int _init_tmpfs(const char* target, myst_fs_t** fs_out)
{
    int ret = 0;
    static myst_fs_t* fs;
    const mode_t mode = 0777;

    if (myst_mkdirhier(target, mode) != 0)
    {
        myst_eprintf("cannot create %s directory\n", target);
        ERAISE(-EINVAL);
    }

    if (myst_init_ramfs(myst_mount_resolve, &fs) != 0)
    {
        myst_eprintf("cannot initialize file system: %s\n", target);
        ERAISE(-EINVAL);
    }

    if (myst_mount(fs, "/", target, false) != 0)
    {
        myst_eprintf("cannot mount %s\n", target);
        ERAISE(-EINVAL);
    }

    *fs_out = fs;

done:
    return ret;
}
#endif

static int _create_standard_directories(void)
{
    int ret = 0;
    const mode_t mode = 0777;

#ifdef USE_TMPFS
    ECHECK(_init_tmpfs("/tmp", &_tmpfs));
#endif

#ifndef USE_TMPFS
    if (myst_mkdirhier("/tmp", mode) != 0)
    {
        myst_eprintf("cannot create /tmp directory\n");
        ERAISE(-EINVAL);
    }
#endif

    if (myst_mkdirhier("/usr/local/etc", mode) != 0)
    {
        myst_eprintf("cannot create the /usr/local/etc directory\n");
        ERAISE(-EINVAL);
    }

done:
    return ret;
}

static int _setup_ramfs(void)
{
    int ret = 0;

    if (myst_init_ramfs(myst_mount_resolve, &_fs) != 0)
    {
        myst_eprintf("failed initialize the RAM file system\n");
        ERAISE(-EINVAL);
    }

    if (myst_mount(_fs, "/", "/", false) != 0)
    {
        myst_eprintf("cannot mount root file system\n");
        ERAISE(-EINVAL);
    }

    _create_standard_directories();

done:
    return ret;
}

#ifdef MYST_ENABLE_EXT2FS
static int _setup_ext2(const char* rootfs, char* err, size_t err_size)
{
    int ret = 0;
    const char* key = NULL; /* no automatic key-release support yet */

    *err = '\0';

    if (myst_load_fs(myst_mount_resolve, rootfs, key, &_fs) != 0)
    {
        snprintf(err, err_size, "cannot load or verify EXT2 image: %s", rootfs);
        ERAISE(-EINVAL);
    }

    if (myst_mount(_fs, rootfs, "/", false) != 0)
    {
        snprintf(err, err_size, "cannot mount EXT2 rootfs: %s", rootfs);
        ERAISE(-EINVAL);
    }

    if (_create_standard_directories() != 0)
    {
        snprintf(err, err_size, "cannot create EXT2 standard directories");
    }

done:
    return ret;
}
#endif /* MYST_ENABLE_EXT2FS */

#if defined(MYST_ENABLE_HOSTFS)
static int _setup_hostfs(const char* rootfs, char* err, size_t err_size)
{
    int ret = 0;

    if (myst_init_hostfs(&_fs) != 0)
    {
        snprintf(
            err, err_size, "cannot initialize HOSTFS file system: %s", rootfs);
        ERAISE(-EINVAL);
    }

    if (myst_mount(_fs, rootfs, "/", false) != 0)
    {
        snprintf(err, err_size, "cannot mount HOSTFS rootfs: %s", rootfs);
        ERAISE(-EINVAL);
    }

    _create_standard_directories();

done:
    return ret;
}
#endif /* MYST_ENABLE_HOSTFS */

static const char* _getenv(const char** envp, const char* varname)
{
    const char* ret = NULL;
    if (envp != NULL)
    {
        size_t len = strlen(varname);
        for (const char** env = envp; *env != NULL; env++)
        {
            if (strncmp(*env, varname, len) == 0 && *(*env + len) == '=')
            {
                ret = *env + len + 1;
                break;
            }
        }
    }
    return ret;
}

static int _create_mem_file(
    const char* path,
    const void* file_data,
    size_t file_size)
{
    int ret = 0;
    int fd = -1;

    if (!path || !file_data)
        ERAISE(-EINVAL);

    if ((fd = open(path, O_WRONLY | O_CREAT, 0444)) < 0)
    {
        myst_panic("kernel: open(): %s\n", path);
        ERAISE(-ENOENT);
    }

    ECHECK(myst_ramfs_set_buf(_fs, path, file_data, file_size));

    ret = 0;

done:

    if (fd >= 0)
        close(fd);

    return ret;
}

static int _teardown_ramfs(void)
{
    if ((*_fs->fs_release)(_fs) != 0)
    {
        myst_eprintf("failed to release ramfs\n");
        return -1;
    }

    return 0;
}

#ifdef USE_TMPFS
static int _teardown_tmpfs(void)
{
    if ((*_tmpfs->fs_release)(_tmpfs) != 0)
    {
        myst_eprintf("failed to release tmpfs\n");
        return -1;
    }

    return 0;
}
#endif

static int _create_main_thread(
    uint64_t event,
    const char* cwd,
    pid_t target_tid,
    myst_thread_t** thread_out)
{
    int ret = 0;
    myst_thread_t* thread = NULL;
    pid_t ppid = myst_generate_tid();
    pid_t pid = myst_generate_tid();

    if (thread_out)
        *thread_out = NULL;

    if (!thread_out)
        ERAISE(-EINVAL);

    if (!(thread = calloc(1, sizeof(myst_thread_t))))
        ERAISE(-ENOMEM);

    thread->magic = MYST_THREAD_MAGIC;
    thread->sid = ppid;
    thread->ppid = ppid;
    thread->pid = pid;
    thread->tid = pid;
    thread->target_tid = target_tid;
    thread->event = event;
    thread->target_td = myst_get_fsbase();
    myst_strlcpy(thread->name, "main", sizeof(thread->name));

    thread->uid = MYST_DEFAULT_UID;
    thread->euid = MYST_DEFAULT_UID;
    thread->savgid = MYST_DEFAULT_UID;
    thread->fsgid = MYST_DEFAULT_UID;
    thread->gid = MYST_DEFAULT_GID;
    thread->egid = MYST_DEFAULT_GID;
    thread->savgid = MYST_DEFAULT_GID;
    thread->fsgid = MYST_DEFAULT_GID;

    thread->main.thread_group_lock = MYST_SPINLOCK_INITIALIZER;
    thread->thread_lock = &thread->main.thread_group_lock;
    thread->main.umask = MYST_DEFAULT_UMASK;
    thread->main.pgid = MYST_DEFAULT_PGID;

    thread->main.cwd_lock = MYST_SPINLOCK_INITIALIZER;
    thread->main.cwd = strdup(cwd);
    if (thread->main.cwd == NULL)
        ERAISE(-ENOMEM);

    // Initial process list is just us. All new processes will be inserted in
    // the list. Dont need to set these as they are already NULL, but being here
    // helps to track where main threads are created and torn down!
    // thread->main.prev_process_thread = NULL;
    // thread->main.next_process_thread = NULL;

    /* allocate the new fdtable for this process */
    ECHECK(myst_fdtable_create(&thread->fdtable));

    /* allocate the sigactions array */
    ECHECK(myst_signal_init(thread));

    /* bind this thread to the target */
    myst_assume(myst_tcall_set_tsd((uint64_t)thread) == 0);

    *thread_out = thread;
    thread = NULL;

done:

    if (thread)
        free(thread);

    return ret;
}

static int _get_fstype(myst_kernel_args_t* args, myst_fstype_t* fstype)
{
    int ret = 0;

    *fstype = MYST_FSTYPE_NONE;

    /* check whether CPIO archive */
    if (myst_is_cpio_archive(args->rootfs_data, args->rootfs_size))
    {
        *fstype = MYST_FSTYPE_RAMFS;
        goto done;
    }

    /* determine whether rootfs is a directory or regular file */
    if (args->rootfs)
    {
        struct stat buf;
        uid_t host_euid;
        gid_t host_egid;

        ECHECK(myst_enc_uid_to_host(myst_syscall_geteuid(), &host_euid));
        ECHECK(myst_enc_uid_to_host(myst_syscall_getegid(), &host_egid));

        long params[6] = {
            (long)args->rootfs, (long)&buf, (long)host_euid, (long)host_egid};

        ECHECK(myst_tcall(SYS_stat, params));

        if (S_ISDIR(buf.st_mode))
            *fstype = MYST_FSTYPE_HOSTFS;
        else
            *fstype = MYST_FSTYPE_EXT2FS;
    }

done:
    return ret;
}

static int _mount_rootfs(myst_kernel_args_t* args, myst_fstype_t fstype)
{
    int ret = 0;
    struct locals
    {
        char err[PATH_MAX + 256];
    };
    struct locals* locals = NULL;

    if (!(locals = malloc(sizeof(struct locals))))
        ERAISE(-ENOMEM);

    switch (fstype)
    {
        case MYST_FSTYPE_RAMFS:
        {
            /* Setup the RAM file system */
            if (_setup_ramfs() != 0)
            {
                myst_eprintf(
                    "failed to setup RAMFS rootfs: %s\n", args->rootfs);
                ERAISE(-EINVAL);
            }

            break;
        }
#if defined(MYST_ENABLE_EXT2FS)
        case MYST_FSTYPE_EXT2FS:
        {
            /* setup and mount the EXT2 file system */
            if (_setup_ext2(args->rootfs, locals->err, sizeof(locals->err)) !=
                0)
            {
                myst_eprintf("kernel: %s\n", locals->err);
                ERAISE(-EINVAL);
            }

            break;
        }
#endif
#if defined(MYST_ENABLE_HOSTFS)
        case MYST_FSTYPE_HOSTFS:
        {
            /* setup and mount the HOSTFS file system */
            if (_setup_hostfs(args->rootfs, locals->err, sizeof(locals->err)) !=
                0)
            {
                myst_eprintf(
                    "failed to setup HOSTFS rootfs: %s (%s)\n",
                    args->rootfs,
                    locals->err);
                ERAISE(-EINVAL);
            }

            break;
        }
#endif
        default:
        {
            myst_eprintf(
                "unsupported rootfs type: %s\n", myst_fstype_name(fstype));
            ERAISE(-EINVAL);
            break;
        }
    }

done:

    if (locals)
        free(locals);

    return ret;
}

static void _print_boottime(void)
{
    struct timespec now;
    static const char yellow[] = "\e[33m";
    static const char reset[] = "\e[0m";

    if (myst_syscall_clock_gettime(CLOCK_REALTIME, &now) == 0)
    {
        struct timespec start;
        start.tv_sec = __myst_kernel_args.start_time_sec;
        start.tv_nsec = __myst_kernel_args.start_time_nsec;

        long nsec = myst_lapsed_nsecs(&start, &now);

        double secs = (double)nsec / (double)NANO_IN_SECOND;

        myst_eprintf("%s", yellow);
        myst_eprintf("=== boot time: %.4lfsec", secs);
        myst_eprintf("%s\n", reset);
    }
}

extern myst_jmp_buf_t __myst_fork_jmpbuf;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstack-usage="
#pragma GCC push_options
#pragma GCC optimize("-fno-stack-protector")
int myst_enter_kernel(myst_kernel_args_t* args)
{
    int ret = 0;
    int exit_status;
    myst_thread_t* thread = NULL;
    myst_fstype_t fstype;
    int tmp_ret;

    /* if this is a forked process, then jump back to SYS_fork syscall */
    if (args->forked)
    {
        __myst_kernel_args.forked = true;
        __myst_kernel_args.target_ppid = args->target_ppid;
        __myst_kernel_args.target_pid = args->target_pid;
        __myst_main_thread->event = args->event;

#if 0
        __myst_kernel_args.trace_syscalls = true;
#endif

#if 0
        myst_set_trace(true);
#endif

        /* ATTN: what if process was not forked from main thread */
        myst_assume(myst_tcall_set_tsd((uint64_t)__myst_main_thread) == 0);

#if 0
        if (myst_listener_ping() != 0)
            myst_eprintf("*** myst_listener_ping() failed\n");
#endif

        ECHECK(myst_tcall_set_run_thread_function(myst_run_thread));
        myst_longjmp(&__myst_fork_jmpbuf, 1);

        /* ATTN: clean up stale threads here! */
    }

    if (!args)
        myst_crash();

    /* args->myst_syscall() can be called from enclave exception handlers */
    args->myst_syscall = myst_syscall;

    /* myst_handle_host_signal can be called from enclave exception handlers */
    args->myst_handle_host_signal = myst_handle_host_signal;

    /* make a copy of the input kernel aguments and reassign args */
    __myst_kernel_args = *args;
    args = &__myst_kernel_args;

    /* turn off various options when TEE is not in debug mode */
    if (!args->tee_debug_mode)
    {
        args->trace_errors = false;
        args->trace_syscalls = false;
        args->shell_mode = false;
        args->memcheck = false;
        args->perf = false;
        args->debug_symbols = false;
        args->shell_mode = false;
        args->report_native_tids = false;
    }

    /* ATTN: it seems __options can be eliminated */
    __options.trace_syscalls = args->trace_syscalls;
    __options.have_syscall_instruction = args->have_syscall_instruction;
    __options.have_fsgsbase_instructions = args->have_fsgsbase_instructions;
    __options.report_native_tids = args->report_native_tids;

    /* enable error tracing if requested */
    if (args->trace_errors)
        myst_set_trace(true);

    if (__options.have_syscall_instruction)
        myst_set_gsbase(myst_get_fsbase());

    /* call global constructors within the kernel */
    myst_call_init_functions();

    /* Check arguments */
    {
        if (!args->argc || !args->argv)
        {
            myst_eprintf("kernel: bad argc/argv arguments\n");
            ERAISE(-EINVAL);
        }

        if (!args->envc || !args->envp)
        {
            myst_eprintf("kernel: bad envc/envp arguments\n");
            ERAISE(-EINVAL);
        }

        if (!args->mman_data || !args->mman_size)
        {
            myst_eprintf("kernel: bad mman arguments\n");
            ERAISE(-EINVAL);
        }

        if (!args->rootfs_data || !args->rootfs_size)
        {
            myst_eprintf("kernel: bad rootfs arguments\n");
            ERAISE(-EINVAL);
        }

        if (!args->crt_data || !args->crt_size)
        {
            myst_eprintf("kernel: bad crt arguments\n");
            ERAISE(-EINVAL);
        }

        if (!args->tcall)
        {
            myst_eprintf("kernel: bad tcall argument\n");
            ERAISE(-EINVAL);
        }
    }

    /* Setup the memory manager */
    if (myst_setup_mman(args->mman_data, args->mman_size) != 0)
    {
        myst_eprintf("kernel: memory manager setup failed\n");
        ERAISE(-EINVAL);
    }

    /* Create the main thread */
    ECHECK(
        _create_main_thread(args->event, args->cwd, args->target_pid, &thread));
    __myst_main_thread = thread;

    myst_copy_host_uid_gid_mappings(&args->host_enc_uid_gid_mappings);

    /* determine the rootfs file system type (RAMFS, EXT2FS, OR HOSTFS) */
    if ((tmp_ret = _get_fstype(args, &fstype)) != 0)
    {
        myst_eprintf(
            "kernel: cannot resolve rootfs type: %s, return: %d\n",
            args->rootfs,
            tmp_ret);
        ERAISE(-EINVAL);
    }

    /* Mount the root file system */
    ECHECK(_mount_rootfs(args, fstype));

    /* Generate TLS credentials if needed */
    ECHECK(myst_init_tls_credential_files(
        _getenv(args->envp, WANT_CREDENTIALS), _tmpfs ? _tmpfs : _fs, fstype));

    /* Setup virtual proc filesystem */
    procfs_setup();

    if (args->hostname)
        ECHECK(
            myst_syscall_sethostname(args->hostname, strlen(args->hostname)));

    /* setup the TTY devices */
    if (_setup_tty() != 0)
    {
        myst_eprintf("kernel: failed to setup of TTY devices\n");
        ERAISE(-EINVAL);
    }

    /* Unpack the CPIO from memory */
    if (fstype == MYST_FSTYPE_RAMFS &&
        myst_cpio_mem_unpack(
            args->rootfs_data, args->rootfs_size, "/", _create_mem_file) != 0)
    {
        myst_eprintf("failed to unpack root file system\n");
        ERAISE(-EINVAL);
    }

    /* Setup devfs */
    devfs_setup();

    /* Create top-level proc entries */
    create_proc_root_entries();

    ECHECK(_process_mount_configuration(args->mounts));

    ECHECK(_copy_host_etc_files());

    /* Set the 'run-proc' which is called by the target to run new threads */
    ECHECK(myst_tcall_set_run_thread_function(myst_run_thread));

    myst_times_start();

    if (args->shell_mode)
        myst_start_shell("\nMystikos shell (enter)\n");

    /* print how long it took to boot */
    if (__myst_kernel_args.perf)
        _print_boottime();

    /* Run the main program: wait for SYS_exit to perform longjmp() */
    if (myst_setjmp(&thread->jmpbuf) == 0)
    {
        /* enter the C-runtime on the target thread descriptor */
        if ((tmp_ret = myst_exec(
                 thread,
                 args->crt_data,
                 args->crt_size,
                 args->crt_reloc_data,
                 args->crt_reloc_size,
                 args->argc,
                 args->argv,
                 args->envc,
                 args->envp,
                 NULL,
                 NULL)) != 0)
        {
            myst_panic("myst_exec() failed, ret=%d", tmp_ret);
        }

        /* never returns */
        for (;;)
            ;
    }
    else
    {
        /* main process thread jumps here on return or if main thread calls
         * SYS_exit. If a non-process thread calls SYS_exit instead it will send
         * a SIGKILL to the main thread, which also triggers the main thread
         * calling back to here.
         */

        /* Switch from the CRT fsbase to the kernel fsbase. This must be done
         * before unmapping the CRT data (which contains the CRT fsbase). Else,
         * munmap eventually calls mprotect which makes the CRT fsbase
         * unreadable, which results in a segmentation fault the next time
         * the fsbase's first word is read with the following instruction.
         *
         *      __asm__ volatile("mov %%fs:0, %0" : "=r"(p));
         *
         * Please do not place any code in this block before the following
         * call to myst_set_fsbase().
         */
        myst_set_fsbase(thread->target_td);

        /* Shutdown the listener thread. */
        if (!args->forked)
        {
            /* ATTN: this is a no-op */
            myst_listener_shutdown();

            /* ATTN:FORK: figure out how to remove this! */
            myst_sleep_msec(1000);
        }

        if (__myst_kernel_args.perf)
            myst_print_syscall_times("kernel shutdown", SIZE_MAX);

        /* release the kernel stack that was passed to SYS_exit if any */
        if (thread->kstack)
            myst_put_kstack(thread->kstack);

            /* ATTN: do not wait for child threads to exit */
#if 0
        /* free all non-process threads, waiting for all other threads to
         * shutdown at the same time. Our thread has not been marked as a zombie
         * yet. */
        {
            myst_thread_t* t = thread->group_next;
            while (t)
            {
                myst_thread_t* next = t->group_next;
                if (t != thread)
                {
                    if (t->status != MYST_ZOMBIE)
                    {
                        // We still have a thread that has not shut down
                        // properly yet
                        myst_sleep_msec(10);
                        continue;
                    }
                    if (t->group_prev)
                        t->group_prev->group_next = t->group_next;
                    if (t->group_next)
                        t->group_next->group_prev = t->group_prev;
                    myst_signal_free_siginfos(t);
                    free(t);
                }
                t = next;
            }
        }
#endif

        /* now all the threads have shutdown we can retrieve the exit status */
        exit_status = thread->exit_status;

        if (args->shell_mode)
            myst_start_shell("\nMystikos shell (exit)\n");

        /* release the fdtable */
        if (thread->fdtable)
        {
            myst_fdtable_free(thread->fdtable);
            thread->fdtable = NULL;
        }

        /* release signal related heap memory */
        myst_signal_free(thread);
        myst_signal_free_siginfos(thread);

        /* release the exec stack */
        if (thread->main.exec_stack)
        {
            free(thread->main.exec_stack);
            thread->main.exec_stack = NULL;
            thread->main.exec_stack_size = 0;
        }

        /* release the exec copy of the CRT data */
        if (thread->main.exec_crt_data)
        {
            myst_munmap(thread->main.exec_crt_data, thread->main.exec_crt_size);
            thread->main.exec_crt_data = NULL;
            thread->main.exec_crt_size = 0;
        }

        /* Free CWD */
        free(thread->main.cwd);
        thread->main.cwd = NULL;
    }

    /* Tear down the temporary file systems */
#ifdef USE_TMPFS
    _teardown_tmpfs();
#endif

    /* Tear down all auto-mounted file systems */
    myst_teardown_auto_mounts();

    /* Tear down the proc file system */
    procfs_teardown();

    /* Tear down the dev file system */
    devfs_teardown();

    /* Tear down the RAM file system */
    _teardown_ramfs();

    /* Put the thread on the zombie list */
    myst_zombify_thread(thread);

    /* call functions installed with myst_atexit() */
    myst_call_atexit_functions();

    // Call global destructors within the kernel.
    // GCOV uses fini functions to generates .gcda files on exit.
    myst_call_fini_functions();

    /* check for memory leaks */
    if (args->memcheck)
    {
        /* check malloc'c memory integrity and report leaks */
        if (myst_debug_malloc_check() != 0)
            myst_eprintf("*** memory leaks detected\n");
    }

    /* unload the debugger symbols */
    if (args->debug_symbols)
        myst_syscall_unload_symbols();

    /* ATTN: move myst_call_atexit_functions() here */

    ret = exit_status;

done:
    return ret;
}
#pragma GCC pop_options
#pragma GCC diagnostic pop
