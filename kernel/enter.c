// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <myst/atexit.h>
#include <myst/cpio.h>
#include <myst/crash.h>
#include <myst/eraise.h>
#include <myst/errno.h>
#include <myst/exec.h>
#include <myst/fdtable.h>
#include <myst/file.h>
#include <myst/fs.h>
#include <myst/fsgs.h>
#include <myst/hex.h>
#include <myst/initfini.h>
#include <myst/kernel.h>
#include <myst/mmanutils.h>
#include <myst/mount.h>
#include <myst/options.h>
#include <myst/panic.h>
#include <myst/printf.h>
#include <myst/process.h>
#include <myst/pubkey.h>
#include <myst/ramfs.h>
#include <myst/signal.h>
#include <myst/strings.h>
#include <myst/syscall.h>
#include <myst/thread.h>
#include <myst/times.h>
#include <myst/ttydev.h>

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

void myst_dump_malloc_stats(void)
{
    myst_malloc_stats_t stats;

    if (myst_get_malloc_stats(&stats) == 0)
    {
        myst_eprintf("kernel: memory used: %zu\n", stats.usage);
        myst_eprintf("kernel: peak memory used: %zu\n", stats.peak_usage);
    }
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

static int _create_standard_directories(void)
{
    int ret = 0;

    /* create /tmp if it does not already exist */
    if (myst_mkdirhier("/tmp", 777) != 0)
    {
        myst_eprintf("cannot create the /tmp directory\n");
        ERAISE(-EINVAL);
    }

    if (myst_mkdirhier("/proc/self/fd", 777) != 0)
    {
        myst_eprintf("cannot create the /proc/self/fd directory\n");
        ERAISE(-EINVAL);
    }

    if (myst_mkdirhier("/usr/local/etc", 777) != 0)
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

    if (myst_init_ramfs(&_fs) != 0)
    {
        myst_eprintf("failed initialize the RAM files system\n");
        ERAISE(-EINVAL);
    }

    if (myst_mount(_fs, "/") != 0)
    {
        myst_eprintf("cannot mount root file system\n");
        ERAISE(-EINVAL);
    }

    _create_standard_directories();

done:
    return ret;
}

static int _setup_ext2(const char* rootfs)
{
    int ret = 0;
    const char* key = NULL; /* not automatic key-release support yet */

    if (myst_load_fs(rootfs, key, &_fs) != 0)
    {
        myst_eprintf("failed load the ext2 rootfs: %s\n", rootfs);
        ERAISE(-EINVAL);
    }

    if (myst_mount(_fs, "/") != 0)
    {
        myst_eprintf("cannot mount root file system\n");
        ERAISE(-EINVAL);
    }

    _create_standard_directories();

done:
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

static int _create_main_thread(uint64_t event, myst_thread_t** thread_out)
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
    thread->event = event;
    thread->target_td = myst_get_fsbase();

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

int myst_enter_kernel(myst_kernel_args_t* args)
{
    int ret = 0;
    int exit_status;
    myst_thread_t* thread = NULL;
    bool use_cpio;

#if 0
    extern void myst_set_trace(bool flag);
    myst_set_trace(true);
#endif

    if (!args)
        myst_crash();

    /* Save the aguments */
    __myst_kernel_args = *args;

    /* ATTN: it seems __options can be eliminated */
    __options.trace_syscalls = args->trace_syscalls;
    __options.have_syscall_instruction = args->have_syscall_instruction;
    __options.export_ramfs = args->export_ramfs;

    if (__options.have_syscall_instruction)
        myst_set_gsbase(myst_get_fsbase());

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

    /* determine whether rootfs is a CPIO archive */
    use_cpio = myst_is_cpio_archive(args->rootfs_data, args->rootfs_size);

    /* if not a CPIO archive, then use EXT2 mounting */
    if (use_cpio)
    {
        /* Setup the RAM file system */
        if (_setup_ramfs() != 0)
            ERAISE(-EINVAL);
    }
    else
    {
        /* setup and mount the EXT2 file system */
        if (_setup_ext2(args->rootfs) != 0)
            ERAISE(-EINVAL);
    }

    /* Create the main thread */
    ECHECK(_create_main_thread(args->event, &thread));
    __myst_main_thread = thread;

    /* setup the TTY devices */
    if (_setup_tty() != 0)
    {
        myst_eprintf("kernel: failed to setup of TTY devices\n");
        ERAISE(-EINVAL);
    }

    /* Unpack the CPIO from memory */
    if (use_cpio &&
        myst_cpio_mem_unpack(
            args->rootfs_data, args->rootfs_size, "/", _create_mem_file) != 0)
    {
        myst_eprintf("failed to unpack root file system\n");
        ERAISE(-EINVAL);
    }

    /* Set the 'run-proc' which is called by the target to run new threads */
    ECHECK(myst_tcall_set_run_thread_function(myst_run_thread));

#ifdef MYST_ENABLE_LEAK_CHECKER
    /* print out memory statistics */
    // myst_dump_malloc_stats();
#endif

    myst_times_start();

    /* Run the main program: wait for SYS_exit to perform longjmp() */
    if (myst_setjmp(&thread->jmpbuf) == 0)
    {
        /* enter the C-runtime on the target thread descriptor */
        if (myst_exec(
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
                NULL) != 0)
        {
            myst_panic("myst_exec() failed");
        }

        /* never returns */
        for (;;)
            ;
    }
    else
    {
        /* thread jumps here on SYS_exit syscall */
        exit_status = thread->exit_status;

        /* release the fdtable */
        if (thread->fdtable)
        {
            myst_fdtable_free(thread->fdtable);
            thread->fdtable = NULL;
        }

        /* release signal related heap memory */
        myst_signal_free(thread);

        /* release the exec stack */
        if (thread->main.exec_stack)
        {
            free(thread->main.exec_stack);
            thread->main.exec_stack = NULL;
        }

        /* release the exec copy of the CRT data */
        if (thread->main.exec_crt_data)
        {
            myst_munmap(thread->main.exec_crt_data, thread->main.exec_crt_size);
            thread->main.exec_crt_data = NULL;
            thread->main.exec_crt_size = 0;
        }

        /* switch back to the target thread descriptor */
        myst_set_fsbase(thread->target_td);
    }

    /* unload the debugger symbols */
    myst_syscall_unload_symbols();

    /* Tear down the RAM file system */
    _teardown_ramfs();

    /* Put the thread on the zombie list */
    myst_zombify_thread(thread);

    /* call functions installed with myst_atexit() */
    myst_call_atexit_functions();

#ifdef MYST_ENABLE_LEAK_CHECKER
    /* Check for memory leaks */
    if (myst_find_leaks() != 0)
    {
        myst_crash();
        myst_panic("kernel memory leaks");
    }
#endif

    /* ATTN: move myst_call_atexit_functions() here */

    ret = exit_status;

done:

    return ret;
}
