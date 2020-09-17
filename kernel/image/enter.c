#include <libos/assert.h>
#include <libos/atexit.h>
#include <libos/cpio.h>
#include <libos/crash.h>
#include <libos/elfutils.h>
#include <libos/eraise.h>
#include <libos/errno.h>
#include <libos/file.h>
#include <libos/fsgs.h>
#include <libos/initfini.h>
#include <libos/kernel.h>
#include <libos/malloc.h>
#include <libos/mmanutils.h>
#include <libos/mount.h>
#include <libos/options.h>
#include <libos/process.h>
#include <libos/ramfs.h>
#include <libos/strings.h>
#include <libos/syscall.h>
#include <libos/thread.h>

static libos_kernel_args_t _args;

static libos_fs_t* _fs;

long libos_tcall(long n, long params[6])
{
    void* fs = NULL;

    if (__options.have_syscall_instruction)
    {
        fs = libos_get_fsbase();
        libos_set_fsbase(libos_get_gsbase());
    }

    long ret = (_args.tcall)(n, params);

    if (fs)
        libos_set_fsbase(fs);

    return ret;
}

static int _setup_ramfs(void)
{
    int ret = 0;

    if (libos_init_ramfs(&_fs) != 0)
    {
        libos_eprintf("failed initialize the RAM files system\n");
        ERAISE(-EINVAL);
    }

    if (libos_mount(_fs, "/") != 0)
    {
        libos_eprintf("failed create the / directory\n");
        ERAISE(-EINVAL);
    }

    if (libos_mkdir("/tmp", 777) != 0)
    {
        libos_eprintf("failed create the /tmp directory\n");
        ERAISE(-EINVAL);
    }

    if (libos_mkdirhier("/proc/self/fd", 777) != 0)
    {
        libos_eprintf("failed create the /proc/self/fd directory\n");
        ERAISE(-EINVAL);
    }

    if (libos_mkdirhier("/usr/local/etc", 777) != 0)
    {
        libos_eprintf("failed create the /usr/local/etc directory\n");
        ERAISE(-EINVAL);
    }

done:
    return ret;
}

static int _create_cpio_file(const char* path, const char* data, size_t size)
{
    int ret = 0;
    int fd = -1;

    if (!path || !data || !size)
        ERAISE(-EINVAL);

    if ((fd = libos_open(path, O_WRONLY | O_CREAT, 0444)) < 0)
        ERAISE(-EINVAL);

    ECHECK(libos_ramfs_set_buf(_fs, path, data, size));

    ret = 0;

done:

    if (fd >= 0)
        libos_close(fd);

    return ret;
}

static int _teardown_ramfs(void)
{
    if ((*_fs->fs_release)(_fs) != 0)
    {
        libos_eprintf("failed to release ramfs\n");
        return -1;
    }

    return 0;
}

static int _create_main_thread(
    uint64_t event,
    libos_thread_t** thread_out)
{
    int ret = 0;
    libos_thread_t* thread = NULL;
    pid_t ppid = libos_generate_tid();
    pid_t pid = libos_generate_tid();

    if (thread_out)
        *thread_out = NULL;

    if (!thread_out)
        ERAISE(-EINVAL);

    if (!(thread = libos_calloc(1, sizeof(libos_thread_t))))
        ERAISE(-ENOMEM);

    libos_setppid(ppid);
    libos_setpid(pid);

    thread->magic = LIBOS_THREAD_MAGIC;
    thread->tid = pid;
    thread->event = event;
    thread->original_fsbase = libos_get_fsbase();

    *thread_out = thread;
    thread = NULL;

done:

    if (thread)
        libos_free(thread);

    return ret;
}

int libos_enter_kernel(libos_kernel_args_t* args)
{
    int ret = 0;
    int exit_status;
    const char rootfs_path[] = "/tmp/rootfs.cpio";
    libos_thread_t* thread = NULL;

    if (!args)
        libos_crash();

    /* Save the aguments */
    _args = *args;

    __options.trace_syscalls = _args.trace_syscalls;
    __options.have_syscall_instruction = _args.have_syscall_instruction;
    __options.export_ramfs = _args.export_ramfs;

    if (__options.have_syscall_instruction)
        libos_set_gsbase(libos_get_fsbase());

    libos_call_init_functions();

    /* Check arguments */
    {
        if (!args->argc || !args->argv)
        {
            libos_eprintf("kernel: bad argc/argv arguments\n");
            ERAISE(-EINVAL);
        }

        if (!args->envc || !args->envp)
        {
            libos_eprintf("kernel: bad envc/envp arguments\n");
            ERAISE(-EINVAL);
        }

        if (!args->mman_data || !args->mman_size)
        {
            libos_eprintf("kernel: bad mman arguments\n");
            ERAISE(-EINVAL);
        }

        if (!args->rootfs_data || !args->rootfs_size)
        {
            libos_eprintf("kernel: bad rootfs arguments\n");
            ERAISE(-EINVAL);
        }

        if (!args->crt_data || !args->crt_size)
        {
            libos_eprintf("kernel: bad crt arguments\n");
            ERAISE(-EINVAL);
        }

        if (!args->tcall)
        {
            libos_eprintf("kernel: bad tcall argument\n");
            ERAISE(-EINVAL);
        }
    }

    /* Setup the memory manager */
    if (libos_setup_mman(args->mman_data, args->mman_size) != 0)
    {
        libos_eprintf("kernel: memory manageger setup failed\n");
        ERAISE(-EINVAL);
    }

    /* Setup the RAM file system */
    if (_setup_ramfs() != 0)
    {
        ERAISE(-EINVAL);
    }

    /* Create a temporary file containing the root file system */
    {
        if (_create_cpio_file(
                rootfs_path, args->rootfs_data, args->rootfs_size) != 0)
        {
            libos_eprintf("kernel: failed to create: %s\n", rootfs_path);
            ERAISE(-EINVAL);
        }

        if (libos_access(rootfs_path, R_OK) != 0)
        {
            libos_eprintf("kernel: failed to create: %s\n", rootfs_path);
            ERAISE(-EINVAL);
        }
    }

    /* Unpack the root file system */
    if (libos_cpio_unpack(rootfs_path, "/") != 0)
    {
        libos_eprintf("failed to unpack: %s\n", rootfs_path);
        ERAISE(-EINVAL);
    }

    /* Set the 'run-proc' which is called by the target to run new threads */
    ECHECK(libos_tcall_set_run_thread_function(libos_run_thread));

    /* Create the main thread */
    ECHECK(_create_main_thread(args->event, &thread));

    /* Enter the C runtime (which enters the application) */
    exit_status = elf_enter_crt(
        thread, args->crt_data, args->argc, args->argv, args->envc, args->envp);

    /* Tear down the RAM file system */
    _teardown_ramfs();

    /* Put the thread on the zombie list */
    libos_zombify_thread(thread);

#if 0
    {
        size_t n = libos_get_num_active_threads();
        libos_eprintf("num active threads: %zu\n", n);
    }
#endif

    /* call functions installed with libos_atexit() */
    libos_call_atexit_functions();

    /* Check for memory leaks */
    if (libos_find_leaks() != 0)
        libos_panic("kernel memory leaks");

    /* ATTN: move libos_call_atexit_functions() here */

    ret = exit_status;

done:

    return ret;
}
