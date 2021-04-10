// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <myst/atexit.h>
#include <myst/cpio.h>
#include <myst/crash.h>
#include <myst/debugmalloc.h>
#include <myst/eraise.h>
#include <myst/errno.h>
#include <myst/exec.h>
#include <myst/fdtable.h>
#include <myst/file.h>
#include <myst/fs.h>
#include <myst/fsgs.h>
#include <myst/hex.h>
#include <myst/hostfs.h>
#include <myst/initfini.h>
#include <myst/kernel.h>
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
#include <myst/tee.h>
#include <myst/thread.h>
#include <myst/times.h>
#include <myst/trace.h>
#include <myst/ttydev.h>

#define WANT_TLS_CREDENTIAL "MYST_WANT_TLS_CREDENTIAL"

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

#ifdef USE_TMPFS
static myst_fs_t* _tmpfs;

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

    if (myst_mount(fs, "/", target) != 0)
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

    if (myst_mount(_fs, "/", "/") != 0)
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

    if (myst_mount(_fs, rootfs, "/") != 0)
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

    if (myst_mount(_fs, rootfs, "/") != 0)
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

static int _create_tls_credentials(myst_fs_t* fs)
{
    int ret = -EINVAL;
    uint8_t* cert = NULL;
    size_t cert_size = 0;
    uint8_t* pkey = NULL;
    size_t pkey_size = 0;
    const char* certificate_path = MYST_CERTIFICATE_PATH;
    const char* private_key_path = MYST_PRIVATE_KEY_PATH;

    assert(fs != NULL);

#ifdef USE_TMPFS
    /* clip the "/tmp" prefix from certificate_path and private_key_path */
    {
        const char prefix[] = "/tmp";
        const size_t len = sizeof(prefix) - 1;

        if (strncmp(certificate_path, prefix, len) == 0)
            certificate_path += len;

        if (strncmp(private_key_path, prefix, len) == 0)
            private_key_path += len;
    }
#endif

    myst_file_t* file = NULL;
    int flags = O_CREAT | O_WRONLY;

    long params[6] = {
        (long)&cert, (long)&cert_size, (long)&pkey, (long)&pkey_size};
    ECHECK(myst_tcall(MYST_TCALL_GEN_CREDS, params));

    // Save the certificate
    ECHECK((fs->fs_open)(fs, certificate_path, flags, 0444, NULL, &file));
    ECHECK((fs->fs_write)(fs, file, cert, cert_size) == (int64_t)cert_size);
    ECHECK((fs->fs_close)(fs, file));
    file = NULL;

    // Save the private key
    ECHECK((fs->fs_open)(fs, private_key_path, flags, 0444, NULL, &file));
    ECHECK((fs->fs_write)(fs, file, pkey, pkey_size) == (int64_t)pkey_size);
    ECHECK((fs->fs_close)(fs, file));
    file = NULL;

    ret = 0;

done:
    if (cert || pkey)
    {
        long params[6] = {
            (long)cert, (long)cert_size, (long)pkey, (long)pkey_size};
        myst_tcall(MYST_TCALL_FREE_CREDS, params);
    }

    if (file)
    {
        fs->fs_close(fs, file);
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
    thread->main.thread_group_lock = MYST_SPINLOCK_INITIALIZER;
    thread->thread_lock = &thread->main.thread_group_lock;
    strcpy(thread->name, "main");

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
        long params[6] = {(long)args->rootfs, (long)&buf};

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
            char err[PATH_MAX + 256];

            /* setup and mount the EXT2 file system */
            if (_setup_ext2(args->rootfs, err, sizeof(err)) != 0)
            {
                myst_eprintf(
                    "failed to setup EXT2 rootfs: %s (%s)\n",
                    args->rootfs,
                    err);
                ERAISE(-EINVAL);
            }

            break;
        }
#endif
#if defined(MYST_ENABLE_HOSTFS)
        case MYST_FSTYPE_HOSTFS:
        {
            char err[PATH_MAX + 256];

            /* disallow HOSTFS rootfs in non-debug mode */
            if (!args->tee_debug_mode)
            {
                myst_eprintf(
                    "HOSTFS as rootfs only permitted only in debug mode\n");
                ERAISE(-EINVAL);
            }

            /* setup and mount the HOSTFS file system */
            if (_setup_hostfs(args->rootfs, err, sizeof(err)) != 0)
            {
                myst_eprintf(
                    "failed to setup HOSTFS rootfs: %s (%s)\n",
                    args->rootfs,
                    err);
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
    return ret;
}

int myst_enter_kernel(myst_kernel_args_t* args)
{
    int ret = 0;
    int exit_status;
    myst_thread_t* thread = NULL;
    const char* want_tls_creds;
    myst_fstype_t fstype;

    if (!args)
        myst_crash();

    /* args->myst_syscall() can be called from enclave exception handlers */
    args->myst_syscall = myst_syscall;

    /* Save the aguments */
    __myst_kernel_args = *args;

    /* ATTN: it seems __options can be eliminated */
    __options.trace_syscalls = args->trace_syscalls;
    __options.have_syscall_instruction = args->have_syscall_instruction;
    __options.export_ramfs = args->export_ramfs;

#if !defined(MYST_RELEASE)
    /* enable memcheck if options present and in TEE debug mode */
    if (args->memcheck && args->tee_debug_mode)
        myst_enable_debug_malloc = true;
#endif

    /* enable error tracing if requested */
    if (args->trace_errors)
        myst_set_trace(true);

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

    /* determine the rootfs file system type (RAMFS, EXT2FS, OR HOSTFS) */
    if (_get_fstype(args, &fstype) != 0)
    {
        myst_eprintf("kernel: cannot resolve rootfs type: %s\n", args->rootfs);
        ERAISE(-EINVAL);
    }

    /* Mount the root file system */
    ECHECK(_mount_rootfs(args, fstype));

    /* Generate TLS credentials if needed */
    want_tls_creds = _getenv(args->envp, WANT_TLS_CREDENTIAL);
    if (want_tls_creds != NULL)
    {
        if (strcmp(want_tls_creds, "1") == 0)
        {
#ifdef USE_TMPFS
            ECHECK(_create_tls_credentials(_tmpfs));
#else
            ECHECK(_create_tls_credentials(_fs));
#endif
        }
        else if (strcmp(want_tls_creds, "0") != 0)
        {
            myst_eprintf(
                "Environment variable %s only accept 0 or 1\n",
                WANT_TLS_CREDENTIAL);
            ERAISE(-EINVAL);
        }
    }

    /* Create the main thread */
    ECHECK(_create_main_thread(args->event, &thread));
    __myst_main_thread = thread;

    thread->main.cwd_lock = MYST_SPINLOCK_INITIALIZER;
    thread->main.cwd = strdup(args->cwd);
    if (thread->main.cwd == NULL)
        ERAISE(-ENOMEM);

    thread->main.umask = MYST_DEFAULT_UMASK;

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

    /* Create top-level proc entries */
    create_proc_root_entries();

    /* Set the 'run-proc' which is called by the target to run new threads */
    ECHECK(myst_tcall_set_run_thread_function(myst_run_thread));

    myst_times_start();

#if !defined(MYST_RELEASE)
    if (args->shell_mode)
        myst_start_shell("\nMystikos shell (enter)\n");
#endif

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
        myst_eprintf("******** exiting: %d\n", __LINE__);
        /* thread jumps here on SYS_exit syscall */
        exit_status = thread->exit_status;

#if !defined(MYST_RELEASE)
        if (args->shell_mode)
            myst_start_shell("\nMystikos shell (exit)\n");
#endif

        /* release the fdtable */
        if (thread->fdtable)
        {
            myst_fdtable_free(thread->fdtable);
            thread->fdtable = NULL;
        }

        myst_eprintf("******** exiting: %d\n", __LINE__);
        /* release signal related heap memory */
        myst_signal_free(thread);

        /* release the exec stack */
        if (thread->main.exec_stack)
        {
            free(thread->main.exec_stack);
            thread->main.exec_stack = NULL;
        }

        myst_eprintf("******** exiting: %d\n", __LINE__);
        /* release the exec copy of the CRT data */
        if (thread->main.exec_crt_data)
        {
            myst_munmap(thread->main.exec_crt_data, thread->main.exec_crt_size);
            thread->main.exec_crt_data = NULL;
            thread->main.exec_crt_size = 0;
        }

        /* Free CWD */
        free(thread->main.cwd);
        myst_eprintf("******** exiting: %d\n", __LINE__);
        thread->main.cwd = NULL;
        myst_eprintf("******** exiting: %d\n", __LINE__);

        /* switch back to the target thread descriptor */
        myst_set_fsbase(thread->target_td);
        myst_eprintf("******** exiting: %d\n", __LINE__);
    }

    /* unload the debugger symbols */
    myst_syscall_unload_symbols();

    myst_eprintf("******** exiting: %d\n", __LINE__);
    /* Tear down the temporary file systems */
#ifdef USE_TMPFS
    _teardown_tmpfs();
#endif

    /* Tear down the proc file system */
    procfs_teardown();

    myst_eprintf("******** exiting: %d\n", __LINE__);
    /* Tear down the RAM file system */
    _teardown_ramfs();

    /* Put the thread on the zombie list */
    myst_zombify_thread(thread);

    /* call functions installed with myst_atexit() */
    myst_call_atexit_functions();

    /* check for memory leaks */
    if (myst_enable_debug_malloc)
    {
        if (myst_debug_malloc_check(true) != 0)
            myst_eprintf("*** memory leaks detected\n");
    }

    myst_eprintf("******** exiting: %d\n", __LINE__);

    /* ATTN: move myst_call_atexit_functions() here */

    ret = exit_status;

done:

    myst_eprintf("******** exiting: ret=%d\n", ret);
    return ret;
}
