// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#define _GNU_SOURCE
#include <assert.h>
#include <linux/futex.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <syscall.h>
#include <time.h>

#include <myst/args.h>
#include <myst/cpio.h>
#include <myst/elf.h>
#include <myst/eraise.h>
#include <myst/file.h>
#include <myst/hex.h>
#include <myst/kernel.h>
#include <myst/regions.h>
#include <myst/reloc.h>
#include <myst/round.h>
#include <myst/signal.h>
#include <myst/strings.h>
#include <myst/tcall.h>
#include <myst/thread.h>

#include "../config.h"
#include "../kargs.h"
#include "../shared.h"
#include "exec_linux.h"
#include "fsgsbase.h"
#include "process.h"
#include "pubkeys.h"
#include "regions.h"
#include "roothash.h"
#include "utils.h"

#define USAGE_FORMAT \
    "\n\
\n\
Usage: %s exec-linux [options] <rootfs> <application> <args...>\n\
\n\
Where:\n\
    exec-linux           -- execute an application within <rootfs> in a\n\
                            non-trusted Linux environment\n\
    <rootfs>             -- the root file system containing the application\n\
                            (CPIO or EXT2)\n\
    <application>        -- the path of the executable program within\n\
                            <rootfs> that will be executed\n\
    <args>               -- arguments to passed through to the <application>\n\
\n\
Options:\n\
    --help               -- this message\n\
    --memory-size <size> -- the memory size required by the Mystikos kernel\n\
                            and application, where <size> may have a\n\
                            multiplier suffix: k 1024, m 1024*1024, or\n\
                            g 1024*1024*1024\n\
    --app-config-path <json> -- specifies the configuration json file for\n\
                                running an unsigned binary. The file can be\n\
                                the same one used for the signing process.\n\
    --host-to-enc-uid-map <host-uid:enc-uid[,host-uid2:enc-uid2,...]>\n\
                         -- comma separated list of uid mappings between\n\
                             the host and the enclave\n\
    --host-to-enc-gid-map <host-gid:enc-gid[,host-gid2:enc-gid2,...]>\n\
                         -- comma separated list of gid mappings between\n\
                             the host and the enclave\n\
\n\
"

struct options
{
    bool trace_errors;
    bool trace_syscalls;
    bool shell_mode;
    bool debug_symbols;
    bool memcheck;
    bool nobrk;
    bool perf;
    bool report_native_tids;
    size_t max_affinity_cpus;
    char rootfs[PATH_MAX];
    size_t heap_size;
    const char* app_config_path;
    myst_host_enc_uid_gid_mappings host_enc_uid_gid_mappings;
    myst_fork_mode_t fork_mode;
};

static void _get_options(
    int* argc,
    const char* argv[],
    myst_args_t* mount_mappings,
    struct options* opts)
{
    memset(opts, 0, sizeof(struct options));

    // process ID mapping options
    cli_get_mapping_opts(argc, argv, &opts->host_enc_uid_gid_mappings);

    // retrieve mount mapping options
    cli_get_mount_mapping_opts(argc, argv, mount_mappings);

    /* Get --trace-syscalls option */
    if (cli_getopt(argc, argv, "--trace-syscalls", NULL) == 0 ||
        cli_getopt(argc, argv, "--strace", NULL) == 0)
    {
        opts->trace_syscalls = true;
    }

    /* Get --trace-errors option */
    if (cli_getopt(argc, argv, "--trace-errors", NULL) == 0 ||
        cli_getopt(argc, argv, "--etrace", NULL) == 0)
    {
        opts->trace_errors = true;
    }

    /* Get --shell option */
    if (cli_getopt(argc, argv, "--shell", NULL) == 0)
        opts->shell_mode = true;

    /* Get --memcheck option */
    if (cli_getopt(argc, argv, "--memcheck", NULL) == 0)
        opts->memcheck = true;

    /* Get --nobrk option */
    if (cli_getopt(argc, argv, "--nobrk", NULL) == 0)
        opts->nobrk = true;

    /* Get --perf option */
    if (cli_getopt(argc, argv, "--perf", NULL) == 0)
        opts->perf = true;

    /* Get --report-native-tids option */
    if (cli_getopt(argc, argv, "--report-native-tids", NULL) == 0)
        opts->report_native_tids = true;

    if (get_fork_mode_opts(argc, argv, &opts->fork_mode) != 0)
        _err(
            "%s: invalid --fork-mode option. Only \"none\" and "
            "\"pseudo_kill_children\" are currently supported\n",
            argv[0]);

    /* Get --max-affinity-cpus */
    {
        const char* arg = NULL;

        if ((cli_getopt(argc, argv, "--max-affinity-cpus", &arg) == 0))
        {
            char* end = NULL;
            size_t val = strtoull(arg, &end, 10);

            if (!end || *end != '\0')
                _err("bad --max-affinity-cpus=%s option", arg);

            opts->max_affinity_cpus = val;
        }
    }

    /* determine whether debug symbols are needed */
    {
        int r;

        if ((r = process_is_being_traced()) < 0)
            _err("process_is_being_traced() failed: %d", r);

        opts->debug_symbols = (bool)r;
    }

    /* Get MYST_MEMCHECK environment variable */
    {
        const char* env;
        if ((env = getenv("MYST_MEMCHECK")) && strcmp(env, "1") == 0)
            opts->memcheck = true;
    }

    /* Get --memory-size or --memory-size option */
    {
        const char* opt;
        const char* arg = NULL;

        if ((cli_getopt(argc, argv, "--memory-size", &arg) == 0))
        {
            opt = "--memory-size";
        }

        if (!arg && cli_getopt(argc, argv, "--user-mem-size", &arg) == 0)
        {
            /* legacy option (kept for backwards compatibility) */
            opt = "--user-mem-size";
        }

        if (arg)
        {
            if ((myst_expand_size_string_to_ulong(arg, &opts->heap_size) !=
                 0) ||
                (myst_round_up(opts->heap_size, PAGE_SIZE, &opts->heap_size) !=
                 0))
            {
                _err("%s <size> -- bad suffix (must be k, m, or g)\n", opt);
            }
        }
    }

    // get app config if present
    cli_getopt(argc, argv, "--app-config-path", &opts->app_config_path);
}

myst_kernel_args_t kernel_args;

static void _sigaction_handler(int sig, siginfo_t* si, void* context)
{
    ucontext_t* ucontext = (ucontext_t*)context;
    mcontext_t* mcontext = &ucontext->uc_mcontext;
    kernel_args.myst_handle_host_signal(si, mcontext);
}

static void _install_signal_handlers()
{
    struct sigaction sa;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = _sigaction_handler;
    if (sigaction(SIGSEGV, &sa, NULL) == -1)
        _err("Failed to register SIGSEGV signal handler\n");
    if (sigaction(SIGILL, &sa, NULL) == -1)
        _err("Failed to register SIGILL signal handler\n");
    if (sigaction(SIGFPE, &sa, NULL) == -1)
        _err("Failed to register SIGFPE signal handler\n");
}

/* the address of this is eventually passed to futex (uaddr argument) */
static __thread int _thread_event;

static int _enter_kernel(
    int argc,
    const char* argv[],
    int envc,
    const char* envp[],
    myst_args_t* mount_mappings,
    struct options* options,
    const void* mmap_addr,
    size_t mmap_length,
    long (*tcall)(long n, long params[6]),
    int* return_status,
    char* err,
    size_t err_size)
{
    int ret = 0;
    const void* image_data = mmap_addr;
    size_t image_size = mmap_length;
    myst_kernel_entry_t entry;
    const char* cwd = "/";
    const char* hostname = NULL;
    config_parsed_data_t pd;
    const char target[] = "MYST_TARGET=linux";
    void* regions_end = (uint8_t*)mmap_addr + mmap_length;
    bool have_config = false;
    myst_fork_mode_t fork_mode = options->fork_mode;

    memset(&pd, 0, sizeof(pd));
    memset(&kernel_args, 0, sizeof(kernel_args));

    if (err)
        *err = '\0';
    else
        ERAISE(-EINVAL);

    if (return_status)
        *return_status = 0;

    if (!argv || !envp || !options || !mmap_addr || !tcall || !return_status)
    {
        snprintf(err, err_size, "bad argument");
        ERAISE(-EINVAL);
    }

    /* extract any configuration settings */
    {
        const char name[] = MYST_REGION_CONFIG;
        myst_region_t r;

        if (myst_region_find(regions_end, name, &r) == 0)
        {
            if (parse_config_from_buffer(r.data, r.size, &pd) == 0)
            {
                /* set the current working directory if any */
                if (pd.cwd)
                    cwd = pd.cwd;

                /* set the hostname if any */
                if (pd.hostname)
                    hostname = pd.hostname;

                /* Add mount source paths to config read mount points */
                if (!myst_merge_mount_mapping_and_config(
                        &pd.mounts, mount_mappings) ||
                    !myst_validate_mount_config(&pd.mounts))
                    ERAISE(-EINVAL);

                fork_mode = pd.fork_mode;

                have_config = true;
            }
            else
            {
                snprintf(err, err_size, "failed to parse config data");
                ERAISE(-EINVAL);
            }
        }
    }

    /* initialize the kernel arguments */
    {
        const bool have_syscall_instruction = true;
        const bool tee_debug_mode = true;
        const size_t max_threads = LONG_MAX;
        char terr[256] = "";

        if (init_kernel_args(
                &kernel_args,
                target,
                argc,
                argv,
                envc,
                envp,
                cwd,
                &options->host_enc_uid_gid_mappings,
                &pd.mounts,
                hostname,
                regions_end,
                image_data,
                image_size,
                max_threads,
                options->trace_errors,
                options->trace_syscalls,
                have_syscall_instruction,
                tee_debug_mode,
                (uint64_t)&_thread_event,
                (pid_t)syscall(SYS_gettid),
                options->max_affinity_cpus,
                fork_mode,
                tcall,
                options->rootfs,
                terr,
                sizeof(terr)) != 0)
        {
            snprintf(err, err_size, "init_kernel_args failed: %s", terr);
            ERAISE(-EINVAL);
        }
    }

    /* set the shell mode flag */
    kernel_args.shell_mode = options->shell_mode;

    /* set whether debug symbols are needed */
    kernel_args.debug_symbols = options->debug_symbols;

    kernel_args.memcheck = options->memcheck;

    kernel_args.nobrk = options->nobrk;

    kernel_args.perf = options->perf;

    /* check whether FSGSBASE instructions are supported */
    if (test_user_space_fsgsbase() == 0)
        kernel_args.have_fsgsbase_instructions = true;

    /* pass the start time into the kernel */
    {
        struct timespec start_time;

        if (clock_gettime(CLOCK_REALTIME, &start_time) != 0)
        {
            snprintf(err, err_size, "clock_gettime() failed");
            ERAISE(-ENOSYS);
        }

        kernel_args.start_time_sec = start_time.tv_sec;
        kernel_args.start_time_nsec = start_time.tv_nsec;
    }

    kernel_args.report_native_tids = options->report_native_tids;

    /* Resolve the the kernel entry point */
    const elf_ehdr_t* ehdr = kernel_args.kernel_data;
    entry = (myst_kernel_entry_t)((uint8_t*)ehdr + ehdr->e_entry);

    if ((uint8_t*)entry < (uint8_t*)ehdr ||
        (uint8_t*)entry >= (uint8_t*)ehdr + kernel_args.kernel_size)
    {
        snprintf(err, err_size, "kernel entry point is out of bounds");
        ERAISE(-EINVAL);
    }

    _install_signal_handlers();

    *return_status = (*entry)(&kernel_args);

done:

    if (have_config)
        free_config(&pd);
    if (kernel_args.envp)
        free(kernel_args.envp);

    return ret;
}

__attribute__((__unused__)) static long _tcall(long n, long params[6])
{
    return myst_tcall(n, params);
}

int exec_linux_action(int argc, const char* argv[], const char* envp[])
{
    struct options opts;
    const char* rootfs_arg;
    const char* program_arg;
    static const size_t max_pubkeys = 128;
    const char* pubkeys[max_pubkeys];
    size_t num_pubkeys = 0;
    char pubkeys_path[PATH_MAX];
    char roothashes_path[PATH_MAX];
    char rootfs_path[] = "/tmp/mystXXXXXX";
    const region_details* details;
    void* mmap_addr = NULL;
    size_t mmap_length = 0;
    char err[256];
    myst_args_t mount_mappings = {0};
    myst_buf_t roothash_buf = MYST_BUF_INITIALIZER;

    (void)program_arg;

    /* Get the command-line options */
    _get_options(&argc, argv, &mount_mappings, &opts);

    /* Get --pubkey=filename options */
    get_pubkeys_options(&argc, argv, pubkeys, max_pubkeys, &num_pubkeys);

    /* Get --roothash=filename options */
    get_roothash_options(&argc, argv, &roothash_buf);

    /* Check usage */
    if (argc < 4)
    {
        fprintf(stderr, USAGE_FORMAT, argv[0]);
        return 1;
    }

    rootfs_arg = argv[2];
    program_arg = argv[3];

    if (extract_roothashes_from_ext2_images(
            rootfs_arg, &mount_mappings, &roothash_buf) != 0)
    {
        _err("failed to extract roothashes from EXT2 images");
    }

    create_pubkeys_file(pubkeys, num_pubkeys, pubkeys_path);

    if (create_roothashes_file(&roothash_buf, roothashes_path) != 0)
        _err("failed to create roothashes file");

    /* copy the rootfs path to the options */
    if (myst_strlcpy(opts.rootfs, rootfs_arg, sizeof(opts.rootfs)) >=
        sizeof(opts.rootfs))
    {
        _err("<rootfs> command line argument is too long: %s", rootfs_arg);
    }

    /* if not a CPIO archive, create a zero-filled file with one page */
    if (myst_cpio_test(rootfs_arg) == -ENOTSUP)
    {
        int fd;
        uint8_t page[PAGE_SIZE];

        if ((fd = mkstemp(rootfs_path)) < 0)
            _err("failed to create temporary file");

        memset(page, 0, sizeof(page));

        if (write(fd, page, sizeof(page)) != sizeof(page))
            _err("failed to create file");

        close(fd);
        rootfs_arg = rootfs_path;
    }

    /* load the regions into memory */
    if (!(details = create_region_details_from_files(
              program_arg,
              rootfs_arg,
              pubkeys_path,
              roothashes_path,
              opts.app_config_path,
              opts.heap_size)))
    {
        _err("create_region_details_from_files() failed");
    }

    /* map the regions onto a flat memory mapping */
    if (map_regions(&mmap_addr, &mmap_length) != 0)
    {
        _err("map_regions() failed");
    }

    unlink(pubkeys_path);
    unlink(roothashes_path);

    int envc = 0;
    while (envp[envc] != NULL)
    {
        envc++;
    }
    int return_status = 0;

    assert(argc >= 4);
    argc -= 3;
    argv += 3;

    /* Enter the kernel image */
    if (_enter_kernel(
            argc,
            argv,
            envc,
            envp,
            &mount_mappings,
            &opts,
            mmap_addr,
            mmap_length,
            _tcall,
            &return_status,
            err,
            sizeof(err)) != 0)
    {
        _err("%s", err);
    }

    myst_args_release(&mount_mappings);

    free_region_details();

    if (rootfs_arg == rootfs_path)
        unlink(rootfs_path);

    return return_status;
}

/*
**==============================================================================
**
** Threading tcalls:
**
**==============================================================================
*/

static void* _thread_func(void* arg)
{
    uint64_t cookie = (uint64_t)arg;
    uint64_t event = (uint64_t)&_thread_event;

    if (myst_run_thread(cookie, event, (pid_t)syscall(SYS_gettid)) != 0)
    {
        fprintf(stderr, "myst_run_thread() failed\n");
        exit(1);
    }

    return NULL;
}

long myst_tcall_create_thread(uint64_t cookie)
{
    long ret = 0;
    pthread_t t;
    pthread_attr_t attr;

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    if (pthread_create(&t, &attr, _thread_func, (void*)cookie) != 0)
    {
        ret = -EINVAL;
        goto done;
    }

done:
    pthread_attr_destroy(&attr);
    return ret;
}
