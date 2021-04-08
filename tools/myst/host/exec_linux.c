// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <linux/futex.h>
#include <pthread.h>
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
#include <myst/strings.h>
#include <myst/tcall.h>
#include <myst/thread.h>

#include "../config.h"
#include "../kargs.h"
#include "../shared.h"
#include "archive.h"
#include "exec_linux.h"
#include "regions.h"
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
\n\
"

struct options
{
    bool trace_errors;
    bool trace_syscalls;
    bool export_ramfs;
    bool shell_mode;
    bool memcheck;
    char rootfs[PATH_MAX];
    size_t heap_size;
    const char* app_config_path;
};

static void _get_options(int* argc, const char* argv[], struct options* opts)
{
    memset(opts, 0, sizeof(struct options));
    size_t max_threads = 0;

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

    /* Get --export-ramfs option */
    if (cli_getopt(argc, argv, "--export-ramfs", NULL) == 0)
        opts->export_ramfs = true;

    /* Set export_ramfs option based on MYST_ENABLE_GCOV env variable */
    {
        const char* val;

        if ((val = getenv("MYST_ENABLE_GCOV")) && strcmp(val, "1") == 0)
            opts->export_ramfs = true;
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

    /* get the --max-threads=n option */
    {
        const char* optarg;

        if (cli_getopt(argc, argv, "--max-threads", &optarg) == 0)
        {
            char* end = NULL;
            max_threads = strtoul(optarg, &end, 10);

            if (!end || *end)
                _err("bad --max-threads argument: %s", optarg);

            if (max_threads > ENCLAVE_MAX_THREADS)
            {
                _err(
                    "--max-threads must be <= %u: %s",
                    ENCLAVE_MAX_THREADS,
                    optarg);
            }
        }
    }
}

/* the address of this is eventually passed to futex (uaddr argument) */
static __thread int _thread_event;

static int _enter_kernel(
    int argc,
    const char* argv[],
    int envc,
    const char* envp[],
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
    myst_kernel_args_t args;
    myst_kernel_entry_t entry;
    const char* cwd = "/";
    const char* hostname = NULL;
    config_parsed_data_t pd;
    const char target[] = "MYST_TARGET=linux";
    void* regions_end = (uint8_t*)mmap_addr + mmap_length;

    memset(&pd, 0, sizeof(pd));
    memset(&args, 0, sizeof(args));

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
        char terr[256];

        if (init_kernel_args(
                &args,
                target,
                argc,
                argv,
                envc,
                envp,
                cwd,
                hostname,
                regions_end,
                image_data,
                image_size,
                max_threads,
                options->trace_errors,
                options->trace_syscalls,
                options->export_ramfs,
                have_syscall_instruction,
                tee_debug_mode,
                (uint64_t)&_thread_event,
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
    args.shell_mode = options->shell_mode;

    args.memcheck = options->memcheck;

    /* Resolve the the kernel entry point */
    const elf_ehdr_t* ehdr = args.kernel_data;
    entry = (myst_kernel_entry_t)((uint8_t*)ehdr + ehdr->e_entry);

    if ((uint8_t*)entry < (uint8_t*)ehdr ||
        (uint8_t*)entry >= (uint8_t*)ehdr + args.kernel_size)
    {
        snprintf(err, err_size, "kernel entry point is out of bounds");
        ERAISE(-EINVAL);
    }

    *return_status = (*entry)(&args);

done:

    if (args.envp)
        free(args.envp);

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
    static const size_t max_roothashes = 128;
    const char* roothashes[max_roothashes];
    size_t num_roothashes = 0;
    char archive_path[PATH_MAX];
    char rootfs_path[] = "/tmp/mystXXXXXX";
    const region_details* details;
    void* mmap_addr = NULL;
    size_t mmap_length = 0;
    char err[256];

    (void)program_arg;

    /* Get the command-line options */
    _get_options(&argc, argv, &opts);

    /* Get --pubkey=filename options */
    get_archive_options(
        &argc,
        argv,
        pubkeys,
        max_pubkeys,
        &num_pubkeys,
        roothashes,
        max_roothashes,
        &num_roothashes);

    /* Check usage */
    if (argc < 4)
    {
        fprintf(stderr, USAGE_FORMAT, argv[0]);
        return 1;
    }

    rootfs_arg = argv[2];
    program_arg = argv[3];
    create_archive(
        pubkeys, num_pubkeys, roothashes, num_roothashes, archive_path);

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
              archive_path,
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

    unlink(archive_path);

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

    if (myst_run_thread(cookie, event) != 0)
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
