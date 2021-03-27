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
#include <myst/region.h>
#include <myst/reloc.h>
#include <myst/round.h>
#include <myst/strings.h>
#include <myst/tcall.h>
#include <myst/thread.h>

#include "../config.h"
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
    char rootfs[PATH_MAX];
    size_t heap_size;
    const char* app_config_path;
};

static void _get_options(int* argc, const char* argv[], struct options* opts)
{
    memset(opts, 0, sizeof(struct options));

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
}

/* the address of this is eventually passed to futex (uaddr argument) */
static __thread int _thread_event;

static int _enter_kernel(
    int argc,
    const char* argv[],
    int envc,
    const char* envp[],
    struct options* options,
    const void* regions_end,
    long (*tcall)(long n, long params[6]),
    int* return_status,
    char* err,
    size_t err_size)
{
    int ret = 0;
    myst_kernel_args_t args;
    const elf_ehdr_t* ehdr;
    myst_kernel_entry_t entry;
    myst_args_t env;
    const char* cwd = "/";       /* default */
    const char* hostname = NULL; // kernel has a default
    myst_region_t config_region;
    myst_region_t kernel_region;
    myst_region_t kernel_reloc_region;
    myst_region_t kernel_symtab_region;
    myst_region_t kernel_dynsym_region;
    myst_region_t kernel_strtab_region;
    myst_region_t kernel_dynstr_region;
    myst_region_t crt_region;
    myst_region_t crt_reloc_region;
    myst_region_t mman_region;
    myst_region_t rootfs_region;
    myst_region_t archive_region;

    if (err)
        *err = '\0';
    else
        ERAISE(-EINVAL);

    memset(&env, 0, sizeof(env));

    if (!argv || !envp || !options || !regions_end || !tcall || !return_status)
    {
        snprintf(err, err_size, "bad argument");
        ERAISE(-EINVAL);
    }

    /* find the optional config region */
    {
        const char name[] = MYST_CONFIG_REGION_NAME;

        if (myst_region_find(regions_end, name, &config_region) != 0)
        {
            memset(&config_region, 0, sizeof(config_region));
        }
    }

    /* find the kernel region */
    {
        const char name[] = MYST_KERNEL_REGION_NAME;

        if (myst_region_find(regions_end, name, &kernel_region) != 0)
        {
            snprintf(err, err_size, "failed to find %s", name);
            ERAISE(-EINVAL);
        }

        ehdr = kernel_region.data;
    }

    /* find the kernel reloc region */
    {
        const char name[] = MYST_KERNEL_RELOC_REGION_NAME;

        if (myst_region_find(regions_end, name, &kernel_reloc_region) != 0)
        {
            snprintf(err, err_size, "failed to find %s", name);
            ERAISE(-EINVAL);
        }
    }

    /* apply relocations to the kernel image */
    {
        if (myst_apply_relocations(
                kernel_region.data,
                kernel_region.size,
                kernel_reloc_region.data,
                kernel_reloc_region.size) != 0)
        {
            fprintf(stderr, "failed to relocate kernel symbols\n");
            assert(0);
        }
    }

    /* find the kernel symtab region */
    {
        const char name[] = MYST_KERNEL_SYMTAB_REGION_NAME;

        if (myst_region_find(regions_end, name, &kernel_symtab_region) != 0)
        {
            snprintf(err, err_size, "failed to find %s", name);
            ERAISE(-EINVAL);
        }
    }

    /* find the kernel dynsym region */
    {
        const char name[] = MYST_KERNEL_DYNSYM_REGION_NAME;

        if (myst_region_find(regions_end, name, &kernel_dynsym_region) != 0)
        {
            snprintf(err, err_size, "failed to find %s", name);
            ERAISE(-EINVAL);
        }
    }

    /* find the kernel strtab region */
    {
        const char name[] = MYST_KERNEL_STRTAB_REGION_NAME;

        if (myst_region_find(regions_end, name, &kernel_strtab_region) != 0)
        {
            snprintf(err, err_size, "failed to find %s", name);
            ERAISE(-EINVAL);
        }
    }

    /* find the kernel dynstr region */
    {
        const char name[] = MYST_KERNEL_DYNSTR_REGION_NAME;

        if (myst_region_find(regions_end, name, &kernel_dynstr_region) != 0)
        {
            snprintf(err, err_size, "failed to find %s", name);
            ERAISE(-EINVAL);
        }
    }

    /* find the crt region */
    {
        const char name[] = MYST_CRT_REGION_NAME;

        if (myst_region_find(regions_end, name, &crt_region) != 0)
        {
            snprintf(err, err_size, "failed to find %s", name);
            ERAISE(-EINVAL);
        }
    }

    /* find the crt reloc region */
    {
        const char name[] = MYST_CRT_RELOC_REGION_NAME;

        if (myst_region_find(regions_end, name, &crt_reloc_region) != 0)
        {
            snprintf(err, err_size, "failed to find %s", name);
            ERAISE(-EINVAL);
        }
    }

    /* find the mman region */
    {
        const char name[] = MYST_MMAN_REGION_NAME;

        if (myst_region_find(regions_end, name, &mman_region) != 0)
        {
            snprintf(err, err_size, "failed to find %s", name);
            ERAISE(-EINVAL);
        }
    }

    /* find the rootfs region */
    {
        const char name[] = MYST_ROOTFS_REGION_NAME;

        if (myst_region_find(regions_end, name, &rootfs_region) != 0)
        {
            snprintf(err, err_size, "failed to find %s", name);
            ERAISE(-EINVAL);
        }
    }

    /* find the archive region */
    {
        const char name[] = MYST_ARCHIVE_REGION_NAME;

        if (myst_region_find(regions_end, name, &archive_region) != 0)
        {
            snprintf(err, err_size, "failed to find %s", name);
            ERAISE(-EINVAL);
        }
    }

    if (return_status)
        *return_status = 0;

    /* Make a copy of the environment variables */
    {
        if (myst_args_init(&env) != 0)
        {
            snprintf(err, err_size, "myst_args_init() failed");
            ERAISE(-EINVAL);
        }

        if (myst_args_append(&env, envp, envc) != 0)
        {
            snprintf(err, err_size, "myst_args_append() failed");
            ERAISE(-EINVAL);
        }
    }

    /* Inject the MYST_TARGET environment variable */
    {
        const char val[] = "MYST_TARGET=";

        for (size_t i = 0; i < env.size; i++)
        {
            if (strncmp(env.data[i], val, sizeof(val) - 1) == 0)
            {
                snprintf(err, err_size, "environment already contains %s", val);
                ERAISE(-EINVAL);
            }
        }

        myst_args_append1(&env, "MYST_TARGET=linux");
    }

    /* Extract any settings from the config, if present */
    config_parsed_data_t parsed_data = {0};
    if (config_region.data && config_region.size)
    {
        if (parse_config_from_buffer(
                config_region.data, config_region.size, &parsed_data) == 0)
        {
            /* only override if we have a cwd config item */
            if (parsed_data.cwd)
                cwd = parsed_data.cwd;

            if (parsed_data.hostname)
                hostname = parsed_data.hostname;
        }
        else
        {
            _err("Failed to parse app config from");
        }
    }

    memset(&args, 0, sizeof(args));
    args.image_data = (void*)0;
    args.image_size = 0x7fffffffffffffff;
    args.kernel_data = kernel_region.data;
    args.kernel_size = kernel_region.size;
    args.reloc_data = kernel_reloc_region.data;
    args.reloc_size = kernel_reloc_region.size;
    args.symtab_data = kernel_symtab_region.data;
    args.symtab_size = kernel_symtab_region.size;
    args.dynsym_data = kernel_dynsym_region.data;
    args.dynsym_size = kernel_dynsym_region.size;
    args.strtab_data = kernel_strtab_region.data;
    args.strtab_size = kernel_strtab_region.size;
    args.dynstr_data = kernel_dynstr_region.data;
    args.dynstr_size = kernel_dynstr_region.size;
    args.crt_data = crt_region.data;
    args.crt_size = crt_region.size;
    args.crt_reloc_data = crt_reloc_region.data;
    args.crt_reloc_size = crt_reloc_region.size;
    args.mman_data = mman_region.data;
    args.mman_size = mman_region.size;
    args.rootfs_data = rootfs_region.data;
    args.rootfs_size = rootfs_region.size;
    args.archive_data = archive_region.data;
    args.archive_size = archive_region.size;
    args.argc = argc;
    args.argv = argv;
    args.envc = env.size;
    args.envp = env.data;
    args.cwd = cwd;
    args.hostname = hostname;
    args.max_threads = LONG_MAX;
    args.trace_errors = options->trace_errors;
    args.trace_syscalls = options->trace_syscalls;
    args.have_syscall_instruction = true;
    args.export_ramfs = options->export_ramfs;
    args.event = (uint64_t)&_thread_event;
    args.tee_debug_mode = true;
    args.tcall = tcall;

    if (options->rootfs)
        myst_strlcpy(args.rootfs, options->rootfs, sizeof(args.rootfs));

    /* Verify that the kernel is an ELF image */
    if (!elf_valid_ehdr_ident(ehdr))
    {
        snprintf(err, err_size, "bad kernel image");
        ERAISE(-EINVAL);
    }

    /* Resolve the the kernel entry point */
    entry = (myst_kernel_entry_t)((uint8_t*)ehdr + ehdr->e_entry);

    if ((uint8_t*)entry < (uint8_t*)ehdr ||
        (uint8_t*)entry >= (uint8_t*)ehdr + kernel_region.size)
    {
        snprintf(err, err_size, "kernel entry point is out of bounds");
        ERAISE(-EINVAL);
    }

    *return_status = (*entry)(&args);

done:

    if (env.data)
        free(env.data);

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
            mmap_addr + mmap_length,
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
