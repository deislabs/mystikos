// Copyright (c) Open Enclave SDK contributors.
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

#include <libos/args.h>
#include <libos/elf.h>
#include <libos/eraise.h>
#include <libos/file.h>
#include <libos/getopt.h>
#include <libos/kernel.h>
#include <libos/reloc.h>
#include <libos/round.h>
#include <libos/tcall.h>
#include <libos/thread.h>

#include "exec_linux.h"
#include "utils.h"

/* standardize this value! */
#define DEFAULT_MMAN_SIZE (256 * 1024 * 1024)

#define USAGE_FORMAT "Usage: %s %s <rootfs> <program> <args...>\n"

struct options
{
    bool trace_syscalls;
    bool export_ramfs;
};

struct regions
{
    void* rootfs_data;
    size_t rootfs_size;
    elf_image_t liboskernel;
    elf_image_t liboscrt;
    void* mman_data;
    size_t mman_size;
};

static int _getopt(
    int* argc,
    const char* argv[],
    const char* opt,
    const char** optarg)
{
    char err[128];
    int ret;

    ret = libos_getopt(argc, argv, opt, optarg, err, sizeof(err));

    if (ret < 0)
        _err("%s", err);

    return ret;
}

static void _get_options(int* argc, const char* argv[], struct options* options)
{
    /* Get --trace-syscalls option */
    if (_getopt(argc, argv, "--trace-syscalls", NULL) == 0 ||
        _getopt(argc, argv, "--strace", NULL) == 0)
    {
        options->trace_syscalls = true;
    }

    /* Get --export-ramfs option */
    if (_getopt(argc, argv, "--export-ramfs", NULL) == 0)
        options->export_ramfs = true;

    /* Set export_ramfs option based on LIBOS_ENABLE_GCOV env variable */
    {
        const char* val;

        if ((val = getenv("LIBOS_ENABLE_GCOV")) && strcmp(val, "1") == 0)
            options->export_ramfs = true;
    }
}

static void* _map_mmap_region(size_t length)
{
    const int prot = PROT_READ | PROT_WRITE | PROT_EXEC;
    const int flags = MAP_ANONYMOUS | MAP_PRIVATE;
    void* addr;

    assert((length % LIBOS_PAGE_SIZE) == 0);

    if ((addr = mmap(NULL, length, prot, flags, -1, 0)) == MAP_FAILED)
        return NULL;

    return addr;
}

static void _load_regions(const char* rootfs, struct regions* r)
{
    char path[PATH_MAX];

    if (libos_load_file(rootfs, &r->rootfs_data, &r->rootfs_size) != 0)
        _err("failed to map file: %s", rootfs);

    /* Load liboscrt.so */
    {
        if (format_liboscrt(path, sizeof(path)) != 0)
            _err("cannot find liboscrt.so");

        if (elf_image_load(path, &r->liboscrt) != 0)
            _err("failed to load C runtime image: %s", path);

        /* Add crt debugger symbols to gdb */
        {
            void* file_data;
            size_t file_size;

            if (libos_load_file(path, &file_data, &file_size) != 0)
                _err("failed to load file: %s", path);

            if (libos_tcall_add_symbol_file(
                    file_data,
                    file_size,
                    r->liboscrt.image_data,
                    r->liboscrt.image_size) != 0)
            {
                _err("failed to add crt debug symbols");
            }

            /* Load symbols and notify gdb */
            libos_tcall_load_symbols();

            free(file_data);
        }
    }

    /* Load liboscrt.so */
    {
        if (format_liboskernel(path, sizeof(path)) != 0)
            _err("cannot find liboskernel.so");

        if (elf_image_load(path, &r->liboskernel) != 0)
            _err("failed to load C runtime image: %s", path);

        /* Add kernel debugger symbols to gdb */
        {
            void* file_data;
            size_t file_size;

            if (libos_load_file(path, &file_data, &file_size) != 0)
                _err("failed to load file: %s", path);

            if (libos_tcall_add_symbol_file(
                    file_data,
                    file_size,
                    r->liboskernel.image_data,
                    r->liboskernel.image_size) != 0)
            {
                _err("failed to add kernel debug symbols");
            }

            /* Load symbols and notify gdb */
            libos_tcall_load_symbols();

            free(file_data);
        }
    }

    if (!(r->mman_data = _map_mmap_region(DEFAULT_MMAN_SIZE)))
        _err("failed to map mmap region");

    /* Apply relocations to the liboscrt.so image */
    if (libos_apply_relocations(
            r->liboscrt.image_data,
            r->liboscrt.image_size,
            r->liboscrt.reloc_data,
            r->liboscrt.reloc_size) != 0)
    {
        _err("failed to apply relocations to liboscrt.so\n");
    }

    /* Apply relocations to the liboskernel.so image */
    if (libos_apply_relocations(
            r->liboskernel.image_data,
            r->liboskernel.image_size,
            r->liboskernel.reloc_data,
            r->liboskernel.reloc_size) != 0)
    {
        _err("failed to apply relocations to liboskernel.so\n");
    }

    r->mman_size = DEFAULT_MMAN_SIZE;
}

static void _release_regions(struct regions* r)
{
    free(r->rootfs_data);
    elf_image_free(&r->liboscrt);
    elf_image_free(&r->liboskernel);
    munmap(r->mman_data, r->mman_size);
}

/* the address of this is eventually passed to futex (uaddr argument) */
static __thread int _thread_event;

static int _enter_kernel(
    int argc,
    const char* argv[],
    int envc,
    const char* envp[],
    struct options* options,
    struct regions* regions,
    long (*tcall)(long n, long params[6]),
    int* return_status,
    char* err,
    size_t err_size)
{
    int ret = 0;
    libos_kernel_args_t args;
    const elf_ehdr_t* ehdr = regions->liboskernel.image_data;
    libos_kernel_entry_t entry;
    libos_args_t env;

    if (err)
        *err = '\0';
    else
        ERAISE(-EINVAL);

    memset(&env, 0, sizeof(env));

    if (!argv || !envp || !options || !regions || !tcall || !return_status)
    {
        snprintf(err, err_size, "bad argument");
        ERAISE(-EINVAL);
    }

    if (return_status)
        *return_status = 0;

    /* Make a copy of the environment variables */
    {
        if (libos_args_init(&env) != 0)
        {
            snprintf(err, err_size, "libos_args_init() failed");
            ERAISE(-EINVAL);
        }

        if (libos_args_append(&env, envp, envc) != 0)
        {
            snprintf(err, err_size, "libos_args_append() failed");
            ERAISE(-EINVAL);
        }
    }

    /* Inject the LIBOS_TARGET environment variable */
    {
        const char val[] = "LIBOS_TARGET=";

        for (size_t i = 0; i < env.size; i++)
        {
            if (strncmp(env.data[i], val, sizeof(val) - 1) == 0)
            {
                snprintf(err, err_size, "environment already contains %s", val);
                ERAISE(-EINVAL);
            }
        }

        libos_args_append1(&env, "LIBOS_TARGET=linux");
    }

    memset(&args, 0, sizeof(args));
    args.image_data = (void*)0;
    args.image_size = 0x7fffffffffffffff;
    args.kernel_data = regions->liboskernel.image_data;
    args.kernel_size = regions->liboskernel.image_size;
    args.reloc_data = regions->liboskernel.reloc_data;
    args.reloc_size = regions->liboskernel.reloc_size;
    args.symtab_data = regions->liboskernel.symtab_data;
    args.symtab_size = regions->liboskernel.symtab_size;
    args.dynsym_data = regions->liboskernel.dynsym_data;
    args.dynsym_size = regions->liboskernel.dynsym_size;
    args.strtab_data = regions->liboskernel.strtab_data;
    args.strtab_size = regions->liboskernel.strtab_size;
    args.dynstr_data = regions->liboskernel.dynstr_data;
    args.dynstr_size = regions->liboskernel.dynstr_size;
    args.argc = argc;
    args.argv = argv;
    args.envc = env.size;
    args.envp = env.data;
    args.mman_data = regions->mman_data;
    args.mman_size = regions->mman_size;
    args.rootfs_data = regions->rootfs_data;
    args.rootfs_size = regions->rootfs_size;
    args.crt_data = regions->liboscrt.image_data;
    args.crt_size = regions->liboscrt.image_size;
    args.max_threads = LONG_MAX;
    args.trace_syscalls = options->trace_syscalls;
    args.have_syscall_instruction = true;
    args.export_ramfs = options->export_ramfs;
    args.event = (uint64_t)&_thread_event;
    args.tcall = tcall;

    /* Verify that the kernel is an ELF image */
    if (!elf_valid_ehdr_ident(ehdr))
    {
        snprintf(err, err_size, "bad kernel image");
        ERAISE(-EINVAL);
    }

    /* Resolve the the kernel entry point */
    entry = (libos_kernel_entry_t)((uint8_t*)ehdr + ehdr->e_entry);

    if ((uint8_t*)entry < (uint8_t*)ehdr ||
        (uint8_t*)entry >= (uint8_t*)ehdr + regions->liboskernel.image_size)
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

static long _tcall(long n, long params[6])
{
    return libos_tcall(n, params);
}

int exec_linux_action(int argc, const char* argv[], const char* envp[])
{
    struct options options = {.trace_syscalls = false, .export_ramfs = false};
    const char* rootfs_arg;
    const char* program_arg;
    struct regions regions;
    char err[128];

    (void)program_arg;

    /* Get the command-line options */
    _get_options(&argc, argv, &options);

    /* Check usage */
    if (argc < 4)
    {
        fprintf(stderr, USAGE_FORMAT, argv[0], argv[1]);
        return 1;
    }

    rootfs_arg = argv[2];
    program_arg = argv[3];

    /* Load the regions into memory */
    _load_regions(rootfs_arg, &regions);

    int envc = 0;
    while (envp[envc] != NULL)
    {
        envc++;
    }
    int return_status = 0;

    assert(argc >= 4);
    argc -= 2;
    argv += 2;
    argv[0] = "exec-linux";

    /* Enter the kernel image */
    if (_enter_kernel(
            argc,
            argv,
            envc,
            envp,
            &options,
            &regions,
            _tcall,
            &return_status,
            err,
            sizeof(err)) != 0)
    {
        _err("%s", err);
    }

    /* release the regions memory */
    _release_regions(&regions);

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

    if (libos_run_thread(cookie, event) != 0)
    {
        fprintf(stderr, "libos_run_thread() failed\n");
        exit(1);
    }

    return NULL;
}

long libos_tcall_create_thread(uint64_t cookie)
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
