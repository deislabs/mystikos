#include <stdlib.h>
#include <string.h>

#include <myst/args.h>
#include <myst/elf.h>
#include <myst/eraise.h>
#include <myst/kernel.h>
#include <myst/region.h>
#include <myst/reloc.h>
#include <myst/strings.h>

#include "config.h"
#include "kargs.h"

int init_kernel_args(
    myst_kernel_args_t* args,
    const char* target,
    int argc,
    const char* argv[],
    int envc,
    const char* envp[],
    const char* cwd,
    const char* hostname,
    const void* regions_end,
    const void* image_data,
    size_t image_size,
    size_t max_threads,
    bool trace_errors,
    bool trace_syscalls,
    bool export_ramfs,
    bool have_syscall_instruction,
    bool tee_debug_mode,
    uint64_t thread_event,
    long (*tcall)(long n, long params[6]),
    const char* rootfs,
    char* err,
    size_t err_size)
{
    int ret;
    myst_args_t env;

    memset(&env, 0, sizeof(env));

    if (args)
        memset(args, 0, sizeof(myst_kernel_args_t));

    if (!args || !argv || !envp || !cwd || !regions_end || !err)
        ERAISE(-EINVAL);

    /* find the kernel region */
    {
        const char name[] = MYST_KERNEL_REGION_NAME;
        myst_region_t region;

        if (myst_region_find(regions_end, name, &region) != 0)
        {
            snprintf(err, err_size, "cannot find region: %s", name);
            ERAISE(-EINVAL);
        }

        /* verify that the kernel image has the ELF header */
        if (!elf_valid_ehdr_ident((elf_ehdr_t*)region.data))
        {
            snprintf(err, err_size, "bad kernel image");
            ERAISE(-EINVAL);
        }

        args->kernel_data = region.data;
        args->kernel_size = region.size;
    }

    /* find the kernel reloc region */
    {
        const char name[] = MYST_KERNEL_RELOC_REGION_NAME;
        myst_region_t region;

        if (myst_region_find(regions_end, name, &region) != 0)
        {
            snprintf(err, err_size, "cannot find region: %s", name);
            ERAISE(-EINVAL);
        }

        args->reloc_data = region.data;
        args->reloc_size = region.size;
    }

    /* apply relocations to the kernel image */
    {
        if (myst_apply_relocations(
                args->kernel_data,
                args->kernel_size,
                args->reloc_data,
                args->reloc_size) != 0)
        {
            snprintf(err, err_size, "failed to relocate kernel symbols");
            ERAISE(-EINVAL);
        }
    }

    /* find the kernel symtab region */
    {
        const char name[] = MYST_KERNEL_SYMTAB_REGION_NAME;
        myst_region_t region;

        if (myst_region_find(regions_end, name, &region) != 0)
        {
            snprintf(err, err_size, "cannot find region: %s", name);
            ERAISE(-EINVAL);
        }

        args->symtab_data = region.data;
        args->symtab_size = region.size;
    }

    /* find the kernel dynsym region */
    {
        const char name[] = MYST_KERNEL_DYNSYM_REGION_NAME;
        myst_region_t region;

        if (myst_region_find(regions_end, name, &region) != 0)
        {
            snprintf(err, err_size, "cannot find region: %s", name);
            ERAISE(-EINVAL);
        }

        args->dynsym_data = region.data;
        args->dynsym_size = region.size;
    }

    /* find the kernel strtab region */
    {
        const char name[] = MYST_KERNEL_STRTAB_REGION_NAME;
        myst_region_t region;

        if (myst_region_find(regions_end, name, &region) != 0)
        {
            snprintf(err, err_size, "cannot find region: %s", name);
            ERAISE(-EINVAL);
        }

        args->strtab_data = region.data;
        args->strtab_size = region.size;
    }

    /* find the kernel dynstr region */
    {
        const char name[] = MYST_KERNEL_DYNSTR_REGION_NAME;
        myst_region_t region;

        if (myst_region_find(regions_end, name, &region) != 0)
        {
            snprintf(err, err_size, "cannot find region: %s", name);
            ERAISE(-EINVAL);
        }

        args->dynstr_data = region.data;
        args->dynstr_size = region.size;
    }

    /* find the crt region */
    {
        const char name[] = MYST_CRT_REGION_NAME;
        myst_region_t region;

        if (myst_region_find(regions_end, name, &region) != 0)
        {
            snprintf(err, err_size, "cannot find region: %s", name);
            ERAISE(-EINVAL);
        }

        args->crt_data = region.data;
        args->crt_size = region.size;
    }

    /* find the crt reloc region */
    {
        const char name[] = MYST_CRT_RELOC_REGION_NAME;
        myst_region_t region;

        if (myst_region_find(regions_end, name, &region) != 0)
        {
            snprintf(err, err_size, "cannot find region: %s", name);
            ERAISE(-EINVAL);
        }

        args->crt_reloc_data = region.data;
        args->crt_reloc_size = region.size;
    }

    /* find the mman region */
    {
        const char name[] = MYST_MMAN_REGION_NAME;
        myst_region_t region;

        if (myst_region_find(regions_end, name, &region) != 0)
        {
            snprintf(err, err_size, "cannot find region: %s", name);
            ERAISE(-EINVAL);
        }

        args->mman_data = region.data;
        args->mman_size = region.size;
    }

    /* find the rootfs region */
    {
        const char name[] = MYST_ROOTFS_REGION_NAME;
        myst_region_t region;

        if (myst_region_find(regions_end, name, &region) != 0)
        {
            snprintf(err, err_size, "cannot find region: %s", name);
            ERAISE(-EINVAL);
        }

        args->rootfs_data = region.data;
        args->rootfs_size = region.size;
    }

    /* find the archive region */
    {
        const char name[] = MYST_ARCHIVE_REGION_NAME;
        myst_region_t region;

        if (myst_region_find(regions_end, name, &region) != 0)
        {
            snprintf(err, err_size, "cannot find region: %s", name);
            ERAISE(-EINVAL);
        }

        args->archive_data = region.data;
        args->archive_size = region.size;
    }

    /* Make a copy of the environment variables */
    {
        if (myst_args_init(&env) != 0)
        {
            snprintf(err, err_size, "myst_args_init() failed");
            ERAISE(-EINVAL);
        }

        if (myst_args_append(&env, envp, (size_t)envc) != 0)
        {
            snprintf(err, err_size, "myst_args_append() failed");
            ERAISE(-EINVAL);
        }
    }

    /* inject the MYST_TARGET environment variable */
    {
        const char val[] = "MYST_TARGET=";
        bool found = false;

        for (size_t i = 0; i < env.size; i++)
        {
            if (strncmp(env.data[i], val, sizeof(val) - 1) == 0)
            {
                found = true;
                break;
            }
        }

        if (!found)
            myst_args_append1(&env, target);
    }

    /* initialize the current working directory default */
    if (cwd)
    {
        MYST_STRLCPY(args->cwd_buffer, cwd);
        args->cwd = args->cwd_buffer;
    }
    else
    {
        MYST_STRLCPY(args->cwd_buffer, "/");
    }

    /* initialize the hostname default */
    if (hostname)
    {
        MYST_STRLCPY(args->hostname_buffer, hostname);
        args->hostname = args->hostname_buffer;
    }

    args->image_data = image_data;
    args->image_size = image_size;
    args->argc = (size_t)argc;
    args->argv = argv;
    args->envc = env.size;
    args->envp = env.data;
    args->max_threads = max_threads;
    args->trace_errors = trace_errors;
    args->trace_syscalls = trace_syscalls;
    args->have_syscall_instruction = have_syscall_instruction;
    args->export_ramfs = export_ramfs;
    args->event = thread_event;
    args->tee_debug_mode = tee_debug_mode;
    args->tcall = tcall;

    if (rootfs)
        MYST_STRLCPY(args->rootfs, rootfs);

done:

    return ret;
}
