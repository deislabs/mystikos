#include <stdlib.h>
#include <string.h>

#include <myst/args.h>
#include <myst/elf.h>
#include <myst/eraise.h>
#include <myst/kernel.h>
#include <myst/regions.h>
#include <myst/reloc.h>
#include <myst/strings.h>

#include "config.h"
#include "kargs.h"

static int _find_region(
    const void* regions_end,
    const char* name,
    void** data,
    size_t* size,
    char* err,
    size_t err_size)
{
    int ret = 0;
    myst_region_t region;

    if (myst_region_find(regions_end, name, &region) != 0)
    {
        snprintf(err, err_size, "cannot find region: %s", name);
        ERAISE(-EINVAL);
    }

    *data = region.data;
    *size = region.file_size;

done:
    return ret;
}

int init_kernel_args(
    myst_kernel_args_t* args,
    const char* target,
    int argc,
    const char* argv[],
    int envc,
    const char* envp[],
    const char* cwd,
    myst_host_enc_uid_gid_mappings* host_enc_uid_gid_mappings,
    myst_mounts_config_t* mounts,
    myst_wanted_secrets_t* wanted_secrets,
    const char* hostname,
    const void* regions_end,
    const void* image_data,
    size_t image_size,
    size_t max_threads,
    bool trace_errors,
    bool trace_times,
    const myst_strace_config_t* strace_config,
    bool have_syscall_instruction,
    bool tee_debug_mode,
    uint64_t thread_event,
    pid_t target_tid,
    size_t max_affinity_cpus,
    myst_fork_mode_t fork_mode,
    long (*tcall)(long n, long params[6]),
    const char* rootfs,
    char* err,
    bool unhandled_syscall_enosys,
    size_t err_size,
    bool crt_memcheck)
{
    int ret = 0;
    myst_args_t env;

    memset(&env, 0, sizeof(env));

    if (args)
        memset(args, 0, sizeof(myst_kernel_args_t));

    if (!args || !argv || !envp || !cwd || !regions_end || !err)
        ERAISE(-EINVAL);

    /* find the kernel region */
    ECHECK(_find_region(
        regions_end,
        MYST_REGION_KERNEL,
        (void**)&args->kernel_data,
        &args->kernel_size,
        err,
        err_size));

    /* verify that the kernel image has the ELF header */
    if (!elf_valid_ehdr_ident((elf_ehdr_t*)args->kernel_data))
    {
        snprintf(err, err_size, "bad kernel image");
        ERAISE(-EINVAL);
    }

    /* find the kernel reloc region */
    ECHECK(_find_region(
        regions_end,
        MYST_REGION_KERNEL_RELOC,
        (void**)&args->reloc_data,
        &args->reloc_size,
        err,
        err_size));

    /* apply relocations to the kernel image */
    if (myst_apply_relocations(
            args->kernel_data,
            args->kernel_size,
            args->reloc_data,
            args->reloc_size) != 0)
    {
        snprintf(err, err_size, "failed to relocate kernel symbols");
        ERAISE(-EINVAL);
    }

    /* find the kernel symtab region */
    ECHECK(_find_region(
        regions_end,
        MYST_REGION_KERNEL_SYMTAB,
        (void**)&args->symtab_data,
        &args->symtab_size,
        err,
        err_size));

    /* find the kernel dynsym region */
    ECHECK(_find_region(
        regions_end,
        MYST_REGION_KERNEL_DYNSYM,
        (void**)&args->dynsym_data,
        &args->dynsym_size,
        err,
        err_size));

    /* find the kernel strtab region */
    ECHECK(_find_region(
        regions_end,
        MYST_REGION_KERNEL_STRTAB,
        (void**)&args->strtab_data,
        &args->strtab_size,
        err,
        err_size));

    /* find the kernel dynstr region */
    ECHECK(_find_region(
        regions_end,
        MYST_REGION_KERNEL_DYNSTR,
        (void**)&args->dynstr_data,
        &args->dynstr_size,
        err,
        err_size));

    /* find the crt region */
    ECHECK(_find_region(
        regions_end,
        MYST_REGION_CRT,
        &args->crt_data,
        &args->crt_size,
        err,
        err_size));

    /* find the crt reloc region */
    ECHECK(_find_region(
        regions_end,
        MYST_REGION_CRT_RELOC,
        (void**)&args->crt_reloc_data,
        &args->crt_reloc_size,
        err,
        err_size));

    /* find the mman region */
    ECHECK(_find_region(
        regions_end,
        MYST_REGION_MMAN,
        &args->mman_data,
        &args->mman_size,
        err,
        err_size));

    /* find the mman-pids region */
    ECHECK(_find_region(
        regions_end,
        MYST_REGION_MMAN_PIDS,
        &args->mman_pids_data,
        &args->mman_pids_size,
        err,
        err_size));

    /* find the fdmappings region */
    ECHECK(_find_region(
        regions_end,
        MYST_REGION_FDMAPPINGS,
        &args->fdmappings_data,
        &args->fdmappings_size,
        err,
        err_size));

    /* find the rootfs region */
    ECHECK(_find_region(
        regions_end,
        MYST_REGION_ROOTFS,
        &args->rootfs_data,
        &args->rootfs_size,
        err,
        err_size));

    /* find the pubkeys region */
    ECHECK(_find_region(
        regions_end,
        MYST_REGION_PUBKEYS,
        &args->pubkeys_data,
        &args->pubkeys_size,
        err,
        err_size));

    /* find the roothashes region */
    ECHECK(_find_region(
        regions_end,
        MYST_REGION_ROOTHASHES,
        &args->roothashes_data,
        &args->roothashes_size,
        err,
        err_size));

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

    /* Copy over host uid gid mappings */
    {
        memcpy(
            &args->host_enc_uid_gid_mappings,
            host_enc_uid_gid_mappings,
            sizeof(myst_host_enc_uid_gid_mappings));
    }

    args->image_data = image_data;
    args->image_size = image_size;
    args->argc = (size_t)argc;
    args->argv = argv;
    args->envc = env.size;
    args->envp = env.data;
    args->max_threads = max_threads;
    args->trace_errors = trace_errors;
    args->trace_times = trace_times;
    args->strace_config = *strace_config;
    args->have_syscall_instruction = have_syscall_instruction;
    args->event = thread_event;
    args->target_tid = target_tid;
    args->max_affinity_cpus = max_affinity_cpus;
    args->fork_mode = fork_mode;
    args->tee_debug_mode = tee_debug_mode;
    args->tcall = tcall;
    args->mounts = mounts;
    args->wanted_secrets = wanted_secrets;
    args->unhandled_syscall_enosys = unhandled_syscall_enosys;
    args->crt_memcheck = crt_memcheck;

    if (rootfs)
        MYST_STRLCPY(args->rootfs, rootfs);

done:

    return ret;
}
