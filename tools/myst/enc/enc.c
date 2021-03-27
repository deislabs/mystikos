// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>

#include <openenclave/enclave.h>

#include <elf.h>
#include <myst/args.h>
#include <myst/buf.h>
#include <myst/eraise.h>
#include <myst/file.h>
#include <myst/kernel.h>
#include <myst/mmanutils.h>
#include <myst/mount.h>
#include <myst/ramfs.h>
#include <myst/region.h>
#include <myst/reloc.h>
#include <myst/shm.h>
#include <myst/strings.h>
#include <myst/syscall.h>
#include <myst/tcall.h>
#include <myst/thread.h>
#include <myst/trace.h>

#include "../config.h"
#include "../shared.h"
#include "myst_t.h"

#define IRETFRAME_Rip 0
#define IRETFRAME_SegCs IRETFRAME_Rip + 8
#define IRETFRAME_EFlags IRETFRAME_SegCs + 8
#define IRETFRAME_Rsp IRETFRAME_EFlags + 8

extern volatile const oe_sgx_enclave_properties_t oe_enclave_properties_sgx;

static size_t _get_num_tcs(void)
{
    return oe_enclave_properties_sgx.header.size_settings.num_tcs;
}

int myst_setup_clock(struct clock_ctrl*);

/* Handle illegal SGX instructions */
static uint64_t _vectored_handler(oe_exception_record_t* er)
{
    const uint16_t RDTSC_OPCODE = 0x310F;
    const uint16_t CPUID_OPCODE = 0xA20F;
    const uint16_t IRETQ_OPCODE = 0xCF48;
    const uint16_t opcode = *((uint16_t*)er->context->rip);

    if (er->code == OE_EXCEPTION_ILLEGAL_INSTRUCTION && opcode == RDTSC_OPCODE)
    {
        uint32_t rax = 0;
        uint32_t rdx = 0;

        /* Ask host to execute RDTSC instruction */
        if (myst_rdtsc_ocall(&rax, &rdx) != OE_OK)
        {
            fprintf(stderr, "myst_rdtsc_ocall() failed\n");
            assert(false);
            return OE_EXCEPTION_CONTINUE_SEARCH;
        }

        er->context->rax = rax;
        er->context->rdx = rdx;

        /* Skip over the illegal instruction. */
        er->context->rip += 2;

        return OE_EXCEPTION_CONTINUE_EXECUTION;
    }

    if (er->code == OE_EXCEPTION_ILLEGAL_INSTRUCTION && opcode == CPUID_OPCODE)
    {
        uint32_t rax = 0xaa;
        uint32_t rbx = 0xbb;
        uint32_t rcx = 0xcc;
        uint32_t rdx = 0xdd;

        if (er->context->rax != 0xff)
        {
            myst_cpuid_ocall(
                (uint32_t)er->context->rax, /* leaf */
                (uint32_t)er->context->rcx, /* subleaf */
                &rax,
                &rbx,
                &rcx,
                &rdx);
        }

        er->context->rax = rax;
        er->context->rbx = rbx;
        er->context->rcx = rcx;
        er->context->rdx = rdx;

        return OE_EXCEPTION_CONTINUE_EXECUTION;
    }
    if (er->code == OE_EXCEPTION_ILLEGAL_INSTRUCTION && opcode == IRETQ_OPCODE)
    {
        // Restore RSP, RIP, EFLAGS from the stack. CS and SS are not
        // applicable for sgx applications, and restoring them triggers #UD.

        er->context->flags = *(uint64_t*)(er->context->rsp + IRETFRAME_EFlags);
        er->context->rip = *(uint64_t*)(er->context->rsp + IRETFRAME_Rip);
        er->context->rsp = *(uint64_t*)(er->context->rsp + IRETFRAME_Rsp);

        return OE_EXCEPTION_CONTINUE_EXECUTION;
    }

    return OE_EXCEPTION_CONTINUE_SEARCH;
}

static bool _is_allowed_env_variable(
    const config_parsed_data_t* config,
    const char* env)
{
    for (size_t i = 0; i < config->host_environment_variables_count; i++)
    {
        const char* allowed = config->host_environment_variables[i];
        size_t len = strlen(allowed);

        if (strncmp(env, allowed, len) == 0 && env[len] == '=')
            return true;
    }

    return false;
}

const void* __oe_get_enclave_base(void);
size_t __oe_get_enclave_size(void);

volatile int myst_enter_ecall_lock = 0;

/* return 0 if OE is in SGX debug mode (else return -1) */
static int _test_oe_debug_mode(void)
{
    int ret = -1;
    uint8_t* buf = NULL;
    size_t buf_size;
    oe_report_t report;

    if (oe_get_report_v2(0, NULL, 0, NULL, 0, &buf, &buf_size) != OE_OK)
        goto done;

    if (oe_parse_report(buf, buf_size, &report) != OE_OK)
        goto done;

    if (!(report.identity.attributes & OE_REPORT_ATTRIBUTES_DEBUG))
        goto done;

    ret = 0;

done:

    if (buf)
        oe_free_report(buf);

    return ret;
}

static int _find_region(const char* name, myst_region_t* region)
{
    extern const void* __oe_get_heap_base(void);
    return myst_region_find(__oe_get_heap_base(), name, region);
}

int myst_enter_ecall(
    struct myst_options* options,
    struct myst_shm* shared_memory,
    const void* argv_data,
    size_t argv_size,
    const void* envp_data,
    size_t envp_size,
    uint64_t event)
{
    int ret = -1;
    const void* crt_data;
    size_t crt_size;
    const void* crt_reloc_data;
    size_t crt_reloc_size;
    const void* kernel_data;
    size_t kernel_size;
    const void* kernel_reloc_data;
    size_t kernel_reloc_size;
    const void* kernel_symtab_data;
    size_t kernel_symtab_size;
    const void* kernel_dynsym_data;
    size_t kernel_dynsym_size;
    const void* kernel_strtab_data;
    size_t kernel_strtab_size;
    const void* kernel_dynstr_data;
    size_t kernel_dynstr_size;
    const void* rootfs_data;
    size_t rootfs_size;
    const void* archive_data;
    size_t archive_size;
    const void* config_data;
    size_t config_size;
    bool trace_errors = false;
    bool trace_syscalls = false;
    bool export_ramfs = false;
    const char* rootfs = NULL;
    config_parsed_data_t parsed_config = {0};
    unsigned char have_config = 0;
    myst_args_t args;
    myst_args_t env;
    const char* cwd = "/";       // default to root dir
    const char* hostname = NULL; // kernel has a default
    const uint8_t* enclave_base;
    size_t enclave_size;

    if (__sync_fetch_and_add(&myst_enter_ecall_lock, 1) != 0)
    {
        fprintf(stderr, "ERROR: myst_enter_ecall() can only be called once\n");
        myst_enter_ecall_lock = 1; // stop this from wrapping
        goto done;
    }

    if (!argv_data || !argv_size || !envp_data || !envp_size)
        goto done;

    memset(&args, 0, sizeof(args));
    memset(&env, 0, sizeof(env));

    /* Get the enclave base address */
    if (!(enclave_base = __oe_get_enclave_base()))
    {
        fprintf(stderr, "__oe_get_enclave_base() failed\n");
        assert(0);
    }

    /* Get the enclave size */
    enclave_size = __oe_get_enclave_size();

    /* Get the config region */
    {
        myst_region_t region;
        memset(&region, 0, sizeof(region));

        if (_find_region(MYST_CONFIG_REGION_NAME, &region) == 0)
        {
            config_data = region.data;
            config_size = region.size;

            if (parse_config_from_buffer(
                    config_data, config_size, &parsed_config) != 0)
            {
                fprintf(stderr, "failed to parse configuration\n");
                assert(0);
            }
            have_config = 1;
        }
    }

    if (have_config == 1 && !parsed_config.allow_host_parameters)
    {
        if (myst_args_init(&args) != 0)
            goto done;

        if (myst_args_append1(&args, parsed_config.application_path) != 0)
            goto done;

        if (myst_args_append(
                &args,
                (const char**)parsed_config.application_parameters,
                parsed_config.application_parameters_count) != 0)
        {
            goto done;
        }
    }
    else
    {
        if (myst_args_unpack(&args, argv_data, argv_size) != 0)
            goto done;
    }

    // Need to handle config to environment
    // in the mean time we will just pull from the host
    if (have_config == 1)
    {
        myst_args_init(&env);

        // append all enclave-side environment variables first
        if (myst_args_append(
                &env,
                (const char**)parsed_config.enclave_environment_variables,
                parsed_config.enclave_environment_variables_count) != 0)
        {
            goto done;
        }

        // now include host-side environment variables that are allowed
        if (parsed_config.host_environment_variables &&
            parsed_config.host_environment_variables_count)
        {
            myst_args_t tmp;

            if (myst_args_unpack(&tmp, envp_data, envp_size) != 0)
                goto done;

            for (size_t i = 0; i < tmp.size; i++)
            {
                if (_is_allowed_env_variable(&parsed_config, tmp.data[i]))
                {
                    if (myst_args_append1(&env, tmp.data[i]) != 0)
                    {
                        free(tmp.data);
                        goto done;
                    }
                }
            }

            free(tmp.data);
        }
    }
    else
    {
        if (myst_args_unpack(&env, envp_data, envp_size) != 0)
            goto done;
    }

    // Override current working directory if present in config
    if (have_config && parsed_config.cwd)
    {
        cwd = parsed_config.cwd;
    }

    // Override current working directory if present in config
    if (have_config && parsed_config.hostname)
    {
        hostname = parsed_config.hostname;
    }

    /* Inject the MYST_TARGET environment variable */
    {
        const char val[] = "MYST_TARGET=";

        for (size_t i = 0; i < env.size; i++)
        {
            if (strncmp(env.data[i], val, sizeof(val) - 1) == 0)
            {
                fprintf(stderr, "environment already contains %s", val);
                goto done;
            }
        }

        myst_args_append1(&env, "MYST_TARGET=sgx");
    }

    if (options)
    {
        trace_errors = options->trace_errors;
        trace_syscalls = options->trace_syscalls;
        export_ramfs = options->export_ramfs;

        if (strlen(options->rootfs) >= PATH_MAX)
        {
            fprintf(stderr, "rootfs path too long (> %u)\n", PATH_MAX);
            goto done;
        }

        rootfs = options->rootfs;
    }

    /* Setup the vectored exception handler */
    if (oe_add_vectored_exception_handler(true, _vectored_handler) != OE_OK)
    {
        fprintf(stderr, "oe_add_vectored_exception_handler() failed\n");
        assert(0);
    }

    if (myst_setup_clock(shared_memory->clock))
    {
        fprintf(stderr, "myst_setup_clock() failed\n");
        assert(0);
    }

    /* Get the mman region */
    void* mman_data;
    size_t mman_size;
    {
        myst_region_t region;

        if (_find_region(MYST_MMAN_REGION_NAME, &region) != OE_OK)
        {
            fprintf(stderr, "failed to get crt region\n");
            assert(0);
        }

        mman_data = region.data;
        mman_size = region.size;
    }

    /* Get the rootfs region */
    {
        myst_region_t region;

        if (_find_region(MYST_ROOTFS_REGION_NAME, &region) != OE_OK)
        {
            fprintf(stderr, "failed to get rootfs region\n");
            assert(0);
        }

        rootfs_data = region.data;
        rootfs_size = region.size;
    }

    /* Get the archive region */
    {
        myst_region_t region;

        if (_find_region(MYST_ARCHIVE_REGION_NAME, &region) != OE_OK)
        {
            fprintf(stderr, "failed to get archive region\n");
            assert(0);
        }

        archive_data = region.data;
        archive_size = region.size;
    }

    /* Get the kernel region */
    {
        myst_region_t region;

        if (_find_region(MYST_KERNEL_REGION_NAME, &region) != OE_OK)
        {
            fprintf(stderr, "failed to get kernel region\n");
            assert(0);
        }

        kernel_data = region.data;
        kernel_size = region.size;
    }

    /* Apply relocations to the kernel image */
    {
        myst_region_t region;

        if (_find_region(MYST_KERNEL_RELOC_REGION_NAME, &region) != OE_OK)
        {
            fprintf(stderr, "failed to get kernel region\n");
            assert(0);
        }

        if (myst_apply_relocations(
                kernel_data, kernel_size, region.data, region.size) != 0)
        {
            fprintf(stderr, "myst_apply_relocations() failed\n");
            assert(0);
        }

        kernel_reloc_data = region.data;
        kernel_reloc_size = region.size;
    }

    /* Get the kernel symbol table region */
    {
        myst_region_t region;

        if (_find_region(MYST_KERNEL_SYMTAB_REGION_NAME, &region) != OE_OK)
        {
            fprintf(stderr, "failed to get kernel symtab region\n");
            assert(0);
        }

        kernel_symtab_data = region.data;
        kernel_symtab_size = region.size;
    }

    /* Get the kernel dynamic symbol table region */
    {
        myst_region_t region;

        if (_find_region(MYST_KERNEL_DYNSYM_REGION_NAME, &region) != OE_OK)
        {
            fprintf(stderr, "failed to get kernel dynsym region\n");
            assert(0);
        }

        kernel_dynsym_data = region.data;
        kernel_dynsym_size = region.size;
    }

    /* Get the kernel string table region */
    {
        myst_region_t region;

        if (_find_region(MYST_KERNEL_STRTAB_REGION_NAME, &region) != OE_OK)
        {
            fprintf(stderr, "failed to get kernel strtab region\n");
            assert(0);
        }

        kernel_strtab_data = region.data;
        kernel_strtab_size = region.size;
    }

    /* Get the kernel dynamic string table region */
    {
        myst_region_t region;

        if (_find_region(MYST_KERNEL_DYNSTR_REGION_NAME, &region) != OE_OK)
        {
            fprintf(stderr, "failed to get kernel dynstr region\n");
            assert(0);
        }

        kernel_dynstr_data = region.data;
        kernel_dynstr_size = region.size;
    }

    /* Get the crt region */
    {
        myst_region_t region;

        if (_find_region(MYST_CRT_REGION_NAME, &region) != OE_OK)
        {
            fprintf(stderr, "failed to get crt region\n");
            assert(0);
        }

        crt_data = region.data;
        crt_size = region.size;
    }

    /* Get relocations to the crt image */
    {
        myst_region_t region;

        if (_find_region(MYST_CRT_RELOC_REGION_NAME, &region) != OE_OK)
        {
            fprintf(stderr, "failed to get crt region\n");
            assert(0);
        }

        crt_reloc_data = region.data;
        crt_reloc_size = region.size;
    }

    /* Enter the kernel image */
    {
        myst_kernel_args_t kargs;
        const Elf64_Ehdr* ehdr = kernel_data;
        myst_kernel_entry_t entry;

        memset(&kargs, 0, sizeof(kargs));
        kargs.image_data = enclave_base;
        kargs.image_size = enclave_size;
        kargs.kernel_data = kernel_data;
        kargs.kernel_size = kernel_size;
        kargs.reloc_data = kernel_reloc_data;
        kargs.reloc_size = kernel_reloc_size;
        kargs.crt_reloc_data = crt_reloc_data;
        kargs.crt_reloc_size = crt_reloc_size;
        kargs.symtab_data = kernel_symtab_data;
        kargs.symtab_size = kernel_symtab_size;
        kargs.dynsym_data = kernel_dynsym_data;
        kargs.dynsym_size = kernel_dynsym_size;
        kargs.strtab_data = kernel_strtab_data;
        kargs.strtab_size = kernel_strtab_size;
        kargs.dynstr_data = kernel_dynstr_data;
        kargs.dynstr_size = kernel_dynstr_size;
        kargs.argc = args.size;
        kargs.argv = args.data;
        kargs.envc = env.size;
        kargs.envp = env.data;
        kargs.cwd = cwd;
        kargs.hostname = hostname;
        kargs.mman_data = mman_data;
        kargs.mman_size = mman_size;
        kargs.rootfs_data = (void*)rootfs_data;
        kargs.rootfs_size = rootfs_size;
        kargs.archive_data = (void*)archive_data;
        kargs.archive_size = archive_size;
        kargs.crt_data = (void*)crt_data;
        kargs.crt_size = crt_size;
        kargs.max_threads = _get_num_tcs();
        kargs.trace_errors = trace_errors;
        kargs.trace_syscalls = trace_syscalls;
        kargs.export_ramfs = export_ramfs;
        kargs.tcall = myst_tcall;
        kargs.event = event;

        /* determine whether in SGX debug mode */
        if (_test_oe_debug_mode() == 0)
            kargs.tee_debug_mode = true;
        else
            kargs.tee_debug_mode = false;

        if (rootfs)
            myst_strlcpy(kargs.rootfs, rootfs, sizeof(kargs.rootfs));

        /* Verify that the kernel is an ELF image */
        {
            const uint8_t ident[] = {0x7f, 'E', 'L', 'F'};

            if (memcmp(ehdr->e_ident, ident, sizeof(ident)) != 0)
            {
                fprintf(stderr, "bad kernel image\n");
                assert(0);
            }
        }

        /* Resolve the the kernel entry point */
        entry = (myst_kernel_entry_t)((uint8_t*)kernel_data + ehdr->e_entry);

        if ((uint8_t*)entry < (uint8_t*)kernel_data ||
            (uint8_t*)entry >= (uint8_t*)kernel_data + kernel_size)
        {
            fprintf(stderr, "kernel entry point is out of bounds\n");
            assert(0);
        }

        ret = (*entry)(&kargs);
    }

done:

    if (args.data)
        free(args.data);

    if (env.data)
        free(env.data);

    free_config(&parsed_config);
    return ret;
}

long myst_run_thread_ecall(uint64_t cookie, uint64_t event)
{
    return myst_run_thread(cookie, event);
}

/* This overrides the weak version in libmystkernel.a */
long myst_tcall_add_symbol_file(
    const void* file_data,
    size_t file_size,
    const void* text,
    size_t text_size)
{
    long ret = 0;
    int retval;

    if (!text || !text_size)
        ERAISE(-EINVAL);

    if (myst_add_symbol_file_ocall(
            &retval, file_data, file_size, text, text_size) != OE_OK)
    {
        ERAISE(-EINVAL);
    }

done:

    return ret;
}

/* This overrides the weak version in libmystkernel.a */
long myst_tcall_load_symbols(void)
{
    long ret = 0;
    int retval;

    if (myst_load_symbols_ocall(&retval) != OE_OK || retval != 0)
        ERAISE(-EINVAL);

done:
    return ret;
}

/* This overrides the weak version in libmystkernel.a */
long myst_tcall_unload_symbols(void)
{
    long ret = 0;
    int retval;

    if (myst_unload_symbols_ocall(&retval) != OE_OK || retval != 0)
        ERAISE(-EINVAL);

done:
    return ret;
}

/* This overrides the weak version in libmystkernel.a */
long myst_tcall_isatty(int fd)
{
    long ret;

    if (myst_syscall_isatty_ocall(&ret, fd) != OE_OK)
        return -EINVAL;

    return (long)ret;
}

long myst_tcall_create_thread(uint64_t cookie)
{
    long ret;

    if (myst_create_thread_ocall(&ret, cookie) != OE_OK)
        return -EINVAL;

    return (long)ret;
}

long myst_tcall_wait(uint64_t event, const struct timespec* timeout)
{
    long retval = -EINVAL;
    const struct myst_timespec* to = (const struct myst_timespec*)timeout;

    if (myst_wait_ocall(&retval, event, to) != OE_OK)
        return -EINVAL;

    return retval;
}

long myst_tcall_wake(uint64_t event)
{
    long retval = -EINVAL;

    if (myst_wake_ocall(&retval, event) != OE_OK)
        return -EINVAL;

    return retval;
}

long myst_tcall_wake_wait(
    uint64_t waiter_event,
    uint64_t self_event,
    const struct timespec* timeout)
{
    long retval = -EINVAL;
    const struct myst_timespec* to = (const struct myst_timespec*)timeout;

    if (myst_wake_wait_ocall(&retval, waiter_event, self_event, to) != OE_OK)
        return -EINVAL;

    return retval;
}

long myst_tcall_export_file(const char* path, const void* data, size_t size)
{
    long retval = -1;

    if (myst_export_file_ocall(&retval, path, data, size) != OE_OK)
        return -EINVAL;

    return retval;
}

long myst_tcall_poll_wake(void)
{
    long r;

    if (myst_poll_wake_ocall(&r) != OE_OK)
        return -EINVAL;

    return r;
}

int myst_tcall_open_block_device(const char* path, bool read_only)
{
    int retval;

    if (myst_open_block_device_ocall(&retval, path, read_only) != OE_OK)
        return -EINVAL;

    return retval;
}

int myst_tcall_close_block_device(int blkdev)
{
    int retval;

    if (myst_close_block_device_ocall(&retval, blkdev) != OE_OK)
        return -EINVAL;

    return retval;
}

int myst_tcall_read_block_device(
    int blkdev,
    uint64_t blkno,
    struct myst_block* blocks,
    size_t num_blocks)
{
    int retval;

    if (myst_read_block_device_ocall(
            &retval, blkdev, blkno, blocks, num_blocks) != OE_OK)
    {
        return -EINVAL;
    }

    return retval;
}

int myst_tcall_write_block_device(
    int blkdev,
    uint64_t blkno,
    const struct myst_block* blocks,
    size_t num_blocks)
{
    int retval;

    if (myst_write_block_device_ocall(
            &retval, blkdev, blkno, blocks, num_blocks) != OE_OK)
    {
        return -EINVAL;
    }

    return retval;
}

int myst_load_fssig(const char* path, myst_fssig_t* fssig)
{
    int retval;

    if (!path || !fssig)
        return -EINVAL;

    if (myst_load_fssig_ocall(&retval, path, fssig) != OE_OK)
        return -EINVAL;

    if (fssig->signature_size > sizeof(fssig->signature))
    {
        memset(fssig, 0, sizeof(myst_fssig_t));
        return -EPERM;
    }

    return retval;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    32,   /* NumHeapPages */
    32,   /* NumStackPages */
    16);  /* NumTCS */
