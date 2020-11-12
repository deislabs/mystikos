// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>

#include <openenclave/bits/sgx/region.h>
#include <openenclave/enclave.h>

#include <elf.h>
#include <libos/args.h>
#include <libos/buf.h>
#include <libos/eraise.h>
#include <libos/file.h>
#include <libos/kernel.h>
#include <libos/mmanutils.h>
#include <libos/mount.h>
#include <libos/ramfs.h>
#include <libos/reloc.h>
#include <libos/shm.h>
#include <libos/syscall.h>
#include <libos/thread.h>
#include <libos/trace.h>

#include "../config.h"
#include "../shared.h"
#include "libos_t.h"

extern volatile const oe_sgx_enclave_properties_t oe_enclave_properties_sgx;

static size_t _get_num_tcs(void)
{
    return oe_enclave_properties_sgx.header.size_settings.num_tcs;
}

int libos_setup_clock(struct clock_ctrl*);

static void _setup_sockets(void)
{
    if (oe_load_module_host_socket_interface() != OE_OK)
    {
        fprintf(stderr, "oe_load_module_host_socket_interface() failed\n");
        assert(0);
    }
}

/* Handle illegal SGX instructions */
static uint64_t _vectored_handler(oe_exception_record_t* er)
{
    const uint16_t RDTSC_OPCODE = 0x310F;
    const uint16_t CPUID_OPCODE = 0xA20F;
    const uint16_t opcode = *((uint16_t*)er->context->rip);

    if (er->code == OE_EXCEPTION_ILLEGAL_INSTRUCTION && opcode == RDTSC_OPCODE)
    {
        uint32_t rax = 0;
        uint32_t rdx = 0;

        /* Ask host to execute RDTSC instruction */
        if (libos_rdtsc_ocall(&rax, &rdx) != OE_OK)
        {
            fprintf(stderr, "libos_rdtsc_ocall() failed\n");
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
            libos_cpuid_ocall(
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

volatile int libos_enter_ecall_lock = 0;

int libos_enter_ecall(
    struct libos_options* options,
    struct libos_shm* shared_memory,
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
    const void* config_data;
    size_t config_size;
    bool trace_syscalls = false;
    bool export_ramfs = false;
    config_parsed_data_t parsed_config = {0};
    unsigned char have_config = 0;
    libos_args_t args;
    libos_args_t env;
    const uint8_t* enclave_base;
    size_t enclave_size;

    if (__sync_fetch_and_add(&libos_enter_ecall_lock, 1) != 0)
    {
        fprintf(stderr, "ERROR: libos_enter_ecall() can only be called once\n");
        libos_enter_ecall_lock = 1; // stop this from wrapping
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
        oe_region_t region;

        if (oe_region_get(LIBOS_CONFIG_REGION_ID, &region) == OE_OK)
        {
            config_data = enclave_base + region.vaddr;
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
        if (libos_args_init(&args) != 0)
            goto done;

        if (libos_args_append1(&args, parsed_config.application_path) != 0)
            goto done;

        if (libos_args_append(
                &args,
                (const char**)parsed_config.application_parameters,
                parsed_config.application_parameters_count) != 0)
        {
            goto done;
        }
    }
    else
    {
        if (libos_args_unpack(&args, argv_data, argv_size) != 0)
            goto done;
    }

    // Need to handle config to environment
    // in the mean time we will just pull from the host
    if (have_config == 1)
    {
        libos_args_init(&env);

        // append all enclave-side environment variables first
        if (libos_args_append(
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
            libos_args_t tmp;

            if (libos_args_unpack(&tmp, envp_data, envp_size) != 0)
                goto done;

            for (size_t i = 0; i < tmp.size; i++)
            {
                if (_is_allowed_env_variable(&parsed_config, tmp.data[i]))
                {
                    if (libos_args_append1(&env, tmp.data[i]) != 0)
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
        if (libos_args_unpack(&env, envp_data, envp_size) != 0)
            goto done;
    }

    /* Inject the LIBOS_TARGET environment variable */
    {
        const char val[] = "LIBOS_TARGET=";

        for (size_t i = 0; i < env.size; i++)
        {
            if (strncmp(env.data[i], val, sizeof(val) - 1) == 0)
            {
                fprintf(stderr, "environment already contains %s", val);
                goto done;
            }
        }

        libos_args_append1(&env, "LIBOS_TARGET=sgx");
    }

    if (options)
    {
        trace_syscalls = options->trace_syscalls;
        export_ramfs = options->export_ramfs;
    }

    /* Setup the vectored exception handler */
    if (oe_add_vectored_exception_handler(true, _vectored_handler) != OE_OK)
    {
        fprintf(stderr, "oe_add_vectored_exception_handler() failed\n");
        assert(0);
    }

    _setup_sockets();

    if (libos_setup_clock(shared_memory->clock))
    {
        fprintf(stderr, "libos_setup_clock() failed\n");
        assert(0);
    }

    /* Get the mman region */
    void* mman_data;
    size_t mman_size;
    {
        oe_region_t region;

        if (oe_region_get(LIBOS_MMAN_REGION_ID, &region) != OE_OK)
        {
            fprintf(stderr, "failed to get crt region\n");
            assert(0);
        }

        mman_data = (void*)(enclave_base + region.vaddr);
        mman_size = region.size;
    }

    /* Get the rootfs region */
    {
        oe_region_t region;

        if (oe_region_get(LIBOS_ROOTFS_REGION_ID, &region) != OE_OK)
        {
            fprintf(stderr, "failed to get crt region\n");
            assert(0);
        }

        rootfs_data = enclave_base + region.vaddr;
        rootfs_size = region.size;
    }

    /* Get the kernel region */
    {
        oe_region_t region;

        if (oe_region_get(LIBOS_KERNEL_REGION_ID, &region) != OE_OK)
        {
            fprintf(stderr, "failed to get kernel region\n");
            assert(0);
        }

        kernel_data = enclave_base + region.vaddr;
        kernel_size = region.size;
    }

    /* Apply relocations to the kernel image */
    {
        oe_region_t region;

        if (oe_region_get(LIBOS_KERNEL_RELOC_REGION_ID, &region) != OE_OK)
        {
            fprintf(stderr, "failed to get kernel region\n");
            assert(0);
        }

        if (libos_apply_relocations(
                kernel_data,
                kernel_size,
                enclave_base + region.vaddr,
                region.size) != 0)
        {
            fprintf(stderr, "libos_apply_relocations() failed\n");
            assert(0);
        }

        kernel_reloc_data = enclave_base + region.vaddr;
        kernel_reloc_size = region.size;
    }

    /* Get the kernel symbol table region */
    {
        oe_region_t region;

        if (oe_region_get(LIBOS_KERNEL_SYMTAB_REGION_ID, &region) != OE_OK)
        {
            fprintf(stderr, "failed to get kernel symtab region\n");
            assert(0);
        }

        kernel_symtab_data = enclave_base + region.vaddr;
        kernel_symtab_size = region.size;
    }

    /* Get the kernel dynamic symbol table region */
    {
        oe_region_t region;

        if (oe_region_get(LIBOS_KERNEL_DYNSYM_REGION_ID, &region) != OE_OK)
        {
            fprintf(stderr, "failed to get kernel dynsym region\n");
            assert(0);
        }

        kernel_dynsym_data = enclave_base + region.vaddr;
        kernel_dynsym_size = region.size;
    }

    /* Get the kernel string table region */
    {
        oe_region_t region;

        if (oe_region_get(LIBOS_KERNEL_STRTAB_REGION_ID, &region) != OE_OK)
        {
            fprintf(stderr, "failed to get kernel strtab region\n");
            assert(0);
        }

        kernel_strtab_data = enclave_base + region.vaddr;
        kernel_strtab_size = region.size;
    }

    /* Get the kernel dynamic string table region */
    {
        oe_region_t region;

        if (oe_region_get(LIBOS_KERNEL_DYNSTR_REGION_ID, &region) != OE_OK)
        {
            fprintf(stderr, "failed to get kernel dynstr region\n");
            assert(0);
        }

        kernel_dynstr_data = enclave_base + region.vaddr;
        kernel_dynstr_size = region.size;
    }

    /* Get the crt region */
    {
        oe_region_t region;

        if (oe_region_get(LIBOS_CRT_REGION_ID, &region) != OE_OK)
        {
            fprintf(stderr, "failed to get crt region\n");
            assert(0);
        }

        crt_data = enclave_base + region.vaddr;
        crt_size = region.size;
    }

    /* Get relocations to the crt image */
    {
        oe_region_t region;

        if (oe_region_get(LIBOS_CRT_RELOC_REGION_ID, &region) != OE_OK)
        {
            fprintf(stderr, "failed to get crt region\n");
            assert(0);
        }

        crt_reloc_data = enclave_base + region.vaddr;
        crt_reloc_size = region.size;
    }

    /* Enter the kernel image */
    {
        libos_kernel_args_t kargs;
        const Elf64_Ehdr* ehdr = kernel_data;
        libos_kernel_entry_t entry;

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
        kargs.mman_data = mman_data;
        kargs.mman_size = mman_size;
        kargs.rootfs_data = (void*)rootfs_data;
        kargs.rootfs_size = rootfs_size;
        kargs.crt_data = (void*)crt_data;
        kargs.crt_size = crt_size;
        kargs.max_threads = _get_num_tcs();
        kargs.trace_syscalls = trace_syscalls;
        kargs.export_ramfs = export_ramfs;
        kargs.tcall = libos_tcall;
        kargs.event = event;

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
        entry = (libos_kernel_entry_t)((uint8_t*)kernel_data + ehdr->e_entry);

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

long libos_run_thread_ecall(uint64_t cookie, uint64_t event)
{
    return libos_run_thread(cookie, event);
}

/* This overrides the weak version in liboskernel.a */
long libos_tcall_add_symbol_file(
    const void* file_data,
    size_t file_size,
    const void* text,
    size_t text_size)
{
    long ret = 0;
    int retval;

    if (!text || !text_size)
        ERAISE(-EINVAL);

    if (libos_add_symbol_file_ocall(
            &retval, file_data, file_size, text, text_size) != OE_OK)
    {
        ERAISE(-EINVAL);
    }

done:

    return ret;
}

/* This overrides the weak version in liboskernel.a */
long libos_tcall_load_symbols(void)
{
    long ret = 0;
    int retval;

    if (libos_load_symbols_ocall(&retval) != OE_OK || retval != 0)
        ERAISE(-EINVAL);

done:
    return ret;
}

/* This overrides the weak version in liboskernel.a */
long libos_tcall_unload_symbols(void)
{
    long ret = 0;
    int retval;

    if (libos_unload_symbols_ocall(&retval) != OE_OK || retval != 0)
        ERAISE(-EINVAL);

done:
    return ret;
}

/* This overrides the weak version in liboskernel.a */
long libos_tcall_isatty(int fd)
{
    long ret;

    if (libos_syscall_isatty_ocall(&ret, fd) != OE_OK)
        return -EINVAL;

    return (long)ret;
}

long libos_tcall_create_thread(uint64_t cookie)
{
    long ret;

    if (libos_create_thread_ocall(&ret, cookie) != OE_OK)
        return -EINVAL;

    return (long)ret;
}

long libos_tcall_wait(uint64_t event, const struct timespec* timeout)
{
    long retval = -EINVAL;
    const struct libos_timespec* to = (const struct libos_timespec*)timeout;

    if (libos_wait_ocall(&retval, event, to) != OE_OK)
        return -EINVAL;

    return retval;
}

long libos_tcall_wake(uint64_t event)
{
    long retval = -EINVAL;

    if (libos_wake_ocall(&retval, event) != OE_OK)
        return -EINVAL;

    return retval;
}

long libos_tcall_wake_wait(
    uint64_t waiter_event,
    uint64_t self_event,
    const struct timespec* timeout)
{
    long retval = -EINVAL;
    const struct libos_timespec* to = (const struct libos_timespec*)timeout;

    if (libos_wake_wait_ocall(&retval, waiter_event, self_event, to) != OE_OK)
        return -EINVAL;

    return retval;
}

long libos_tcall_export_file(const char* path, const void* data, size_t size)
{
    long retval = -1;

    if (libos_export_file_ocall(&retval, path, data, size) != OE_OK)
        return -EINVAL;

    return retval;
}

long oe_get_host_fd(int fd);

/* overrides function by same name in SGX target */
long libos_tcall_fstat(int fd, struct stat* statbuf)
{
    long retval = 0;
    long hfd;

    if (!statbuf)
        return -EINVAL;

    if ((hfd = oe_get_host_fd(fd)) < 0)
        return -EINVAL;

    if (libos_fstat_ocall(&retval, hfd, (struct libos_stat*)statbuf) != OE_OK)
        return -EINVAL;

    return retval;
}

long libos_tcall_sched_yield(void)
{
    long retval = 0;

    if (libos_sched_yield_ocall(&retval) != OE_OK)
        return -EINVAL;

    return retval;
}

long libos_tcall_fchmod(int fd, mode_t mode)
{
    long retval;
    long hfd;

    if ((hfd = oe_get_host_fd(fd)) < 0)
        return -EINVAL;

    if (libos_fchmod_ocall(&retval, (int)hfd, mode) != OE_OK)
        return -EINVAL;

    return retval;
}

OE_SET_ENCLAVE_SGX(
    1,        /* ProductID */
    1,        /* SecurityVersion */
    true,     /* Debug */
    8 * 4096, /* NumHeapPages */
    32,       /* NumStackPages */
    16);      /* NumTCS */
