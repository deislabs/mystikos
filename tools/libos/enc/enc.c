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

#include <libos/buf.h>
#include <libos/cpio.h>
#include <libos/elfutils.h>
#include <libos/eraise.h>
#include <libos/file.h>
#include <libos/kernel.h>
#include <libos/mmanutils.h>
#include <libos/mount.h>
#include <libos/ramfs.h>
#include <libos/reloc.h>
#include <libos/syscall.h>
#include <libos/thread.h>
#include <libos/trace.h>

#include "../config.h"
#include "../shared.h"
#include "libos_t.h"

extern int oe_host_printf(const char* fmt, ...);

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

int libos_enter_ecall(
    struct libos_options* options,
    const void* argv_data,
    size_t argv_size,
    const void* envp_data,
    size_t envp_size,
    uint64_t event)
{
    int ret = -1;
    const char** envp = NULL;
    const size_t ENVC = 64;
    size_t envc = 0;
    const void* crt_data;
    size_t crt_size;
    const void* kernel_data;
    size_t kernel_size;
    const void* rootfs_data;
    size_t rootfs_size;
    const void* config_data;
    size_t config_size;
    bool trace_syscalls = false;
    bool export_ramfs = false;
    config_parsed_data_t parsed_config = {0};
    unsigned char have_config = 0;
    const char** argv = NULL;
    size_t argc = 0;
    const char** xargv = NULL;
    size_t xargc = 0;

    if (!argv_data || !argv_size || !envp_data || !envp_size)
        goto done;

    /* Get the config region */
    {
        extern const void* __oe_get_enclave_base(void);
        oe_region_t region;
        const uint8_t* enclave_base;

        if (!(enclave_base = __oe_get_enclave_base()))
        {
            fprintf(stderr, "__oe_get_enclave_base() failed\n");
            assert(0);
        }

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

    if (have_config == 1 && parsed_config.allow_host_parameters)
    {
        /* add extra space for argv[0] */
        argc = parsed_config.application_parameters_count + 1;

        /* allocate extra entry for the null terminator */
        if (!(argv = calloc(argc + 1, sizeof(char*))))
            goto done;

        argv[0] = parsed_config.application_path;

        for (size_t i = 1; i < argc; i++)
            argv[i] = parsed_config.application_parameters[i];
    }
    else
    {
        libos_buf_t buf;
        buf.data = (void*)argv_data;
        buf.size = argv_size;
        buf.cap = argv_size;
        buf.offset = 0;

        if (libos_buf_unpack_strings(&buf, &argv, &argc) != 0)
            goto done;
    }

    // Need to handle config to environment
    // in the mean time we will just pull from the host
    if (have_config == 1)
    {
        size_t env_slot = 0;
        size_t source_slot = 0;

        if (!(envp = calloc(ENVC, sizeof(char*))))
            goto done;

        // First config-side environment variables
        while ((source_slot !=
                parsed_config.enclave_environment_variables_count) &&
               ((env_slot + 2) != ENVC)) // slots including null one
        {
            envp[env_slot] =
                parsed_config.enclave_environment_variables[source_slot];
            env_slot++;
            source_slot++;
        }

        // now include host-side environment variables that are allowed
        for (int allowed_index = 0;
             parsed_config.host_environment_variables != NULL &&
             (parsed_config.host_environment_variables[allowed_index] !=
              NULL) &&
             (allowed_index != (sizeof(envp) / sizeof(*envp)));
             allowed_index++)
        {
            size_t n = 0;
            const char* p = (const char*)envp_data;
            const char* end = (const char*)envp_data + envp_size;

            while (p != end)
            {
                if (n == ENVC)
                    break;

                // Only add if it is mentioned in allow list, then we are done
                // for this iteration
                if (strncmp(
                        parsed_config.host_environment_variables[allowed_index],
                        p,
                        strlen(
                            parsed_config
                                .host_environment_variables[allowed_index])) ==
                    0)
                {
                    envp[env_slot] = p;
                    env_slot++;
                    break;
                }
                p += strlen(p) + 1;
            }
        }

        envc = env_slot;
    }
    else
    {
        libos_buf_t buf;
        buf.data = (uint8_t*)envp_data;
        buf.size = envp_size;
        buf.cap = envp_size;
        buf.offset = 0;

        if (libos_buf_unpack_strings(&buf, &envp, &envc) != 0)
            goto done;
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

    /* inject the library name as argv[0] (required by musl libc) */
    {
        xargc = argc + 1;

        if (!(xargv = calloc(xargc + 1, sizeof(char*))))
            goto done;

        xargv[0] = "libosenc.so";
        memcpy(&xargv[1], argv, argc * sizeof(char*));
    }

#ifdef TRACE
    printf("envc{%zu}\n", envc);

    for (size_t i = 0; i < envc; i++)
        printf("envp{%s}\n", envp[i]);
#endif

    /* Get the mman region */
    void* mman_data;
    size_t mman_size;
    {
        extern const void* __oe_get_enclave_base(void);
        oe_region_t region;
        const uint8_t* enclave_base;

        if (!(enclave_base = __oe_get_enclave_base()))
        {
            fprintf(stderr, "__oe_get_enclave_base() failed\n");
            assert(0);
        }

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
        extern const void* __oe_get_enclave_base(void);
        oe_region_t region;
        const uint8_t* enclave_base;

        if (!(enclave_base = __oe_get_enclave_base()))
        {
            fprintf(stderr, "__oe_get_enclave_base() failed\n");
            assert(0);
        }

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
        extern const void* __oe_get_enclave_base(void);
        oe_region_t region;
        const uint8_t* enclave_base;

        if (!(enclave_base = __oe_get_enclave_base()))
        {
            fprintf(stderr, "__oe_get_enclave_base() failed\n");
            assert(0);
        }

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
        extern const void* __oe_get_enclave_base(void);
        oe_region_t region;
        const uint8_t* enclave_base;

        if (!(enclave_base = __oe_get_enclave_base()))
        {
            fprintf(stderr, "__oe_get_enclave_base() failed\n");
            assert(0);
        }

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
    }

    /* Get the crt region */
    {
        extern const void* __oe_get_enclave_base(void);
        oe_region_t region;
        const uint8_t* enclave_base;

        if (!(enclave_base = __oe_get_enclave_base()))
        {
            fprintf(stderr, "__oe_get_enclave_base() failed\n");
            assert(0);
        }

        if (oe_region_get(LIBOS_CRT_REGION_ID, &region) != OE_OK)
        {
            fprintf(stderr, "failed to get crt region\n");
            assert(0);
        }

        crt_data = enclave_base + region.vaddr;
        crt_size = region.size;
    }

    /* Apply relocations to the crt image */
    {
        extern const void* __oe_get_enclave_base(void);
        oe_region_t region;
        const uint8_t* enclave_base;

        if (!(enclave_base = __oe_get_enclave_base()))
        {
            fprintf(stderr, "__oe_get_enclave_base() failed\n");
            assert(0);
        }

        if (oe_region_get(LIBOS_CRT_RELOC_REGION_ID, &region) != OE_OK)
        {
            fprintf(stderr, "failed to get crt region\n");
            assert(0);
        }

        if (libos_apply_relocations(
                crt_data, crt_size, enclave_base + region.vaddr, region.size) !=
            0)
        {
            fprintf(stderr, "libos_apply_relocations() failed\n");
            assert(0);
        }
    }

    /* Enter the kernel image */
    {
        libos_kernel_args_t args;
        const Elf64_Ehdr* ehdr = kernel_data;
        libos_kernel_entry_t entry;

        memset(&args, 0, sizeof(args));
        args.argc = xargc;
        args.argv = xargv;
        args.envc = envc;
        args.envp = envp;
        args.mman_data = mman_data;
        args.mman_size = mman_size;
        args.rootfs_data = (void*)rootfs_data;
        args.rootfs_size = rootfs_size;
        args.crt_data = (void*)crt_data;
        args.crt_size = crt_size;
        args.trace_syscalls = trace_syscalls;
        args.export_ramfs = export_ramfs;
        args.tcall = libos_tcall;
        args.event = event;

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

        ret = (*entry)(&args);
    }

done:

    if (argv)
        free(argv);

    if (xargv)
        free(xargv);

    if (envp)
        free(envp);

    free_config(&parsed_config);
    return ret;
}

long libos_run_thread_ecall(uint64_t cookie, uint64_t event)
{
    return libos_run_thread(cookie, event);
}

_Static_assert(sizeof(struct libos_timespec) == sizeof(struct timespec), "");

/* ATTN: replace this with clock ticks implementation */
/* This overrides the weak version in liboskernel.a */
long libos_tcall_clock_gettime(clockid_t clk_id, struct timespec* tp_)
{
    int retval = -1;
    struct libos_timespec* tp = (struct libos_timespec*)tp_;

    if (libos_clock_gettime_ocall(&retval, clk_id, tp) != OE_OK)
        return -EINVAL;

    return (long)retval;
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

    if (!file_data || !file_size || !text || !text_size)
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

OE_SET_ENCLAVE_SGX(
    1,        /* ProductID */
    1,        /* SecurityVersion */
    true,     /* Debug */
    8 * 4096, /* NumHeapPages */
    32,       /* NumStackPages */
    16);      /* NumTCS */
