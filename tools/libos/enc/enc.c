// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/bits/sgx/region.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sys/mount.h>
#include <libos/syscall.h>
#include <stdlib.h>
#include <libos/mmanutils.h>
#include <libos/eraise.h>
#include <libos/elfutils.h>
#include <libos/ramfs.h>
#include <libos/mount.h>
#include <libos/file.h>
#include <libos/cpio.h>
#include <libos/trace.h>
#include <libos/kernel.h>
#include "libos_t.h"
#include "../shared.h"

extern int oe_host_printf(const char* fmt, ...);

static int _deserialize_args(
    const void* args,
    size_t args_size,
    const char* argv[],
    size_t argv_size)
{
    int ret = -1;
    size_t n = 0;
    const char* p = (const char*)args;
    const char* end = (const char*)args + args_size;

    while (p != end)
    {
        if (n == argv_size)
            goto done;

        argv[n++] = p;
        p += strlen(p) + 1;
    }

    argv[n] = NULL;
    ret = 0;

done:
    return ret;
}

static size_t _count_args(const char* args[])
{
    size_t n = 0;

    for (size_t i = 0; args[i]; i++)
        n++;

    return n;
}

#if 0
static void _dump_args(const char* args[])
{
    printf("args=%p\n", args);
    for (int i = 0; args[i]; i++)
        printf("args[%d]=%s\n", i, args[i]);
}
#endif

static void _setup_sockets(void)
{
    if (oe_load_module_host_socket_interface() != OE_OK)
    {
        fprintf(stderr, "oe_load_module_host_socket_interface() failed\n");
        assert(0);
    }
}

static void _apply_relocations(
    const void* image_base,
    size_t image_size,
    const void* reloc_base,
    size_t reloc_size)
{
    const Elf64_Rela* relocs = (const Elf64_Rela*)reloc_base;
    size_t nrelocs = reloc_size / sizeof(Elf64_Rela);
    const uint8_t* baseaddr = (const uint8_t*)image_base;

    for (size_t i = 0; i < nrelocs; i++)
    {
        const Elf64_Rela* p = &relocs[i];

        /* If zero-padded bytes reached */
        if (p->r_offset == 0)
            break;

        assert(p->r_offset > 0);
        assert(p->r_offset <= image_size);

        /* Compute address of reference to be relocated */
        uint64_t* dest = (uint64_t*)(baseaddr + p->r_offset);

        uint64_t reloc_type = ELF64_R_TYPE(p->r_info);

        /* Relocate the reference */
        if (reloc_type == R_X86_64_RELATIVE)
        {
            *dest = (uint64_t)(baseaddr + p->r_addend);
        }
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
    const void* args,
    size_t args_size,
    const void* env,
    size_t env_size)
{
    int ret = -1;
    const char* argv[64];
    size_t argv_size = sizeof(argv) / sizeof(argv[0]);
    const char* envp[64];
    size_t envp_size = sizeof(envp) / sizeof(envp[0]);
    const void* crt_data;
    size_t crt_size;
    const void* kernel_data;
    size_t kernel_size;
    const void* rootfs_data;
    size_t rootfs_size;
    bool trace_syscalls = false;
    bool real_syscalls = false;

    if (!args || !args_size || !env || !env_size)
        goto done;

    if (_deserialize_args(args, args_size, argv + 1, argv_size - 1) != 0)
        goto done;

    if (_deserialize_args(env, env_size, envp, envp_size) != 0)
        goto done;

    argv[0] = "libosenc.so";

    if (options)
    {
        trace_syscalls = options->trace_syscalls;
        real_syscalls = options->real_syscalls;
    }

    /* Setup the vectored exception handler */
    if (oe_add_vectored_exception_handler(true, _vectored_handler) != OE_OK)
    {
        fprintf(stderr, "oe_add_vectored_exception_handler() failed\n");
        assert(0);
    }

    _setup_sockets();

#ifdef TRACE
    _dump_args(argv);
    _dump_args(envp);
#endif

    /* Get the mman region */
    void* mman_data;
    size_t mman_size;
    {
        {
            extern const void* __oe_get_enclave_base(void);
            oe_region_t region;
            const uint8_t* enclave_base;

            if (!(enclave_base = __oe_get_enclave_base()))
            {
                fprintf(stderr, "__oe_get_enclave_base() failed\n");
                assert(0);
            }

            if (oe_region_get(MMAN_REGION_ID, &region) != OE_OK)
            {
                fprintf(stderr, "failed to get crt region\n");
                assert(0);
            }

            mman_data = (void*)(enclave_base + region.vaddr);
            mman_size = region.size;
        }
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

        if (oe_region_get(ROOTFS_REGION_ID, &region) != OE_OK)
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

        if (oe_region_get(KERNEL_REGION_ID, &region) != OE_OK)
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

        if (oe_region_get(KERNEL_RELOC_REGION_ID, &region) != OE_OK)
        {
            fprintf(stderr, "failed to get kernel region\n");
            assert(0);
        }

        _apply_relocations(
            kernel_data,
            kernel_size,
            enclave_base + region.vaddr,
            region.size);
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

        if (oe_region_get(CRT_REGION_ID, &region) != OE_OK)
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

        if (oe_region_get(CRT_RELOC_REGION_ID, &region) != OE_OK)
        {
            fprintf(stderr, "failed to get crt region\n");
            assert(0);
        }

        _apply_relocations(
            crt_data,
            crt_size,
            enclave_base + region.vaddr,
            region.size);
    }

    /* Enter the kernel image */
    {
        libos_kernel_args_t args;
        const Elf64_Ehdr* ehdr = kernel_data;
        libos_kernel_entry_t entry;

        args.argc = _count_args(argv);
        args.argv = argv;
        args.envc = _count_args(envp);
        args.envp = envp;
        args.mman_data = mman_data;
        args.mman_size = mman_size;
        args.rootfs_data = (void*)rootfs_data;
        args.rootfs_size = rootfs_size;
        args.crt_data = (void*)crt_data;
        args.crt_size = crt_size;
        args.trace_syscalls = trace_syscalls;
        args.real_syscalls = real_syscalls;
        args.tcall = libos_tcall;

        /* Verify that the kernel is an ELF image */
        {
            const uint8_t ident[] = { 0x7f, 'E', 'L', 'F' };

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
    return ret;
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

    if (libos_add_symbol_file_ocall(&retval, file_data, file_size, text,
        text_size) != OE_OK)
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

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    8*4096, /* NumHeapPages */
    1024, /* NumStackPages */
    4);   /* NumTCS */
